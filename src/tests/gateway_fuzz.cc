// Gateway frame parser fuzz targets (T15/F08/R2-F04).
//
// Targets:
//   gateway_fuzz_smoke  - standalone deterministic smoke (all compilers);
//                         entry is gateway_fuzz_smoke_main() via
//                         gateway_fuzz_smoke_main.cc.
//   gateway_fuzz        - real libFuzzer target (clang only), built only
//                         when GATEWAY_FUZZ_LIBFUZZER=ON; the fuzzer
//                         runtime provides main() and calls
//                         LLVMFuzzerTestOneInput.
//
// Lifecycle contract (R2-F04):
//   - every scenario owns a FuzzGatewayFixture: one bufferevent pair plus a
//     registered GatewayMaster;
//   - a dispatch may remove the master (invalid frame length, ingress-ack
//     failure), which destroys the GatewayMaster and its bufferevent, so the
//     harness NEVER reuses a raw master pointer across dispatches: it
//     re-resolves by fd via FuzzGatewayFixture::current();
//   - empty inputs must not dereference data (no data[0] on empty vectors);
//   - libFuzzer init failure aborts the process instead of returning 0 (a
//     "ran many inputs without a parser" false pass is not allowed);
//   - the smoke binary converts counters into hard assertions and exits
//     nonzero when any contract is violated; it never prints a blanket
//     "no crash/hang" claim.
//
// Build (libFuzzer + ASan/UBSan, clang):
//   cmake -B build-fuzz -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
//         -DMARCH_NATIVE=OFF -DENABLE_LTO=OFF
//         -DGATEWAY_FUZZ_LIBFUZZER=ON
//   cmake --build build-fuzz --target gateway_fuzz -j
//   build-fuzz/src/tests/gateway_fuzz -runs=10000 -max_len=4096
//     -timeout=5 -print_final_stats=1 src/tests/fuzz/corpus/gateway/
//
// Smoke (no libFuzzer, standalone deterministic loop):
//   build/src/tests/gateway_fuzz_smoke

#ifdef _WIN32
#include <direct.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "base/package_api.h"
#include "mainlib.h"
#include "packages/gateway/gateway.h"

namespace {

// Deterministic pseudo-random bytes so the smoke mode is reproducible.
uint64_t g_state = 0x9e3779b97f4a7c15ULL;
uint64_t next_random() {
  g_state ^= g_state << 13;
  g_state ^= g_state >> 7;
  g_state ^= g_state << 17;
  return g_state;
}

int fuzz_chdir(const char *path) {
#ifdef _WIN32
  return _chdir(path);
#else
  return chdir(path);
#endif
}

bool init_driver_once() {
  // The gateway read path needs the driver event base and runtime state,
  // mirroring the DriverTest fixture: chdir into the testsuite and init.
  static bool initialized = false;
  if (initialized) {
    return true;
  }
  if (fuzz_chdir(TESTSUITE_DIR) != 0) {
    std::fprintf(stderr, "gateway_fuzz: chdir %s failed\n", TESTSUITE_DIR);
    return false;
  }
  if (!init_main("etc/config.test")) {
    std::fprintf(stderr, "gateway_fuzz: init_main failed\n");
    return false;
  }
  vm_start();
  initialized = true;
  return true;
}

// One isolated scenario fixture: a fresh bufferevent pair plus a registered
// master. The master adopts endpoint 0 and frees it in ~GatewayMaster; this
// fixture always owns and explicitly frees peer endpoint 1. After a dispatch
// that removed the master, only current() may be used to query master state.
struct FuzzGatewayFixture {
  static constexpr int kFd = 4242;

  ~FuzzGatewayFixture() { teardown(); }
  FuzzGatewayFixture() = default;
  FuzzGatewayFixture(const FuzzGatewayFixture &) = delete;
  FuzzGatewayFixture &operator=(const FuzzGatewayFixture &) = delete;

  bool create() {
    teardown();
    bufferevent *pair[2]{nullptr, nullptr};
    if (bufferevent_pair_new(g_event_base, BEV_OPT_CLOSE_ON_FREE, pair) != 0) {
      std::fprintf(stderr, "gateway_fuzz: bufferevent_pair_new failed\n");
      return false;
    }
    master_ = gateway_register_master_for_test(kFd, pair[0]);
    if (!master_) {
      // Registration failed before either endpoint was adopted.
      bufferevent_free(pair[0]);
      bufferevent_free(pair[1]);
      std::fprintf(stderr, "gateway_fuzz: register_master failed\n");
      return false;
    }
    peer_ = pair[1];
    return true;
  }

  // Live master by fd; nullptr when the previous dispatch removed it. Never
  // cache the result across a dispatch.
  GatewayMaster *current() {
    master_ = gateway_master_for_test(kFd);
    return master_;
  }

  void teardown() {
    gateway_remove_master_for_test(kFd);
    master_ = nullptr;
    if (peer_) {
      bufferevent_free(peer_);
      peer_ = nullptr;
    }
  }

  GatewayMaster *master_{nullptr};
  bufferevent *peer_{nullptr};
};

template <typename Scenario>
bool run_isolated_scenario(Scenario &&scenario) {
  FuzzGatewayFixture fx;
  if (!fx.create()) {
    return false;
  }
  scenario(fx);
  return true;
}

// Append bytes and dispatch. Re-resolve the master before every call: the
// previous dispatch may have removed it. Returns false when the master is
// gone (caller must stop using the fixture).
bool append_and_dispatch(FuzzGatewayFixture &fx, const char *data, size_t len,
                         int budget = 16) {
  auto *master = fx.current();
  if (!master) {
    return false;
  }
  gateway_append_read_bytes_for_test(master, data, len);
  gateway_dispatch_buffered_frames_for_test(master, budget);
  return fx.current() != nullptr;
}

// Derive a bounded payload length from the input: reuse the first 4 bytes as
// a network-order frame length when plausible, otherwise derive one from the
// input size so every input still produces a complete frame.
uint32_t derive_frame_length(const uint8_t *data, size_t size) {
  const auto hard_limit = gateway_packet_size_hard_limit_for_test();
  if (size >= sizeof(uint32_t)) {
    uint32_t candidate = 0;
    std::memcpy(&candidate, data, sizeof(candidate));
    candidate = ntohl(candidate);
    if (candidate > 0 && static_cast<size_t>(candidate) <= hard_limit) {
      return candidate;
    }
  }
  // Deterministic fallback derived from the input bytes; keep the frame
  // small enough that the harness stays fast while still exercising the
  // parser on real payload bytes.
  const auto fallback = size > 4 ? (static_cast<uint32_t>(data[4]) + 1) : 1;
  return fallback <= hard_limit ? fallback : static_cast<uint32_t>(hard_limit);
}

// Payload bytes for one frame. size == 0 must never dereference data: the
// byte is a NUL in that case, and the produced frame is still a structurally
// complete (header + payload) byte sequence.
std::string make_frame_payload(const uint8_t *data, size_t size,
                               uint32_t frame_len) {
  std::string payload;
  payload.reserve(frame_len);
  for (uint32_t i = 0; i < frame_len; i++) {
    payload.push_back(size > 0 ? static_cast<char>(data[i % size]) : '\0');
  }
  return payload;
}

std::string encode_frame(const std::string &payload) {
  std::string frame;
  frame.reserve(sizeof(uint32_t) + payload.size());
  uint32_t be_len = htonl(static_cast<uint32_t>(payload.size()));
  frame.append(reinterpret_cast<const char *>(&be_len), sizeof(be_len));
  frame.append(payload);
  return frame;
}

// A structurally valid production data frame: JSON object with a valid
// session id, so the parser accepts it and reaches gateway_handle_data
// (data_frames_received++). The payload is built from input bytes but
// escaped as JSON numbers so the frame is valid for every input.
std::string make_valid_frame(const uint8_t *data, size_t size) {
  std::string json = "{\"type\":\"data\",\"cid\":\"sess-001\",\"data\":{\"payload\":[";
  const size_t count = 1 + (size % 16);
  for (size_t i = 0; i < count; i++) {
    if (i > 0) {
      json.push_back(',');
    }
    json += std::to_string(size > 0 ? data[i % size] : 0);
  }
  json += "]}}";
  return encode_frame(json);
}

// One fuzz iteration: run every scenario against its own fresh fixture. Scenarios
// cover: valid full frame, fragmented valid frame, coalesced valid frames,
// oversized header, truncated frame, invalid JSON and empty input.
bool fuzz_one_input(const uint8_t *data, size_t size) {
  const auto frame_len = derive_frame_length(data, size);
  auto payload = make_frame_payload(data, size, frame_len);
  auto frame = encode_frame(payload);

  // Full frame (valid JSON only when the input bytes happen to produce a
  // parseable payload; the structured valid frame below guarantees the
  // accepted path).
  if (!run_isolated_scenario(
          [&](FuzzGatewayFixture &fx) {
            append_and_dispatch(fx, frame.data(), frame.size());
          })) {
    return false;
  }

  // Structured valid frame: guaranteed accepted (data_frames_received).
  auto valid = make_valid_frame(data, size);
  if (!run_isolated_scenario(
          [&](FuzzGatewayFixture &fx) {
            append_and_dispatch(fx, valid.data(), valid.size());
          })) {
    return false;
  }

  // Fragment: split the valid frame at a deterministic point; dispatch
  // between the two parts so the partial buffer path is exercised.
  if (valid.size() > 1) {
    const size_t split = 1 + (size % (valid.size() - 1));
    if (!run_isolated_scenario([&](FuzzGatewayFixture &fx) {
          if (append_and_dispatch(fx, valid.data(), split)) {
            append_and_dispatch(fx, valid.data() + split,
                                valid.size() - split);
          }
        })) {
      return false;
    }
  }

  // Coalesced: two valid frames back to back.
  if (valid.size() < 4096) {
    std::string coalesced = valid + valid;
    if (!run_isolated_scenario([&](FuzzGatewayFixture &fx) {
          append_and_dispatch(fx, coalesced.data(), coalesced.size());
        })) {
      return false;
    }
  }

  // Malicious length: header claims a huge payload; the parser must reject
  // it without unbounded allocation (removes the master).
  {
    uint32_t huge = 0xFFFFFFFFu;
    std::string malicious(sizeof(huge), '\0');
    std::memcpy(malicious.data(), &huge, sizeof(huge));
    if (!run_isolated_scenario([&](FuzzGatewayFixture &fx) {
          append_and_dispatch(fx, malicious.data(), malicious.size());
        })) {
      return false;
    }
  }

  // Truncated frame: retain the original length header but provide only half
  // the payload, so the parser must keep a bounded partial frame buffered.
  if (payload.size() > 2) {
    const auto truncated_size = sizeof(uint32_t) + payload.size() / 2;
    if (!run_isolated_scenario([&](FuzzGatewayFixture &fx) {
          append_and_dispatch(fx, frame.data(), truncated_size);
        })) {
      return false;
    }
  }

  // Invalid JSON: parse must reject it (json_frames_rejected).
  {
    const std::string broken = "{\"type\":\"data\",\"cid\":";
    auto invalid = encode_frame(broken);
    if (!run_isolated_scenario([&](FuzzGatewayFixture &fx) {
          append_and_dispatch(fx, invalid.data(), invalid.size());
        })) {
      return false;
    }
  }

  // Empty input: zero bytes must be a no-op, never a dereference.
  if (!run_isolated_scenario(
          [](FuzzGatewayFixture &fx) { append_and_dispatch(fx, "", 0); })) {
    return false;
  }
  return true;
}

struct SmokeCounters {
  uint64_t frames_received{0};
  uint64_t length_rejected{0};
  uint64_t json_rejected{0};
  uint64_t buffer_rejected{0};
};

SmokeCounters read_counters() {
  SmokeCounters c;
  c.frames_received = g_gateway_runtime_counters.data_frames_received.load(
      std::memory_order_relaxed);
  c.length_rejected =
      g_gateway_runtime_counters.read_dispatch_frame_length_rejected.load(
          std::memory_order_relaxed);
  c.json_rejected = g_gateway_runtime_counters.json_frames_rejected.load(
      std::memory_order_relaxed);
  c.buffer_rejected =
      g_gateway_runtime_counters.read_dispatch_buffer_limit_rejected.load(
          std::memory_order_relaxed);
  return c;
}

int run_smoke() {
  if (!init_driver_once()) {
    std::fprintf(stderr, "gateway_fuzz smoke: driver init failed\n");
    return 2;
  }
  const size_t kSmokeInputs = 256;
  const auto baseline = read_counters();
  for (size_t i = 0; i < kSmokeInputs; i++) {
    std::vector<uint8_t> data;
    const size_t len = static_cast<size_t>(next_random() % 2048);
    data.reserve(len);
    for (size_t j = 0; j < len; j++) {
      data.push_back(static_cast<uint8_t>(next_random() & 0xff));
    }
    // Seed with structured prefixes occasionally to hit the parser deeper.
    if ((i % 4) == 0) {
      const std::string json_prefix = "{\"type\":\"CHAT\",\"payload\":{\"messages\":[";
      data.insert(data.begin(), json_prefix.begin(), json_prefix.end());
    }
    if (!fuzz_one_input(data.data(), data.size())) {
      std::fprintf(stderr, "gateway_fuzz smoke: fixture creation failed\n");
      return 2;
    }
  }

  const auto after = read_counters();
  const SmokeCounters delta{after.frames_received - baseline.frames_received,
                            after.length_rejected - baseline.length_rejected,
                            after.json_rejected - baseline.json_rejected,
                            after.buffer_rejected - baseline.buffer_rejected};

  // Hard assertions: the counters must prove the parser ran both paths.
  bool ok = true;
  if (delta.frames_received == 0) {
    std::fprintf(stderr, "FAIL: no valid frame reached the data path\n");
    ok = false;
  }
  if (delta.length_rejected == 0) {
    std::fprintf(stderr, "FAIL: no oversized frame was rejected\n");
    ok = false;
  }
  if (delta.json_rejected == 0) {
    std::fprintf(stderr, "FAIL: no invalid JSON was rejected\n");
    ok = false;
  }
  const size_t masters_left = gateway_master_count_for_test();
  if (masters_left != 0) {
    std::fprintf(stderr, "FAIL: %zu master(s) leaked after teardown\n",
                 masters_left);
    ok = false;
  }
  const int64_t pending_left = gateway_read_dispatch_pending_for_test();
  if (pending_left != 0) {
    std::fprintf(stderr, "FAIL: %lld read-dispatch pending counter(s) leaked\n",
                 static_cast<long long>(pending_left));
    ok = false;
  }

  std::printf("gateway_fuzz smoke: %zu inputs, frames_received=%llu, "
              "length_rejected=%llu, json_rejected=%llu, "
              "buffer_rejected=%llu, masters_left=%zu, pending_left=%lld\n",
              kSmokeInputs,
              static_cast<unsigned long long>(delta.frames_received),
              static_cast<unsigned long long>(delta.length_rejected),
              static_cast<unsigned long long>(delta.json_rejected),
              static_cast<unsigned long long>(delta.buffer_rejected),
              masters_left, static_cast<long long>(pending_left));
  return ok ? 0 : 1;
}

}  // namespace

// Exposed for the standalone smoke entry (gateway_fuzz_smoke_main.cc).
int gateway_fuzz_smoke_main(int /*argc*/, char ** /*argv*/) {
  return run_smoke();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!init_driver_once()) {
    // Never report "success" for uninitialized runs: abort so the fuzzer
    // stops instead of counting inputs against a parser that never started.
    std::fprintf(stderr, "gateway_fuzz: driver init failed; aborting\n");
    std::abort();
  }
  if (!fuzz_one_input(data, size)) {
    std::abort();
  }
  return 0;
}
