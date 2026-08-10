// Gateway frame parser fuzz targets (T15/F08).
//
// Two targets:
//   gateway_fuzz_smoke  - standalone deterministic smoke (no libFuzzer).
//   gateway_fuzz        - real libFuzzer target (no custom main) that
//                         constructs production protocol frames from the
//                         input and drives the real buffered-frame dispatch.
//
// Build (libFuzzer + ASan/UBSan, clang):
//   cmake -B build-fuzz -DENABLE_ASAN=ON -DENABLE_UBSAN=ON \
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
//         -DMARCH_NATIVE=OFF -DENABLE_LTO=OFF
//   cmake --build build-fuzz --target gateway_fuzz -j
//   build-fuzz/src/tests/gateway_fuzz -runs=10000 -max_len=4096 -timeout=5
//
// Smoke (no libFuzzer, standalone deterministic loop):
//   build/src/tests/gateway_fuzz_smoke

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
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

GatewayMaster *fuzz_master = nullptr;
bufferevent *fuzz_bev_pair[2] = {nullptr, nullptr};

// Fresh master per input: dispatch may remove the master (invalid frame,
// ack failure), and reusing a freed pointer is a use-after-free. The cost is
// one pair allocation per fuzz iteration, which is negligible relative to
// the parse work. The master owns the bev pair (BEV_OPT_CLOSE_ON_FREE), so
// after a removal the bev is already freed and must not be freed again.
void ensure_fuzz_master() {
  fuzz_master = nullptr;
  gateway_remove_master_for_test(4242);
  // A real bufferevent pair is required: the register helper rejects
  // nullptr bev, and the read path drives event-base callbacks.
  if (bufferevent_pair_new(g_event_base, BEV_OPT_CLOSE_ON_FREE, fuzz_bev_pair) != 0) {
    std::fprintf(stderr, "gateway_fuzz: bufferevent_pair_new failed\n");
    std::exit(2);
  }
  fuzz_master = gateway_register_master_for_test(4242, fuzz_bev_pair[0]);
  if (!fuzz_master) {
    std::fprintf(stderr, "gateway_fuzz: register_master failed\n");
    std::exit(2);
  }
}

bool init_driver_once() {
  // The gateway read path needs the driver event base and runtime state,
  // mirroring the DriverTest fixture: chdir into the testsuite and init.
  static bool initialized = false;
  if (initialized) {
    return true;
  }
  if (chdir(TESTSUITE_DIR) != 0) {
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

std::string make_frame_payload(const uint8_t *data, size_t size, uint32_t frame_len) {
  std::string payload;
  payload.reserve(frame_len);
  for (uint32_t i = 0; i < frame_len; i++) {
    payload.push_back(static_cast<char>(data[i % (size > 0 ? size : 1)]));
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

// One fuzz iteration: derive a frame length, build a production-encoded
// frame, and feed it through the real buffered-frame dispatch. Also exercise
// fragment, coalesced and oversized variants of the same input.
void fuzz_one_input(const uint8_t *data, size_t size) {
  ensure_fuzz_master();
  const auto frame_len = derive_frame_length(data, size);
  auto payload = make_frame_payload(data, size, frame_len);
  auto frame = encode_frame(payload);

  // Full frame.
  gateway_append_read_bytes_for_test(fuzz_master, frame.data(), frame.size());
  gateway_dispatch_buffered_frames_for_test(fuzz_master, 16);

  // Fragment: split the frame at a deterministic point.
  if (frame.size() > 1) {
    const size_t split = 1 + (size % (frame.size() - 1));
    gateway_append_read_bytes_for_test(fuzz_master, frame.data(), split);
    gateway_dispatch_buffered_frames_for_test(fuzz_master, 16);
    gateway_append_read_bytes_for_test(fuzz_master, frame.data() + split,
                                       frame.size() - split);
    gateway_dispatch_buffered_frames_for_test(fuzz_master, 16);
  }

  // Coalesced: two frames back to back.
  if (frame.size() < 4096) {
    std::string coalesced = frame + frame;
    gateway_append_read_bytes_for_test(fuzz_master, coalesced.data(),
                                       coalesced.size());
    gateway_dispatch_buffered_frames_for_test(fuzz_master, 16);
  }

  // Malicious length: header claims a huge payload; the parser must reject
  // it without unbounded allocation.
  if (size >= sizeof(uint32_t)) {
    uint32_t huge = 0xFFFFFFFFu;
    std::string malicious(sizeof(huge), '\0');
    std::memcpy(malicious.data(), &huge, sizeof(huge));
    gateway_append_read_bytes_for_test(fuzz_master, malicious.data(),
                                       malicious.size());
    gateway_dispatch_buffered_frames_for_test(fuzz_master, 16);
  }

  // Truncated JSON payload.
  if (payload.size() > 2) {
    auto truncated = encode_frame(payload.substr(0, payload.size() / 2));
    gateway_append_read_bytes_for_test(fuzz_master, truncated.data(),
                                       truncated.size());
    gateway_dispatch_buffered_frames_for_test(fuzz_master, 16);
  }
}

int run_smoke() {
  if (!init_driver_once()) {
    return 2;
  }
  const size_t kSmokeInputs = 256;
  size_t rejected = 0;
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
    const auto before_rejected =
        g_gateway_runtime_counters.read_dispatch_buffer_limit_rejected.load(
            std::memory_order_relaxed);
    fuzz_one_input(data.data(), data.size());
    const auto after_rejected =
        g_gateway_runtime_counters.read_dispatch_buffer_limit_rejected.load(
            std::memory_order_relaxed);
    if (after_rejected > before_rejected) {
      rejected++;
    }
  }
  std::printf("gateway_fuzz smoke: %zu inputs, %zu buffer-rejected, "
              "dispatch_runs=%llu, length_rejected=%llu, "
              "json_rejected=%llu, frames_received=%llu, no crash/hang\n",
              kSmokeInputs, rejected,
              static_cast<unsigned long long>(
                  g_gateway_runtime_counters.read_dispatch_runs.load(
                      std::memory_order_relaxed)),
              static_cast<unsigned long long>(
                  g_gateway_runtime_counters.read_dispatch_frame_length_rejected.load(
                      std::memory_order_relaxed)),
              static_cast<unsigned long long>(
                  g_gateway_runtime_counters.json_frames_rejected.load(
                      std::memory_order_relaxed)),
              static_cast<unsigned long long>(
                  g_gateway_runtime_counters.data_frames_received.load(
                      std::memory_order_relaxed)));
  return 0;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!init_driver_once()) {
    return 0;
  }
  fuzz_one_input(data, size);
  return 0;
}

#ifndef GATEWAY_FUZZ_NO_MAIN
int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--help") == 0) {
      std::printf("usage: %s  (deterministic smoke; libFuzzer builds use "
                  "gateway_fuzz with fuzzer flags)\n",
                  argv[0]);
      return 0;
    }
  }
  return run_smoke();
}
#endif
