// Gateway frame parser fuzz target (T15).
//
// libFuzzer-compatible entry point that feeds arbitrary bytes into the
// gateway read path via gateway_append_read_bytes_for_test(). The harness
// must never crash, hang, or leak on malformed input; ASan/UBSan builds
// turn memory errors into failures.
//
// Build (libFuzzer + ASan, clang):
//   cmake -B build-fuzz -DENABLE_ASAN=ON -DCMAKE_C_COMPILER=clang \
//         -DCMAKE_CXX_COMPILER=clang++ -DMARCH_NATIVE=OFF -DENABLE_LTO=OFF
//   cmake --build build-fuzz --target gateway_fuzz -j
//   build-fuzz/src/tests/gateway_fuzz -runs=1000 -max_len=4096
//
// Smoke (no libFuzzer, standalone deterministic loop):
//   build/src/tests/gateway_fuzz --smoke

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

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

void ensure_fuzz_master() {
  if (!fuzz_master) {
    // A real bufferevent pair is required: the register helper rejects
    // nullptr bev, and the read path drives event-base callbacks.
    if (bufferevent_pair_new(g_event_base, BEV_OPT_CLOSE_ON_FREE, fuzz_bev_pair) != 0) {
      std::fprintf(stderr, "gateway_fuzz: bufferevent_pair_new failed\n");
      std::exit(2);
    }
    fuzz_master = gateway_register_master_for_test(4242, fuzz_bev_pair[0]);
  }
}

int run_smoke() {
  // The gateway read path needs the driver event base and runtime state,
  // mirroring the DriverTest fixture: chdir into the testsuite and init.
  if (chdir(TESTSUITE_DIR) != 0) {
    std::fprintf(stderr, "gateway_fuzz: chdir %s failed\n", TESTSUITE_DIR);
    return 2;
  }
  if (!init_main("etc/config.test")) {
    std::fprintf(stderr, "gateway_fuzz: init_main failed\n");
    return 2;
  }
  const size_t kSmokeInputs = 256;
  size_t rejected = 0;
  for (size_t i = 0; i < kSmokeInputs; i++) {
    ensure_fuzz_master();
    std::string data;
    const size_t len = static_cast<size_t>(next_random() % 2048);
    data.reserve(len);
    for (size_t j = 0; j < len; j++) {
      data.push_back(static_cast<char>(next_random() & 0xff));
    }
    // Seed with structured prefixes occasionally to hit the parser deeper.
    if ((i % 4) == 0) {
      data = "{\"type\":\"CHAT\",\"payload\":{\"messages\":[" + data + "]}}";
    }
    bool ok = gateway_append_read_bytes_for_test(fuzz_master, data.data(), data.size());
    if (!ok) {
      rejected++;
    }
  }
  std::printf("gateway_fuzz smoke: %zu inputs, %zu rejected, no crash/hang\n", kSmokeInputs,
              rejected);
  return 0;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ensure_fuzz_master();
  // Bounded replay: also try frame-aligned slices to exercise resync paths.
  gateway_append_read_bytes_for_test(fuzz_master, reinterpret_cast<const char *>(data), size);
  if (size > 4) {
    gateway_append_read_bytes_for_test(fuzz_master, reinterpret_cast<const char *>(data) + 1,
                                       size - 2);
  }
  return 0;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--smoke") == 0) {
      return run_smoke();
    }
    if (std::strcmp(argv[i], "--help") == 0) {
      std::printf("usage: %s [--smoke]  (libFuzzer mode: pass fuzzer flags)\n", argv[0]);
      return 0;
    }
  }
  // Without --smoke, behave as a libFuzzer target: main is unused by the
  // fuzzer runtime, so fall back to smoke for standalone invocation.
  return run_smoke();
}
