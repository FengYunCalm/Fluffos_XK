// Standalone smoke entry for the gateway frame parser fuzz harness
// (gateway_fuzz_smoke). The libFuzzer target (gateway_fuzz) has no main:
// the fuzzer runtime provides it. Keeping main() in a separate shim lets
// the default build graph contain only the smoke binary while the fuzzer
// target is created exclusively for clang + GATEWAY_FUZZ_LIBFUZZER=ON.
#include <cstdio>
#include <cstring>

int gateway_fuzz_smoke_main(int argc, char **argv);

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--help") == 0) {
      std::printf("usage: %s  (deterministic smoke; libFuzzer builds use "
                  "gateway_fuzz with fuzzer flags and a corpus dir)\n",
                  argv[0]);
      return 0;
    }
  }
  return gateway_fuzz_smoke_main(argc, argv);
}
