// #1247 C-S2: scratch-path allocation hotspot benchmark (plan layer 1).
//
// Exercises the scratch_* API surface (token copies, string
// accumulation, macro-argument blocks, joins) and reports per-round wall
// time plus process-heap growth via mallinfo2. Pre-C-S1 trees allocate
// per call (old scratchpad); post-C-S1 the shim bumps the compile arena,
// so heap growth should flatten after the first round (retained pool
// reuse). This layer explains allocation hotspots; it does not by itself
// decide rollout (that is bench_compile's throughput gate).
//
// Usage: bench_scratchpad [--rounds N]

#include "base/package_api.h"

#include "compiler/internal/compile_arena.h"
#include "compiler/internal/scratchpad.h"

#include <malloc.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

// Only meaningful with glibc malloc (uordblks is 0 under jemalloc,
// which this project links by default); kept for glibc-only builds.
static size_t heap_used() {
  struct mallinfo2 mi = mallinfo2();
  return mi.uordblks;
}

int main(int argc, char **argv) {
  int rounds = 5;
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--rounds" && i + 1 < argc) {
      rounds = atoi(argv[++i]);
    } else if (std::string(argv[i]) == "--help") {
      std::printf("usage: bench_scratchpad [--rounds N]\n");
      return 0;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return 2;
    }
  }
  if (rounds < 1) {
    rounds = 1;
  }

  const char *tokens[] = {"if",       "return", "string", "mapping", "int",
                          "void",     "foreach", "switch", "case",    "default"};
  std::string acc;
  for (int i = 0; i < 200; i++) {
    acc += "0123456789abcdef";
  }
  std::string macro;
  for (int i = 0; i < 50; i++) {
    macro += "((a) > (b) ? (a) : (b)) + ";
  }

  std::vector<double> round_secs;
  std::vector<size_t> round_heap;
  for (int r = 0; r < rounds; r++) {
    compile_arena::begin();
    auto t0 = Clock::now();
    for (int i = 0; i < 20000; i++) {
      char *s = scratch_copy(tokens[i % 10]);
      (void)s;
    }
    for (int i = 0; i < 2000; i++) {
      char *s = scratch_copy(acc.c_str());
      (void)s;
    }
    for (int i = 0; i < 2000; i++) {
      char *s = scratch_alloc(64 + (i % 7));
      (void)s;
    }
    for (int i = 0; i < 500; i++) {
      char *a = scratch_copy("prefix_");
      char *b = scratch_copy(macro.c_str());
      char *j = scratch_join(a, b);
      (void)j;
    }
    auto t1 = Clock::now();
    round_secs.push_back(std::chrono::duration<double>(t1 - t0).count());
    round_heap.push_back(heap_used());
    compile_arena::end();
  }

  double total_secs = std::accumulate(round_secs.begin(), round_secs.end(), 0.0);
  std::printf("bench_scratchpad: rounds=%d\n", rounds);
  for (int r = 0; r < rounds; r++) {
    std::printf("round %d: %.4f s heap_uordblks=%zu\n", r, round_secs[r], round_heap[r]);
  }
  std::printf("total: %.4f s\n", total_secs);
  if (rounds > 1) {
    std::printf("heap_growth_after_first: %ld bytes\n",
                static_cast<long>(round_heap.back()) - static_cast<long>(round_heap[0]));
  }
  // The compile corpus never crosses the 1MB base chunk (vacuous pass);
  // this layer is where chunk behavior is actually exercised.
  std::printf("arena: chunk_mallocs=%zu retained_chunks=%zu retained_heap_bytes=%zu "
              "peak_cycle_bytes=%zu resets=%zu\n",
              compile_arena::chunk_mallocs(), compile_arena::retained_chunks(),
              compile_arena::retained_heap_bytes(), compile_arena::peak_cycle_bytes(),
              compile_arena::reset_count());
  return 0;
}
