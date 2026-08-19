// #1247 C-S2: compile throughput A/B benchmark.
//
// Compiles a fixed representative LPC corpus through the real
// compile_file() path (the same entry the loader uses) and reports
// throughput, round latencies, peak RSS and -- when the compile arena
// exists (post C-S1) -- arena chunk/retained statistics.
//
// Usage: bench_compile <rounds> [corpus-dir]
//   - runs from the testsuite directory (chdir + init_main like
//     owner_runtime_bench), corpus defaults to tools/perf/corpus
//   - rounds: number of full-corpus passes (default 5)

#include "base/package_api.h"

#include "backend.h"
#include "compiler/internal/LexStream.h"
#include "compiler/internal/compiler.h"
#include "mainlib.h"
#include "vm/internal/base/program.h"

#include "compiler/internal/compile_arena.h"

#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

static long peak_rss_kb() {
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) != 0) {
    return -1;
  }
  return ru.ru_maxrss;
}

static int compile_one(const fs::path &f) {
  int fd = open(f.c_str(), O_RDONLY);
  if (fd < 0) {
    return -1;
  }
  auto stream = std::make_unique<FileLexStream>(fd);
  program_t *prog = nullptr;
  error_context_t econ{};
  save_context(&econ);
  try {
    prog = compile_file(std::move(stream), f.c_str());
    pop_context(&econ);
  } catch (...) {
    // error() threw (simulate.cc:2325); restore the error context like
    // test_lpc.cc does. The stream dtor ran during unwind (fd closed);
    // compile_file's RAII DEFERs restored guard/current_file and ended
    // the arena scope, so the next compile is unaffected.
    restore_context(&econ);
    return -1;
  }
  if (!prog) {
    // Parse error / inherit_file abandon path: epilog returns nullptr
    // (compiler.cc:2251-2255) without throwing. Count it as a failure.
    return -1;
  }
  free_prog(&prog);
  return 0;
}

int main(int argc, char **argv) {
  int rounds = 5;
  fs::path corpus_dir;
  fs::path json_path;
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--rounds" && i + 1 < argc) {
      rounds = atoi(argv[++i]);
    } else if (std::string(argv[i]) == "--corpus" && i + 1 < argc) {
      corpus_dir = argv[++i];
    } else if (std::string(argv[i]) == "--json" && i + 1 < argc) {
      json_path = argv[++i];
    } else if (std::string(argv[i]) == "--help") {
      std::printf("usage: bench_compile [--rounds N] [--corpus DIR] [--json PATH]\n");
      return 0;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return 2;
    }
  }
  if (rounds < 1) {
    rounds = 1;
  }
  if (corpus_dir.empty()) {
    corpus_dir = fs::path(TESTSUITE_DIR) / ".." / "tools" / "perf" / "corpus";
  }
  corpus_dir = fs::absolute(corpus_dir);

  // Full driver environment (shared string table, mem blocks, error
  // context, master/simul_efun load) -- same bootstrap as the benches
  // in src/tests.
  if (chdir(TESTSUITE_DIR) != 0) {
    std::perror("chdir(TESTSUITE_DIR)");
    return 2;
  }
  init_main("etc/config.test");

  std::vector<fs::path> files;
  if (fs::is_directory(corpus_dir)) {
    for (auto &e : fs::directory_iterator(corpus_dir)) {
      auto ext = e.path().extension();
      if (ext == ".c" || ext == ".lpc") {
        files.push_back(e.path());
      }
    }
  } else if (fs::is_regular_file(corpus_dir)) {
    files.push_back(corpus_dir);
  }
  std::sort(files.begin(), files.end());
  if (files.empty()) {
    std::fprintf(stderr, "no corpus files under %s\n", corpus_dir.c_str());
    return 2;
  }

  // Warmup pass (also absorbs the first-compile effects after master load).
  for (auto &f : files) {
    compile_one(f);
  }
  size_t warmup_mallocs = compile_arena::chunk_mallocs();

  std::vector<double> round_secs;
  std::vector<double> per_file_secs;  // ordered per-file latencies (last round)
  int failures = 0;
  for (int r = 0; r < rounds; r++) {
    auto t0 = Clock::now();
    for (auto &f : files) {
      auto f0 = Clock::now();
      if (compile_one(f) != 0) {
        failures++;
      }
      auto f1 = Clock::now();
      if (r == rounds - 1) {
        per_file_secs.push_back(std::chrono::duration<double>(f1 - f0).count());
      }
    }
    auto t1 = Clock::now();
    round_secs.push_back(std::chrono::duration<double>(t1 - t0).count());
  }

  std::sort(round_secs.begin(), round_secs.end());
  double total_secs = std::accumulate(round_secs.begin(), round_secs.end(), 0.0);
  double median = round_secs[rounds / 2];
  double p95 = round_secs[static_cast<size_t>(rounds * 0.95)];
  double p99 = round_secs[static_cast<size_t>(rounds * 0.99)];

  // Lifecycle degradation gate: mean per-file latency of the LAST 10% of
  // files (in time order) vs the FIRST 10% must stay <= 1.10 (plan C-S2).
  // per_file_secs is already in time order (last round).
  size_t tail_n = std::max<size_t>(1, per_file_secs.size() / 10);
  double head_mean =
      std::accumulate(per_file_secs.begin(), per_file_secs.begin() + tail_n, 0.0) / tail_n;
  double tail_mean =
      std::accumulate(per_file_secs.end() - tail_n, per_file_secs.end(), 0.0) / tail_n;
  double degradation = head_mean > 0 ? tail_mean / head_mean : 0.0;

  std::printf("bench_compile: files=%zu rounds=%d corpus=%s\n", files.size(), rounds,
              corpus_dir.c_str());
  std::printf("throughput: %.2f files/s (%.2f s total)\n", files.size() * rounds / total_secs,
              total_secs);
  std::printf("round_secs: median=%.4f p95=%.4f p99=%.4f min=%.4f max=%.4f\n", median, p95, p99,
              round_secs.front(), round_secs.back());
  std::printf("failures: %d\n", failures);
  std::printf("per_file_last_round: head10_mean=%.6f tail10_mean=%.6f degradation=%.4f\n",
              head_mean, tail_mean, degradation);
  std::printf("peak_rss_kb: %ld\n", peak_rss_kb());
  size_t final_mallocs = compile_arena::chunk_mallocs();
  std::printf("arena: warmup_chunk_mallocs=%zu final_chunk_mallocs=%zu delta=%zu\n",
              warmup_mallocs, final_mallocs, final_mallocs - warmup_mallocs);
  std::printf("arena: retained_chunks=%zu retained_heap_bytes=%zu cycle_bytes=%zu "
              "peak_cycle_bytes=%zu resets=%zu\n",
              compile_arena::retained_chunks(), compile_arena::retained_heap_bytes(),
              compile_arena::cycle_bytes(), compile_arena::peak_cycle_bytes(),
              compile_arena::reset_count());
  if (!json_path.empty()) {
    std::ofstream out(json_path);
    if (out) {
      out << "{\n";
      out << "  \"files\": " << files.size() << ",\n";
      out << "  \"rounds\": " << rounds << ",\n";
      out << "  \"corpus\": \"" << corpus_dir.string() << "\",\n";
      out << "  \"throughput_files_per_s\": " << files.size() * rounds / total_secs << ",\n";
      out << "  \"total_secs\": " << total_secs << ",\n";
      out << "  \"round_secs\": [";
      for (size_t i = 0; i < round_secs.size(); i++) {
        if (i) out << ", ";
        out << round_secs[i];
      }
      out << "],\n";
      out << "  \"per_file_secs_last_round\": [";
      for (size_t i = 0; i < per_file_secs.size(); i++) {
        if (i) out << ", ";
        out << per_file_secs[i];
      }
      out << "],\n";
      out << "  \"failures\": " << failures << ",\n";
      out << "  \"degradation\": " << degradation << ",\n";
      out << "  \"peak_rss_kb\": " << peak_rss_kb() << "\n";
      out << "  ,\"arena\": {\n";
      out << "    \"warmup_chunk_mallocs\": " << warmup_mallocs << ",\n";
      out << "    \"final_chunk_mallocs\": " << final_mallocs << ",\n";
      out << "    \"delta\": " << final_mallocs - warmup_mallocs << ",\n";
      out << "    \"retained_chunks\": " << compile_arena::retained_chunks() << ",\n";
      out << "    \"retained_heap_bytes\": " << compile_arena::retained_heap_bytes() << ",\n";
      out << "    \"cycle_bytes\": " << compile_arena::cycle_bytes() << ",\n";
      out << "    \"peak_cycle_bytes\": " << compile_arena::peak_cycle_bytes() << ",\n";
      out << "    \"resets\": " << compile_arena::reset_count() << "\n";
      out << "  }\n";
      out << "}\n";
    }
  }
  return failures > 0 ? 1 : 0;
}
