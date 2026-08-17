#include "base/std.h"

#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <event2/event.h>
#include <iostream>
#include <iterator>
#include <string>
#include <string>
#include <vector>
#include <unistd.h>
#include <nlohmann/json.hpp>

#include "mainlib.h"

#include "compiler/internal/lpc_modern_profile.h"
#include "thirdparty/scope_guard/scope_guard.hpp"
#include "compiler/internal/disassembler.h"
#include "base/internal/rc.h"
#include "base/internal/tracing.h"
#include "vm/vm.h"
#include "vm/internal/base/scoped_current_object_as_master.h"

namespace {
void print_usage() {
  std::cerr << "Usage: lpcc config_file lpc_file\n"
            << "       lpcc --owner-audit --format=json config_file lpc_file\n";
}

int run_owner_audit_json(const char *config_file, const char *lpc_file) {
  std::ifstream input(lpc_file, std::ios::binary);
  if (!input) {
    std::cerr << "Fail to read LPC file " << lpc_file << ".\n";
    return 1;
  }
  std::string source((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  auto report = lpc_owner_audit_source(source);

  nlohmann::json output;
  output["schema"] = kLpcOwnerAuditSchemaV1;
  output["success"] = true;
  output["config_file"] = config_file;
  output["file"] = lpc_file;
  output["modern_lpc"] = report.modern_lpc;
  output["strict_owner"] = report.strict_owner;
  output["source_encoding_schema"] = kLpcSourceEncodingSchemaV1;
  output["source_encoding"] = report.source_encoding;
  output["vm_internal_string_encoding"] = kLpcInternalStringEncoding;
  output["transcoded"] = report.transcoded;
  output["invalid_sequence_count"] = report.invalid_sequence_count;
  output["finding_count"] = report.findings.size();
  output["rules"] = nlohmann::json::array();
  for (const auto &rule : lpc_owner_audit_rules()) {
    output["rules"].push_back({
        {"code", rule.code},
        {"category", rule.category},
        {"severity", rule.severity},
        {"message", rule.message},
        {"suggestion", rule.suggestion},
    });
  }
  output["findings"] = nlohmann::json::array();
  for (const auto &finding : report.findings) {
    output["findings"].push_back({
        {"code", finding.code},
        {"category", finding.category},
        {"severity", finding.severity},
        {"message", finding.message},
        {"suggestion", finding.suggestion},
        {"line", finding.line},
        {"column", finding.column},
        {"excerpt", finding.excerpt},
    });
  }

  std::cout << output.dump(2) << std::endl;
  return 0;
}
}  // namespace

static int lpcc_main(int argc, char** argv) {
  bool flag_batch = false;
  std::vector<const char*> batch_files;
  if (argc == 5 && std::string(argv[1]) == "--owner-audit" && std::string(argv[2]) == "--format=json") {
    return run_owner_audit_json(argv[3], argv[4]);
  }
  if (argc >= 3 && std::string(argv[1]) == "--batch") {
    flag_batch = true;
    // argv[2] is the config file (consumed by get_argument below); the rest
    // are files to compile.
    for (int i = 3; i < argc; i++) {
      batch_files.push_back(argv[i]);
    }
  } else if (argc != 3) {
    print_usage();
    return 1;
  }

  Tracer::start("trace_lpcc.json");

  Tracer::setThreadName("lpcc main");

  ScopedTracer const trace(__PRETTY_FUNCTION__);

  Tracer::begin("init_main", EventCategory::DEFAULT);

  // Initialize libevent, This should be done before executing LPC.
  auto config = get_argument(0, argc, argv);
  auto* base = init_main(config);

  Tracer::end("init_main", EventCategory::DEFAULT);

  // Start running.
  {
    ScopedTracer const tracer("vm_start");

    vm_start();
  }

  ScopedCurrentObjectAsMaster master_scope_main;
  const char* file = nullptr;
  struct object_t* obj = nullptr;

  if (flag_batch) {
    // Compile MANY files against this ONE VM boot (master/simul_efun loaded
    // once above) instead of paying a fresh boot per file. Reads
    // newline-separated paths from stdin when no files are given.
    std::vector<std::string> files(batch_files.begin(), batch_files.end());
    if (files.empty()) {
      std::string line;
      while (std::getline(std::cin, line)) {
        if (!line.empty()) files.push_back(line);
      }
    }
    int failed = 0;
    for (const auto& f : files) {
      printf("===== %s =====\n", f.c_str());
      fflush(stdout);

      // set_eval() arms a real OS timer (see eval_limit.cc) that isn't reset
      // just by looping here -- without this, elapsed wall-clock time keeps
      // accumulating across every file's compile in this one process. The
      // real driver rearms this before every top-level command/heartbeat;
      // do the same per batch file.
      set_eval(max_eval_cost);

      ScopedCurrentObjectAsMaster master_scope_batch;
      struct object_t* bobj = nullptr;
      error_context_t econ{};
      save_context(&econ);
      try {
        bobj = find_object(f.c_str());
      } catch (...) {
        restore_context(&econ);
      }
      pop_context(&econ);
      ScopedCurrentObjectAsMaster master_scope_after;

      bool ok = bobj != nullptr && bobj->prog != nullptr;
      if (!ok) {
        fprintf(stderr, "Fail to load object %s.\n", f.c_str());
        failed++;
      }
      printf("%s %s\n", ok ? "PASS" : "FAIL", f.c_str());
      fflush(stdout);
    }
    Tracer::collect();
    clear_state();
    return failed > 0 ? 1 : 0;
  }

  file = argv[2];

  {
    ScopedTracer const tracer("find_object");

    error_context_t econ{};
    save_context(&econ);
    try {
      obj = find_object(file);
    } catch (...) {
      restore_context(&econ);
    }
    pop_context(&econ);
  }

  if (obj == nullptr || obj->prog == nullptr) {
    fprintf(stderr, "Fail to load object %s. \n", file);
    return 1;
  }

  {
    ScopedTracer const tracer("dump_prog");

    dump_prog(obj->prog, stdout, 1 | 2);
  }

  Tracer::collect();

  clear_state();

  return 0;
}


int main(int argc, char** argv) {
  // Nothing may throw past main() (json serialization errors, an LPC
  // error() unwind escaping the guarded compile) -- that would be
  // std::terminate/abort instead of a clean CLI failure.
  try {
    return lpcc_main(argc, argv);
  } catch (const std::exception& e) {
    fprintf(stderr, "lpcc: fatal: %s\n", e.what());
    return 1;
  } catch (...) {
    fprintf(stderr, "lpcc: fatal: unhandled exception\n");
    return 1;
  }
}
