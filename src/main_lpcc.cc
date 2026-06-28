#include "base/std.h"

#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <event2/event.h>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <nlohmann/json.hpp>

#include "mainlib.h"

#include "compiler/internal/lpc_modern_profile.h"
#include "thirdparty/scope_guard/scope_guard.hpp"
#include "compiler/internal/disassembler.h"
#include "base/internal/rc.h"
#include "base/internal/tracing.h"
#include "vm/vm.h"

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
  output["finding_count"] = report.findings.size();
  output["rules"] = nlohmann::json::array();
  for (const auto &rule : lpc_owner_audit_rules()) {
    output["rules"].push_back({
        {"code", rule.code},
        {"category", rule.category},
        {"severity", rule.severity},
        {"message", rule.message},
    });
  }
  output["findings"] = nlohmann::json::array();
  for (const auto &finding : report.findings) {
    output["findings"].push_back({
        {"code", finding.code},
        {"category", finding.category},
        {"severity", finding.severity},
        {"message", finding.message},
        {"line", finding.line},
        {"column", finding.column},
        {"excerpt", finding.excerpt},
    });
  }

  std::cout << output.dump(2) << std::endl;
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc == 5 && std::string(argv[1]) == "--owner-audit" && std::string(argv[2]) == "--format=json") {
    return run_owner_audit_json(argv[3], argv[4]);
  }

  Tracer::start("trace_lpcc.json");

  Tracer::setThreadName("lpcc main");

  ScopedTracer const trace(__PRETTY_FUNCTION__);

  if (argc != 3) {
    print_usage();
    return 1;
  }

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

  current_object = master_ob;
  const char* file = argv[2];
  struct object_t* obj = nullptr;

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
