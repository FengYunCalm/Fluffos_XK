#include "base/package_api.h"

#include "backend.h"
#include "mainlib.h"
#include "vm/internal/apply.h"
#include "vm/internal/base/apply_cache.h"
#include "vm/internal/base/interpret.h"
#include "vm/internal/base/mapping.h"
#include "vm/internal/base/machine.h"
#include "vm/internal/base/object.h"
#include "vm/internal/lpc_vm_profile.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

namespace {
using Clock = std::chrono::steady_clock;

struct Metric {
  std::string name;
  long long value{0};
};

struct StringMetric {
  std::string name;
  std::string value;
};

struct Report {
  std::vector<Metric> metrics;
  std::vector<StringMetric> strings;

  void add(const std::string &name, long long value) { metrics.push_back({name, value}); }
  void add_string(const std::string &name, std::string value) { strings.push_back({name, std::move(value)}); }
};

long long elapsed_ns(Clock::time_point start) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count();
}

long long percentile(std::vector<long long> samples, double rank) {
  if (samples.empty()) {
    return 0;
  }
  std::sort(samples.begin(), samples.end());
  const auto index = static_cast<size_t>((samples.size() - 1) * rank);
  return samples[index];
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

object_t *clone_object_for_bench(const char *path) {
  error_context_t econ{};
  object_t *object = nullptr;
  object_t *saved_current_object = current_object;
  if (current_object == nullptr && master_ob != nullptr) {
    current_object = master_ob;
  }
  save_context(&econ);
  try {
    object = clone_object(path, 0);
    pop_context(&econ);
    current_object = saved_current_object;
  } catch (...) {
    restore_context(&econ);
    current_object = saved_current_object;
    throw std::runtime_error(std::string("clone_object failed for ") + path);
  }
  return object;
}

void destruct_object_for_bench(object_t *object) {
  if (object == nullptr || (object->flags & O_DESTRUCTED)) {
    return;
  }
  error_context_t econ{};
  object_t *saved_current_object = current_object;
  if (current_object == nullptr && master_ob != nullptr) {
    current_object = master_ob;
  }
  save_context(&econ);
  try {
    destruct_object(object);
    pop_context(&econ);
    current_object = saved_current_object;
  } catch (...) {
    restore_context(&econ);
    current_object = saved_current_object;
    throw std::runtime_error(std::string("destruct_object failed for ") + object->obname);
  }
}

std::string json_escape(const std::string &value) {
  std::ostringstream out;
  for (char ch : value) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        out << ch;
        break;
    }
  }
  return out.str();
}

std::string report_json(const Report &report) {
  std::ostringstream json;
  json << "{\n";
  json << "  \"schema\": \"" << kLpcVmBenchSchemaV1 << "\",\n";
  json << "  \"runtime\": {\n";
  for (size_t i = 0; i < report.strings.size(); i++) {
    json << "    \"" << json_escape(report.strings[i].name) << "\": \""
         << json_escape(report.strings[i].value) << "\"";
    json << (i + 1 == report.strings.size() ? "\n" : ",\n");
  }
  json << "  },\n";
  json << "  \"metrics\": {\n";
  for (size_t i = 0; i < report.metrics.size(); i++) {
    json << "    \"" << json_escape(report.metrics[i].name) << "\": " << report.metrics[i].value;
    json << (i + 1 == report.metrics.size() ? "\n" : ",\n");
  }
  json << "  }\n";
  json << "}\n";
  return json.str();
}

void write_json_report(const std::string &path, const std::string &json) {
  if (path.empty()) {
    return;
  }
  auto output_path = std::filesystem::path(path);
  if (output_path.has_parent_path()) {
    std::filesystem::create_directories(output_path.parent_path());
  }
  std::ofstream output(output_path);
  if (!output.is_open()) {
    throw std::runtime_error("failed to open benchmark json output: " + path);
  }
  output << json;
}

void run_apply_cache_bench(Report &report) {
  const long iterations = 512;
  lpc_vm_profile_reset();

  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone VM profile probe object");

  std::vector<long long> hit_samples;
  std::vector<long long> miss_samples;
  auto start = Clock::now();
  auto warm = apply_cache_lookup("dummy", probe->prog);
  require(warm.funp != nullptr, "warm apply cache lookup did not find dummy()");

  for (long i = 0; i < iterations; i++) {
    auto hit_start = Clock::now();
    auto hit = apply_cache_lookup("dummy", probe->prog);
    hit_samples.push_back(elapsed_ns(hit_start));
    require(hit.funp != nullptr, "apply cache hit lookup failed");

    auto miss_start = Clock::now();
    auto miss = apply_cache_lookup("__missing_lpc_vm_profile_probe__", probe->prog);
    miss_samples.push_back(elapsed_ns(miss_start));
    require(miss.funp == nullptr, "apply cache miss lookup unexpectedly resolved");
  }

  auto snapshot = lpc_vm_profile_snapshot();
  report.add("apply_cache_iterations", iterations);
  report.add("apply_cache_elapsed_ns", elapsed_ns(start));
  report.add("apply_cache_profile_lookups", static_cast<long long>(snapshot.apply_cache_lookup_count));
  report.add("apply_cache_profile_hits", static_cast<long long>(snapshot.apply_cache_hit_count));
  report.add("apply_cache_profile_misses", static_cast<long long>(snapshot.apply_cache_miss_count));
  report.add("apply_cache_table_builds", static_cast<long long>(snapshot.apply_cache_table_build_count));
  report.add("apply_cache_table_items", static_cast<long long>(snapshot.apply_cache_table_item_count));
  report.add("apply_cache_table_build_ns", static_cast<long long>(snapshot.apply_cache_table_build_ns));
  report.add("apply_dispatch_cache_lookups", static_cast<long long>(snapshot.apply_dispatch_cache_lookup_count));
  report.add("apply_dispatch_cache_hits", static_cast<long long>(snapshot.apply_dispatch_cache_hit_count));
  report.add("apply_dispatch_cache_epoch_invalidations",
             static_cast<long long>(snapshot.apply_dispatch_cache_epoch_invalidation_count));
  report.add("apply_cache_hit_latency_p50_ns", percentile(hit_samples, 0.50));
  report.add("apply_cache_hit_latency_p95_ns", percentile(hit_samples, 0.95));
  report.add("apply_cache_hit_latency_p99_ns", percentile(hit_samples, 0.99));
  report.add("apply_cache_miss_latency_p50_ns", percentile(miss_samples, 0.50));
  report.add("apply_cache_miss_latency_p95_ns", percentile(miss_samples, 0.95));
  report.add("apply_cache_miss_latency_p99_ns", percentile(miss_samples, 0.99));

  destruct_object_for_bench(probe);
}

void add_profile_snapshot_metrics(Report &report, const std::string &prefix,
                                  const LpcVmProfileSnapshot &snapshot) {
  report.add(prefix + "opcode_dispatch_count", static_cast<long long>(snapshot.opcode_dispatch_count));
  report.add(prefix + "efun_dispatch_count", static_cast<long long>(snapshot.efun_dispatch_count));
  report.add(prefix + "efun_dispatch_ns", static_cast<long long>(snapshot.efun_dispatch_ns));
  report.add(prefix + "call_other_dispatch_count", static_cast<long long>(snapshot.call_other_dispatch_count));
  report.add(prefix + "function_pointer_dispatch_count",
             static_cast<long long>(snapshot.function_pointer_dispatch_count));
  report.add(prefix + "function_pointer_efun_dispatch_count",
             static_cast<long long>(snapshot.function_pointer_efun_dispatch_count));
  report.add(prefix + "parser_action_lookup_count", static_cast<long long>(snapshot.parser_action_lookup_count));
  report.add(prefix + "parser_action_match_count", static_cast<long long>(snapshot.parser_action_match_count));
  report.add(prefix + "mapping_lookup_count", static_cast<long long>(snapshot.mapping_lookup_count));
  report.add(prefix + "mapping_insert_lookup_count", static_cast<long long>(snapshot.mapping_insert_lookup_count));
  report.add(prefix + "string_push_count", static_cast<long long>(snapshot.string_push_count));
}

void run_hot_path_profile_bench(Report &report) {
  const long iterations = 128;
  lpc_vm_profile_reset();

  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone VM hot path probe object");

  std::vector<long long> call_other_samples;
  auto start = Clock::now();
  for (long i = 0; i < iterations; i++) {
    auto call_start = Clock::now();
    push_object(probe);
    auto *result = safe_apply("call_target", probe, 1, ORIGIN_DRIVER);
    call_other_samples.push_back(elapsed_ns(call_start));
    require(result != nullptr, "call_target() did not return");
  }

  mapping_t *map = allocate_mapping(4);
  add_mapping_pair(map, "alpha", 1);
  add_mapping_pair(map, "beta", 2);
  require(find_string_in_mapping(map, "alpha")->type == T_NUMBER, "mapping alpha lookup failed");
  require(find_string_in_mapping(map, "missing")->type == T_NUMBER,
          "mapping missing lookup did not return undefined sentinel");
  free_mapping(map);

  copy_and_push_string("lpc_vm_profile_string_copy");
  pop_stack();
  share_and_push_string("lpc_vm_profile_string_shared");
  pop_stack();
  push_constant_string("lpc_vm_profile_string_constant");
  pop_stack();

  auto snapshot = lpc_vm_profile_snapshot();
  report.add("hot_path_iterations", iterations);
  report.add("hot_path_elapsed_ns", elapsed_ns(start));
  report.add("hot_path_call_other_latency_p50_ns", percentile(call_other_samples, 0.50));
  report.add("hot_path_call_other_latency_p95_ns", percentile(call_other_samples, 0.95));
  report.add("hot_path_call_other_latency_p99_ns", percentile(call_other_samples, 0.99));
  add_profile_snapshot_metrics(report, "hot_path_profile_", snapshot);

  destruct_object_for_bench(probe);
}

void print_text_report(const Report &report, const std::string &json_path) {
  std::cout << "lpc_vm_bench: schema=" << kLpcVmBenchSchemaV1 << "\n";
  for (const auto &metric : report.metrics) {
    std::cout << metric.name << "=" << metric.value << "\n";
  }
  if (!json_path.empty()) {
    std::cout << "json_report=" << json_path << "\n";
  }
}
}  // namespace

int main(int argc, char **argv) {
  std::string json_path;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--json" && i + 1 < argc) {
      json_path = argv[++i];
    } else if (arg == "--help") {
      std::cout << "usage: lpc_vm_bench [--json path]\n";
      return 0;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      return 2;
    }
  }

  try {
    if (!json_path.empty()) {
      json_path = std::filesystem::absolute(json_path).string();
    }
    if (chdir(TESTSUITE_DIR) != 0) {
      std::ostringstream error;
      error << "failed to chdir to " << TESTSUITE_DIR << ": " << strerror(errno);
      throw std::runtime_error(error.str());
    }
    init_main("etc/config.test");
    vm_start();

    Report report;
    report.add_string("mode", "diagnostic");
    report.add_string("profile_schema", kLpcVmProfileSchemaV1);
    report.add_string("dispatch_cache_probe", "apply_cache_lookup_v1");
    report.add_string("hot_path_profile_probe", "opcode_efun_call_other_mapping_string_v1");

    run_apply_cache_bench(report);
    run_hot_path_profile_bench(report);

    auto json = report_json(report);
    write_json_report(json_path, json);
    print_text_report(report, json_path);
    std::cout << json;
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "lpc_vm_bench failed: " << error.what() << "\n";
    return 1;
  }
}
