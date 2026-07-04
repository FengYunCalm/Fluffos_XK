#include "base/package_api.h"

#include "backend.h"
#include "mainlib.h"
#include "vm/internal/base/object.h"
#include "vm/internal/simulate.h"
#include "vm/object_handle.h"
#include "vm/owner.h"

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
#include <utility>
#include <vector>
#include <unistd.h>

namespace {
using Clock = std::chrono::steady_clock;
constexpr const char *kObjectStoreBenchSchemaV1 = "object_store_bench_v1";

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
  json << "  \"schema\": \"" << kObjectStoreBenchSchemaV1 << "\",\n";
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

void run_object_handle_resolve_bench(Report &report) {
  constexpr long object_count = 32;
  constexpr long iterations = 256;
  std::vector<object_t *> objects;
  std::vector<VMObjectHandle> handles;
  std::vector<long long> resolve_samples;
  std::vector<long long> owner_id_lookup_samples;
  std::vector<long long> owner_path_lookup_samples;
  long long owner_local_fast_path = 0;
  long long global_fallback_used = 0;

  objects.reserve(object_count);
  handles.reserve(object_count);
  for (long i = 0; i < object_count; i++) {
    auto *object = clone_object_for_bench("single/void");
    require(object != nullptr, "failed to clone object store bench probe");
    objects.push_back(object);
    vm_owner_set_id(object, (std::string("owner/bench/") + std::to_string(i % 4)).c_str());
    handles.push_back(vm_object_handle_with_intent(object, "object_store_bench"));
  }

  auto start = Clock::now();
  for (long pass = 0; pass < iterations; pass++) {
    for (const auto &handle : handles) {
      auto resolve_start = Clock::now();
      auto result = vm_object_handle_resolve_status(handle);
      resolve_samples.push_back(elapsed_ns(resolve_start));
      require(result.status == VMObjectHandleResolveStatus::kCurrent,
              std::string("object handle resolve failed: ") + vm_object_handle_resolve_status_name(result.status));
      owner_local_fast_path += result.owner_local_fast_path_used ? 1 : 0;
      global_fallback_used += result.resolved_via_global_index ? 1 : 0;

      auto id_start = Clock::now();
      require(vm_object_store_owner_resolve(handle.owner_id.c_str(), handle.object_id) == result.object,
              "owner id lookup failed");
      owner_id_lookup_samples.push_back(elapsed_ns(id_start));

      auto path_start = Clock::now();
      require(vm_object_store_owner_path_resolve(handle.owner_id.c_str(), handle.object_path.c_str()) == result.object,
              "owner path lookup failed");
      owner_path_lookup_samples.push_back(elapsed_ns(path_start));
    }
  }

  report.add("object_count", object_count);
  report.add("resolve_iterations", object_count * iterations);
  report.add("resolve_elapsed_ns", elapsed_ns(start));
  report.add("owner_local_fast_path_count", owner_local_fast_path);
  report.add("object_resolve_global_fallback_count", global_fallback_used);
  report.add("resolve_latency_p50_ns", percentile(resolve_samples, 0.50));
  report.add("resolve_latency_p95_ns", percentile(resolve_samples, 0.95));
  report.add("resolve_latency_p99_ns", percentile(resolve_samples, 0.99));
  report.add("owner_id_lookup_latency_p50_ns", percentile(owner_id_lookup_samples, 0.50));
  report.add("owner_id_lookup_latency_p95_ns", percentile(owner_id_lookup_samples, 0.95));
  report.add("owner_path_lookup_latency_p50_ns", percentile(owner_path_lookup_samples, 0.50));
  report.add("owner_path_lookup_latency_p95_ns", percentile(owner_path_lookup_samples, 0.95));

  for (auto *object : objects) {
    destruct_object_for_bench(object);
  }
}

void add_samples(Report &report, const std::string &prefix, const std::vector<long long> &samples) {
  report.add(prefix + "_count", static_cast<long long>(samples.size()));
  report.add(prefix + "_p50_ns", percentile(samples, 0.50));
  report.add(prefix + "_p95_ns", percentile(samples, 0.95));
  report.add(prefix + "_p99_ns", percentile(samples, 0.99));
}

void run_clone_destruct_lifecycle_bench(Report &report) {
  constexpr long iterations = 512;
  std::vector<long long> clone_samples;
  std::vector<long long> destruct_samples;
  clone_samples.reserve(iterations);
  destruct_samples.reserve(iterations);

  vm_object_lifecycle_perf_reset();
  vm_object_lifecycle_perf_set_enabled(true);
  auto total_start = Clock::now();
  for (long i = 0; i < iterations; i++) {
    auto clone_start = Clock::now();
    auto *object = clone_object_for_bench("single/void");
    clone_samples.push_back(elapsed_ns(clone_start));
    require(object != nullptr, "clone/destruct lifecycle bench clone failed");

    auto destruct_start = Clock::now();
    destruct_object_for_bench(object);
    destruct_samples.push_back(elapsed_ns(destruct_start));
  }
  auto total_elapsed = elapsed_ns(total_start);
  vm_object_lifecycle_perf_set_enabled(false);
  auto snapshot = vm_object_lifecycle_perf_snapshot();

  report.add("clone_destruct_iterations", iterations);
  report.add("clone_destruct_elapsed_ns", total_elapsed);
  add_samples(report, "clone_latency", clone_samples);
  add_samples(report, "destruct_latency", destruct_samples);
  for (size_t i = 0; i < VM_OBJECT_LIFECYCLE_PERF_STAGE_COUNT; i++) {
    std::string stage = vm_object_lifecycle_perf_stage_name(i);
    if (stage.empty()) {
      continue;
    }
    auto count = static_cast<long long>(snapshot.counts[i]);
    auto total_ns = static_cast<long long>(snapshot.total_ns[i]);
    report.add("lifecycle_stage_" + stage + "_count", count);
    report.add("lifecycle_stage_" + stage + "_total_ns", total_ns);
    report.add("lifecycle_stage_" + stage + "_avg_ns", count > 0 ? total_ns / count : 0);
  }
}

void print_text_report(const Report &report, const std::string &json_path) {
  std::cout << "object_store_bench: schema=" << kObjectStoreBenchSchemaV1 << "\n";
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
      std::cout << "usage: object_store_bench [--json path]\n";
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
    report.add_string("object_handle_model", kVMObjectHandleCapabilityModelV1);
    report.add_string("owner_fast_path", "owner_shard_resolve_without_global_fallback");

    run_object_handle_resolve_bench(report);
    run_clone_destruct_lifecycle_bench(report);

    auto json = report_json(report);
    write_json_report(json_path, json);
    print_text_report(report, json_path);
    std::cout << json;
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "object_store_bench failed: " << error.what() << "\n";
    return 1;
  }
}
