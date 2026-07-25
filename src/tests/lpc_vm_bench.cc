#include "base/package_api.h"

#include "backend.h"
#include "mainlib.h"
#include "packages/gateway/gateway.h"
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
  lpc_vm_profile_set_recording(true);
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
  lpc_vm_profile_set_recording(false);
}

void run_dispatch_bench(Report &report) {
  constexpr long kWarmupIterations = 4096;
  constexpr long kMeasuredIterations = 250000;
  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone dispatch probe object");

  auto direct = apply_cache_lookup("dummy", probe->prog);
  require(direct.funp != nullptr, "dispatch probe dummy() lookup failed");

  for (long i = 0; i < kWarmupIterations; i++) {
    require(safe_apply("dummy", probe, 0, ORIGIN_DRIVER) != nullptr,
            "dispatch apply warmup failed");
    call_direct(probe, direct.runtime_index, ORIGIN_DRIVER, 0);
    pop_stack();
  }

  auto apply_start = Clock::now();
  for (long i = 0; i < kMeasuredIterations; i++) {
    require(safe_apply("dummy", probe, 0, ORIGIN_DRIVER) != nullptr,
            "dispatch apply probe failed");
  }
  const auto apply_elapsed = elapsed_ns(apply_start);

  auto direct_start = Clock::now();
  for (long i = 0; i < kMeasuredIterations; i++) {
    call_direct(probe, direct.runtime_index, ORIGIN_DRIVER, 0);
    pop_stack();
  }
  const auto direct_elapsed = elapsed_ns(direct_start);

  report.add("dispatch_iterations", kMeasuredIterations);
  report.add("dispatch_apply_elapsed_ns", apply_elapsed);
  report.add("dispatch_apply_ns_per_call", apply_elapsed / kMeasuredIterations);
  report.add("dispatch_call_direct_elapsed_ns", direct_elapsed);
  report.add("dispatch_call_direct_ns_per_call", direct_elapsed / kMeasuredIterations);

  destruct_object_for_bench(probe);
}

long long require_mapping_number(mapping_t *map, const char *key) {
  auto *value = map ? find_string_in_mapping(map, key) : nullptr;
  require(value != nullptr && value->type == T_NUMBER,
          std::string("representative LPC workload missing numeric field: ") + key);
  return value->u.number;
}

void run_representative_lpc_bench(Report &report) {
  constexpr long kItemCount = 16;
  constexpr long kIterations = 256;
  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone representative LPC workload probe");

  push_number(kItemCount);
  push_number(8);
  require(safe_apply("benchmark_representative_lpc_workload", probe, 2,
                     ORIGIN_DRIVER) != nullptr,
          "representative LPC workload warmup failed");

  push_number(kItemCount);
  push_number(kIterations);
  auto wall_start = Clock::now();
  auto *result = safe_apply("benchmark_representative_lpc_workload", probe, 2,
                            ORIGIN_DRIVER);
  auto wall_elapsed = elapsed_ns(wall_start);
  require(result != nullptr && result->type == T_MAPPING,
          "representative LPC workload result missing");
  auto *values = result->u.map;
  auto cpu_total_ns = require_mapping_number(values, "cpu_total_ns");
  auto iterations = require_mapping_number(values, "iterations");
  require(iterations == kIterations && cpu_total_ns > 0,
          "representative LPC workload returned invalid timing");

  report.add("representative_lpc_items",
             require_mapping_number(values, "item_count"));
  report.add("representative_lpc_iterations", iterations);
  report.add("representative_lpc_checksum",
             require_mapping_number(values, "checksum"));
  report.add("representative_lpc_cpu_total_ns", cpu_total_ns);
  report.add("representative_lpc_cpu_ns_per_iteration",
             cpu_total_ns / iterations);
  report.add("representative_lpc_wall_total_ns", wall_elapsed);
  report.add("representative_lpc_wall_ns_per_iteration",
             wall_elapsed / iterations);

  destruct_object_for_bench(probe);
}

void run_message_event_template_cache_bench(Report &report) {
  constexpr size_t kTemplateCount = 104;
  constexpr size_t kUncachedRecipients = 16;
  constexpr size_t kWarmRecipients = 64;
  std::vector<std::string> stable_children;
  std::vector<std::string> scope_types;
  std::vector<LPC_INT> message_seqs;
  std::vector<LPC_INT> server_seqs;
  std::vector<LPC_INT> epochs;
  std::vector<LPC_INT> sent_ats;

  stable_children.reserve(kTemplateCount);
  scope_types.reserve(kTemplateCount);
  message_seqs.reserve(kTemplateCount);
  server_seqs.reserve(kTemplateCount);
  epochs.reserve(kTemplateCount);
  sent_ats.reserve(kTemplateCount);
  for (size_t index = 0; index < kTemplateCount; ++index) {
    stable_children.push_back(
        "{\"schema_version\":1,\"channel\":\"main\",\"intent\":\"append\","
        "\"priority\":\"normal\",\"reliability\":\"important\","
        "\"display_mode\":\"paced\",\"ttl_ms\":30000,\"collapse_key\":\"\","
        "\"text\":\"room event " + std::to_string(index) +
        "\",\"payload\":{}}");
    scope_types.emplace_back("player");
    message_seqs.push_back(static_cast<LPC_INT>(index + 1));
    server_seqs.push_back(static_cast<LPC_INT>(1000 + index));
    epochs.push_back(0);
    sent_ats.push_back(2000);
  }

  size_t output_bytes = 0;
  auto uncached_started_at = Clock::now();
  for (size_t recipient = 0; recipient < kUncachedRecipients; ++recipient) {
    gateway_clear_message_event_template_cache_for_test();
    auto frame = gateway_encode_preencoded_message_event_batch_for_test(
        stable_children, scope_types,
        "observer-uncached-" + std::to_string(recipient), message_seqs,
        server_seqs, epochs, sent_ats,
        static_cast<LPC_INT>(3000 + recipient), 0, 2000);
    require(!frame.empty(), "message-event uncached probe failed");
    output_bytes += frame.size();
  }
  const auto uncached_elapsed = elapsed_ns(uncached_started_at);

  gateway_clear_message_event_template_cache_for_test();
  const auto hits_before =
      g_gateway_runtime_counters.message_event_template_cache_hits.load();
  const auto misses_before =
      g_gateway_runtime_counters.message_event_template_cache_misses.load();
  auto cold_started_at = Clock::now();
  auto cold_frame = gateway_encode_preencoded_message_event_batch_for_test(
      stable_children, scope_types, "observer-cold", message_seqs,
      server_seqs, epochs, sent_ats, 999, 0, 1999);
  const auto cold_elapsed = elapsed_ns(cold_started_at);
  require(!cold_frame.empty(), "message-event cold cache probe failed");

  output_bytes += cold_frame.size();
  auto warm_started_at = Clock::now();
  for (size_t recipient = 0; recipient < kWarmRecipients; ++recipient) {
    auto frame = gateway_encode_preencoded_message_event_batch_for_test(
        stable_children, scope_types,
        "observer-warm-" + std::to_string(recipient), message_seqs,
        server_seqs, epochs, sent_ats,
        static_cast<LPC_INT>(2000 + recipient), 0, 2000);
    require(!frame.empty(), "message-event warm cache probe failed");
    output_bytes += frame.size();
  }
  const auto warm_elapsed = elapsed_ns(warm_started_at);

  report.add("message_event_template_count", kTemplateCount);
  report.add("message_event_template_uncached_recipients",
             kUncachedRecipients);
  report.add("message_event_template_uncached_fill_total_ns",
             uncached_elapsed);
  report.add("message_event_template_uncached_fill_ns_per_recipient",
             uncached_elapsed / kUncachedRecipients);
  report.add("message_event_template_cold_fill_ns", cold_elapsed);
  report.add("message_event_template_warm_recipients", kWarmRecipients);
  report.add("message_event_template_warm_fill_total_ns", warm_elapsed);
  report.add("message_event_template_warm_fill_ns_per_recipient",
             warm_elapsed / kWarmRecipients);
  report.add("message_event_template_output_bytes",
             static_cast<long long>(output_bytes));
  report.add(
      "message_event_template_cache_hits",
      static_cast<long long>(
          g_gateway_runtime_counters.message_event_template_cache_hits.load() -
          hits_before));
  report.add(
      "message_event_template_cache_misses",
      static_cast<long long>(
          g_gateway_runtime_counters.message_event_template_cache_misses.load() -
          misses_before));
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

void run_hot_path_profile_bench(Report &report, bool recording_enabled, const std::string &prefix) {
  const long iterations = 4096;
  lpc_vm_profile_set_recording(recording_enabled);
  lpc_vm_profile_reset();

  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone VM hot path probe object");

  for (long i = 0; i < 128; i++) {
    push_object(probe);
    require(safe_apply("call_target", probe, 1, ORIGIN_DRIVER) != nullptr,
            "call_target() warmup did not return");
  }

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
  report.add(prefix + "hot_path_iterations", iterations);
  report.add(prefix + "hot_path_elapsed_ns", elapsed_ns(start));
  report.add(prefix + "hot_path_call_other_latency_p50_ns", percentile(call_other_samples, 0.50));
  report.add(prefix + "hot_path_call_other_latency_p95_ns", percentile(call_other_samples, 0.95));
  report.add(prefix + "hot_path_call_other_latency_p99_ns", percentile(call_other_samples, 0.99));
  add_profile_snapshot_metrics(report, prefix + "hot_path_profile_", snapshot);

  destruct_object_for_bench(probe);
  lpc_vm_profile_set_recording(false);
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
    report.add_string("dispatch_hot_path_probe", "apply_and_call_direct_v1");
    report.add_string("hot_path_profile_probe", "opcode_efun_call_other_mapping_string_v1");
    report.add_string("representative_lpc_probe",
                      "mapping_array_sort_sprintf_json_encode_v1");
    report.add_string("message_event_template_probe",
                      "validated_stable_json_cache_104x64_v1");
    report.add_string("profile_comparison", "explicit_enabled_vs_disabled_same_audit_mode");

    run_apply_cache_bench(report);
    run_dispatch_bench(report);
    run_representative_lpc_bench(report);
    run_message_event_template_cache_bench(report);
    run_hot_path_profile_bench(report, false, "profile_disabled_");
    run_hot_path_profile_bench(report, true, "");

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
