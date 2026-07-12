#include "base/package_api.h"

#include "backend.h"
#include "mainlib.h"
#include "packages/gateway/gateway.h"
#include "vm/internal/base/mapping.h"
#include "vm/internal/base/object.h"
#include "vm/internal/owner_future_store.h"
#include "vm/context.h"
#include "vm/frozen_value.h"
#include "vm/object_handle.h"
#include "vm/owner.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

namespace {
using Clock = std::chrono::steady_clock;

void bench_set_env(const char *name, const char *value) {
#ifdef _WIN32
  (void)_putenv_s(name, value);
#else
  (void)setenv(name, value, 1);
#endif
}

void bench_unset_env(const char *name) {
#ifdef _WIN32
  (void)_putenv_s(name, "");
#else
  (void)unsetenv(name);
#endif
}

int bench_chdir(const char *path) {
#ifdef _WIN32
  return _chdir(path);
#else
  return chdir(path);
#endif
}

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

long mapping_number(mapping_t *map, const char *key) {
  auto *value = find_string_in_mapping(map, key);
  if (!value || value->type != T_NUMBER) {
    std::ostringstream error;
    error << "missing numeric mapping key: " << key;
    throw std::runtime_error(error.str());
  }
  return value->u.number;
}

long long elapsed_us(Clock::time_point start) {
  return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count();
}

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
  json << "  \"schema\": \"owner_runtime_bench_v1\",\n";
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

void wait_for_probe_count(long expected_probe_count) {
  for (int i = 0; i < 400; i++) {
    auto *status = vm_owner_thread_status();
    auto probe_done = mapping_number(status, "executor_probe_executed");
    free_mapping(status);
    if (probe_done >= expected_probe_count) {
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  throw std::runtime_error("timed out waiting for owner executor probe tasks");
}

std::string metric_key(const std::string &prefix, const std::string &case_name, int workers,
                       const std::string &suffix) {
  std::ostringstream key;
  key << prefix << "_" << case_name << "_" << workers << "w_" << suffix;
  return key.str();
}

long long run_probe_matrix_case(Report &report, const std::string &case_name,
                                const std::vector<std::string> &owners, long tasks_per_owner,
                                int workers, int probe_delay_ms) {
  const auto total_tasks = static_cast<long>(owners.size()) * tasks_per_owner;
  auto *before = vm_owner_thread_status();
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto before_claim_conflicts = mapping_number(before, "executor_same_owner_claim_conflicts");
  auto before_dispatched = mapping_number(before, "thread_dispatched");
  free_mapping(before);

  bench_set_env("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS", std::to_string(probe_delay_ms).c_str());
  auto start = Clock::now();
  for (long i = 0; i < tasks_per_owner; i++) {
    for (const auto &owner : owners) {
      require(vm_owner_enqueue_task(owner.c_str(), "executor_probe", case_name.c_str()) > 0,
              case_name + " enqueue failed");
    }
  }

  vm_owner_thread_start(workers);
  wait_for_probe_count(before_probe + total_tasks);
  auto elapsed = elapsed_us(start);
  auto *running = vm_owner_thread_status();
  auto completed = mapping_number(running, "executor_probe_executed") - before_probe;
  auto dispatched = mapping_number(running, "thread_dispatched") - before_dispatched;
  auto claim_conflicts =
      mapping_number(running, "executor_same_owner_claim_conflicts") - before_claim_conflicts;
  auto throughput = elapsed > 0 ? completed * 1000000LL / elapsed : 0;

  report.add(metric_key("thread_matrix", case_name, workers, "tasks"), total_tasks);
  report.add(metric_key("thread_matrix", case_name, workers, "completed"), completed);
  report.add(metric_key("thread_matrix", case_name, workers, "elapsed_us"), elapsed);
  report.add(metric_key("thread_matrix", case_name, workers, "throughput_per_sec"), throughput);
  report.add(metric_key("thread_matrix", case_name, workers, "observed_thread_count"),
             mapping_number(running, "thread_count"));
  report.add(metric_key("thread_matrix", case_name, workers, "thread_dispatched"), dispatched);
  report.add(metric_key("thread_matrix", case_name, workers, "runtime_max_parallel_owners_seen"),
             mapping_number(running, "executor_max_parallel_owners"));
  report.add(metric_key("thread_matrix", case_name, workers, "claim_conflicts"), claim_conflicts);
  free_mapping(running);
  vm_owner_thread_stop();
  bench_unset_env("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS");
  return throughput;
}

void run_probe_thread_matrix(Report &report) {
  const long tasks_per_owner = 16;
  const int probe_delay_ms = 5;
  const std::vector<int> worker_counts{1, 2, 4};
  const std::vector<std::string> same_owner{
      "owner/bench/runtime-v4/thread-matrix/same",
  };
  const std::vector<std::string> different_owners{
      "owner/bench/runtime-v4/thread-matrix/different-a",
      "owner/bench/runtime-v4/thread-matrix/different-b",
      "owner/bench/runtime-v4/thread-matrix/different-c",
      "owner/bench/runtime-v4/thread-matrix/different-d",
  };
  const std::vector<std::string> service_shards{
      "owner/service/bench/runtime-v4/shard-a",
      "owner/service/bench/runtime-v4/shard-b",
      "owner/service/bench/runtime-v4/shard-c",
      "owner/service/bench/runtime-v4/shard-d",
  };

  auto run_case = [&](const std::string &case_name, const std::vector<std::string> &owners) {
    long long one_worker = 0;
    long long four_worker = 0;
    for (auto workers : worker_counts) {
      vm_owner_thread_stop();
      auto throughput =
          run_probe_matrix_case(report, case_name, owners, tasks_per_owner, workers, probe_delay_ms);
      if (workers == 1) {
        one_worker = throughput;
      } else if (workers == 4) {
        four_worker = throughput;
      }
    }
    report.add("thread_matrix_" + case_name + "_4w_speedup_x100",
               one_worker > 0 ? four_worker * 100LL / one_worker : 0);
  };

  run_case("same_owner", same_owner);
  run_case("different_owner", different_owners);
  run_case("service_shard", service_shards);
}

void run_same_owner_bench(Report &report) {
  const char *owner = "owner/bench/runtime-v4/same";
  const long tasks = 32;
  auto *before = vm_owner_thread_status();
  auto before_probe = mapping_number(before, "executor_probe_executed");
  free_mapping(before);

  std::vector<long long> enqueue_samples;
  auto start = Clock::now();
  for (long i = 0; i < tasks; i++) {
    auto enqueue_start = Clock::now();
    auto task_id = vm_owner_enqueue_task(owner, "executor_probe", "bench_same_owner");
    enqueue_samples.push_back(elapsed_us(enqueue_start));
    require(task_id > 0, "same-owner enqueue failed");
  }
  auto *queued = vm_owner_mailbox_status(owner);
  report.add("same_owner_initial_queue_depth", mapping_number(queued, "owner_queue_depth"));
  free_mapping(queued);

  vm_owner_thread_start(1);
  wait_for_probe_count(before_probe + tasks);
  vm_owner_thread_stop();
  auto total_elapsed = elapsed_us(start);

  auto *after = vm_owner_thread_status();
  auto completed = mapping_number(after, "executor_probe_executed") - before_probe;
  report.add("same_owner_tasks", tasks);
  report.add("same_owner_completed", completed);
  report.add("same_owner_elapsed_us", total_elapsed);
  report.add("same_owner_throughput_per_sec", total_elapsed > 0 ? completed * 1000000LL / total_elapsed : 0);
  report.add("scheduler_enqueue_api_latency_p50_us", percentile(enqueue_samples, 0.50));
  report.add("scheduler_enqueue_api_latency_p95_us", percentile(enqueue_samples, 0.95));
  report.add("scheduler_enqueue_api_latency_p99_us", percentile(enqueue_samples, 0.99));
  report.add("same_owner_claim_conflicts", mapping_number(after, "executor_same_owner_claim_conflicts"));
  free_mapping(after);
}

void run_different_owner_bench(Report &report) {
  const char *owner_a = "owner/bench/runtime-v4/parallel-a";
  const char *owner_b = "owner/bench/runtime-v4/parallel-b";
  const long tasks_per_owner = 16;
  auto *before = vm_owner_thread_status();
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto before_claims = mapping_number(before, "executor_owner_claims");
  auto before_releases = mapping_number(before, "executor_owner_releases");
  free_mapping(before);

  bench_set_env("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS", "4");
  auto start = Clock::now();
  for (long i = 0; i < tasks_per_owner; i++) {
    require(vm_owner_enqueue_task(owner_a, "executor_probe", "bench_parallel_a") > 0, "parallel owner A enqueue failed");
    require(vm_owner_enqueue_task(owner_b, "executor_probe", "bench_parallel_b") > 0, "parallel owner B enqueue failed");
  }
  vm_owner_thread_start(2);
  wait_for_probe_count(before_probe + tasks_per_owner * 2);
  vm_owner_thread_stop();
  bench_unset_env("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS");
  auto total_elapsed = elapsed_us(start);

  auto *after = vm_owner_thread_status();
  auto completed = mapping_number(after, "executor_probe_executed") - before_probe;
  auto claim_delta = mapping_number(after, "executor_owner_claims") - before_claims;
  auto release_delta = mapping_number(after, "executor_owner_releases") - before_releases;
  report.add("different_owner_tasks", tasks_per_owner * 2);
  report.add("different_owner_completed", completed);
  report.add("different_owner_elapsed_us", total_elapsed);
  report.add("different_owner_throughput_per_sec", total_elapsed > 0 ? completed * 1000000LL / total_elapsed : 0);
  report.add("different_owner_max_parallel", mapping_number(after, "executor_max_parallel_owners"));
  report.add("owner_claim_delta", claim_delta);
  report.add("owner_release_delta", release_delta);
  require(claim_delta == release_delta, "owner claim/release delta mismatch");
  free_mapping(after);
}

void run_future_bench(Report &report) {
  std::vector<long long> samples;
  auto start = Clock::now();
  auto future_cancel = vm_owner_register_compute_future("owner/bench/runtime-v4/future-cancel", 9301,
                                                        "bench_future_cancel", "payload");
  auto future_timeout = vm_owner_register_compute_future("owner/bench/runtime-v4/future-timeout", 9302,
                                                         "bench_future_timeout", "payload");
  require(future_cancel > 0 && future_timeout > 0, "future registration failed");
  auto poll_start = Clock::now();
  auto *pending = vm_owner_future_poll(future_cancel);
  samples.push_back(elapsed_us(poll_start));
  free_mapping(pending);
  auto cancel_start = Clock::now();
  auto *cancelled = vm_owner_future_cancel(future_cancel, "bench cancel");
  samples.push_back(elapsed_us(cancel_start));
  free_mapping(cancelled);
  auto timeout_start = Clock::now();
  auto *timed_out = vm_owner_future_timeout(future_timeout, "bench timeout");
  samples.push_back(elapsed_us(timeout_start));
  free_mapping(timed_out);

  auto *runtime = vm_owner_runtime_status();
  report.add("future_ops_elapsed_us", elapsed_us(start));
  report.add("future_api_latency_p50_us", percentile(samples, 0.50));
  report.add("future_api_latency_p95_us", percentile(samples, 0.95));
  report.add("future_api_latency_p99_us", percentile(samples, 0.99));
  report.add("future_pending_backlog", mapping_number(runtime, "owner_executor_future_pending_backlog"));
  report.add("future_cancelled_total", mapping_number(runtime, "owner_executor_future_cancelled"));
  report.add("future_timeout_total", mapping_number(runtime, "owner_executor_future_timeout"));
  free_mapping(runtime);
}

mapping_t *make_frozen_payload_bench_value(int item_count) {
  auto *payload = allocate_mapping(5);
  add_mapping_string(payload, "payload_key", "bench/frozen-payload/v1");
  add_mapping_string(payload, "type", "protocol_payload");
  add_mapping_pair(payload, "server_seq", 123456);
  add_mapping_string(payload, "title", "representative owner payload");

  auto *items = allocate_array(item_count);
  for (int i = 0; i < item_count; i++) {
    auto *item = allocate_mapping(6);
    auto id = "item/" + std::to_string(i);
    auto name = "representative payload item " + std::to_string(i);
    add_mapping_string(item, "id", id.c_str());
    add_mapping_string(item, "name", name.c_str());
    add_mapping_pair(item, "count", i + 1);
    add_mapping_pair(item, "weight", (i + 1) * 25);
    add_mapping_string(item, "category", i % 2 == 0 ? "equipment" : "consumable");
    add_mapping_string(item, "description", "fixed nested payload text for frozen traversal benchmark");
    items->item[i].type = T_MAPPING;
    items->item[i].subtype = 0;
    items->item[i].u.map = item;
  }
  add_mapping_array(payload, "items", items);
  free_array(items);
  return payload;
}

void run_frozen_payload_traversal_case(Report &report, const std::string &case_name,
                                       int item_count, int iterations) {
  auto *payload = make_frozen_payload_bench_value(item_count);
  svalue_t source{T_MAPPING, 0, {0}};
  source.u.map = payload;
  std::string error;

  require(vm_frozen_value_safe(&source, 0, "owner payload", &error),
          case_name + " payload validation failed: " + error);
  auto warm_clone = vm_clone_frozen_value(&source);
  require(warm_clone != nullptr, case_name + " payload clone warmup failed");
  warm_clone.reset();
  svalue_t warm_copy{const0u};
  require(vm_copy_frozen_svalue(&warm_copy, &source), case_name + " payload copy warmup failed");
  free_svalue(&warm_copy, "owner runtime frozen payload copy warmup");

  auto validation_start = Clock::now();
  for (int i = 0; i < iterations; i++) {
    error.clear();
    require(vm_frozen_value_safe(&source, 0, "owner payload", &error),
            case_name + " payload validation failed");
  }
  auto validation_total_ns = elapsed_ns(validation_start);

  auto clone_start = Clock::now();
  for (int i = 0; i < iterations; i++) {
    auto clone = vm_clone_frozen_value(&source);
    require(clone != nullptr, case_name + " payload clone failed");
  }
  auto clone_total_ns = elapsed_ns(clone_start);

  auto copy_start = Clock::now();
  for (int i = 0; i < iterations; i++) {
    svalue_t copied{const0u};
    require(vm_copy_frozen_svalue(&copied, &source), case_name + " payload copy failed");
    free_svalue(&copied, "owner runtime frozen payload copy");
  }
  auto copy_total_ns = elapsed_ns(copy_start);

  auto validation_avg_ns = validation_total_ns / iterations;
  auto clone_avg_ns = clone_total_ns / iterations;
  auto copy_avg_ns = copy_total_ns / iterations;
  auto current_efun_avg_ns = validation_avg_ns + clone_avg_ns;

  report.add("frozen_payload_" + case_name + "_items", item_count);
  report.add("frozen_payload_" + case_name + "_iterations", iterations);
  report.add("frozen_payload_" + case_name + "_validation_avg_ns", validation_avg_ns);
  report.add("frozen_payload_" + case_name + "_clone_avg_ns", clone_avg_ns);
  report.add("frozen_payload_" + case_name + "_copy_avg_ns", copy_avg_ns);
  report.add("frozen_payload_" + case_name + "_current_efun_avg_ns", current_efun_avg_ns);
  report.add("frozen_payload_" + case_name + "_redundant_traversal_avg_ns",
             current_efun_avg_ns - copy_avg_ns);
  report.add("frozen_payload_" + case_name + "_copy_share_x100",
             current_efun_avg_ns > 0 ? copy_avg_ns * 100LL / current_efun_avg_ns : 0);

  free_mapping(payload);
}

void run_frozen_payload_traversal_bench(Report &report) {
  constexpr int iterations = 1000;
  run_frozen_payload_traversal_case(report, "small", 4, iterations);
  run_frozen_payload_traversal_case(report, "medium", 16, iterations);
}

void run_future_completion_lookup_case(Report &report, int backlog) {
  OwnerFutureStore store;
  for (int i = 1; i <= backlog; i++) {
    OwnerFutureRecord future;
    future.future_id = static_cast<uint64_t>(i);
    future.target_task_id = static_cast<uint64_t>(100000 + i);
    future.source_owner_id = "owner/bench/future/source";
    future.target_owner_id = "owner/bench/future/target";
    future.message_type = "bench_future_lookup";
    future.payload_key = "bench/future/lookup/v1";
    future.state = "pending";
    store.insert(std::move(future));
  }

  auto completion_start = Clock::now();
  for (int i = 1; i <= backlog; i++) {
    auto completion = store.complete_for_task(static_cast<uint64_t>(100000 + i),
                                              "completed", "bench_result", "");
    require(completion.has_value(), "future completion lookup missed target task");
  }
  auto completion_total_ns = elapsed_ns(completion_start);

  auto take_start = Clock::now();
  for (int i = 1; i <= backlog; i++) {
    auto taken = store.take(static_cast<uint64_t>(i));
    require(taken.found && taken.consumed, "future completion lookup take failed");
  }
  auto take_total_ns = elapsed_ns(take_start);
  require(store.size() == 0, "future completion lookup store did not drain");

  auto prefix = "future_completion_lookup_" + std::to_string(backlog);
  report.add(prefix + "_backlog", backlog);
  report.add(prefix + "_completion_total_ns", completion_total_ns);
  report.add(prefix + "_completion_avg_ns", completion_total_ns / backlog);
  report.add(prefix + "_take_total_ns", take_total_ns);
  report.add(prefix + "_take_avg_ns", take_total_ns / backlog);
}

void run_future_completion_lookup_bench(Report &report) {
  for (auto backlog : {16, 256, 2048}) {
    run_future_completion_lookup_case(report, backlog);
  }
}

long query_lpc_number_for_bench(object_t *target, const char *method) {
  auto *value = safe_apply(method, target, 0, ORIGIN_DRIVER);
  require(value != nullptr && value->type == T_NUMBER,
          std::string("missing numeric LPC benchmark result: ") + method);
  return value->u.number;
}

std::string query_lpc_string_for_bench(object_t *target, const char *method) {
  auto *value = safe_apply(method, target, 0, ORIGIN_DRIVER);
  require(value != nullptr && value->type == T_STRING,
          std::string("missing string LPC benchmark result: ") + method);
  return std::string(value->u.string, SVALUE_STRLEN(value));
}

void run_submit_watch_current_path_case(Report &report, object_t *target,
                                        const std::string &case_name, int item_count,
                                        int iterations) {
  constexpr int timeout_ms = 1000;
  const char *owner_id = "owner/bench/runtime-v4/submit-watch";
  auto *payload = make_frozen_payload_bench_value(item_count);
  std::vector<long long> samples;
  samples.reserve(iterations);

  for (int i = 0; i < iterations; i++) {
    push_number(100000 + i);
    push_mapping(payload);
    push_number(timeout_ms);
    auto started_at = Clock::now();
    auto *submitted = safe_apply("submit_and_watch_generic_owner_future", target, 3,
                                 ORIGIN_DRIVER);
    samples.push_back(elapsed_ns(started_at));
    require(submitted != nullptr && submitted->type == T_NUMBER && submitted->u.number == 1,
            case_name + " submit-watch current path failed");

    auto future_id = query_lpc_number_for_bench(target, "query_last_submit_watch_future_id");
    require(future_id > 0, case_name + " submit-watch future id missing");
    auto *cancelled = vm_owner_future_cancel(static_cast<uint64_t>(future_id),
                                             "submit-watch benchmark cleanup");
    free_mapping(cancelled);
    require(gateway_process_future_watches_at(std::numeric_limits<uint64_t>::max()) == 1,
            case_name + " submit-watch cleanup did not consume watch");
    auto *purged = vm_owner_purge_mailbox(owner_id);
    free_mapping(purged);
    require(gateway_future_watch_count() == 0,
            case_name + " submit-watch leaked generic watcher");
  }

  auto total_ns = std::accumulate(samples.begin(), samples.end(), 0LL);
  auto prefix = "submit_watch_current_" + case_name;
  report.add(prefix + "_items", item_count);
  report.add(prefix + "_iterations", iterations);
  report.add(prefix + "_total_ns", total_ns);
  report.add(prefix + "_avg_ns", total_ns / iterations);
  report.add(prefix + "_p50_ns", percentile(samples, 0.50));
  report.add(prefix + "_p95_ns", percentile(samples, 0.95));
  report.add(prefix + "_p99_ns", percentile(samples, 0.99));
  free_mapping(payload);
}

void run_submit_watch_current_path_bench(Report &report) {
  constexpr int iterations = 128;
  auto *target = clone_object_for_bench("clone/gateway_login_example");
  require(target != nullptr, "failed to clone submit-watch benchmark target");
  vm_owner_set_id(target, "owner/bench/runtime-v4/submit-watch");
  vm_object_store_register(target);

  run_submit_watch_current_path_case(report, target, "small", 4, iterations);
  run_submit_watch_current_path_case(report, target, "medium", 16, iterations);

  vm_owner_clear_id(target);
  destruct_object_for_bench(target);
}

object_t *create_gateway_session_for_bench(const char *session_id, int master_fd) {
  svalue_t data{T_MAPPING, 0, {0}};
  data.u.map = allocate_mapping(1);
  add_mapping_string(data.u.map, "ip", "127.0.0.1");
  copy_and_push_string("/clone/gateway_login_example");
  safe_apply("set_test_login_ob", master_ob, 1, ORIGIN_DRIVER);
  auto *target = gateway_create_session_internal(session_id, &data, "127.0.0.1",
                                                 6040, master_fd);
  safe_apply("reset_test_login_ob", master_ob, 0, ORIGIN_DRIVER);
  free_svalue(&data, "owner runtime gateway session benchmark");
  return target;
}

void run_session_submit_watch_upfront_case(Report &report, object_t *target,
                                           const std::string &case_name, int item_count,
                                           int iterations) {
  constexpr int timeout_ms = 1000;
  const char *owner_id = "owner/bench/runtime-v4/session-submit-watch";
  auto *payload = make_frozen_payload_bench_value(item_count);
  std::vector<long long> samples;
  samples.reserve(iterations);

  for (int i = 0; i < iterations; i++) {
    auto started_at = Clock::now();
    auto reservation_id = gateway_reserve_session_output_for_object(target);
    require(reservation_id > 0, case_name + " session reservation failed");
    push_mapping(payload);
    auto *submitted = safe_apply("submit_gateway_owner_future_payload", target, 1,
                                 ORIGIN_DRIVER);
    require(submitted != nullptr && submitted->type == T_MAPPING,
            case_name + " session owner submit failed");
    auto future_id = mapping_number(submitted->u.map, "future_id");
    require(future_id > 0, case_name + " session future id missing");
    require(gateway_watch_session_future_for_object(
                target, reservation_id, static_cast<uint64_t>(future_id), timeout_ms) == 1,
            case_name + " session future watch failed");
    samples.push_back(elapsed_ns(started_at));

    auto *cancelled = vm_owner_future_cancel(static_cast<uint64_t>(future_id),
                                             "session submit-watch benchmark cleanup");
    free_mapping(cancelled);
    require(gateway_process_session_future_watches_at(
                std::numeric_limits<uint64_t>::max()) == 1,
            case_name + " session watcher cleanup failed");
    auto *purged = vm_owner_purge_mailbox(owner_id);
    free_mapping(purged);
    auto *session = gateway_find_session_by_object(target);
    require(session != nullptr && session->output_fifo.empty(),
            case_name + " session FIFO did not drain");
    require(gateway_session_future_watch_count() == 0,
            case_name + " session watcher leaked");
  }

  auto total_ns = std::accumulate(samples.begin(), samples.end(), 0LL);
  auto prefix = "session_submit_watch_upfront_" + case_name;
  report.add(prefix + "_items", item_count);
  report.add(prefix + "_iterations", iterations);
  report.add(prefix + "_total_ns", total_ns);
  report.add(prefix + "_avg_ns", total_ns / iterations);
  report.add(prefix + "_p50_ns", percentile(samples, 0.50));
  report.add(prefix + "_p95_ns", percentile(samples, 0.95));
  report.add(prefix + "_p99_ns", percentile(samples, 0.99));
  free_mapping(payload);
}

void run_session_submit_watch_upfront_bench(Report &report) {
  constexpr int iterations = 128;
  const char *session_id = "gw-bench-session-submit-watch";
  auto *target = create_gateway_session_for_bench(session_id, 99);
  require(target != nullptr, "failed to create session submit-watch benchmark target");
  add_ref(target, "owner runtime session submit-watch benchmark");
  vm_owner_set_id(target, "owner/bench/runtime-v4/session-submit-watch");

  run_session_submit_watch_upfront_case(report, target, "small", 4, iterations);
  run_session_submit_watch_upfront_case(report, target, "medium", 16, iterations);

  require(gateway_destroy_session_internal(session_id, "bench_done", "bench done") == 1,
          "failed to destroy session submit-watch benchmark target");
  destruct_object_for_bench(target);
  free_object(&target, "owner runtime session submit-watch benchmark");
}

mapping_t *make_owner_frame_bench_payload(int frame_bytes) {
  auto *payload = allocate_mapping(2);
  add_mapping_string(payload, "payload_key", "bench/session-frame/v1");
  auto frame = std::string(static_cast<size_t>(frame_bytes), 'x');
  add_mapping_string(payload, "frame", frame.c_str());
  return payload;
}

void wait_for_owner_future_terminal(uint64_t future_id, const std::string &case_name) {
  for (int i = 0; i < 1000; i++) {
    auto state = vm_owner_future_state(future_id);
    if (state == VM_OWNER_FUTURE_COMPLETED || state == VM_OWNER_FUTURE_FAILED) {
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  throw std::runtime_error(case_name + " owner future did not reach terminal state");
}

void run_session_publish_case(Report &report, const std::string &case_name,
                              int frame_bytes, int iterations, bool native_output = false) {
  auto *payload = make_owner_frame_bench_payload(frame_bytes);
  auto frame = std::string(static_cast<size_t>(frame_bytes), 'x');
  std::vector<long long> process_samples;
  process_samples.reserve(iterations);
  auto *before = gateway_status_internal();
  auto before_take_samples = mapping_number(before, "gateway_future_watch_take_samples");
  auto before_take_total_us = mapping_number(before, "gateway_future_watch_take_total_us");
  auto before_callback_samples = mapping_number(before, "gateway_future_watch_callback_samples");
  auto before_callback_total_us = mapping_number(before, "gateway_future_watch_callback_total_us");
  free_mapping(before);

  for (int i = 0; i < iterations; i++) {
    auto session_id = "gw-bench-session-publish-" +
                      std::string(native_output ? "native-" : "lpc-") + case_name + "-" +
                      std::to_string(i);
    auto *target = create_gateway_session_for_bench(session_id.c_str(), 99);
    require(target != nullptr, case_name + " failed to create publish session");
    add_ref(target, "owner runtime session publish benchmark");
    vm_owner_set_id(target, "owner/bench/runtime-v4/session-publish");

    auto reservation_id = gateway_reserve_session_output_for_object(target);
    require(reservation_id > 0, case_name + " publish reservation failed");
    if (native_output) {
      copy_and_push_string(frame.c_str());
    } else {
      push_mapping(payload);
    }
    auto *submitted = safe_apply(native_output ? "submit_gateway_owner_frame_string"
                                               : "submit_gateway_owner_frame",
                                 target, 1, ORIGIN_DRIVER);
    require(submitted != nullptr && submitted->type == T_MAPPING,
            case_name + " owner frame submit failed");
    auto future_id = mapping_number(submitted->u.map, "future_id");
    require(future_id > 0, case_name + " owner frame future id missing");
    auto watched = native_output
                       ? gateway_watch_session_future_output_for_object(
                             target, reservation_id, static_cast<uint64_t>(future_id), 1000)
                       : gateway_watch_session_future_for_object(
                             target, reservation_id, static_cast<uint64_t>(future_id), 1000);
    require(watched == 1,
            case_name + " owner frame watch failed");

    wait_for_owner_future_terminal(static_cast<uint64_t>(future_id), case_name);
    auto process_started_at = Clock::now();
    require(gateway_process_session_future_watches_at(
                std::numeric_limits<uint64_t>::max()) == 1,
            case_name + " owner frame publish did not process");
    process_samples.push_back(elapsed_ns(process_started_at));

    require(query_lpc_number_for_bench(target,
                                       "query_last_owner_future_callback_off_main") == 0,
            case_name + " owner frame callback ran off main");
    auto callback_reservation = query_lpc_number_for_bench(
        target, "query_last_owner_future_reservation_id");
    require(callback_reservation ==
                (native_output ? 0 : static_cast<long>(reservation_id)),
            case_name + " owner frame callback mode mismatch");
    if (native_output) {
      require(query_lpc_number_for_bench(
                  target, "query_last_owner_future_output_reservation_id") ==
                  static_cast<long>(reservation_id),
              case_name + " owner frame output notification used wrong reservation");
      require(query_lpc_string_for_bench(target,
                                         "query_last_owner_future_output_state") ==
                  "completed",
              case_name + " owner frame output notification used wrong state");
      require(query_lpc_number_for_bench(
                  target, "query_last_owner_future_output_callback_off_main") == 0,
              case_name + " owner frame output notification ran off main");
    }
    require(vm_owner_future_state(static_cast<uint64_t>(future_id)) ==
                VM_OWNER_FUTURE_UNKNOWN,
            case_name + " owner frame future was not consumed");
    require(gateway_session_future_watch_count() == 0,
            case_name + " owner frame watcher leaked");

    require(gateway_destroy_session_internal(session_id.c_str(), "bench_done", "bench done") == 1,
            case_name + " failed to destroy publish session");
    destruct_object_for_bench(target);
    free_object(&target, "owner runtime session publish benchmark");
  }

  auto *after = gateway_status_internal();
  auto take_samples = mapping_number(after, "gateway_future_watch_take_samples") -
                      before_take_samples;
  auto take_total_us = mapping_number(after, "gateway_future_watch_take_total_us") -
                       before_take_total_us;
  auto callback_samples = mapping_number(after, "gateway_future_watch_callback_samples") -
                          before_callback_samples;
  auto callback_total_us = mapping_number(after, "gateway_future_watch_callback_total_us") -
                           before_callback_total_us;
  free_mapping(after);
  require(take_samples == iterations && callback_samples == iterations,
          case_name + " publish timing sample count mismatch");

  auto process_total_ns = std::accumulate(process_samples.begin(), process_samples.end(), 0LL);
  auto prefix = std::string(native_output ? "session_publish_native_"
                                          : "session_publish_") +
                case_name;
  report.add(prefix + "_frame_bytes", frame_bytes);
  report.add(prefix + "_iterations", iterations);
  report.add(prefix + "_process_avg_ns", process_total_ns / iterations);
  report.add(prefix + "_process_p50_ns", percentile(process_samples, 0.50));
  report.add(prefix + "_process_p95_ns", percentile(process_samples, 0.95));
  report.add(prefix + "_process_p99_ns", percentile(process_samples, 0.99));
  report.add(prefix + "_take_avg_us", take_total_us / take_samples);
  report.add(prefix + "_callback_avg_us", callback_total_us / callback_samples);
  free_mapping(payload);
}

void run_session_publish_bench(Report &report) {
  constexpr int iterations = 64;
  vm_owner_thread_start(1);
  run_session_publish_case(report, "frame_512b", 512, iterations);
  run_session_publish_case(report, "frame_2k", 2048, iterations);
  run_session_publish_case(report, "frame_512b", 512, iterations, true);
  run_session_publish_case(report, "frame_2k", 2048, iterations, true);
  vm_owner_thread_stop();
}

void run_object_resolve_bench(Report &report) {
  const long iterations = 256;
  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone resolve probe object");
  vm_owner_set_id(probe, "owner/bench/runtime-v4/resolve");
  vm_object_store_register(probe);
  auto handle = vm_object_handle(probe);

  long fast_path = 0;
  long global_fallback = 0;
  std::vector<long long> samples;
  auto start = Clock::now();
  for (long i = 0; i < iterations; i++) {
    auto sample_start = Clock::now();
    auto resolved = vm_object_handle_resolve_status(handle);
    samples.push_back(elapsed_us(sample_start));
    require(resolved.object == probe, "object handle resolve returned wrong object");
    require(resolved.status == VMObjectHandleResolveStatus::kCurrent, "object handle resolve is not current");
    if (resolved.owner_local_fast_path_used && resolved.resolved_via_owner_local_store) {
      fast_path++;
    }
    if (resolved.resolved_via_global_index) {
      global_fallback++;
    }
  }

  report.add("object_resolve_iterations", iterations);
  report.add("object_resolve_elapsed_us", elapsed_us(start));
  report.add("object_resolve_fast_path_count", fast_path);
  report.add("object_resolve_global_fallback_count", global_fallback);
  report.add("object_resolve_api_latency_p50_us", percentile(samples, 0.50));
  report.add("object_resolve_api_latency_p95_us", percentile(samples, 0.95));
  report.add("object_resolve_api_latency_p99_us", percentile(samples, 0.99));
  vm_owner_clear_id(probe);
  destruct_object_for_bench(probe);
}

void run_callback_admission_bench(Report &report) {
  object_t *probe = clone_object_for_bench("single/void");
  require(probe != nullptr, "failed to clone callback probe object");
  const char *owner = "owner/bench/runtime-v4/callback";
  vm_owner_set_id(probe, owner);

  auto *before = vm_owner_runtime_status();
  auto before_accepted = mapping_number(before, "owner_executor_admission_accepted");
  auto before_rejected = mapping_number(before, "owner_executor_admission_rejected");
  auto before_dropped = mapping_number(before, "owner_executor_admission_dropped");
  free_mapping(before);

  std::vector<long long> samples;
  auto rejected_start = Clock::now();
  require(vm_owner_enqueue_executor_task(probe, "ordinary_lpc", "bench_rejected", [] {}) == 0,
          "ordinary LPC callback should be rejected while executor is unavailable");
  samples.push_back(elapsed_us(rejected_start));

  std::atomic<int> adapter_ran{0};
  std::atomic<int> stale_ran{0};
  std::atomic<int> stale_drop_cleanup{0};
  vm_owner_thread_start(1);
  auto adapter_start = Clock::now();
  auto adapter = vm_owner_enqueue_executor_task(probe, "heartbeat", "bench_main_adapter", [&] {
    adapter_ran.store(vm_context_is_main_thread() ? 1 : -1, std::memory_order_release);
  });
  samples.push_back(elapsed_us(adapter_start));
  require(adapter > 0, "callback main adapter enqueue failed");
  require(vm_owner_drain_main_tasks(16) >= 1, "callback main adapter did not drain");
  require(adapter_ran.load(std::memory_order_acquire) == 1, "callback main adapter did not run on main thread");

  auto stale_start = Clock::now();
  auto stale = vm_owner_enqueue_executor_task(
      probe, "call_out", "bench_stale",
      [&] {
        stale_ran.store(1, std::memory_order_release);
      },
      [&] {
        stale_drop_cleanup.store(vm_context_is_main_thread() ? 1 : -1, std::memory_order_release);
      });
  samples.push_back(elapsed_us(stale_start));
  require(stale > adapter, "stale callback enqueue failed");
  vm_owner_set_id(probe, "owner/bench/runtime-v4/callback/moved");
  require(vm_owner_drain_main_tasks(16) >= 1, "stale callback main adapter did not drain");
  require(vm_owner_drain_main_tasks(16) >= 1, "stale callback cleanup did not drain");
  require(stale_ran.load(std::memory_order_acquire) == 0, "stale callback should not run after owner move");
  require(stale_drop_cleanup.load(std::memory_order_acquire) == 1,
          "stale callback cleanup should run on main thread");
  vm_owner_thread_stop();

  auto *after = vm_owner_runtime_status();
  report.add("callback_admission_api_latency_p50_us", percentile(samples, 0.50));
  report.add("callback_admission_api_latency_p95_us", percentile(samples, 0.95));
  report.add("callback_admission_api_latency_p99_us", percentile(samples, 0.99));
  report.add("callback_admission_accept_delta", mapping_number(after, "owner_executor_admission_accepted") - before_accepted);
  report.add("callback_admission_reject_delta", mapping_number(after, "owner_executor_admission_rejected") - before_rejected);
  report.add("callback_admission_drop_delta", mapping_number(after, "owner_executor_admission_dropped") - before_dropped);
  report.add("callback_drop_cleanup_main_thread", stale_drop_cleanup.load(std::memory_order_acquire));
  free_mapping(after);

  vm_owner_clear_id(probe);
  destruct_object_for_bench(probe);
}

void add_final_status(Report &report) {
  auto *runtime = vm_owner_runtime_status();
  report.add("normal_path_main_fallback_count", mapping_number(runtime, "normal_path_main_fallback_count"));
  report.add("executor_context_cleanup_leaks", mapping_number(runtime, "owner_executor_context_cleanup_leaks"));
  report.add("owner_runtime_layering_guard_ready", mapping_number(runtime, "owner_runtime_layering_guard_ready"));
  free_mapping(runtime);

  auto *thread = vm_owner_thread_status();
  report.add("executor_queue_depth", mapping_number(thread, "executor_queue_depth"));
  report.add("executor_runnable_queue_depth", mapping_number(thread, "executor_runnable_queue_depth"));
  report.add("executor_same_owner_claim_conflicts", mapping_number(thread, "executor_same_owner_claim_conflicts"));
  free_mapping(thread);
}

void print_text_report(const Report &report, const std::string &json_path) {
  std::cout << "owner_runtime_bench: schema=owner_runtime_bench_v1\n";
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
      std::cout << "usage: owner_runtime_bench [--json path]\n";
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
    if (bench_chdir(TESTSUITE_DIR) != 0) {
      std::ostringstream error;
      error << "failed to chdir to " << TESTSUITE_DIR << ": " << strerror(errno);
      throw std::runtime_error(error.str());
    }
    init_main("etc/config.test");
    vm_start();

    Report report;
    report.add_string("mode", "diagnostic");
    report.add_string("lock_profile_mode", "api_latency_proxy_v1");
    report.add_string("task_model", "owner_executor_manifest_v4");

    vm_owner_thread_stop();
    run_probe_thread_matrix(report);
    run_same_owner_bench(report);
    run_different_owner_bench(report);
    run_future_bench(report);
    run_frozen_payload_traversal_bench(report);
    run_future_completion_lookup_bench(report);
    run_submit_watch_current_path_bench(report);
    run_session_submit_watch_upfront_bench(report);
    run_session_publish_bench(report);
    run_object_resolve_bench(report);
    run_callback_admission_bench(report);
    add_final_status(report);
    vm_owner_thread_stop();

    auto json = report_json(report);
    write_json_report(json_path, json);
    print_text_report(report, json_path);
    std::cout << json;
    return 0;
  } catch (const std::exception &error) {
    vm_owner_thread_stop();
    std::cerr << "owner_runtime_bench failed: " << error.what() << "\n";
    return 1;
  }
}
