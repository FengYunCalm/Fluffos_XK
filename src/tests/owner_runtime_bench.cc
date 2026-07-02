#include "base/package_api.h"

#include "backend.h"
#include "mainlib.h"
#include "vm/internal/base/mapping.h"
#include "vm/internal/base/object.h"
#include "vm/context.h"
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
    run_same_owner_bench(report);
    run_different_owner_bench(report);
    run_future_bench(report);
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
