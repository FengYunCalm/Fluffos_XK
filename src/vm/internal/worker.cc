#include "vm/worker.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/internal/tracing.h"

namespace {

struct AsyncRecord {
  VMWorkerTaskState state{VMWorkerTaskState::kPending};
  std::string type;
  VMWorkerBenchResult bench;
  VMWorkerSnapshotDigestResult snapshot_digest;
  VMWorkerActorScoreResult actor_score;
  std::string error;
};

struct AsyncBenchmarkState {
  uint64_t task_id{0};
  int tasks{0};
  int worker_count{0};
  std::chrono::steady_clock::time_point started;
  std::shared_ptr<std::atomic<bool>> start_barrier;
  std::shared_ptr<std::atomic<int>> active;
  std::shared_ptr<std::atomic<int>> max_parallel;
  std::shared_ptr<std::atomic<int>> remaining;
  std::shared_ptr<std::atomic<uint64_t>> checksum;
};

void update_max(std::atomic<int> &target, int value) {
  auto current = target.load();
  while (value > current && !target.compare_exchange_weak(current, value)) {
  }
}

int ratio_bp(int value, int max_value) {
  if (max_value <= 0 || value <= 0) {
    return 0;
  }
  value = std::min(value, max_value);
  return static_cast<int>((static_cast<int64_t>(value) * 10000) / max_value);
}

std::string actor_state_from_score(int total_score);

void fill_actor_score_result(VMWorkerActorScoreResult *result,
                             const VMWorkerActorScoreInput &input) {
  result->hp_pct_bp = ratio_bp(input.hp, input.max_hp);
  result->mp_pct_bp = ratio_bp(input.mp, input.max_mp);
  result->ep_pct_bp = ratio_bp(input.ep, input.max_ep);
  result->survival_score = result->hp_pct_bp;
  result->resource_score = (result->mp_pct_bp + result->ep_pct_bp) / 2;
  result->total_score = (result->survival_score * 7 + result->resource_score * 3) / 10;
  result->state = actor_state_from_score(result->total_score);
}

std::string actor_state_from_score(int total_score) {
  if (total_score >= 8000) {
    return "stable";
  }
  if (total_score >= 5000) {
    return "strained";
  }
  if (total_score > 0) {
    return "critical";
  }
  return "down";
}

class VMWorkerRuntime {
 public:
  ~VMWorkerRuntime() { stop(); }

  void start(int requested_workers) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!workers_.empty()) {
      return;
    }
    stopping_ = false;
    auto detected = static_cast<int>(std::thread::hardware_concurrency());
    auto count = requested_workers > 0 ? requested_workers : std::max(1, detected - 1);
    count = std::clamp(count, 1, 64);
    for (int i = 0; i < count; i++) {
      workers_.emplace_back([this] { run(); });
    }
  }

  void stop() {
    std::vector<std::thread> workers;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
      workers.swap(workers_);
    }
    cv_.notify_all();
    for (auto &worker : workers) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

  std::future<void> submit(std::function<void()> task) {
    auto promise = std::make_shared<std::promise<void>>();
    auto future = promise->get_future();
    auto accepted = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!stopping_) {
        accepted = true;
        submitted_++;
        tasks_.push_back(wrap_task(std::move(task), promise));
        update_queue_high_watermark(tasks_.size());
      }
    }
    if (!accepted) {
      try {
        throw std::runtime_error("VM worker runtime is stopping");
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
      return future;
    }
    cv_.notify_one();
    return future;
  }

  std::future<void> submit_keyed(std::string owner_key, std::function<void()> task) {
    if (owner_key.empty()) {
      return submit(std::move(task));
    }

    auto promise = std::make_shared<std::promise<void>>();
    auto future = promise->get_future();
    auto accepted = false;
    auto wrapped = wrap_task(std::move(task), promise, owner_key);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!stopping_) {
        accepted = true;
        submitted_++;
        if (running_owner_keys_.count(owner_key) == 0) {
          running_owner_keys_.insert(owner_key);
          tasks_.push_back(std::move(wrapped));
          update_queue_high_watermark(tasks_.size());
        } else {
          owner_queues_[owner_key].push_back(std::move(wrapped));
        }
      }
    }
    if (!accepted) {
      try {
        throw std::runtime_error("VM worker runtime is stopping");
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
      return future;
    }
    cv_.notify_one();
    return future;
  }

  VMWorkerStats stats() const {
    VMWorkerStats stats;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stats.worker_count = static_cast<int>(workers_.size());
      stats.submitted = submitted_.load();
      stats.completed = completed_.load();
      stats.queue_depth = tasks_.size();
      stats.queue_high_watermark = queue_high_watermark_.load();
      stats.owner_queue_depth = owner_queue_depth_locked();
      stats.active_owners = static_cast<int>(running_owner_keys_.size());
      stats.active = active_.load();
    }
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      for (const auto &entry : async_results_) {
        switch (entry.second.state) {
          case VMWorkerTaskState::kPending:
            stats.async_pending++;
            break;
          case VMWorkerTaskState::kSucceeded:
            stats.async_ready++;
            break;
          case VMWorkerTaskState::kFailed:
            stats.async_failed++;
            break;
          case VMWorkerTaskState::kUnknown:
            break;
        }
      }
    }
    return stats;
  }

  VMWorkerActorBenchResult actor_benchmark(int owners, int tasks_per_owner, int millis) {
    owners = std::clamp(owners, 1, 64);
    tasks_per_owner = std::clamp(tasks_per_owner, 1, 64);
    millis = std::clamp(millis, 1, 5000);
    start(0);

    auto stats = this->stats();
    auto total_tasks = owners * tasks_per_owner;
    auto start_barrier = std::make_shared<std::atomic<bool>>(false);
    auto active = std::make_shared<std::atomic<int>>(0);
    auto max_parallel = std::make_shared<std::atomic<int>>(0);
    auto checksum = std::make_shared<std::atomic<uint64_t>>(0);
    auto owner_active = std::make_shared<std::vector<std::atomic<int>>>(owners);
    auto max_owner_parallel = std::make_shared<std::atomic<int>>(0);
    std::vector<std::future<void>> futures;
    futures.reserve(total_tasks);

    auto start_time = std::chrono::steady_clock::now();
    for (int owner = 0; owner < owners; owner++) {
      for (int index = 0; index < tasks_per_owner; index++) {
        auto owner_key = std::string("actor/") + std::to_string(owner);
        futures.push_back(submit_keyed(owner_key, [=] {
          while (!start_barrier->load(std::memory_order_acquire)) {
            std::this_thread::yield();
          }
          auto running = active->fetch_add(1) + 1;
          update_max(*max_parallel, running);
          auto same_owner_running = (*owner_active)[owner].fetch_add(1) + 1;
          update_max(*max_owner_parallel, same_owner_running);
          auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
          uint64_t local = static_cast<uint64_t>((owner + 1) * 1000 + index + 1);
          while (std::chrono::steady_clock::now() < end) {
            local = local * 2862933555777941757ULL + 3037000493ULL;
          }
          checksum->fetch_add(local);
          (*owner_active)[owner].fetch_sub(1);
          active->fetch_sub(1);
        }));
      }
    }

    start_barrier->store(true, std::memory_order_release);
    for (auto &future : futures) {
      future.get();
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    stats = this->stats();
    return VMWorkerActorBenchResult{owners,
                                    tasks_per_owner,
                                    total_tasks,
                                    stats.worker_count,
                                    max_parallel->load(),
                                    max_owner_parallel->load(),
                                    elapsed.count(),
                                    checksum->load()};
  }

  VMWorkerSnapshotDigestResult snapshot_digest(std::string owner_key, std::string snapshot_text, int repeat) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    repeat = std::clamp(repeat, 1, 10000);
    start(0);

    auto input_bytes = static_cast<uint64_t>(snapshot_text.size());
    auto checksum = std::make_shared<std::atomic<uint64_t>>(0);
    auto start_time = std::chrono::steady_clock::now();
    auto future = submit_keyed(owner_key, [snapshot_text = std::move(snapshot_text), checksum, repeat] {
      uint64_t local = 1469598103934665603ULL;
      for (int i = 0; i < repeat; i++) {
        for (auto ch : snapshot_text) {
          local ^= static_cast<unsigned char>(ch);
          local *= 1099511628211ULL;
        }
        local ^= static_cast<uint64_t>(i + 1);
        local *= 1099511628211ULL;
      }
      checksum->store(local);
    });
    future.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    auto stats = this->stats();
    return VMWorkerSnapshotDigestResult{owner_key, stats.worker_count, elapsed.count(),
                                        input_bytes, repeat, checksum->load()};
  }

  VMWorkerActorScoreResult actor_score(std::string owner_key, VMWorkerActorScoreInput input) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    start(0);

    auto result = std::make_shared<VMWorkerActorScoreResult>();
    result->owner_key = owner_key;
    auto start_time = std::chrono::steady_clock::now();
    auto future = submit_keyed(owner_key, [result, input] {
      fill_actor_score_result(result.get(), input);
    });
    future.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    auto stats = this->stats();
    result->worker_count = stats.worker_count;
    result->elapsed_ms = elapsed.count();
    return *result;
  }

  uint64_t submit_actor_score(std::string owner_key, VMWorkerActorScoreInput input) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    start(0);

    auto id = next_task_id_++;
    auto started = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      AsyncRecord record;
      record.type = "actor_score";
      async_results_[id] = record;
    }

    submit_keyed(owner_key, [this, id, owner_key, input, started] {
      VMWorkerActorScoreResult score;
      score.owner_key = owner_key;
      fill_actor_score_result(&score, input);
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started);
      auto stats = this->stats();
      score.worker_count = stats.worker_count;
      score.elapsed_ms = elapsed.count();

      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(id);
      if (it != async_results_.end()) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        it->second.actor_score = score;
      }
    });
    return id;
  }

  uint64_t submit_benchmark(int tasks, int millis) {
    tasks = std::clamp(tasks, 1, 64);
    millis = std::clamp(millis, 1, 5000);
    start(0);

    auto id = next_task_id_++;
    auto stats = this->stats();
    auto state = std::make_shared<AsyncBenchmarkState>();
    state->task_id = id;
    state->tasks = tasks;
    state->worker_count = stats.worker_count;
    state->started = std::chrono::steady_clock::now();
    state->start_barrier = std::make_shared<std::atomic<bool>>(false);
    state->active = std::make_shared<std::atomic<int>>(0);
    state->max_parallel = std::make_shared<std::atomic<int>>(0);
    state->remaining = std::make_shared<std::atomic<int>>(tasks);
    state->checksum = std::make_shared<std::atomic<uint64_t>>(0);

    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      AsyncRecord record;
      record.type = "bench";
      async_results_[id] = record;
    }

    for (int i = 0; i < tasks; i++) {
      submit([this, state, millis, i] { run_async_benchmark_slice(state, millis, i); });
    }
    state->start_barrier->store(true, std::memory_order_release);
    return id;
  }

  uint64_t submit_snapshot_digest(std::string owner_key, std::string snapshot_text, int repeat) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    repeat = std::clamp(repeat, 1, 10000);
    start(0);

    auto id = next_task_id_++;
    auto input_bytes = static_cast<uint64_t>(snapshot_text.size());
    auto started = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      AsyncRecord record;
      record.type = "snapshot_digest";
      async_results_[id] = record;
    }

    submit_keyed(owner_key, [this, id, owner_key, snapshot_text = std::move(snapshot_text), repeat,
                             input_bytes, started] {
      uint64_t checksum = 1469598103934665603ULL;
      for (int i = 0; i < repeat; i++) {
        for (auto ch : snapshot_text) {
          checksum ^= static_cast<unsigned char>(ch);
          checksum *= 1099511628211ULL;
        }
        checksum ^= static_cast<uint64_t>(i + 1);
        checksum *= 1099511628211ULL;
      }
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started);
      auto stats = this->stats();
      VMWorkerSnapshotDigestResult digest{owner_key, stats.worker_count, elapsed.count(),
                                          input_bytes, repeat, checksum};
      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(id);
      if (it != async_results_.end()) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        it->second.snapshot_digest = digest;
      }
    });
    return id;
  }

  VMWorkerTaskResult poll(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = async_results_.find(task_id);
    if (it == async_results_.end()) {
      return VMWorkerTaskResult{task_id, VMWorkerTaskState::kUnknown, "", {}, {}, {}, "unknown worker task id"};
    }

    VMWorkerTaskResult result{task_id, it->second.state, it->second.type, it->second.bench,
                              it->second.snapshot_digest, it->second.actor_score, it->second.error};
    if (result.state == VMWorkerTaskState::kSucceeded || result.state == VMWorkerTaskState::kFailed) {
      async_results_.erase(it);
    }
    return result;
  }

 private:
  std::function<void()> wrap_task(std::function<void()> task,
                                  std::shared_ptr<std::promise<void>> promise,
                                  std::string owner_key = "") {
    return [this, task = std::move(task), promise, owner_key = std::move(owner_key)] {
      active_++;
      try {
        task();
        promise->set_value();
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
      active_--;
      completed_++;
      if (!owner_key.empty()) {
        release_owner_key(owner_key);
      }
    };
  }

  void release_owner_key(const std::string &owner_key) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto queue = owner_queues_.find(owner_key);
      if (queue != owner_queues_.end() && !queue->second.empty()) {
        tasks_.push_back(std::move(queue->second.front()));
        queue->second.pop_front();
        if (queue->second.empty()) {
          owner_queues_.erase(queue);
        }
        update_queue_high_watermark(tasks_.size());
      } else {
        running_owner_keys_.erase(owner_key);
      }
    }
    cv_.notify_one();
  }

  uint64_t owner_queue_depth_locked() const {
    uint64_t depth = 0;
    for (const auto &entry : owner_queues_) {
      depth += entry.second.size();
    }
    return depth;
  }

  void run() {
    Tracer::setThreadName("VM worker");
    while (true) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
        if (stopping_ && tasks_.empty()) {
          return;
        }
        task = std::move(tasks_.front());
        tasks_.pop_front();
      }
      task();
    }
  }

  void update_queue_high_watermark(uint64_t value) {
    auto current = queue_high_watermark_.load();
    while (value > current && !queue_high_watermark_.compare_exchange_weak(current, value)) {
    }
  }

  void run_async_benchmark_slice(std::shared_ptr<AsyncBenchmarkState> state, int millis, int index) {
    while (!state->start_barrier->load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    auto running = state->active->fetch_add(1) + 1;
    update_max(*state->max_parallel, running);
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
    uint64_t local = static_cast<uint64_t>(index + 1);
    while (std::chrono::steady_clock::now() < end) {
      local = local * 2862933555777941757ULL + 3037000493ULL;
    }
    state->checksum->fetch_add(local);
    state->active->fetch_sub(1);

    if (state->remaining->fetch_sub(1) == 1) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - state->started);
      VMWorkerBenchResult bench{state->tasks, state->worker_count, state->max_parallel->load(),
                                elapsed.count(), state->checksum->load()};
      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(state->task_id);
      if (it != async_results_.end()) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        it->second.bench = bench;
      }
    }
  }

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  bool stopping_{false};
  std::deque<std::function<void()>> tasks_;
  std::unordered_map<std::string, std::deque<std::function<void()>>> owner_queues_;
  std::unordered_set<std::string> running_owner_keys_;
  std::vector<std::thread> workers_;
  std::atomic<uint64_t> submitted_{0};
  std::atomic<uint64_t> completed_{0};
  std::atomic<uint64_t> queue_high_watermark_{0};
  std::atomic<int> active_{0};
  std::atomic<uint64_t> next_task_id_{1};
  mutable std::mutex results_mutex_;
  std::unordered_map<uint64_t, AsyncRecord> async_results_;
};

VMWorkerRuntime &runtime() {
  static VMWorkerRuntime instance;
  return instance;
}

}  // namespace

void vm_worker_start(int requested_workers) { runtime().start(requested_workers); }

void vm_worker_stop() { runtime().stop(); }

VMWorkerStats vm_worker_stats() { return runtime().stats(); }

VMWorkerBenchResult vm_worker_benchmark(int tasks, int millis) {
  tasks = std::clamp(tasks, 1, 64);
  millis = std::clamp(millis, 1, 5000);
  vm_worker_start();

  auto stats = vm_worker_stats();
  auto start_barrier = std::make_shared<std::atomic<bool>>(false);
  auto ready = std::make_shared<std::atomic<int>>(0);
  auto active = std::make_shared<std::atomic<int>>(0);
  auto max_parallel = std::make_shared<std::atomic<int>>(0);
  auto checksum = std::make_shared<std::atomic<uint64_t>>(0);
  std::vector<std::future<void>> futures;
  futures.reserve(tasks);

  auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < tasks; i++) {
    futures.push_back(runtime().submit([=] {
      ready->fetch_add(1);
      while (!start_barrier->load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      auto running = active->fetch_add(1) + 1;
      update_max(*max_parallel, running);
      auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
      uint64_t local = static_cast<uint64_t>(i + 1);
      while (std::chrono::steady_clock::now() < end) {
        local = local * 2862933555777941757ULL + 3037000493ULL;
      }
      checksum->fetch_add(local);
      active->fetch_sub(1);
    }));
  }

  auto barrier_target = std::min(tasks, std::max(1, stats.worker_count));
  while (ready->load() < barrier_target) {
    std::this_thread::yield();
  }
  start_barrier->store(true, std::memory_order_release);
  for (auto &future : futures) {
    future.get();
  }
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);
  stats = vm_worker_stats();
  return VMWorkerBenchResult{tasks, stats.worker_count, max_parallel->load(), elapsed.count(),
                             checksum->load()};
}

VMWorkerActorBenchResult vm_worker_actor_benchmark(int owners, int tasks_per_owner, int millis) {
  return runtime().actor_benchmark(owners, tasks_per_owner, millis);
}

VMWorkerSnapshotDigestResult vm_worker_snapshot_digest(std::string owner_key,
                                                       std::string snapshot_text,
                                                       int repeat) {
  return runtime().snapshot_digest(std::move(owner_key), std::move(snapshot_text), repeat);
}

VMWorkerActorScoreResult vm_worker_actor_score(std::string owner_key,
                                               VMWorkerActorScoreInput input) {
  return runtime().actor_score(std::move(owner_key), input);
}

uint64_t vm_worker_submit_benchmark(int tasks, int millis) {
  return runtime().submit_benchmark(tasks, millis);
}

uint64_t vm_worker_submit_snapshot_digest(std::string owner_key,
                                          std::string snapshot_text,
                                          int repeat) {
  return runtime().submit_snapshot_digest(std::move(owner_key), std::move(snapshot_text), repeat);
}

uint64_t vm_worker_submit_actor_score(std::string owner_key,
                                      VMWorkerActorScoreInput input) {
  return runtime().submit_actor_score(std::move(owner_key), input);
}

VMWorkerTaskResult vm_worker_poll_task(uint64_t task_id) { return runtime().poll(task_id); }
