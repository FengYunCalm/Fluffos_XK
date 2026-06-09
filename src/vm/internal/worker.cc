#include "vm/worker.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "base/internal/tracing.h"

namespace {

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
    {
      std::lock_guard<std::mutex> lock(mutex_);
      submitted_++;
      tasks_.push_back([this, task = std::move(task), promise] {
        active_++;
        try {
          task();
          promise->set_value();
        } catch (...) {
          promise->set_exception(std::current_exception());
        }
        active_--;
        completed_++;
      });
    }
    cv_.notify_one();
    return future;
  }

  VMWorkerStats stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return VMWorkerStats{static_cast<int>(workers_.size()), submitted_.load(), completed_.load(),
                         active_.load()};
  }

 private:
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

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  bool stopping_{false};
  std::deque<std::function<void()>> tasks_;
  std::vector<std::thread> workers_;
  std::atomic<uint64_t> submitted_{0};
  std::atomic<uint64_t> completed_{0};
  std::atomic<int> active_{0};
};

VMWorkerRuntime &runtime() {
  static VMWorkerRuntime instance;
  return instance;
}

void update_max(std::atomic<int> &target, int value) {
  auto current = target.load();
  while (value > current && !target.compare_exchange_weak(current, value)) {
  }
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
