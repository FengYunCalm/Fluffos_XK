#pragma once

#include "vm/internal/owner_future_store.h"
#include "vm/internal/owner_runtime_metrics.h"
#include "vm/internal/owner_scheduler_state.h"
#include "vm/internal/owner_trace_store.h"

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

class OwnerRuntimeCoordinator {
 public:
  OwnerRuntimeMetrics &metrics();
  OwnerFutureStore &futures();
  OwnerSchedulerState &scheduler();
  OwnerTraceStore &traces();

  std::mutex &mutex();
  std::condition_variable &cv();
  bool &thread_stopping();
  bool &main_draining();
  std::vector<std::thread> &threads();

 private:
  OwnerRuntimeMetrics metrics_;
  OwnerFutureStore futures_;
  OwnerSchedulerState scheduler_;
  OwnerTraceStore traces_;
  std::mutex mutex_;
  std::condition_variable cv_;
  bool thread_stopping_{false};
  bool main_draining_{false};
  std::vector<std::thread> threads_;
};

OwnerRuntimeCoordinator &owner_runtime_coordinator();
OwnerRuntimeMetrics &owner_runtime_metrics_instance();
OwnerFutureStore &owner_future_store_instance();
OwnerSchedulerState &owner_scheduler_state_instance();
OwnerTraceStore &owner_trace_store_instance();
std::mutex &owner_runtime_mutex_instance();
std::condition_variable &owner_runtime_cv_instance();
bool &owner_thread_stopping_flag();
bool &owner_main_draining_flag();
std::vector<std::thread> &owner_threads_instance();
