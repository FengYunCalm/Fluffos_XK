#include "vm/internal/owner_runtime_coordinator.h"

OwnerRuntimeMetrics &OwnerRuntimeCoordinator::metrics() { return metrics_; }

OwnerFutureStore &OwnerRuntimeCoordinator::futures() { return futures_; }

OwnerSchedulerState &OwnerRuntimeCoordinator::scheduler() { return scheduler_; }

OwnerTraceStore &OwnerRuntimeCoordinator::traces() { return traces_; }

std::mutex &OwnerRuntimeCoordinator::mutex() { return mutex_; }

std::condition_variable &OwnerRuntimeCoordinator::cv() { return cv_; }

bool &OwnerRuntimeCoordinator::thread_stopping() { return thread_stopping_; }

bool &OwnerRuntimeCoordinator::main_draining() { return main_draining_; }

std::vector<std::thread> &OwnerRuntimeCoordinator::threads() { return threads_; }

OwnerRuntimeCoordinator &owner_runtime_coordinator() {
  static OwnerRuntimeCoordinator coordinator;
  return coordinator;
}

OwnerRuntimeMetrics &owner_runtime_metrics_instance() { return owner_runtime_coordinator().metrics(); }

OwnerFutureStore &owner_future_store_instance() { return owner_runtime_coordinator().futures(); }

OwnerSchedulerState &owner_scheduler_state_instance() { return owner_runtime_coordinator().scheduler(); }

OwnerTraceStore &owner_trace_store_instance() { return owner_runtime_coordinator().traces(); }

std::mutex &owner_runtime_mutex_instance() { return owner_runtime_coordinator().mutex(); }

std::condition_variable &owner_runtime_cv_instance() { return owner_runtime_coordinator().cv(); }

bool &owner_thread_stopping_flag() { return owner_runtime_coordinator().thread_stopping(); }

bool &owner_main_draining_flag() { return owner_runtime_coordinator().main_draining(); }

std::vector<std::thread> &owner_threads_instance() { return owner_runtime_coordinator().threads(); }
