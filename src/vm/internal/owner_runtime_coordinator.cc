#include "vm/internal/owner_runtime_coordinator.h"

#include "vm/context.h"

OwnerRuntimeMetrics &OwnerRuntimeCoordinator::metrics() { return metrics_; }

OwnerFutureStore &OwnerRuntimeCoordinator::futures() { return futures_; }

OwnerSchedulerState &OwnerRuntimeCoordinator::scheduler() { return scheduler_; }

OwnerTraceStore &OwnerRuntimeCoordinator::traces() { return traces_; }

std::mutex &OwnerRuntimeCoordinator::mutex() { return mutex_; }

std::condition_variable &OwnerRuntimeCoordinator::cv() { return cv_; }

bool &OwnerRuntimeCoordinator::thread_stopping() { return thread_stopping_; }

bool &OwnerRuntimeCoordinator::main_draining() { return main_draining_; }

std::vector<std::thread> &OwnerRuntimeCoordinator::threads() { return threads_; }

void OwnerRuntimeCoordinator::claim_begin_locked() {
  // Caller must already hold the runtime mutex (owner.cc claim_next_owner).
  active_owner_claims_++;
}

void OwnerRuntimeCoordinator::claim_end() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (active_owner_claims_ > 0) {
    active_owner_claims_--;
  }
  cv_.notify_all();
}

OwnerRecompileState &OwnerRuntimeCoordinator::recompile_state() { return recompile_state_; }

uint64_t OwnerRuntimeCoordinator::active_owner_claims() const { return active_owner_claims_; }

uint64_t OwnerRuntimeCoordinator::quiesce_attempts() const { return quiesce_attempts_; }

uint64_t OwnerRuntimeCoordinator::quiesce_success() const { return quiesce_success_; }

uint64_t OwnerRuntimeCoordinator::quiesce_timeouts() const { return quiesce_timeouts_; }

uint64_t OwnerRuntimeCoordinator::admission_rejected() const { return admission_rejected_; }

uint64_t OwnerRuntimeCoordinator::recompile_epoch() const { return recompile_epoch_; }

uint64_t OwnerRuntimeCoordinator::advance_recompile_epoch() {
  // Caller must hold the runtime mutex (quiesce_end path).
  return ++recompile_epoch_;
}

void OwnerRuntimeCoordinator::note_admission_rejected_locked() {
  // Caller must hold the runtime mutex (owner.cc enqueue_owner_task_locked).
  admission_rejected_++;
}

void OwnerRuntimeCoordinator::note_quiesce_attempt_locked() {
  // Caller must hold the runtime mutex (quiesce_begin path).
  quiesce_attempts_++;
}

void OwnerRuntimeCoordinator::note_quiesce_success_locked() {
  // Caller must hold the runtime mutex (quiesce_begin success path).
  quiesce_success_++;
}

void OwnerRuntimeCoordinator::note_quiesce_timeout_locked() {
  // Caller must hold the runtime mutex (quiesce_begin timeout path).
  quiesce_timeouts_++;
}

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

// E3 P1: owner-wide quiescence. begin() is main-thread-only; it closes
// admission, waits for active owner claims (worker-side, executor-local) to
// drain, then freezes. Any failure path restores OPEN. end() reopens with an epoch
// guard so a stale end() from a failed transaction cannot unlock a newer
// one. (v0.4 §7.)
OwnerRecompileQuiesceResult vm_owner_recompile_quiesce_begin(
    std::chrono::milliseconds timeout) {
  OwnerRecompileQuiesceResult result;
  auto &coordinator = owner_runtime_coordinator();
  std::unique_lock<std::mutex> lock(coordinator.mutex());

  if (!vm_context_is_main_thread()) {
    debug_message("recompile quiesce: not main thread\n");
    result.failure = OwnerRecompileQuiesceFailure::kNotMainThread;
    return result;  // ok=false: main-thread-only
  }
  if (coordinator.recompile_state() != OwnerRecompileState::kOpen) {
    debug_message("recompile quiesce: state != kOpen\n");
    result.failure = OwnerRecompileQuiesceFailure::kNestedTransaction;
    return result;  // nested/active transaction
  }
  // NOTE: there is deliberately no main_draining() guard here. Gateway and
  // socket commands execute inside the main-thread drain slice, so a guard
  // would reject every interactive recompile_object() call. The wait loop
  // below only counts worker-side activity (claims), which drains
  // independently of the main queue; tasks that reach the main queue after
  // the swap are dispatched serially on this same thread against the new
  // program, so no stale program can be executed across the swap.

  coordinator.note_quiesce_attempt_locked();
  coordinator.recompile_state() = OwnerRecompileState::kClosing;

  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (coordinator.active_owner_claims() != 0) {
    if (coordinator.thread_stopping()) {
      coordinator.recompile_state() = OwnerRecompileState::kOpen;
      coordinator.cv().notify_all();
      result.failure = OwnerRecompileQuiesceFailure::kThreadStopping;
      return result;
    }
    if (coordinator.cv().wait_until(lock, deadline) == std::cv_status::timeout) {
      coordinator.note_quiesce_timeout_locked();
      coordinator.recompile_state() = OwnerRecompileState::kOpen;
      coordinator.cv().notify_all();
      result.failure = OwnerRecompileQuiesceFailure::kTimeout;
      return result;
    }
  }

  coordinator.recompile_state() = OwnerRecompileState::kFrozen;
  coordinator.note_quiesce_success_locked();
  result.ok = true;
  result.epoch = coordinator.recompile_epoch();
  return result;
}

void vm_owner_recompile_quiesce_end(uint64_t epoch) noexcept {
  auto &coordinator = owner_runtime_coordinator();
  std::lock_guard<std::mutex> lock(coordinator.mutex());
  if (coordinator.recompile_state() == OwnerRecompileState::kFrozen &&
      coordinator.recompile_epoch() == epoch) {
    coordinator.advance_recompile_epoch();
    coordinator.recompile_state() = OwnerRecompileState::kOpen;
    coordinator.cv().notify_all();
  }
}

