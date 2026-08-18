#pragma once

#include "vm/internal/owner_future_store.h"
#include "vm/internal/owner_runtime_metrics.h"
#include "vm/internal/owner_scheduler_state.h"
#include "vm/internal/owner_trace_store.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

// Owner-wide quiescence for recompile_object() (v0.4 §7): the state machine
// OPEN -> CLOSING -> FROZEN -> OPEN lives under the existing runtime mutex;
// there is deliberately no second lock.
enum class OwnerRecompileState { kOpen, kClosing, kFrozen };

// Why quiescence failed (distinct failure modes were previously conflated
// into one "timed out" text, which sent LPC-side debugging in circles).
enum class OwnerRecompileQuiesceFailure {
  kNone,
  kNotMainThread,
  kNestedTransaction,
  kThreadStopping,
  kTimeout,
};

struct OwnerRecompileQuiesceResult {
  bool ok{false};
  uint64_t epoch{0};
  OwnerRecompileQuiesceFailure failure{OwnerRecompileQuiesceFailure::kNone};
};

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

  // E3 P1: worker claim accounting. Only these methods touch the counters,
  // so a missed decrement cannot silently wedge quiescence.
  //
  // Lock contract is asymmetric on purpose: claim_begin_locked() runs while
  // the caller already holds the runtime mutex (the state machine's single
  // lock) and must NOT lock again; claim_end() runs outside the lock and
  // takes it internally. Do not "unify" this.
  void claim_begin_locked();
  void claim_end();

  // Recompile quiescence (E3 P1). Callers must hold no locks; begin/end take
  // the runtime mutex internally.
  OwnerRecompileState &recompile_state();

  // Read-only counters (F1: observable in runtime status). Mutation happens
  // only inside the state machine; external code cannot write these.
  uint64_t active_owner_claims() const;
  uint64_t quiesce_attempts() const;
  uint64_t quiesce_success() const;
  uint64_t quiesce_timeouts() const;
  uint64_t recompile_epoch() const;
  uint64_t advance_recompile_epoch();
  uint64_t admission_rejected() const;
  // E3 P1: semantic increment points for the quiescence lifecycle. Only
  // these methods (plus the state machine itself) may touch the counters.
  // All _locked variants require the caller to hold the runtime mutex
  // (same non-recursive mutex as the state machine -- locking inside would
  // self-deadlock); advance_recompile_epoch() has the same contract.
  void note_admission_rejected_locked();
  void note_quiesce_attempt_locked();
  void note_quiesce_success_locked();
  void note_quiesce_timeout_locked();

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

  OwnerRecompileState recompile_state_{OwnerRecompileState::kOpen};
  uint64_t recompile_epoch_{0};
  uint64_t active_owner_claims_{0};
  uint64_t quiesce_attempts_{0};
  uint64_t quiesce_success_{0};
  uint64_t quiesce_timeouts_{0};
  uint64_t admission_rejected_{0};
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

// E3 P1 public API. begin() is main-thread-only, transitions OPEN->CLOSING,
// waits (bounded by timeout) for active owner claims (worker-side,
// executor-local) to drain, then FROZEN. Any failure restores OPEN and returns ok=false. end() must be
// called with the matching epoch; it reopens admission.
OwnerRecompileQuiesceResult vm_owner_recompile_quiesce_begin(
    std::chrono::milliseconds timeout);
void vm_owner_recompile_quiesce_end(uint64_t epoch) noexcept;
// NOTE: there is intentionally no unlocked vm_owner_recompile_context_allowed()
// helper -- the only admission gate (enqueue_owner_task_locked in owner.cc)
// runs under the runtime mutex and reads recompile_state() directly. A
// locking helper here would self-deadlock on the same non-recursive mutex.
