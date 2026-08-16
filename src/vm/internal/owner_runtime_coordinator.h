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

struct OwnerRecompileQuiesceResult {
  bool ok{false};
  uint64_t epoch{0};
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

  // Recompile quiescence (E3 P1). Callers must hold no locks; begin/end take
  // the runtime mutex internally.
  OwnerRecompileState &recompile_state();
  uint64_t &recompile_epoch();
  uint64_t &active_worker_tasks();
  uint64_t &active_owner_claims();
  uint64_t &active_worker_program_pins();
  uint64_t &quiesce_attempts();
  uint64_t &quiesce_success();
  uint64_t &quiesce_timeouts();
  uint64_t &admission_rejected();

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
  uint64_t active_worker_tasks_{0};
  uint64_t active_owner_claims_{0};
  uint64_t active_worker_program_pins_{0};
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
// waits (bounded by timeout) for active worker tasks/claims/pins to drain,
// then FROZEN. Any failure restores OPEN and returns ok=false. end() must be
// called with the matching epoch; it reopens admission.
OwnerRecompileQuiesceResult vm_owner_recompile_quiesce_begin(
    std::chrono::milliseconds timeout);
void vm_owner_recompile_quiesce_end(uint64_t epoch) noexcept;
bool vm_owner_recompile_context_allowed() noexcept;
