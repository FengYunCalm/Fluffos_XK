#pragma once

#include <atomic>
#include <cstdint>

#define OWNER_RUNTIME_METRIC_FIELDS(X)                           \
  X(total_checks, 0)                                              \
  X(mismatch_checks, 0)                                           \
  X(next_mailbox_task_id, 1)                                      \
  X(total_enqueued, 0)                                            \
  X(total_drained, 0)                                             \
  X(total_cross_owner_accesses, 0)                                \
  X(total_cross_owner_snapshot_accesses, 0)                       \
  X(total_cross_owner_message_accesses, 0)                        \
  X(total_cross_owner_rejected_accesses, 0)                       \
  X(total_cross_owner_enforced_blocks, 0)                         \
  X(owner_thread_dispatched, 0)                                   \
  X(owner_executor_budget_yields, 0)                              \
  X(owner_thread_starts, 0)                                       \
  X(owner_thread_stops, 0)                                        \
  X(owner_thread_context_bound, 0)                                \
  X(owner_thread_object_store_isolated, 0)                        \
  X(owner_thread_owner_bound, 0)                                  \
  X(owner_thread_owner_cleared, 0)                                \
  X(owner_thread_execution_cleared, 0)                            \
  X(owner_thread_eval_stack_owner_bound, 0)                       \
  X(owner_thread_eval_stack_cleared, 0)                           \
  X(owner_thread_eval_stack_leak_detected, 0)                     \
  X(owner_thread_control_stack_owner_bound, 0)                    \
  X(owner_thread_control_stack_cleared, 0)                        \
  X(owner_thread_control_stack_leak_detected, 0)                  \
  X(owner_thread_value_stack_owner_bound, 0)                      \
  X(owner_thread_value_stack_cleared, 0)                          \
  X(owner_thread_value_stack_leak_detected, 0)                    \
  X(owner_thread_apply_return_owner_bound, 0)                     \
  X(owner_thread_apply_return_cleared, 0)                         \
  X(owner_thread_apply_return_leak_detected, 0)                   \
  X(owner_thread_lpc_canary_flag_cleared, 0)                      \
  X(owner_thread_context_leak_detected, 0)                        \
  X(owner_thread_lpc_rejected, 0)                                 \
  X(owner_thread_owner_state_guarded, 0)                          \
  X(owner_thread_message_dispatched, 0)                           \
  X(owner_executor_command_consume_entry_executed, 0)             \
  X(owner_executor_command_frame_restore_entry_executed, 0)       \
  X(owner_thread_gateway_command_guarded, 0)                      \
  X(owner_thread_gateway_command_rejected, 0)                     \
  X(owner_thread_lpc_probe_executed, 0)                           \
  X(owner_thread_lpc_probe_failed, 0)                             \
  X(owner_thread_lpc_probe_guarded, 0)                            \
  X(owner_thread_lpc_canary_executed, 0)                          \
  X(owner_thread_lpc_canary_succeeded, 0)                         \
  X(owner_thread_lpc_canary_failed, 0)                            \
  X(owner_thread_lpc_canary_rejected, 0)                          \
  X(owner_thread_lpc_task_executed, 0)                            \
  X(owner_thread_lpc_task_succeeded, 0)                           \
  X(owner_thread_lpc_task_failed, 0)                              \
  X(owner_thread_lpc_task_rejected, 0)                            \
  X(owner_async_queue_wait_ns_total, 0)                           \
  X(owner_async_queue_wait_ns_max, 0)                             \
  X(owner_async_queue_wait_samples, 0)                            \
  X(owner_async_lpc_execute_ns_total, 0)                          \
  X(owner_async_lpc_execute_ns_max, 0)                            \
  X(owner_async_lpc_execute_samples, 0)                           \
  X(owner_async_lpc_execute_thread_cpu_ns_total, 0)               \
  X(owner_async_lpc_execute_thread_cpu_unavailable, 0)            \
  X(owner_async_result_completion_ns_total, 0)                    \
  X(owner_async_result_completion_ns_max, 0)                      \
  X(owner_async_result_completion_samples, 0)                     \
  X(owner_async_result_completion_thread_cpu_ns_total, 0)         \
  X(owner_async_result_completion_thread_cpu_unavailable, 0)      \
  X(owner_thread_ordinary_lpc_executed, 0)                        \
  X(owner_thread_ordinary_lpc_succeeded, 0)                       \
  X(owner_thread_ordinary_lpc_failed, 0)                          \
  X(owner_thread_ordinary_lpc_rejected, 0)                        \
  X(owner_thread_compute_result_completed, 0)                     \
  X(owner_executor_callback_queued, 0)                            \
  X(owner_executor_callback_dispatched, 0)                        \
  X(owner_executor_callback_dropped, 0)                           \
  X(owner_executor_callback_main_cleanup_queued, 0)               \
  X(owner_executor_callback_main_cleanup_dispatched, 0)           \
  X(owner_executor_admission_accepted, 0)                         \
  X(owner_executor_admission_rejected, 0)                         \
  X(owner_executor_admission_dropped, 0)                          \
  X(owner_executor_stale_drop, 0)                                 \
  X(owner_executor_destructed_drop, 0)                            \
  X(owner_executor_epoch_mismatch_drop, 0)                        \
  X(owner_executor_future_timeout, 0)                             \
  X(owner_executor_future_cancelled, 0)                           \
  X(owner_executor_backpressure_rejected, 0)                       \
  X(owner_executor_owner_claims, 0)                               \
  X(owner_executor_owner_releases, 0)                             \
  X(owner_executor_runnable_task_dispatched, 0)                   \
  X(owner_executor_safe_task_dispatched, 0)                       \
  X(owner_executor_probe_executed, 0)                             \
  X(owner_executor_main_required_skipped, 0)                      \
  X(owner_executor_max_parallel_owners, 0)                        \
  X(owner_executor_max_owner_parallel, 0)                         \
  X(owner_executor_same_owner_claim_conflicts, 0)                 \
  X(owner_main_queued, 0)                                         \
  X(owner_main_dispatched, 0)                                     \
  X(owner_main_stale, 0)                                          \
  X(owner_main_destructed, 0)                                     \
  X(owner_main_budget_yields, 0)                                  \
  X(owner_normal_path_main_fallback_count, 0)                     \
  X(owner_explicit_main_fallback_count, 0)                        \
  X(owner_off_mode_main_fallback_count, 0)                        \
  X(owner_main_io_adapter_count, 0)                               \
  X(owner_main_cleanup_adapter_count, 0)                          \
  X(owner_main_owner_claims, 0)                                   \
  X(owner_main_owner_releases, 0)

struct OwnerRuntimeMetricsSnapshot {
#define OWNER_RUNTIME_METRIC_SNAPSHOT_FIELD(name, initial) uint64_t name{initial};
  OWNER_RUNTIME_METRIC_FIELDS(OWNER_RUNTIME_METRIC_SNAPSHOT_FIELD)
#undef OWNER_RUNTIME_METRIC_SNAPSHOT_FIELD
};

class OwnerRuntimeMetrics {
 public:
#define OWNER_RUNTIME_METRIC_ATOMIC_FIELD(name, initial) std::atomic<uint64_t> name{initial};
  OWNER_RUNTIME_METRIC_FIELDS(OWNER_RUNTIME_METRIC_ATOMIC_FIELD)
#undef OWNER_RUNTIME_METRIC_ATOMIC_FIELD

  OwnerRuntimeMetricsSnapshot snapshot() const;
};
