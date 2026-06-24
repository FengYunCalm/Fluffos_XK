#include "base/package_api.h"

#include "vm/context.h"
#include "vm/frozen_value.h"
#include "vm/object_handle.h"
#include "vm/owner.h"
#include "vm/internal/owner_executor.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {
constexpr const char *kDefaultOwnerId = "legacy/main";
constexpr size_t kOwnerTraceLimit = 256;
constexpr size_t kOwnerAccessTraceLimit = 256;
constexpr size_t kOwnerMessageTraceLimit = 256;
constexpr size_t kOwnerCommitTraceLimit = 256;
constexpr size_t kOwnerExecutorTraceLimit = 256;
constexpr int kOwnerExecutorTaskBudget = 32;
constexpr const char *kOwnerExecutorContractVersion = "owner_executor_v1";

struct OwnerLpcTaskDescriptor {
  const char *method;
  const char *executor_mode;
  const char *route;
  const char *result_policy;
  const char *reason;
  int executor_safe;
  int main_required;
  int rejected;
  int requires_target;
  int requires_owner_thread;
  int requires_owner_message_completion;
  int frozen_result_required;
  int direct_cross_owner_write;
};

constexpr std::array<OwnerLpcTaskDescriptor, 1> kOwnerLpcTaskDescriptors = {
    {{"owner_task_readonly", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
      "registered readonly owner task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0}}};

struct OwnerTaskRouteContract {
  const char *executor_mode;
  const char *route;
  const char *reason;
  int executor_safe;
  int main_required;
  int rejected;
  int requires_owner_mailbox;
  int requires_owner_main_queue;
};

constexpr OwnerTaskRouteContract kOwnerTaskExecutorSafeContract = {
    "executor_safe", "owner_executor", "mailbox task is safe for owner executor", 1, 0, 0, 1, 0};
constexpr OwnerTaskRouteContract kOwnerTaskMainRequiredContract = {
    "main_required", "owner_main_queue", "object target handle must run on main bridge", 0, 1, 0, 0, 1};

enum class OwnerExecutorDispatchKind {
  ExecutorProbe,
  LpcProbe,
  LpcCanary,
  LpcTask,
  OrdinaryLpc,
  RejectLpc,
  GuardOwnerState,
  OwnerMessage,
  CommandConsume,
  CommandFrameRestore,
  GatewayCommand,
  ExecutorCallback,
  ComputeResult,
  Generic,
};

struct OwnerExecutorTaskDescriptor {
  const char *task_type;
  const char *contract_key;
  OwnerExecutorDispatchKind dispatch_kind;
  const char *executor_mode;
  const char *route;
  const char *reason;
  int executor_runnable;
  int executor_safe;
  int main_required;
  int rejected;
  int requires_owner_mailbox;
  int requires_owner_main_queue;
};

constexpr const char *kGatewayCommandExecutorActivationBlocker = "";

constexpr std::array<OwnerExecutorTaskDescriptor, 18> kOwnerExecutorTaskDescriptors = {{
    {"executor_probe", "executor_probe", OwnerExecutorDispatchKind::ExecutorProbe, "executor_safe", "owner_executor",
     "diagnostic owner executor task", 1, 1, 0, 0, 1, 0},
    {"lpc_probe", "lpc_probe", OwnerExecutorDispatchKind::LpcProbe, "executor_safe", "owner_executor",
     "diagnostic off-main LPC probe", 1, 1, 0, 0, 1, 0},
    {"lpc_canary", "lpc_canary", OwnerExecutorDispatchKind::LpcCanary, "executor_safe", "owner_executor",
     "restricted owner LPC canary", 1, 1, 0, 0, 1, 0},
    {"lpc_task", "lpc_task_allowlist", OwnerExecutorDispatchKind::LpcTask, "executor_safe_allowlist",
     "owner_executor", "registered LPC tasks only; ordinary LPC remains default closed", 1, 1, 0, 0, 1, 0},
    {"ordinary_lpc", "ordinary_lpc_dispatch", OwnerExecutorDispatchKind::OrdinaryLpc,
     "executor_safe_explicit_open", "owner_executor",
     "generic owner LPC dispatch requires explicit open and frozen result", 1, 1, 0, 0, 1, 0},
    {"lpc", "lpc", OwnerExecutorDispatchKind::RejectLpc, "rejected", "owner_executor",
     "ordinary LPC remains default closed for legacy lpc tasks", 1, 0, 0, 1, 1, 0},
    {"owner_state", "owner_state", OwnerExecutorDispatchKind::GuardOwnerState, "rejected", "owner_executor",
     "owner state mutation is guarded off-main", 1, 0, 0, 1, 1, 0},
    {"owner_message", "owner_message_mailbox", OwnerExecutorDispatchKind::OwnerMessage, "executor_safe",
     "owner_executor", "mailbox task is safe for owner executor when it has no target handle", 1, 1, 0, 0, 1, 0},
    {"command_consume", "owner_executor_command_consumer", OwnerExecutorDispatchKind::CommandConsume,
     "executor_safe", "owner_executor", "redacted owner command consume entry without LPC execution", 1, 1, 0,
     0, 1, 0},
    {"command_frame_restore", "owner_executor_command_frame_restore", OwnerExecutorDispatchKind::CommandFrameRestore,
     "executor_safe", "owner_executor", "restores redacted gateway command execution frame without LPC execution", 1,
     1, 0, 0, 1, 0},
    {"gateway_command", "gateway_command_executor_activation", OwnerExecutorDispatchKind::GatewayCommand,
     "executor_safe", "owner_executor",
     "guarded gateway command activation with owner epoch and frame cleanup checks", 1, 1, 0, 0, 1, 0},
    {"heartbeat", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback, "executor_safe_callback",
     "owner_executor", "driver heartbeat callback closure on target owner executor", 1, 1, 0, 0, 1, 0},
    {"call_out", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback, "executor_safe_callback",
     "owner_executor", "driver call_out callback closure on target owner executor", 1, 1, 0, 0, 1, 0},
    {"async_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "executor_safe_callback", "owner_executor", "async worker callback closure with frozen result", 1, 1, 0, 0,
     1, 0},
    {"dns_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "executor_safe_callback", "owner_executor", "DNS callback closure with frozen result", 1, 1, 0, 0, 1, 0},
    {"socket_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "executor_safe_callback", "owner_executor", "socket callback closure with main-thread cleanup", 1, 1, 0, 0,
     1, 0},
    {"gateway_command_execute", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "executor_safe_callback", "owner_executor", "guarded gateway command execution callback closure", 1, 1, 0, 0,
     1, 0},
    {"compute_result", "compute_result", OwnerExecutorDispatchKind::ComputeResult, "executor_safe",
     "owner_executor", "worker v2 result completion", 1, 1, 0, 0, 1, 0},
}};

struct VMContextReadinessGate {
  const char *gate;
  const char *model;
  const char *blocker;
  const char *next_action;
  int satisfied;
};

struct GatewayCommandSideEffectReadinessGate {
  const char *gate;
  const char *model;
  const char *blocker;
  const char *next_action;
  const char *state_owner;
  const char *migration_boundary;
  const char *side_effect_class;
  const char *snapshot_policy;
  int snapshot_ready;
  int state_redacted;
  int blocks_activation;
  int satisfied;
};

struct FrozenPayloadContractEntry {
  const char *path;
  const char *input_policy;
  const char *result_policy;
  int uses_shared_validator;
  int top_level_mapping_required;
  int frozen_result_required;
};

struct GatewayOwnerTaskContractEntry {
  const char *task_type;
  const char *task_key;
  const char *executor_mode;
  const char *route;
  const char *owner_scope_model;
  const char *stale_policy;
  const char *payload_key;
  const char *input_payload_policy;
  const char *command_consume_model;
  int command_consume_snapshot_ready;
  int command_consume_executor_ready;
  const char *command_consume_blocker;
  const char *execution_frame_model;
  const char *execution_frame_policy;
  const char *execution_frame_restore_policy;
  const char *execution_frame_restore_blocker;
  int execution_frame_restore_ready;
  int execution_frame_executor_ready;
  int main_required;
  int executor_safe;
  int requires_owner_main_queue;
  int requires_owner_scope;
  int requires_current_interactive;
  int requires_command_giver;
  int ordinary_lpc_ready_required;
  int command_serial_per_owner;
  int requires_target_handle;
  int requires_frozen_payload;
};

constexpr std::array<FrozenPayloadContractEntry, 5> kFrozenPayloadContractEntries = {{
    {"owner_send", "owner_payload", "future_pending_no_result", 1, 1, 0},
    {"owner_call_async", "owner_payload", "frozen_result_required", 1, 1, 1},
    {"owner_publish_snapshot", "owner_payload", "snapshot_only", 1, 1, 0},
    {"worker_snapshot", "worker_value", "owner_future_frozen_result_required", 1, 0, 1},
    {"domain_task", "domain_task_payload", "owner_future_frozen_result_required", 1, 1, 1},
}};

constexpr std::array<const char *, 5> kFrozenPayloadAllowedTypes = {{"number", "real", "string", "array", "mapping"}};
constexpr std::array<const char *, 4> kFrozenPayloadRejectedTypes = {{"object", "function", "buffer", "class"}};

constexpr std::array<GatewayOwnerTaskContractEntry, 4> kGatewayOwnerTaskContracts = {{
    {"gateway", "gateway_receive", "main_required", "owner_main_queue", "owner_scope_and_current_interactive",
     "owner_epoch_target_guard", "gateway_receive_data", "direct_lpc_payload", "", 0, 0, "",
     "gateway_receive_execution_frame_v1", "owner_scope_current_interactive_command_giver", "", "", 0, 0, 1, 0, 1,
     1, 1, 1, 0, 1, 0, 0},
    {"gateway", "process_user_command", "main_required", "owner_main_queue", "interactive_owner_scope_frame",
     "owner_epoch_target_guard", "gateway_command_input", "buffer_metadata_no_raw_command_text",
     "owner_owned_snapshot_main_thread_consume", 1, 1, "",
     "gateway_command_execution_frame_v1", "owner_scope_current_interactive_command_giver",
     "owner_executor_vmcontext_restore", "", 1, 1, 1, 0, 1, 1, 1, 1,
     0, 1, 1, 1},
    {"gateway", "gateway_logon", "main_required", "direct_main_owner_scope", "owner_scope_and_current_interactive",
     "session_owner_resolve_after_exec", "gateway_logon_data", "direct_lpc_payload", "", 0, 0, "",
     "gateway_session_lifecycle_frame_v1", "owner_scope_current_interactive_command_giver", "", "", 0, 0, 1, 0,
     0, 1, 1, 1, 0, 1, 0, 0},
    {"gateway", "gateway_disconnected", "main_required", "direct_main_owner_scope",
     "owner_scope_and_current_interactive", "session_owner_resolve_after_exec", "gateway_disconnect_reason",
     "direct_lpc_payload", "", 0, 0, "", "gateway_session_lifecycle_frame_v1",
     "owner_scope_current_interactive_command_giver", "", "", 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0},
}};

constexpr std::array<VMContextReadinessGate, 7> kGatewayCommandExecutorReadinessGates = {{
    {"owner_epoch_target_handle_guard", "owner_epoch_target_handle_guard", "",
     "keep_stale_command_drop_before_dispatch", 1},
    {"owner_owned_command_snapshot", "gateway_command_text_snapshot", "",
     "keep_command_text_snapshot_private_and_redacted_from_trace", 1},
    {"owner_owned_command_consume", "gateway_command_consume_owner_transfer", "",
     "keep_owner_snapshot_command_consume_private_and_main_thread_bound", 1},
    {"owner_executor_command_consume_entry", "owner_executor_command_consumer", "",
     "keep_command_consume_entry_without_lpc_execution", 1},
    {"owner_executor_frame_restore", "gateway_command_execution_frame_v1", "",
     "keep_gateway_command_frame_restore_without_lpc_execution", 1},
    {"ordinary_lpc_ready", "ordinary_lpc_executor_dispatch", "",
     "keep_generic_lpc_dispatch_explicit_open_only", 1},
    {"gateway_command_executor_activation", "gateway_command_executor_rollout",
     kGatewayCommandExecutorActivationBlocker, "keep_guarded_executor_activation_before_production_rollout", 1},
}};

constexpr std::array<GatewayCommandSideEffectReadinessGate, 5> kGatewayCommandSideEffectReadinessGates = {{
    {"interactive_buffer_consume", "owner_snapshot_main_thread_consume", "",
     "keep_snapshot_consume_before_executor_activation", "owner_command_snapshot",
     "main_thread_consume_before_executor_activation", "input_buffer_consume",
     "owner_private_command_text_snapshot_v1", 1, 1, 0, 1},
    {"input_to_get_char_state", "interactive_input_callback_state", "",
     "keep_input_callback_state_in_owner_command_frame",
     "owner_command_frame", "owner_command_frame_input_callback_executor", "input_callback_state",
     "redacted_input_to_get_char_state_v1", 1, 1, 0, 1},
    {"process_input_add_action_parser", "interactive_command_parser_state", "",
     "keep_parser_state_in_owner_command_frame",
     "owner_command_frame", "owner_command_parser_context_executor", "parser_command_giver_state",
     "redacted_process_input_add_action_parser_state_v1", 1, 1, 0, 1},
    {"prompt_telnet_reschedule_io", "interactive_output_reschedule_state", "",
     "keep_prompt_telnet_reschedule_in_main_reply_queue_after_owner_command",
     "main_reply_queue_and_network_io", "main_reply_queue_after_owner_command", "prompt_telnet_reschedule_io",
     "redacted_prompt_telnet_reschedule_io_v1", 1, 1, 0, 1},
    {"interactive_mode_flags", "interactive_flags_echo_mxp_ed_state", "",
     "keep_echo_mxp_ed_mode_mutations_in_owner_command_frame",
     "owner_command_frame", "owner_command_frame_mode_delta_executor", "echo_mxp_ed_mode_flags",
     "redacted_interactive_mode_flags_v1", 1, 1, 0, 1},
}};

constexpr std::array<VMContextReadinessGate, 13> kVMContextOrdinaryLpcReadinessGates = {{
    {"thread_local_vm_context", "thread_local_vm_context", "", "keep_thread_local_context_binding", 1},
    {"execution_state_contextualized", "vm_context_execution_snapshot", "", "keep_execution_state_api_only", 1},
    {"owner_scope_contextualized", "vm_context_owner_scope", "", "keep_owner_scope_api_only", 1},
    {"error_state_contextualized", "vm_context_error_snapshot", "", "keep_error_state_api_only", 1},
    {"off_main_object_store_sync_rejected", "owner_local_object_store", "", "keep_sync_rejection_guard", 1},
    {"eval_stack_owner_local", "thread_local_owner_execution_stack", "",
     "keep_eval_stack_synced_to_owner_vm_context", 1},
    {"control_stack_owner_local", "thread_local_owner_control_stack", "",
     "keep_control_stack_synced_to_owner_vm_context", 1},
    {"value_stack_owner_local", "thread_local_owner_value_stack", "",
     "keep_value_stack_synced_to_owner_vm_context", 1},
    {"apply_return_owner_local", "thread_local_owner_apply_return", "",
     "keep_apply_return_synced_to_owner_vm_context", 1},
    {"object_refs_owner_local", "object_handle_boundary", "",
     "keep_cross_owner_object_refs_handle_or_frozen_payload_only", 1},
    {"object_store_owner_local_complete", "owner_local_object_store", "",
     "keep_owner_local_store_canonical_without_global_fallback", 1},
    {"ordinary_lpc_activation_policy", "default_closed_explicit_open_policy", "",
     "keep_default_closed_until_dispatch_path_ready", 1},
    {"ordinary_lpc_dispatch_path", "ordinary_lpc_executor_dispatch", "",
     "keep_generic_dispatch_explicit_open_and_frozen_result_guarded", 1},
}};

struct OwnerComputeResultField {
  std::string key;
  std::string string_value;
  int64_t number_value{0};
  bool is_string{false};
};

std::atomic<uint64_t> total_checks{0};
std::atomic<uint64_t> mismatch_checks{0};
std::atomic<uint64_t> next_mailbox_task_id{1};
std::atomic<uint64_t> next_trace_id{1};
std::atomic<uint64_t> total_enqueued{0};
std::atomic<uint64_t> total_drained{0};
std::atomic<uint64_t> total_traced{0};
std::atomic<uint64_t> next_access_trace_id{1};
std::atomic<uint64_t> total_access_traced{0};
std::atomic<uint64_t> total_cross_owner_accesses{0};
std::atomic<uint64_t> total_cross_owner_snapshot_accesses{0};
std::atomic<uint64_t> total_cross_owner_message_accesses{0};
std::atomic<uint64_t> total_cross_owner_rejected_accesses{0};
std::atomic<uint64_t> total_cross_owner_enforced_blocks{0};
std::atomic<uint64_t> next_message_trace_id{1};
std::atomic<uint64_t> total_message_traced{0};
std::atomic<uint64_t> total_futures_completed{0};
std::atomic<uint64_t> total_futures_failed{0};
std::atomic<uint64_t> next_commit_trace_id{1};
std::atomic<uint64_t> total_commit_traced{0};
std::atomic<uint64_t> next_executor_trace_id{1};
std::atomic<uint64_t> total_executor_traced{0};
std::atomic<uint64_t> owner_thread_dispatched{0};
std::atomic<uint64_t> owner_executor_budget_yields{0};
std::string owner_executor_last_budget_yield_owner;
long owner_executor_last_budget_yield_backlog{0};
long owner_executor_last_budget_yield_safe_backlog{0};
std::atomic<uint64_t> owner_thread_starts{0};
std::atomic<uint64_t> owner_thread_stops{0};
std::atomic<uint64_t> owner_thread_context_bound{0};
std::atomic<uint64_t> owner_thread_object_store_isolated{0};
std::atomic<uint64_t> owner_thread_owner_bound{0};
std::atomic<uint64_t> owner_thread_owner_cleared{0};
std::atomic<uint64_t> owner_thread_execution_cleared{0};
std::atomic<uint64_t> owner_thread_eval_stack_owner_bound{0};
std::atomic<uint64_t> owner_thread_eval_stack_cleared{0};
std::atomic<uint64_t> owner_thread_eval_stack_leak_detected{0};
std::atomic<uint64_t> owner_thread_control_stack_owner_bound{0};
std::atomic<uint64_t> owner_thread_control_stack_cleared{0};
std::atomic<uint64_t> owner_thread_control_stack_leak_detected{0};
std::atomic<uint64_t> owner_thread_value_stack_owner_bound{0};
std::atomic<uint64_t> owner_thread_value_stack_cleared{0};
std::atomic<uint64_t> owner_thread_value_stack_leak_detected{0};
std::atomic<uint64_t> owner_thread_apply_return_owner_bound{0};
std::atomic<uint64_t> owner_thread_apply_return_cleared{0};
std::atomic<uint64_t> owner_thread_apply_return_leak_detected{0};
std::atomic<uint64_t> owner_thread_lpc_canary_flag_cleared{0};
std::atomic<uint64_t> owner_thread_context_leak_detected{0};
std::atomic<uint64_t> owner_thread_lpc_rejected{0};
std::atomic<uint64_t> owner_thread_owner_state_guarded{0};
std::atomic<uint64_t> owner_thread_message_dispatched{0};
std::atomic<uint64_t> owner_executor_command_consume_entry_executed{0};
std::atomic<uint64_t> owner_executor_command_frame_restore_entry_executed{0};
std::atomic<uint64_t> owner_thread_gateway_command_guarded{0};
std::atomic<uint64_t> owner_thread_gateway_command_rejected{0};
std::atomic<uint64_t> owner_thread_lpc_probe_executed{0};
std::atomic<uint64_t> owner_thread_lpc_probe_failed{0};
std::atomic<uint64_t> owner_thread_lpc_probe_guarded{0};
std::atomic<uint64_t> owner_thread_lpc_canary_executed{0};
std::atomic<uint64_t> owner_thread_lpc_canary_succeeded{0};
std::atomic<uint64_t> owner_thread_lpc_canary_failed{0};
std::atomic<uint64_t> owner_thread_lpc_canary_rejected{0};
std::atomic<uint64_t> owner_thread_lpc_task_executed{0};
std::atomic<uint64_t> owner_thread_lpc_task_succeeded{0};
std::atomic<uint64_t> owner_thread_lpc_task_failed{0};
std::atomic<uint64_t> owner_thread_lpc_task_rejected{0};
std::atomic<uint64_t> owner_thread_ordinary_lpc_executed{0};
std::atomic<uint64_t> owner_thread_ordinary_lpc_succeeded{0};
std::atomic<uint64_t> owner_thread_ordinary_lpc_failed{0};
std::atomic<uint64_t> owner_thread_ordinary_lpc_rejected{0};
std::atomic<uint64_t> owner_thread_compute_result_completed{0};
std::atomic<uint64_t> owner_executor_callback_queued{0};
std::atomic<uint64_t> owner_executor_callback_dispatched{0};
std::atomic<uint64_t> owner_executor_callback_dropped{0};
std::atomic<uint64_t> owner_executor_callback_main_cleanup_queued{0};
std::atomic<uint64_t> owner_executor_callback_main_cleanup_dispatched{0};
std::atomic<uint64_t> owner_executor_owner_claims{0};
std::atomic<uint64_t> owner_executor_owner_releases{0};
std::atomic<uint64_t> owner_executor_runnable_task_dispatched{0};
std::atomic<uint64_t> owner_executor_safe_task_dispatched{0};
std::atomic<uint64_t> owner_executor_probe_executed{0};
std::atomic<uint64_t> owner_executor_main_required_skipped{0};
std::atomic<uint64_t> owner_executor_max_parallel_owners{0};
std::atomic<uint64_t> owner_executor_max_owner_parallel{0};
std::atomic<uint64_t> owner_executor_same_owner_claim_conflicts{0};
std::atomic<uint64_t> owner_main_queued{0};
std::atomic<uint64_t> owner_main_dispatched{0};
std::atomic<uint64_t> owner_main_stale{0};
std::atomic<uint64_t> owner_main_destructed{0};
std::atomic<uint64_t> owner_main_budget_yields{0};
std::atomic<uint64_t> owner_main_owner_claims{0};
std::atomic<uint64_t> owner_main_owner_releases{0};

struct OwnerMailboxTask {
  uint64_t task_id;
  uint64_t future_target_task_id{0};
  uint64_t sequence;
  uint64_t owner_epoch;
  VMObjectHandle target_handle;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::string future_state;
  std::string future_error;
  std::string target_object;
  std::vector<OwnerComputeResultField> compute_result_fields;
  object_t *target{nullptr};
  bool has_target_handle{false};
  bool ordinary_lpc_explicit_open{false};
  std::shared_ptr<VMFrozenValue> payload;
  std::function<void()> callback;
  std::function<void()> drop_callback;
};

struct OwnerTaskTrace {
  uint64_t trace_id;
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  VMObjectHandle target_handle;
  std::shared_ptr<VMFrozenValue> payload;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::string state;
  std::string target_object;
  std::string payload_key;
  std::string command_text_snapshot;
  std::string command_consume_model;
  std::string command_consume_blocker;
  std::string execution_frame_model;
  std::string execution_frame_policy;
  std::string execution_frame_restore_policy;
  std::string execution_frame_restore_blocker;
  bool has_target_handle{false};
  bool command_text_snapshot_ready{false};
  bool command_consume_snapshot_ready{false};
  bool command_consume_executor_ready{false};
  bool execution_frame_requires_current_interactive{false};
  bool execution_frame_requires_command_giver{false};
  bool execution_frame_executor_ready{false};
  bool execution_frame_restore_ready{false};
};

struct OwnerAccessTrace {
  uint64_t access_id;
  uint64_t sequence;
  uint64_t source_owner_epoch;
  uint64_t target_owner_epoch;
  bool cross_owner;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string source_object;
  std::string target_object;
  std::string operation;
};

struct OwnerMessageTrace {
  uint64_t message_id;
  uint64_t sequence;
  uint64_t target_task_id;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string message_type;
  std::string payload_key;
  std::string state;
  std::string route;
  std::string result_key;
  std::string error;
  std::string target_handle_status;
  bool has_target_handle{false};
  bool requires_owner_mailbox{true};
  bool requires_owner_main_queue{false};
  bool queued_on_main{false};
  bool frozen_result{false};
};

struct OwnerCommitTrace {
  uint64_t commit_id;
  uint64_t sequence;
  uint64_t message_id;
  bool direct_write;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string operation;
  std::string state;
};

struct OwnerExecutorTrace {
  uint64_t trace_id;
  uint64_t sequence;
  long backlog{0};
  long runnable_backlog{0};
  long safe_backlog{0};
  long main_required_backlog{0};
  long runnable_owners{0};
  long claimed_owners{0};
  long active_claims{0};
  std::string owner_id;
  std::string event;
};

struct OwnerFutureRecord {
  uint64_t future_id;
  uint64_t target_task_id;
  VMObjectHandle target_handle;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string message_type;
  std::string payload_key;
  std::string state;
  std::string result_key;
  std::string error;
  bool has_target_handle{false};
  std::shared_ptr<VMFrozenValue> result;
};

struct OwnerMainTask {
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::string future_state;
  std::string future_error;
  std::string target_object;
  std::string payload_key;
  std::string command_text_snapshot;
  std::string command_consume_model;
  std::string command_consume_blocker;
  std::string execution_frame_model;
  std::string execution_frame_policy;
  std::string execution_frame_restore_policy;
  std::string execution_frame_restore_blocker;
  object_t *target{nullptr};
  bool has_target_handle{false};
  bool command_text_snapshot_ready{false};
  bool command_consume_snapshot_ready{false};
  bool command_consume_executor_ready{false};
  bool execution_frame_requires_current_interactive{false};
  bool execution_frame_requires_command_giver{false};
  bool execution_frame_executor_ready{false};
  bool execution_frame_restore_ready{false};
  VMObjectHandle target_handle;
  std::shared_ptr<VMFrozenValue> payload;
  std::function<void()> callback;
  std::function<void()> drop_callback;
};

struct OwnerExecutorCallbackCleanup {
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::function<void()> callback;
};

std::unordered_map<std::string, std::deque<OwnerMailboxTask>> owner_mailboxes;
std::unordered_map<std::string, std::deque<OwnerMainTask>> owner_main_queues;
std::deque<OwnerExecutorCallbackCleanup> owner_executor_callback_main_cleanups;
std::deque<std::string> schedulable_owners;
std::deque<std::string> main_schedulable_owners;
std::unordered_set<std::string> schedulable_owner_set;
std::unordered_set<std::string> main_schedulable_owner_set;
std::unordered_set<std::string> active_owner_set;
std::unordered_map<std::string, int> active_owner_claim_counts;
std::unordered_set<std::string> active_main_owner_set;
std::deque<OwnerTaskTrace> owner_task_traces;
std::deque<OwnerAccessTrace> owner_access_traces;
std::deque<OwnerMessageTrace> owner_message_traces;
std::deque<OwnerCommitTrace> owner_commit_traces;
std::deque<OwnerExecutorTrace> owner_executor_traces;
std::unordered_map<uint64_t, OwnerFutureRecord> owner_futures;
std::vector<object_t *> owner_deferred_target_releases;
std::mutex owner_runtime_mutex;
std::condition_variable owner_runtime_cv;
bool owner_thread_stopping{false};
bool owner_main_draining{false};
std::vector<std::thread> owner_threads;

uint64_t append_owner_task_trace(uint64_t task_id, uint64_t sequence, const std::string &owner_id,
                                 uint64_t owner_epoch, const std::string &task_type,
                                 const std::string &task_key, const char *state);
uint64_t append_owner_task_trace(const OwnerMailboxTask &task, const char *state);

bool valid_owner_id(const char *owner_id) {
  return owner_id && owner_id[0] != '\0';
}

const char *normalize_owner_id(const char *owner_id) {
  return valid_owner_id(owner_id) ? owner_id : kDefaultOwnerId;
}

bool owner_id_is_default(const char *owner_id) { return std::strcmp(normalize_owner_id(owner_id), kDefaultOwnerId) == 0; }

const char *normalize_task_text(const char *text, const char *fallback) {
  return text && text[0] != '\0' ? text : fallback;
}

std::string stale_target_error(VMObjectHandleResolveStatus status) {
  return std::string("stale target: ") + vm_object_handle_resolve_status_name(status);
}

const char *owner_object_name(object_t *object) {
  return object && object->obname ? object->obname : "";
}

void add_mapping_svalue(mapping_t *map, const char *key, svalue_t *value) {
  svalue_t key_sv{T_STRING, STRING_SHARED, {0}};
  key_sv.u.string = make_shared_string(key ? key : "");
  auto *slot = find_for_insert(map, &key_sv, 1);
  free_svalue(&key_sv, "owner future result key");
  assign_svalue_no_free(slot, value);
}

bool command_giver_owner_applies(object_t *source, object_t *target) {
  return vm_context().owner.current_owner_id == kDefaultOwnerId && vm_owner_has_explicit_id(command_giver) &&
         (source == command_giver || target == command_giver);
}

const char *effective_source_owner_id(object_t *source, object_t *target) {
  if (!vm_context().owner.current_owner_id.empty() && vm_context().owner.current_owner_id != kDefaultOwnerId) {
    if (owner_id_is_default(vm_owner_id(source))) {
      return vm_owner_id(source);
    }
    return vm_context().owner.current_owner_id.c_str();
  }
  if (command_giver_owner_applies(source, target)) {
    return vm_owner_id(command_giver);
  }
  return vm_owner_id(source);
}

uint64_t effective_source_owner_epoch(object_t *source, object_t *target) {
  if (!vm_context().owner.current_owner_id.empty() && vm_context().owner.current_owner_id != kDefaultOwnerId) {
    if (owner_id_is_default(vm_owner_id(source))) {
      return vm_owner_epoch(source);
    }
    return vm_context().owner.current_owner_epoch;
  }
  if (command_giver_owner_applies(source, target)) {
    return vm_owner_epoch(command_giver);
  }
  return vm_owner_epoch(source);
}

const char *owner_access_policy_mode(const char *operation, bool cross_owner) {
  if (!cross_owner) {
    return "same_owner";
  }
  if (std::strcmp(operation, "environment") == 0 || std::strcmp(operation, "all_inventory") == 0) {
    return "snapshot";
  }
  if (std::strcmp(operation, "call_other") == 0 || std::strcmp(operation, "move_object") == 0 ||
      std::strcmp(operation, "destruct") == 0 || std::strcmp(operation, "present") == 0) {
    return "message";
  }
  return "reject";
}

bool owner_policy_allows_direct_access(const char *policy_mode) {
  return std::strcmp(policy_mode, "same_owner") == 0 || std::strcmp(policy_mode, "snapshot") == 0;
}

void record_owner_access_policy_counter(const char *policy_mode) {
  if (std::strcmp(policy_mode, "snapshot") == 0) {
    total_cross_owner_snapshot_accesses.fetch_add(1, std::memory_order_relaxed);
  } else if (std::strcmp(policy_mode, "message") == 0) {
    total_cross_owner_message_accesses.fetch_add(1, std::memory_order_relaxed);
  } else if (std::strcmp(policy_mode, "reject") == 0) {
    total_cross_owner_rejected_accesses.fetch_add(1, std::memory_order_relaxed);
  }
}

long owner_mailbox_depth(const std::string &owner_id) {
  auto it = owner_mailboxes.find(owner_id);
  return it == owner_mailboxes.end() ? 0 : static_cast<long>(it->second.size());
}

long owner_mailbox_total_depth() {
  long depth = 0;
  for (const auto &entry : owner_mailboxes) {
    depth += static_cast<long>(entry.second.size());
  }
  return depth;
}

long owner_main_queue_total_depth() {
  long depth = 0;
  for (const auto &entry : owner_main_queues) {
    depth += static_cast<long>(entry.second.size());
  }
  return depth;
}

long owner_main_queue_depth(const std::string &owner_id) {
  auto it = owner_main_queues.find(owner_id);
  return it == owner_main_queues.end() ? 0 : static_cast<long>(it->second.size());
}

long owner_mailbox_active_owners() {
  long owners = 0;
  for (const auto &entry : owner_mailboxes) {
    if (!entry.second.empty()) {
      owners++;
    }
  }
  return owners;
}

long owner_pending_future_count() {
  long pending = 0;
  for (const auto &entry : owner_futures) {
    if (entry.second.state == "pending") {
      pending++;
    }
  }
  return pending;
}

std::shared_ptr<VMFrozenValue> frozen_compute_result_mapping(const OwnerMailboxTask &task) {
  if (task.compute_result_fields.empty()) {
    return nullptr;
  }

  auto *map = allocate_mapping(static_cast<int>(task.compute_result_fields.size()));
  for (const auto &field : task.compute_result_fields) {
    if (field.key.empty()) {
      continue;
    }
    if (field.is_string) {
      add_mapping_string(map, field.key.c_str(), field.string_value.c_str());
    } else {
      add_mapping_pair(map, field.key.c_str(), static_cast<long>(field.number_value));
    }
  }

  svalue_t value{T_MAPPING, 0, {0}};
  value.u.map = map;
  auto frozen = vm_clone_frozen_value(&value);
  free_svalue(&value, "worker compute result mapping");
  return frozen;
}

const OwnerLpcTaskDescriptor *find_owner_lpc_task_descriptor(const std::string &method) {
  for (const auto &descriptor : kOwnerLpcTaskDescriptors) {
    if (method == descriptor.method) {
      return &descriptor;
    }
  }
  return nullptr;
}

const char *owner_executor_dispatch_kind_name(OwnerExecutorDispatchKind kind) {
  switch (kind) {
    case OwnerExecutorDispatchKind::ExecutorProbe:
      return "executor_probe";
    case OwnerExecutorDispatchKind::LpcProbe:
      return "lpc_probe";
    case OwnerExecutorDispatchKind::LpcCanary:
      return "lpc_canary";
    case OwnerExecutorDispatchKind::LpcTask:
      return "lpc_task";
    case OwnerExecutorDispatchKind::OrdinaryLpc:
      return "ordinary_lpc";
    case OwnerExecutorDispatchKind::RejectLpc:
      return "reject_lpc";
    case OwnerExecutorDispatchKind::GuardOwnerState:
      return "guard_owner_state";
    case OwnerExecutorDispatchKind::OwnerMessage:
      return "owner_message";
    case OwnerExecutorDispatchKind::CommandConsume:
      return "command_consume";
    case OwnerExecutorDispatchKind::CommandFrameRestore:
      return "command_frame_restore";
    case OwnerExecutorDispatchKind::GatewayCommand:
      return "gateway_command";
    case OwnerExecutorDispatchKind::ExecutorCallback:
      return "executor_callback";
    case OwnerExecutorDispatchKind::ComputeResult:
      return "compute_result";
    case OwnerExecutorDispatchKind::Generic:
      return "generic";
  }
  return "generic";
}

const OwnerExecutorTaskDescriptor *find_owner_executor_task_descriptor(const std::string &task_type) {
  for (const auto &descriptor : kOwnerExecutorTaskDescriptors) {
    if (task_type == descriptor.task_type) {
      return &descriptor;
    }
  }
  return nullptr;
}

const OwnerExecutorTaskDescriptor &owner_executor_task_descriptor(const OwnerMailboxTask &task) {
  if (const auto *descriptor = find_owner_executor_task_descriptor(task.task_type)) {
    return *descriptor;
  }
  static constexpr OwnerExecutorTaskDescriptor kGenericDescriptor = {
      "generic", "generic", OwnerExecutorDispatchKind::Generic, "executor_compat", "owner_executor",
      "legacy test mailbox task without LPC execution contract", 1, 0, 0, 0, 1, 0};
  return kGenericDescriptor;
}

array_t *owner_lpc_task_allowlist_array() {
  auto *methods = allocate_array(static_cast<int>(kOwnerLpcTaskDescriptors.size()));
  for (size_t i = 0; i < kOwnerLpcTaskDescriptors.size(); i++) {
    methods->item[i].type = T_STRING;
    methods->item[i].subtype = STRING_SHARED;
    methods->item[i].u.string = make_shared_string(kOwnerLpcTaskDescriptors[i].method);
  }
  return methods;
}

mapping_t *owner_lpc_task_contract_entry(const OwnerLpcTaskDescriptor &descriptor) {
  auto *map = allocate_mapping(13);
  add_mapping_string(map, "method", descriptor.method);
  add_mapping_string(map, "executor_mode", descriptor.executor_mode);
  add_mapping_string(map, "route", descriptor.route);
  add_mapping_string(map, "result_policy", descriptor.result_policy);
  add_mapping_pair(map, "executor_safe", descriptor.executor_safe);
  add_mapping_pair(map, "main_required", descriptor.main_required);
  add_mapping_pair(map, "rejected", descriptor.rejected);
  add_mapping_pair(map, "requires_target", descriptor.requires_target);
  add_mapping_pair(map, "requires_owner_thread", descriptor.requires_owner_thread);
  add_mapping_pair(map, "requires_owner_message_completion", descriptor.requires_owner_message_completion);
  add_mapping_pair(map, "frozen_result_required", descriptor.frozen_result_required);
  add_mapping_pair(map, "direct_cross_owner_write", descriptor.direct_cross_owner_write);
  add_mapping_string(map, "reason", descriptor.reason);
  return map;
}

mapping_t *owner_task_contract_entry(const char *executor_mode, const char *route, int executor_safe, int main_required,
                                     int rejected, const char *reason) {
  auto *map = allocate_mapping(6);
  add_mapping_string(map, "executor_mode", executor_mode);
  add_mapping_string(map, "route", route);
  add_mapping_pair(map, "executor_safe", executor_safe);
  add_mapping_pair(map, "main_required", main_required);
  add_mapping_pair(map, "rejected", rejected);
  add_mapping_string(map, "reason", reason);
  return map;
}

mapping_t *owner_ordinary_lpc_contract_entry(const OwnerExecutorTaskDescriptor &descriptor) {
  auto *map = allocate_mapping(15);
  add_mapping_string(map, "executor_mode", descriptor.executor_mode);
  add_mapping_string(map, "route", descriptor.route);
  add_mapping_pair(map, "executor_safe", descriptor.executor_safe);
  add_mapping_pair(map, "main_required", descriptor.main_required);
  add_mapping_pair(map, "rejected", descriptor.rejected);
  add_mapping_string(map, "reason", descriptor.reason);
  add_mapping_string(map, "dispatch_model", "generic_owner_lpc_dispatch");
  add_mapping_string(map, "activation_policy", "default_closed_explicit_open");
  add_mapping_pair(map, "default_closed", 1);
  add_mapping_pair(map, "explicit_open_required", 1);
  add_mapping_pair(map, "requires_target", 1);
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "requires_owner_message_completion", 1);
  add_mapping_pair(map, "frozen_result_required", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *owner_executor_task_contract_entry(const OwnerExecutorTaskDescriptor &descriptor) {
  auto *map = allocate_mapping(12);
  add_mapping_string(map, "task_type", descriptor.task_type);
  add_mapping_string(map, "contract_key", descriptor.contract_key);
  add_mapping_string(map, "dispatch_kind", owner_executor_dispatch_kind_name(descriptor.dispatch_kind));
  add_mapping_string(map, "executor_mode", descriptor.executor_mode);
  add_mapping_string(map, "route", descriptor.route);
  add_mapping_pair(map, "executor_runnable", descriptor.executor_runnable);
  add_mapping_pair(map, "executor_safe", descriptor.executor_safe);
  add_mapping_pair(map, "main_required", descriptor.main_required);
  add_mapping_pair(map, "rejected", descriptor.rejected);
  add_mapping_pair(map, "requires_owner_mailbox", descriptor.requires_owner_mailbox);
  add_mapping_pair(map, "requires_owner_main_queue", descriptor.requires_owner_main_queue);
  add_mapping_string(map, "reason", descriptor.reason);
  return map;
}

mapping_t *owner_task_route_contract_entry(const OwnerTaskRouteContract &contract) {
  auto *map = allocate_mapping(8);
  add_mapping_string(map, "executor_mode", contract.executor_mode);
  add_mapping_string(map, "route", contract.route);
  add_mapping_pair(map, "executor_safe", contract.executor_safe);
  add_mapping_pair(map, "main_required", contract.main_required);
  add_mapping_pair(map, "rejected", contract.rejected);
  add_mapping_pair(map, "requires_owner_mailbox", contract.requires_owner_mailbox);
  add_mapping_pair(map, "requires_owner_main_queue", contract.requires_owner_main_queue);
  add_mapping_string(map, "reason", contract.reason);
  return map;
}

array_t *owner_lpc_task_contracts_array() {
  auto *contracts = allocate_array(static_cast<int>(kOwnerLpcTaskDescriptors.size()));
  for (size_t i = 0; i < kOwnerLpcTaskDescriptors.size(); i++) {
    contracts->item[i].type = T_MAPPING;
    contracts->item[i].subtype = 0;
    contracts->item[i].u.map = owner_lpc_task_contract_entry(kOwnerLpcTaskDescriptors[i]);
  }
  return contracts;
}

array_t *owner_executor_task_contracts_array() {
  auto *contracts = allocate_array(static_cast<int>(kOwnerExecutorTaskDescriptors.size()));
  for (size_t i = 0; i < kOwnerExecutorTaskDescriptors.size(); i++) {
    contracts->item[i].type = T_MAPPING;
    contracts->item[i].subtype = 0;
    contracts->item[i].u.map = owner_executor_task_contract_entry(kOwnerExecutorTaskDescriptors[i]);
  }
  return contracts;
}

array_t *owner_executor_callback_contracts_array() {
  size_t callback_count = 0;
  for (const auto &descriptor : kOwnerExecutorTaskDescriptors) {
    if (descriptor.dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
      callback_count++;
    }
  }

  auto *contracts = allocate_array(static_cast<int>(callback_count));
  size_t index = 0;
  for (const auto &descriptor : kOwnerExecutorTaskDescriptors) {
    if (descriptor.dispatch_kind != OwnerExecutorDispatchKind::ExecutorCallback) {
      continue;
    }
    contracts->item[index].type = T_MAPPING;
    contracts->item[index].subtype = 0;
    contracts->item[index].u.map = owner_executor_task_contract_entry(descriptor);
    index++;
  }
  return contracts;
}

void add_mapping_owned_mapping(mapping_t *map, const char *key, mapping_t *value) {
  svalue_t value_sv{T_MAPPING, 0, {0}};
  value_sv.u.map = value;
  add_mapping_svalue(map, key, &value_sv);
  free_mapping(value);
}

mapping_t *vm_context_readiness_gate_mapping(const VMContextReadinessGate &gate) {
  auto *map = allocate_mapping(5);
  add_mapping_string(map, "gate", gate.gate);
  add_mapping_string(map, "model", gate.model);
  add_mapping_pair(map, "satisfied", gate.satisfied);
  add_mapping_string(map, "blocker", gate.blocker);
  add_mapping_string(map, "next_action", gate.next_action);
  return map;
}

mapping_t *gateway_command_side_effect_readiness_gate_mapping(
    const GatewayCommandSideEffectReadinessGate &gate) {
  auto *map = allocate_mapping(12);
  add_mapping_string(map, "gate", gate.gate);
  add_mapping_string(map, "model", gate.model);
  add_mapping_pair(map, "satisfied", gate.satisfied);
  add_mapping_string(map, "blocker", gate.blocker);
  add_mapping_string(map, "next_action", gate.next_action);
  add_mapping_string(map, "state_owner", gate.state_owner);
  add_mapping_string(map, "migration_boundary", gate.migration_boundary);
  add_mapping_string(map, "side_effect_class", gate.side_effect_class);
  add_mapping_string(map, "snapshot_policy", gate.snapshot_policy);
  add_mapping_pair(map, "snapshot_ready", gate.snapshot_ready);
  add_mapping_pair(map, "state_redacted", gate.state_redacted);
  add_mapping_pair(map, "blocks_activation", gate.blocks_activation);
  return map;
}

array_t *vm_context_readiness_gates_array() {
  auto *gates = allocate_array(static_cast<int>(kVMContextOrdinaryLpcReadinessGates.size()));
  for (size_t i = 0; i < kVMContextOrdinaryLpcReadinessGates.size(); i++) {
    gates->item[i].type = T_MAPPING;
    gates->item[i].subtype = 0;
    gates->item[i].u.map = vm_context_readiness_gate_mapping(kVMContextOrdinaryLpcReadinessGates[i]);
  }
  return gates;
}

array_t *gateway_command_executor_readiness_gates_array() {
  auto *gates = allocate_array(static_cast<int>(kGatewayCommandExecutorReadinessGates.size()));
  for (size_t i = 0; i < kGatewayCommandExecutorReadinessGates.size(); i++) {
    gates->item[i].type = T_MAPPING;
    gates->item[i].subtype = 0;
    gates->item[i].u.map = vm_context_readiness_gate_mapping(kGatewayCommandExecutorReadinessGates[i]);
  }
  return gates;
}

long gateway_command_executor_satisfied_readiness_gate_count() {
  long count = 0;
  for (const auto &gate : kGatewayCommandExecutorReadinessGates) {
    if (gate.satisfied) {
      count++;
    }
  }
  return count;
}

array_t *gateway_command_side_effect_readiness_gates_array() {
  auto *gates = allocate_array(static_cast<int>(kGatewayCommandSideEffectReadinessGates.size()));
  for (size_t i = 0; i < kGatewayCommandSideEffectReadinessGates.size(); i++) {
    gates->item[i].type = T_MAPPING;
    gates->item[i].subtype = 0;
    gates->item[i].u.map =
        gateway_command_side_effect_readiness_gate_mapping(kGatewayCommandSideEffectReadinessGates[i]);
  }
  return gates;
}

long gateway_command_side_effect_satisfied_readiness_gate_count() {
  long count = 0;
  for (const auto &gate : kGatewayCommandSideEffectReadinessGates) {
    if (gate.satisfied) {
      count++;
    }
  }
  return count;
}

long gateway_command_side_effect_snapshot_ready_gate_count() {
  long count = 0;
  for (const auto &gate : kGatewayCommandSideEffectReadinessGates) {
    if (gate.snapshot_ready) {
      count++;
    }
  }
  return count;
}

mapping_t *gateway_command_activation_contract_entry(const OwnerExecutorTaskDescriptor &descriptor) {
  auto *map = owner_task_contract_entry(descriptor.executor_mode, descriptor.route, descriptor.executor_safe,
                                        descriptor.main_required, descriptor.rejected, descriptor.reason);
  const auto gate_count = static_cast<long>(kGatewayCommandSideEffectReadinessGates.size());
  const auto satisfied_gates = gateway_command_side_effect_satisfied_readiness_gate_count();
  const auto snapshot_ready_gates = gateway_command_side_effect_snapshot_ready_gate_count();
  add_mapping_pair(map, "side_effect_snapshot_gate_count", gate_count);
  add_mapping_pair(map, "side_effect_snapshot_ready_count", snapshot_ready_gates);
  add_mapping_pair(map, "side_effect_observability_ready", snapshot_ready_gates == gate_count ? 1 : 0);
  add_mapping_pair(map, "side_effect_activation_ready", satisfied_gates == gate_count ? 1 : 0);
  add_mapping_string(map, "activation_blocker", kGatewayCommandExecutorActivationBlocker);
  return map;
}

array_t *string_array_from_contract(const std::array<const char *, 5> &values) {
  auto *array = allocate_array(static_cast<int>(values.size()));
  for (size_t i = 0; i < values.size(); i++) {
    array->item[i].type = T_STRING;
    array->item[i].subtype = STRING_SHARED;
    array->item[i].u.string = make_shared_string(values[i]);
  }
  return array;
}

array_t *string_array_from_contract(const std::array<const char *, 4> &values) {
  auto *array = allocate_array(static_cast<int>(values.size()));
  for (size_t i = 0; i < values.size(); i++) {
    array->item[i].type = T_STRING;
    array->item[i].subtype = STRING_SHARED;
    array->item[i].u.string = make_shared_string(values[i]);
  }
  return array;
}

mapping_t *frozen_payload_contract_entry(const FrozenPayloadContractEntry &entry) {
  auto *map = allocate_mapping(6);
  add_mapping_string(map, "path", entry.path);
  add_mapping_string(map, "input_policy", entry.input_policy);
  add_mapping_string(map, "result_policy", entry.result_policy);
  add_mapping_pair(map, "uses_shared_validator", entry.uses_shared_validator);
  add_mapping_pair(map, "top_level_mapping_required", entry.top_level_mapping_required);
  add_mapping_pair(map, "frozen_result_required", entry.frozen_result_required);
  return map;
}

array_t *frozen_payload_contract_entries_array() {
  auto *entries = allocate_array(static_cast<int>(kFrozenPayloadContractEntries.size()));
  for (size_t i = 0; i < kFrozenPayloadContractEntries.size(); i++) {
    entries->item[i].type = T_MAPPING;
    entries->item[i].subtype = 0;
    entries->item[i].u.map = frozen_payload_contract_entry(kFrozenPayloadContractEntries[i]);
  }
  return entries;
}

mapping_t *frozen_payload_contract_mapping() {
  auto *map = allocate_mapping(15);
  add_mapping_pair(map, "contract_version", 1);
  add_mapping_string(map, "validator", "vm_frozen_value_safe");
  add_mapping_pair(map, "deep_copy", 1);
  add_mapping_pair(map, "max_depth", 8);
  add_mapping_pair(map, "mapping_keys_must_be_strings", 1);
  add_mapping_pair(map, "top_level_owner_payload_must_be_mapping", 1);
  add_mapping_pair(map, "arrays_allowed", 1);
  add_mapping_pair(map, "mappings_allowed", 1);
  add_mapping_pair(map, "object_allowed", 0);
  add_mapping_pair(map, "function_allowed", 0);
  add_mapping_pair(map, "buffer_allowed", 0);
  add_mapping_pair(map, "class_allowed", 0);
  auto *allowed = string_array_from_contract(kFrozenPayloadAllowedTypes);
  add_mapping_array(map, "allowed_types", allowed);
  free_array(allowed);
  auto *rejected = string_array_from_contract(kFrozenPayloadRejectedTypes);
  add_mapping_array(map, "rejected_types", rejected);
  free_array(rejected);
  auto *paths = frozen_payload_contract_entries_array();
  add_mapping_array(map, "paths", paths);
  free_array(paths);
  return map;
}

mapping_t *gateway_owner_task_contract_entry(const GatewayOwnerTaskContractEntry &entry) {
  auto *map = allocate_mapping(28);
  add_mapping_string(map, "task_type", entry.task_type);
  add_mapping_string(map, "task_key", entry.task_key);
  add_mapping_string(map, "executor_mode", entry.executor_mode);
  add_mapping_string(map, "route", entry.route);
  add_mapping_string(map, "owner_scope_model", entry.owner_scope_model);
  add_mapping_string(map, "stale_policy", entry.stale_policy);
  add_mapping_string(map, "payload_key", entry.payload_key);
  add_mapping_string(map, "input_payload_policy", entry.input_payload_policy);
  add_mapping_string(map, "command_consume_model", entry.command_consume_model);
  add_mapping_pair(map, "command_consume_snapshot_ready", entry.command_consume_snapshot_ready);
  add_mapping_pair(map, "command_consume_executor_ready", entry.command_consume_executor_ready);
  add_mapping_string(map, "command_consume_blocker", entry.command_consume_blocker);
  add_mapping_string(map, "execution_frame_model", entry.execution_frame_model);
  add_mapping_string(map, "execution_frame_policy", entry.execution_frame_policy);
  add_mapping_string(map, "execution_frame_restore_policy", entry.execution_frame_restore_policy);
  add_mapping_pair(map, "execution_frame_restore_ready", entry.execution_frame_restore_ready);
  add_mapping_string(map, "execution_frame_restore_blocker", entry.execution_frame_restore_blocker);
  add_mapping_pair(map, "execution_frame_executor_ready", entry.execution_frame_executor_ready);
  add_mapping_pair(map, "main_required", entry.main_required);
  add_mapping_pair(map, "executor_safe", entry.executor_safe);
  add_mapping_pair(map, "requires_owner_main_queue", entry.requires_owner_main_queue);
  add_mapping_pair(map, "requires_owner_scope", entry.requires_owner_scope);
  add_mapping_pair(map, "requires_current_interactive", entry.requires_current_interactive);
  add_mapping_pair(map, "requires_command_giver", entry.requires_command_giver);
  add_mapping_pair(map, "ordinary_lpc_ready_required", entry.ordinary_lpc_ready_required);
  add_mapping_pair(map, "command_serial_per_owner", entry.command_serial_per_owner);
  add_mapping_pair(map, "requires_target_handle", entry.requires_target_handle);
  add_mapping_pair(map, "requires_frozen_payload", entry.requires_frozen_payload);
  return map;
}

array_t *gateway_owner_task_contract_entries_array() {
  auto *entries = allocate_array(static_cast<int>(kGatewayOwnerTaskContracts.size()));
  for (size_t i = 0; i < kGatewayOwnerTaskContracts.size(); i++) {
    entries->item[i].type = T_MAPPING;
    entries->item[i].subtype = 0;
    entries->item[i].u.map = gateway_owner_task_contract_entry(kGatewayOwnerTaskContracts[i]);
  }
  return entries;
}

mapping_t *gateway_owner_task_contract_mapping() {
  auto *map = allocate_mapping(107);
  add_mapping_pair(map, "contract_version", 1);
  add_mapping_string(map, "input_model", "owner_main_queue_bridge");
  add_mapping_string(map, "executor_migration_state", "main_required_before_owner_executor");
  add_mapping_string(map, "command_payload_model", "gateway_command_buffer_metadata_v1");
  add_mapping_string(map, "command_input_source", "interactive_text_buffer");
  add_mapping_string(map, "command_text_snapshot_policy", "owner_private_redacted_from_trace");
  add_mapping_pair(map, "command_text_snapshot_ready", 1);
  add_mapping_string(map, "command_input_callback_state_policy", "redacted_input_to_get_char_state_v1");
  add_mapping_pair(map, "command_input_callback_snapshot_ready", 1);
  add_mapping_string(map, "command_input_callback_frame_model", "owner_command_frame_input_callback_detach_v1");
  add_mapping_pair(map, "command_input_callback_frame_detach_ready", 1);
  add_mapping_pair(map, "command_input_callback_frame_executor_ready", 1);
  add_mapping_string(map, "command_input_callback_apply_frame_model", "owner_command_frame_input_callback_apply");
  add_mapping_string(map, "command_input_callback_apply_frame_task_type", "interactive_input_callback");
  add_mapping_pair(map, "command_input_callback_apply_frame_ready", 1);
  add_mapping_pair(map, "command_input_callback_apply_frame_executor_ready", 1);
  add_mapping_string(map, "command_input_callback_mode_delta_model",
                     "owner_command_frame_input_callback_mode_delta");
  add_mapping_pair(map, "command_input_callback_mode_delta_ready", 1);
  add_mapping_pair(map, "command_input_callback_mode_delta_executor_ready", 1);
  add_mapping_string(map, "command_input_callback_blocker", "");
  add_mapping_string(map, "process_input_apply_frame_model", "owner_command_frame_process_input_apply");
  add_mapping_string(map, "process_input_apply_frame_task_type", "interactive_command_parser");
  add_mapping_pair(map, "process_input_apply_frame_ready", 1);
  add_mapping_pair(map, "process_input_apply_frame_executor_ready", 1);
  add_mapping_string(map, "process_input_add_action_parser_frame_model", "owner_command_parser_context_v1");
  add_mapping_pair(map, "process_input_add_action_parser_frame_ready", 1);
  add_mapping_pair(map, "process_input_add_action_parser_frame_executor_ready", 1);
  add_mapping_string(map, "process_input_add_action_parser_blocker", "");
  add_mapping_string(map, "command_executor_blocker", kGatewayCommandExecutorActivationBlocker);
  add_mapping_string(map, "command_consume_model", "owner_owned_snapshot_main_thread_consume");
  add_mapping_pair(map, "command_consume_snapshot_ready", 1);
  add_mapping_pair(map, "command_consume_executor_ready", 1);
  add_mapping_string(map, "command_consume_blocker", "");
  add_mapping_string(map, "command_reply_queue_model", "main_reply_queue_after_owner_command");
  add_mapping_string(map, "command_reply_queue_task_type", "command_reply");
  add_mapping_string(map, "command_reply_queue_task_key", "prompt_telnet_reschedule_io");
  add_mapping_string(map, "command_reply_queue_side_effects", "prompt_telnet_reschedule_io");
  add_mapping_pair(map, "command_reply_queue_ready", 1);
  add_mapping_pair(map, "command_reply_queue_main_required", 1);
  add_mapping_string(map, "command_reply_write_prompt_apply_frame_model",
                     "owner_command_frame_write_prompt_apply");
  add_mapping_string(map, "command_reply_write_prompt_apply_frame_task_type", "command_reply");
  add_mapping_pair(map, "command_reply_write_prompt_apply_frame_ready", 1);
  add_mapping_pair(map, "command_reply_write_prompt_apply_frame_executor_ready", 0);
  add_mapping_string(map, "command_mode_delta_model", "owner_command_frame_mode_delta");
  add_mapping_string(map, "command_mode_delta_localecho_restore_boundary",
                     "main_reply_queue_after_command_consume");
  add_mapping_pair(map, "command_mode_delta_localecho_restore_ready", 1);
  add_mapping_string(map, "interactive_mode_localecho_restore_model",
                     "owner_command_frame_localecho_restore");
  add_mapping_string(map, "interactive_mode_localecho_restore_task_type", "interactive_mode_flags");
  add_mapping_pair(map, "interactive_mode_localecho_restore_ready", 1);
  add_mapping_pair(map, "interactive_mode_localecho_restore_executor_ready", 1);
  add_mapping_string(map, "command_mode_delta_terminal_mode_task_type", "command_mode_delta");
  add_mapping_string(map, "command_mode_delta_terminal_mode_task_keys",
                     "get_char_linemode_restore,single_char_escape_linemode,single_char_escape_charmode_restore");
  add_mapping_string(map, "command_mode_delta_terminal_mode_boundary",
                     "main_mode_delta_queue_after_command_consume");
  add_mapping_pair(map, "command_mode_delta_terminal_mode_ready", 1);
  add_mapping_pair(map, "command_mode_delta_ready", 1);
  add_mapping_string(map, "interactive_mode_mxp_tag_filter_model", "owner_command_frame_mxp_tag_filter");
  add_mapping_string(map, "interactive_mode_mxp_tag_filter_task_type", "interactive_mode_flags");
  add_mapping_pair(map, "interactive_mode_mxp_tag_filter_ready", 1);
  add_mapping_pair(map, "interactive_mode_mxp_tag_filter_executor_ready", 1);
  add_mapping_string(map, "interactive_mode_ed_command_model", "owner_command_frame_ed_command");
  add_mapping_string(map, "interactive_mode_ed_command_task_type", "interactive_mode_flags");
  add_mapping_pair(map, "interactive_mode_ed_command_ready", 1);
  add_mapping_pair(map, "interactive_mode_ed_command_executor_ready", 1);
  add_mapping_string(map, "raw_input_trace_policy", "no_raw_command_text_in_trace");
  add_mapping_string(map, "command_execution_frame_model", "gateway_command_execution_frame_v1");
  add_mapping_string(map, "command_execution_frame_policy", "owner_scope_current_interactive_command_giver");
  add_mapping_string(map, "command_execution_frame_restore_policy", "owner_executor_vmcontext_restore");
  add_mapping_pair(map, "command_execution_frame_restore_ready", 1);
  add_mapping_string(map, "command_execution_frame_restore_blocker", "");
  add_mapping_pair(map, "command_execution_frame_executor_ready", 1);
  add_mapping_string(map, "command_stale_guard", "owner_epoch_target_handle_guard");
  add_mapping_string(map, "command_stale_trace_state", "main_stale");
  add_mapping_string(map, "command_stale_target_status", "owner_epoch_mismatch");
  add_mapping_string(map, "command_executor_readiness_gate_model", "all_gates_required_before_owner_executor");
  add_mapping_string(map, "command_executor_next_gate", "gateway_command_executor_activation");
  add_mapping_string(map, "command_executor_next_blocker", kGatewayCommandExecutorActivationBlocker);
  add_mapping_pair(map, "command_executor_readiness_gate_count",
                   static_cast<long>(kGatewayCommandExecutorReadinessGates.size()));
  const auto command_executor_satisfied_gates = gateway_command_executor_satisfied_readiness_gate_count();
  add_mapping_pair(map, "command_executor_satisfied_gate_count", command_executor_satisfied_gates);
  add_mapping_pair(map, "command_executor_blocked_gate_count",
                   static_cast<long>(kGatewayCommandExecutorReadinessGates.size()) - command_executor_satisfied_gates);
  auto *command_executor_gates = gateway_command_executor_readiness_gates_array();
  add_mapping_array(map, "command_executor_readiness_gates", command_executor_gates);
  free_array(command_executor_gates);
  add_mapping_string(map, "command_side_effect_readiness_gate_model",
                     "all_side_effect_gates_required_before_activation");
  const auto command_side_effect_gate_count = static_cast<long>(kGatewayCommandSideEffectReadinessGates.size());
  add_mapping_pair(map, "command_side_effect_readiness_gate_count", command_side_effect_gate_count);
  const auto command_side_effect_satisfied_gates = gateway_command_side_effect_satisfied_readiness_gate_count();
  const auto command_side_effect_snapshot_ready_gates = gateway_command_side_effect_snapshot_ready_gate_count();
  add_mapping_pair(map, "command_side_effect_satisfied_gate_count", command_side_effect_satisfied_gates);
  add_mapping_pair(map, "command_side_effect_blocked_gate_count",
                   command_side_effect_gate_count - command_side_effect_satisfied_gates);
  add_mapping_pair(map, "command_side_effect_snapshot_gate_count", command_side_effect_gate_count);
  add_mapping_pair(map, "command_side_effect_snapshot_ready_count", command_side_effect_snapshot_ready_gates);
  add_mapping_pair(map, "command_side_effect_observability_ready",
                   command_side_effect_snapshot_ready_gates == command_side_effect_gate_count ? 1 : 0);
  add_mapping_pair(map, "command_side_effect_activation_ready",
                   command_side_effect_satisfied_gates == command_side_effect_gate_count ? 1 : 0);
  auto *command_side_effect_gates = gateway_command_side_effect_readiness_gates_array();
  add_mapping_array(map, "command_side_effect_readiness_gates", command_side_effect_gates);
  free_array(command_side_effect_gates);
  add_mapping_pair(map, "ordinary_lpc_ready_required", 0);
  add_mapping_pair(map, "main_required", 1);
  add_mapping_pair(map, "task_count", static_cast<long>(kGatewayOwnerTaskContracts.size()));
  auto *tasks = gateway_owner_task_contract_entries_array();
  add_mapping_array(map, "tasks", tasks);
  free_array(tasks);
  add_mapping_string(map, "next_blocker", "gateway_command_executor_activation");
  add_mapping_string(map, "next_blocker_chain", "gateway_command_executor/gateway_command_executor_activation");
  return map;
}

long vm_context_satisfied_readiness_gate_count() {
  long count = 0;
  for (const auto &gate : kVMContextOrdinaryLpcReadinessGates) {
    if (gate.satisfied) {
      count++;
    }
  }
  return count;
}

mapping_t *vm_context_contract_mapping() {
  auto *contract = allocate_mapping(69);
  add_mapping_pair(contract, "contract_version", 1);
  add_mapping_string(contract, "context_model", "thread_local_vm_context");
  add_mapping_string(contract, "execution_state_model", "vm_context_execution_snapshot");
  add_mapping_string(contract, "owner_state_model", "vm_context_owner_scope");
  add_mapping_string(contract, "error_state_model", "vm_context_error_snapshot");
  add_mapping_string(contract, "object_store_model", "owner_local_object_store");
  add_mapping_string(contract, "object_store_off_main_policy", "owner_local_lookup_only");
  add_mapping_pair(contract, "ordinary_lpc_ready", 1);
  add_mapping_string(contract, "ordinary_lpc_blocker", "");
  add_mapping_pair(contract, "controlled_lpc_ready", 1);
  add_mapping_string(contract, "controlled_lpc_policy", "descriptor_manifest_only");
  add_mapping_string(contract, "eval_stack_model", "thread_local_owner_execution_stack");
  add_mapping_pair(contract, "eval_stack_thread_local", 1);
  add_mapping_pair(contract, "eval_stack_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "eval_stack_cleared_after_task", 1);
  add_mapping_pair(contract, "eval_stack_owner_local", 1);
  add_mapping_string(contract, "control_stack_model", "thread_local_owner_control_stack");
  add_mapping_pair(contract, "control_stack_thread_local", 1);
  add_mapping_pair(contract, "control_stack_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "control_stack_cleared_after_task", 1);
  add_mapping_pair(contract, "control_stack_owner_local", 1);
  add_mapping_string(contract, "value_stack_model", "thread_local_owner_value_stack");
  add_mapping_pair(contract, "value_stack_thread_local", 1);
  add_mapping_pair(contract, "value_stack_lvalue_refs_cleared_after_task", 1);
  add_mapping_pair(contract, "value_stack_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "value_stack_cleared_after_task", 1);
  add_mapping_pair(contract, "value_stack_owner_local", 1);
  add_mapping_string(contract, "apply_return_model", "thread_local_owner_apply_return");
  add_mapping_pair(contract, "apply_return_thread_local", 1);
  add_mapping_pair(contract, "apply_return_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "apply_return_cleared_after_task", 1);
  add_mapping_pair(contract, "apply_return_owner_local", 1);
  add_mapping_string(contract, "object_refs_model", "object_handle_boundary");
  add_mapping_pair(contract, "object_refs_owner_local", 1);
  add_mapping_string(contract, "cross_owner_object_refs_policy", "object_handle_or_frozen_payload_only");
  add_mapping_pair(contract, "cross_owner_payload_rejects_objects", 1);
  add_mapping_pair(contract, "cross_owner_result_rejects_objects", 1);
  add_mapping_pair(contract, "owner_message_target_handle_guard", 1);
  add_mapping_pair(contract, "owner_executor_same_owner_object_refs_only", 1);
  add_mapping_pair(contract, "ordinary_lpc_object_store_gate_required", 1);
  add_mapping_pair(contract, "object_store_owner_local_complete", 1);
  add_mapping_pair(contract, "ordinary_lpc_activation_required", 1);
  add_mapping_pair(contract, "ordinary_lpc_activation_policy_ready", 1);
  add_mapping_pair(contract, "ordinary_lpc_dispatch_path_ready", 1);
  add_mapping_pair(contract, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(contract, "ordinary_lpc_explicit_open_required", 1);
  add_mapping_string(contract, "ordinary_lpc_dispatch_model", "generic_owner_lpc_dispatch");
  add_mapping_string(contract, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
  add_mapping_string(contract, "ordinary_lpc_activation_rollout", "explicit_open_only_until_gateway_migration");
  add_mapping_string(contract, "ordinary_lpc_activation_rollback", "disable_explicit_open_submission");
  add_mapping_pair(contract, "error_state_contextualized", 1);
  add_mapping_pair(contract, "execution_state_contextualized", 1);
  add_mapping_pair(contract, "owner_scope_contextualized", 1);
  add_mapping_pair(contract, "object_store_main_thread_only", 0);
  add_mapping_pair(contract, "object_store_sync_rejections",
                   static_cast<long>(vm_context_object_store_sync_rejections()));
  add_mapping_pair(contract, "off_main_object_store_sync_allowed", 0);
  add_mapping_string(contract, "ordinary_lpc_readiness_gate_model", "all_gates_required_before_open");
  add_mapping_string(contract, "ordinary_lpc_next_blocker", "");
  add_mapping_pair(contract, "ordinary_lpc_readiness_gate_count",
                   static_cast<long>(kVMContextOrdinaryLpcReadinessGates.size()));
  const auto satisfied_gates = vm_context_satisfied_readiness_gate_count();
  add_mapping_pair(contract, "ordinary_lpc_satisfied_gate_count", satisfied_gates);
  add_mapping_pair(contract, "ordinary_lpc_blocked_gate_count",
                   static_cast<long>(kVMContextOrdinaryLpcReadinessGates.size()) - satisfied_gates);
  auto *readiness_gates = vm_context_readiness_gates_array();
  add_mapping_array(contract, "ordinary_lpc_readiness_gates", readiness_gates);
  free_array(readiness_gates);
  return contract;
}

mapping_t *owner_executor_boundary_contract_mapping() {
  auto *contract = allocate_mapping(48);
  add_mapping_pair(contract, "contract_version", 1);
  add_mapping_string(contract, "boundary_model", "owner_executor_boundary_v1");
  add_mapping_string(contract, "implementation_state", "compilation_unit_active");
  add_mapping_string(contract, "class_name", "OwnerExecutor");
  add_mapping_pair(contract, "class_extracted", 1);
  add_mapping_pair(contract, "module_extracted", 1);
  add_mapping_string(contract, "module_file", "vm/internal/owner_executor.h");
  add_mapping_pair(contract, "compilation_unit_extracted", 1);
  add_mapping_string(contract, "compilation_unit_file", "vm/internal/owner_executor.cc");
  add_mapping_pair(contract, "depends_on_owner_cc_internal_state", 1);
  add_mapping_pair(contract, "dependency_manifest_ready", 1);
  add_mapping_pair(contract, "runtime_dependency_contract_version", 1);
  add_mapping_string(contract, "dependency_domains",
                     "scheduler_state,mailbox_state,task_dispatch,vm_context,metric_counters,future_completion");
  add_mapping_pair(contract, "scheduler_state_dependency", 1);
  add_mapping_pair(contract, "mailbox_state_dependency", 1);
  add_mapping_pair(contract, "task_dispatch_dependency", 1);
  add_mapping_pair(contract, "vm_context_dependency", 1);
  add_mapping_pair(contract, "metric_counter_dependency", 1);
  add_mapping_pair(contract, "future_completion_dependency", 1);
  add_mapping_pair(contract, "owner_runtime_facade_required", 1);
  add_mapping_pair(contract, "owner_runtime_facade_ready", 1);
  add_mapping_string(contract, "owner_runtime_facade_model", "owner_executor_runtime_facade_v1");
  add_mapping_string(contract, "owner_runtime_facade_file", "vm/internal/owner.cc");
  add_mapping_string(contract, "owner_runtime_facade_domains", "scheduler_state,mailbox_state,future_completion");
  add_mapping_pair(contract, "owner_runtime_facade_scheduler_ready", 1);
  add_mapping_pair(contract, "owner_runtime_facade_future_completion_ready", 1);
  add_mapping_string(contract, "compilation_unit_blocker", "owner_cc_anonymous_runtime_state");
  add_mapping_pair(contract, "claim_release_boundary_ready", 1);
  add_mapping_pair(contract, "budget_boundary_ready", 1);
  add_mapping_pair(contract, "thread_context_boundary_ready", 1);
  add_mapping_pair(contract, "dispatch_manifest_boundary_ready", 1);
  add_mapping_pair(contract, "same_owner_serial_required", 1);
  add_mapping_pair(contract, "main_required_tasks_excluded", 1);
  add_mapping_pair(contract, "target_handle_messages_main_required", 1);
  add_mapping_pair(contract, "compute_result_executor_safe", 1);
  add_mapping_pair(contract, "executor_callback_task_boundary_ready", 1);
  add_mapping_pair(contract, "executor_callback_allowlist_ready", 1);
  add_mapping_pair(contract, "executor_callback_cleanup_main_required", 1);
  add_mapping_string(contract, "executor_callback_allowlist",
                     "heartbeat,call_out,async_callback,dns_callback,socket_callback,gateway_command_execute");
  add_mapping_pair(contract, "heartbeat_owner_executor_ready", 1);
  add_mapping_string(contract, "heartbeat_owner_executor_task_type", "heartbeat");
  add_mapping_string(contract, "heartbeat_owner_executor_route", "owner_executor");
  add_mapping_string(contract, "heartbeat_owner_executor_fallback_route", "owner_main_queue");
  add_mapping_string(contract, "heartbeat_owner_executor_policy", "audit_enforced_owner_thread_else_main");
  add_mapping_pair(contract, "heartbeat_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(contract, "heartbeat_current_object_thread_local", 1);
  add_mapping_pair(contract, "callout_owner_executor_ready", 1);
  add_mapping_string(contract, "callout_owner_executor_task_type", "call_out");
  add_mapping_string(contract, "callout_owner_executor_route", "owner_executor");
  add_mapping_string(contract, "callout_owner_executor_fallback_route", "owner_main_queue");
  add_mapping_string(contract, "callout_owner_executor_policy", "audit_enforced_owner_thread_else_main");
  add_mapping_pair(contract, "callout_owner_executor_expired_handle_detach_ready", 1);
  add_mapping_pair(contract, "callout_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(contract, "callout_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(contract, "callout_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(contract, "gateway_command_rejected", 0);
  add_mapping_pair(contract, "gateway_command_executor_activation_ready", 1);
  add_mapping_pair(contract, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(contract, "ordinary_lpc_explicit_open_required", 1);
  add_mapping_string(contract, "ordinary_lpc_policy", "explicit_open_same_owner_only");
  add_mapping_pair(contract, "lpc_surface_expanded", 0);
  add_mapping_string(contract, "next_refactor_target", "migrate_async_dns_socket_callbacks_to_owner_executor");
  return contract;
}

mapping_t *owner_task_contract_mapping() {
  auto *contract = allocate_mapping(13);
  const auto *executor_probe = find_owner_executor_task_descriptor("executor_probe");
  const auto *compute_result = find_owner_executor_task_descriptor("compute_result");
  const auto *command_consume = find_owner_executor_task_descriptor("command_consume");
  const auto *command_frame_restore = find_owner_executor_task_descriptor("command_frame_restore");
  const auto *gateway_command = find_owner_executor_task_descriptor("gateway_command");
  const auto *ordinary_lpc = find_owner_executor_task_descriptor("ordinary_lpc");
  const auto *lpc = find_owner_executor_task_descriptor("lpc");
  add_mapping_owned_mapping(contract, "executor_probe",
                            owner_task_contract_entry(executor_probe->executor_mode, executor_probe->route,
                                                      executor_probe->executor_safe, executor_probe->main_required,
                                                      executor_probe->rejected, executor_probe->reason));
  add_mapping_owned_mapping(contract, "compute_result",
                            owner_task_contract_entry(compute_result->executor_mode, compute_result->route,
                                                      compute_result->executor_safe, compute_result->main_required,
                                                      compute_result->rejected, compute_result->reason));
  add_mapping_owned_mapping(contract, "owner_executor_command_consumer",
                            owner_task_contract_entry(command_consume->executor_mode, command_consume->route,
                                                      command_consume->executor_safe, command_consume->main_required,
                                                      command_consume->rejected, command_consume->reason));
  add_mapping_owned_mapping(contract, "owner_executor_command_frame_restore",
                            owner_task_contract_entry(command_frame_restore->executor_mode, command_frame_restore->route,
                                                      command_frame_restore->executor_safe,
                                                      command_frame_restore->main_required,
                                                      command_frame_restore->rejected, command_frame_restore->reason));
  add_mapping_owned_mapping(contract, "gateway_command_executor_activation",
                            gateway_command_activation_contract_entry(*gateway_command));
  auto *executor_callback_allowlist = owner_task_contract_entry(
      "executor_safe_callback", "owner_executor", 1, 0, 0,
      "driver callback closures only; ordinary LPC remains default closed");
  auto *executor_callback_contracts = owner_executor_callback_contracts_array();
  add_mapping_array(executor_callback_allowlist, "contracts", executor_callback_contracts);
  free_array(executor_callback_contracts);
  add_mapping_owned_mapping(contract, "owner_executor_callback_allowlist", executor_callback_allowlist);
  add_mapping_owned_mapping(contract, "owner_message_mailbox",
                            owner_task_route_contract_entry(kOwnerTaskExecutorSafeContract));
  add_mapping_owned_mapping(contract, "owner_message_target_handle",
                            owner_task_route_contract_entry(kOwnerTaskMainRequiredContract));
  const auto *lpc_task = find_owner_executor_task_descriptor("lpc_task");
  auto *lpc_task_allowlist =
      owner_task_contract_entry(lpc_task->executor_mode, lpc_task->route, lpc_task->executor_safe,
                                lpc_task->main_required, lpc_task->rejected, lpc_task->reason);
  auto *lpc_contracts = owner_lpc_task_contracts_array();
  add_mapping_array(lpc_task_allowlist, "contracts", lpc_contracts);
  free_array(lpc_contracts);
  add_mapping_owned_mapping(contract, "lpc_task_allowlist", lpc_task_allowlist);
  add_mapping_owned_mapping(contract, "ordinary_lpc", owner_ordinary_lpc_contract_entry(*ordinary_lpc));
  add_mapping_owned_mapping(contract, "lpc",
                            owner_task_contract_entry(lpc->executor_mode, lpc->route, lpc->executor_safe,
                                                      lpc->main_required, lpc->rejected, lpc->reason));
  return contract;
}

const OwnerTaskRouteContract &owner_task_route_contract(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return kOwnerTaskMainRequiredContract;
  }
  return kOwnerTaskExecutorSafeContract;
}

mapping_t *owner_mailbox_task_mapping(const OwnerMailboxTask &task) {
  auto *map = allocate_mapping(24);
  const auto &descriptor = owner_executor_task_descriptor(task);
  const auto target_message = task.task_type == "owner_message" && task.has_target_handle;
  const auto &message_route_contract = owner_task_route_contract(task);
  const auto &route_contract = target_message ? message_route_contract : kOwnerTaskExecutorSafeContract;
  const auto *task_executor_mode = target_message ? message_route_contract.executor_mode : descriptor.executor_mode;
  const auto *executor_mode = route_contract.executor_mode;
  const auto *route = target_message ? message_route_contract.route : descriptor.route;
  const auto *contract_key = target_message ? "owner_message_target_handle" : descriptor.contract_key;
  const auto executor_runnable = target_message ? 0 : descriptor.executor_runnable;
  const auto executor_safe = target_message ? message_route_contract.executor_safe : descriptor.executor_safe;
  const auto main_required = target_message ? message_route_contract.main_required : descriptor.main_required;
  const auto rejected = target_message ? message_route_contract.rejected : descriptor.rejected;
  const auto requires_owner_mailbox =
      target_message ? message_route_contract.requires_owner_mailbox : descriptor.requires_owner_mailbox;
  const auto requires_owner_main_queue =
      target_message ? message_route_contract.requires_owner_main_queue : descriptor.requires_owner_main_queue;
  add_mapping_pair(map, "task_id", static_cast<long>(task.task_id));
  add_mapping_pair(map, "future_target_task_id", static_cast<long>(task.future_target_task_id));
  add_mapping_pair(map, "sequence", static_cast<long>(task.sequence));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(task.owner_epoch));
  add_mapping_string(map, "owner_id", task.owner_id.c_str());
  add_mapping_string(map, "task_type", task.task_type.c_str());
  add_mapping_string(map, "task_key", task.task_key.c_str());
  add_mapping_string(map, "future_state", task.future_state.c_str());
  add_mapping_string(map, "future_error", task.future_error.c_str());
  add_mapping_string(map, "target_object",
                     task.target_object.empty() ? owner_object_name(task.target) : task.target_object.c_str());
  add_mapping_string(map, "task_contract_key", contract_key);
  add_mapping_string(map, "dispatch_kind", owner_executor_dispatch_kind_name(descriptor.dispatch_kind));
  add_mapping_string(map, "task_executor_mode", task_executor_mode);
  add_mapping_string(map, "executor_mode", executor_mode);
  add_mapping_string(map, "route", route);
  add_mapping_pair(map, "executor_runnable", executor_runnable);
  add_mapping_pair(map, "executor_safe", executor_safe);
  add_mapping_pair(map, "main_required", main_required);
  add_mapping_pair(map, "rejected", rejected);
  add_mapping_pair(map, "ordinary_lpc_explicit_open", task.ordinary_lpc_explicit_open ? 1 : 0);
  add_mapping_pair(map, "requires_owner_mailbox", requires_owner_mailbox);
  add_mapping_pair(map, "requires_owner_main_queue", requires_owner_main_queue);
  return map;
}

mapping_t *owner_task_trace_mapping(const OwnerTaskTrace &trace) {
  auto target_status = trace.has_target_handle ? vm_object_handle_resolve_status(trace.target_handle).status
                                               : VMObjectHandleResolveStatus::kInvalidHandle;
  auto *map = allocate_mapping(36);
  add_mapping_pair(map, "trace_id", static_cast<long>(trace.trace_id));
  add_mapping_string(map, "trace_model", "owner_task_lifecycle_event");
  add_mapping_pair(map, "task_id", static_cast<long>(trace.task_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(trace.owner_epoch));
  add_mapping_string(map, "owner_id", trace.owner_id.c_str());
  add_mapping_string(map, "task_type", trace.task_type.c_str());
  add_mapping_string(map, "task_key", trace.task_key.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  add_mapping_string(map, "target_object", trace.target_object.c_str());
  add_mapping_pair(map, "has_target_handle", trace.has_target_handle ? 1 : 0);
  add_mapping_pair(map, "target_handle_current",
                   target_status == VMObjectHandleResolveStatus::kCurrent ? 1 : 0);
  add_mapping_string(map, "target_handle_status",
                     trace.has_target_handle ? vm_object_handle_resolve_status_name(target_status) : "none");
  add_mapping_pair(map, "target_object_id", trace.has_target_handle ? static_cast<long>(trace.target_handle.object_id) : 0);
  add_mapping_string(map, "target_object_path", trace.has_target_handle ? trace.target_handle.object_path.c_str() : "");
  add_mapping_pair(map, "target_owner_epoch", trace.has_target_handle ? static_cast<long>(trace.target_handle.owner_epoch) : 0);
  add_mapping_string(map, "payload_key", trace.payload_key.c_str());
  add_mapping_string(map, "command_text_snapshot_policy", "owner_private_redacted_from_trace");
  add_mapping_pair(map, "command_text_snapshot_ready", trace.command_text_snapshot_ready ? 1 : 0);
  add_mapping_pair(map, "command_text_snapshot_bytes", static_cast<long>(trace.command_text_snapshot.size()));
  add_mapping_pair(map, "command_text_snapshot_redacted", trace.command_text_snapshot_ready ? 1 : 0);
  add_mapping_string(map, "command_text_snapshot_blocker", trace.command_text_snapshot_ready ? "" : "interactive_command_buffer_not_snapshotted");
  add_mapping_string(map, "command_consume_model", trace.command_consume_model.c_str());
  add_mapping_pair(map, "command_consume_snapshot_ready", trace.command_consume_snapshot_ready ? 1 : 0);
  add_mapping_pair(map, "command_consume_executor_ready", trace.command_consume_executor_ready ? 1 : 0);
  add_mapping_string(map, "command_consume_blocker", trace.command_consume_blocker.c_str());
  add_mapping_string(map, "execution_frame_model", trace.execution_frame_model.c_str());
  add_mapping_string(map, "execution_frame_policy", trace.execution_frame_policy.c_str());
  add_mapping_string(map, "execution_frame_restore_policy", trace.execution_frame_restore_policy.c_str());
  add_mapping_pair(map, "execution_frame_restore_ready", trace.execution_frame_restore_ready ? 1 : 0);
  add_mapping_string(map, "execution_frame_restore_blocker", trace.execution_frame_restore_blocker.c_str());
  add_mapping_pair(map, "execution_frame_requires_current_interactive",
                   trace.execution_frame_requires_current_interactive ? 1 : 0);
  add_mapping_pair(map, "execution_frame_requires_command_giver",
                   trace.execution_frame_requires_command_giver ? 1 : 0);
  add_mapping_pair(map, "execution_frame_executor_ready", trace.execution_frame_executor_ready ? 1 : 0);
  add_mapping_pair(map, "payload_frozen", trace.payload ? 1 : 0);
  if (trace.payload) {
    add_mapping_svalue(map, "payload", &trace.payload->value);
  }
  return map;
}

void release_owner_task_target(OwnerMailboxTask *task) {
  if (task && task->target) {
    auto *target = task->target;
    if (vm_context_is_main_thread()) {
      free_object(&target, "owner mailbox task");
    } else {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      owner_deferred_target_releases.push_back(target);
    }
    task->target = nullptr;
  }
}

void release_owner_main_task_target(OwnerMainTask *task) {
  if (task && task->target) {
    auto *target = task->target;
    if (vm_context_is_main_thread()) {
      free_object(&target, "owner main task");
    } else {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      owner_deferred_target_releases.push_back(target);
    }
    task->target = nullptr;
  }
}

void release_deferred_owner_targets_on_main() {
  if (!vm_context_is_main_thread()) {
    return;
  }
  std::vector<object_t *> releases;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    releases.swap(owner_deferred_target_releases);
  }
  for (auto *target : releases) {
    if (target) {
      free_object(&target, "owner mailbox task deferred release");
    }
  }
}

void enqueue_owner_executor_callback_cleanup_locked(OwnerMailboxTask &task) {
  if (!task.drop_callback) {
    return;
  }

  OwnerExecutorCallbackCleanup cleanup;
  cleanup.task_id = task.task_id;
  cleanup.sequence = task.sequence;
  cleanup.owner_epoch = task.owner_epoch;
  cleanup.owner_id = task.owner_id;
  cleanup.task_type = task.task_type;
  cleanup.task_key = task.task_key;
  cleanup.callback = std::move(task.drop_callback);
  append_owner_task_trace(task, "executor_callback_main_cleanup_queued");
  owner_executor_callback_main_cleanups.push_back(std::move(cleanup));
  owner_executor_callback_main_cleanup_queued.fetch_add(1, std::memory_order_relaxed);
}

void schedule_owner_executor_callback_cleanup_on_main(OwnerMailboxTask &task) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  enqueue_owner_executor_callback_cleanup_locked(task);
}

int drain_owner_executor_callback_cleanups(int limit) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }

  auto budget = limit <= 0 ? kOwnerExecutorTaskBudget : limit;
  int dispatched = 0;
  while (dispatched < budget) {
    OwnerExecutorCallbackCleanup cleanup;
    {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      if (owner_executor_callback_main_cleanups.empty()) {
        break;
      }
      cleanup = std::move(owner_executor_callback_main_cleanups.front());
      owner_executor_callback_main_cleanups.pop_front();
      append_owner_task_trace(cleanup.task_id, cleanup.sequence, cleanup.owner_id, cleanup.owner_epoch,
                              cleanup.task_type, cleanup.task_key,
                              "executor_callback_main_cleanup_dispatched");
    }
    if (cleanup.callback) {
      cleanup.callback();
    }
    owner_executor_callback_main_cleanup_dispatched.fetch_add(1, std::memory_order_relaxed);
    dispatched++;
  }
  return dispatched;
}

void record_owner_mailbox_task_drained(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message") {
    vm_object_store_remove_message(task.owner_id.c_str(), task.task_id);
  }
}

long owner_executor_runnable_queue_depth(const std::string &owner_id);
long owner_executor_safe_queue_depth(const std::string &owner_id);
long owner_main_required_queue_depth(const std::string &owner_id);
long owner_runnable_owner_count();

mapping_t *owner_access_trace_mapping(const OwnerAccessTrace &trace) {
  auto policy_mode = owner_access_policy_mode(trace.operation.c_str(), trace.cross_owner);
  auto *map = allocate_mapping(16);
  add_mapping_pair(map, "access_id", static_cast<long>(trace.access_id));
  add_mapping_string(map, "trace_model", "cross_owner_access_policy_event");
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "source_owner_epoch", static_cast<long>(trace.source_owner_epoch));
  add_mapping_pair(map, "target_owner_epoch", static_cast<long>(trace.target_owner_epoch));
  add_mapping_pair(map, "cross_owner", trace.cross_owner ? 1 : 0);
  add_mapping_string(map, "source_owner_id", trace.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", trace.target_owner_id.c_str());
  add_mapping_string(map, "source_object", trace.source_object.c_str());
  add_mapping_string(map, "target_object", trace.target_object.c_str());
  add_mapping_string(map, "operation", trace.operation.c_str());
  add_mapping_string(map, "access_mode", policy_mode);
  add_mapping_pair(map, "snapshot_only", std::strcmp(policy_mode, "snapshot") == 0 ? 1 : 0);
  add_mapping_pair(map, "message_only_cross_owner", std::strcmp(policy_mode, "message") == 0 ? 1 : 0);
  add_mapping_pair(map, "rejected_by_default", std::strcmp(policy_mode, "reject") == 0 ? 1 : 0);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *owner_message_trace_mapping(const OwnerMessageTrace &trace) {
  auto pending = trace.state == "message_submitted" || trace.state == "pending";
  auto completed = trace.state == "completed";
  auto failed = trace.state == "failed";
  auto target_handle_current = !trace.has_target_handle || trace.target_handle_status == "current";
  auto *map = allocate_mapping(27);
  add_mapping_pair(map, "message_id", static_cast<long>(trace.message_id));
  add_mapping_string(map, "trace_model", "owner_message_lifecycle_event");
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "target_task_id", static_cast<long>(trace.target_task_id));
  add_mapping_string(map, "source_owner_id", trace.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", trace.target_owner_id.c_str());
  add_mapping_string(map, "message_type", trace.message_type.c_str());
  add_mapping_string(map, "payload_key", trace.payload_key.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  add_mapping_string(map, "route", trace.route.c_str());
  add_mapping_string(map, "result_key", trace.result_key.c_str());
  add_mapping_string(map, "error", trace.error.c_str());
  add_mapping_pair(map, "pending", pending ? 1 : 0);
  add_mapping_pair(map, "completed", completed ? 1 : 0);
  add_mapping_pair(map, "failed", failed ? 1 : 0);
  add_mapping_pair(map, "terminal", (completed || failed) ? 1 : 0);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "frozen_result", trace.frozen_result ? 1 : 0);
  add_mapping_pair(map, "has_target_handle", trace.has_target_handle ? 1 : 0);
  add_mapping_pair(map, "target_handle_current", target_handle_current ? 1 : 0);
  add_mapping_string(map, "target_handle_status", trace.target_handle_status.c_str());
  add_mapping_pair(map, "requires_owner_mailbox", trace.requires_owner_mailbox ? 1 : 0);
  add_mapping_pair(map, "requires_owner_main_queue", trace.requires_owner_main_queue ? 1 : 0);
  add_mapping_pair(map, "main_required", trace.requires_owner_main_queue ? 1 : 0);
  add_mapping_pair(map, "queued_on_main", trace.queued_on_main ? 1 : 0);
  add_mapping_pair(map, "message_only_cross_owner", 1);
  return map;
}

mapping_t *owner_commit_trace_mapping(const OwnerCommitTrace &trace) {
  auto *map = allocate_mapping(10);
  add_mapping_pair(map, "commit_id", static_cast<long>(trace.commit_id));
  add_mapping_string(map, "trace_model", "owner_commit_boundary_event");
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "message_id", static_cast<long>(trace.message_id));
  add_mapping_pair(map, "direct_write", trace.direct_write ? 1 : 0);
  add_mapping_string(map, "source_owner_id", trace.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", trace.target_owner_id.c_str());
  add_mapping_string(map, "operation", trace.operation.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  add_mapping_pair(map, "commit_boundary_only", 1);
  return map;
}

mapping_t *owner_executor_trace_mapping(const OwnerExecutorTrace &trace) {
  auto *map = allocate_mapping(15);
  add_mapping_pair(map, "trace_id", static_cast<long>(trace.trace_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_string(map, "trace_model", "owner_executor_scheduler_event");
  add_mapping_string(map, "executor_contract_version", "owner_executor_v1");
  add_mapping_string(map, "executor_model", "owner_executor");
  add_mapping_string(map, "executor_dispatch_model", "descriptor_manifest");
  add_mapping_string(map, "owner_id", trace.owner_id.c_str());
  add_mapping_string(map, "event", trace.event.c_str());
  add_mapping_pair(map, "backlog", trace.backlog);
  add_mapping_pair(map, "runnable_backlog", trace.runnable_backlog);
  add_mapping_pair(map, "safe_backlog", trace.safe_backlog);
  add_mapping_pair(map, "main_required_backlog", trace.main_required_backlog);
  add_mapping_pair(map, "runnable_owners", trace.runnable_owners);
  add_mapping_pair(map, "claimed_owners", trace.claimed_owners);
  add_mapping_pair(map, "active_claims", trace.active_claims);
  return map;
}

uint64_t append_owner_task_trace(uint64_t task_id, uint64_t sequence, const std::string &owner_id,
                                 uint64_t owner_epoch, const std::string &task_type,
                                 const std::string &task_key, const char *state) {
  OwnerTaskTrace trace;
  trace.trace_id = next_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.task_id = task_id;
  trace.sequence = sequence;
  trace.owner_epoch = owner_epoch;
  trace.owner_id = owner_id;
  trace.task_type = task_type;
  trace.task_key = task_key;
  trace.state = normalize_task_text(state, "observed");
  owner_task_traces.push_back(std::move(trace));
  while (owner_task_traces.size() > kOwnerTraceLimit) {
    owner_task_traces.pop_front();
  }
  total_traced.fetch_add(1, std::memory_order_relaxed);
  return owner_task_traces.back().trace_id;
}

uint64_t append_owner_task_trace(const OwnerMailboxTask &task, const char *state) {
  OwnerTaskTrace trace;
  trace.trace_id = next_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.task_id = task.task_id;
  trace.sequence = task.sequence;
  trace.owner_epoch = task.owner_epoch;
  trace.target_handle = task.target_handle;
  trace.payload = task.payload;
  trace.owner_id = task.owner_id;
  trace.task_type = task.task_type;
  trace.task_key = task.task_key;
  trace.state = normalize_task_text(state, "observed");
  trace.target_object = task.target_object.empty() ? owner_object_name(task.target) : task.target_object;
  trace.has_target_handle = task.has_target_handle;
  owner_task_traces.push_back(std::move(trace));
  while (owner_task_traces.size() > kOwnerTraceLimit) {
    owner_task_traces.pop_front();
  }
  total_traced.fetch_add(1, std::memory_order_relaxed);
  return owner_task_traces.back().trace_id;
}

uint64_t append_owner_task_trace(const OwnerMainTask &task, const char *state) {
  OwnerTaskTrace trace;
  trace.trace_id = next_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.task_id = task.task_id;
  trace.sequence = task.sequence;
  trace.owner_epoch = task.owner_epoch;
  trace.target_handle = task.target_handle;
  trace.payload = task.payload;
  trace.owner_id = task.owner_id;
  trace.task_type = task.task_type;
  trace.task_key = task.task_key;
  trace.state = normalize_task_text(state, "observed");
  trace.target_object = task.target_object.empty() ? owner_object_name(task.target) : task.target_object;
  trace.payload_key = task.payload_key;
  trace.command_text_snapshot = task.command_text_snapshot;
  trace.command_text_snapshot_ready = task.command_text_snapshot_ready;
  trace.command_consume_model = task.command_consume_model;
  trace.command_consume_blocker = task.command_consume_blocker;
  trace.command_consume_snapshot_ready = task.command_consume_snapshot_ready;
  trace.command_consume_executor_ready = task.command_consume_executor_ready;
  trace.execution_frame_model = task.execution_frame_model;
  trace.execution_frame_policy = task.execution_frame_policy;
  trace.execution_frame_restore_policy = task.execution_frame_restore_policy;
  trace.execution_frame_restore_blocker = task.execution_frame_restore_blocker;
  trace.execution_frame_requires_current_interactive = task.execution_frame_requires_current_interactive;
  trace.execution_frame_requires_command_giver = task.execution_frame_requires_command_giver;
  trace.execution_frame_executor_ready = task.execution_frame_executor_ready;
  trace.execution_frame_restore_ready = task.execution_frame_restore_ready;
  trace.has_target_handle = task.has_target_handle;
  owner_task_traces.push_back(std::move(trace));
  while (owner_task_traces.size() > kOwnerTraceLimit) {
    owner_task_traces.pop_front();
  }
  total_traced.fetch_add(1, std::memory_order_relaxed);
  return owner_task_traces.back().trace_id;
}

uint64_t append_owner_task_trace_threadsafe(const OwnerMailboxTask &task, const char *state) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return append_owner_task_trace(task, state);
}

uint64_t append_owner_executor_trace_locked(const std::string &owner_id, const char *event) {
  OwnerExecutorTrace trace;
  trace.trace_id = next_executor_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = trace.trace_id;
  trace.owner_id = owner_id;
  trace.event = normalize_task_text(event, "observed");
  trace.backlog = owner_mailbox_depth(owner_id);
  trace.runnable_backlog = owner_executor_runnable_queue_depth(owner_id);
  trace.safe_backlog = owner_executor_safe_queue_depth(owner_id);
  trace.main_required_backlog = owner_main_required_queue_depth(owner_id);
  trace.runnable_owners = owner_runnable_owner_count();
  trace.claimed_owners = static_cast<long>(active_owner_set.size());
  trace.active_claims = static_cast<long>(active_owner_claim_counts.size());
  owner_executor_traces.push_back(std::move(trace));
  while (owner_executor_traces.size() > kOwnerExecutorTraceLimit) {
    owner_executor_traces.pop_front();
  }
  total_executor_traced.fetch_add(1, std::memory_order_relaxed);
  return owner_executor_traces.back().trace_id;
}

mapping_t *owner_future_mapping(const OwnerFutureRecord &record) {
  auto target_status = record.has_target_handle ? vm_object_handle_resolve_status(record.target_handle).status
                                                : VMObjectHandleResolveStatus::kCurrent;
  auto *map = allocate_mapping(21);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "future_id", static_cast<long>(record.future_id));
  add_mapping_pair(map, "target_task_id", static_cast<long>(record.target_task_id));
  add_mapping_string(map, "source_owner_id", record.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", record.target_owner_id.c_str());
  add_mapping_string(map, "message_type", record.message_type.c_str());
  add_mapping_string(map, "payload_key", record.payload_key.c_str());
  add_mapping_string(map, "state", record.state.c_str());
  add_mapping_string(map, "result_key", record.result_key.c_str());
  add_mapping_string(map, "error", record.error.c_str());
  add_mapping_pair(map, "requires_owner_message_completion", record.state == "pending" ? 1 : 0);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "frozen_result", record.result ? 1 : 0);
  add_mapping_pair(map, "has_target_handle", record.has_target_handle ? 1 : 0);
  add_mapping_pair(map, "target_handle_current",
                   target_status == VMObjectHandleResolveStatus::kCurrent ? 1 : 0);
  add_mapping_string(map, "target_handle_status", vm_object_handle_resolve_status_name(target_status));
  add_mapping_pair(map, "target_object_id", static_cast<long>(record.target_handle.object_id));
  add_mapping_string(map, "target_object_path", record.target_handle.object_path.c_str());
  add_mapping_pair(map, "target_owner_epoch", static_cast<long>(record.target_handle.owner_epoch));
  if (record.result) {
    add_mapping_svalue(map, "result", &record.result->value);
  }
  return map;
}

bool owner_message_target_current(const OwnerMailboxTask &task) {
  return !task.has_target_handle ||
         vm_object_handle_resolve_status(task.target_handle).status == VMObjectHandleResolveStatus::kCurrent;
}

void complete_owner_future_locked(uint64_t future_id, const char *state, const char *result_key, const char *error,
                                  std::shared_ptr<VMFrozenValue> result = nullptr) {
  auto it = owner_futures.find(future_id);
  if (it == owner_futures.end()) {
    return;
  }
  if (it->second.state != "pending") {
    return;
  }
  it->second.state = normalize_task_text(state, "completed");
  it->second.result_key = normalize_task_text(result_key, "");
  it->second.error = normalize_task_text(error, "");
  it->second.result = std::move(result);
  if (it->second.state == "failed") {
    total_futures_failed.fetch_add(1, std::memory_order_relaxed);
  } else {
    total_futures_completed.fetch_add(1, std::memory_order_relaxed);
  }
}

void update_owner_message_trace_state_for_task_locked(uint64_t target_task_id, const char *state,
                                                      const char *result_key, const char *error,
                                                      bool frozen_result,
                                                      VMObjectHandleResolveStatus target_handle_status) {
  for (auto &trace : owner_message_traces) {
    if (trace.target_task_id == target_task_id) {
      trace.state = normalize_task_text(state, "completed");
      trace.result_key = normalize_task_text(result_key, "");
      trace.error = normalize_task_text(error, "");
      trace.frozen_result = frozen_result;
      if (trace.has_target_handle) {
        trace.target_handle_status = vm_object_handle_resolve_status_name(target_handle_status);
      }
      return;
    }
  }
}

void complete_owner_future_for_task_locked(uint64_t target_task_id, const char *state, const char *result_key,
                                            const char *error,
                                            std::shared_ptr<VMFrozenValue> result = nullptr) {
  for (auto &entry : owner_futures) {
    if (entry.second.target_task_id == target_task_id && entry.second.state == "pending") {
      auto target_status = entry.second.has_target_handle ? vm_object_handle_resolve_status(entry.second.target_handle).status
                                                          : VMObjectHandleResolveStatus::kCurrent;
      entry.second.state = normalize_task_text(state, "completed");
      entry.second.result_key = normalize_task_text(result_key, "");
      entry.second.error = normalize_task_text(error, "");
      auto completed_with_frozen_result = entry.second.state == "completed" && result != nullptr;
      entry.second.result = std::move(result);
      update_owner_message_trace_state_for_task_locked(target_task_id, entry.second.state.c_str(),
                                                       entry.second.result_key.c_str(), entry.second.error.c_str(),
                                                       completed_with_frozen_result, target_status);
      if (entry.second.state == "failed") {
        total_futures_failed.fetch_add(1, std::memory_order_relaxed);
      } else {
        total_futures_completed.fetch_add(1, std::memory_order_relaxed);
      }
      return;
    }
  }
}

void complete_owner_future_for_task_threadsafe(uint64_t target_task_id, const char *state, const char *result_key,
                                               const char *error,
                                               std::shared_ptr<VMFrozenValue> result = nullptr) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  complete_owner_future_for_task_locked(target_task_id, state, result_key, error, std::move(result));
}

void complete_owner_message_task_locked(const OwnerMailboxTask &task) {
  if (owner_message_target_current(task)) {
    complete_owner_future_for_task_locked(task.task_id, "completed", task.task_key.c_str(), "");
  } else {
    complete_owner_future_for_task_locked(task.task_id, "failed", "", "stale target");
  }
}

void complete_owner_message_task_threadsafe(const OwnerMailboxTask &task, const char *state,
                                            const char *result_key, const char *error,
                                            std::shared_ptr<VMFrozenValue> result = nullptr) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  complete_owner_future_for_task_locked(task.task_id, state, result_key, error, std::move(result));
}

void complete_owner_main_message_task_threadsafe(const OwnerMainTask &task, const char *state,
                                                 const char *result_key, const char *error,
                                                 std::shared_ptr<VMFrozenValue> result = nullptr) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  complete_owner_future_for_task_locked(task.task_id, state, result_key, error, std::move(result));
  vm_object_store_remove_message(task.owner_id.c_str(), task.task_id);
}

void dispatch_owner_main_message(const OwnerMainTask &task) {
  if (!task.has_target_handle) {
    complete_owner_main_message_task_threadsafe(task, "failed", "", "missing target handle");
    return;
  }

  auto target_status = vm_object_handle_resolve_status(task.target_handle);
  if (target_status.status != VMObjectHandleResolveStatus::kCurrent) {
    auto error = stale_target_error(target_status.status);
    complete_owner_main_message_task_threadsafe(task, "failed", "", error.c_str());
    return;
  }

  auto *target = target_status.object;
  if (!target || (target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(target, task.owner_id.c_str(), task.owner_epoch)) {
    complete_owner_main_message_task_threadsafe(task, "failed", "", "stale target");
    return;
  }

  set_eval(max_eval_cost);
  int num_args = 0;
  if (task.payload) {
    push_svalue(&task.payload->value);
    num_args = 1;
  }
  auto *result = safe_apply(task.task_key.c_str(), target, num_args, ORIGIN_DRIVER);
  if (!result) {
    complete_owner_main_message_task_threadsafe(task, "failed", "", "lpc call failed");
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  if (!frozen_result) {
    complete_owner_main_message_task_threadsafe(task, "failed", "", "owner async result must be frozen data");
    return;
  }
  complete_owner_main_message_task_threadsafe(task, "completed", task.task_key.c_str(), "",
                                             std::move(frozen_result));
}

void dispatch_owner_message_on_main(const OwnerMailboxTask &task) {
  if (!task.has_target_handle) {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    complete_owner_message_task_locked(task);
    return;
  }
  auto target_status = vm_object_handle_resolve_status(task.target_handle);
  if (target_status.status != VMObjectHandleResolveStatus::kCurrent) {
    auto error = stale_target_error(target_status.status);
    complete_owner_message_task_threadsafe(task, "failed", "", error.c_str());
    return;
  }

  auto *target = target_status.object;
  if (!target || (target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(target, task.owner_id.c_str(), task.owner_epoch)) {
    complete_owner_message_task_threadsafe(task, "failed", "", "stale target");
    return;
  }

  VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
  set_eval(max_eval_cost);
  int num_args = 0;
  if (task.payload) {
    push_svalue(&task.payload->value);
    num_args = 1;
  }
  auto *result = safe_apply(task.task_key.c_str(), target, num_args, ORIGIN_DRIVER);
  if (!result) {
    complete_owner_message_task_threadsafe(task, "failed", "", "lpc call failed");
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  if (!frozen_result) {
    complete_owner_message_task_threadsafe(task, "failed", "", "owner async result must be frozen data");
    return;
  }
  complete_owner_message_task_threadsafe(task, "completed", task.task_key.c_str(), "", std::move(frozen_result));
}

void complete_owner_compute_result_task_locked(const OwnerMailboxTask &task) {
  auto target_task_id = task.future_target_task_id == 0 ? task.task_id : task.future_target_task_id;
  auto failed = task.future_state == "failed";
  if (failed) {
    complete_owner_future_for_task_locked(target_task_id, "failed", "", task.future_error.c_str());
    return;
  }

  auto result = frozen_compute_result_mapping(task);
  if (!result) {
    complete_owner_future_for_task_locked(target_task_id, "failed", "",
                                          "worker compute result must contain frozen data");
    return;
  }
  complete_owner_future_for_task_locked(target_task_id, "completed", task.task_key.c_str(), "",
                                        std::move(result));
}

void mark_owner_schedulable(const std::string &owner_id);
void mark_main_owner_schedulable(const std::string &owner_id);

bool owner_task_requires_main_drain(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return kOwnerTaskMainRequiredContract.main_required != 0;
  }
  return owner_executor_task_descriptor(task).main_required != 0;
}

bool owner_task_executor_runnable(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return false;
  }
  return owner_executor_task_descriptor(task).executor_runnable != 0;
}

bool owner_task_executor_safe(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return false;
  }
  return owner_executor_task_descriptor(task).executor_safe != 0;
}

bool owner_queue_has_thread_task(const std::deque<OwnerMailboxTask> &queue) {
  for (const auto &task : queue) {
    if (owner_task_executor_runnable(task)) {
      return true;
    }
  }
  return false;
}

long owner_executor_runnable_queue_depth(const std::deque<OwnerMailboxTask> &queue) {
  long depth = 0;
  for (const auto &task : queue) {
    if (owner_task_executor_runnable(task)) {
      depth++;
    }
  }
  return depth;
}

long owner_executor_safe_queue_depth(const std::deque<OwnerMailboxTask> &queue) {
  long depth = 0;
  for (const auto &task : queue) {
    if (owner_task_executor_safe(task)) {
      depth++;
    }
  }
  return depth;
}

long owner_main_required_queue_depth(const std::deque<OwnerMailboxTask> &queue) {
  long depth = 0;
  for (const auto &task : queue) {
    if (owner_task_requires_main_drain(task)) {
      depth++;
    }
  }
  return depth;
}

long owner_executor_runnable_queue_depth(const std::string &owner_id) {
  auto it = owner_mailboxes.find(owner_id);
  return it == owner_mailboxes.end() ? 0 : owner_executor_runnable_queue_depth(it->second);
}

long owner_executor_safe_queue_depth(const std::string &owner_id) {
  auto it = owner_mailboxes.find(owner_id);
  return it == owner_mailboxes.end() ? 0 : owner_executor_safe_queue_depth(it->second);
}

long owner_main_required_queue_depth(const std::string &owner_id) {
  auto it = owner_mailboxes.find(owner_id);
  return it == owner_mailboxes.end() ? 0 : owner_main_required_queue_depth(it->second);
}

void record_owner_executor_budget_yield_locked(const std::string &owner_id) {
  owner_executor_budget_yields.fetch_add(1, std::memory_order_relaxed);
  owner_executor_last_budget_yield_owner = owner_id;
  owner_executor_last_budget_yield_backlog = owner_mailbox_depth(owner_id);
  owner_executor_last_budget_yield_safe_backlog = owner_executor_safe_queue_depth(owner_id);
  append_owner_executor_trace_locked(owner_id, "budget_yield");
}

long owner_executor_runnable_queue_depth() {
  long depth = 0;
  for (const auto &entry : owner_mailboxes) {
    depth += owner_executor_runnable_queue_depth(entry.second);
  }
  return depth;
}

long owner_executor_safe_queue_depth() {
  long depth = 0;
  for (const auto &entry : owner_mailboxes) {
    depth += owner_executor_safe_queue_depth(entry.second);
  }
  return depth;
}

long owner_main_required_queue_depth() {
  long depth = 0;
  for (const auto &entry : owner_mailboxes) {
    depth += owner_main_required_queue_depth(entry.second);
  }
  return depth;
}

long owner_runnable_owner_count() {
  long owners = 0;
  for (const auto &entry : owner_mailboxes) {
    if (active_owner_set.count(entry.first) == 0 && owner_queue_has_thread_task(entry.second)) {
      owners++;
    }
  }
  return owners;
}

long owner_main_runnable_owner_count() {
  long owners = 0;
  for (const auto &entry : owner_main_queues) {
    if (!entry.second.empty() && active_main_owner_set.count(entry.first) == 0) {
      owners++;
    }
  }
  return owners;
}

mapping_t *owner_queue_fairness_mapping() {
  long mailbox_owner_count = 0;
  long executor_ready_owner_count = 0;
  long executor_claim_blocked_owner_count = 0;
  long executor_runnable_owner_count = 0;
  long executor_runnable_claim_blocked_owner_count = 0;
  long main_required_only_owner_count = 0;
  long mixed_backlog_owner_count = 0;
  long max_owner_backlog = 0;
  long max_executor_runnable_backlog = 0;
  long max_executor_safe_backlog = 0;
  long max_main_required_backlog = 0;

  for (const auto &entry : owner_mailboxes) {
    auto owner_backlog = static_cast<long>(entry.second.size());
    if (owner_backlog <= 0) {
      continue;
    }

    auto runnable_backlog = owner_executor_runnable_queue_depth(entry.second);
    auto safe_backlog = owner_executor_safe_queue_depth(entry.second);
    auto main_required_backlog = owner_main_required_queue_depth(entry.second);
    mailbox_owner_count++;
    if (runnable_backlog > 0 && active_owner_set.count(entry.first) == 0) {
      executor_runnable_owner_count++;
    }
    if (runnable_backlog > 0 && active_owner_set.count(entry.first) > 0) {
      executor_runnable_claim_blocked_owner_count++;
    }
    if (safe_backlog > 0 && active_owner_set.count(entry.first) == 0) {
      executor_ready_owner_count++;
    }
    if (safe_backlog > 0 && active_owner_set.count(entry.first) > 0) {
      executor_claim_blocked_owner_count++;
    }
    if (safe_backlog == 0 && main_required_backlog > 0) {
      main_required_only_owner_count++;
    }
    if (safe_backlog > 0 && main_required_backlog > 0) {
      mixed_backlog_owner_count++;
    }
    if (owner_backlog > max_owner_backlog) {
      max_owner_backlog = owner_backlog;
    }
    if (runnable_backlog > max_executor_runnable_backlog) {
      max_executor_runnable_backlog = runnable_backlog;
    }
    if (safe_backlog > max_executor_safe_backlog) {
      max_executor_safe_backlog = safe_backlog;
    }
    if (main_required_backlog > max_main_required_backlog) {
      max_main_required_backlog = main_required_backlog;
    }
  }

  long main_queue_owner_count = 0;
  long main_ready_owner_count = 0;
  long main_claim_blocked_owner_count = 0;
  long max_owner_main_queue_depth = 0;
  for (const auto &entry : owner_main_queues) {
    auto main_depth = static_cast<long>(entry.second.size());
    if (main_depth <= 0) {
      continue;
    }
    main_queue_owner_count++;
    if (active_main_owner_set.count(entry.first) == 0) {
      main_ready_owner_count++;
    } else {
      main_claim_blocked_owner_count++;
    }
    if (main_depth > max_owner_main_queue_depth) {
      max_owner_main_queue_depth = main_depth;
    }
  }

  auto *map = allocate_mapping(15);
  add_mapping_pair(map, "owner_mailbox_owner_count", mailbox_owner_count);
  add_mapping_pair(map, "executor_ready_owner_count", executor_ready_owner_count);
  add_mapping_pair(map, "executor_claim_blocked_owner_count", executor_claim_blocked_owner_count);
  add_mapping_pair(map, "executor_runnable_owner_count", executor_runnable_owner_count);
  add_mapping_pair(map, "executor_runnable_claim_blocked_owner_count", executor_runnable_claim_blocked_owner_count);
  add_mapping_pair(map, "main_required_only_owner_count", main_required_only_owner_count);
  add_mapping_pair(map, "mixed_backlog_owner_count", mixed_backlog_owner_count);
  add_mapping_pair(map, "max_owner_backlog", max_owner_backlog);
  add_mapping_pair(map, "max_executor_runnable_backlog", max_executor_runnable_backlog);
  add_mapping_pair(map, "max_executor_safe_backlog", max_executor_safe_backlog);
  add_mapping_pair(map, "max_main_required_backlog", max_main_required_backlog);
  add_mapping_pair(map, "owner_main_queue_owner_count", main_queue_owner_count);
  add_mapping_pair(map, "main_ready_owner_count", main_ready_owner_count);
  add_mapping_pair(map, "main_claim_blocked_owner_count", main_claim_blocked_owner_count);
  add_mapping_pair(map, "max_owner_main_queue_depth", max_owner_main_queue_depth);
  return map;
}

void store_max_atomic(std::atomic<uint64_t> &target, uint64_t value) {
  auto current = target.load(std::memory_order_relaxed);
  while (value > current &&
         !target.compare_exchange_weak(current, value, std::memory_order_relaxed, std::memory_order_relaxed)) {
  }
}

void enqueue_owner_task_locked(OwnerMailboxTask task, const std::string &owner_id, bool *notify_owner_thread) {
  append_owner_task_trace(task, "queued");
  auto &queue = owner_mailboxes[owner_id];
  auto had_thread_task = owner_queue_has_thread_task(queue);
  auto task_requires_main = owner_task_requires_main_drain(task);
  queue.push_back(std::move(task));
  if (!task_requires_main && !had_thread_task && active_owner_set.count(owner_id) == 0) {
    mark_owner_schedulable(owner_id);
    *notify_owner_thread = true;
  }
}

void mark_owner_schedulable(const std::string &owner_id) {
  if (schedulable_owner_set.insert(owner_id).second) {
    schedulable_owners.push_back(owner_id);
  }
}

void mark_main_owner_schedulable(const std::string &owner_id) {
  if (main_schedulable_owner_set.insert(owner_id).second) {
    main_schedulable_owners.push_back(owner_id);
  }
}

void finish_active_main_owner_task(const std::string &owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  if (active_main_owner_set.erase(owner_id) > 0) {
    owner_main_owner_releases.fetch_add(1, std::memory_order_relaxed);
  }
  auto it = owner_main_queues.find(owner_id);
  if (it != owner_main_queues.end() && !it->second.empty()) {
    mark_main_owner_schedulable(owner_id);
  }
}

void finish_active_owner_task(const std::string &owner_id) {
  bool notify_owner_thread = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    auto released = active_owner_set.erase(owner_id) > 0;
    if (released) {
      owner_executor_owner_releases.fetch_add(1, std::memory_order_relaxed);
    }
    active_owner_claim_counts.erase(owner_id);
    auto it = owner_mailboxes.find(owner_id);
    if (it != owner_mailboxes.end() && owner_queue_has_thread_task(it->second)) {
      mark_owner_schedulable(owner_id);
      notify_owner_thread = true;
    }
    if (released) {
      append_owner_executor_trace_locked(owner_id, "owner_released");
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
}

bool pop_next_schedulable_task(OwnerMailboxTask *out, bool claim_owner) {
  while (!schedulable_owners.empty()) {
    auto owner_id = schedulable_owners.front();
    schedulable_owners.pop_front();
    if (schedulable_owner_set.erase(owner_id) == 0) {
      continue;
    }
    if (active_owner_set.count(owner_id) > 0) {
      continue;
    }

    auto it = owner_mailboxes.find(owner_id);
    if (it == owner_mailboxes.end() || it->second.empty()) {
      owner_mailboxes.erase(owner_id);
      continue;
    }

    auto task_it = it->second.begin();
    while (task_it != it->second.end() && !owner_task_executor_runnable(*task_it)) {
      ++task_it;
      if (claim_owner) {
        owner_executor_main_required_skipped.fetch_add(1, std::memory_order_relaxed);
      }
    }
    if (task_it == it->second.end()) {
      continue;
    }

    *out = *task_it;
    it->second.erase(task_it);
    if (it->second.empty()) {
      owner_mailboxes.erase(it);
    } else if (!claim_owner && owner_queue_has_thread_task(it->second)) {
      mark_owner_schedulable(owner_id);
    }
    if (claim_owner) {
      active_owner_set.insert(owner_id);
      auto owner_claims = ++active_owner_claim_counts[owner_id];
      if (owner_claims > 1) {
        owner_executor_same_owner_claim_conflicts.fetch_add(1, std::memory_order_relaxed);
      }
      store_max_atomic(owner_executor_max_owner_parallel, static_cast<uint64_t>(owner_claims));
      store_max_atomic(owner_executor_max_parallel_owners, static_cast<uint64_t>(active_owner_set.size()));
      owner_executor_owner_claims.fetch_add(1, std::memory_order_relaxed);
    }
    return true;
  }

  return false;
}

bool pop_next_main_task(OwnerMainTask *out, bool claim_owner) {
  while (!main_schedulable_owners.empty()) {
    auto owner_id = main_schedulable_owners.front();
    main_schedulable_owners.pop_front();
    if (main_schedulable_owner_set.erase(owner_id) == 0) {
      continue;
    }
    if (claim_owner && active_main_owner_set.count(owner_id) > 0) {
      continue;
    }

    auto it = owner_main_queues.find(owner_id);
    if (it == owner_main_queues.end() || it->second.empty()) {
      owner_main_queues.erase(owner_id);
      continue;
    }

    *out = std::move(it->second.front());
    it->second.pop_front();
    if (it->second.empty()) {
      owner_main_queues.erase(it);
    } else if (!claim_owner) {
      mark_main_owner_schedulable(owner_id);
    }
    if (claim_owner) {
      active_main_owner_set.insert(owner_id);
      owner_main_owner_claims.fetch_add(1, std::memory_order_relaxed);
    }
    return true;
  }

  return false;
}

bool pop_next_executor_task_for_owner(const std::string &owner_id, OwnerMailboxTask *out) {
  auto it = owner_mailboxes.find(owner_id);
  if (it == owner_mailboxes.end() || it->second.empty()) {
    owner_mailboxes.erase(owner_id);
    return false;
  }

  auto task_it = it->second.begin();
  while (task_it != it->second.end() && !owner_task_executor_runnable(*task_it)) {
    ++task_it;
    owner_executor_main_required_skipped.fetch_add(1, std::memory_order_relaxed);
  }
  if (task_it == it->second.end()) {
    return false;
  }

  *out = std::move(*task_it);
  it->second.erase(task_it);
  if (it->second.empty()) {
    owner_mailboxes.erase(it);
  }
  return true;
}

bool owner_execution_state_cleared() {
  const auto &execution = vm_context().execution;
  const auto &error = vm_context().error;
  const auto &eval_stack = vm_context().eval_stack;
  const auto &control_stack = vm_context().control_stack;
  const auto &value_stack = vm_context().value_stack;
  const auto &apply_return = vm_context().apply_return;
  const auto &object_store = vm_context().object_store;
  return execution.current_object == nullptr && execution.command_giver == nullptr &&
         execution.current_interactive == nullptr && execution.previous_ob == nullptr &&
         execution.current_prog == nullptr && execution.caller_type == 0 &&
         execution.call_origin == 0 &&
         execution.function_index_offset == 0 && execution.variable_index_offset == 0 &&
         execution.stack_in_use_as_temporary == 0 && eval_stack.empty && !eval_stack.owner_bound &&
         control_stack.empty && !control_stack.owner_bound && value_stack.empty &&
         !value_stack.owner_bound && apply_return.empty && !apply_return.owner_bound &&
         error.current_error_context == nullptr && error.too_deep_error == 0 &&
         error.max_eval_error == 0 && error.error_depth == 0 &&
         error.mudlib_error_depth == 0 && object_store.load_object_depth == 0 &&
         object_store.restricted_destruct_object == nullptr;
}

bool owner_lpc_task_allowed(const OwnerMailboxTask &task) {
  return find_owner_lpc_task_descriptor(task.task_key) != nullptr;
}

void maybe_delay_owner_executor_probe() {
  auto *value = std::getenv("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS");
  if (!value) {
    return;
  }
  auto delay_ms = std::atoi(value);
  if (delay_ms > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
  }
}

void record_owner_context_cleanup(const OwnerMailboxTask &task) {
  vm_context_sync_eval_stack(vm_context());
  vm_context_sync_control_stack(vm_context());
  vm_context_sync_value_stack(vm_context());
  vm_context_clear_apply_return(vm_context());
  vm_context_sync_apply_return(vm_context());
  auto owner_cleared = vm_context().owner.current_owner_id.empty() &&
                       vm_context().owner.current_owner_epoch == 0;
  auto eval_stack_cleared = vm_context().eval_stack.empty && !vm_context().eval_stack.owner_bound;
  auto control_stack_cleared = vm_context().control_stack.empty && !vm_context().control_stack.owner_bound;
  auto value_stack_cleared = vm_context().value_stack.empty && !vm_context().value_stack.owner_bound;
  auto apply_return_cleared = vm_context().apply_return.empty && !vm_context().apply_return.owner_bound;
  auto execution_cleared = owner_execution_state_cleared();
  auto canary_cleared = !vm_context().owner.lpc_canary_active && !vm_context().owner.controlled_lpc_active;

  if (owner_cleared) {
    owner_thread_owner_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  if (execution_cleared) {
    owner_thread_execution_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  if (eval_stack_cleared) {
    owner_thread_eval_stack_cleared.fetch_add(1, std::memory_order_relaxed);
  } else {
    owner_thread_eval_stack_leak_detected.fetch_add(1, std::memory_order_relaxed);
  }
  if (control_stack_cleared) {
    owner_thread_control_stack_cleared.fetch_add(1, std::memory_order_relaxed);
  } else {
    owner_thread_control_stack_leak_detected.fetch_add(1, std::memory_order_relaxed);
  }
  if (value_stack_cleared) {
    owner_thread_value_stack_cleared.fetch_add(1, std::memory_order_relaxed);
  } else {
    owner_thread_value_stack_leak_detected.fetch_add(1, std::memory_order_relaxed);
  }
  if (apply_return_cleared) {
    owner_thread_apply_return_cleared.fetch_add(1, std::memory_order_relaxed);
  } else {
    owner_thread_apply_return_leak_detected.fetch_add(1, std::memory_order_relaxed);
  }
  if (canary_cleared) {
    owner_thread_lpc_canary_flag_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  if (!owner_cleared || !execution_cleared || !eval_stack_cleared || !control_stack_cleared ||
      !value_stack_cleared || !apply_return_cleared || !canary_cleared) {
    append_owner_task_trace_threadsafe(task, "thread_context_leak_detected");
    owner_thread_context_leak_detected.fetch_add(1, std::memory_order_relaxed);
  }
}

void run_owner_lpc_probe(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;
  if (off_main_context && object_store_isolated && owner_bound && !task.target_object.empty()) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_probe_guarded");
    owner_thread_lpc_probe_guarded.fetch_add(1, std::memory_order_relaxed);
  } else {
    append_owner_task_trace_threadsafe(task, "thread_lpc_probe_failed");
    owner_thread_lpc_probe_failed.fetch_add(1, std::memory_order_relaxed);
  }
}

void run_owner_lpc_canary(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;
  auto method_allowed = task.task_key == "owner_lpc_canary";

  if (!off_main_context || !object_store_isolated || !owner_bound || !task.target ||
      !method_allowed || (task.target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(task.target, task.owner_id.c_str(), task.owner_epoch)) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_canary_rejected");
    owner_thread_lpc_canary_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  VMExecutionState execution;
  execution.current_object = task.target;
  execution.current_prog = task.target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  auto saved_canary = vm_context().owner.lpc_canary_active;
  vm_context().owner.lpc_canary_active = true;
  owner_thread_lpc_canary_executed.fetch_add(1, std::memory_order_relaxed);
  auto *result = safe_apply(task.task_key.c_str(), task.target, 0, ORIGIN_DRIVER);
  vm_context().owner.lpc_canary_active = saved_canary;

  if (result && result->type == T_NUMBER && result->u.number == 1) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_canary_succeeded");
    owner_thread_lpc_canary_succeeded.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  append_owner_task_trace_threadsafe(task, "thread_lpc_canary_failed");
  owner_thread_lpc_canary_failed.fetch_add(1, std::memory_order_relaxed);
}

void run_owner_lpc_task(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;

  if (!off_main_context || !object_store_isolated || !owner_bound || !task.target ||
      !owner_lpc_task_allowed(task) || (task.target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(task.target, task.owner_id.c_str(), task.owner_epoch)) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_rejected");
    owner_thread_lpc_task_rejected.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "owner lpc task rejected");
    return;
  }

  VMExecutionState execution;
  execution.current_object = task.target;
  execution.current_prog = task.target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  auto saved_controlled_lpc = vm_context().owner.controlled_lpc_active;
  vm_context().owner.controlled_lpc_active = true;
  owner_thread_lpc_task_executed.fetch_add(1, std::memory_order_relaxed);
  auto *result = safe_apply(task.task_key.c_str(), task.target, 0, ORIGIN_DRIVER);
  vm_context().owner.controlled_lpc_active = saved_controlled_lpc;

  if (!result) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_failed");
    owner_thread_lpc_task_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "lpc call failed");
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  if (!frozen_result) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_failed");
    owner_thread_lpc_task_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "owner lpc result must be frozen data");
    return;
  }
  if (result && result->type == T_NUMBER && result->u.number == 1) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_succeeded");
    owner_thread_lpc_task_succeeded.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "completed", task.task_key.c_str(), "",
                                             std::move(frozen_result));
    return;
  }
  append_owner_task_trace_threadsafe(task, "thread_lpc_task_failed");
  owner_thread_lpc_task_failed.fetch_add(1, std::memory_order_relaxed);
  complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "owner lpc task returned failure");
}

void run_owner_ordinary_lpc(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;

  if (!off_main_context || !object_store_isolated || !owner_bound || !task.ordinary_lpc_explicit_open ||
      !task.target || (task.target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(task.target, task.owner_id.c_str(), task.owner_epoch)) {
    append_owner_task_trace_threadsafe(task, "thread_ordinary_lpc_rejected");
    owner_thread_ordinary_lpc_rejected.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "ordinary lpc task rejected");
    return;
  }

  VMExecutionState execution;
  execution.current_object = task.target;
  execution.current_prog = task.target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  auto saved_controlled_lpc = vm_context().owner.controlled_lpc_active;
  vm_context().owner.controlled_lpc_active = true;
  owner_thread_ordinary_lpc_executed.fetch_add(1, std::memory_order_relaxed);
  auto *result = safe_apply(task.task_key.c_str(), task.target, 0, ORIGIN_DRIVER);
  vm_context().owner.controlled_lpc_active = saved_controlled_lpc;

  if (!result) {
    append_owner_task_trace_threadsafe(task, "thread_ordinary_lpc_failed");
    owner_thread_ordinary_lpc_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "ordinary lpc call failed");
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  if (!frozen_result) {
    append_owner_task_trace_threadsafe(task, "thread_ordinary_lpc_failed");
    owner_thread_ordinary_lpc_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "ordinary lpc result must be frozen data");
    return;
  }
  append_owner_task_trace_threadsafe(task, "thread_ordinary_lpc_succeeded");
  owner_thread_ordinary_lpc_succeeded.fetch_add(1, std::memory_order_relaxed);
  complete_owner_future_for_task_threadsafe(task.task_id, "completed", task.task_key.c_str(), "",
                                           std::move(frozen_result));
}

void run_owner_command_frame_restore(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;

  if (!off_main_context || !object_store_isolated || !owner_bound || !task.target ||
      (task.target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(task.target, task.owner_id.c_str(), task.owner_epoch)) {
    append_owner_task_trace_threadsafe(task, "thread_command_frame_restore_rejected");
    return;
  }

  bool frame_restored = false;
  bool frame_restored_cleared = false;
  {
    VMExecutionState execution;
    execution.current_object = task.target;
    execution.current_prog = task.target->prog;
    execution.current_interactive = task.target;
    execution.command_giver = task.target;
    VMExecutionScope execution_scope(vm_context(), execution);
    const auto &current_execution = vm_context().execution;
    frame_restored = current_execution.current_object == task.target &&
                     current_execution.current_prog == task.target->prog &&
                     current_execution.current_interactive == task.target &&
                     current_execution.command_giver == task.target;
  }
  const auto &restored_execution = vm_context().execution;
  frame_restored_cleared = restored_execution.current_object == nullptr &&
                           restored_execution.current_prog == nullptr &&
                           restored_execution.current_interactive == nullptr &&
                           restored_execution.command_giver == nullptr;

  if (!frame_restored || !frame_restored_cleared) {
    append_owner_task_trace_threadsafe(task, "thread_command_frame_restore_rejected");
    return;
  }

  append_owner_task_trace_threadsafe(task, "thread_command_frame_restore_ready");
  owner_executor_command_frame_restore_entry_executed.fetch_add(1, std::memory_order_relaxed);
}

void drop_owner_executor_callback(OwnerMailboxTask &task, const char *state) {
  append_owner_task_trace_threadsafe(task, state);
  owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
  schedule_owner_executor_callback_cleanup_on_main(task);
}

void run_owner_executor_callback(OwnerMailboxTask &task) {
  if (!task.callback || !task.has_target_handle || !task.target) {
    drop_owner_executor_callback(task, "thread_executor_callback_stale");
    return;
  }

  auto target_status = vm_object_handle_resolve_status(task.target_handle);
  if (target_status.status != VMObjectHandleResolveStatus::kCurrent) {
    drop_owner_executor_callback(task,
                                 target_status.status == VMObjectHandleResolveStatus::kObjectDestructed
                                     ? "thread_executor_callback_destructed"
                                     : "thread_executor_callback_stale");
    return;
  }

  auto *target = target_status.object;
  if (!target || (target->flags & O_DESTRUCTED)) {
    drop_owner_executor_callback(task, "thread_executor_callback_destructed");
    return;
  }
  if (!vm_owner_epoch_matches(target, task.owner_id.c_str(), task.owner_epoch)) {
    drop_owner_executor_callback(task, "thread_executor_callback_stale");
    return;
  }

  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;
  if (vm_context_is_main_thread() || !owner_bound) {
    drop_owner_executor_callback(task, "thread_executor_callback_guard_rejected");
    return;
  }

  VMExecutionState execution;
  execution.current_object = target;
  execution.current_prog = target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  append_owner_task_trace_threadsafe(task, "thread_executor_callback_dispatched");
  owner_executor_callback_dispatched.fetch_add(1, std::memory_order_relaxed);
  task.callback();
  append_owner_task_trace_threadsafe(task, "thread_executor_callback_completed");
}

class OwnerExecutorRuntimeImpl final : public OwnerExecutorRuntime {
 public:
  void bind_context() override {
    context_scope_.emplace(owner_context_);
    if (&vm_context() != &vm_main_context()) {
      owner_thread_context_bound.fetch_add(1, std::memory_order_relaxed);
    }
    if (!vm_context().object_store.main_thread_owned && vm_context().object_store.objects == nullptr) {
      owner_thread_object_store_isolated.fetch_add(1, std::memory_order_relaxed);
    }
    reset_machine(1);
    vm_context_sync_eval_stack(vm_context());
    vm_context_sync_control_stack(vm_context());
    vm_context_sync_value_stack(vm_context());
    vm_context_clear_apply_return(vm_context());
    vm_context_sync_apply_return(vm_context());
  }

  std::string claim_next_owner() override {
    while (true) {
      std::unique_lock<std::mutex> lock(owner_runtime_mutex);
      owner_runtime_cv.wait(lock, [] { return owner_thread_stopping || !schedulable_owners.empty(); });
      if (owner_thread_stopping) {
        return "";
      }
      OwnerMailboxTask first_task;
      if (!pop_next_schedulable_task(&first_task, true)) {
        continue;
      }
      auto owner_id = first_task.owner_id;
      owner_mailboxes[owner_id].push_front(std::move(first_task));
      append_owner_executor_trace_locked(owner_id, "owner_claimed");
      return owner_id;
    }
  }

  void run_claimed_owner(const std::string &owner_id) override {
    int budget_used = 0;
    while (budget_used < kOwnerExecutorTaskBudget) {
      OwnerMailboxTask task;
      if (!pop_executor_task(owner_id, &task)) {
        break;
      }
      run_task(task);
      budget_used++;
    }
    if (budget_used >= kOwnerExecutorTaskBudget) {
      record_budget_yield_if_needed(owner_id);
    }
  }

  void release_owner_after_task(const std::string &owner_id) override {
    finish_active_owner_task(owner_id);
  }

 private:
  VMContext owner_context_;
  std::optional<VMContextThreadScope> context_scope_;

  bool pop_executor_task(const std::string &owner_id, OwnerMailboxTask *task) {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    return pop_next_executor_task_for_owner(owner_id, task);
  }

  void record_budget_yield_if_needed(const std::string &owner_id) {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    auto it = owner_mailboxes.find(owner_id);
    if (it != owner_mailboxes.end() && owner_queue_has_thread_task(it->second)) {
      record_owner_executor_budget_yield_locked(owner_id);
    }
  }

  void complete_owner_message_task(const OwnerMailboxTask &task) {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    complete_owner_message_task_locked(task);
  }

  void complete_owner_compute_result_task(const OwnerMailboxTask &task) {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    complete_owner_compute_result_task_locked(task);
  }

  void run_task(OwnerMailboxTask &task) {
    record_owner_mailbox_task_drained(task);
    {
      VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
      if (vm_context().owner.current_owner_id == task.owner_id &&
          vm_context().owner.current_owner_epoch == task.owner_epoch) {
        owner_thread_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_eval_stack(vm_context());
      if (vm_context().eval_stack.thread_local_storage && vm_context().eval_stack.context_bound &&
          vm_context().eval_stack.owner_id == task.owner_id &&
          vm_context().eval_stack.owner_epoch == task.owner_epoch) {
        owner_thread_eval_stack_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_control_stack(vm_context());
      if (vm_context().control_stack.thread_local_storage && vm_context().control_stack.context_bound &&
          vm_context().control_stack.owner_id == task.owner_id &&
          vm_context().control_stack.owner_epoch == task.owner_epoch) {
        owner_thread_control_stack_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_value_stack(vm_context());
      if (vm_context().value_stack.thread_local_storage && vm_context().value_stack.context_bound &&
          vm_context().value_stack.owner_id == task.owner_id &&
          vm_context().value_stack.owner_epoch == task.owner_epoch) {
        owner_thread_value_stack_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_apply_return(vm_context());
      if (vm_context().apply_return.thread_local_storage && vm_context().apply_return.context_bound &&
          vm_context().apply_return.owner_id == task.owner_id &&
          vm_context().apply_return.owner_epoch == task.owner_epoch) {
        owner_thread_apply_return_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      append_owner_task_trace_threadsafe(task, "thread_dispatched");
      owner_executor_runnable_task_dispatched.fetch_add(1, std::memory_order_relaxed);
      if (owner_task_executor_safe(task)) {
        owner_executor_safe_task_dispatched.fetch_add(1, std::memory_order_relaxed);
      }
      dispatch_task(task);
      total_drained.fetch_add(1, std::memory_order_relaxed);
      owner_thread_dispatched.fetch_add(1, std::memory_order_relaxed);
    }

    record_owner_context_cleanup(task);
    release_owner_task_target(&task);
  }

  void dispatch_task(OwnerMailboxTask &task) {
    switch (owner_executor_task_descriptor(task).dispatch_kind) {
      case OwnerExecutorDispatchKind::ExecutorProbe:
        maybe_delay_owner_executor_probe();
        append_owner_task_trace_threadsafe(task, "executor_probe_completed");
        owner_executor_probe_executed.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::LpcProbe:
        run_owner_lpc_probe(task);
        break;
      case OwnerExecutorDispatchKind::LpcCanary:
        run_owner_lpc_canary(task);
        break;
      case OwnerExecutorDispatchKind::LpcTask:
        run_owner_lpc_task(task);
        break;
      case OwnerExecutorDispatchKind::OrdinaryLpc:
        run_owner_ordinary_lpc(task);
        break;
      case OwnerExecutorDispatchKind::RejectLpc:
        append_owner_task_trace_threadsafe(task, "thread_lpc_rejected");
        owner_thread_lpc_rejected.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::GuardOwnerState:
        append_owner_task_trace_threadsafe(task, "thread_owner_state_guarded");
        owner_thread_owner_state_guarded.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::OwnerMessage:
        append_owner_task_trace_threadsafe(task, "thread_message_dispatched");
        owner_thread_message_dispatched.fetch_add(1, std::memory_order_relaxed);
        complete_owner_message_task(task);
        break;
      case OwnerExecutorDispatchKind::CommandConsume:
        append_owner_task_trace_threadsafe(task, "thread_command_consume_entry_ready");
        owner_executor_command_consume_entry_executed.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::CommandFrameRestore:
        run_owner_command_frame_restore(task);
        break;
      case OwnerExecutorDispatchKind::GatewayCommand:
        append_owner_task_trace_threadsafe(task, "thread_gateway_command_executor_guarded");
        owner_thread_gateway_command_guarded.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::ExecutorCallback:
        run_owner_executor_callback(task);
        break;
      case OwnerExecutorDispatchKind::ComputeResult:
        append_owner_task_trace_threadsafe(task, "thread_compute_result_completed");
        owner_thread_compute_result_completed.fetch_add(1, std::memory_order_relaxed);
        complete_owner_compute_result_task(task);
        break;
      case OwnerExecutorDispatchKind::Generic:
        break;
    }
  }
};

void owner_thread_loop() {
  OwnerExecutorRuntimeImpl runtime;
  OwnerExecutor executor(runtime);
  executor.run();
}
}  // namespace

const char *vm_owner_default_id() { return kDefaultOwnerId; }

int vm_multicore_mode() {
  auto mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  if (mode < VM_MULTICORE_MODE_OFF || mode > VM_MULTICORE_MODE_ENFORCED) {
    return VM_MULTICORE_MODE_AUDIT;
  }
  return mode;
}

const char *vm_multicore_mode_name(int mode) {
  switch (mode) {
    case VM_MULTICORE_MODE_OFF:
      return "off";
    case VM_MULTICORE_MODE_ENFORCED:
      return "enforced";
    case VM_MULTICORE_MODE_AUDIT:
    default:
      return "audit";
  }
}

bool vm_multicore_audit_enabled() { return vm_multicore_mode() != VM_MULTICORE_MODE_OFF; }

bool vm_multicore_enforced() { return vm_multicore_mode() == VM_MULTICORE_MODE_ENFORCED; }

const char *vm_owner_id(object_t *object) {
  if (!object || !valid_owner_id(object->vm_owner_id)) {
    return kDefaultOwnerId;
  }
  return object->vm_owner_id;
}

bool vm_owner_has_explicit_id(object_t *object) { return object && valid_owner_id(object->vm_owner_id); }

uint64_t vm_owner_epoch(object_t *object) { return object ? object->vm_owner_epoch : 0; }

void vm_owner_set_id(object_t *object, const char *owner_id) {
  if (!object) {
    return;
  }
  if (!valid_owner_id(owner_id)) {
    owner_id = kDefaultOwnerId;
  }
  if (object->vm_owner_id && std::strcmp(object->vm_owner_id, owner_id) == 0) {
    return;
  }
  if (object->vm_owner_id) {
    free_string(object->vm_owner_id);
  }
  object->vm_owner_id = make_shared_string(owner_id);
  object->vm_owner_epoch++;
  vm_object_store_update_owner(object);
}

void vm_owner_assign_default(object_t *object, object_t *context_object, const char *fallback_owner_id) {
  if (!object || valid_owner_id(object->vm_owner_id)) {
    return;
  }
  const char *owner_id = nullptr;
  if (valid_owner_id(fallback_owner_id)) {
    owner_id = fallback_owner_id;
  } else if (context_object && valid_owner_id(context_object->vm_owner_id)) {
    owner_id = vm_owner_id(context_object);
  } else if (!vm_context().owner.current_owner_id.empty()) {
    owner_id = vm_context().owner.current_owner_id.c_str();
  } else {
    owner_id = kDefaultOwnerId;
  }
  vm_owner_set_id(object, owner_id);
}

void vm_owner_clear_id(object_t *object) {
  if (object && object->vm_owner_id) {
    free_string(object->vm_owner_id);
    object->vm_owner_id = nullptr;
    object->vm_owner_epoch++;
    vm_object_store_update_owner(object);
  }
}

bool vm_owner_matches(object_t *object, const char *expected_owner_id) {
  if (!valid_owner_id(expected_owner_id)) {
    expected_owner_id = kDefaultOwnerId;
  }
  return std::strcmp(vm_owner_id(object), expected_owner_id) == 0;
}

bool vm_owner_epoch_matches(object_t *object, const char *expected_owner_id, uint64_t expected_epoch) {
  return vm_owner_matches(object, expected_owner_id) && vm_owner_epoch(object) == expected_epoch;
}

void vm_owner_record_check(object_t *object, const char *expected_owner_id, bool matched) {
  total_checks.fetch_add(1, std::memory_order_relaxed);
  if (!matched) {
    mismatch_checks.fetch_add(1, std::memory_order_relaxed);
  }
}

uint64_t vm_owner_total_checks() { return total_checks.load(std::memory_order_relaxed); }

uint64_t vm_owner_mismatch_checks() { return mismatch_checks.load(std::memory_order_relaxed); }

mapping_t *vm_owner_status(object_t *object) {
  auto *map = allocate_mapping(10);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "default_owner_id", kDefaultOwnerId);
  add_mapping_pair(map, "multicore_mode", vm_multicore_mode());
  add_mapping_string(map, "multicore_mode_name", vm_multicore_mode_name(vm_multicore_mode()));
  add_mapping_pair(map, "multicore_enforced", vm_multicore_enforced() ? 1 : 0);
  add_mapping_pair(map, "total_checks", static_cast<long>(vm_owner_total_checks()));
  add_mapping_pair(map, "mismatch_checks", static_cast<long>(vm_owner_mismatch_checks()));
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  add_mapping_pair(map, "has_explicit_owner", object && object->vm_owner_id ? 1 : 0);
  return map;
}

mapping_t *vm_owner_guard(object_t *object, const char *expected_owner_id) {
  const char *normalized_owner_id = normalize_owner_id(expected_owner_id);
  auto matched = vm_owner_matches(object, normalized_owner_id);
  vm_owner_record_check(object, normalized_owner_id, matched);
  if (!matched) {
    error("vm_owner_guard(): owner mismatch: object owner '%s', expected '%s'.\n", vm_owner_id(object),
          normalized_owner_id);
  }

  auto *map = allocate_mapping(5);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "expected_owner_id", normalized_owner_id);
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  return map;
}

mapping_t *vm_owner_guard_epoch(object_t *object, const char *expected_owner_id, uint64_t expected_epoch) {
  const char *normalized_owner_id = normalize_owner_id(expected_owner_id);
  auto matched = vm_owner_epoch_matches(object, normalized_owner_id, expected_epoch);
  vm_owner_record_check(object, normalized_owner_id, matched);
  if (!matched) {
    error("vm_owner_guard_epoch(): owner epoch mismatch: object owner '%s' epoch %llu, expected '%s' epoch %llu.\n",
          vm_owner_id(object), static_cast<unsigned long long>(vm_owner_epoch(object)), normalized_owner_id,
          static_cast<unsigned long long>(expected_epoch));
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "expected_owner_id", normalized_owner_id);
  add_mapping_pair(map, "expected_owner_epoch", static_cast<long>(expected_epoch));
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  return map;
}

uint64_t vm_owner_enqueue_task(const char *owner_id, const char *task_type, const char *task_key) {
  return vm_owner_enqueue_task_epoch(owner_id, task_type, task_key, 0);
}

uint64_t vm_owner_enqueue_task_epoch(const char *owner_id, const char *task_type, const char *task_key,
                                      uint64_t owner_epoch) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = owner_epoch;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = normalize_task_text(task_type, "generic");
  task.task_key = normalize_task_text(task_key, "");
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto had_thread_task = owner_queue_has_thread_task(queue);
    queue.push_back(std::move(task));
    if (!had_thread_task && active_owner_set.count(normalized_owner_id) == 0 &&
        owner_queue_has_thread_task(queue)) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

uint64_t vm_owner_enqueue_command_frame_restore(object_t *target) {
  if (!target) {
    return 0;
  }

  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = vm_owner_epoch(target);
  task.owner_id = normalize_owner_id(vm_owner_id(target));
  task.task_type = "command_frame_restore";
  task.task_key = "gateway-command-frame-restore";
  task.target_object = owner_object_name(target);
  task.target = target;
  task.has_target_handle = true;
  task.target_handle = vm_object_handle(target);
  if (!task.target_handle.object_path.empty()) {
    task.target_object = task.target_handle.object_path;
  }
  add_ref(task.target, "owner command frame restore task");
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    enqueue_owner_task_locked(std::move(task), normalized_owner_id, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

bool vm_owner_executor_available() {
  if (!vm_multicore_audit_enabled()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return !owner_threads.empty();
}

uint64_t vm_owner_enqueue_executor_task(object_t *target, const char *task_type, const char *task_key,
                                        std::function<void()> callback,
                                        std::function<void()> drop_callback) {
  if (!target || !callback || !vm_multicore_audit_enabled()) {
    return 0;
  }

  auto normalized_task_type = std::string(normalize_task_text(task_type, ""));
  const auto *descriptor = find_owner_executor_task_descriptor(normalized_task_type);
  if (!descriptor || descriptor->dispatch_kind != OwnerExecutorDispatchKind::ExecutorCallback) {
    return 0;
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (owner_threads.empty()) {
      return 0;
    }
  }

  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;
  bool queued = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = vm_owner_epoch(target);
  task.owner_id = normalize_owner_id(vm_owner_id(target));
  task.task_type = std::move(normalized_task_type);
  task.task_key = normalize_task_text(task_key, "");
  task.target_object = owner_object_name(target);
  task.target = target;
  task.has_target_handle = true;
  task.target_handle = vm_object_handle(target);
  if (!task.target_handle.object_path.empty()) {
    task.target_object = task.target_handle.object_path;
  }
  task.callback = std::move(callback);
  task.drop_callback = std::move(drop_callback);
  add_ref(task.target, "owner executor callback task");
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (!owner_threads.empty()) {
      append_owner_task_trace(task, "executor_callback_queued");
      enqueue_owner_task_locked(std::move(task), normalized_owner_id, &notify_owner_thread);
      owner_executor_callback_queued.fetch_add(1, std::memory_order_relaxed);
      queued = true;
    }
  }
  if (!queued) {
    release_owner_task_target(&task);
    return 0;
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

uint64_t vm_owner_enqueue_executor_callback_cleanup(const char *owner_id, uint64_t owner_epoch,
                                                    const char *task_type, const char *task_key,
                                                    std::function<void()> callback) {
  if (!callback) {
    return 0;
  }

  OwnerExecutorCallbackCleanup cleanup;
  cleanup.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  cleanup.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  cleanup.owner_epoch = owner_epoch;
  cleanup.owner_id = normalize_owner_id(owner_id);
  cleanup.task_type = normalize_task_text(task_type, "executor_callback_cleanup");
  cleanup.task_key = normalize_task_text(task_key, "");
  cleanup.callback = std::move(callback);
  auto task_id = cleanup.task_id;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(cleanup.task_id, cleanup.sequence, cleanup.owner_id, cleanup.owner_epoch,
                            cleanup.task_type, cleanup.task_key,
                            "executor_callback_main_cleanup_queued");
    owner_executor_callback_main_cleanups.push_back(std::move(cleanup));
    owner_executor_callback_main_cleanup_queued.fetch_add(1, std::memory_order_relaxed);
  }
  return task_id;
}

uint64_t vm_owner_enqueue_test_main_required_message(const char *owner_id, const char *task_key) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = 0;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = "owner_message";
  task.task_key = normalize_task_text(task_key, "test-main-required");
  task.has_target_handle = true;
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    enqueue_owner_task_locked(std::move(task), normalized_owner_id, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

mapping_t *vm_owner_lpc_probe(object_t *target, const char *owner_id, const char *method) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target ? vm_owner_epoch(target) : 0;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = "lpc_probe";
  task.task_key = normalize_task_text(method, "owner_lpc_probe");
  task.target_object = owner_object_name(target);
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;
  auto target_name = task.target_object;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto had_thread_task = owner_queue_has_thread_task(queue);
    queue.push_back(std::move(task));
    if (!had_thread_task && active_owner_set.count(normalized_owner_id) == 0 &&
        owner_queue_has_thread_task(queue)) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "task_type", "lpc_probe");
  add_mapping_string(map, "method", normalize_task_text(method, "owner_lpc_probe"));
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *vm_owner_lpc_canary(object_t *target, const char *owner_id, const char *method) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target ? vm_owner_epoch(target) : 0;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = "lpc_canary";
  task.task_key = normalize_task_text(method, "owner_lpc_canary");
  task.target_object = owner_object_name(target);
  task.target = target;
  if (task.target) {
    add_ref(task.target, "owner lpc canary task");
  }
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;
  auto target_name = task.target_object;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto had_thread_task = owner_queue_has_thread_task(queue);
    queue.push_back(std::move(task));
    if (!had_thread_task && active_owner_set.count(normalized_owner_id) == 0 &&
        owner_queue_has_thread_task(queue)) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(9);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "task_type", "lpc_canary");
  add_mapping_string(map, "method", normalize_task_text(method, "owner_lpc_canary"));
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(target ? vm_owner_epoch(target) : 0));
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *vm_owner_lpc_task(object_t *target, const char *owner_id, const char *method) {
  auto normalized_owner_id = std::string(normalize_owner_id(owner_id));
  auto method_name = std::string(normalize_task_text(method, ""));
  auto target_name = std::string(owner_object_name(target));
  auto target_owner_id = std::string(normalize_owner_id(target ? vm_owner_id(target) : nullptr));
  auto *descriptor = find_owner_lpc_task_descriptor(method_name);
  auto allowed = descriptor ? 1 : 0;

  if (target && normalized_owner_id != target_owner_id) {
    auto *map = allocate_mapping(27);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", 0);
    add_mapping_pair(map, "task_id", 0);
    add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
    add_mapping_string(map, "target_owner_id", target_owner_id.c_str());
    add_mapping_string(map, "task_type", "lpc_task");
    add_mapping_string(map, "method", method_name.c_str());
    add_mapping_string(map, "target_object", target_name.c_str());
    add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(target)));
    add_mapping_string(map, "executor_mode", "rejected");
    add_mapping_string(map, "route", "owner_executor");
    add_mapping_string(map, "result_policy", "none");
    add_mapping_string(map, "contract_reason", "owner lpc task target owner mismatch");
    add_mapping_string(map, "state", "rejected");
    add_mapping_string(map, "error", "owner lpc task target owner mismatch");
    add_mapping_pair(map, "requires_owner_thread", 0);
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "payload_frozen", 1);
    add_mapping_pair(map, "registered_task", 0);
    add_mapping_pair(map, "frozen_result_required", 0);
    add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
    add_mapping_pair(map, "ordinary_lpc_activation_policy_ready", 1);
    add_mapping_string(map, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
    add_mapping_string(map, "ordinary_lpc_next_blocker", "");
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    add_mapping_owned_mapping(map, "task_contract",
                              owner_task_contract_entry("rejected", "owner_executor", 0, 0, 1,
                                                        "owner lpc task target owner mismatch"));
    return map;
  }

  OwnerMailboxTask task;
  uint64_t task_id;
  auto future_id = next_message_trace_id.fetch_add(1, std::memory_order_relaxed);
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target ? vm_owner_epoch(target) : 0;
  task.owner_id = normalized_owner_id;
  task.task_type = "lpc_task";
  task.task_key = method_name;
  task.target_object = target_name;
  task.target = target;
  if (task.target) {
    add_ref(task.target, "owner lpc task");
  }
  task_id = task.task_id;

  OwnerFutureRecord future;
  future.future_id = future_id;
  future.target_task_id = task_id;
  future.source_owner_id = normalized_owner_id;
  future.target_owner_id = normalized_owner_id;
  future.message_type = "lpc_task";
  future.payload_key = method_name;
  future.state = "pending";

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_futures[future.future_id] = std::move(future);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto had_thread_task = owner_queue_has_thread_task(queue);
    queue.push_back(std::move(task));
    if (!had_thread_task && active_owner_set.count(normalized_owner_id) == 0 &&
        owner_queue_has_thread_task(queue)) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(23);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "future_id", static_cast<long>(future_id));
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "task_type", "lpc_task");
  add_mapping_string(map, "method", method_name.c_str());
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(target ? vm_owner_epoch(target) : 0));
  add_mapping_string(map, "executor_mode", descriptor ? descriptor->executor_mode : "rejected");
  add_mapping_string(map, "route", descriptor ? descriptor->route : "owner_executor");
  add_mapping_string(map, "result_policy", descriptor ? descriptor->result_policy : "none");
  add_mapping_string(map, "contract_reason", descriptor ? descriptor->reason : "ordinary LPC remains default closed");
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "requires_owner_message_completion", 1);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "registered_task", allowed);
  add_mapping_pair(map, "frozen_result_required", descriptor ? descriptor->frozen_result_required : 0);
  add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(map, "ordinary_lpc_activation_policy_ready", 1);
  add_mapping_string(map, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
  add_mapping_string(map, "ordinary_lpc_next_blocker", "");
  add_mapping_pair(map, "direct_cross_owner_write", descriptor ? descriptor->direct_cross_owner_write : 0);
  if (descriptor) {
    add_mapping_owned_mapping(map, "task_contract", owner_lpc_task_contract_entry(*descriptor));
  } else {
    add_mapping_owned_mapping(map, "task_contract",
                              owner_task_contract_entry("rejected", "owner_executor", 0, 0, 1,
                                                        "ordinary LPC remains default closed"));
  }
  return map;
}

mapping_t *vm_owner_ordinary_lpc_task(object_t *target, const char *owner_id, const char *method, int explicit_open) {
  auto normalized_owner_id = std::string(normalize_owner_id(owner_id));
  auto method_name = std::string(normalize_task_text(method, ""));
  auto target_name = std::string(owner_object_name(target));
  auto target_owner_id = std::string(normalize_owner_id(target ? vm_owner_id(target) : nullptr));
  const auto *descriptor = find_owner_executor_task_descriptor("ordinary_lpc");

  if (!explicit_open || !target || normalized_owner_id != target_owner_id) {
    auto *map = allocate_mapping(29);
    auto *contract = owner_task_contract_entry("rejected", "owner_executor", 0, 0, 1,
                                              explicit_open ? "ordinary LPC target owner mismatch"
                                                            : "ordinary LPC requires explicit open");
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", 0);
    add_mapping_pair(map, "task_id", 0);
    add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
    add_mapping_string(map, "target_owner_id", target_owner_id.c_str());
    add_mapping_string(map, "task_type", "ordinary_lpc");
    add_mapping_string(map, "method", method_name.c_str());
    add_mapping_string(map, "target_object", target_name.c_str());
    add_mapping_pair(map, "owner_epoch", static_cast<long>(target ? vm_owner_epoch(target) : 0));
    add_mapping_string(map, "executor_mode", "rejected");
    add_mapping_string(map, "route", "owner_executor");
    add_mapping_string(map, "result_policy", "none");
    add_mapping_string(map, "contract_reason", explicit_open ? "ordinary LPC target owner mismatch"
                                                              : "ordinary LPC requires explicit open");
    add_mapping_string(map, "state", "rejected");
    add_mapping_string(map, "error", explicit_open ? "ordinary LPC target owner mismatch"
                                                    : "ordinary LPC requires explicit open");
    add_mapping_pair(map, "requires_owner_thread", 0);
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "payload_frozen", 1);
    add_mapping_pair(map, "ordinary_lpc_explicit_open", explicit_open ? 1 : 0);
    add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
    add_mapping_pair(map, "ordinary_lpc_activation_policy_ready", 1);
    add_mapping_pair(map, "ordinary_lpc_dispatch_path_ready", 1);
    add_mapping_string(map, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
    add_mapping_string(map, "ordinary_lpc_next_blocker", "");
    add_mapping_pair(map, "frozen_result_required", 0);
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    add_mapping_owned_mapping(map, "task_contract", contract);
    return map;
  }

  OwnerMailboxTask task;
  uint64_t task_id;
  auto future_id = next_message_trace_id.fetch_add(1, std::memory_order_relaxed);
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = vm_owner_epoch(target);
  task.owner_id = normalized_owner_id;
  task.task_type = "ordinary_lpc";
  task.task_key = method_name;
  task.target_object = target_name;
  task.target = target;
  task.ordinary_lpc_explicit_open = true;
  add_ref(task.target, "owner ordinary lpc task");
  task_id = task.task_id;

  OwnerFutureRecord future;
  future.future_id = future_id;
  future.target_task_id = task_id;
  future.source_owner_id = normalized_owner_id;
  future.target_owner_id = normalized_owner_id;
  future.message_type = "ordinary_lpc";
  future.payload_key = method_name;
  future.state = "pending";

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_futures[future.future_id] = std::move(future);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto had_thread_task = owner_queue_has_thread_task(queue);
    queue.push_back(std::move(task));
    if (!had_thread_task && active_owner_set.count(normalized_owner_id) == 0 &&
        owner_queue_has_thread_task(queue)) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(29);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "future_id", static_cast<long>(future_id));
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", target_owner_id.c_str());
  add_mapping_string(map, "task_type", "ordinary_lpc");
  add_mapping_string(map, "method", method_name.c_str());
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(target)));
  add_mapping_string(map, "executor_mode", descriptor->executor_mode);
  add_mapping_string(map, "route", descriptor->route);
  add_mapping_string(map, "result_policy", "frozen_result_required");
  add_mapping_string(map, "contract_reason", descriptor->reason);
  add_mapping_string(map, "state", "pending");
  add_mapping_string(map, "error", "");
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "requires_owner_message_completion", 1);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "ordinary_lpc_explicit_open", 1);
  add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(map, "ordinary_lpc_activation_policy_ready", 1);
  add_mapping_pair(map, "ordinary_lpc_dispatch_path_ready", 1);
  add_mapping_string(map, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
  add_mapping_string(map, "ordinary_lpc_next_blocker", "");
  add_mapping_pair(map, "frozen_result_required", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_owned_mapping(map, "task_contract", owner_ordinary_lpc_contract_entry(*descriptor));
  return map;
}

uint64_t vm_owner_record_task_trace(const char *owner_id, const char *task_type, const char *task_key,
                                     uint64_t owner_epoch, const char *state) {
  auto sequence = total_traced.load(std::memory_order_relaxed) + 1;
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return append_owner_task_trace(0, sequence, normalize_owner_id(owner_id), owner_epoch,
                                  normalize_task_text(task_type, "generic"), normalize_task_text(task_key, ""), state);
}

uint64_t enqueue_owner_main_task(object_t *target, const char *task_type, const char *task_key,
                                 std::function<void()> callback, std::function<void()> drop_callback,
                                 const char *payload_key, std::shared_ptr<VMFrozenValue> payload,
                                 bool capture_target_handle, const char *command_consume_model,
                                 const char *command_consume_blocker, const char *execution_frame_model,
                                 const char *execution_frame_policy,
                                 bool execution_frame_requires_current_interactive,
                                 bool execution_frame_requires_command_giver,
                                 const char *execution_frame_restore_policy,
                                 const char *execution_frame_restore_blocker,
                                 const char *command_text_snapshot,
                                 size_t command_text_snapshot_length) {
  if (!target || !callback) {
    return 0;
  }

  OwnerMainTask task;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_id = normalize_owner_id(vm_owner_id(target));
  task.owner_epoch = vm_owner_epoch(target);
  task.task_type = normalize_task_text(task_type, "main");
  task.task_key = normalize_task_text(task_key, "");
  task.target_object = owner_object_name(target);
  task.payload_key = normalize_task_text(payload_key, "");
  task.command_text_snapshot_ready = command_text_snapshot != nullptr;
  if (command_text_snapshot != nullptr) {
    task.command_text_snapshot.assign(command_text_snapshot, command_text_snapshot_length);
  }
  task.command_consume_model = normalize_task_text(command_consume_model, "");
  task.command_consume_blocker = normalize_task_text(command_consume_blocker, "");
  task.command_consume_snapshot_ready = task.command_text_snapshot_ready;
  task.command_consume_executor_ready = !task.command_consume_model.empty() && task.command_consume_snapshot_ready &&
                                        task.command_consume_blocker.empty();
  task.execution_frame_model = normalize_task_text(execution_frame_model, "");
  task.execution_frame_policy = normalize_task_text(execution_frame_policy, "");
  task.execution_frame_restore_policy = normalize_task_text(execution_frame_restore_policy, "");
  task.execution_frame_restore_blocker = normalize_task_text(execution_frame_restore_blocker, "");
  task.execution_frame_requires_current_interactive = execution_frame_requires_current_interactive;
  task.execution_frame_requires_command_giver = execution_frame_requires_command_giver;
  task.execution_frame_restore_ready = !task.execution_frame_restore_policy.empty() &&
                                       task.execution_frame_restore_blocker.empty();
  task.execution_frame_executor_ready = task.execution_frame_restore_ready;
  task.payload = std::move(payload);
  if (capture_target_handle) {
    task.has_target_handle = true;
    task.target_handle = vm_object_handle(target);
    if (!task.target_handle.object_path.empty()) {
      task.target_object = task.target_handle.object_path;
    }
  }
  task.target = target;
  task.callback = std::move(callback);
  task.drop_callback = std::move(drop_callback);
  add_ref(target, "owner main task");

  auto task_id = task.task_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "main_queued");
    auto &queue = owner_main_queues[task.owner_id];
    auto was_empty = queue.empty();
    queue.push_back(std::move(task));
    if (was_empty && active_main_owner_set.count(queue.back().owner_id) == 0) {
      mark_main_owner_schedulable(queue.back().owner_id);
    }
  }
  owner_main_queued.fetch_add(1, std::memory_order_relaxed);
  return task_id;
}

uint64_t vm_owner_enqueue_main_task(object_t *target, const char *task_type, const char *task_key,
                                    std::function<void()> callback, std::function<void()> drop_callback) {
  return enqueue_owner_main_task(target, task_type, task_key, std::move(callback), std::move(drop_callback),
                                 nullptr, nullptr, false, nullptr, nullptr, nullptr, nullptr, false, false, nullptr,
                                 nullptr, nullptr, 0);
}

uint64_t vm_owner_enqueue_main_task_with_payload(object_t *target, const char *task_type,
                                                 const char *task_key, const char *payload_key,
                                                 svalue_t *payload, std::function<void()> callback,
                                                 std::function<void()> drop_callback,
                                                 const char *execution_frame_model,
                                                 const char *execution_frame_policy,
                                                 const char *command_consume_model,
                                                 const char *command_consume_blocker,
                                                 bool execution_frame_requires_current_interactive,
                                                 bool execution_frame_requires_command_giver,
                                                 const char *execution_frame_restore_policy,
                                                 const char *execution_frame_restore_blocker,
                                                 const char *command_text_snapshot,
                                                 size_t command_text_snapshot_length) {
  auto frozen_payload = payload ? vm_clone_frozen_value(payload) : nullptr;
  if (payload && !frozen_payload) {
    return 0;
  }
  return enqueue_owner_main_task(target, task_type, task_key, std::move(callback), std::move(drop_callback),
                                 payload_key, std::move(frozen_payload), true, command_consume_model,
                                 command_consume_blocker, execution_frame_model, execution_frame_policy,
                                 execution_frame_requires_current_interactive, execution_frame_requires_command_giver,
                                 execution_frame_restore_policy, execution_frame_restore_blocker, command_text_snapshot,
                                 command_text_snapshot_length);
}

uint64_t enqueue_owner_message_main_task_locked(const OwnerMailboxTask &mailbox_task, object_t *target) {
  OwnerMainTask task;
  task.task_id = mailbox_task.task_id;
  task.sequence = mailbox_task.sequence;
  task.owner_id = mailbox_task.owner_id;
  task.owner_epoch = mailbox_task.owner_epoch;
  task.task_type = "owner_message";
  task.task_key = mailbox_task.task_key;
  task.target_object = mailbox_task.target_object;
  task.has_target_handle = mailbox_task.has_target_handle;
  task.target_handle = mailbox_task.target_handle;
  task.payload = mailbox_task.payload;
  task.target = target;
  add_ref(target, "owner message main task");

  auto task_id = task.task_id;
  append_owner_task_trace(task, "main_queued");
  auto &queue = owner_main_queues[task.owner_id];
  auto was_empty = queue.empty();
  queue.push_back(std::move(task));
  if (was_empty && active_main_owner_set.count(queue.back().owner_id) == 0) {
    mark_main_owner_schedulable(queue.back().owner_id);
  }
  owner_main_queued.fetch_add(1, std::memory_order_relaxed);
  return task_id;
}

int vm_owner_drain_main_tasks(int limit) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (owner_main_draining) {
      return 0;
    }
    owner_main_draining = true;
  }

  auto budget = limit <= 0 ? kOwnerExecutorTaskBudget : limit;
  int dispatched = drain_owner_executor_callback_cleanups(budget);
  while (dispatched < budget) {
    OwnerMainTask task;
    {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      if (!pop_next_main_task(&task, true)) {
        break;
      }
    }

    auto *target = task.target;
    bool stale = !target || (target->flags & O_DESTRUCTED) || task.owner_id != vm_owner_id(target) ||
                 task.owner_epoch != vm_owner_epoch(target);
    if (stale) {
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        append_owner_task_trace(task, target && (target->flags & O_DESTRUCTED) ? "main_destructed" : "main_stale");
        if (target && (target->flags & O_DESTRUCTED)) {
          owner_main_destructed.fetch_add(1, std::memory_order_relaxed);
        } else {
          owner_main_stale.fetch_add(1, std::memory_order_relaxed);
        }
      }
      if (task.task_type == "owner_message" && task.has_target_handle) {
        auto target_status = vm_object_handle_resolve_status(task.target_handle);
        auto error = stale_target_error(target_status.status);
        complete_owner_main_message_task_threadsafe(task, "failed", "", error.c_str());
      } else if (task.drop_callback) {
        task.drop_callback();
      }
    } else {
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        append_owner_task_trace(task, "main_dispatched");
      }
      VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
      if (task.task_type == "owner_message" && task.has_target_handle) {
        dispatch_owner_main_message(task);
      } else {
        task.callback();
      }
      owner_main_dispatched.fetch_add(1, std::memory_order_relaxed);
    }

    dispatched++;
    finish_active_main_owner_task(task.owner_id);
    release_owner_main_task_target(&task);
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (dispatched >= budget && owner_main_queue_total_depth() > 0) {
      owner_main_budget_yields.fetch_add(1, std::memory_order_relaxed);
    }
    owner_main_draining = false;
  }
  return dispatched;
}

uint64_t vm_owner_record_access(object_t *source, object_t *target, const char *operation) {
  if (!vm_multicore_audit_enabled()) {
    return 0;
  }
  OwnerAccessTrace trace;
  uint64_t access_id;
  trace.access_id = next_access_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_access_traced.fetch_add(1, std::memory_order_relaxed) + 1;
  trace.source_owner_epoch = effective_source_owner_epoch(source, target);
  trace.target_owner_epoch = vm_owner_epoch(target);
  trace.source_owner_id = effective_source_owner_id(source, target);
  trace.target_owner_id = vm_owner_id(target);
  trace.source_object = owner_object_name(source);
  trace.target_object = owner_object_name(target);
  trace.operation = normalize_task_text(operation, "access");
  trace.cross_owner = trace.source_owner_id != trace.target_owner_id;
  if (trace.cross_owner) {
    total_cross_owner_accesses.fetch_add(1, std::memory_order_relaxed);
    record_owner_access_policy_counter(owner_access_policy_mode(trace.operation.c_str(), trace.cross_owner));
  }
  access_id = trace.access_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_access_traces.push_back(std::move(trace));
    while (owner_access_traces.size() > kOwnerAccessTraceLimit) {
      owner_access_traces.pop_front();
    }
  }
  return access_id;
}

uint64_t vm_owner_record_cross_owner_access(object_t *source, object_t *target, const char *operation) {
  if (!source || !target || std::strcmp(effective_source_owner_id(source, target), vm_owner_id(target)) == 0) {
    return 0;
  }
  return vm_owner_record_access(source, target, operation);
}

bool vm_owner_cross_owner_access_blocked(object_t *source, object_t *target, const char *operation) {
  if (!source || !target || !vm_multicore_enforced()) {
    return false;
  }
  auto source_owner = effective_source_owner_id(source, target);
  auto target_owner = vm_owner_id(target);
  if (std::strcmp(source_owner, target_owner) == 0 || owner_id_is_default(source_owner) ||
      owner_id_is_default(target_owner)) {
    return false;
  }
  auto policy_mode = owner_access_policy_mode(normalize_task_text(operation, "access"), true);
  if (owner_policy_allows_direct_access(policy_mode)) {
    return false;
  }
  total_cross_owner_enforced_blocks.fetch_add(1, std::memory_order_relaxed);
  return true;
}

mapping_t *vm_owner_drain_mailbox(const char *owner_id, int limit) {
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  std::vector<OwnerMailboxTask> drained_tasks;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto requested = limit <= 0 || static_cast<size_t>(limit) > queue.size() ? queue.size() : static_cast<size_t>(limit);

    drained_tasks.reserve(requested);
    for (size_t i = 0; i < requested; i++) {
      auto task = queue.front();
      queue.pop_front();
      append_owner_task_trace(task, "drained");
      record_owner_mailbox_task_drained(task);
      drained_tasks.push_back(std::move(task));
    }
    if (queue.empty()) {
      owner_mailboxes.erase(normalized_owner_id);
      schedulable_owner_set.erase(normalized_owner_id);
    }
    total_drained.fetch_add(drained_tasks.size(), std::memory_order_relaxed);
  }

  auto requested = drained_tasks.size();
  auto *tasks = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto &task = drained_tasks[i];
    if (task.task_type == "owner_message") {
      dispatch_owner_message_on_main(task);
    } else if (task.task_type == "compute_result") {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      complete_owner_compute_result_task_locked(task);
    } else if (task.task_type == "lpc_task") {
      complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "owner lpc task requires owner thread");
    } else if (task.task_type == "ordinary_lpc") {
      complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "ordinary lpc task requires owner thread");
    } else if (owner_executor_task_descriptor(task).dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
      owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
      schedule_owner_executor_callback_cleanup_on_main(task);
    }
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[i].type = T_MAPPING;
    tasks->item[i].subtype = 0;
    tasks->item[i].u.map = task_map;
    release_owner_task_target(&task);
  }

  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_pair(map, "drained", static_cast<long>(requested));
  add_mapping_pair(map, "remaining", owner_mailbox_depth(normalized_owner_id));
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_array(map, "tasks", tasks);
  free_array(tasks);
  return map;
}

mapping_t *vm_owner_purge_mailbox(const char *owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  auto purged = owner_mailbox_depth(normalized_owner_id);
  auto it = owner_mailboxes.find(normalized_owner_id);
  if (it != owner_mailboxes.end()) {
    for (const auto &task : it->second) {
      append_owner_task_trace(task, "purged");
    }
    for (auto &task : it->second) {
      if (task.task_type == "owner_message" || task.task_type == "compute_result") {
        auto target_task_id = task.future_target_task_id == 0 ? task.task_id : task.future_target_task_id;
        complete_owner_future_for_task_locked(target_task_id, "failed", "", "purged");
      } else if (task.task_type == "lpc_task" || task.task_type == "ordinary_lpc") {
        complete_owner_future_for_task_locked(task.task_id, "failed", "", "purged");
      } else if (owner_executor_task_descriptor(task).dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
        owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
        enqueue_owner_executor_callback_cleanup_locked(task);
      }
      record_owner_mailbox_task_drained(task);
      release_owner_task_target(&task);
    }
  }
  owner_mailboxes.erase(normalized_owner_id);
  schedulable_owner_set.erase(normalized_owner_id);
  total_drained.fetch_add(purged, std::memory_order_relaxed);

  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_pair(map, "purged", purged);
  add_mapping_pair(map, "remaining", owner_mailbox_depth(normalized_owner_id));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_schedule(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto requested = limit <= 0 ? static_cast<size_t>(owner_mailbox_total_depth()) : static_cast<size_t>(limit);
  auto *tasks = allocate_array(static_cast<int>(requested));
  size_t dispatched = 0;

  while (dispatched < requested) {
    OwnerMailboxTask task;
    if (!pop_next_schedulable_task(&task, false)) {
      break;
    }
    append_owner_task_trace(task, "dispatched");
    if (task.task_type == "owner_message") {
      complete_owner_message_task_locked(task);
    } else if (task.task_type == "compute_result") {
      complete_owner_compute_result_task_locked(task);
    } else if (task.task_type == "lpc_task") {
      complete_owner_future_for_task_locked(task.task_id, "failed", "", "owner lpc task requires owner thread");
    } else if (task.task_type == "ordinary_lpc") {
      complete_owner_future_for_task_locked(task.task_id, "failed", "", "ordinary lpc task requires owner thread");
    } else if (owner_executor_task_descriptor(task).dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
      owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
      enqueue_owner_executor_callback_cleanup_locked(task);
    }
    record_owner_mailbox_task_drained(task);
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[dispatched].type = T_MAPPING;
    tasks->item[dispatched].subtype = 0;
    tasks->item[dispatched].u.map = task_map;
    release_owner_task_target(&task);
    dispatched++;
  }

  tasks->size = static_cast<int>(dispatched);
  total_drained.fetch_add(dispatched, std::memory_order_relaxed);

  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "dispatched", static_cast<long>(dispatched));
  add_mapping_pair(map, "remaining", owner_mailbox_total_depth());
  add_mapping_pair(map, "active_owners", owner_mailbox_active_owners());
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_array(map, "tasks", tasks);
  free_array(tasks);
  return map;
}

mapping_t *vm_owner_mailbox_status(const char *owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  auto *map = allocate_mapping(17);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_pair(map, "owner_queue_depth", owner_mailbox_depth(normalized_owner_id));
  add_mapping_pair(map, "owner_executor_runnable_queue_depth",
                   owner_executor_runnable_queue_depth(normalized_owner_id));
  add_mapping_pair(map, "owner_executor_safe_queue_depth", owner_executor_safe_queue_depth(normalized_owner_id));
  add_mapping_pair(map, "owner_main_required_queue_depth", owner_main_required_queue_depth(normalized_owner_id));
  add_mapping_pair(map, "owner_main_queue_depth", owner_main_queue_depth(normalized_owner_id));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "executor_runnable_queue_depth", owner_executor_runnable_queue_depth());
  add_mapping_pair(map, "executor_safe_queue_depth", owner_executor_safe_queue_depth());
  add_mapping_pair(map, "main_required_queue_depth", owner_main_required_queue_depth());
  add_mapping_pair(map, "main_queue_depth", owner_main_queue_total_depth());
  add_mapping_pair(map, "active_owners", owner_mailbox_active_owners());
  add_mapping_pair(map, "main_active_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_task_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_task_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_task_trace_mapping(owner_task_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_task_trace");
  add_mapping_string(map, "trace_model", "owner_task_lifecycle_trace");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_executor_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_executor_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_executor_trace_mapping(owner_executor_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_executor_trace");
  add_mapping_string(map, "trace_model", "owner_executor_scheduler_trace");
  add_mapping_string(map, "executor_contract_version", "owner_executor_v1");
  add_mapping_string(map, "executor_model", "owner_executor");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_executor_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_access_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_access_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_access_trace_mapping(owner_access_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(14);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_access_trace");
  add_mapping_string(map, "trace_model", "cross_owner_access_policy_trace");
  add_mapping_pair(map, "multicore_mode", vm_multicore_mode());
  add_mapping_string(map, "multicore_mode_name", vm_multicore_mode_name(vm_multicore_mode()));
  add_mapping_pair(map, "enforced_blocks",
                   static_cast<long>(total_cross_owner_enforced_blocks.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_access_traced.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "cross_owner", static_cast<long>(total_cross_owner_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "snapshot_required",
                   static_cast<long>(total_cross_owner_snapshot_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "message_required",
                   static_cast<long>(total_cross_owner_message_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "rejected_by_default",
                   static_cast<long>(total_cross_owner_rejected_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *submit_owner_message(const char *source_owner_id, const char *target_owner_id, const char *message_type,
                                const char *payload_key, const VMObjectHandle *target_handle, svalue_t *payload) {
  std::string source_owner = normalize_owner_id(source_owner_id);
  std::string target_owner = target_handle && !target_handle->owner_id.empty() ? target_handle->owner_id
                                                                              : normalize_owner_id(target_owner_id);
  std::string normalized_type = normalize_task_text(message_type, "message");
  std::string normalized_payload = normalize_task_text(payload_key, "");
  auto frozen_payload = payload ? vm_clone_frozen_value(payload) : nullptr;
  if (payload && !frozen_payload) {
    auto *map = allocate_mapping(4);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "frozen_payload", 0);
    add_mapping_string(map, "state", "rejected");
    add_mapping_string(map, "error", "owner payload must be frozen data");
    return map;
  }
  auto message_id = next_message_trace_id.fetch_add(1, std::memory_order_relaxed);

  OwnerMailboxTask task;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target_handle ? target_handle->owner_epoch : 0;
  task.owner_id = target_owner;
  task.task_type = "owner_message";
  task.task_key = normalized_type;
  task.has_target_handle = target_handle != nullptr;
  task.payload = std::move(frozen_payload);
  if (target_handle) {
    task.target_handle = *target_handle;
    task.target_object = target_handle->object_path;
  }
  auto target_task_id = task.task_id;
  auto target_status = target_handle ? vm_object_handle_resolve_status(*target_handle).status
                                     : VMObjectHandleResolveStatus::kCurrent;

  OwnerMessageTrace trace;
  trace.message_id = message_id;
  trace.sequence = total_message_traced.fetch_add(1, std::memory_order_relaxed) + 1;
  trace.target_task_id = target_task_id;
  trace.source_owner_id = source_owner;
  trace.target_owner_id = target_owner;
  trace.message_type = normalized_type;
  trace.payload_key = normalized_payload;
  trace.state = "message_submitted";
  trace.route = target_handle ? "owner_main_queue" : "owner_mailbox";
  trace.target_handle_status = vm_object_handle_resolve_status_name(target_status);
  trace.has_target_handle = target_handle != nullptr;
  trace.requires_owner_mailbox = target_handle == nullptr;
  trace.requires_owner_main_queue = target_handle != nullptr;

  OwnerFutureRecord future;
  future.future_id = message_id;
  future.target_task_id = target_task_id;
  future.has_target_handle = target_handle != nullptr;
  if (target_handle) {
    future.target_handle = *target_handle;
  }
  future.source_owner_id = source_owner;
  future.target_owner_id = target_owner;
  future.message_type = normalized_type;
  future.payload_key = normalized_payload;
  future.state = "pending";

  bool notify_owner_thread = false;
  bool enqueued_main_task = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    vm_object_store_record_message(target_owner.c_str(), target_task_id);
    owner_futures[future.future_id] = std::move(future);
    owner_message_traces.push_back(std::move(trace));
    while (owner_message_traces.size() > kOwnerMessageTraceLimit) {
      owner_message_traces.pop_front();
    }
    if (target_handle) {
      auto resolved_target = vm_object_handle_resolve_status(*target_handle);
      if (resolved_target.status == VMObjectHandleResolveStatus::kCurrent && resolved_target.object) {
        enqueue_owner_message_main_task_locked(task, resolved_target.object);
        for (auto &message_trace : owner_message_traces) {
          if (message_trace.target_task_id == target_task_id) {
            message_trace.queued_on_main = true;
            message_trace.target_handle_status = vm_object_handle_resolve_status_name(resolved_target.status);
            break;
          }
        }
        enqueued_main_task = true;
      } else {
        for (auto &message_trace : owner_message_traces) {
          if (message_trace.target_task_id == target_task_id) {
            message_trace.target_handle_status = vm_object_handle_resolve_status_name(resolved_target.status);
            message_trace.requires_owner_mailbox = false;
            message_trace.requires_owner_main_queue = false;
            message_trace.queued_on_main = false;
            break;
          }
        }
        vm_object_store_remove_message(target_owner.c_str(), target_task_id);
        auto error = stale_target_error(resolved_target.status);
        complete_owner_future_for_task_locked(target_task_id, "failed", "", error.c_str());
      }
    } else {
      enqueue_owner_task_locked(std::move(task), target_owner, &notify_owner_thread);
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(20);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "message_id", static_cast<long>(message_id));
  add_mapping_pair(map, "future_id", static_cast<long>(message_id));
  add_mapping_pair(map, "target_task_id", static_cast<long>(target_task_id));
  add_mapping_string(map, "source_owner_id", source_owner.c_str());
  add_mapping_string(map, "target_owner_id", target_owner.c_str());
  add_mapping_string(map, "message_type", normalized_type.c_str());
  add_mapping_string(map, "payload_key", normalized_payload.c_str());
  add_mapping_pair(map, "requires_owner_mailbox", target_handle ? 0 : 1);
  add_mapping_pair(map, "requires_owner_main_queue", enqueued_main_task ? 1 : 0);
  add_mapping_pair(map, "main_required", target_handle ? 1 : 0);
  add_mapping_pair(map, "queued_on_main", enqueued_main_task ? 1 : 0);
  add_mapping_pair(map, "message_only_cross_owner", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "has_target_handle", target_handle ? 1 : 0);
  add_mapping_pair(map, "target_handle_current",
                   target_status == VMObjectHandleResolveStatus::kCurrent ? 1 : 0);
  add_mapping_string(map, "target_handle_status", vm_object_handle_resolve_status_name(target_status));
  add_mapping_pair(map, "target_object_id", target_handle ? static_cast<long>(target_handle->object_id) : 0);
  add_mapping_string(map, "target_object_path", target_handle ? target_handle->object_path.c_str() : "");
  add_mapping_pair(map, "target_owner_epoch", target_handle ? static_cast<long>(target_handle->owner_epoch) : 0);
  return map;
}

mapping_t *vm_owner_submit_message(const char *source_owner_id, const char *target_owner_id, const char *message_type,
                                    const char *payload_key) {
  return submit_owner_message(source_owner_id, target_owner_id, message_type, payload_key, nullptr, nullptr);
}

mapping_t *vm_owner_submit_object_message(const char *source_owner_id, const VMObjectHandle &target_handle,
                                          const char *message_type, const char *payload_key, svalue_t *payload) {
  return submit_owner_message(source_owner_id, target_handle.owner_id.c_str(), message_type, payload_key, &target_handle,
                              payload);
}

uint64_t vm_owner_register_compute_future(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                          const char *payload_key) {
  std::string normalized_owner = normalize_owner_id(owner_id);
  std::string normalized_type = normalize_task_text(task_type, "compute_result");
  std::string normalized_payload = normalize_task_text(payload_key, "");
  auto future_id = next_message_trace_id.fetch_add(1, std::memory_order_relaxed);

  OwnerFutureRecord future;
  future.future_id = future_id;
  future.target_task_id = worker_task_id;
  future.source_owner_id = normalized_owner;
  future.target_owner_id = normalized_owner;
  future.message_type = normalized_type;
  future.payload_key = normalized_payload;
  future.state = "pending";

  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  owner_futures[future.future_id] = std::move(future);
  return future_id;
}

uint64_t vm_owner_enqueue_compute_result(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                         const char *state, const char *result_key, const char *error) {
  return vm_owner_enqueue_compute_result_fields(owner_id, worker_task_id, task_type, state, result_key, error, nullptr,
                                                0);
}

uint64_t vm_owner_enqueue_compute_result_fields(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                                const char *state, const char *result_key, const char *error,
                                                const VMOwnerComputeResultField *fields, size_t field_count) {
  std::string normalized_owner = normalize_owner_id(owner_id);
  OwnerMailboxTask task;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.future_target_task_id = worker_task_id;
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_id = normalized_owner;
  task.task_type = "compute_result";
  task.task_key = normalize_task_text(result_key, task_type);
  task.future_state = normalize_task_text(state, "completed");
  task.future_error = normalize_task_text(error, "");
  task.compute_result_fields.reserve(field_count);
  for (size_t i = 0; fields && i < field_count; i++) {
    if (!fields[i].key || fields[i].key[0] == '\0') {
      continue;
    }
    OwnerComputeResultField field;
    field.key = fields[i].key;
    field.is_string = fields[i].is_string;
    if (field.is_string) {
      field.string_value = fields[i].string_value ? fields[i].string_value : "";
    } else {
      field.number_value = fields[i].number_value;
    }
    task.compute_result_fields.push_back(std::move(field));
  }

  bool notify_owner_thread = false;
  auto task_id = task.task_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    enqueue_owner_task_locked(std::move(task), normalized_owner, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

mapping_t *vm_owner_message_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_message_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_message_trace_mapping(owner_message_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_message_trace");
  add_mapping_string(map, "trace_model", "owner_message_lifecycle_trace");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_message_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_future_poll(uint64_t future_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto it = owner_futures.find(future_id);
  if (it == owner_futures.end()) {
    auto *map = allocate_mapping(6);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", static_cast<long>(future_id));
    add_mapping_string(map, "state", "unknown");
    add_mapping_string(map, "error", "unknown future");
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    return map;
  }
  return owner_future_mapping(it->second);
}

mapping_t *vm_owner_record_commit_boundary(const char *source_owner_id, const char *target_owner_id,
                                           const char *operation, uint64_t message_id, const char *state) {
  OwnerCommitTrace trace;
  trace.commit_id = next_commit_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_commit_traced.fetch_add(1, std::memory_order_relaxed) + 1;
  trace.message_id = message_id;
  trace.direct_write = false;
  trace.source_owner_id = normalize_owner_id(source_owner_id);
  trace.target_owner_id = normalize_owner_id(target_owner_id);
  trace.operation = normalize_task_text(operation, "commit");
  trace.state = normalize_task_text(state, "commit_guarded");
  auto result = trace;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_commit_traces.push_back(std::move(trace));
    while (owner_commit_traces.size() > kOwnerCommitTraceLimit) {
      owner_commit_traces.pop_front();
    }
  }
  auto *map = allocate_mapping(9);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "commit_id", static_cast<long>(result.commit_id));
  add_mapping_pair(map, "message_id", static_cast<long>(result.message_id));
  add_mapping_pair(map, "direct_write", 0);
  add_mapping_string(map, "source_owner_id", result.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", result.target_owner_id.c_str());
  add_mapping_string(map, "operation", result.operation.c_str());
  add_mapping_string(map, "state", result.state.c_str());
  add_mapping_pair(map, "commit_boundary_only", 1);
  return map;
}

mapping_t *vm_owner_commit_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_commit_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_commit_trace_mapping(owner_commit_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_commit_trace");
  add_mapping_string(map, "trace_model", "owner_commit_boundary_trace");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_commit_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

void vm_owner_thread_start(int requested_threads) {
  auto thread_count = requested_threads <= 0 ? 1 : requested_threads;
  if (thread_count > 4) {
    thread_count = 4;
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (!owner_threads.empty()) {
      return;
    }
    owner_thread_stopping = false;
    owner_threads.reserve(static_cast<size_t>(thread_count));
    for (int i = 0; i < thread_count; i++) {
      owner_threads.emplace_back(owner_thread_loop);
    }
    owner_thread_starts.fetch_add(1, std::memory_order_relaxed);
  }
  owner_runtime_cv.notify_all();
}

void vm_owner_thread_stop() {
  std::vector<std::thread> threads;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (owner_threads.empty()) {
      owner_thread_stopping = false;
      return;
    }
    owner_thread_stopping = true;
    threads.swap(owner_threads);
  }
  owner_runtime_cv.notify_all();
  for (auto &thread : threads) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  release_deferred_owner_targets_on_main();
  drain_owner_executor_callback_cleanups(0);
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_thread_stopping = false;
    owner_thread_stops.fetch_add(1, std::memory_order_relaxed);
  }
}

mapping_t *vm_owner_thread_status() {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto *map = allocate_mapping(109);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "enabled", owner_threads.empty() ? 0 : 1);
  add_mapping_pair(map, "thread_count", static_cast<long>(owner_threads.size()));
  add_mapping_pair(map, "stopping", owner_thread_stopping ? 1 : 0);
  add_mapping_pair(map, "thread_dispatched", static_cast<long>(owner_thread_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_context_bound",
                   static_cast<long>(owner_thread_context_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_object_store_isolated",
                   static_cast<long>(owner_thread_object_store_isolated.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_owner_bound",
                   static_cast<long>(owner_thread_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_owner_cleared",
                   static_cast<long>(owner_thread_owner_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_execution_cleared",
                   static_cast<long>(owner_thread_execution_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_eval_stack_owner_bound",
                   static_cast<long>(owner_thread_eval_stack_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_eval_stack_cleared",
                   static_cast<long>(owner_thread_eval_stack_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_eval_stack_leak_detected",
                   static_cast<long>(owner_thread_eval_stack_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_control_stack_owner_bound",
                   static_cast<long>(owner_thread_control_stack_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_control_stack_cleared",
                   static_cast<long>(owner_thread_control_stack_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_control_stack_leak_detected",
                   static_cast<long>(owner_thread_control_stack_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_value_stack_owner_bound",
                   static_cast<long>(owner_thread_value_stack_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_value_stack_cleared",
                   static_cast<long>(owner_thread_value_stack_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_value_stack_leak_detected",
                   static_cast<long>(owner_thread_value_stack_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_apply_return_owner_bound",
                   static_cast<long>(owner_thread_apply_return_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_apply_return_cleared",
                   static_cast<long>(owner_thread_apply_return_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_apply_return_leak_detected",
                   static_cast<long>(owner_thread_apply_return_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_flag_cleared",
                   static_cast<long>(owner_thread_lpc_canary_flag_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_context_leak_detected",
                   static_cast<long>(owner_thread_context_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_rejected",
                   static_cast<long>(owner_thread_lpc_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_owner_state_guarded",
                   static_cast<long>(owner_thread_owner_state_guarded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_message_dispatched",
                   static_cast<long>(owner_thread_message_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_command_consume_entry_executed",
                   static_cast<long>(owner_executor_command_consume_entry_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_command_frame_restore_entry_executed",
                   static_cast<long>(owner_executor_command_frame_restore_entry_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_gateway_command_guarded",
                   static_cast<long>(owner_thread_gateway_command_guarded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_gateway_command_rejected",
                   static_cast<long>(owner_thread_gateway_command_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_probe_executed",
                   static_cast<long>(owner_thread_lpc_probe_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_probe_failed",
                   static_cast<long>(owner_thread_lpc_probe_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_probe_guarded",
                   static_cast<long>(owner_thread_lpc_probe_guarded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_executed",
                   static_cast<long>(owner_thread_lpc_canary_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_succeeded",
                   static_cast<long>(owner_thread_lpc_canary_succeeded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_failed",
                   static_cast<long>(owner_thread_lpc_canary_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_rejected",
                   static_cast<long>(owner_thread_lpc_canary_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_executed",
                   static_cast<long>(owner_thread_lpc_task_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_succeeded",
                   static_cast<long>(owner_thread_lpc_task_succeeded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_failed",
                   static_cast<long>(owner_thread_lpc_task_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_rejected",
                   static_cast<long>(owner_thread_lpc_task_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_executed",
                   static_cast<long>(owner_thread_ordinary_lpc_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_succeeded",
                   static_cast<long>(owner_thread_ordinary_lpc_succeeded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_failed",
                   static_cast<long>(owner_thread_ordinary_lpc_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_rejected",
                   static_cast<long>(owner_thread_ordinary_lpc_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_compute_result_completed",
                   static_cast<long>(owner_thread_compute_result_completed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_task_boundary_ready", 1);
  add_mapping_pair(map, "executor_callback_allowlist_ready", 1);
  add_mapping_pair(map, "executor_callback_allowlist_count", 6);
  add_mapping_string(map, "executor_callback_payload_policy", "frozen_payload_or_owner_handle_only");
  add_mapping_pair(map, "heartbeat_owner_executor_ready", 1);
  add_mapping_string(map, "heartbeat_owner_executor_task_type", "heartbeat");
  add_mapping_string(map, "heartbeat_owner_executor_route", "owner_executor");
  add_mapping_string(map, "heartbeat_owner_executor_fallback_route", "owner_main_queue");
  add_mapping_string(map, "heartbeat_owner_executor_policy", "audit_enforced_owner_thread_else_main");
  add_mapping_pair(map, "heartbeat_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "heartbeat_current_object_thread_local", 1);
  add_mapping_pair(map, "callout_owner_executor_ready", 1);
  add_mapping_string(map, "callout_owner_executor_task_type", "call_out");
  add_mapping_string(map, "callout_owner_executor_route", "owner_executor");
  add_mapping_string(map, "callout_owner_executor_fallback_route", "owner_main_queue");
  add_mapping_string(map, "callout_owner_executor_policy", "audit_enforced_owner_thread_else_main");
  add_mapping_pair(map, "callout_owner_executor_expired_handle_detach_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "executor_callback_queued",
                   static_cast<long>(owner_executor_callback_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_dispatched",
                   static_cast<long>(owner_executor_callback_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_dropped",
                   static_cast<long>(owner_executor_callback_dropped.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_main_cleanup_backlog",
                   static_cast<long>(owner_executor_callback_main_cleanups.size()));
  add_mapping_pair(map, "executor_callback_main_cleanup_queued",
                   static_cast<long>(owner_executor_callback_main_cleanup_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_main_cleanup_dispatched",
                   static_cast<long>(owner_executor_callback_main_cleanup_dispatched.load(std::memory_order_relaxed)));
  auto *callback_contracts = owner_executor_callback_contracts_array();
  add_mapping_array(map, "executor_callback_task_contracts", callback_contracts);
  free_array(callback_contracts);
  add_mapping_pair(map, "active_owners", static_cast<long>(active_owner_set.size()));
  add_mapping_pair(map, "claimed_owners", static_cast<long>(active_owner_set.size()));
  add_mapping_pair(map, "claimed_main_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "max_owner_threads", 4);
  add_mapping_pair(map, "executor_task_budget", kOwnerExecutorTaskBudget);
  add_mapping_pair(map, "executor_budget_yields",
                   static_cast<long>(owner_executor_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_string(map, "executor_last_budget_yield_owner", owner_executor_last_budget_yield_owner.c_str());
  add_mapping_pair(map, "executor_last_budget_yield_backlog", owner_executor_last_budget_yield_backlog);
  add_mapping_pair(map, "executor_last_budget_yield_safe_backlog", owner_executor_last_budget_yield_safe_backlog);
  add_mapping_pair(map, "executor_owner_claims",
                   static_cast<long>(owner_executor_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_owner_releases",
                   static_cast<long>(owner_executor_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_runnable_task_dispatched",
                   static_cast<long>(owner_executor_runnable_task_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_safe_task_dispatched",
                   static_cast<long>(owner_executor_safe_task_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_probe_executed",
                   static_cast<long>(owner_executor_probe_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_main_required_skipped",
                   static_cast<long>(owner_executor_main_required_skipped.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_max_parallel_owners",
                   static_cast<long>(owner_executor_max_parallel_owners.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_max_owner_parallel",
                   static_cast<long>(owner_executor_max_owner_parallel.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_same_owner_claim_conflicts",
                   static_cast<long>(owner_executor_same_owner_claim_conflicts.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_active_claims", static_cast<long>(active_owner_claim_counts.size()));
  add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(map, "ordinary_lpc_activation_policy_ready", 1);
  add_mapping_pair(map, "ordinary_lpc_dispatch_path_ready", 1);
  add_mapping_pair(map, "ordinary_lpc_explicit_open_required", 1);
  add_mapping_string(map, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
  add_mapping_string(map, "ordinary_lpc_next_blocker", "");
  add_mapping_string(map, "executor_contract_version", kOwnerExecutorContractVersion);
  add_mapping_string(map, "executor_model", "owner_executor");
  add_mapping_string(map, "executor_dispatch_model", "descriptor_manifest");
  add_mapping_string(map, "executor_lpc_model", "default_closed_explicit_open");
  add_mapping_string(map, "ordinary_lpc_default_policy", "default_closed_explicit_open");
  auto *allowlist = owner_lpc_task_allowlist_array();
  add_mapping_pair(map, "lpc_task_allowlist_count", static_cast<long>(kOwnerLpcTaskDescriptors.size()));
  add_mapping_array(map, "lpc_task_allowlist", allowlist);
  free_array(allowlist);
  auto *lpc_contracts = owner_lpc_task_contracts_array();
  add_mapping_array(map, "executor_lpc_task_contracts", lpc_contracts);
  free_array(lpc_contracts);
  auto *task_contracts = owner_executor_task_contracts_array();
  add_mapping_array(map, "executor_task_dispatch_contracts", task_contracts);
  free_array(task_contracts);
  add_mapping_owned_mapping(map, "executor_task_contract", owner_task_contract_mapping());
  add_mapping_owned_mapping(map, "vm_context_contract", vm_context_contract_mapping());
  add_mapping_owned_mapping(map, "frozen_payload_contract", frozen_payload_contract_mapping());
  add_mapping_owned_mapping(map, "gateway_owner_task_contract", gateway_owner_task_contract_mapping());
  add_mapping_owned_mapping(map, "owner_executor_boundary_contract", owner_executor_boundary_contract_mapping());
  add_mapping_owned_mapping(map, "executor_queue_fairness", owner_queue_fairness_mapping());
  add_mapping_pair(map, "deferred_target_releases", static_cast<long>(owner_deferred_target_releases.size()));
  add_mapping_pair(map, "thread_starts", static_cast<long>(owner_thread_starts.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_stops", static_cast<long>(owner_thread_stops.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "executor_runnable_queue_depth", owner_executor_runnable_queue_depth());
  add_mapping_pair(map, "executor_safe_queue_depth", owner_executor_safe_queue_depth());
  add_mapping_pair(map, "main_required_queue_depth", owner_main_required_queue_depth());
  add_mapping_pair(map, "runnable_owner_count", owner_runnable_owner_count());
  add_mapping_pair(map, "main_queue_depth", owner_main_queue_total_depth());
  add_mapping_pair(map, "main_runnable_owner_count", owner_main_runnable_owner_count());
  add_mapping_pair(map, "pending_futures", owner_pending_future_count());
  add_mapping_pair(map, "main_active_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "main_queued", static_cast<long>(owner_main_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_dispatched", static_cast<long>(owner_main_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_stale", static_cast<long>(owner_main_stale.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_destructed", static_cast<long>(owner_main_destructed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_budget_yields", static_cast<long>(owner_main_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_claims", static_cast<long>(owner_main_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_releases", static_cast<long>(owner_main_owner_releases.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_runtime_status() {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto *map = allocate_mapping(101);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "multicore_mode", vm_multicore_mode());
  add_mapping_string(map, "multicore_mode_name", vm_multicore_mode_name(vm_multicore_mode()));
  add_mapping_pair(map, "audit_enabled", vm_multicore_audit_enabled() ? 1 : 0);
  add_mapping_pair(map, "enforced", vm_multicore_enforced() ? 1 : 0);
  add_mapping_string(map, "default_owner_id", kDefaultOwnerId);
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "executor_runnable_queue_depth", owner_executor_runnable_queue_depth());
  add_mapping_pair(map, "executor_safe_queue_depth", owner_executor_safe_queue_depth());
  add_mapping_pair(map, "main_required_queue_depth", owner_main_required_queue_depth());
  add_mapping_pair(map, "runnable_owner_count", owner_runnable_owner_count());
  add_mapping_pair(map, "main_queue_depth", owner_main_queue_total_depth());
  add_mapping_pair(map, "main_runnable_owner_count", owner_main_runnable_owner_count());
  add_mapping_pair(map, "main_active_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "claimed_owners", static_cast<long>(active_owner_set.size()));
  add_mapping_pair(map, "claimed_main_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "main_queued", static_cast<long>(owner_main_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_dispatched", static_cast<long>(owner_main_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_stale", static_cast<long>(owner_main_stale.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_destructed", static_cast<long>(owner_main_destructed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_budget_yields", static_cast<long>(owner_main_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_claims", static_cast<long>(owner_main_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_releases", static_cast<long>(owner_main_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "active_owners", static_cast<long>(active_owner_set.size()));
  add_mapping_pair(map, "owner_threads", static_cast<long>(owner_threads.size()));
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "future_count", static_cast<long>(owner_futures.size()));
  add_mapping_pair(map, "pending_futures", owner_pending_future_count());
  add_mapping_pair(map, "futures_completed", static_cast<long>(total_futures_completed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "futures_failed", static_cast<long>(total_futures_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_budget_yields",
                   static_cast<long>(owner_executor_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_string(map, "executor_last_budget_yield_owner", owner_executor_last_budget_yield_owner.c_str());
  add_mapping_pair(map, "executor_last_budget_yield_backlog", owner_executor_last_budget_yield_backlog);
  add_mapping_pair(map, "executor_last_budget_yield_safe_backlog", owner_executor_last_budget_yield_safe_backlog);
  add_mapping_pair(map, "executor_owner_claims",
                   static_cast<long>(owner_executor_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_owner_releases",
                   static_cast<long>(owner_executor_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_runnable_task_dispatched",
                   static_cast<long>(owner_executor_runnable_task_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_safe_task_dispatched",
                   static_cast<long>(owner_executor_safe_task_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_compute_result_completed",
                   static_cast<long>(owner_thread_compute_result_completed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_task_boundary_ready", 1);
  add_mapping_pair(map, "executor_callback_allowlist_ready", 1);
  add_mapping_pair(map, "executor_callback_allowlist_count", 6);
  add_mapping_string(map, "executor_callback_payload_policy", "frozen_payload_or_owner_handle_only");
  add_mapping_pair(map, "heartbeat_owner_executor_ready", 1);
  add_mapping_string(map, "heartbeat_owner_executor_task_type", "heartbeat");
  add_mapping_string(map, "heartbeat_owner_executor_route", "owner_executor");
  add_mapping_string(map, "heartbeat_owner_executor_fallback_route", "owner_main_queue");
  add_mapping_string(map, "heartbeat_owner_executor_policy", "audit_enforced_owner_thread_else_main");
  add_mapping_pair(map, "heartbeat_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "heartbeat_current_object_thread_local", 1);
  add_mapping_pair(map, "callout_owner_executor_ready", 1);
  add_mapping_string(map, "callout_owner_executor_task_type", "call_out");
  add_mapping_string(map, "callout_owner_executor_route", "owner_executor");
  add_mapping_string(map, "callout_owner_executor_fallback_route", "owner_main_queue");
  add_mapping_string(map, "callout_owner_executor_policy", "audit_enforced_owner_thread_else_main");
  add_mapping_pair(map, "callout_owner_executor_expired_handle_detach_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "executor_callback_queued",
                   static_cast<long>(owner_executor_callback_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_dispatched",
                   static_cast<long>(owner_executor_callback_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_dropped",
                   static_cast<long>(owner_executor_callback_dropped.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_main_cleanup_backlog",
                   static_cast<long>(owner_executor_callback_main_cleanups.size()));
  add_mapping_pair(map, "executor_callback_main_cleanup_queued",
                   static_cast<long>(owner_executor_callback_main_cleanup_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_callback_main_cleanup_dispatched",
                   static_cast<long>(owner_executor_callback_main_cleanup_dispatched.load(std::memory_order_relaxed)));
  auto *callback_contracts = owner_executor_callback_contracts_array();
  add_mapping_array(map, "executor_callback_task_contracts", callback_contracts);
  free_array(callback_contracts);
  add_mapping_pair(map, "thread_ordinary_lpc_executed",
                   static_cast<long>(owner_thread_ordinary_lpc_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_succeeded",
                   static_cast<long>(owner_thread_ordinary_lpc_succeeded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_failed",
                   static_cast<long>(owner_thread_ordinary_lpc_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_ordinary_lpc_rejected",
                   static_cast<long>(owner_thread_ordinary_lpc_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_command_consume_entry_executed",
                   static_cast<long>(owner_executor_command_consume_entry_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_command_frame_restore_entry_executed",
                   static_cast<long>(owner_executor_command_frame_restore_entry_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_gateway_command_guarded",
                   static_cast<long>(owner_thread_gateway_command_guarded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_gateway_command_rejected",
                   static_cast<long>(owner_thread_gateway_command_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_eval_stack_owner_bound",
                   static_cast<long>(owner_thread_eval_stack_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_eval_stack_cleared",
                   static_cast<long>(owner_thread_eval_stack_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_eval_stack_leak_detected",
                   static_cast<long>(owner_thread_eval_stack_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_control_stack_owner_bound",
                   static_cast<long>(owner_thread_control_stack_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_control_stack_cleared",
                   static_cast<long>(owner_thread_control_stack_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_control_stack_leak_detected",
                   static_cast<long>(owner_thread_control_stack_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_value_stack_owner_bound",
                   static_cast<long>(owner_thread_value_stack_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_value_stack_cleared",
                   static_cast<long>(owner_thread_value_stack_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_value_stack_leak_detected",
                   static_cast<long>(owner_thread_value_stack_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_apply_return_owner_bound",
                   static_cast<long>(owner_thread_apply_return_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_apply_return_cleared",
                   static_cast<long>(owner_thread_apply_return_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_apply_return_leak_detected",
                   static_cast<long>(owner_thread_apply_return_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_probe_executed",
                   static_cast<long>(owner_executor_probe_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_main_required_skipped",
                   static_cast<long>(owner_executor_main_required_skipped.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_max_parallel_owners",
                   static_cast<long>(owner_executor_max_parallel_owners.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_max_owner_parallel",
                   static_cast<long>(owner_executor_max_owner_parallel.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_same_owner_claim_conflicts",
                   static_cast<long>(owner_executor_same_owner_claim_conflicts.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_active_claims", static_cast<long>(active_owner_claim_counts.size()));
  add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(map, "ordinary_lpc_activation_policy_ready", 1);
  add_mapping_pair(map, "ordinary_lpc_dispatch_path_ready", 1);
  add_mapping_pair(map, "ordinary_lpc_explicit_open_required", 1);
  add_mapping_string(map, "ordinary_lpc_activation_policy", "default_closed_explicit_open");
  add_mapping_string(map, "ordinary_lpc_next_blocker", "");
  add_mapping_string(map, "executor_contract_version", kOwnerExecutorContractVersion);
  add_mapping_string(map, "executor_model", "owner_executor");
  add_mapping_string(map, "executor_dispatch_model", "descriptor_manifest");
  add_mapping_string(map, "executor_lpc_model", "default_closed_explicit_open");
  add_mapping_string(map, "ordinary_lpc_default_policy", "default_closed_explicit_open");
  auto *allowlist = owner_lpc_task_allowlist_array();
  add_mapping_pair(map, "lpc_task_allowlist_count", static_cast<long>(kOwnerLpcTaskDescriptors.size()));
  add_mapping_array(map, "lpc_task_allowlist", allowlist);
  free_array(allowlist);
  auto *lpc_contracts = owner_lpc_task_contracts_array();
  add_mapping_array(map, "executor_lpc_task_contracts", lpc_contracts);
  free_array(lpc_contracts);
  auto *task_contracts = owner_executor_task_contracts_array();
  add_mapping_array(map, "executor_task_dispatch_contracts", task_contracts);
  free_array(task_contracts);
  add_mapping_owned_mapping(map, "executor_task_contract", owner_task_contract_mapping());
  add_mapping_owned_mapping(map, "vm_context_contract", vm_context_contract_mapping());
  add_mapping_owned_mapping(map, "frozen_payload_contract", frozen_payload_contract_mapping());
  add_mapping_owned_mapping(map, "gateway_owner_task_contract", gateway_owner_task_contract_mapping());
  add_mapping_owned_mapping(map, "owner_executor_boundary_contract", owner_executor_boundary_contract_mapping());
  add_mapping_owned_mapping(map, "executor_queue_fairness", owner_queue_fairness_mapping());
  add_mapping_pair(map, "cross_owner", static_cast<long>(total_cross_owner_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "snapshot_required",
                   static_cast<long>(total_cross_owner_snapshot_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "message_required",
                   static_cast<long>(total_cross_owner_message_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "rejected_by_default",
                   static_cast<long>(total_cross_owner_rejected_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "enforced_blocks",
                   static_cast<long>(total_cross_owner_enforced_blocks.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "object_store_sync_rejections",
                   static_cast<long>(vm_context_object_store_sync_rejections()));
  return map;
}

// Query object snapshot for safe cross-owner read-only access
// Returns a mapping with basic properties that don't require synchronous call_other
mapping_t *vm_owner_query_object_snapshot(object_t *target, const char *requesting_owner_id) {
  if (!target) {
    return nullptr;
  }

  const char *target_owner_id = vm_owner_id(target);

  // Record this as a snapshot access
  vm_owner_record_cross_owner_access(current_object, target, "snapshot");

  // If same owner or target is default owner, allow direct access
  if (std::strcmp(target_owner_id, requesting_owner_id) == 0 ||
      std::strcmp(target_owner_id, kDefaultOwnerId) == 0) {
    return nullptr;  // Signal that direct access is safe
  }

  // Cross-owner access - return a safe snapshot
  total_cross_owner_snapshot_accesses.fetch_add(1, std::memory_order_relaxed);

  auto *snapshot = allocate_mapping(8);

  // Object identity
  add_mapping_string(snapshot, "object_name", target->obname);
  add_mapping_string(snapshot, "owner_id", target_owner_id);

  // Living status (check flags directly without calling methods)
  int living_flag = (target->flags & O_ENABLE_COMMANDS) ? 1 : 0;
  add_mapping_pair(snapshot, "living", living_flag);

  // Object type flags (check if methods exist without calling them)
  int has_is_npc = 0;
  int has_is_player = 0;
  int has_is_character = 0;

  // Check if methods exist (pass 0 as third argument for local function check)
  if (function_exists("is_npc", target, 0)) {
    has_is_npc = 1;
  }
  if (function_exists("is_player", target, 0)) {
    has_is_player = 1;
  }
  if (function_exists("is_character", target, 0)) {
    has_is_character = 1;
  }

  add_mapping_pair(snapshot, "has_is_npc", has_is_npc);
  add_mapping_pair(snapshot, "has_is_player", has_is_player);
  add_mapping_pair(snapshot, "has_is_character", has_is_character);
  add_mapping_pair(snapshot, "living_flag", living_flag);

  return snapshot;
}
