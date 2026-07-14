#include "base/package_api.h"

#include "base/internal/port.h"

#include "vm/context.h"
#include "vm/frozen_value.h"
#include "vm/object_handle.h"
#include "vm/owner.h"
#include "vm/vm.h"
#include "vm/internal/owner_executor.h"
#include "vm/internal/owner_future_store.h"
#include "vm/internal/owner_runtime_coordinator.h"
#include "vm/internal/owner_runtime_metrics.h"
#include "vm/internal/owner_scheduler_state.h"
#include "vm/internal/owner_service_registry.h"
#include "vm/internal/owner_task_manifest.h"
#include "vm/internal/owner_trace_store.h"
#include "vm/internal/lpc_vm_profile.h"
#include "vm/internal/apply.h"
#include "compiler/internal/lpc_modern_profile.h"

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
constexpr int kOwnerExecutorTaskBudget = 32;
constexpr long kOwnerSchedulerMaxOwnerQueueDepth = 4096;
constexpr long kOwnerSchedulerBackpressureHighWatermark = kOwnerSchedulerMaxOwnerQueueDepth * 8 / 10;
constexpr const char *kOwnerExecutorContractVersion = "owner_executor_v2";
constexpr const char *kOwnerRuntimeBenchmarkSchemaV1 = "owner_runtime_bench_v1";
constexpr const char *kOwnerRuntimeStressEntry = "tools/owner-runtime-v4-stress.sh";
constexpr const char *kObjectStoreBenchmarkSchemaV1 = "object_store_bench_v1";
constexpr const char *kLpcModernRuntimeStressEntry = "tools/lpc-modern-runtime-stress.sh";
constexpr const char *kOwnerCallbackDiagnosticsSchemaV1 = "owner_callback_diagnostics_v1";
constexpr const char *kOwnerCallbackFailureCodeSchemaV1 = "owner_callback_failure_code_v1";
constexpr const char *kOwnerCallbackDropReasonSchemaV1 = "owner_callback_drop_reason_v1";
constexpr const char *kOwnerCallbackPayloadPolicySchemaV1 = "owner_callback_payload_policy_v1";
constexpr const char *kOwnerCallbackFailureReasonSchemaV1 = "owner_callback_failure_reason_v1";
constexpr const char *kOwnerCallbackPayloadPolicyStrictV1 = "frozen_payload_or_owner_handle_only";
constexpr const char *kOwnerCallbackFailureCodesV1 =
    "owner_scheduler_backpressure,callback_not_allowlisted,callback_invalid_target,owner_epoch_mismatch,"
    "target_destructed,target_stale,admission_rejected,task_dropped";
constexpr const char *kOwnerCallbackDropReasonsV1 =
    "none,owner_scheduler_backpressure,callback_not_allowlisted,callback_invalid_target,owner_epoch_mismatch,"
    "target_destructed,target_stale,admission_rejected,task_dropped";
constexpr const char *kOwnerCallbackSupportedKinds =
    "heartbeat,call_out,async_callback,dns_callback,socket_callback,gateway_command_execute,ed_callback";
constexpr const char *kOwnerExecutorCallbackAllowlistKinds =
    "heartbeat,call_out,async_callback,dns_callback,socket_callback,ed_callback";

constexpr const char *kGatewayCommandExecutorActivationBlocker = "interactive_command_requires_main_thread_io_adapter";

void clear_owner_apply_return() { vm_apply_return_clear(); }

class OwnerProgramPin {
 public:
  OwnerProgramPin(program_t *program, const char *reason) : program_(program) {
    if (program_) {
      reference_prog(program_, reason);
    }
  }

  ~OwnerProgramPin() {
    if (program_) {
      auto *program = program_;
      program_ = nullptr;
      free_prog(&program);
    }
  }

  OwnerProgramPin(const OwnerProgramPin &) = delete;
  OwnerProgramPin &operator=(const OwnerProgramPin &) = delete;

 private:
  program_t *program_{nullptr};
};

void add_owner_callback_diagnostic_contract_fields(mapping_t *map) {
  add_mapping_pair(map, "owner_callback_payload_strict_diagnostics_ready", 1);
  add_mapping_string(map, "owner_callback_payload_policy_schema", kOwnerCallbackPayloadPolicySchemaV1);
  add_mapping_string(map, "owner_callback_payload_policy", kOwnerCallbackPayloadPolicyStrictV1);
  add_mapping_string(map, "owner_callback_failure_codes", kOwnerCallbackFailureCodesV1);
  add_mapping_string(map, "owner_callback_drop_reasons", kOwnerCallbackDropReasonsV1);
  add_mapping_pair(map, "owner_callback_human_reason_ready", 1);
  add_mapping_string(map, "owner_callback_failure_reason_schema", kOwnerCallbackFailureReasonSchemaV1);
}

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
    {"gateway", "process_user_command", "main_required", "owner_main_queue",
     "owner_scope_current_interactive_command_giver", "owner_epoch_target_guard", "gateway_command_input",
     "buffer_metadata_no_raw_command_text", "owner_owned_snapshot_main_thread_consume", 1, 0,
     kGatewayCommandExecutorActivationBlocker,
     "gateway_command_execution_frame_v1", "owner_scope_current_interactive_command_giver",
     "main_thread_vmcontext_scope", "", 1, 0, 1, 0, 1, 1, 1, 1,
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

OwnerRuntimeMetrics &owner_runtime_metrics = owner_runtime_metrics_instance();
#define OWNER_RUNTIME_METRIC_ALIAS(name, initial) std::atomic<uint64_t> &name = owner_runtime_metrics.name;
OWNER_RUNTIME_METRIC_FIELDS(OWNER_RUNTIME_METRIC_ALIAS)
#undef OWNER_RUNTIME_METRIC_ALIAS
std::string owner_executor_last_budget_yield_owner;
long owner_executor_last_budget_yield_backlog{0};
long owner_executor_last_budget_yield_safe_backlog{0};

struct OwnerExecutorCallbackCleanup {
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::function<void()> callback;
};

std::deque<OwnerExecutorCallbackCleanup> owner_executor_callback_main_cleanups;
std::vector<object_t *> owner_deferred_target_releases;
OwnerFutureStore &owner_future_store = owner_future_store_instance();
OwnerSchedulerState &owner_scheduler_state = owner_scheduler_state_instance();
OwnerTraceStore &owner_trace_store = owner_trace_store_instance();
std::atomic<VMOwnerFutureTerminalNotifier> owner_future_terminal_notifier{nullptr};
std::mutex &owner_runtime_mutex = owner_runtime_mutex_instance();
std::condition_variable &owner_runtime_cv = owner_runtime_cv_instance();
bool &owner_thread_stopping = owner_thread_stopping_flag();
bool &owner_main_draining = owner_main_draining_flag();
std::vector<std::thread> &owner_threads = owner_threads_instance();

uint64_t append_owner_task_trace(uint64_t task_id, uint64_t sequence, const std::string &owner_id,
                                 uint64_t owner_epoch, const std::string &task_type,
                                 const std::string &task_key, const char *state);
uint64_t append_owner_task_trace(const OwnerMailboxTask &task, const char *state);
uint64_t append_owner_task_trace(const OwnerMainTask &task, const char *state);

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

uint64_t owner_now_ms() {
  using namespace std::chrono;
  return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint64_t owner_now_ns() {
  using namespace std::chrono;
  return static_cast<uint64_t>(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

void owner_record_latency(std::atomic<uint64_t> &total, std::atomic<uint64_t> &max,
                          std::atomic<uint64_t> &samples, uint64_t elapsed_ns) {
  total.fetch_add(elapsed_ns, std::memory_order_relaxed);
  samples.fetch_add(1, std::memory_order_relaxed);
  auto current = max.load(std::memory_order_relaxed);
  while (elapsed_ns > current &&
         !max.compare_exchange_weak(current, elapsed_ns, std::memory_order_relaxed,
                                    std::memory_order_relaxed)) {
  }
}

void owner_record_thread_cpu(std::atomic<uint64_t> &total,
                             std::atomic<uint64_t> &unavailable,
                             int64_t started_ns) {
  auto finished_ns = get_current_thread_cpu_time_ns();
  if (started_ns < 0 || finished_ns < started_ns) {
    unavailable.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  total.fetch_add(static_cast<uint64_t>(finished_ns - started_ns),
                  std::memory_order_relaxed);
}

void notify_owner_future_terminal() {
  auto notifier = owner_future_terminal_notifier.load(std::memory_order_acquire);
  if (notifier) {
    notifier();
  }
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
  return owner_scheduler_state.mailbox_depth(owner_id);
}

long owner_mailbox_total_depth() {
  return owner_scheduler_state.mailbox_total_depth();
}

long owner_main_queue_total_depth() {
  return owner_scheduler_state.main_queue_total_depth();
}

long owner_main_queue_depth(const std::string &owner_id) {
  return owner_scheduler_state.main_queue_depth(owner_id);
}

long owner_mailbox_active_owners() {
  return owner_scheduler_state.mailbox_active_owners();
}

long owner_pending_future_count() {
  return owner_future_store.pending_count();
}

long owner_executor_runnable_queue_depth();
long owner_executor_safe_queue_depth();
long owner_main_required_queue_depth();
long owner_executor_callback_allowlist_count();
bool owner_task_executor_runnable(const OwnerMailboxTask &task);
bool owner_task_executor_safe(const OwnerMailboxTask &task);
bool owner_task_requires_main_drain(const OwnerMailboxTask &task);
void add_owner_scheduler_backpressure_fields(mapping_t *map, const OwnerQueueFairnessSnapshot &snapshot);

void add_owner_runtime_v2_status_fields(mapping_t *map) {
  auto metrics = owner_runtime_metrics.snapshot();
  auto fairness = owner_scheduler_state.fairness_snapshot(owner_task_executor_runnable, owner_task_executor_safe,
                                                          owner_task_requires_main_drain);
  auto normal_path_main_fallbacks = static_cast<long>(metrics.owner_normal_path_main_fallback_count);
  add_mapping_pair(map, "owner_runtime_split_ready", 1);
  add_mapping_string(map, "owner_runtime_split_model", "runtime_v4_modules_with_owner_runtime_coordinator");
  add_mapping_pair(map, "owner_runtime_v4_hardening_ready", 1);
  add_mapping_pair(map, "owner_runtime_benchmark_smoke_ready", 1);
  add_mapping_string(map, "owner_runtime_benchmark_schema", kOwnerRuntimeBenchmarkSchemaV1);
  add_mapping_pair(map, "owner_runtime_stress_profile_ready", 1);
  add_mapping_string(map, "owner_runtime_stress_entry", kOwnerRuntimeStressEntry);
  add_mapping_pair(map, "lpc_modern_runtime_stress_ready", 1);
  add_mapping_string(map, "lpc_modern_runtime_stress_entry", kLpcModernRuntimeStressEntry);
  add_mapping_pair(map, "owner_runtime_layering_guard_ready", 1);
  add_mapping_pair(map, "owner_runtime_coordinator_module_ready", 1);
  add_mapping_pair(map, "lpc_modern_profile_ready", 1);
  add_mapping_string(map, "lpc_modern_profile_schema", kLpcModernProfileSchemaV1);
  add_mapping_string(map, "lpc_modern_profile_mode", kLpcModernProfileModeOptIn);
  add_mapping_pair(map, "lpc_vm_profile_ready", 1);
  add_mapping_string(map, "lpc_vm_profile_schema", kLpcVmProfileSchemaV1);
  add_mapping_pair(map, "lpc_vm_profile_default_recording", 0);
  add_mapping_string(map, "lpc_vm_profile_recording_policy", "explicit_current_thread_only");
  add_mapping_pair(map, "lpc_vm_benchmark_smoke_ready", 1);
  add_mapping_string(map, "lpc_vm_benchmark_schema", kLpcVmBenchSchemaV1);
  add_mapping_pair(map, "lpc_vm_hot_path_profile_ready", 1);
  add_mapping_string(map, "lpc_vm_hot_path_profile_model",
                     "opcode_efun_call_other_function_pointer_parser_mapping_string_v1");
  add_mapping_pair(map, "object_store_benchmark_smoke_ready", 1);
  add_mapping_string(map, "object_store_benchmark_schema", kObjectStoreBenchmarkSchemaV1);
  add_mapping_pair(map, "lpc_apply_dispatch_cache_probe_ready", 1);
  add_mapping_pair(map, "lpc_opcode_dispatch_profile_ready", 1);
  add_mapping_pair(map, "lpc_efun_dispatch_profile_ready", 1);
  add_mapping_pair(map, "lpc_call_other_profile_ready", 1);
  add_mapping_pair(map, "lpc_function_pointer_profile_ready", 1);
  add_mapping_pair(map, "lpc_parser_action_profile_ready", 1);
  add_mapping_pair(map, "lpc_mapping_string_profile_ready", 1);
  add_mapping_pair(map, "lpc_dispatch_cache_ready", 1);
  add_mapping_string(map, "lpc_dispatch_cache_model", "apply_dispatch_thread_local_direct_cache_v1");
  add_mapping_pair(map, "lpc_jit_experiment_default_off", 1);
  add_mapping_pair(map, "modern_lpc_pragma_ready", 1);
  add_mapping_pair(map, "strict_owner_pragma_ready", 1);
  add_mapping_string(map, "strict_owner_policy", kLpcStrictOwnerPolicyV1);
  add_mapping_pair(map, "lpcc_owner_audit_ready", 1);
  add_mapping_string(map, "lpcc_owner_audit_schema", kLpcOwnerAuditSchemaV1);
  add_mapping_pair(map, "lpcc_owner_audit_cli_ready", 1);
  add_mapping_string(map, "lpcc_owner_audit_cli", "lpcc --owner-audit --format=json");
  add_mapping_pair(map, "lpcc_owner_audit_static_scanner_ready", 1);
  add_mapping_pair(map, "lpc_source_encoding_ready", 1);
  add_mapping_string(map, "lpc_source_encoding_schema", kLpcSourceEncodingSchemaV1);
  add_mapping_string(map, "vm_internal_string_encoding", kLpcInternalStringEncoding);
  add_mapping_pair(map, "session_encoding_contract_ready", 1);
  add_mapping_pair(map, "gateway_encoding_boundary_ready", 1);
  add_mapping_pair(map, "encoding_audit_ready", 1);
  add_mapping_pair(map, "legacy_lpc_default_closed", 1);
  add_mapping_pair(map, "owner_safe_future_api_ready", 1);
  add_mapping_pair(map, "owner_safe_lpc_api_failure_schema_ready", 1);
  add_mapping_string(map, "owner_safe_lpc_api_failure_schema", "owner_safe_lpc_api_failure_v1");
  add_mapping_string(map, "owner_safe_lpc_api_return_fields", "success,ok,code,error,reason,api,trace_id");
  add_mapping_pair(map, "owner_async_api_ready", 1);
  add_mapping_pair(map, "owner_await_poll_adapter_ready", 1);
  add_mapping_pair(map, "owner_await_coroutine_runtime_ready", 0);
  add_mapping_pair(map, "freeze_snapshot_api_ready", 1);
  add_mapping_string(map, "freeze_snapshot_model", "validated_deep_copy");
  add_mapping_pair(map, "lpc_value_object_profile_ready", 1);
  add_mapping_string(map, "lpc_value_object_model", "frozen_snapshot_value_object_v1");
  add_mapping_pair(map, "lpc_value_object_live_lifecycle_member", 0);
  add_mapping_pair(map, "lpc_value_object_cross_owner_payload_safe", 1);
  add_mapping_pair(map, "owner_snapshot_persistence_ready", 1);
  add_mapping_string(map, "owner_snapshot_persistence_model", "owner_snapshot_serialized_payload_v1");
  add_mapping_string(map, "owner_snapshot_persistence_adapter", "main_thread_file_adapter");
  add_mapping_pair(map, "owner_snapshot_direct_save_hot_path_audit_ready", 1);
  add_mapping_pair(map, "owner_commit_api_ready", 1);
  add_mapping_string(map, "owner_commit_model", "owner_commit_boundary_record");
  add_mapping_pair(map, "owner_task_manifest_module_ready", 1);
  add_mapping_pair(map, "owner_trace_store_ready", 1);
  add_mapping_pair(map, "owner_future_store_ready", 1);
  add_mapping_pair(map, "owner_scheduler_state_ready", 1);
  add_mapping_pair(map, "owner_metrics_store_ready", 1);
  add_mapping_pair(map, "object_store_owner_fast_path_ready", 1);
  add_mapping_pair(map, "object_store_global_fallback_on_owner_fast_path", 0);
  add_mapping_pair(map, "object_handle_capability_ready", 1);
  add_mapping_string(map, "object_handle_capability_model", kVMObjectHandleCapabilityModelV1);
  add_mapping_pair(map, "owner_task_manifest_v2_ready", 1);
  add_mapping_string(map, "owner_task_manifest_schema", kOwnerTaskManifestSchemaV2);
  add_mapping_pair(map, "owner_executor_admission_gate_ready", 1);
  add_mapping_pair(map, "owner_callback_admission_unified", 1);
  add_mapping_pair(map, "owner_callback_diagnostics_ready", 1);
  add_mapping_string(map, "owner_callback_diagnostics_schema", kOwnerCallbackDiagnosticsSchemaV1);
  add_mapping_string(map, "owner_callback_failure_code_schema", kOwnerCallbackFailureCodeSchemaV1);
  add_mapping_string(map, "owner_callback_drop_reason_schema", kOwnerCallbackDropReasonSchemaV1);
  add_mapping_pair(map, "owner_callback_allowlist_complete", 1);
  add_mapping_string(map, "owner_callback_supported_kinds", kOwnerCallbackSupportedKinds);
  add_owner_callback_diagnostic_contract_fields(map);
  add_mapping_pair(map, "executor_callback_allowlist_count", owner_executor_callback_allowlist_count());
  add_mapping_string(map, "owner_executor_admission_policy", kOwnerTaskAdmissionPolicyV2);
  add_mapping_pair(map, "owner_executor_admission_accepted",
                   static_cast<long>(metrics.owner_executor_admission_accepted));
  add_mapping_pair(map, "owner_executor_admission_rejected",
                   static_cast<long>(metrics.owner_executor_admission_rejected));
  add_mapping_pair(map, "owner_executor_admission_dropped",
                   static_cast<long>(metrics.owner_executor_admission_dropped));
  add_mapping_pair(map, "owner_executor_payload_policy_v2_ready", 1);
  add_mapping_pair(map, "owner_executor_trace_schema_v2_ready", 1);
  add_mapping_string(map, "owner_executor_trace_schema", kOwnerExecutorTraceSchemaV2);
  add_mapping_pair(map, "owner_executor_metrics_v2_ready", 1);
  add_mapping_pair(map, "owner_async_stage_timing_ready", 1);
  add_mapping_pair(map, "owner_async_queue_wait_samples",
                   static_cast<long>(metrics.owner_async_queue_wait_samples));
  add_mapping_pair(map, "owner_async_queue_wait_total_us",
                   static_cast<long>(metrics.owner_async_queue_wait_ns_total / 1000));
  add_mapping_pair(map, "owner_async_queue_wait_max_us",
                   static_cast<long>(metrics.owner_async_queue_wait_ns_max / 1000));
  add_mapping_pair(map, "owner_async_lpc_execute_samples",
                   static_cast<long>(metrics.owner_async_lpc_execute_samples));
  add_mapping_pair(map, "owner_async_lpc_execute_total_us",
                   static_cast<long>(metrics.owner_async_lpc_execute_ns_total / 1000));
  add_mapping_pair(map, "owner_async_lpc_execute_max_us",
                   static_cast<long>(metrics.owner_async_lpc_execute_ns_max / 1000));
  add_mapping_pair(
      map, "owner_async_lpc_execute_thread_cpu_total_us",
      static_cast<long>(metrics.owner_async_lpc_execute_thread_cpu_ns_total / 1000));
  add_mapping_pair(
      map, "owner_async_lpc_execute_thread_cpu_unavailable",
      static_cast<long>(metrics.owner_async_lpc_execute_thread_cpu_unavailable));
  add_mapping_pair(map, "owner_async_result_completion_samples",
                   static_cast<long>(metrics.owner_async_result_completion_samples));
  add_mapping_pair(map, "owner_async_result_completion_total_us",
                   static_cast<long>(metrics.owner_async_result_completion_ns_total / 1000));
  add_mapping_pair(map, "owner_async_result_completion_max_us",
                   static_cast<long>(metrics.owner_async_result_completion_ns_max / 1000));
  add_mapping_pair(
      map, "owner_async_result_completion_thread_cpu_total_us",
      static_cast<long>(metrics.owner_async_result_completion_thread_cpu_ns_total / 1000));
  add_mapping_pair(
      map, "owner_async_result_completion_thread_cpu_unavailable",
      static_cast<long>(metrics.owner_async_result_completion_thread_cpu_unavailable));
  add_mapping_pair(map, "owner_executor_queue_depth_metrics_ready", 1);
  add_mapping_pair(map, "owner_executor_queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "owner_executor_runnable_queue_depth", owner_executor_runnable_queue_depth());
  add_mapping_pair(map, "owner_executor_safe_queue_depth", owner_executor_safe_queue_depth());
  add_mapping_pair(map, "owner_executor_main_required_queue_depth", owner_main_required_queue_depth());
  add_mapping_pair(map, "owner_executor_future_timeout_cancel_ready", 1);
  add_mapping_pair(map, "owner_executor_future_terminal_take_ready", 1);
  add_mapping_pair(map, "owner_executor_future_timeout", static_cast<long>(metrics.owner_executor_future_timeout));
  add_mapping_pair(map, "owner_executor_future_cancelled", static_cast<long>(metrics.owner_executor_future_cancelled));
  add_mapping_pair(map, "owner_executor_backpressure_rejected",
                   static_cast<long>(metrics.owner_executor_backpressure_rejected));
  add_owner_scheduler_backpressure_fields(map, fairness);
  add_mapping_pair(map, "owner_executor_stale_drop", static_cast<long>(metrics.owner_executor_stale_drop));
  add_mapping_pair(map, "owner_executor_destructed_drop", static_cast<long>(metrics.owner_executor_destructed_drop));
  add_mapping_pair(map, "owner_executor_epoch_mismatch_drop",
                   static_cast<long>(metrics.owner_executor_epoch_mismatch_drop));
  add_mapping_pair(map, "owner_executor_context_cleanup_leaks",
                   static_cast<long>(metrics.owner_thread_context_leak_detected));
  add_mapping_pair(map, "owner_executor_future_pending_backlog", owner_pending_future_count());
  add_mapping_pair(map, "owner_executor_socket_release_trace_ready", 1);
  add_mapping_pair(map, "registered_owner_task_domains_ready", 1);
  add_mapping_pair(map, "registered_owner_task_domain_count", static_cast<long>(owner_lpc_task_descriptors().size()));
  add_mapping_pair(map, "owner_service_shard_registry_ready", 1);
  add_mapping_string(map, "owner_service_shard_registry_schema", kOwnerServiceShardRegistrySchemaV1);
  add_mapping_pair(map, "owner_service_shard_domain_count",
                   static_cast<long>(owner_service_shard_descriptors().size()));
  add_mapping_string(map, "owner_service_shard_domains", owner_service_shard_domain_list().c_str());
  add_mapping_pair(map, "owner_service_registry_lpc_domain_alignment_ready",
                   owner_service_registry_matches_lpc_domains() ? 1 : 0);
  add_mapping_pair(map, "owner_tick_group_scheduler_ready", 1);
  add_mapping_string(map, "owner_tick_group_scheduler_schema", kOwnerTickGroupSchedulerSchemaV1);
  add_mapping_pair(map, "owner_tick_group_count", static_cast<long>(owner_tick_group_descriptors().size()));
  add_mapping_string(map, "owner_tick_groups", owner_tick_group_name_list().c_str());
  add_mapping_pair(map, "owner_scheduler_tuning_config_ready", 1);
  add_mapping_string(map, "owner_scheduler_tuning_config_schema", kOwnerSchedulerTuningConfigSchemaV1);
  add_mapping_string(map, "owner_scheduler_tick_group_budget_source", "owner_service_registry");
  add_mapping_pair(map, "owner_scheduler_priority_groups_ready", 1);
  add_mapping_pair(map, "owner_scheduler_tick_group_backpressure_ready", 1);
  add_mapping_pair(map, "owner_scheduler_starvation_guard_ready", 1);
  add_mapping_pair(map, "target_owner_message_executor_ready", 1);
  add_mapping_pair(map, "normal_path_main_fallback_count", normal_path_main_fallbacks);
  add_mapping_pair(map, "normal_path_main_fallback_ready", normal_path_main_fallbacks == 0 ? 1 : 0);
  add_mapping_pair(map, "main_fallback_policy_ready", 1);
  add_mapping_string(map, "main_fallback_classification", "explicit_policy");
  add_mapping_pair(map, "explicit_fallback_count", static_cast<long>(metrics.owner_explicit_main_fallback_count));
  add_mapping_pair(map, "off_mode_main_fallback_count", static_cast<long>(metrics.owner_off_mode_main_fallback_count));
  add_mapping_pair(map, "main_io_adapter_count", static_cast<long>(metrics.owner_main_io_adapter_count));
  add_mapping_pair(map, "main_cleanup_adapter_count", static_cast<long>(metrics.owner_main_cleanup_adapter_count));
  add_mapping_pair(map, "session_fifo_contract_ready", 1);
  add_mapping_pair(map, "gateway_io_adapter_only_ready", 1);
  add_mapping_string(map, "gateway_io_boundary", "main_thread_io_adapter");
  add_mapping_pair(map, "gateway_low_overhead_latency_probe_ready", 1);
  add_mapping_string(map, "gateway_latency_probe_source", "gateway_status_internal");
  add_mapping_string(map, "gateway_latency_probe_fields",
                     "receive_decode,receive_payload_copy,receive_enqueue_to_dispatch,receive_apply,"
                     "command_enqueue_to_dispatch,command_execute,"
                     "receive_main_queue_depth,deferred_main_drain_wait,"
                     "reply_enqueue_to_dispatch,reply_execute,output_enqueue_to_dispatch,output_execute,main_drain");
  add_mapping_pair(map, "callback_payload_strict_ready", 1);
  add_mapping_pair(map, "service_shard_executor_ready", 1);
  add_mapping_pair(map, "domain_task_registry_mudlib_aligned", 1);
  add_mapping_pair(map, "keyed_service_shard_ready", 1);
  add_mapping_pair(map, "hot_path_service_owner_single_point", owner_service_hot_path_service_owner_count());
  add_mapping_pair(map, "hot_path_service_shard_count", owner_service_hot_path_service_shard_count());
  add_mapping_string(map, "owner_service_shard_policy_model", "keyed_service_shard_for_hot_paths");
  add_mapping_pair(map, "target_owner_message_main_fallback", 0);
  add_mapping_pair(map, "production_perfect_contract_ready", normal_path_main_fallbacks == 0 ? 1 : 0);
  add_mapping_pair(map, "facade_only_runtime_claims", 0);
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

const OwnerExecutorTaskDescriptor &owner_executor_task_descriptor(const OwnerMailboxTask &task) {
  if (const auto *descriptor = find_owner_executor_task_descriptor(task.task_type)) {
    return *descriptor;
  }
  return owner_generic_executor_task_descriptor();
}

const OwnerExecutorTaskDescriptor &owner_executor_task_descriptor(const OwnerMainTask &task) {
  if (const auto *descriptor = find_owner_executor_task_descriptor(task.task_type)) {
    return *descriptor;
  }
  return owner_generic_executor_task_descriptor();
}

bool owner_handle_status_destructed(VMObjectHandleResolveStatus status) {
  return status == VMObjectHandleResolveStatus::kObjectDestructed ||
         status == VMObjectHandleResolveStatus::kRecordDestructed;
}

bool owner_handle_status_epoch_mismatch(VMObjectHandleResolveStatus status) {
  return status == VMObjectHandleResolveStatus::kOwnerEpochMismatch ||
         status == VMObjectHandleResolveStatus::kLiveOwnerEpochMismatch;
}

void apply_owner_task_manifest_v2(OwnerMailboxTask &task) {
  const auto &descriptor = owner_executor_task_descriptor(task);
  task.manifest_version = 2;
  task.manifest_schema = kOwnerTaskManifestSchemaV2;
  task.task_kind = owner_executor_dispatch_kind_name(descriptor.dispatch_kind);
  task.payload_policy =
      owner_manifest_payload_policy(descriptor.dispatch_kind, task.has_target_handle, task.payload != nullptr);
  task.cleanup_policy = owner_manifest_cleanup_policy(descriptor.dispatch_kind, task.has_target_handle);
  task.reply_future_policy = owner_manifest_reply_future_policy(descriptor.dispatch_kind);
  task.admission_policy = kOwnerTaskAdmissionPolicyV2;
  task.admission_state = descriptor.rejected ? "accepted_dispatch_rejected" : "accepted";
  task.trace_schema = kOwnerExecutorTraceSchemaV2;
  const auto &tick_group = owner_tick_group_for_executor_task(task.task_type.c_str());
  task.tick_group = tick_group.name;
  task.scheduler_priority = tick_group.priority;
  task.scheduler_budget = tick_group.budget;
  task.scheduler_max_queue_depth = tick_group.max_queue_depth;
  task.backpressure_policy = tick_group.backpressure_policy;
}

array_t *owner_lpc_task_allowlist_array() {
  auto *methods = allocate_array(static_cast<int>(owner_lpc_task_descriptors().size()));
  for (size_t i = 0; i < owner_lpc_task_descriptors().size(); i++) {
    methods->item[i].type = T_STRING;
    methods->item[i].subtype = STRING_SHARED;
    methods->item[i].u.string = make_shared_string(owner_lpc_task_descriptors()[i].method);
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
  auto *map = allocate_mapping(28);
  const auto &tick_group = owner_tick_group_for_executor_task(descriptor.task_type);
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
  add_mapping_pair(map, "manifest_version", 2);
  add_mapping_string(map, "manifest_schema", kOwnerTaskManifestSchemaV2);
  add_mapping_string(map, "task_kind", owner_executor_dispatch_kind_name(descriptor.dispatch_kind));
  add_mapping_string(map, "admission_policy", kOwnerTaskAdmissionPolicyV2);
  add_mapping_string(map, "payload_policy",
                     owner_manifest_payload_policy(descriptor.dispatch_kind, false, false));
  add_mapping_string(map, "cleanup_policy", owner_manifest_cleanup_policy(descriptor.dispatch_kind, false));
  add_mapping_string(map, "reply_future_policy", owner_manifest_reply_future_policy(descriptor.dispatch_kind));
  add_mapping_string(map, "trace_schema", kOwnerExecutorTraceSchemaV2);
  add_mapping_string(map, "tick_group", tick_group.name);
  add_mapping_pair(map, "scheduler_priority", tick_group.priority);
  add_mapping_pair(map, "scheduler_budget", tick_group.budget);
  add_mapping_pair(map, "scheduler_max_queue_depth", tick_group.max_queue_depth);
  add_mapping_string(map, "backpressure_policy", tick_group.backpressure_policy);
  add_mapping_pair(map, "deadline_required", 0);
  add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
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
  auto *contracts = allocate_array(static_cast<int>(owner_lpc_task_descriptors().size()));
  for (size_t i = 0; i < owner_lpc_task_descriptors().size(); i++) {
    contracts->item[i].type = T_MAPPING;
    contracts->item[i].subtype = 0;
    contracts->item[i].u.map = owner_lpc_task_contract_entry(owner_lpc_task_descriptors()[i]);
  }
  return contracts;
}

array_t *owner_executor_task_contracts_array() {
  auto *contracts = allocate_array(static_cast<int>(owner_executor_task_descriptors().size()));
  for (size_t i = 0; i < owner_executor_task_descriptors().size(); i++) {
    contracts->item[i].type = T_MAPPING;
    contracts->item[i].subtype = 0;
    contracts->item[i].u.map = owner_executor_task_contract_entry(owner_executor_task_descriptors()[i]);
  }
  return contracts;
}

array_t *owner_executor_callback_contracts_array() {
  size_t callback_count = 0;
  for (const auto &descriptor : owner_executor_task_descriptors()) {
    if (descriptor.dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
      callback_count++;
    }
  }

  auto *contracts = allocate_array(static_cast<int>(callback_count));
  size_t index = 0;
  for (const auto &descriptor : owner_executor_task_descriptors()) {
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

long owner_executor_callback_allowlist_count() {
  long callback_count = 0;
  for (const auto &descriptor : owner_executor_task_descriptors()) {
    if (descriptor.dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
      callback_count++;
    }
  }
  return callback_count;
}

const char *owner_task_failure_code(const std::string &state, const std::string &admission_state) {
  if (admission_state == "rejected_backpressure" || state == "backpressure_rejected") {
    return "owner_scheduler_backpressure";
  }
  if (admission_state == "rejected_callback_not_allowlisted") {
    return "callback_not_allowlisted";
  }
  if (admission_state == "dropped_callback_invalid_target") {
    return "callback_invalid_target";
  }
  if (state.find("epoch_mismatch") != std::string::npos) {
    return "owner_epoch_mismatch";
  }
  if (state.find("destructed") != std::string::npos) {
    return "target_destructed";
  }
  if (state.find("stale") != std::string::npos) {
    return "target_stale";
  }
  if (state.find("rejected") != std::string::npos || admission_state.find("rejected") != std::string::npos) {
    return "admission_rejected";
  }
  if (state.find("dropped") != std::string::npos || admission_state.find("dropped") != std::string::npos) {
    return "task_dropped";
  }
  return "";
}

const char *owner_task_failure_reason(const std::string &state, const std::string &admission_state) {
  const auto *code = owner_task_failure_code(state, admission_state);
  if (code[0] == '\0') {
    return "";
  }
  if (std::string(code) == "owner_scheduler_backpressure") {
    return "owner queue depth reached the scheduler backpressure limit";
  }
  if (std::string(code) == "callback_not_allowlisted") {
    return "callback task kind is not registered in the owner executor allowlist";
  }
  if (std::string(code) == "callback_invalid_target") {
    return "callback target handle could not be resolved before executor admission";
  }
  if (std::string(code) == "owner_epoch_mismatch") {
    return "target owner epoch no longer matches the captured callback handle";
  }
  if (std::string(code) == "target_destructed") {
    return "target object was destructed before callback dispatch";
  }
  if (std::string(code) == "target_stale") {
    return "target handle became stale before callback dispatch";
  }
  if (std::string(code) == "admission_rejected") {
    return "owner executor admission rejected the task";
  }
  if (std::string(code) == "task_dropped") {
    return "owner executor dropped the task before callback dispatch";
  }
  return "owner executor callback failed";
}

const char *owner_task_drop_reason(const std::string &state, const std::string &admission_state) {
  auto *failure_code = owner_task_failure_code(state, admission_state);
  return failure_code[0] == '\0' ? "none" : failure_code;
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

void add_production_gate_contract_fields(mapping_t *map) {
  add_mapping_pair(map, "mudlib_audit_required", 1);
  add_mapping_pair(map, "mudlib_cross_owner_hotspots_ready", 1);
  add_mapping_string(map, "mudlib_cross_owner_hotspots_blocker", "");
  add_mapping_string(map, "mudlib_cross_owner_hotspots_evidence",
                     "xkx_5513c8a12_multicore_mudlib_audit_2026_06_25_zero_delayed_object_payloads");
  add_mapping_pair(map, "production_gate_ready", 1);
  add_mapping_string(map, "production_gate_blocker", "");
  add_mapping_string(map, "production_gate_required_users", "1,3,10");
  add_mapping_string(map, "production_gate_required_durations", "smoke,30m");
  add_mapping_pair(map, "production_gate_pressure_evidence_ready", 1);
  add_mapping_string(map, "production_gate_pressure_evidence",
                     "xkx_audit_10_users_30m_2026_06_25_zero_timeouts_zero_gateway_errors");
  add_mapping_string(map, "production_gate_required_modes", "off,audit,enforced");
  add_mapping_string(map, "production_gate_required_scenarios",
                     "login,create,move,chat,inventory,shop,quest,combat,skills,mail,reconnect,"
                     "gateway_callback,socket_callback,heartbeat,callout");
  add_mapping_string(map, "production_gate_evidence_schema", "multicore_production_gate_evidence_v1");
  add_mapping_pair(map, "production_gate_evidence_required", 1);
  add_mapping_pair(map, "production_gate_short_smoke_sufficient", 0);
  add_mapping_string(map, "production_gate_minimum_ready_evidence",
                     "accepted_30m_pressure_scope_final_audit_and_socket_release_handshake");
  add_mapping_pair(map, "production_gate_unclassified_hotspots_required_zero", 1);
  add_mapping_pair(map, "production_gate_direct_cross_owner_writes_required_zero", 1);
  add_mapping_pair(map, "production_gate_context_leaks_required_zero", 1);
  add_mapping_pair(map, "production_gate_future_backlog_required_zero", 1);
  add_mapping_pair(map, "production_gate_same_owner_claim_conflict_required_zero", 1);
  add_mapping_pair(map, "production_gate_gateway_error_delta_required_zero", 1);
  add_mapping_string(map, "production_gate_socket_release_policy",
                     "owner_safe_synchronous_release_acquire_handshake");
  add_mapping_pair(map, "production_gate_socket_release_handshake_ready", 1);
  add_mapping_string(map, "production_gate_socket_release_handshake_evidence",
                     "socket_release_owner_epoch_handshake_contract_v1");
  add_mapping_string(map, "production_gate_report_schema", "xkx_gateway_loadtest_report_v1");
  add_mapping_string(map, "production_gate_report_required_fields",
                     "schema,run_id,mode,users_requested,duration_seconds,scenario,commands_ok,timeouts,"
                     "gateway_metrics_delta,production_gate_observations");
}

mapping_t *gateway_owner_task_contract_mapping() {
  auto *map = allocate_mapping(136);
  add_mapping_pair(map, "contract_version", 1);
  add_mapping_string(map, "input_model", "owner_executor_with_main_fallback");
  add_mapping_string(map, "executor_migration_state", "owner_executor_active");
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
  add_mapping_pair(map, "gateway_command_execute_ready", 1);
  add_mapping_string(map, "gateway_command_execute_task_type", "gateway_command_execute");
  add_mapping_string(map, "gateway_command_execute_route", "owner_main_queue_io_adapter");
  add_mapping_string(map, "gateway_command_execute_fallback_route", "");
  add_mapping_string(map, "gateway_command_execute_policy", "main_thread_io_adapter_until_interactive_detached");
  add_mapping_string(map, "command_consume_model", "owner_owned_snapshot_main_thread_consume");
  add_mapping_pair(map, "command_consume_snapshot_ready", 1);
  add_mapping_pair(map, "command_consume_executor_ready", 0);
  add_mapping_string(map, "command_consume_blocker", kGatewayCommandExecutorActivationBlocker);
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
  add_mapping_string(map, "command_execution_frame_restore_policy", "main_thread_vmcontext_scope");
  add_mapping_pair(map, "command_execution_frame_restore_ready", 1);
  add_mapping_string(map, "command_execution_frame_restore_blocker", "");
  add_mapping_pair(map, "command_execution_frame_executor_ready", 0);
  add_mapping_string(map, "command_stale_guard", "owner_epoch_target_handle_guard");
  add_mapping_string(map, "command_stale_trace_state", "main_stale");
  add_mapping_string(map, "command_stale_target_status", "owner_epoch_mismatch");
  add_mapping_pair(map, "gateway_command_execute_stale_drop_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_context_cleanup_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_session_revalidate_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_reply_queue_main_ready", 1);
  add_mapping_string(map, "command_executor_readiness_gate_model", "all_gates_required_before_owner_executor");
  add_mapping_string(map, "command_executor_next_gate", "");
  add_mapping_string(map, "command_executor_next_blocker", "");
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
  add_mapping_pair(map, "main_required", 0);
  add_mapping_pair(map, "fallback_main_required", 1);
  add_mapping_pair(map, "task_count", static_cast<long>(kGatewayOwnerTaskContracts.size()));
  auto *tasks = gateway_owner_task_contract_entries_array();
  add_mapping_array(map, "tasks", tasks);
  free_array(tasks);
  add_mapping_string(map, "next_blocker", "");
  add_mapping_string(map, "next_blocker_chain", "production_gate_complete");
  add_production_gate_contract_fields(map);
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
  auto *contract = allocate_mapping(71);
  const int owner_thread_vm_enabled = FLUFFOS_OWNER_THREAD_VM != 0;
  add_mapping_pair(contract, "contract_version", 1);
  add_mapping_string(contract, "context_model",
                     owner_thread_vm_enabled ? "thread_local_vm_context" : "single_thread_vm_context");
  add_mapping_string(contract, "execution_state_model", "vm_context_execution_snapshot");
  add_mapping_string(contract, "owner_state_model", "vm_context_owner_scope");
  add_mapping_string(contract, "error_state_model", "vm_context_error_snapshot");
  add_mapping_string(contract, "object_store_model", "owner_local_object_store");
  add_mapping_string(contract, "object_store_off_main_policy", "owner_local_lookup_only");
  add_mapping_pair(contract, "ordinary_lpc_ready", 1);
  add_mapping_string(contract, "ordinary_lpc_blocker", "");
  add_mapping_pair(contract, "controlled_lpc_ready", 1);
  add_mapping_string(contract, "controlled_lpc_policy", "descriptor_manifest_only");
  add_mapping_string(contract, "eval_stack_model",
                     owner_thread_vm_enabled ? "thread_local_owner_execution_stack"
                                             : "single_thread_execution_stack");
  add_mapping_pair(contract, "eval_stack_thread_local", owner_thread_vm_enabled);
  add_mapping_pair(contract, "eval_stack_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "eval_stack_cleared_after_task", 1);
  add_mapping_pair(contract, "eval_stack_owner_local", 1);
  add_mapping_string(contract, "control_stack_model",
                     owner_thread_vm_enabled ? "thread_local_owner_control_stack"
                                             : "single_thread_control_stack");
  add_mapping_pair(contract, "control_stack_thread_local", owner_thread_vm_enabled);
  add_mapping_pair(contract, "control_stack_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "control_stack_cleared_after_task", 1);
  add_mapping_pair(contract, "control_stack_owner_local", 1);
  add_mapping_string(contract, "value_stack_model",
                     owner_thread_vm_enabled ? "thread_local_owner_value_stack"
                                             : "single_thread_value_stack");
  add_mapping_pair(contract, "value_stack_thread_local", owner_thread_vm_enabled);
  add_mapping_pair(contract, "value_stack_lvalue_refs_cleared_after_task", 1);
  add_mapping_pair(contract, "value_stack_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "value_stack_cleared_after_task", 1);
  add_mapping_pair(contract, "value_stack_owner_local", 1);
  add_mapping_string(contract, "apply_return_model",
                     owner_thread_vm_enabled ? "thread_local_owner_apply_return"
                                             : "single_thread_apply_return");
  add_mapping_pair(contract, "apply_return_thread_local", owner_thread_vm_enabled);
  add_mapping_pair(contract, "apply_return_owner_bound_on_executor", 1);
  add_mapping_pair(contract, "apply_return_cleared_after_task", 1);
  add_mapping_pair(contract, "apply_return_owner_local", 1);
  add_mapping_pair(contract, "sprintf_state_thread_local", owner_thread_vm_enabled);
  add_mapping_pair(contract, "sprintf_format_buffers_static_free", 1);
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
  auto *contract = allocate_mapping(156);
  add_mapping_pair(contract, "contract_version", 1);
  add_mapping_string(contract, "boundary_model", "owner_executor_boundary_v1");
  add_mapping_string(contract, "implementation_state", "compilation_unit_active");
  add_mapping_string(contract, "class_name", "OwnerExecutor");
  add_mapping_pair(contract, "class_extracted", 1);
  add_mapping_pair(contract, "module_extracted", 1);
  add_mapping_string(contract, "module_file", "vm/internal/owner_executor.h");
  add_mapping_pair(contract, "compilation_unit_extracted", 1);
  add_mapping_string(contract, "compilation_unit_file", "vm/internal/owner_executor.cc");
  add_mapping_pair(contract, "depends_on_owner_cc_internal_state", 0);
  add_mapping_pair(contract, "owner_runtime_split_ready", 1);
  add_mapping_string(contract, "owner_runtime_split_model", "runtime_v4_modules_with_owner_runtime_coordinator");
  add_mapping_pair(contract, "owner_runtime_v4_hardening_ready", 1);
  add_mapping_pair(contract, "owner_runtime_benchmark_smoke_ready", 1);
  add_mapping_string(contract, "owner_runtime_benchmark_schema", kOwnerRuntimeBenchmarkSchemaV1);
  add_mapping_pair(contract, "owner_runtime_stress_profile_ready", 1);
  add_mapping_string(contract, "owner_runtime_stress_entry", kOwnerRuntimeStressEntry);
  add_mapping_pair(contract, "lpc_modern_runtime_stress_ready", 1);
  add_mapping_string(contract, "lpc_modern_runtime_stress_entry", kLpcModernRuntimeStressEntry);
  add_mapping_pair(contract, "owner_runtime_layering_guard_ready", 1);
  add_mapping_pair(contract, "owner_runtime_coordinator_module_ready", 1);
  add_mapping_string(contract, "owner_runtime_coordinator_file", "vm/internal/owner_runtime_coordinator.cc");
  add_mapping_string(contract, "owner_runtime_store_owner", "OwnerRuntimeCoordinator");
  add_mapping_string(contract, "owner_cc_runtime_role", "runtime_status_facade_and_legacy_glue");
  add_mapping_pair(contract, "lpc_modern_profile_ready", 1);
  add_mapping_string(contract, "lpc_modern_profile_schema", kLpcModernProfileSchemaV1);
  add_mapping_string(contract, "lpc_modern_profile_mode", kLpcModernProfileModeOptIn);
  add_mapping_pair(contract, "lpc_vm_profile_ready", 1);
  add_mapping_string(contract, "lpc_vm_profile_schema", kLpcVmProfileSchemaV1);
  add_mapping_pair(contract, "lpc_vm_profile_default_recording", 0);
  add_mapping_string(contract, "lpc_vm_profile_recording_policy", "explicit_current_thread_only");
  add_mapping_pair(contract, "lpc_vm_benchmark_smoke_ready", 1);
  add_mapping_string(contract, "lpc_vm_benchmark_schema", kLpcVmBenchSchemaV1);
  add_mapping_pair(contract, "lpc_vm_hot_path_profile_ready", 1);
  add_mapping_string(contract, "lpc_vm_hot_path_profile_model",
                     "opcode_efun_call_other_function_pointer_parser_mapping_string_v1");
  add_mapping_pair(contract, "object_store_benchmark_smoke_ready", 1);
  add_mapping_string(contract, "object_store_benchmark_schema", kObjectStoreBenchmarkSchemaV1);
  add_mapping_pair(contract, "lpc_apply_dispatch_cache_probe_ready", 1);
  add_mapping_pair(contract, "lpc_opcode_dispatch_profile_ready", 1);
  add_mapping_pair(contract, "lpc_efun_dispatch_profile_ready", 1);
  add_mapping_pair(contract, "lpc_call_other_profile_ready", 1);
  add_mapping_pair(contract, "lpc_function_pointer_profile_ready", 1);
  add_mapping_pair(contract, "lpc_parser_action_profile_ready", 1);
  add_mapping_pair(contract, "lpc_mapping_string_profile_ready", 1);
  add_mapping_pair(contract, "lpc_dispatch_cache_ready", 1);
  add_mapping_string(contract, "lpc_dispatch_cache_model", "apply_dispatch_thread_local_direct_cache_v1");
  add_mapping_pair(contract, "lpc_jit_experiment_default_off", 1);
  add_mapping_pair(contract, "modern_lpc_pragma_ready", 1);
  add_mapping_pair(contract, "strict_owner_pragma_ready", 1);
  add_mapping_string(contract, "strict_owner_policy", kLpcStrictOwnerPolicyV1);
  add_mapping_pair(contract, "lpcc_owner_audit_ready", 1);
  add_mapping_string(contract, "lpcc_owner_audit_schema", kLpcOwnerAuditSchemaV1);
  add_mapping_pair(contract, "lpcc_owner_audit_cli_ready", 1);
  add_mapping_string(contract, "lpcc_owner_audit_cli", "lpcc --owner-audit --format=json");
  add_mapping_pair(contract, "lpcc_owner_audit_static_scanner_ready", 1);
  add_mapping_pair(contract, "lpc_source_encoding_ready", 1);
  add_mapping_string(contract, "lpc_source_encoding_schema", kLpcSourceEncodingSchemaV1);
  add_mapping_string(contract, "vm_internal_string_encoding", kLpcInternalStringEncoding);
  add_mapping_pair(contract, "session_encoding_contract_ready", 1);
  add_mapping_pair(contract, "gateway_encoding_boundary_ready", 1);
  add_mapping_pair(contract, "encoding_audit_ready", 1);
  add_mapping_pair(contract, "legacy_lpc_default_closed", 1);
  add_mapping_string(contract, "lpc_modern_profile_module_file", "compiler/internal/lpc_modern_profile.cc");
  add_mapping_pair(contract, "owner_safe_future_api_ready", 1);
  add_mapping_pair(contract, "owner_safe_lpc_api_failure_schema_ready", 1);
  add_mapping_string(contract, "owner_safe_lpc_api_failure_schema", "owner_safe_lpc_api_failure_v1");
  add_mapping_string(contract, "owner_safe_lpc_api_return_fields", "success,ok,code,error,reason,api,trace_id");
  add_mapping_pair(contract, "owner_async_api_ready", 1);
  add_mapping_pair(contract, "owner_await_poll_adapter_ready", 1);
  add_mapping_pair(contract, "owner_await_coroutine_runtime_ready", 0);
  add_mapping_pair(contract, "freeze_snapshot_api_ready", 1);
  add_mapping_string(contract, "freeze_snapshot_model", "validated_deep_copy");
  add_mapping_pair(contract, "lpc_value_object_profile_ready", 1);
  add_mapping_string(contract, "lpc_value_object_model", "frozen_snapshot_value_object_v1");
  add_mapping_pair(contract, "lpc_value_object_live_lifecycle_member", 0);
  add_mapping_pair(contract, "lpc_value_object_cross_owner_payload_safe", 1);
  add_mapping_pair(contract, "owner_snapshot_persistence_ready", 1);
  add_mapping_string(contract, "owner_snapshot_persistence_model", "owner_snapshot_serialized_payload_v1");
  add_mapping_string(contract, "owner_snapshot_persistence_adapter", "main_thread_file_adapter");
  add_mapping_pair(contract, "owner_snapshot_direct_save_hot_path_audit_ready", 1);
  add_mapping_pair(contract, "owner_commit_api_ready", 1);
  add_mapping_string(contract, "owner_commit_model", "owner_commit_boundary_record");
  add_mapping_string(contract, "lpc_modern_api_file", "packages/core/vm_owner.cc");
  add_mapping_pair(contract, "owner_task_manifest_module_ready", 1);
  add_mapping_string(contract, "owner_task_manifest_module_file", "vm/internal/owner_task_manifest.cc");
  add_mapping_pair(contract, "owner_trace_store_ready", 1);
  add_mapping_string(contract, "owner_trace_store_file", "vm/internal/owner_trace_store.cc");
  add_mapping_pair(contract, "owner_future_store_ready", 1);
  add_mapping_string(contract, "owner_future_store_file", "vm/internal/owner_future_store.cc");
  add_mapping_pair(contract, "owner_scheduler_state_ready", 1);
  add_mapping_string(contract, "owner_scheduler_state_file", "vm/internal/owner_scheduler_state.cc");
  add_mapping_pair(contract, "owner_metrics_store_ready", 1);
  add_mapping_string(contract, "owner_metrics_store_file", "vm/internal/owner_runtime_metrics.cc");
  add_mapping_pair(contract, "object_store_owner_fast_path_ready", 1);
  add_mapping_pair(contract, "object_store_global_fallback_on_owner_fast_path", 0);
  add_mapping_pair(contract, "object_handle_capability_ready", 1);
  add_mapping_string(contract, "object_handle_capability_model", kVMObjectHandleCapabilityModelV1);
  add_mapping_string(contract, "object_handle_capability_file", "vm/object_handle.h");
  add_mapping_string(contract, "object_handle_permission_intent_default", kVMObjectHandleDefaultPermissionIntent);
  add_mapping_pair(contract, "owner_scheduler_backpressure_ready", 1);
  add_mapping_string(contract, "owner_scheduler_backpressure_strategy", "observe_then_reject_new_tasks");
  add_mapping_pair(contract, "owner_scheduler_max_owner_queue_depth", kOwnerSchedulerMaxOwnerQueueDepth);
  add_mapping_pair(contract, "owner_scheduler_fairness_guard_ready", 1);
  add_mapping_pair(contract, "owner_future_timeout_cancel_drop_cleanup_ready", 1);
  add_mapping_pair(contract, "dependency_manifest_ready", 1);
  add_mapping_pair(contract, "runtime_dependency_contract_version", 1);
  add_mapping_string(contract, "dependency_domains",
                     "owner_scheduler_state,owner_task_manifest,owner_trace_store,owner_future_store,"
                     "owner_runtime_metrics,task_dispatch,vm_context");
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
  add_mapping_string(contract, "compilation_unit_blocker", "");
  add_mapping_pair(contract, "claim_release_boundary_ready", 1);
  add_mapping_pair(contract, "budget_boundary_ready", 1);
  add_mapping_pair(contract, "thread_context_boundary_ready", 1);
  add_mapping_pair(contract, "dispatch_manifest_boundary_ready", 1);
  add_mapping_pair(contract, "same_owner_serial_required", 1);
  add_mapping_pair(contract, "main_required_tasks_excluded", 1);
  add_mapping_pair(contract, "target_handle_messages_main_required", 0);
  add_mapping_pair(contract, "target_handle_messages_executor_safe", 1);
  add_mapping_pair(contract, "compute_result_executor_safe", 1);
  add_mapping_pair(contract, "executor_callback_task_boundary_ready", 1);
  add_mapping_pair(contract, "executor_callback_allowlist_ready", 1);
  add_mapping_pair(contract, "executor_callback_main_adapter_ready", 1);
  add_mapping_pair(contract, "owner_callback_admission_unified", 1);
  add_mapping_pair(contract, "owner_callback_diagnostics_ready", 1);
  add_mapping_string(contract, "owner_callback_diagnostics_schema", kOwnerCallbackDiagnosticsSchemaV1);
  add_mapping_string(contract, "owner_callback_failure_code_schema", kOwnerCallbackFailureCodeSchemaV1);
  add_mapping_string(contract, "owner_callback_drop_reason_schema", kOwnerCallbackDropReasonSchemaV1);
  add_mapping_pair(contract, "owner_callback_allowlist_complete", 1);
  add_mapping_string(contract, "owner_callback_supported_kinds", kOwnerCallbackSupportedKinds);
  add_owner_callback_diagnostic_contract_fields(contract);
  add_mapping_pair(contract, "executor_callback_cleanup_main_required", 1);
  add_mapping_pair(contract, "executor_callback_allowlist_count", owner_executor_callback_allowlist_count());
  add_mapping_string(contract, "executor_callback_allowlist", kOwnerExecutorCallbackAllowlistKinds);
  add_mapping_pair(contract, "heartbeat_owner_executor_ready", 1);
  add_mapping_string(contract, "heartbeat_owner_executor_task_type", "heartbeat");
  add_mapping_string(contract, "heartbeat_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(contract, "heartbeat_owner_executor_fallback_route", "");
  add_mapping_string(contract, "heartbeat_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_pair(contract, "heartbeat_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(contract, "heartbeat_current_object_thread_local", 0);
  add_mapping_pair(contract, "callout_owner_executor_ready", 1);
  add_mapping_string(contract, "callout_owner_executor_task_type", "call_out");
  add_mapping_string(contract, "callout_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(contract, "callout_owner_executor_fallback_route", "");
  add_mapping_string(contract, "callout_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_pair(contract, "callout_owner_executor_expired_handle_detach_ready", 1);
  add_mapping_pair(contract, "callout_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(contract, "callout_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(contract, "callout_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(contract, "async_owner_executor_ready", 1);
  add_mapping_string(contract, "async_owner_executor_task_type", "async_callback");
  add_mapping_string(contract, "async_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(contract, "async_owner_executor_fallback_route", "");
  add_mapping_string(contract, "async_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(contract, "async_owner_executor_result_policy", "frozen_deep_copy_result");
  add_mapping_pair(contract, "async_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(contract, "async_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(contract, "dns_owner_executor_ready", 1);
  add_mapping_string(contract, "dns_owner_executor_task_type", "dns_callback");
  add_mapping_string(contract, "dns_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(contract, "dns_owner_executor_fallback_route", "");
  add_mapping_string(contract, "dns_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(contract, "dns_owner_executor_result_policy", "frozen_deep_copy_result");
  add_mapping_pair(contract, "dns_owner_executor_owner_epoch_capture_ready", 1);
  add_mapping_pair(contract, "dns_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(contract, "dns_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(contract, "socket_owner_executor_ready", 1);
  add_mapping_string(contract, "socket_owner_executor_task_type", "socket_callback");
  add_mapping_string(contract, "socket_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(contract, "socket_owner_executor_fallback_route", "");
  add_mapping_string(contract, "socket_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(contract, "socket_owner_executor_result_policy", "frozen_deep_copy_args");
  add_mapping_pair(contract, "socket_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(contract, "socket_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(contract, "socket_release_main_required", 0);
  add_mapping_pair(contract, "socket_release_owner_safe_handshake_ready", 1);
  add_mapping_string(contract, "socket_release_owner_safe_handshake_policy",
                     "synchronous_release_acquire_owner_epoch_guard");
  add_mapping_pair(contract, "socket_release_owner_epoch_guard_ready", 1);
  add_mapping_pair(contract, "gateway_command_rejected", 0);
  add_mapping_pair(contract, "gateway_command_executor_activation_ready", 1);
  add_mapping_pair(contract, "gateway_command_execute_ready", 1);
  add_mapping_string(contract, "gateway_command_execute_task_type", "gateway_command_execute");
  add_mapping_string(contract, "gateway_command_execute_route", "owner_main_queue_io_adapter");
  add_mapping_string(contract, "gateway_command_execute_fallback_route", "");
  add_mapping_string(contract, "gateway_command_execute_policy", "main_thread_io_adapter_until_interactive_detached");
  add_mapping_string(contract, "gateway_command_execute_payload_policy", "owner_private_command_snapshot");
  add_mapping_pair(contract, "gateway_command_execute_reply_queue_main_ready", 1);
  add_mapping_pair(contract, "gateway_command_execute_stale_drop_ready", 1);
  add_mapping_pair(contract, "gateway_command_execute_context_cleanup_ready", 1);
  add_mapping_pair(contract, "gateway_command_execute_session_revalidate_ready", 1);
  add_mapping_pair(contract, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(contract, "ordinary_lpc_explicit_open_required", 1);
  add_mapping_string(contract, "ordinary_lpc_policy", "explicit_open_same_owner_only");
  add_mapping_pair(contract, "lpc_surface_expanded", 0);
  add_mapping_pair(contract, "registered_owner_task_domains_ready", 1);
  add_mapping_pair(contract, "owner_service_shard_registry_ready", 1);
  add_mapping_string(contract, "owner_service_shard_registry_schema", kOwnerServiceShardRegistrySchemaV1);
  add_mapping_pair(contract, "owner_service_shard_domain_count",
                   static_cast<long>(owner_service_shard_descriptors().size()));
  add_mapping_string(contract, "owner_service_shard_domains", owner_service_shard_domain_list().c_str());
  add_mapping_pair(contract, "owner_service_registry_lpc_domain_alignment_ready",
                   owner_service_registry_matches_lpc_domains() ? 1 : 0);
  add_mapping_pair(contract, "owner_tick_group_scheduler_ready", 1);
  add_mapping_string(contract, "owner_tick_group_scheduler_schema", kOwnerTickGroupSchedulerSchemaV1);
  add_mapping_pair(contract, "owner_tick_group_count", static_cast<long>(owner_tick_group_descriptors().size()));
  add_mapping_string(contract, "owner_tick_groups", owner_tick_group_name_list().c_str());
  add_mapping_pair(contract, "owner_scheduler_tuning_config_ready", 1);
  add_mapping_string(contract, "owner_scheduler_tuning_config_schema", kOwnerSchedulerTuningConfigSchemaV1);
  add_mapping_string(contract, "owner_scheduler_tick_group_budget_source", "owner_service_registry");
  add_mapping_pair(contract, "owner_scheduler_priority_groups_ready", 1);
  add_mapping_pair(contract, "owner_scheduler_tick_group_backpressure_ready", 1);
  add_mapping_pair(contract, "owner_scheduler_starvation_guard_ready", 1);
  add_mapping_pair(contract, "target_owner_message_executor_ready", 1);
  add_mapping_pair(contract, "normal_path_main_fallback_count", 0);
  add_mapping_pair(contract, "normal_path_main_fallback_ready", 1);
  add_mapping_pair(contract, "main_fallback_policy_ready", 1);
  add_mapping_string(contract, "main_fallback_classification", "explicit_policy");
  add_mapping_pair(contract, "session_fifo_contract_ready", 1);
  add_mapping_pair(contract, "gateway_io_adapter_only_ready", 1);
  add_mapping_string(contract, "gateway_io_boundary", "main_thread_io_adapter");
  add_mapping_pair(contract, "gateway_low_overhead_latency_probe_ready", 1);
  add_mapping_string(contract, "gateway_latency_probe_source", "gateway_status_internal");
  add_mapping_string(contract, "gateway_latency_probe_fields",
                     "receive_decode,receive_payload_copy,receive_enqueue_to_dispatch,receive_apply,"
                     "command_enqueue_to_dispatch,command_execute,"
                     "receive_main_queue_depth,deferred_main_drain_wait,"
                     "reply_enqueue_to_dispatch,reply_execute,output_enqueue_to_dispatch,output_execute,main_drain");
  add_mapping_pair(contract, "callback_payload_strict_ready", 1);
  add_mapping_pair(contract, "service_shard_executor_ready", 1);
  add_mapping_pair(contract, "domain_task_registry_mudlib_aligned", 1);
  add_mapping_pair(contract, "keyed_service_shard_ready", 1);
  add_mapping_pair(contract, "hot_path_service_owner_single_point", owner_service_hot_path_service_owner_count());
  add_mapping_pair(contract, "hot_path_service_shard_count", owner_service_hot_path_service_shard_count());
  add_mapping_string(contract, "owner_service_shard_policy_model", "keyed_service_shard_for_hot_paths");
  add_mapping_pair(contract, "target_owner_message_main_fallback", 0);
  add_mapping_pair(contract, "production_perfect_contract_ready", 1);
  add_mapping_pair(contract, "facade_only_runtime_claims", 0);
  add_mapping_string(contract, "next_refactor_target", "");
  add_production_gate_contract_fields(contract);
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
      "main_required_callback", "owner_main_queue_callback_adapter", 0, 1, 0,
      "driver callback closures require owner admission and run on the main callback adapter");
  auto *executor_callback_contracts = owner_executor_callback_contracts_array();
  add_mapping_array(executor_callback_allowlist, "contracts", executor_callback_contracts);
  free_array(executor_callback_contracts);
  add_mapping_owned_mapping(contract, "owner_executor_callback_allowlist", executor_callback_allowlist);
  add_mapping_owned_mapping(contract, "owner_message_mailbox",
                            owner_task_route_contract_entry(owner_task_executor_safe_contract()));
  add_mapping_owned_mapping(contract, "owner_message_target_handle",
                            owner_task_route_contract_entry(owner_task_target_handle_contract()));
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
    return owner_task_target_handle_contract();
  }
  return owner_task_executor_safe_contract();
}

mapping_t *owner_mailbox_task_mapping(const OwnerMailboxTask &task) {
  auto *map = allocate_mapping(48);
  const auto &descriptor = owner_executor_task_descriptor(task);
  const auto target_message = task.task_type == "owner_message" && task.has_target_handle;
  const auto &message_route_contract = owner_task_route_contract(task);
  const auto &route_contract = target_message ? message_route_contract : owner_task_executor_safe_contract();
  const auto *task_executor_mode = target_message ? message_route_contract.executor_mode : descriptor.executor_mode;
  const auto *executor_mode = route_contract.executor_mode;
  const auto *route = target_message ? message_route_contract.route : descriptor.route;
  const auto *contract_key = target_message ? "owner_message_target_handle" : descriptor.contract_key;
  const auto executor_runnable = target_message ? 1 : descriptor.executor_runnable;
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
  add_mapping_pair(map, "manifest_version", task.manifest_version);
  add_mapping_string(map, "manifest_schema", task.manifest_schema.c_str());
  add_mapping_string(map, "task_kind", task.task_kind.c_str());
  add_mapping_string(map, "payload_policy", task.payload_policy.c_str());
  add_mapping_string(map, "cleanup_policy", task.cleanup_policy.c_str());
  add_mapping_string(map, "reply_future_policy", task.reply_future_policy.c_str());
  add_mapping_string(map, "admission_policy", task.admission_policy.c_str());
  add_mapping_string(map, "admission_state", task.admission_state.c_str());
  add_mapping_string(map, "trace_schema", task.trace_schema.c_str());
  add_mapping_string(map, "tick_group", task.tick_group.c_str());
  add_mapping_pair(map, "scheduler_priority", task.scheduler_priority);
  add_mapping_pair(map, "scheduler_budget", task.scheduler_budget);
  add_mapping_pair(map, "scheduler_max_queue_depth", task.scheduler_max_queue_depth);
  add_mapping_string(map, "backpressure_policy", task.backpressure_policy.c_str());
  add_mapping_pair(map, "trace_schema_version", 2);
  add_mapping_string(map, "diagnostic_schema", kOwnerCallbackDiagnosticsSchemaV1);
  add_mapping_string(map, "failure_code_schema", kOwnerCallbackFailureCodeSchemaV1);
  add_mapping_string(map, "drop_reason_schema", kOwnerCallbackDropReasonSchemaV1);
  add_mapping_string(map, "failure_code", owner_task_failure_code("", task.admission_state));
  add_mapping_string(map, "failure_reason", owner_task_failure_reason("", task.admission_state));
  add_mapping_string(map, "drop_reason", owner_task_drop_reason("", task.admission_state));
  add_mapping_string(map, "payload_policy_code", task.payload_policy.c_str());
  add_mapping_pair(map, "callback_payload_strict_required",
                   descriptor.dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback ? 1 : 0);
  add_mapping_pair(map, "deadline_ms", static_cast<long>(task.deadline_ms));
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
  auto *map = allocate_mapping(61);
  add_mapping_pair(map, "trace_id", static_cast<long>(trace.trace_id));
  add_mapping_string(map, "trace_model", "owner_task_lifecycle_event");
  add_mapping_pair(map, "task_id", static_cast<long>(trace.task_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(trace.owner_epoch));
  add_mapping_pair(map, "manifest_version", trace.manifest_version);
  add_mapping_pair(map, "deadline_ms", static_cast<long>(trace.deadline_ms));
  add_mapping_string(map, "owner_id", trace.owner_id.c_str());
  add_mapping_string(map, "task_type", trace.task_type.c_str());
  add_mapping_string(map, "task_key", trace.task_key.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  add_mapping_string(map, "target_object", trace.target_object.c_str());
  add_mapping_string(map, "manifest_schema", trace.manifest_schema.c_str());
  add_mapping_string(map, "task_kind", trace.task_kind.c_str());
  add_mapping_string(map, "payload_policy", trace.payload_policy.c_str());
  add_mapping_string(map, "cleanup_policy", trace.cleanup_policy.c_str());
  add_mapping_string(map, "reply_future_policy", trace.reply_future_policy.c_str());
  add_mapping_string(map, "admission_policy", trace.admission_policy.c_str());
  add_mapping_string(map, "admission_state", trace.admission_state.c_str());
  add_mapping_string(map, "trace_schema", trace.trace_schema.c_str());
  add_mapping_string(map, "tick_group", trace.tick_group.c_str());
  add_mapping_pair(map, "scheduler_priority", trace.scheduler_priority);
  add_mapping_pair(map, "scheduler_budget", trace.scheduler_budget);
  add_mapping_pair(map, "scheduler_max_queue_depth", trace.scheduler_max_queue_depth);
  add_mapping_string(map, "backpressure_policy", trace.backpressure_policy.c_str());
  add_mapping_pair(map, "trace_schema_version", 2);
  add_mapping_string(map, "diagnostic_schema", kOwnerCallbackDiagnosticsSchemaV1);
  add_mapping_string(map, "failure_code_schema", kOwnerCallbackFailureCodeSchemaV1);
  add_mapping_string(map, "drop_reason_schema", kOwnerCallbackDropReasonSchemaV1);
  add_mapping_string(map, "failure_code", owner_task_failure_code(trace.state, trace.admission_state));
  add_mapping_string(map, "failure_reason", owner_task_failure_reason(trace.state, trace.admission_state));
  add_mapping_string(map, "drop_reason", owner_task_drop_reason(trace.state, trace.admission_state));
  add_mapping_string(map, "payload_policy_code", trace.payload_policy.c_str());
  add_mapping_pair(map, "callback_payload_strict_required",
                   trace.task_kind == owner_executor_dispatch_kind_name(OwnerExecutorDispatchKind::ExecutorCallback) ? 1 : 0);
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
  add_mapping_string(map, "main_task_policy", trace.main_task_policy.c_str());
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

void enqueue_owner_executor_callback_cleanup_locked(OwnerMainTask &task) {
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

struct OwnerTaskAdmissionResult {
  bool accepted{false};
};

OwnerTaskAdmissionResult reject_owner_executor_callback_admission_locked(OwnerMailboxTask &task, const char *state,
                                                                         const char *admission_state,
                                                                         bool dropped) {
  task.admission_state = normalize_task_text(admission_state, "rejected");
  append_owner_task_trace(task, state);
  if (dropped) {
    owner_executor_admission_dropped.fetch_add(1, std::memory_order_relaxed);
    owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
    owner_executor_stale_drop.fetch_add(1, std::memory_order_relaxed);
    enqueue_owner_executor_callback_cleanup_locked(task);
  } else {
    owner_executor_admission_rejected.fetch_add(1, std::memory_order_relaxed);
  }
  return OwnerTaskAdmissionResult{false};
}

OwnerTaskAdmissionResult admit_owner_executor_callback_task_locked(OwnerMailboxTask &task) {
  apply_owner_task_manifest_v2(task);

  const auto *descriptor = find_owner_executor_task_descriptor(task.task_type);
  auto callback_route_allowed =
      descriptor && descriptor->dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback &&
      !descriptor->rejected &&
      ((descriptor->executor_runnable != 0 && descriptor->executor_safe != 0) ||
       (descriptor->main_required != 0 && descriptor->requires_owner_main_queue != 0));
  if (!callback_route_allowed) {
    return reject_owner_executor_callback_admission_locked(task, "executor_callback_admission_rejected",
                                                          "rejected_callback_not_allowlisted", false);
  }

  if (!task.callback || !task.has_target_handle || !task.target || !task.target_handle.valid ||
      task.owner_id.empty()) {
    return reject_owner_executor_callback_admission_locked(task, "executor_callback_admission_dropped",
                                                          "dropped_callback_invalid_target", true);
  }

  task.admission_state = "accepted";
  owner_executor_admission_accepted.fetch_add(1, std::memory_order_relaxed);
  append_owner_task_trace(task, "executor_callback_admission_accepted");
  return OwnerTaskAdmissionResult{true};
}

bool owner_executor_callback_main_adapter_required(const OwnerMailboxTask &task) {
  const auto &descriptor = owner_executor_task_descriptor(task);
  return descriptor.dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback &&
         descriptor.main_required != 0 &&
         descriptor.requires_owner_main_queue != 0;
}

bool enqueue_owner_executor_callback_main_adapter_locked(OwnerMailboxTask &task) {
  if (!task.callback || !task.target) {
    return false;
  }

  OwnerMainTask main_task;
  main_task.task_id = task.task_id;
  main_task.sequence = task.sequence;
  main_task.owner_epoch = task.owner_epoch;
  main_task.owner_id = task.owner_id;
  main_task.task_type = task.task_type;
  main_task.task_key = task.task_key;
  main_task.future_state = task.future_state;
  main_task.future_error = task.future_error;
  main_task.target_object = task.target_object;
  main_task.target = task.target;
  main_task.has_target_handle = task.has_target_handle;
  main_task.target_handle = task.target_handle;
  main_task.main_task_policy = VM_OWNER_MAIN_TASK_IO_ADAPTER;
  main_task.callback = std::move(task.callback);
  main_task.drop_callback = std::move(task.drop_callback);

  append_owner_task_trace(task, "executor_callback_queued");
  append_owner_task_trace(task, "executor_callback_main_adapter_queued");
  append_owner_task_trace(main_task, "main_queued");
  owner_scheduler_state.enqueue_main_task(std::move(main_task));
  owner_main_queued.fetch_add(1, std::memory_order_relaxed);
  owner_main_io_adapter_count.fetch_add(1, std::memory_order_relaxed);

  task.target = nullptr;
  task.has_target_handle = false;
  task.callback = nullptr;
  task.drop_callback = nullptr;
  return true;
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
  auto *map = allocate_mapping(18);
  add_mapping_pair(map, "trace_id", static_cast<long>(trace.trace_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_string(map, "trace_model", "owner_executor_scheduler_event");
  add_mapping_string(map, "trace_schema", kOwnerExecutorTraceSchemaV2);
  add_mapping_string(map, "owner_task_manifest_schema", kOwnerTaskManifestSchemaV2);
  add_mapping_string(map, "admission_policy", kOwnerTaskAdmissionPolicyV2);
  add_mapping_string(map, "executor_contract_version", kOwnerExecutorContractVersion);
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
  trace.task_id = task_id;
  trace.sequence = sequence;
  trace.owner_epoch = owner_epoch;
  trace.owner_id = owner_id;
  trace.task_type = task_type;
  trace.task_key = task_key;
  trace.state = normalize_task_text(state, "observed");
  return owner_trace_store.append_task(std::move(trace));
}

uint64_t append_owner_task_trace(const OwnerMailboxTask &task, const char *state) {
  OwnerTaskTrace trace;
  trace.task_id = task.task_id;
  trace.sequence = task.sequence;
  trace.owner_epoch = task.owner_epoch;
  trace.manifest_version = task.manifest_version;
  trace.deadline_ms = task.deadline_ms;
  trace.target_handle = task.target_handle;
  trace.payload = task.payload;
  trace.owner_id = task.owner_id;
  trace.task_type = task.task_type;
  trace.task_key = task.task_key;
  trace.state = normalize_task_text(state, "observed");
  trace.target_object = task.target_object.empty() ? owner_object_name(task.target) : task.target_object;
  trace.manifest_schema = task.manifest_schema;
  trace.task_kind = task.task_kind;
  trace.payload_policy = task.payload_policy;
  trace.cleanup_policy = task.cleanup_policy;
  trace.reply_future_policy = task.reply_future_policy;
  trace.admission_policy = task.admission_policy;
  trace.admission_state = task.admission_state;
  trace.trace_schema = task.trace_schema;
  trace.tick_group = task.tick_group;
  trace.scheduler_priority = task.scheduler_priority;
  trace.scheduler_budget = task.scheduler_budget;
  trace.scheduler_max_queue_depth = task.scheduler_max_queue_depth;
  trace.backpressure_policy = task.backpressure_policy;
  trace.has_target_handle = task.has_target_handle;
  return owner_trace_store.append_task(std::move(trace));
}

const char *owner_main_task_policy_name(VMOwnerMainTaskPolicy policy) {
  switch (policy) {
    case VM_OWNER_MAIN_TASK_EXPLICIT_FALLBACK:
      return "explicit_fallback";
    case VM_OWNER_MAIN_TASK_OFF_MODE_FALLBACK:
      return "off_mode_fallback";
    case VM_OWNER_MAIN_TASK_IO_ADAPTER:
      return "io_adapter";
    case VM_OWNER_MAIN_TASK_CLEANUP_ADAPTER:
      return "cleanup_adapter";
    case VM_OWNER_MAIN_TASK_NORMAL_PATH_FALLBACK:
      return "normal_path_fallback";
  }
  return "explicit_fallback";
}

uint64_t append_owner_task_trace(const OwnerMainTask &task, const char *state) {
  OwnerTaskTrace trace;
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
  trace.main_task_policy = owner_main_task_policy_name(task.main_task_policy);
  trace.has_target_handle = task.has_target_handle;
  const auto &descriptor = owner_executor_task_descriptor(task);
  if (descriptor.dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback) {
    trace.manifest_version = 2;
    trace.manifest_schema = kOwnerTaskManifestSchemaV2;
    trace.task_kind = owner_executor_dispatch_kind_name(descriptor.dispatch_kind);
    trace.payload_policy =
        owner_manifest_payload_policy(descriptor.dispatch_kind, task.has_target_handle, task.payload != nullptr);
    trace.cleanup_policy = owner_manifest_cleanup_policy(descriptor.dispatch_kind, task.has_target_handle);
    trace.reply_future_policy = owner_manifest_reply_future_policy(descriptor.dispatch_kind);
    trace.admission_policy = kOwnerTaskAdmissionPolicyV2;
    trace.admission_state = descriptor.rejected ? "accepted_dispatch_rejected" : "accepted";
    trace.trace_schema = kOwnerExecutorTraceSchemaV2;
    const auto &tick_group = owner_tick_group_for_executor_task(task.task_type.c_str());
    trace.tick_group = tick_group.name;
    trace.scheduler_priority = tick_group.priority;
    trace.scheduler_budget = tick_group.budget;
    trace.scheduler_max_queue_depth = tick_group.max_queue_depth;
    trace.backpressure_policy = tick_group.backpressure_policy;
  }
  return owner_trace_store.append_task(std::move(trace));
}

uint64_t append_owner_task_trace_threadsafe(const OwnerMailboxTask &task, const char *state) {
  return append_owner_task_trace(task, state);
}

uint64_t append_owner_executor_trace_locked(const std::string &owner_id, const char *event) {
  OwnerExecutorTrace trace;
  trace.owner_id = owner_id;
  trace.event = normalize_task_text(event, "observed");
  trace.backlog = owner_mailbox_depth(owner_id);
  trace.runnable_backlog = owner_executor_runnable_queue_depth(owner_id);
  trace.safe_backlog = owner_executor_safe_queue_depth(owner_id);
  trace.main_required_backlog = owner_main_required_queue_depth(owner_id);
  trace.runnable_owners = owner_runnable_owner_count();
  trace.claimed_owners = owner_scheduler_state.active_owner_count();
  trace.active_claims = owner_scheduler_state.active_claim_count();
  return owner_trace_store.append_executor(std::move(trace));
}

mapping_t *owner_future_mapping(const OwnerFutureRecord &record) {
  auto target_status = record.has_target_handle ? vm_object_handle_resolve_status(record.target_handle).status
                                                : VMObjectHandleResolveStatus::kCurrent;
  auto *map = allocate_mapping(28);
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
  add_mapping_pair(map, "created_at_ms", static_cast<long>(record.created_at_ms));
  add_mapping_pair(map, "deadline_ms", static_cast<long>(record.deadline_ms));
  add_mapping_pair(map, "terminal_at_ns", static_cast<long>(record.terminal_at_ns));
  add_mapping_pair(map, "cancelled", record.cancelled ? 1 : 0);
  add_mapping_pair(map, "timed_out", record.timed_out ? 1 : 0);
  add_mapping_pair(map, "terminal_cleanup_required", record.terminal_cleanup_required ? 1 : 0);
  add_mapping_string(map, "future_policy", "owner_future_timeout_cancel_v2");
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

void update_owner_message_trace_state_for_task_locked(uint64_t target_task_id, const char *state,
                                                      const char *result_key, const char *error,
                                                      bool frozen_result,
                                                      VMObjectHandleResolveStatus target_handle_status);

void complete_owner_future_locked(uint64_t future_id, const char *state, const char *result_key, const char *error,
                                  std::shared_ptr<VMFrozenValue> result = nullptr) {
  auto completion = owner_future_store.complete(future_id, state, result_key, error, std::move(result));
  if (!completion) {
    return;
  }
  update_owner_message_trace_state_for_task_locked(
      completion->record.target_task_id, completion->record.state.c_str(), completion->record.result_key.c_str(),
      completion->record.error.c_str(), completion->completed_with_frozen_result, completion->target_status);
  notify_owner_future_terminal();
}

void update_owner_message_trace_state_for_task_locked(uint64_t target_task_id, const char *state,
                                                      const char *result_key, const char *error,
                                                      bool frozen_result,
                                                      VMObjectHandleResolveStatus target_handle_status) {
  owner_trace_store.update_message_state_for_task(target_task_id, state, result_key, error, frozen_result,
                                                  target_handle_status);
}

void complete_owner_future_for_task_locked(uint64_t target_task_id, const char *state, const char *result_key,
                                            const char *error,
                                            std::shared_ptr<VMFrozenValue> result = nullptr) {
  auto completion = owner_future_store.complete_for_task(target_task_id, state, result_key, error, std::move(result));
  if (!completion) {
    return;
  }
  update_owner_message_trace_state_for_task_locked(
      target_task_id, completion->record.state.c_str(), completion->record.result_key.c_str(),
      completion->record.error.c_str(), completion->completed_with_frozen_result, completion->target_status);
  notify_owner_future_terminal();
}

void complete_owner_future_for_task_threadsafe(uint64_t target_task_id, const char *state, const char *result_key,
                                               const char *error,
                                               std::shared_ptr<VMFrozenValue> result = nullptr) {
  complete_owner_future_for_task_locked(target_task_id, state, result_key, error, std::move(result));
}

mapping_t *mark_owner_future_failed_terminal(uint64_t future_id, const char *reason, bool cancelled, bool timed_out) {
  auto result = owner_future_store.fail_terminal(future_id, reason, cancelled, timed_out);
  if (!result.found) {
    auto *map = allocate_mapping(10);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", static_cast<long>(future_id));
    add_mapping_string(map, "state", "unknown");
    add_mapping_string(map, "error", "unknown future");
    add_mapping_pair(map, "cancelled", cancelled ? 1 : 0);
    add_mapping_pair(map, "timed_out", timed_out ? 1 : 0);
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    add_mapping_pair(map, "terminal_cleanup_required", 0);
    add_mapping_string(map, "future_policy", "owner_future_timeout_cancel_v2");
    return map;
  }

  if (result.changed) {
    update_owner_message_trace_state_for_task_locked(result.record.target_task_id, result.record.state.c_str(),
                                                     result.record.result_key.c_str(), result.record.error.c_str(),
                                                     false, result.target_status);
    if (cancelled) {
      owner_executor_future_cancelled.fetch_add(1, std::memory_order_relaxed);
    }
    if (timed_out) {
      owner_executor_future_timeout.fetch_add(1, std::memory_order_relaxed);
    }
    notify_owner_future_terminal();
  }
  return owner_future_mapping(result.record);
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
  complete_owner_future_for_task_locked(task.task_id, state, result_key, error, std::move(result));
}

void complete_owner_main_message_task_threadsafe(const OwnerMainTask &task, const char *state,
                                                 const char *result_key, const char *error,
                                                 std::shared_ptr<VMFrozenValue> result = nullptr) {
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
    clear_owner_apply_return();
    complete_owner_main_message_task_threadsafe(task, "failed", "", "lpc call failed");
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  clear_owner_apply_return();
  if (!frozen_result) {
    complete_owner_main_message_task_threadsafe(task, "failed", "", "owner async result must be frozen data");
    return;
  }
  complete_owner_main_message_task_threadsafe(task, "completed", task.task_key.c_str(), "",
                                             std::move(frozen_result));
}

void dispatch_owner_message_in_current_context(const OwnerMailboxTask &task) {
  auto dispatch_started_ns = owner_now_ns();
  if (task.has_target_handle && task.enqueued_at_ns > 0 && dispatch_started_ns >= task.enqueued_at_ns) {
    owner_record_latency(owner_async_queue_wait_ns_total, owner_async_queue_wait_ns_max,
                         owner_async_queue_wait_samples, dispatch_started_ns - task.enqueued_at_ns);
  }
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
  VMExecutionState execution;
  execution.current_object = target;
  execution.current_prog = target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  set_eval(max_eval_cost);
  int num_args = 0;
  if (task.payload) {
    push_svalue(&task.payload->value);
    num_args = 1;
  }
  auto lpc_started_ns = owner_now_ns();
  auto lpc_cpu_started_ns = get_current_thread_cpu_time_ns();
  auto *result = safe_apply(task.task_key.c_str(), target, num_args, ORIGIN_DRIVER);
  owner_record_thread_cpu(owner_async_lpc_execute_thread_cpu_ns_total,
                          owner_async_lpc_execute_thread_cpu_unavailable,
                          lpc_cpu_started_ns);
  owner_record_latency(owner_async_lpc_execute_ns_total, owner_async_lpc_execute_ns_max,
                       owner_async_lpc_execute_samples, owner_now_ns() - lpc_started_ns);
  auto completion_started_ns = owner_now_ns();
  auto completion_cpu_started_ns = get_current_thread_cpu_time_ns();
  if (!result) {
    clear_owner_apply_return();
    complete_owner_message_task_threadsafe(task, "failed", "", "lpc call failed");
    owner_record_thread_cpu(owner_async_result_completion_thread_cpu_ns_total,
                            owner_async_result_completion_thread_cpu_unavailable,
                            completion_cpu_started_ns);
    owner_record_latency(owner_async_result_completion_ns_total, owner_async_result_completion_ns_max,
                         owner_async_result_completion_samples, owner_now_ns() - completion_started_ns);
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  clear_owner_apply_return();
  if (!frozen_result) {
    complete_owner_message_task_threadsafe(task, "failed", "", "owner async result must be frozen data");
    owner_record_thread_cpu(owner_async_result_completion_thread_cpu_ns_total,
                            owner_async_result_completion_thread_cpu_unavailable,
                            completion_cpu_started_ns);
    owner_record_latency(owner_async_result_completion_ns_total, owner_async_result_completion_ns_max,
                         owner_async_result_completion_samples, owner_now_ns() - completion_started_ns);
    return;
  }
  complete_owner_message_task_threadsafe(task, "completed", task.task_key.c_str(), "", std::move(frozen_result));
  owner_record_thread_cpu(owner_async_result_completion_thread_cpu_ns_total,
                          owner_async_result_completion_thread_cpu_unavailable,
                          completion_cpu_started_ns);
  owner_record_latency(owner_async_result_completion_ns_total, owner_async_result_completion_ns_max,
                       owner_async_result_completion_samples, owner_now_ns() - completion_started_ns);
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

bool owner_task_requires_main_drain(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return owner_task_target_handle_contract().main_required != 0;
  }
  return owner_executor_task_descriptor(task).main_required != 0;
}

bool owner_task_executor_runnable(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return owner_task_target_handle_contract().executor_safe != 0;
  }
  return owner_executor_task_descriptor(task).executor_runnable != 0;
}

bool owner_task_executor_safe(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message" && task.has_target_handle) {
    return owner_task_target_handle_contract().executor_safe != 0;
  }
  return owner_executor_task_descriptor(task).executor_safe != 0;
}

long owner_executor_runnable_queue_depth(const std::string &owner_id) {
  return owner_scheduler_state.mailbox_depth_if(owner_id, owner_task_executor_runnable);
}

long owner_executor_safe_queue_depth(const std::string &owner_id) {
  return owner_scheduler_state.mailbox_depth_if(owner_id, owner_task_executor_safe);
}

long owner_main_required_queue_depth(const std::string &owner_id) {
  return owner_scheduler_state.mailbox_depth_if(owner_id, owner_task_requires_main_drain);
}

void record_owner_executor_budget_yield_locked(const std::string &owner_id) {
  owner_executor_budget_yields.fetch_add(1, std::memory_order_relaxed);
  owner_executor_last_budget_yield_owner = owner_id;
  owner_executor_last_budget_yield_backlog = owner_mailbox_depth(owner_id);
  owner_executor_last_budget_yield_safe_backlog = owner_executor_safe_queue_depth(owner_id);
  append_owner_executor_trace_locked(owner_id, "budget_yield");
}

long owner_executor_runnable_queue_depth() {
  return owner_scheduler_state.mailbox_total_depth_if(owner_task_executor_runnable);
}

long owner_executor_safe_queue_depth() {
  return owner_scheduler_state.mailbox_total_depth_if(owner_task_executor_safe);
}

long owner_main_required_queue_depth() {
  return owner_scheduler_state.mailbox_total_depth_if(owner_task_requires_main_drain);
}

long owner_runnable_owner_count() {
  return owner_scheduler_state.runnable_owner_count(owner_task_executor_runnable);
}

long owner_main_runnable_owner_count() {
  return owner_scheduler_state.main_runnable_owner_count();
}

void add_owner_scheduler_backpressure_fields(mapping_t *map, const OwnerQueueFairnessSnapshot &snapshot) {
  add_mapping_pair(map, "owner_scheduler_backpressure_ready", 1);
  add_mapping_string(map, "owner_scheduler_backpressure_strategy", "observe_then_reject_new_tasks");
  add_mapping_pair(map, "owner_scheduler_max_owner_queue_depth", kOwnerSchedulerMaxOwnerQueueDepth);
  add_mapping_pair(map, "owner_scheduler_backpressure_high_watermark",
                   kOwnerSchedulerBackpressureHighWatermark);
  add_mapping_pair(map, "owner_scheduler_max_owner_backlog", snapshot.max_owner_backlog);
  add_mapping_pair(map, "owner_scheduler_backpressure_over_limit",
                   snapshot.max_owner_backlog > kOwnerSchedulerMaxOwnerQueueDepth ? 1 : 0);
  add_mapping_pair(map, "owner_scheduler_backpressure_high_watermark_exceeded",
                   snapshot.max_owner_backlog >= kOwnerSchedulerBackpressureHighWatermark ? 1 : 0);
  add_mapping_pair(map, "owner_scheduler_fairness_guard_ready", 1);
}

mapping_t *owner_queue_fairness_mapping() {
  auto snapshot = owner_scheduler_state.fairness_snapshot(owner_task_executor_runnable, owner_task_executor_safe,
                                                          owner_task_requires_main_drain);

  auto *map = allocate_mapping(23);
  add_mapping_pair(map, "owner_mailbox_owner_count", snapshot.mailbox_owner_count);
  add_mapping_pair(map, "executor_ready_owner_count", snapshot.executor_ready_owner_count);
  add_mapping_pair(map, "executor_claim_blocked_owner_count", snapshot.executor_claim_blocked_owner_count);
  add_mapping_pair(map, "executor_runnable_owner_count", snapshot.executor_runnable_owner_count);
  add_mapping_pair(map, "executor_runnable_claim_blocked_owner_count",
                   snapshot.executor_runnable_claim_blocked_owner_count);
  add_mapping_pair(map, "main_required_only_owner_count", snapshot.main_required_only_owner_count);
  add_mapping_pair(map, "mixed_backlog_owner_count", snapshot.mixed_backlog_owner_count);
  add_mapping_pair(map, "max_owner_backlog", snapshot.max_owner_backlog);
  add_mapping_pair(map, "max_executor_runnable_backlog", snapshot.max_executor_runnable_backlog);
  add_mapping_pair(map, "max_executor_safe_backlog", snapshot.max_executor_safe_backlog);
  add_mapping_pair(map, "max_main_required_backlog", snapshot.max_main_required_backlog);
  add_mapping_pair(map, "owner_main_queue_owner_count", snapshot.main_queue_owner_count);
  add_mapping_pair(map, "main_ready_owner_count", snapshot.main_ready_owner_count);
  add_mapping_pair(map, "main_claim_blocked_owner_count", snapshot.main_claim_blocked_owner_count);
  add_mapping_pair(map, "max_owner_main_queue_depth", snapshot.max_owner_main_queue_depth);
  add_owner_scheduler_backpressure_fields(map, snapshot);
  return map;
}

void store_max_atomic(std::atomic<uint64_t> &target, uint64_t value) {
  auto current = target.load(std::memory_order_relaxed);
  while (value > current &&
         !target.compare_exchange_weak(current, value, std::memory_order_relaxed, std::memory_order_relaxed)) {
  }
}

bool enqueue_owner_task_locked(OwnerMailboxTask &task, const std::string &owner_id, bool *notify_owner_thread,
                               bool admission_recorded = false) {
  if (task.manifest_version == 0 || task.admission_policy.empty()) {
    apply_owner_task_manifest_v2(task);
  }
  if (owner_scheduler_state.mailbox_depth(owner_id) >= kOwnerSchedulerMaxOwnerQueueDepth) {
    task.admission_state = "rejected_backpressure";
    append_owner_task_trace(task, "backpressure_rejected");
    owner_executor_backpressure_rejected.fetch_add(1, std::memory_order_relaxed);
    if (task.drop_callback) {
      owner_executor_admission_dropped.fetch_add(1, std::memory_order_relaxed);
      owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
      enqueue_owner_executor_callback_cleanup_locked(task);
    } else {
      owner_executor_admission_rejected.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
  }
  if (!admission_recorded) {
    owner_executor_admission_accepted.fetch_add(1, std::memory_order_relaxed);
  }
  append_owner_task_trace(task, "queued");
  auto task_requires_main = owner_task_requires_main_drain(task);
  task.enqueued_at_ns = owner_now_ns();
  if (owner_scheduler_state.enqueue_owner_task(std::move(task), owner_id, task_requires_main,
                                               owner_task_executor_runnable)) {
    *notify_owner_thread = true;
  }
  return true;
}

void finish_active_main_owner_task(const std::string &owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  if (owner_scheduler_state.release_active_main_owner(owner_id)) {
    owner_main_owner_releases.fetch_add(1, std::memory_order_relaxed);
  }
}

void finish_active_owner_task(const std::string &owner_id) {
  bool notify_owner_thread = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    auto release = owner_scheduler_state.release_active_owner(owner_id, owner_task_executor_runnable);
    if (release.released) {
      owner_executor_owner_releases.fetch_add(1, std::memory_order_relaxed);
    }
    notify_owner_thread = release.should_notify;
    if (release.released) {
      append_owner_executor_trace_locked(owner_id, "owner_released");
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
}

bool pop_next_schedulable_task(OwnerMailboxTask *out, bool claim_owner) {
  auto result = owner_scheduler_state.pop_next_schedulable_task(out, claim_owner, owner_task_executor_runnable);
  if (result.skipped_non_runnable > 0) {
    owner_executor_main_required_skipped.fetch_add(static_cast<uint64_t>(result.skipped_non_runnable),
                                                   std::memory_order_relaxed);
  }
  if (!result.found) {
    return false;
  }
  if (claim_owner) {
    if (result.claim_conflict) {
      owner_executor_same_owner_claim_conflicts.fetch_add(1, std::memory_order_relaxed);
    }
    store_max_atomic(owner_executor_max_owner_parallel, static_cast<uint64_t>(result.owner_claims));
    store_max_atomic(owner_executor_max_parallel_owners, static_cast<uint64_t>(result.active_owner_count));
    owner_executor_owner_claims.fetch_add(1, std::memory_order_relaxed);
  }
  return true;
}

bool pop_next_main_task(OwnerMainTask *out, bool claim_owner) {
  auto found = owner_scheduler_state.pop_next_main_task(out, claim_owner);
  if (found && claim_owner) {
    owner_main_owner_claims.fetch_add(1, std::memory_order_relaxed);
  }
  return found;
}

bool pop_next_executor_task_for_owner(const std::string &owner_id, OwnerMailboxTask *out) {
  auto result = owner_scheduler_state.pop_next_executor_task_for_owner(owner_id, out, owner_task_executor_runnable);
  if (result.skipped_non_runnable > 0) {
    owner_executor_main_required_skipped.fetch_add(static_cast<uint64_t>(result.skipped_non_runnable),
                                                   std::memory_order_relaxed);
  }
  return result.found;
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
  auto canary_succeeded = result && result->type == T_NUMBER && result->u.number == 1;
  clear_owner_apply_return();

  if (canary_succeeded) {
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
    clear_owner_apply_return();
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_failed");
    owner_thread_lpc_task_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "lpc call failed");
    return;
  }
  auto lpc_task_succeeded = result->type == T_NUMBER && result->u.number == 1;
  auto frozen_result = vm_clone_frozen_value(result);
  clear_owner_apply_return();
  if (!frozen_result) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_failed");
    owner_thread_lpc_task_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "owner lpc result must be frozen data");
    return;
  }
  if (lpc_task_succeeded) {
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
    clear_owner_apply_return();
    append_owner_task_trace_threadsafe(task, "thread_ordinary_lpc_failed");
    owner_thread_ordinary_lpc_failed.fetch_add(1, std::memory_order_relaxed);
    complete_owner_future_for_task_threadsafe(task.task_id, "failed", "", "ordinary lpc call failed");
    return;
  }
  auto frozen_result = vm_clone_frozen_value(result);
  clear_owner_apply_return();
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

void record_owner_executor_callback_drop_class(const char *state, VMObjectHandleResolveStatus status) {
  owner_executor_admission_dropped.fetch_add(1, std::memory_order_relaxed);
  if (owner_handle_status_destructed(status) || std::strcmp(normalize_task_text(state, ""), "thread_executor_callback_destructed") == 0) {
    owner_executor_destructed_drop.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (owner_handle_status_epoch_mismatch(status)) {
    owner_executor_epoch_mismatch_drop.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (std::strcmp(normalize_task_text(state, ""), "thread_executor_callback_guard_rejected") == 0) {
    owner_executor_admission_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  owner_executor_stale_drop.fetch_add(1, std::memory_order_relaxed);
}

void drop_owner_executor_callback(OwnerMailboxTask &task, const char *state,
                                  VMObjectHandleResolveStatus status = VMObjectHandleResolveStatus::kInvalidHandle) {
  append_owner_task_trace_threadsafe(task, state);
  owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
  record_owner_executor_callback_drop_class(state, status);
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
                                 owner_handle_status_destructed(target_status.status)
                                     ? "thread_executor_callback_destructed"
                                     : "thread_executor_callback_stale",
                                 target_status.status);
    return;
  }

  auto *target = target_status.object;
  if (!target || (target->flags & O_DESTRUCTED)) {
    drop_owner_executor_callback(task, "thread_executor_callback_destructed",
                                 VMObjectHandleResolveStatus::kObjectDestructed);
    return;
  }
  if (!vm_owner_epoch_matches(target, task.owner_id.c_str(), task.owner_epoch)) {
    drop_owner_executor_callback(task, "thread_executor_callback_stale",
                                 VMObjectHandleResolveStatus::kOwnerEpochMismatch);
    return;
  }
  if (!target->prog) {
    drop_owner_executor_callback(task, "thread_executor_callback_stale",
                                 VMObjectHandleResolveStatus::kObjectNotFound);
    return;
  }

  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;
  if (vm_context_is_main_thread() || !owner_bound) {
    drop_owner_executor_callback(task, "thread_executor_callback_guard_rejected");
    return;
  }

  OwnerProgramPin program_pin(target->prog, "owner executor callback");
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
      owner_runtime_cv.wait(lock, [] { return owner_thread_stopping || !owner_scheduler_state.schedulable_empty(); });
      if (owner_thread_stopping) {
        return "";
      }
      OwnerMailboxTask first_task;
      if (!pop_next_schedulable_task(&first_task, true)) {
        continue;
      }
      auto owner_id = first_task.owner_id;
      owner_scheduler_state.push_front_owner_task(owner_id, std::move(first_task));
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
    if (owner_scheduler_state.owner_has_thread_task(owner_id, owner_task_executor_runnable)) {
      record_owner_executor_budget_yield_locked(owner_id);
    }
  }

  void complete_owner_message_task(const OwnerMailboxTask &task) {
    if (task.has_target_handle) {
      dispatch_owner_message_in_current_context(task);
      return;
    }
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
      case OwnerExecutorDispatchKind::MainThread:
        append_owner_task_trace_threadsafe(task, "thread_main_required_guarded");
        owner_thread_gateway_command_guarded.fetch_add(1, std::memory_order_relaxed);
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

void vm_owner_set_future_terminal_notifier(VMOwnerFutureTerminalNotifier notifier) {
  owner_future_terminal_notifier.store(notifier, std::memory_order_release);
}

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
  if (owner_id_is_default(owner_id)) {
    vm_owner_clear_id(object);
    return;
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
  bool queued = false;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return queued ? task_id : 0;
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
  bool queued = false;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
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

bool vm_owner_executor_available() {
  if (!vm_multicore_audit_enabled()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return !owner_threads.empty();
}

long vm_owner_main_queue_total_depth() {
  return owner_main_queue_total_depth();
}

uint64_t vm_owner_enqueue_executor_task(object_t *target, const char *task_type, const char *task_key,
                                        std::function<void()> callback,
                                        std::function<void()> drop_callback) {
  if (!target || !callback || !vm_multicore_audit_enabled()) {
    return 0;
  }

  auto normalized_task_type = std::string(normalize_task_text(task_type, ""));

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
      auto admission = admit_owner_executor_callback_task_locked(task);
      if (admission.accepted) {
        if (owner_executor_callback_main_adapter_required(task)) {
          queued = enqueue_owner_executor_callback_main_adapter_locked(task);
        } else {
          append_owner_task_trace(task, "executor_callback_queued");
          queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread, true);
        }
        if (queued) {
          owner_executor_callback_queued.fetch_add(1, std::memory_order_relaxed);
        }
      }
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
  bool queued = false;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return queued ? task_id : 0;
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
  bool queued = false;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", queued ? 1 : 0);
  add_mapping_pair(map, "task_id", queued ? static_cast<long>(task_id) : 0);
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
  bool queued = false;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
  }
  if (!queued) {
    release_owner_task_target(&task);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(9);
  add_mapping_pair(map, "success", queued ? 1 : 0);
  add_mapping_pair(map, "task_id", queued ? static_cast<long>(task_id) : 0);
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
  auto future_id = owner_trace_store.next_message_id();
  bool notify_owner_thread = false;
  bool queued = false;

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
  future.created_at_ms = owner_now_ms();

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_future_store.insert(std::move(future));
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
    if (!queued) {
      complete_owner_future_for_task_locked(task_id, "failed", "", "owner scheduler backpressure");
    }
  }
  if (!queued) {
    release_owner_task_target(&task);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(23);
  add_mapping_pair(map, "success", queued ? 1 : 0);
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
  add_mapping_pair(map, "requires_owner_thread", queued ? 1 : 0);
  add_mapping_pair(map, "requires_owner_message_completion", queued ? 1 : 0);
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
  auto future_id = owner_trace_store.next_message_id();
  bool notify_owner_thread = false;
  bool queued = false;

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
  future.created_at_ms = owner_now_ms();

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_future_store.insert(std::move(future));
    append_owner_task_trace(task, "queued");
    queued = enqueue_owner_task_locked(task, normalized_owner_id, &notify_owner_thread);
    if (!queued) {
      complete_owner_future_for_task_locked(task_id, "failed", "", "owner scheduler backpressure");
    }
  }
  if (!queued) {
    release_owner_task_target(&task);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(29);
  add_mapping_pair(map, "success", queued ? 1 : 0);
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
  add_mapping_string(map, "state", queued ? "pending" : "failed");
  add_mapping_string(map, "error", queued ? "" : "owner scheduler backpressure");
  add_mapping_pair(map, "requires_owner_thread", queued ? 1 : 0);
  add_mapping_pair(map, "requires_owner_message_completion", queued ? 1 : 0);
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
  if (!vm_multicore_audit_enabled()) {
    return 0;
  }
  auto sequence = owner_trace_store.total_task_traced() + 1;
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return append_owner_task_trace(0, sequence, normalize_owner_id(owner_id), owner_epoch,
                                  normalize_task_text(task_type, "generic"), normalize_task_text(task_key, ""), state);
}

void record_owner_main_queue_fallback(const OwnerMainTask &task) {
  switch (task.main_task_policy) {
    case VM_OWNER_MAIN_TASK_NORMAL_PATH_FALLBACK:
      owner_normal_path_main_fallback_count.fetch_add(1, std::memory_order_relaxed);
      return;
    case VM_OWNER_MAIN_TASK_OFF_MODE_FALLBACK:
      owner_off_mode_main_fallback_count.fetch_add(1, std::memory_order_relaxed);
      return;
    case VM_OWNER_MAIN_TASK_IO_ADAPTER:
      owner_main_io_adapter_count.fetch_add(1, std::memory_order_relaxed);
      return;
    case VM_OWNER_MAIN_TASK_CLEANUP_ADAPTER:
      owner_main_cleanup_adapter_count.fetch_add(1, std::memory_order_relaxed);
      return;
    case VM_OWNER_MAIN_TASK_EXPLICIT_FALLBACK:
      owner_explicit_main_fallback_count.fetch_add(1, std::memory_order_relaxed);
      return;
  }
  owner_explicit_main_fallback_count.fetch_add(1, std::memory_order_relaxed);
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
                                 size_t command_text_snapshot_length,
                                 VMOwnerMainTaskPolicy policy) {
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
  task.command_consume_executor_ready = policy != VM_OWNER_MAIN_TASK_IO_ADAPTER &&
                                        !task.command_consume_model.empty() &&
                                        task.command_consume_snapshot_ready &&
                                        task.command_consume_blocker.empty();
  task.execution_frame_model = normalize_task_text(execution_frame_model, "");
  task.execution_frame_policy = normalize_task_text(execution_frame_policy, "");
  task.execution_frame_restore_policy = normalize_task_text(execution_frame_restore_policy, "");
  task.execution_frame_restore_blocker = normalize_task_text(execution_frame_restore_blocker, "");
  task.execution_frame_requires_current_interactive = execution_frame_requires_current_interactive;
  task.execution_frame_requires_command_giver = execution_frame_requires_command_giver;
  task.execution_frame_restore_ready = !task.execution_frame_restore_policy.empty() &&
                                       task.execution_frame_restore_blocker.empty();
  task.execution_frame_executor_ready = policy != VM_OWNER_MAIN_TASK_IO_ADAPTER &&
                                        task.execution_frame_restore_ready;
  task.main_task_policy = policy;
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
  record_owner_main_queue_fallback(task);
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "main_queued");
    owner_scheduler_state.enqueue_main_task(std::move(task));
  }
  owner_main_queued.fetch_add(1, std::memory_order_relaxed);
  return task_id;
}

uint64_t vm_owner_enqueue_main_task(object_t *target, const char *task_type, const char *task_key,
                                    std::function<void()> callback, std::function<void()> drop_callback,
                                    VMOwnerMainTaskPolicy policy) {
  return enqueue_owner_main_task(target, task_type, task_key, std::move(callback), std::move(drop_callback),
                                 nullptr, nullptr, false, nullptr, nullptr, nullptr, nullptr, false, false, nullptr,
                                 nullptr, nullptr, 0, policy);
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
                                                 size_t command_text_snapshot_length,
                                                 VMOwnerMainTaskPolicy policy) {
  auto frozen_payload = payload ? vm_clone_frozen_value(payload) : nullptr;
  if (payload && !frozen_payload) {
    return 0;
  }
  return enqueue_owner_main_task(target, task_type, task_key, std::move(callback), std::move(drop_callback),
                                 payload_key, std::move(frozen_payload), true, command_consume_model,
                                 command_consume_blocker, execution_frame_model, execution_frame_policy,
                                 execution_frame_requires_current_interactive, execution_frame_requires_command_giver,
                                 execution_frame_restore_policy, execution_frame_restore_blocker, command_text_snapshot,
                                 command_text_snapshot_length, policy);
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
  owner_scheduler_state.enqueue_main_task(std::move(task));
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
    auto is_executor_callback = owner_executor_task_descriptor(task).dispatch_kind == OwnerExecutorDispatchKind::ExecutorCallback;
    if (stale) {
      const char *callback_stale_state = target && (target->flags & O_DESTRUCTED)
                                             ? "main_executor_callback_destructed"
                                             : "main_executor_callback_stale";
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        append_owner_task_trace(task, target && (target->flags & O_DESTRUCTED) ? "main_destructed" : "main_stale");
        if (is_executor_callback) {
          append_owner_task_trace(task, callback_stale_state);
        }
        if (target && (target->flags & O_DESTRUCTED)) {
          owner_main_destructed.fetch_add(1, std::memory_order_relaxed);
        } else {
          owner_main_stale.fetch_add(1, std::memory_order_relaxed);
        }
      }
      if (is_executor_callback) {
        auto target_status = task.has_target_handle ? vm_object_handle_resolve_status(task.target_handle).status
                                                    : VMObjectHandleResolveStatus::kInvalidHandle;
        owner_executor_callback_dropped.fetch_add(1, std::memory_order_relaxed);
        record_owner_executor_callback_drop_class(callback_stale_state, target_status);
      }
      if (task.task_type == "owner_message" && task.has_target_handle) {
        auto target_status = vm_object_handle_resolve_status(task.target_handle);
        auto error = stale_target_error(target_status.status);
        complete_owner_main_message_task_threadsafe(task, "failed", "", error.c_str());
      } else if (task.drop_callback) {
        if (is_executor_callback) {
          std::lock_guard<std::mutex> lock(owner_runtime_mutex);
          enqueue_owner_executor_callback_cleanup_locked(task);
        } else {
          task.drop_callback();
        }
      }
    } else {
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        append_owner_task_trace(task, "main_dispatched");
      }
      VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
      if (task.task_type == "owner_message" && task.has_target_handle) {
        dispatch_owner_main_message(task);
      } else if (is_executor_callback) {
        {
          std::lock_guard<std::mutex> lock(owner_runtime_mutex);
          append_owner_task_trace(task, "main_executor_callback_dispatched");
        }
        owner_executor_callback_dispatched.fetch_add(1, std::memory_order_relaxed);
        OwnerProgramPin program_pin(target->prog, "owner main callback adapter");
        VMExecutionState execution;
        execution.current_object = target;
        execution.current_prog = target->prog;
        VMExecutionScope execution_scope(vm_context(), execution);
        task.callback();
        {
          std::lock_guard<std::mutex> lock(owner_runtime_mutex);
          append_owner_task_trace(task, "main_executor_callback_completed");
        }
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
  access_id = owner_trace_store.append_access(std::move(trace));
  return access_id;
}

bool vm_owner_access_fast_bypass(object_t *source, object_t *target) {
  if (!source || !target) {
    return true;
  }
  if (source == target) {
    return true;
  }
  if (!vm_multicore_audit_enabled() && !vm_multicore_enforced()) {
    return true;
  }
  return false;
}

uint64_t vm_owner_record_cross_owner_access(object_t *source, object_t *target, const char *operation) {
  if (vm_owner_access_fast_bypass(source, target)) {
    return 0;
  }
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
    auto requested_limit = limit <= 0 ? 0 : static_cast<size_t>(limit);
    drained_tasks = owner_scheduler_state.drain_owner_mailbox(normalized_owner_id, requested_limit);
    for (auto &task : drained_tasks) {
      append_owner_task_trace(task, "drained");
      record_owner_mailbox_task_drained(task);
    }
    total_drained.fetch_add(drained_tasks.size(), std::memory_order_relaxed);
  }

  auto requested = drained_tasks.size();
  auto *tasks = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto &task = drained_tasks[i];
    if (task.task_type == "owner_message") {
      if (task.has_target_handle) {
        complete_owner_message_task_threadsafe(task, "failed", "",
                                               "target-handle owner message requires owner executor");
      } else {
        dispatch_owner_message_in_current_context(task);
      }
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
  auto purged_tasks = owner_scheduler_state.remove_owner_mailbox(normalized_owner_id);
  auto purged = static_cast<long>(purged_tasks.size());
  for (const auto &task : purged_tasks) {
    append_owner_task_trace(task, "purged");
  }
  for (auto &task : purged_tasks) {
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
      if (task.has_target_handle) {
        complete_owner_future_for_task_locked(task.task_id, "failed", "",
                                              "target-handle owner message requires owner executor");
      } else {
        complete_owner_message_task_locked(task);
      }
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
  add_mapping_pair(map, "main_active_owners", owner_scheduler_state.active_main_owner_count());
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_task_trace(int limit) {
  auto snapshot = owner_trace_store.task_snapshot(limit);
  auto requested = snapshot.events.size();
  auto *events = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_task_trace_mapping(snapshot.events[i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_task_trace");
  add_mapping_string(map, "trace_model", "owner_task_lifecycle_trace");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(snapshot.total_traced));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_executor_trace(int limit) {
  auto snapshot = owner_trace_store.executor_snapshot(limit);
  auto requested = snapshot.events.size();
  auto *events = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_executor_trace_mapping(snapshot.events[i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(11);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_executor_trace");
  add_mapping_string(map, "trace_model", "owner_executor_scheduler_trace");
  add_mapping_string(map, "trace_schema", kOwnerExecutorTraceSchemaV2);
  add_mapping_string(map, "owner_task_manifest_schema", kOwnerTaskManifestSchemaV2);
  add_mapping_string(map, "admission_policy", kOwnerTaskAdmissionPolicyV2);
  add_mapping_string(map, "executor_contract_version", kOwnerExecutorContractVersion);
  add_mapping_string(map, "executor_model", "owner_executor");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(snapshot.total_traced));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_access_trace(int limit) {
  auto snapshot = owner_trace_store.access_snapshot(limit);
  auto requested = snapshot.events.size();
  auto *events = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_access_trace_mapping(snapshot.events[i]);
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
  add_mapping_pair(map, "total_traced", static_cast<long>(snapshot.total_traced));
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
  auto message_id = owner_trace_store.next_message_id();

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
  trace.target_task_id = target_task_id;
  trace.source_owner_id = source_owner;
  trace.target_owner_id = target_owner;
  trace.message_type = normalized_type;
  trace.payload_key = normalized_payload;
  trace.state = "message_submitted";
  trace.route = "owner_mailbox";
  trace.target_handle_status = vm_object_handle_resolve_status_name(target_status);
  trace.has_target_handle = target_handle != nullptr;
  trace.requires_owner_mailbox = true;
  trace.requires_owner_main_queue = false;

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
  future.created_at_ms = owner_now_ms();

  bool notify_owner_thread = false;
  bool enqueued_owner_task = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    vm_object_store_record_message(target_owner.c_str(), target_task_id);
    owner_future_store.insert(std::move(future));
    owner_trace_store.append_message(std::move(trace));
    if (target_handle) {
      auto resolved_target = vm_object_handle_resolve_status(*target_handle);
      if (resolved_target.status == VMObjectHandleResolveStatus::kCurrent && resolved_target.object) {
        enqueued_owner_task = enqueue_owner_task_locked(task, target_owner, &notify_owner_thread);
        if (enqueued_owner_task) {
          owner_trace_store.update_message_route_for_task(target_task_id,
                                                          vm_object_handle_resolve_status_name(resolved_target.status),
                                                          true, false, false);
        } else {
          owner_trace_store.update_message_route_for_task(target_task_id, "owner_scheduler_backpressure", false, false,
                                                          false);
          vm_object_store_remove_message(target_owner.c_str(), target_task_id);
          complete_owner_future_for_task_locked(target_task_id, "failed", "", "owner scheduler backpressure");
        }
      } else {
        owner_trace_store.update_message_route_for_task(target_task_id,
                                                        vm_object_handle_resolve_status_name(resolved_target.status),
                                                        false, false, false);
        vm_object_store_remove_message(target_owner.c_str(), target_task_id);
        auto error = stale_target_error(resolved_target.status);
        complete_owner_future_for_task_locked(target_task_id, "failed", "", error.c_str());
      }
    } else {
      enqueued_owner_task = enqueue_owner_task_locked(task, target_owner, &notify_owner_thread);
      if (!enqueued_owner_task) {
        owner_trace_store.update_message_route_for_task(target_task_id, "owner_scheduler_backpressure", false, false,
                                                        false);
        vm_object_store_remove_message(target_owner.c_str(), target_task_id);
        complete_owner_future_for_task_locked(target_task_id, "failed", "", "owner scheduler backpressure");
      }
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
  add_mapping_pair(map, "requires_owner_mailbox", enqueued_owner_task ? 1 : 0);
  add_mapping_pair(map, "requires_owner_main_queue", 0);
  add_mapping_pair(map, "main_required", 0);
  add_mapping_pair(map, "queued_on_main", 0);
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
  auto future_id = owner_trace_store.next_message_id();

  OwnerFutureRecord future;
  future.future_id = future_id;
  future.target_task_id = worker_task_id;
  future.source_owner_id = normalized_owner;
  future.target_owner_id = normalized_owner;
  future.message_type = normalized_type;
  future.payload_key = normalized_payload;
  future.state = "pending";
  future.created_at_ms = owner_now_ms();

  owner_future_store.insert(std::move(future));
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
  bool queued = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    queued = enqueue_owner_task_locked(task, normalized_owner, &notify_owner_thread);
    if (!queued) {
      complete_owner_future_for_task_locked(worker_task_id, "failed", "", "owner scheduler backpressure");
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return queued ? task_id : 0;
}

mapping_t *vm_owner_message_trace(int limit) {
  auto snapshot = owner_trace_store.message_snapshot(limit);
  auto requested = snapshot.events.size();
  auto *events = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_message_trace_mapping(snapshot.events[i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_message_trace");
  add_mapping_string(map, "trace_model", "owner_message_lifecycle_trace");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(snapshot.total_traced));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_future_poll(uint64_t future_id) {
  auto record = owner_future_store.poll(future_id);
  if (!record) {
    auto *map = allocate_mapping(6);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", static_cast<long>(future_id));
    add_mapping_string(map, "state", "unknown");
    add_mapping_string(map, "error", "unknown future");
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    return map;
  }
  return owner_future_mapping(*record);
}

VMOwnerFutureState vm_owner_future_state(uint64_t future_id) {
  switch (owner_future_store.state(future_id)) {
    case OwnerFutureState::kPending:
      return VM_OWNER_FUTURE_PENDING;
    case OwnerFutureState::kCompleted:
      return VM_OWNER_FUTURE_COMPLETED;
    case OwnerFutureState::kFailed:
      return VM_OWNER_FUTURE_FAILED;
    case OwnerFutureState::kUnknown:
      return VM_OWNER_FUTURE_UNKNOWN;
  }
  return VM_OWNER_FUTURE_UNKNOWN;
}

bool vm_owner_future_targets_object(uint64_t future_id, object_t *target) {
  if (!target || (target->flags & O_DESTRUCTED)) {
    return false;
  }
  auto record = owner_future_store.poll(future_id);
  if (!record || !record->has_target_handle) {
    return false;
  }
  auto resolved = vm_object_handle_resolve_status(record->target_handle);
  return resolved.status == VMObjectHandleResolveStatus::kCurrent && resolved.object == target;
}

mapping_t *vm_owner_future_take(uint64_t future_id) {
  return vm_owner_future_take(future_id, nullptr);
}

mapping_t *vm_owner_future_take(uint64_t future_id, uint64_t *terminal_at_ns) {
  if (terminal_at_ns) {
    *terminal_at_ns = 0;
  }
  auto result = owner_future_store.take(future_id);
  if (!result.found) {
    auto *map = allocate_mapping(7);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", static_cast<long>(future_id));
    add_mapping_string(map, "state", "unknown");
    add_mapping_string(map, "error", "unknown future");
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    add_mapping_pair(map, "consumed", 0);
    return map;
  }

  if (terminal_at_ns) {
    *terminal_at_ns = result.record.terminal_at_ns;
  }
  auto *map = owner_future_mapping(result.record);
  add_mapping_pair(map, "consumed", result.consumed ? 1 : 0);
  return map;
}

VMOwnerFutureStringTakeResult vm_owner_future_take_string(uint64_t future_id) {
  VMOwnerFutureStringTakeResult output;
  if (!vm_context_is_main_thread()) {
    return output;
  }
  auto result = owner_future_store.take(future_id);
  output.found = result.found;
  output.consumed = result.consumed;
  if (!result.found) {
    return output;
  }

  output.terminal_at_ns = result.record.terminal_at_ns;
  if (result.record.state == "pending") {
    output.state = VM_OWNER_FUTURE_PENDING;
  } else if (result.record.state == "completed") {
    output.state = VM_OWNER_FUTURE_COMPLETED;
  } else {
    output.state = VM_OWNER_FUTURE_FAILED;
  }
  if (result.record.result && result.record.result->value.type == T_STRING &&
      result.record.result->value.u.string) {
    output.string_result = true;
    output.value.assign(result.record.result->value.u.string,
                        SVALUE_STRLEN(&result.record.result->value));
  }
  return output;
}

mapping_t *vm_owner_future_cancel(uint64_t future_id, const char *reason) {
  return mark_owner_future_failed_terminal(future_id, normalize_task_text(reason, "future cancelled"), true, false);
}

mapping_t *vm_owner_future_timeout(uint64_t future_id, const char *reason) {
  return mark_owner_future_failed_terminal(future_id, normalize_task_text(reason, "future timed out"), false, true);
}

mapping_t *vm_owner_record_commit_boundary(const char *source_owner_id, const char *target_owner_id,
                                           const char *operation, uint64_t message_id, const char *state) {
  OwnerCommitTrace trace;
  trace.message_id = message_id;
  trace.direct_write = false;
  trace.source_owner_id = normalize_owner_id(source_owner_id);
  trace.target_owner_id = normalize_owner_id(target_owner_id);
  trace.operation = normalize_task_text(operation, "commit");
  trace.state = normalize_task_text(state, "commit_guarded");
  auto result = owner_trace_store.append_commit(std::move(trace));
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
  auto snapshot = owner_trace_store.commit_snapshot(limit);
  auto requested = snapshot.events.size();
  auto *events = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_commit_trace_mapping(snapshot.events[i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "trace_kind", "owner_commit_trace");
  add_mapping_string(map, "trace_model", "owner_commit_boundary_trace");
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(snapshot.total_traced));
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
  auto *map = allocate_mapping(192);
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
  add_mapping_pair(map, "executor_callback_main_adapter_ready", 1);
  add_mapping_pair(map, "executor_callback_allowlist_count", owner_executor_callback_allowlist_count());
  add_mapping_string(map, "executor_callback_allowlist", kOwnerExecutorCallbackAllowlistKinds);
  add_mapping_pair(map, "owner_callback_diagnostics_ready", 1);
  add_mapping_string(map, "owner_callback_diagnostics_schema", kOwnerCallbackDiagnosticsSchemaV1);
  add_mapping_string(map, "owner_callback_failure_code_schema", kOwnerCallbackFailureCodeSchemaV1);
  add_mapping_string(map, "owner_callback_drop_reason_schema", kOwnerCallbackDropReasonSchemaV1);
  add_mapping_pair(map, "owner_callback_allowlist_complete", 1);
  add_mapping_string(map, "owner_callback_supported_kinds", kOwnerCallbackSupportedKinds);
  add_owner_callback_diagnostic_contract_fields(map);
  add_mapping_string(map, "executor_callback_payload_policy", "frozen_payload_or_owner_handle_only");
  add_mapping_pair(map, "heartbeat_owner_executor_ready", 1);
  add_mapping_string(map, "heartbeat_owner_executor_task_type", "heartbeat");
  add_mapping_string(map, "heartbeat_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "heartbeat_owner_executor_fallback_route", "");
  add_mapping_string(map, "heartbeat_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_pair(map, "heartbeat_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "heartbeat_current_object_thread_local", 0);
  add_mapping_pair(map, "callout_owner_executor_ready", 1);
  add_mapping_string(map, "callout_owner_executor_task_type", "call_out");
  add_mapping_string(map, "callout_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "callout_owner_executor_fallback_route", "");
  add_mapping_string(map, "callout_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_pair(map, "callout_owner_executor_expired_handle_detach_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "async_owner_executor_ready", 1);
  add_mapping_string(map, "async_owner_executor_task_type", "async_callback");
  add_mapping_string(map, "async_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "async_owner_executor_fallback_route", "");
  add_mapping_string(map, "async_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(map, "async_owner_executor_result_policy", "frozen_deep_copy_result");
  add_mapping_pair(map, "async_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "async_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "dns_owner_executor_ready", 1);
  add_mapping_string(map, "dns_owner_executor_task_type", "dns_callback");
  add_mapping_string(map, "dns_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "dns_owner_executor_fallback_route", "");
  add_mapping_string(map, "dns_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(map, "dns_owner_executor_result_policy", "frozen_deep_copy_result");
  add_mapping_pair(map, "dns_owner_executor_owner_epoch_capture_ready", 1);
  add_mapping_pair(map, "dns_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "dns_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "socket_owner_executor_ready", 1);
  add_mapping_string(map, "socket_owner_executor_task_type", "socket_callback");
  add_mapping_string(map, "socket_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "socket_owner_executor_fallback_route", "");
  add_mapping_string(map, "socket_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(map, "socket_owner_executor_result_policy", "frozen_deep_copy_args");
  add_mapping_pair(map, "socket_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "socket_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "socket_release_main_required", 0);
  add_mapping_pair(map, "socket_release_owner_safe_handshake_ready", 1);
  add_mapping_string(map, "socket_release_owner_safe_handshake_policy",
                     "synchronous_release_acquire_owner_epoch_guard");
  add_mapping_pair(map, "socket_release_owner_epoch_guard_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_ready", 1);
  add_mapping_string(map, "gateway_command_execute_task_type", "gateway_command_execute");
  add_mapping_string(map, "gateway_command_execute_route", "owner_main_queue_io_adapter");
  add_mapping_string(map, "gateway_command_execute_fallback_route", "");
  add_mapping_string(map, "gateway_command_execute_policy", "main_thread_io_adapter_until_interactive_detached");
  add_mapping_string(map, "gateway_command_execute_payload_policy", "owner_private_command_snapshot");
  add_mapping_pair(map, "gateway_command_execute_reply_queue_main_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_stale_drop_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_context_cleanup_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_session_revalidate_ready", 1);
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
  add_mapping_pair(map, "active_owners", owner_scheduler_state.active_owner_count());
  add_mapping_pair(map, "claimed_owners", owner_scheduler_state.active_owner_count());
  add_mapping_pair(map, "claimed_main_owners", owner_scheduler_state.active_main_owner_count());
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
  add_mapping_pair(map, "executor_active_claims", owner_scheduler_state.active_claim_count());
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
  add_mapping_pair(map, "lpc_task_allowlist_count", static_cast<long>(owner_lpc_task_descriptors().size()));
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
  add_owner_runtime_v2_status_fields(map);
  add_mapping_pair(map, "main_active_owners", owner_scheduler_state.active_main_owner_count());
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
  auto *map = allocate_mapping(192);
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
  add_mapping_pair(map, "main_active_owners", owner_scheduler_state.active_main_owner_count());
  add_mapping_pair(map, "claimed_owners", owner_scheduler_state.active_owner_count());
  add_mapping_pair(map, "claimed_main_owners", owner_scheduler_state.active_main_owner_count());
  add_mapping_pair(map, "main_queued", static_cast<long>(owner_main_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_dispatched", static_cast<long>(owner_main_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_stale", static_cast<long>(owner_main_stale.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_destructed", static_cast<long>(owner_main_destructed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_budget_yields", static_cast<long>(owner_main_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_claims", static_cast<long>(owner_main_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_releases", static_cast<long>(owner_main_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "destructed_object_backlog", static_cast<long>(vm_destructed_object_backlog_size()));
  add_mapping_pair(map, "destructed_object_cleanup_total",
                   static_cast<long>(vm_destructed_object_cleanup_total()));
  add_mapping_pair(map, "destructed_object_cleanup_batches",
                   static_cast<long>(vm_destructed_object_cleanup_batches()));
  add_mapping_pair(map, "destructed_object_cleanup_last_removed",
                   static_cast<long>(vm_destructed_object_cleanup_last_removed()));
  add_mapping_pair(map, "destructed_object_incremental_cleanup_ready", 1);
  add_mapping_pair(map, "active_owners", owner_scheduler_state.active_owner_count());
  add_mapping_pair(map, "owner_threads", static_cast<long>(owner_threads.size()));
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "future_count", owner_future_store.size());
  add_mapping_pair(map, "pending_futures", owner_pending_future_count());
  add_mapping_pair(map, "future_terminal_take_ready", 1);
  add_owner_runtime_v2_status_fields(map);
  add_mapping_pair(map, "futures_completed", static_cast<long>(owner_future_store.completed_count()));
  add_mapping_pair(map, "futures_failed", static_cast<long>(owner_future_store.failed_count()));
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
  add_mapping_pair(map, "executor_callback_main_adapter_ready", 1);
  add_mapping_pair(map, "executor_callback_allowlist_count", owner_executor_callback_allowlist_count());
  add_mapping_string(map, "executor_callback_allowlist", kOwnerExecutorCallbackAllowlistKinds);
  add_mapping_pair(map, "owner_callback_diagnostics_ready", 1);
  add_mapping_string(map, "owner_callback_diagnostics_schema", kOwnerCallbackDiagnosticsSchemaV1);
  add_mapping_string(map, "owner_callback_failure_code_schema", kOwnerCallbackFailureCodeSchemaV1);
  add_mapping_string(map, "owner_callback_drop_reason_schema", kOwnerCallbackDropReasonSchemaV1);
  add_mapping_pair(map, "owner_callback_allowlist_complete", 1);
  add_mapping_string(map, "owner_callback_supported_kinds", kOwnerCallbackSupportedKinds);
  add_owner_callback_diagnostic_contract_fields(map);
  add_mapping_string(map, "executor_callback_payload_policy", "frozen_payload_or_owner_handle_only");
  add_mapping_pair(map, "heartbeat_owner_executor_ready", 1);
  add_mapping_string(map, "heartbeat_owner_executor_task_type", "heartbeat");
  add_mapping_string(map, "heartbeat_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "heartbeat_owner_executor_fallback_route", "");
  add_mapping_string(map, "heartbeat_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_pair(map, "heartbeat_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "heartbeat_current_object_thread_local", 0);
  add_mapping_pair(map, "callout_owner_executor_ready", 1);
  add_mapping_string(map, "callout_owner_executor_task_type", "call_out");
  add_mapping_string(map, "callout_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "callout_owner_executor_fallback_route", "");
  add_mapping_string(map, "callout_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_pair(map, "callout_owner_executor_expired_handle_detach_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "callout_owner_executor_fallback_main_ready", 1);
  add_mapping_pair(map, "async_owner_executor_ready", 1);
  add_mapping_string(map, "async_owner_executor_task_type", "async_callback");
  add_mapping_string(map, "async_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "async_owner_executor_fallback_route", "");
  add_mapping_string(map, "async_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(map, "async_owner_executor_result_policy", "frozen_deep_copy_result");
  add_mapping_pair(map, "async_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "async_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "dns_owner_executor_ready", 1);
  add_mapping_string(map, "dns_owner_executor_task_type", "dns_callback");
  add_mapping_string(map, "dns_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "dns_owner_executor_fallback_route", "");
  add_mapping_string(map, "dns_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(map, "dns_owner_executor_result_policy", "frozen_deep_copy_result");
  add_mapping_pair(map, "dns_owner_executor_owner_epoch_capture_ready", 1);
  add_mapping_pair(map, "dns_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "dns_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "socket_owner_executor_ready", 1);
  add_mapping_string(map, "socket_owner_executor_task_type", "socket_callback");
  add_mapping_string(map, "socket_owner_executor_route", "owner_main_queue_callback_adapter");
  add_mapping_string(map, "socket_owner_executor_fallback_route", "");
  add_mapping_string(map, "socket_owner_executor_policy", "main_thread_callback_adapter_after_owner_admission");
  add_mapping_string(map, "socket_owner_executor_result_policy", "frozen_deep_copy_args");
  add_mapping_pair(map, "socket_owner_executor_cleanup_main_ready", 1);
  add_mapping_pair(map, "socket_owner_executor_drop_cleanup_ready", 1);
  add_mapping_pair(map, "socket_release_main_required", 0);
  add_mapping_pair(map, "socket_release_owner_safe_handshake_ready", 1);
  add_mapping_string(map, "socket_release_owner_safe_handshake_policy",
                     "synchronous_release_acquire_owner_epoch_guard");
  add_mapping_pair(map, "socket_release_owner_epoch_guard_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_ready", 1);
  add_mapping_string(map, "gateway_command_execute_task_type", "gateway_command_execute");
  add_mapping_string(map, "gateway_command_execute_route", "owner_main_queue_io_adapter");
  add_mapping_string(map, "gateway_command_execute_fallback_route", "");
  add_mapping_string(map, "gateway_command_execute_policy", "main_thread_io_adapter_until_interactive_detached");
  add_mapping_string(map, "gateway_command_execute_payload_policy", "owner_private_command_snapshot");
  add_mapping_pair(map, "gateway_command_execute_reply_queue_main_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_stale_drop_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_context_cleanup_ready", 1);
  add_mapping_pair(map, "gateway_command_execute_session_revalidate_ready", 1);
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
  add_mapping_pair(map, "executor_active_claims", owner_scheduler_state.active_claim_count());
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
  add_mapping_pair(map, "lpc_task_allowlist_count", static_cast<long>(owner_lpc_task_descriptors().size()));
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

#ifdef DEBUGMALLOC_EXTENSIONS
void vm_owner_mark_runtime_refs() {
  std::unordered_set<const VMFrozenValue *> seen;
  owner_scheduler_state.mark_debug_refs(seen);
  owner_trace_store.mark_debug_refs(seen);
  owner_future_store.mark_debug_refs(seen);
}
#endif

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
