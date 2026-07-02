#include "vm/internal/owner_task_manifest.h"

namespace {
constexpr std::array<OwnerLpcTaskDescriptor, 18> kOwnerLpcTaskDescriptors = {{
    {"owner_task_readonly", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered readonly owner task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_player", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered player owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_room", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered room owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_session", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered session owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_item", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered item owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_economy", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered economy service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_combat", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered combat service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_mail", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered mail service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_reward", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered reward service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_world", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered world owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_persistence", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered persistence owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_team", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered team owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_guild", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered guild service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_sect", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered sect service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_quest", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered quest owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_rank", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered rank service owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_crafting", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered crafting owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
    {"owner_task_life_skill", "executor_safe_allowlist", "owner_executor", "frozen_result_required",
     "registered life skill owner domain task with frozen result", 1, 0, 0, 1, 1, 1, 1, 0},
}};

constexpr OwnerTaskRouteContract kOwnerTaskExecutorSafeContract = {
    "executor_safe", "owner_executor", "mailbox task is safe for owner executor", 1, 0, 0, 1, 0};
constexpr OwnerTaskRouteContract kOwnerTaskTargetHandleContract = {
    "executor_safe", "owner_executor", "object target handle runs on target owner executor with stale guard", 1, 0, 0,
    1, 0};

constexpr std::array<OwnerExecutorTaskDescriptor, 19> kOwnerExecutorTaskDescriptors = {{
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
    {"heartbeat", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback, "main_required_callback",
     "owner_main_queue_callback_adapter", "driver heartbeat callback closure admitted by owner runtime and run on main callback adapter", 0, 0, 1, 0, 0, 1},
    {"call_out", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback, "main_required_callback",
     "owner_main_queue_callback_adapter", "driver call_out callback closure admitted by owner runtime and run on main callback adapter", 0, 0, 1, 0, 0, 1},
    {"async_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "main_required_callback", "owner_main_queue_callback_adapter", "async worker callback closure admitted by owner runtime and run on main callback adapter", 0, 0, 1, 0,
     0, 1},
    {"dns_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "main_required_callback", "owner_main_queue_callback_adapter", "DNS callback closure admitted by owner runtime and run on main callback adapter", 0, 0, 1, 0, 0, 1},
    {"socket_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "main_required_callback", "owner_main_queue_callback_adapter", "socket callback closure admitted by owner runtime and run on main callback adapter", 0, 0, 1, 0,
     0, 1},
    {"gateway_command_execute", "gateway_command_main_queue", OwnerExecutorDispatchKind::MainThread,
     "main_required", "owner_main_queue", "guarded gateway command execution main-thread IO adapter", 1, 0, 1, 0,
     1, 1},
    {"ed_callback", "owner_executor_callback", OwnerExecutorDispatchKind::ExecutorCallback,
     "main_required_callback", "owner_main_queue_callback_adapter", "ed callback closure admitted by owner runtime and run on main callback adapter", 0, 0, 1,
     0, 0, 1},
    {"compute_result", "compute_result", OwnerExecutorDispatchKind::ComputeResult, "executor_safe",
     "owner_executor", "worker v2 result completion", 1, 1, 0, 0, 1, 0},
}};

constexpr OwnerExecutorTaskDescriptor kGenericDescriptor = {
    "generic", "generic", OwnerExecutorDispatchKind::Generic, "executor_compat", "owner_executor",
    "legacy test mailbox task without LPC execution contract", 1, 0, 0, 0, 1, 0};
}  // namespace

const std::array<OwnerLpcTaskDescriptor, 18> &owner_lpc_task_descriptors() {
  return kOwnerLpcTaskDescriptors;
}

const std::array<OwnerExecutorTaskDescriptor, 19> &owner_executor_task_descriptors() {
  return kOwnerExecutorTaskDescriptors;
}

const OwnerTaskRouteContract &owner_task_executor_safe_contract() {
  return kOwnerTaskExecutorSafeContract;
}

const OwnerTaskRouteContract &owner_task_target_handle_contract() {
  return kOwnerTaskTargetHandleContract;
}

const OwnerExecutorTaskDescriptor &owner_generic_executor_task_descriptor() {
  return kGenericDescriptor;
}

const OwnerLpcTaskDescriptor *find_owner_lpc_task_descriptor(const std::string &method) {
  for (const auto &descriptor : kOwnerLpcTaskDescriptors) {
    if (method == descriptor.method) {
      return &descriptor;
    }
  }
  return nullptr;
}

const OwnerExecutorTaskDescriptor *find_owner_executor_task_descriptor(const std::string &task_type) {
  for (const auto &descriptor : kOwnerExecutorTaskDescriptors) {
    if (task_type == descriptor.task_type) {
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
    case OwnerExecutorDispatchKind::MainThread:
      return "main_thread";
    case OwnerExecutorDispatchKind::ComputeResult:
      return "compute_result";
    case OwnerExecutorDispatchKind::Generic:
      return "generic";
  }
  return "generic";
}

const char *owner_manifest_payload_policy(OwnerExecutorDispatchKind kind, bool has_target_handle, bool has_payload) {
  switch (kind) {
    case OwnerExecutorDispatchKind::OwnerMessage:
      return has_target_handle ? "owner_handle_or_frozen_payload" : "frozen_payload_or_message_key";
    case OwnerExecutorDispatchKind::GatewayCommand:
    case OwnerExecutorDispatchKind::MainThread:
      return "owner_private_command_snapshot";
    case OwnerExecutorDispatchKind::ExecutorCallback:
      return "frozen_payload_or_owner_handle_only";
    case OwnerExecutorDispatchKind::ComputeResult:
      return "owner_future_frozen_result";
    case OwnerExecutorDispatchKind::LpcTask:
    case OwnerExecutorDispatchKind::OrdinaryLpc:
      return "owner_handle_and_frozen_result";
    case OwnerExecutorDispatchKind::RejectLpc:
    case OwnerExecutorDispatchKind::GuardOwnerState:
      return "no_mutable_payload";
    default:
      return has_payload ? "frozen_payload" : "no_mutable_payload";
  }
}

const char *owner_manifest_cleanup_policy(OwnerExecutorDispatchKind kind, bool has_target_handle) {
  switch (kind) {
    case OwnerExecutorDispatchKind::ExecutorCallback:
      return "main_thread_drop_cleanup";
    case OwnerExecutorDispatchKind::OwnerMessage:
      return has_target_handle ? "future_fail_on_stale" : "none";
    case OwnerExecutorDispatchKind::ComputeResult:
      return "future_completion_cleanup";
    case OwnerExecutorDispatchKind::GatewayCommand:
    case OwnerExecutorDispatchKind::MainThread:
      return "owner_command_frame_cleanup";
    default:
      return "none";
  }
}

const char *owner_manifest_reply_future_policy(OwnerExecutorDispatchKind kind) {
  switch (kind) {
    case OwnerExecutorDispatchKind::OwnerMessage:
    case OwnerExecutorDispatchKind::ComputeResult:
    case OwnerExecutorDispatchKind::LpcTask:
    case OwnerExecutorDispatchKind::OrdinaryLpc:
      return "owner_future";
    case OwnerExecutorDispatchKind::ExecutorCallback:
    case OwnerExecutorDispatchKind::GatewayCommand:
    case OwnerExecutorDispatchKind::MainThread:
      return "main_reply_or_cleanup_queue";
    default:
      return "none";
  }
}
