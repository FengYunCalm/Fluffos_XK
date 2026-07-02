#pragma once

#include <array>
#include <string>

inline constexpr const char *kOwnerTaskManifestSchemaV2 = "owner_task_manifest_v2";
inline constexpr const char *kOwnerTaskAdmissionPolicyV2 = "owner_epoch_payload_allowlist_deadline_guard";
inline constexpr const char *kOwnerExecutorTraceSchemaV2 = "owner_executor_trace_v2";

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
  MainThread,
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

const std::array<OwnerLpcTaskDescriptor, 18> &owner_lpc_task_descriptors();
const std::array<OwnerExecutorTaskDescriptor, 19> &owner_executor_task_descriptors();
const OwnerTaskRouteContract &owner_task_executor_safe_contract();
const OwnerTaskRouteContract &owner_task_target_handle_contract();
const OwnerExecutorTaskDescriptor &owner_generic_executor_task_descriptor();

const OwnerLpcTaskDescriptor *find_owner_lpc_task_descriptor(const std::string &method);
const OwnerExecutorTaskDescriptor *find_owner_executor_task_descriptor(const std::string &task_type);
const char *owner_executor_dispatch_kind_name(OwnerExecutorDispatchKind kind);
const char *owner_manifest_payload_policy(OwnerExecutorDispatchKind kind, bool has_target_handle, bool has_payload);
const char *owner_manifest_cleanup_policy(OwnerExecutorDispatchKind kind, bool has_target_handle);
const char *owner_manifest_reply_future_policy(OwnerExecutorDispatchKind kind);
