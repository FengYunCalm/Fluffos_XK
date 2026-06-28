#pragma once

#include "vm/frozen_value.h"
#include "vm/object_handle.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct OwnerTaskTrace {
  uint64_t trace_id{0};
  uint64_t task_id{0};
  uint64_t sequence{0};
  uint64_t owner_epoch{0};
  int manifest_version{0};
  uint64_t deadline_ms{0};
  VMObjectHandle target_handle;
  std::shared_ptr<VMFrozenValue> payload;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::string state;
  std::string target_object;
  std::string payload_key;
  std::string manifest_schema;
  std::string task_kind;
  std::string payload_policy;
  std::string cleanup_policy;
  std::string reply_future_policy;
  std::string admission_policy;
  std::string admission_state;
  std::string trace_schema;
  std::string command_text_snapshot;
  std::string command_consume_model;
  std::string command_consume_blocker;
  std::string execution_frame_model;
  std::string execution_frame_policy;
  std::string execution_frame_restore_policy;
  std::string execution_frame_restore_blocker;
  std::string main_task_policy;
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
  uint64_t access_id{0};
  uint64_t sequence{0};
  uint64_t source_owner_epoch{0};
  uint64_t target_owner_epoch{0};
  bool cross_owner{false};
  std::string source_owner_id;
  std::string target_owner_id;
  std::string source_object;
  std::string target_object;
  std::string operation;
};

struct OwnerMessageTrace {
  uint64_t message_id{0};
  uint64_t sequence{0};
  uint64_t target_task_id{0};
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
  uint64_t commit_id{0};
  uint64_t sequence{0};
  uint64_t message_id{0};
  bool direct_write{false};
  std::string source_owner_id;
  std::string target_owner_id;
  std::string operation;
  std::string state;
};

struct OwnerExecutorTrace {
  uint64_t trace_id{0};
  uint64_t sequence{0};
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

template <typename Trace>
struct OwnerTraceSnapshot {
  std::vector<Trace> events;
  uint64_t total_traced{0};
};

class OwnerTraceStore {
 public:
  uint64_t append_task(OwnerTaskTrace trace);
  uint64_t append_executor(OwnerExecutorTrace trace);
  uint64_t append_access(OwnerAccessTrace trace);
  void append_message(OwnerMessageTrace trace);
  OwnerCommitTrace append_commit(OwnerCommitTrace trace);

  uint64_t next_message_id();

  bool update_message_state_for_task(uint64_t target_task_id, const char *state, const char *result_key,
                                     const char *error, bool frozen_result,
                                     VMObjectHandleResolveStatus target_handle_status);
  bool update_message_route_for_task(uint64_t target_task_id, const char *target_handle_status,
                                     bool requires_owner_mailbox, bool requires_owner_main_queue,
                                     bool queued_on_main);

  OwnerTraceSnapshot<OwnerTaskTrace> task_snapshot(int limit) const;
  OwnerTraceSnapshot<OwnerExecutorTrace> executor_snapshot(int limit) const;
  OwnerTraceSnapshot<OwnerAccessTrace> access_snapshot(int limit) const;
  OwnerTraceSnapshot<OwnerMessageTrace> message_snapshot(int limit) const;
  OwnerTraceSnapshot<OwnerCommitTrace> commit_snapshot(int limit) const;

  uint64_t total_task_traced() const;
  uint64_t total_executor_traced() const;
  uint64_t total_access_traced() const;
  uint64_t total_message_traced() const;
  uint64_t total_commit_traced() const;

 private:
  template <typename Trace>
  OwnerTraceSnapshot<Trace> snapshot_locked(const std::deque<Trace> &events, uint64_t total, int limit) const;

  mutable std::mutex mutex_;
  std::deque<OwnerTaskTrace> task_traces_;
  std::deque<OwnerAccessTrace> access_traces_;
  std::deque<OwnerMessageTrace> message_traces_;
  std::deque<OwnerCommitTrace> commit_traces_;
  std::deque<OwnerExecutorTrace> executor_traces_;
  std::atomic<uint64_t> next_task_trace_id_{1};
  std::atomic<uint64_t> next_access_trace_id_{1};
  std::atomic<uint64_t> next_message_trace_id_{1};
  std::atomic<uint64_t> next_commit_trace_id_{1};
  std::atomic<uint64_t> next_executor_trace_id_{1};
  std::atomic<uint64_t> total_task_traced_{0};
  std::atomic<uint64_t> total_access_traced_{0};
  std::atomic<uint64_t> total_message_traced_{0};
  std::atomic<uint64_t> total_commit_traced_{0};
  std::atomic<uint64_t> total_executor_traced_{0};
};
