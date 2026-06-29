#pragma once

#include "vm/frozen_value.h"
#include "vm/object_handle.h"
#include "vm/owner.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct object_t;

struct OwnerComputeResultField {
  std::string key;
  std::string string_value;
  int64_t number_value{0};
  bool is_string{false};
};

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
  int manifest_version{0};
  uint64_t deadline_ms{0};
  std::string manifest_schema;
  std::string task_kind;
  std::string payload_policy;
  std::string cleanup_policy;
  std::string reply_future_policy;
  std::string admission_policy;
  std::string admission_state;
  std::string trace_schema;
  std::string tick_group;
  std::string backpressure_policy;
  int scheduler_priority{0};
  int scheduler_budget{0};
  int scheduler_max_queue_depth{0};
  std::vector<OwnerComputeResultField> compute_result_fields;
  object_t *target{nullptr};
  bool has_target_handle{false};
  bool ordinary_lpc_explicit_open{false};
  std::shared_ptr<VMFrozenValue> payload;
  std::function<void()> callback;
  std::function<void()> drop_callback;
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
  VMOwnerMainTaskPolicy main_task_policy{VM_OWNER_MAIN_TASK_EXPLICIT_FALLBACK};
  VMObjectHandle target_handle;
  std::shared_ptr<VMFrozenValue> payload;
  std::function<void()> callback;
  std::function<void()> drop_callback;
};

using OwnerMailboxPredicate = bool (*)(const OwnerMailboxTask &task);

struct OwnerSchedulerPopResult {
  bool found{false};
  long skipped_non_runnable{0};
  int owner_claims{0};
  bool claim_conflict{false};
  long active_owner_count{0};
};

struct OwnerSchedulerReleaseResult {
  bool released{false};
  bool should_notify{false};
};

struct OwnerQueueFairnessSnapshot {
  long mailbox_owner_count{0};
  long executor_ready_owner_count{0};
  long executor_claim_blocked_owner_count{0};
  long executor_runnable_owner_count{0};
  long executor_runnable_claim_blocked_owner_count{0};
  long main_required_only_owner_count{0};
  long mixed_backlog_owner_count{0};
  long max_owner_backlog{0};
  long max_executor_runnable_backlog{0};
  long max_executor_safe_backlog{0};
  long max_main_required_backlog{0};
  long main_queue_owner_count{0};
  long main_ready_owner_count{0};
  long main_claim_blocked_owner_count{0};
  long max_owner_main_queue_depth{0};
};

long owner_mailbox_queue_depth_if(const std::deque<OwnerMailboxTask> &queue, OwnerMailboxPredicate predicate);
bool owner_mailbox_queue_has_task(const std::deque<OwnerMailboxTask> &queue, OwnerMailboxPredicate predicate);

class OwnerSchedulerState {
 public:
  long mailbox_depth(const std::string &owner_id) const;
  long mailbox_total_depth() const;
  long main_queue_total_depth() const;
  long main_queue_depth(const std::string &owner_id) const;
  long mailbox_active_owners() const;
  long active_owner_count() const;
  long active_main_owner_count() const;
  long active_claim_count() const;
  bool schedulable_empty() const;

  long mailbox_depth_if(const std::string &owner_id, OwnerMailboxPredicate predicate) const;
  long mailbox_total_depth_if(OwnerMailboxPredicate predicate) const;
  long runnable_owner_count(OwnerMailboxPredicate runnable) const;
  long main_runnable_owner_count() const;
  bool owner_has_thread_task(const std::string &owner_id, OwnerMailboxPredicate runnable) const;
  OwnerQueueFairnessSnapshot fairness_snapshot(OwnerMailboxPredicate runnable, OwnerMailboxPredicate safe,
                                               OwnerMailboxPredicate main_required) const;

  bool enqueue_owner_task(OwnerMailboxTask task, const std::string &owner_id, bool task_requires_main,
                          OwnerMailboxPredicate runnable);
  void push_front_owner_task(const std::string &owner_id, OwnerMailboxTask task);
  bool enqueue_main_task(OwnerMainTask task);

  OwnerSchedulerReleaseResult release_active_owner(const std::string &owner_id, OwnerMailboxPredicate runnable);
  bool release_active_main_owner(const std::string &owner_id);
  OwnerSchedulerPopResult pop_next_schedulable_task(OwnerMailboxTask *out, bool claim_owner,
                                                    OwnerMailboxPredicate runnable);
  bool pop_next_main_task(OwnerMainTask *out, bool claim_owner);
  OwnerSchedulerPopResult pop_next_executor_task_for_owner(const std::string &owner_id, OwnerMailboxTask *out,
                                                           OwnerMailboxPredicate runnable);

  std::vector<OwnerMailboxTask> drain_owner_mailbox(const std::string &owner_id, size_t limit);
  std::vector<OwnerMailboxTask> remove_owner_mailbox(const std::string &owner_id);
  void erase_owner_mailbox(const std::string &owner_id);

#ifdef DEBUGMALLOC_EXTENSIONS
  void mark_debug_refs(std::unordered_set<const VMFrozenValue *> &seen) const;
#endif

 private:
  void mark_owner_schedulable(const std::string &owner_id);
  void mark_main_owner_schedulable(const std::string &owner_id);

  std::unordered_map<std::string, std::deque<OwnerMailboxTask>> owner_mailboxes_;
  std::unordered_map<std::string, std::deque<OwnerMainTask>> owner_main_queues_;
  std::deque<std::string> schedulable_owners_;
  std::deque<std::string> main_schedulable_owners_;
  std::unordered_set<std::string> schedulable_owner_set_;
  std::unordered_set<std::string> main_schedulable_owner_set_;
  std::unordered_set<std::string> active_owner_set_;
  std::unordered_map<std::string, int> active_owner_claim_counts_;
  std::unordered_set<std::string> active_main_owner_set_;
};
