#include "vm/internal/owner_scheduler_state.h"

#include <algorithm>

long owner_mailbox_queue_depth_if(const std::deque<OwnerMailboxTask> &queue, OwnerMailboxPredicate predicate) {
  long depth = 0;
  for (const auto &task : queue) {
    if (predicate && predicate(task)) {
      depth++;
    }
  }
  return depth;
}

bool owner_mailbox_queue_has_task(const std::deque<OwnerMailboxTask> &queue, OwnerMailboxPredicate predicate) {
  for (const auto &task : queue) {
    if (predicate && predicate(task)) {
      return true;
    }
  }
  return false;
}

long OwnerSchedulerState::mailbox_depth(const std::string &owner_id) const {
  auto it = owner_mailboxes_.find(owner_id);
  return it == owner_mailboxes_.end() ? 0 : static_cast<long>(it->second.size());
}

long OwnerSchedulerState::mailbox_total_depth() const {
  long depth = 0;
  for (const auto &entry : owner_mailboxes_) {
    depth += static_cast<long>(entry.second.size());
  }
  return depth;
}

long OwnerSchedulerState::main_queue_total_depth() const {
  long depth = 0;
  for (const auto &entry : owner_main_queues_) {
    depth += static_cast<long>(entry.second.size());
  }
  return depth;
}

long OwnerSchedulerState::main_queue_depth(const std::string &owner_id) const {
  auto it = owner_main_queues_.find(owner_id);
  return it == owner_main_queues_.end() ? 0 : static_cast<long>(it->second.size());
}

long OwnerSchedulerState::mailbox_active_owners() const {
  long owners = 0;
  for (const auto &entry : owner_mailboxes_) {
    if (!entry.second.empty()) {
      owners++;
    }
  }
  return owners;
}

long OwnerSchedulerState::active_owner_count() const { return static_cast<long>(active_owner_set_.size()); }

long OwnerSchedulerState::active_main_owner_count() const { return static_cast<long>(active_main_owner_set_.size()); }

long OwnerSchedulerState::active_claim_count() const {
  return static_cast<long>(active_owner_claim_counts_.size());
}

bool OwnerSchedulerState::schedulable_empty() const { return schedulable_owners_.empty(); }

long OwnerSchedulerState::mailbox_depth_if(const std::string &owner_id, OwnerMailboxPredicate predicate) const {
  auto it = owner_mailboxes_.find(owner_id);
  return it == owner_mailboxes_.end() ? 0 : owner_mailbox_queue_depth_if(it->second, predicate);
}

long OwnerSchedulerState::mailbox_total_depth_if(OwnerMailboxPredicate predicate) const {
  long depth = 0;
  for (const auto &entry : owner_mailboxes_) {
    depth += owner_mailbox_queue_depth_if(entry.second, predicate);
  }
  return depth;
}

long OwnerSchedulerState::runnable_owner_count(OwnerMailboxPredicate runnable) const {
  long owners = 0;
  for (const auto &entry : owner_mailboxes_) {
    if (active_owner_set_.count(entry.first) == 0 && owner_mailbox_queue_has_task(entry.second, runnable)) {
      owners++;
    }
  }
  return owners;
}

long OwnerSchedulerState::main_runnable_owner_count() const {
  long owners = 0;
  for (const auto &entry : owner_main_queues_) {
    if (!entry.second.empty() && active_main_owner_set_.count(entry.first) == 0) {
      owners++;
    }
  }
  return owners;
}

bool OwnerSchedulerState::owner_has_thread_task(const std::string &owner_id, OwnerMailboxPredicate runnable) const {
  auto it = owner_mailboxes_.find(owner_id);
  return it != owner_mailboxes_.end() && owner_mailbox_queue_has_task(it->second, runnable);
}

OwnerQueueFairnessSnapshot OwnerSchedulerState::fairness_snapshot(OwnerMailboxPredicate runnable,
                                                                  OwnerMailboxPredicate safe,
                                                                  OwnerMailboxPredicate main_required) const {
  OwnerQueueFairnessSnapshot snapshot;
  for (const auto &entry : owner_mailboxes_) {
    auto owner_backlog = static_cast<long>(entry.second.size());
    if (owner_backlog <= 0) {
      continue;
    }

    auto runnable_backlog = owner_mailbox_queue_depth_if(entry.second, runnable);
    auto safe_backlog = owner_mailbox_queue_depth_if(entry.second, safe);
    auto main_required_backlog = owner_mailbox_queue_depth_if(entry.second, main_required);
    snapshot.mailbox_owner_count++;
    if (runnable_backlog > 0 && active_owner_set_.count(entry.first) == 0) {
      snapshot.executor_runnable_owner_count++;
    }
    if (runnable_backlog > 0 && active_owner_set_.count(entry.first) > 0) {
      snapshot.executor_runnable_claim_blocked_owner_count++;
    }
    if (safe_backlog > 0 && active_owner_set_.count(entry.first) == 0) {
      snapshot.executor_ready_owner_count++;
    }
    if (safe_backlog > 0 && active_owner_set_.count(entry.first) > 0) {
      snapshot.executor_claim_blocked_owner_count++;
    }
    if (safe_backlog == 0 && main_required_backlog > 0) {
      snapshot.main_required_only_owner_count++;
    }
    if (safe_backlog > 0 && main_required_backlog > 0) {
      snapshot.mixed_backlog_owner_count++;
    }
    snapshot.max_owner_backlog = std::max(snapshot.max_owner_backlog, owner_backlog);
    snapshot.max_executor_runnable_backlog = std::max(snapshot.max_executor_runnable_backlog, runnable_backlog);
    snapshot.max_executor_safe_backlog = std::max(snapshot.max_executor_safe_backlog, safe_backlog);
    snapshot.max_main_required_backlog = std::max(snapshot.max_main_required_backlog, main_required_backlog);
  }

  for (const auto &entry : owner_main_queues_) {
    auto main_depth = static_cast<long>(entry.second.size());
    if (main_depth <= 0) {
      continue;
    }
    snapshot.main_queue_owner_count++;
    if (active_main_owner_set_.count(entry.first) == 0) {
      snapshot.main_ready_owner_count++;
    } else {
      snapshot.main_claim_blocked_owner_count++;
    }
    snapshot.max_owner_main_queue_depth = std::max(snapshot.max_owner_main_queue_depth, main_depth);
  }
  return snapshot;
}

bool OwnerSchedulerState::enqueue_owner_task(OwnerMailboxTask task, const std::string &owner_id,
                                             bool task_requires_main, OwnerMailboxPredicate runnable) {
  auto &queue = owner_mailboxes_[owner_id];
  auto had_thread_task = owner_mailbox_queue_has_task(queue, runnable);
  queue.push_back(std::move(task));
  if (!task_requires_main && !had_thread_task && active_owner_set_.count(owner_id) == 0 &&
      owner_mailbox_queue_has_task(queue, runnable)) {
    mark_owner_schedulable(owner_id);
    return true;
  }
  return false;
}

void OwnerSchedulerState::push_front_owner_task(const std::string &owner_id, OwnerMailboxTask task) {
  owner_mailboxes_[owner_id].push_front(std::move(task));
}

bool OwnerSchedulerState::enqueue_main_task(OwnerMainTask task) {
  auto owner_id = task.owner_id;
  auto &queue = owner_main_queues_[owner_id];
  auto was_empty = queue.empty();
  queue.push_back(std::move(task));
  if (was_empty && active_main_owner_set_.count(owner_id) == 0) {
    mark_main_owner_schedulable(owner_id);
    return true;
  }
  return false;
}

OwnerSchedulerReleaseResult OwnerSchedulerState::release_active_owner(const std::string &owner_id,
                                                                      OwnerMailboxPredicate runnable) {
  OwnerSchedulerReleaseResult result;
  result.released = active_owner_set_.erase(owner_id) > 0;
  active_owner_claim_counts_.erase(owner_id);
  if (owner_has_thread_task(owner_id, runnable)) {
    mark_owner_schedulable(owner_id);
    result.should_notify = true;
  }
  return result;
}

bool OwnerSchedulerState::release_active_main_owner(const std::string &owner_id) {
  auto released = active_main_owner_set_.erase(owner_id) > 0;
  auto it = owner_main_queues_.find(owner_id);
  if (it != owner_main_queues_.end() && !it->second.empty()) {
    mark_main_owner_schedulable(owner_id);
  }
  return released;
}

OwnerSchedulerPopResult OwnerSchedulerState::pop_next_schedulable_task(OwnerMailboxTask *out, bool claim_owner,
                                                                       OwnerMailboxPredicate runnable) {
  OwnerSchedulerPopResult result;
  while (!schedulable_owners_.empty()) {
    auto owner_id = schedulable_owners_.front();
    schedulable_owners_.pop_front();
    if (schedulable_owner_set_.erase(owner_id) == 0) {
      continue;
    }
    if (active_owner_set_.count(owner_id) > 0) {
      continue;
    }

    auto it = owner_mailboxes_.find(owner_id);
    if (it == owner_mailboxes_.end() || it->second.empty()) {
      owner_mailboxes_.erase(owner_id);
      continue;
    }

    auto task_it = it->second.begin();
    while (task_it != it->second.end() && !(runnable && runnable(*task_it))) {
      ++task_it;
      if (claim_owner) {
        result.skipped_non_runnable++;
      }
    }
    if (task_it == it->second.end()) {
      continue;
    }

    *out = *task_it;
    it->second.erase(task_it);
    if (it->second.empty()) {
      owner_mailboxes_.erase(it);
    } else if (!claim_owner && owner_mailbox_queue_has_task(it->second, runnable)) {
      mark_owner_schedulable(owner_id);
    }
    if (claim_owner) {
      active_owner_set_.insert(owner_id);
      result.owner_claims = ++active_owner_claim_counts_[owner_id];
      result.claim_conflict = result.owner_claims > 1;
      result.active_owner_count = static_cast<long>(active_owner_set_.size());
    }
    result.found = true;
    return result;
  }

  return result;
}

bool OwnerSchedulerState::pop_next_main_task(OwnerMainTask *out, bool claim_owner) {
  while (!main_schedulable_owners_.empty()) {
    auto owner_id = main_schedulable_owners_.front();
    main_schedulable_owners_.pop_front();
    if (main_schedulable_owner_set_.erase(owner_id) == 0) {
      continue;
    }
    if (claim_owner && active_main_owner_set_.count(owner_id) > 0) {
      continue;
    }

    auto it = owner_main_queues_.find(owner_id);
    if (it == owner_main_queues_.end() || it->second.empty()) {
      owner_main_queues_.erase(owner_id);
      continue;
    }

    *out = std::move(it->second.front());
    it->second.pop_front();
    if (it->second.empty()) {
      owner_main_queues_.erase(it);
    } else if (!claim_owner) {
      mark_main_owner_schedulable(owner_id);
    }
    if (claim_owner) {
      active_main_owner_set_.insert(owner_id);
    }
    return true;
  }

  return false;
}

OwnerSchedulerPopResult OwnerSchedulerState::pop_next_executor_task_for_owner(const std::string &owner_id,
                                                                              OwnerMailboxTask *out,
                                                                              OwnerMailboxPredicate runnable) {
  OwnerSchedulerPopResult result;
  auto it = owner_mailboxes_.find(owner_id);
  if (it == owner_mailboxes_.end() || it->second.empty()) {
    owner_mailboxes_.erase(owner_id);
    return result;
  }

  auto task_it = it->second.begin();
  while (task_it != it->second.end() && !(runnable && runnable(*task_it))) {
    ++task_it;
    result.skipped_non_runnable++;
  }
  if (task_it == it->second.end()) {
    return result;
  }

  *out = std::move(*task_it);
  it->second.erase(task_it);
  if (it->second.empty()) {
    owner_mailboxes_.erase(it);
  }
  result.found = true;
  return result;
}

std::vector<OwnerMailboxTask> OwnerSchedulerState::drain_owner_mailbox(const std::string &owner_id, size_t limit) {
  std::vector<OwnerMailboxTask> tasks;
  auto it = owner_mailboxes_.find(owner_id);
  if (it == owner_mailboxes_.end()) {
    return tasks;
  }

  auto requested = limit == 0 || limit > it->second.size() ? it->second.size() : limit;
  tasks.reserve(requested);
  for (size_t i = 0; i < requested; i++) {
    tasks.push_back(std::move(it->second.front()));
    it->second.pop_front();
  }
  if (it->second.empty()) {
    owner_mailboxes_.erase(it);
    schedulable_owner_set_.erase(owner_id);
  }
  return tasks;
}

std::vector<OwnerMailboxTask> OwnerSchedulerState::remove_owner_mailbox(const std::string &owner_id) {
  std::vector<OwnerMailboxTask> tasks;
  auto it = owner_mailboxes_.find(owner_id);
  if (it == owner_mailboxes_.end()) {
    return tasks;
  }
  tasks.reserve(it->second.size());
  while (!it->second.empty()) {
    tasks.push_back(std::move(it->second.front()));
    it->second.pop_front();
  }
  owner_mailboxes_.erase(it);
  schedulable_owner_set_.erase(owner_id);
  return tasks;
}

void OwnerSchedulerState::erase_owner_mailbox(const std::string &owner_id) {
  owner_mailboxes_.erase(owner_id);
  schedulable_owner_set_.erase(owner_id);
}

void OwnerSchedulerState::mark_owner_schedulable(const std::string &owner_id) {
  if (schedulable_owner_set_.insert(owner_id).second) {
    schedulable_owners_.push_back(owner_id);
  }
}

void OwnerSchedulerState::mark_main_owner_schedulable(const std::string &owner_id) {
  if (main_schedulable_owner_set_.insert(owner_id).second) {
    main_schedulable_owners_.push_back(owner_id);
  }
}
