#include "vm/internal/owner_trace_store.h"

namespace {
constexpr size_t kOwnerTraceLimit = 256;
constexpr size_t kOwnerAccessTraceLimit = 256;
constexpr size_t kOwnerMessageTraceLimit = 256;
constexpr size_t kOwnerCommitTraceLimit = 256;
constexpr size_t kOwnerExecutorTraceLimit = 256;

const char *normalize_trace_text(const char *text, const char *fallback) {
  return text && text[0] != '\0' ? text : fallback;
}

template <typename Trace>
void trim_trace_deque(std::deque<Trace> &events, size_t limit) {
  while (events.size() > limit) {
    events.pop_front();
  }
}
}  // namespace

uint64_t OwnerTraceStore::append_task(OwnerTaskTrace trace) {
  trace.trace_id = next_task_trace_id_.fetch_add(1, std::memory_order_relaxed);
  std::lock_guard<std::mutex> lock(mutex_);
  task_traces_.push_back(std::move(trace));
  trim_trace_deque(task_traces_, kOwnerTraceLimit);
  total_task_traced_.fetch_add(1, std::memory_order_relaxed);
  return task_traces_.back().trace_id;
}

uint64_t OwnerTraceStore::append_executor(OwnerExecutorTrace trace) {
  trace.trace_id = next_executor_trace_id_.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = trace.trace_id;
  std::lock_guard<std::mutex> lock(mutex_);
  executor_traces_.push_back(std::move(trace));
  trim_trace_deque(executor_traces_, kOwnerExecutorTraceLimit);
  total_executor_traced_.fetch_add(1, std::memory_order_relaxed);
  return executor_traces_.back().trace_id;
}

uint64_t OwnerTraceStore::append_access(OwnerAccessTrace trace) {
  trace.access_id = next_access_trace_id_.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_access_traced_.fetch_add(1, std::memory_order_relaxed) + 1;
  auto access_id = trace.access_id;
  std::lock_guard<std::mutex> lock(mutex_);
  access_traces_.push_back(std::move(trace));
  trim_trace_deque(access_traces_, kOwnerAccessTraceLimit);
  return access_id;
}

void OwnerTraceStore::append_message(OwnerMessageTrace trace) {
  trace.sequence = total_message_traced_.fetch_add(1, std::memory_order_relaxed) + 1;
  std::lock_guard<std::mutex> lock(mutex_);
  message_traces_.push_back(std::move(trace));
  trim_trace_deque(message_traces_, kOwnerMessageTraceLimit);
}

OwnerCommitTrace OwnerTraceStore::append_commit(OwnerCommitTrace trace) {
  trace.commit_id = next_commit_trace_id_.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_commit_traced_.fetch_add(1, std::memory_order_relaxed) + 1;
  auto stored_trace = trace;
  std::lock_guard<std::mutex> lock(mutex_);
  commit_traces_.push_back(std::move(trace));
  trim_trace_deque(commit_traces_, kOwnerCommitTraceLimit);
  return stored_trace;
}

uint64_t OwnerTraceStore::next_message_id() {
  return next_message_trace_id_.fetch_add(1, std::memory_order_relaxed);
}

bool OwnerTraceStore::update_message_state_for_task(uint64_t target_task_id, const char *state,
                                                    const char *result_key, const char *error, bool frozen_result,
                                                    VMObjectHandleResolveStatus target_handle_status) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto &trace : message_traces_) {
    if (trace.target_task_id == target_task_id) {
      trace.state = normalize_trace_text(state, "completed");
      trace.result_key = normalize_trace_text(result_key, "");
      trace.error = normalize_trace_text(error, "");
      trace.frozen_result = frozen_result;
      if (trace.has_target_handle) {
        trace.target_handle_status = vm_object_handle_resolve_status_name(target_handle_status);
      }
      return true;
    }
  }
  return false;
}

bool OwnerTraceStore::update_message_route_for_task(uint64_t target_task_id, const char *target_handle_status,
                                                    bool requires_owner_mailbox, bool requires_owner_main_queue,
                                                    bool queued_on_main) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto &trace : message_traces_) {
    if (trace.target_task_id == target_task_id) {
      trace.target_handle_status = normalize_trace_text(target_handle_status, "");
      trace.requires_owner_mailbox = requires_owner_mailbox;
      trace.requires_owner_main_queue = requires_owner_main_queue;
      trace.queued_on_main = queued_on_main;
      return true;
    }
  }
  return false;
}

template <typename Trace>
OwnerTraceSnapshot<Trace> OwnerTraceStore::snapshot_locked(const std::deque<Trace> &events, uint64_t total,
                                                           int limit) const {
  OwnerTraceSnapshot<Trace> snapshot;
  auto available = events.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto start = available - requested;
  snapshot.events.reserve(requested);
  for (size_t i = 0; i < requested; i++) {
    snapshot.events.push_back(events[start + i]);
  }
  snapshot.total_traced = total;
  return snapshot;
}

OwnerTraceSnapshot<OwnerTaskTrace> OwnerTraceStore::task_snapshot(int limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_locked(task_traces_, total_task_traced_.load(std::memory_order_relaxed), limit);
}

OwnerTraceSnapshot<OwnerExecutorTrace> OwnerTraceStore::executor_snapshot(int limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_locked(executor_traces_, total_executor_traced_.load(std::memory_order_relaxed), limit);
}

OwnerTraceSnapshot<OwnerAccessTrace> OwnerTraceStore::access_snapshot(int limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_locked(access_traces_, total_access_traced_.load(std::memory_order_relaxed), limit);
}

OwnerTraceSnapshot<OwnerMessageTrace> OwnerTraceStore::message_snapshot(int limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_locked(message_traces_, total_message_traced_.load(std::memory_order_relaxed), limit);
}

OwnerTraceSnapshot<OwnerCommitTrace> OwnerTraceStore::commit_snapshot(int limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_locked(commit_traces_, total_commit_traced_.load(std::memory_order_relaxed), limit);
}

uint64_t OwnerTraceStore::total_task_traced() const {
  return total_task_traced_.load(std::memory_order_relaxed);
}

uint64_t OwnerTraceStore::total_executor_traced() const {
  return total_executor_traced_.load(std::memory_order_relaxed);
}

uint64_t OwnerTraceStore::total_access_traced() const {
  return total_access_traced_.load(std::memory_order_relaxed);
}

uint64_t OwnerTraceStore::total_message_traced() const {
  return total_message_traced_.load(std::memory_order_relaxed);
}

uint64_t OwnerTraceStore::total_commit_traced() const {
  return total_commit_traced_.load(std::memory_order_relaxed);
}

#ifdef DEBUGMALLOC_EXTENSIONS
void OwnerTraceStore::mark_debug_refs(std::unordered_set<const VMFrozenValue *> &seen) const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto &trace : task_traces_) {
    vm_mark_frozen_value_once(trace.payload, seen);
  }
}
#endif
