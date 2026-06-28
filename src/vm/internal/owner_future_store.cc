#include "vm/internal/owner_future_store.h"

void OwnerFutureStore::insert(OwnerFutureRecord record) {
  std::lock_guard<std::mutex> lock(mutex_);
  futures_[record.future_id] = std::move(record);
}

std::optional<OwnerFutureRecord> OwnerFutureStore::poll(uint64_t future_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = futures_.find(future_id);
  if (it == futures_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<OwnerFutureCompletion> OwnerFutureStore::complete(uint64_t future_id, const char *state,
                                                                const char *result_key, const char *error,
                                                                std::shared_ptr<VMFrozenValue> result) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = futures_.find(future_id);
  if (it == futures_.end() || it->second.state != "pending") {
    return std::nullopt;
  }
  return complete_record(it->second, state, result_key, error, std::move(result));
}

std::optional<OwnerFutureCompletion> OwnerFutureStore::complete_for_task(uint64_t target_task_id, const char *state,
                                                                         const char *result_key, const char *error,
                                                                         std::shared_ptr<VMFrozenValue> result) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto &entry : futures_) {
    if (entry.second.target_task_id == target_task_id && entry.second.state == "pending") {
      return complete_record(entry.second, state, result_key, error, std::move(result));
    }
  }
  return std::nullopt;
}

OwnerFutureTerminalResult OwnerFutureStore::fail_terminal(uint64_t future_id, const char *reason, bool cancelled,
                                                          bool timed_out) {
  std::lock_guard<std::mutex> lock(mutex_);
  OwnerFutureTerminalResult result;
  auto it = futures_.find(future_id);
  if (it == futures_.end()) {
    return result;
  }

  result.found = true;
  auto &future = it->second;
  if (future.state == "pending") {
    future.state = "failed";
    future.result_key.clear();
    future.error = normalize_text(reason, cancelled ? "future cancelled" : "future timed out");
    future.cancelled = cancelled;
    future.timed_out = timed_out;
    future.terminal_cleanup_required = false;
    failed_.fetch_add(1, std::memory_order_relaxed);
    result.changed = true;
  }
  result.target_status = target_status(future);
  result.record = future;
  return result;
}

long OwnerFutureStore::pending_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  long pending = 0;
  for (const auto &entry : futures_) {
    if (entry.second.state == "pending") {
      pending++;
    }
  }
  return pending;
}

long OwnerFutureStore::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<long>(futures_.size());
}

uint64_t OwnerFutureStore::completed_count() const {
  return completed_.load(std::memory_order_relaxed);
}

uint64_t OwnerFutureStore::failed_count() const {
  return failed_.load(std::memory_order_relaxed);
}

const char *OwnerFutureStore::normalize_text(const char *text, const char *fallback) {
  return text && text[0] != '\0' ? text : fallback;
}

VMObjectHandleResolveStatus OwnerFutureStore::target_status(const OwnerFutureRecord &record) {
  return record.has_target_handle ? vm_object_handle_resolve_status(record.target_handle).status
                                  : VMObjectHandleResolveStatus::kCurrent;
}

OwnerFutureCompletion OwnerFutureStore::complete_record(OwnerFutureRecord &record, const char *state,
                                                        const char *result_key, const char *error,
                                                        std::shared_ptr<VMFrozenValue> result) {
  record.state = normalize_text(state, "completed");
  record.result_key = normalize_text(result_key, "");
  record.error = normalize_text(error, "");
  auto completed_with_frozen_result = record.state == "completed" && result != nullptr;
  record.result = std::move(result);
  if (record.state == "failed") {
    failed_.fetch_add(1, std::memory_order_relaxed);
  } else {
    completed_.fetch_add(1, std::memory_order_relaxed);
  }

  OwnerFutureCompletion completion;
  completion.record = record;
  completion.target_status = target_status(record);
  completion.completed_with_frozen_result = completed_with_frozen_result;
  return completion;
}
