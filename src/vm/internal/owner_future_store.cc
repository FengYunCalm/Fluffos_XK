#include "vm/internal/owner_future_store.h"

#include <chrono>
#include <cstring>

namespace {
uint64_t owner_future_now_ns() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
}

bool owner_future_terminal_state_valid(const char *state) {
  return !state || state[0] == '\0' || std::strcmp(state, "completed") == 0 ||
         std::strcmp(state, "failed") == 0;
}
}  // namespace

bool OwnerFutureStore::insert(OwnerFutureRecord record) {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
  auto future_id = record.future_id;
  if (record.state == "pending") {
    // Hard cap on retained terminal records: reject new submissions instead of
    // growing without bound. Payload-bearing terminal records are never
    // auto-reaped, so the cap is the only bound for them.
    size_t terminal_records = 0;
    for (const auto &entry : futures_) {
      if (entry.second.state != "pending") {
        terminal_records++;
      }
    }
    if (terminal_records >= kMaxTerminalRecords) {
      capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
  }
  auto existing = futures_.find(future_id);
  const auto replaced_pending =
      existing != futures_.end() && existing->second.state == "pending";
  const auto inserted_pending = record.state == "pending";
  if (existing != futures_.end()) {
    erase_task_index_entry(existing->second.target_task_id, future_id);
  }
  auto target_task_id = record.target_task_id;
  futures_[future_id] = std::move(record);
  future_ids_by_task_.emplace(target_task_id, future_id);
  if (inserted_pending && !replaced_pending) {
    pending_.fetch_add(1, std::memory_order_relaxed);
  } else if (!inserted_pending && replaced_pending) {
    pending_.fetch_sub(1, std::memory_order_relaxed);
  }
  return true;
}

std::optional<OwnerFutureRecord> OwnerFutureStore::poll(uint64_t future_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
  auto it = futures_.find(future_id);
  if (it == futures_.end()) {
    return std::nullopt;
  }
  return it->second;
}

OwnerFutureState OwnerFutureStore::state(uint64_t future_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
  auto it = futures_.find(future_id);
  if (it == futures_.end()) {
    return OwnerFutureState::kUnknown;
  }
  if (it->second.state == "pending") {
    return OwnerFutureState::kPending;
  }
  if (it->second.state == "completed") {
    return OwnerFutureState::kCompleted;
  }
  return OwnerFutureState::kFailed;
}

OwnerFutureTakeResult OwnerFutureStore::take(uint64_t future_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  OwnerFutureTakeResult result;
  auto it = futures_.find(future_id);
  if (it == futures_.end()) {
    return result;
  }

  result.found = true;
  result.record = it->second;
  if (it->second.state != "pending") {
    erase_task_index_entry(it->second.target_task_id, future_id);
    futures_.erase(it);
    result.consumed = true;
  }
  return result;
}

bool OwnerFutureStore::has_pending_for_task(uint64_t target_task_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto range = future_ids_by_task_.equal_range(target_task_id);
  for (auto it = range.first; it != range.second; ++it) {
    const auto future_it = futures_.find(it->second);
    if (future_it != futures_.end() &&
        future_it->second.target_task_id == target_task_id &&
        future_it->second.state == "pending") {
      return true;
    }
  }
  return false;
}

std::optional<OwnerFutureCompletion> OwnerFutureStore::complete(uint64_t future_id, const char *state,
                                                                const char *result_key, const char *error,
                                                                std::shared_ptr<VMFrozenValue> result) {
  if (!owner_future_terminal_state_valid(state)) {
    return std::nullopt;
  }
  std::unique_lock<std::mutex> lock(mutex_);
  auto it = futures_.find(future_id);
  if (it == futures_.end() || it->second.state != "pending") {
    return std::nullopt;
  }
  auto completion = complete_record(it->second, state, result_key, error, std::move(result));
  lock.unlock();
  completion.target_status = target_status(completion.record);
  return completion;
}

std::optional<OwnerFutureCompletion> OwnerFutureStore::complete_for_task(uint64_t target_task_id, const char *state,
                                                                         const char *result_key, const char *error,
                                                                         std::shared_ptr<VMFrozenValue> result) {
  if (!owner_future_terminal_state_valid(state)) {
    return std::nullopt;
  }
  std::unique_lock<std::mutex> lock(mutex_);
  auto range = future_ids_by_task_.equal_range(target_task_id);
  for (auto index_it = range.first; index_it != range.second;) {
    auto current_index = index_it++;
    auto future_it = futures_.find(current_index->second);
    if (future_it == futures_.end() || future_it->second.target_task_id != target_task_id) {
      future_ids_by_task_.erase(current_index);
      continue;
    }
    if (future_it->second.state == "pending") {
      auto completion = complete_record(future_it->second, state, result_key, error, std::move(result));
      lock.unlock();
      completion.target_status = target_status(completion.record);
      return completion;
    }
  }
  return std::nullopt;
}

std::optional<OwnerFutureCompletion> OwnerFutureStore::complete_string_for_task(
    uint64_t target_task_id, const char *result_key, std::string result) {
  std::unique_lock<std::mutex> lock(mutex_);
  auto range = future_ids_by_task_.equal_range(target_task_id);
  for (auto index_it = range.first; index_it != range.second;) {
    auto current_index = index_it++;
    auto future_it = futures_.find(current_index->second);
    if (future_it == futures_.end() ||
        future_it->second.target_task_id != target_task_id) {
      future_ids_by_task_.erase(current_index);
      continue;
    }
    auto &record = future_it->second;
    if (record.state != "pending") {
      continue;
    }
    record.state = "completed";
    record.result_key = normalize_text(result_key, "native_string");
    record.error.clear();
    record.terminal_at_ns = owner_future_now_ns();
    record.result.reset();
    record.native_string_result =
        std::make_shared<const std::string>(std::move(result));
    pending_.fetch_sub(1, std::memory_order_relaxed);
    completed_.fetch_add(1, std::memory_order_relaxed);

    OwnerFutureCompletion completion;
    completion.record = record;
    completion.completed_with_frozen_result = true;
    lock.unlock();
    completion.target_status = target_status(completion.record);
    return completion;
  }
  return std::nullopt;
}

OwnerFutureTerminalResult OwnerFutureStore::fail_terminal(uint64_t future_id, const char *reason, bool cancelled,
                                                          bool timed_out) {
  std::unique_lock<std::mutex> lock(mutex_);
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
    future.terminal_at_ns = owner_future_now_ns();
    pending_.fetch_sub(1, std::memory_order_relaxed);
    failed_.fetch_add(1, std::memory_order_relaxed);
    result.changed = true;
  }
  result.record = future;
  lock.unlock();
  result.target_status = target_status(result.record);
  return result;
}

int64_t OwnerFutureStore::pending_count() const {
  return pending_.load(std::memory_order_relaxed);
}

int64_t OwnerFutureStore::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<int64_t>(futures_.size());
}

uint64_t OwnerFutureStore::completed_count() const {
  return completed_.load(std::memory_order_relaxed);
}

uint64_t OwnerFutureStore::failed_count() const {
  return failed_.load(std::memory_order_relaxed);
}

size_t OwnerFutureStore::terminal_record_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t count = 0;
  for (const auto &entry : futures_) {
    if (entry.second.state != "pending") {
      count++;
    }
  }
  return count;
}

uint64_t OwnerFutureStore::oldest_terminal_age_ns() const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto now = owner_future_now_ns();
  uint64_t oldest = 0;
  for (const auto &entry : futures_) {
    if (entry.second.state != "pending" && entry.second.terminal_at_ns > 0) {
      auto age = now > entry.second.terminal_at_ns ? now - entry.second.terminal_at_ns : 0;
      if (age > oldest) {
        oldest = age;
      }
    }
  }
  return oldest;
}

uint64_t OwnerFutureStore::reaped_terminal_count() const {
  return reaped_terminal_.load(std::memory_order_relaxed);
}

uint64_t OwnerFutureStore::capacity_reject_count() const {
  return capacity_rejects_.load(std::memory_order_relaxed);
}

void OwnerFutureStore::reap_expired_terminal() {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
}

void OwnerFutureStore::reap_expired_terminal_locked() {
  if (futures_.empty()) {
    return;
  }
  auto now = owner_future_now_ns();
  for (auto it = futures_.begin(); it != futures_.end();) {
    auto &record = it->second;
    const bool terminal = record.state != "pending";
    // Never silently drop payload-bearing terminal records: only TTL-reap
    // records that carry no result payload at all.
    const bool has_payload = record.result != nullptr || record.native_string_result != nullptr;
    if (terminal && !has_payload && record.terminal_at_ns > 0 &&
        now - record.terminal_at_ns >= kTerminalTtlNs) {
      erase_task_index_entry(record.target_task_id, record.future_id);
      it = futures_.erase(it);
      reaped_terminal_.fetch_add(1, std::memory_order_relaxed);
    } else {
      ++it;
    }
  }
}

#ifdef DEBUGMALLOC_EXTENSIONS
void OwnerFutureStore::mark_debug_refs(std::unordered_set<const VMFrozenValue *> &seen) const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto &entry : futures_) {
    vm_mark_frozen_value_once(entry.second.result, seen);
  }
}
#endif

const char *OwnerFutureStore::normalize_text(const char *text, const char *fallback) {
  return text && text[0] != '\0' ? text : fallback;
}

VMObjectHandleResolveStatus OwnerFutureStore::target_status(const OwnerFutureRecord &record) {
  return record.has_target_handle ? vm_object_handle_resolve_status(record.target_handle).status
                                  : VMObjectHandleResolveStatus::kCurrent;
}

void OwnerFutureStore::erase_task_index_entry(uint64_t target_task_id, uint64_t future_id) {
  auto range = future_ids_by_task_.equal_range(target_task_id);
  for (auto it = range.first; it != range.second; ++it) {
    if (it->second == future_id) {
      future_ids_by_task_.erase(it);
      return;
    }
  }
}

OwnerFutureCompletion OwnerFutureStore::complete_record(OwnerFutureRecord &record, const char *state,
                                                        const char *result_key, const char *error,
                                                        std::shared_ptr<VMFrozenValue> result) {
  record.state = normalize_text(state, "completed");
  record.result_key = normalize_text(result_key, "");
  record.error = normalize_text(error, "");
  record.terminal_at_ns = owner_future_now_ns();
  auto completed_with_frozen_result = record.state == "completed" && result != nullptr;
  record.result = std::move(result);
  record.native_string_result.reset();
  pending_.fetch_sub(1, std::memory_order_relaxed);
  if (record.state == "failed") {
    failed_.fetch_add(1, std::memory_order_relaxed);
  } else {
    completed_.fetch_add(1, std::memory_order_relaxed);
  }

  OwnerFutureCompletion completion;
  completion.record = record;
  completion.completed_with_frozen_result = completed_with_frozen_result;
  return completion;
}
