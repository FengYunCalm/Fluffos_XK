#include "vm/internal/owner_future_store.h"

#include <cassert>
#include <chrono>
#include <cstring>

namespace {

// Estimate the byte weight of a frozen svalue for quota accounting. This is
// a conservative accounting metric (string bytes plus structural overhead),
// not an exact memory measurement.
uint64_t owner_future_frozen_bytes(const svalue_t *value, int depth) {
  if (!value) {
    return 0;
  }
  uint64_t bytes = sizeof(svalue_t);
  if (depth <= 0) {
    return bytes;
  }
  switch (value->type) {
    case T_STRING:
      bytes += value->u.string ? std::strlen(value->u.string) : 0;
      break;
    case T_ARRAY:
      if (value->u.arr) {
        bytes += sizeof(array_t);
        for (int i = 0; i < value->u.arr->size; i++) {
          bytes += owner_future_frozen_bytes(&value->u.arr->item[i], depth - 1);
        }
      }
      break;
    case T_MAPPING:
      if (value->u.map) {
        bytes += sizeof(mapping_t);
        bytes += static_cast<uint64_t>(MAP_COUNT(value->u.map)) * sizeof(mapping_node_t);
      }
      break;
    default:
      break;
  }
  return bytes;
}

uint64_t owner_future_payload_bytes(const OwnerFutureRecord &record) {
  uint64_t bytes = 0;
  if (record.native_string_result) {
    bytes += record.native_string_result->size() + sizeof(std::string);
  }
  if (record.result) {
    bytes += owner_future_frozen_bytes(&record.result->value, 8);
  }
  return bytes;
}

bool owner_future_terminal_state_valid(const char *state) {
  return !state || state[0] == '\0' || std::strcmp(state, "completed") == 0 ||
         std::strcmp(state, "failed") == 0;
}
}  // namespace

uint64_t OwnerFutureStore::default_clock() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
}

void OwnerFutureStore::set_clock_for_test(ClockFn clock) {
  clock_ = std::move(clock);
}

void OwnerFutureStore::assert_counts_locked() const {
#ifndef NDEBUG
  size_t terminal = 0;
  int64_t payload_bytes = 0;
  for (const auto &entry : futures_) {
    if (entry.second.state != "pending") {
      terminal++;
      payload_bytes += static_cast<int64_t>(owner_future_payload_bytes(entry.second));
    }
  }
  assert(terminal == terminal_records_);
  assert(payload_bytes == terminal_payload_bytes_);
  assert(terminal_by_time_.size() == terminal_time_index_.size());
#endif
}

void OwnerFutureStore::index_terminal_record_locked(const OwnerFutureRecord &record) {
  if (record.state == "pending" || record.terminal_at_ns == 0) {
    return;
  }
  const bool has_payload = record.result != nullptr || record.native_string_result != nullptr;
  if (has_payload) {
    // Payload-bearing terminal records are never auto-reaped; exclude them
    // from the TTL time index so reap scans stay bounded.
    return;
  }
  auto existing = terminal_time_index_.find(record.future_id);
  if (existing != terminal_time_index_.end() &&
      existing->second != terminal_by_time_.end()) {
    terminal_by_time_.erase(existing->second);
  }
  terminal_time_index_[record.future_id] =
      terminal_by_time_.emplace(record.terminal_at_ns, record.future_id);
}

void OwnerFutureStore::unindex_terminal_record_locked(const OwnerFutureRecord &record) {
  if (record.state == "pending") {
    return;
  }
  auto it = terminal_time_index_.find(record.future_id);
  if (it != terminal_time_index_.end()) {
    if (it->second != terminal_by_time_.end()) {
      terminal_by_time_.erase(it->second);
    }
    terminal_time_index_.erase(it);
  }
}

OwnerFutureRecord OwnerFutureStore::reject_pending_by_quota_locked(uint64_t future_id, const char *reason) {
  auto it = futures_.find(future_id);
  if (it == futures_.end() || it->second.state != "pending") {
    return OwnerFutureRecord{};
  }
  OwnerFutureRecord &record = it->second;
  record.state = "failed";
  record.result_key.clear();
  record.error = normalize_text(reason, "future quota exceeded");
  record.terminal_at_ns = now_ns();
  record.result.reset();
  record.native_string_result.reset();
  pending_.fetch_sub(1, std::memory_order_relaxed);
  failed_.fetch_add(1, std::memory_order_relaxed);
  // Do not retain the record: terminal cap and byte caps must never be
  // exceeded, and a quota-rejected record has no payload to preserve.
  OwnerFutureRecord rejected = std::move(record);
  erase_task_index_entry(rejected.target_task_id, future_id);
  futures_.erase(it);
  assert_counts_locked();
  return rejected;
}

bool OwnerFutureStore::insert(OwnerFutureRecord record) {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
  auto future_id = record.future_id;
  auto existing = futures_.find(future_id);
  const bool replacing_terminal =
      existing != futures_.end() && existing->second.state != "pending";
  const auto replaced_pending =
      existing != futures_.end() && existing->second.state == "pending";
  const auto inserted_pending = record.state == "pending";
  if (inserted_pending && !replacing_terminal) {
    // Hard cap on retained terminal records: reject new submissions instead
    // of growing without bound. Payload-bearing terminal records are never
    // auto-reaped, so the cap is the only bound for them. Replacing an
    // existing terminal keeps the count flat and never breaches the cap.
    if (terminal_records_ >= kMaxTerminalRecords) {
      capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    // Pending cap applies to the count after this insert (replacing a
    // pending record does not grow the pending set).
    const int64_t pending_after =
        pending_.load(std::memory_order_relaxed) - (replaced_pending ? 1 : 0) +
        (inserted_pending ? 1 : 0);
    if (pending_after > static_cast<int64_t>(kMaxPendingRecords)) {
      capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
  }
  if (replacing_terminal) {
    // Replacing an existing terminal record: account for the old record's
    // counters before inserting the replacement.
    unindex_terminal_record_locked(existing->second);
    terminal_records_--;
    terminal_payload_bytes_ -= static_cast<int64_t>(owner_future_payload_bytes(existing->second));
  }

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
  if (!inserted_pending) {
    terminal_records_++;
    terminal_payload_bytes_ += static_cast<int64_t>(owner_future_payload_bytes(futures_[future_id]));
    if (terminal_payload_bytes_ > peak_terminal_payload_bytes_) {
      peak_terminal_payload_bytes_ = terminal_payload_bytes_;
    }
    index_terminal_record_locked(futures_[future_id]);
  }
  assert_counts_locked();
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
    unindex_terminal_record_locked(it->second);
    terminal_records_--;
    terminal_payload_bytes_ -= static_cast<int64_t>(owner_future_payload_bytes(it->second));
    erase_task_index_entry(it->second.target_task_id, future_id);
    futures_.erase(it);
    result.consumed = true;
    assert_counts_locked();
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
  if (completion.quota_rejected) {
    lock.unlock();
    completion.target_status = VMObjectHandleResolveStatus::kCurrent;
    return completion;
  }
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
      if (completion.quota_rejected) {
        lock.unlock();
        completion.target_status = VMObjectHandleResolveStatus::kCurrent;
        return completion;
      }
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
    // Enforce byte quotas before transitioning pending -> terminal.
    const uint64_t payload_bytes = result.size() + sizeof(std::string);
    if (payload_bytes > kMaxSinglePayloadBytes ||
        terminal_payload_bytes_ + static_cast<int64_t>(payload_bytes) >
            static_cast<int64_t>(kMaxTotalPayloadBytes)) {
      byte_rejects_.fetch_add(1, std::memory_order_relaxed);
      OwnerFutureCompletion completion;
      completion.record = reject_pending_by_quota_locked(
          record.future_id, payload_bytes > kMaxSinglePayloadBytes
                                ? "future_payload_single_byte_cap"
                                : "future_payload_total_byte_cap");
      completion.completed_with_frozen_result = false;
      completion.quota_rejected = true;
      lock.unlock();
      completion.target_status = VMObjectHandleResolveStatus::kCurrent;
      return completion;
    }
    record.state = "completed";
    record.result_key = normalize_text(result_key, "native_string");
    record.error.clear();
    record.terminal_at_ns = now_ns();
    record.result.reset();
    record.native_string_result =
        std::make_shared<const std::string>(std::move(result));
    pending_.fetch_sub(1, std::memory_order_relaxed);
    completed_.fetch_add(1, std::memory_order_relaxed);
    terminal_records_++;
    terminal_payload_bytes_ += static_cast<int64_t>(payload_bytes);
    if (terminal_payload_bytes_ > peak_terminal_payload_bytes_) {
      peak_terminal_payload_bytes_ = terminal_payload_bytes_;
    }
    // Native-string payload is not TTL-reapable: no time index entry needed.
    assert_counts_locked();

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
    if (terminal_records_ >= kMaxTerminalRecords) {
      // Every entry point must respect the terminal cap: reject this
      // transition deterministically instead of breaching the bound.
      capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
      result.record = reject_pending_by_quota_locked(future.future_id, "future_terminal_capacity");
      result.changed = true;
      lock.unlock();
      result.target_status = VMObjectHandleResolveStatus::kCurrent;
      return result;
    }
    future.state = "failed";
    future.result_key.clear();
    future.error = normalize_text(reason, cancelled ? "future cancelled" : "future timed out");
    future.cancelled = cancelled;
    future.timed_out = timed_out;
    future.terminal_cleanup_required = false;
    future.terminal_at_ns = now_ns();
    future.result.reset();
    future.native_string_result.reset();
    pending_.fetch_sub(1, std::memory_order_relaxed);
    failed_.fetch_add(1, std::memory_order_relaxed);
    terminal_records_++;
    index_terminal_record_locked(future);
    result.changed = true;
    assert_counts_locked();
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
  return terminal_records_;
}

uint64_t OwnerFutureStore::oldest_terminal_age_ns() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (terminal_by_time_.empty()) {
    return 0;
  }
  auto now = now_ns();
  auto oldest_at = terminal_by_time_.begin()->first;
  return now > oldest_at ? now - oldest_at : 0;
}

int64_t OwnerFutureStore::terminal_payload_bytes() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return terminal_payload_bytes_;
}

int64_t OwnerFutureStore::peak_terminal_payload_bytes() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return peak_terminal_payload_bytes_;
}

uint64_t OwnerFutureStore::reaped_terminal_count() const {
  return reaped_terminal_.load(std::memory_order_relaxed);
}

uint64_t OwnerFutureStore::capacity_reject_count() const {
  return capacity_rejects_.load(std::memory_order_relaxed);
}

uint64_t OwnerFutureStore::byte_reject_count() const {
  return byte_rejects_.load(std::memory_order_relaxed);
}

void OwnerFutureStore::reap_expired_terminal() {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
}

void OwnerFutureStore::reap_expired_terminal_locked() {
  if (terminal_by_time_.empty()) {
    return;
  }
  auto now = now_ns();
  size_t scanned = 0;
  auto it = terminal_by_time_.begin();
  while (it != terminal_by_time_.end() && scanned < kReapScanBudget) {
    // The time index only contains payload-free terminal records, so every
    // entry is a reap candidate once its TTL has elapsed.
    if (now < it->first || now - it->first < kTerminalTtlNs) {
      break;
    }
    scanned++;
    auto future_id = it->second;
    auto future_it = futures_.find(future_id);
    auto next = std::next(it);
    terminal_by_time_.erase(it);
    terminal_time_index_.erase(future_id);
    if (future_it == futures_.end() || future_it->second.state == "pending") {
      // Stale index entry; counters were already maintained at removal time.
      it = next;
      continue;
    }
    const bool has_payload =
        future_it->second.result != nullptr || future_it->second.native_string_result != nullptr;
    if (has_payload) {
      // Never silently drop payload-bearing terminal records (defensive;
      // payload-bearing records are not indexed, so this should not happen).
      it = next;
      continue;
    }
    erase_task_index_entry(future_it->second.target_task_id, future_id);
    terminal_records_--;
    futures_.erase(future_it);
    reaped_terminal_.fetch_add(1, std::memory_order_relaxed);
    it = next;
  }
  assert_counts_locked();
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
  // Enforce quotas before transitioning pending -> terminal. A breach is a
  // deterministic rejection: terminalize as failed and drop the record so no
  // cap is ever exceeded and no payload is silently preserved.
  const bool wants_frozen_result = result != nullptr;
  const uint64_t payload_bytes = wants_frozen_result
                                     ? owner_future_frozen_bytes(&result->value, 8)
                                     : 0;
  const bool single_cap_breach = payload_bytes > kMaxSinglePayloadBytes;
  const bool total_cap_breach =
      terminal_payload_bytes_ + static_cast<int64_t>(payload_bytes) >
      static_cast<int64_t>(kMaxTotalPayloadBytes);
  if (terminal_records_ >= kMaxTerminalRecords ||
      (wants_frozen_result && (single_cap_breach || total_cap_breach))) {
    byte_rejects_.fetch_add(single_cap_breach || total_cap_breach ? 1 : 0,
                            std::memory_order_relaxed);
    capacity_rejects_.fetch_add(terminal_records_ >= kMaxTerminalRecords ? 1 : 0,
                                std::memory_order_relaxed);
    OwnerFutureCompletion completion;
    completion.record = reject_pending_by_quota_locked(
        record.future_id,
        terminal_records_ >= kMaxTerminalRecords
            ? "future_terminal_capacity"
            : (single_cap_breach ? "future_payload_single_byte_cap"
                                 : "future_payload_total_byte_cap"));
    completion.completed_with_frozen_result = false;
    completion.quota_rejected = true;
    return completion;
  }
  record.state = normalize_text(state, "completed");
  record.result_key = normalize_text(result_key, "");
  record.error = normalize_text(error, "");
  record.terminal_at_ns = now_ns();
  auto completed_with_frozen_result = record.state == "completed" && result != nullptr;
  record.result = std::move(result);
  record.native_string_result.reset();
  pending_.fetch_sub(1, std::memory_order_relaxed);
  if (record.state == "failed") {
    failed_.fetch_add(1, std::memory_order_relaxed);
  } else {
    completed_.fetch_add(1, std::memory_order_relaxed);
  }
  terminal_records_++;
  terminal_payload_bytes_ += static_cast<int64_t>(payload_bytes);
  if (terminal_payload_bytes_ > peak_terminal_payload_bytes_) {
    peak_terminal_payload_bytes_ = terminal_payload_bytes_;
  }
  index_terminal_record_locked(record);
  assert_counts_locked();

  OwnerFutureCompletion completion;
  completion.record = record;
  completion.completed_with_frozen_result = completed_with_frozen_result;
  return completion;
}
