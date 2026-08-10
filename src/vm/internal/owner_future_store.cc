#include "vm/internal/owner_future_store.h"

#include "base/internal/stralloc.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <limits>

namespace {

// Bounds for the conservative frozen-payload weight visitor: a malicious or
// pathological value cannot force an unbounded recursion or an unbounded
// node walk inside the quota accounting.
constexpr int kMaxFrozenDepth = 32;
constexpr uint64_t kMaxFrozenNodes = 65536;

uint64_t saturating_add(uint64_t a, uint64_t b) {
  return a > std::numeric_limits<uint64_t>::max() - b
             ? std::numeric_limits<uint64_t>::max()
             : a + b;
}

// Exact byte length of a string svalue: counted strings (malloc/shared) use
// the allocator block size so embedded NULs are counted (strlen would
// undercount); constant strings fall back to strlen. No global scratch
// state is used (COUNTED_STRLEN is not thread-safe and must not be used
// from the store lock).
uint64_t owner_future_string_bytes(const svalue_t *sv) {
  if (!sv->u.string) {
    return 0;
  }
  if (sv->subtype == STRING_MALLOC || sv->subtype == STRING_SHARED) {
    return static_cast<uint64_t>(MSTR_SIZE(sv->u.string));
  }
  return std::strlen(sv->u.string);
}

struct FrozenWeightState {
  uint64_t bytes{0};
  uint64_t nodes{0};
  int depth{kMaxFrozenDepth};
};

// Forward declaration: the mapping node callback below recurses into it.
void owner_future_frozen_bytes_internal(const svalue_t *value,
                                        FrozenWeightState *state);

int owner_future_frozen_map_node(mapping_t * /*map*/, mapping_node_t *node,
                                 void *opaque) {
  auto *state = static_cast<FrozenWeightState *>(opaque);
  // Both the key and the value of every mapping pair are metered.
  auto *key = &node->values[0];
  auto *value = &node->values[1];
  state->bytes = saturating_add(state->bytes, sizeof(svalue_t));
  if (state->depth > 0) {
    FrozenWeightState key_state{0, state->nodes, state->depth - 1};
    owner_future_frozen_bytes_internal(key, &key_state);
    state->nodes = key_state.nodes;
    state->bytes = saturating_add(state->bytes, key_state.bytes);

    FrozenWeightState value_state{0, state->nodes, state->depth - 1};
    owner_future_frozen_bytes_internal(value, &value_state);
    state->nodes = value_state.nodes;
    state->bytes = saturating_add(state->bytes, value_state.bytes);
  } else {
    state->nodes++;
  }
  return 1;
}

// Estimate the byte weight of a frozen svalue for quota accounting. This is
// a conservative accounting metric (string bytes plus structural overhead),
// not an exact memory measurement. Mapping keys AND values are counted,
// recursion is depth-bounded, node count is bounded, and all additions
// saturate so a pathological value can never overflow the accounting.
void owner_future_frozen_bytes_internal(const svalue_t *value,
                                        FrozenWeightState *state) {
  if (!value || !state) {
    return;
  }
  if (state->nodes >= kMaxFrozenNodes || state->depth <= 0) {
    state->nodes++;
    return;
  }
  state->nodes++;
  state->depth--;
  state->bytes = saturating_add(state->bytes, sizeof(svalue_t));
  switch (value->type) {
    case T_STRING:
      state->bytes = saturating_add(state->bytes, owner_future_string_bytes(value));
      break;
    case T_ARRAY:
      if (value->u.arr) {
        state->bytes = saturating_add(state->bytes, sizeof(array_t));
        for (int i = 0; i < value->u.arr->size; i++) {
          owner_future_frozen_bytes_internal(&value->u.arr->item[i], state);
        }
      }
      break;
    case T_MAPPING:
      if (value->u.map) {
        state->bytes = saturating_add(state->bytes, sizeof(mapping_t));
        state->bytes = saturating_add(
            state->bytes,
            static_cast<uint64_t>(MAP_COUNT(value->u.map)) * sizeof(mapping_node_t));
        mapTraverse(value->u.map, owner_future_frozen_map_node, state);
      }
      break;
    default:
      break;
  }
}

uint64_t owner_future_frozen_bytes(const svalue_t *value) {
  FrozenWeightState state;
  owner_future_frozen_bytes_internal(value, &state);
  return state.bytes;
}

uint64_t owner_future_payload_bytes(const OwnerFutureRecord &record) {
  uint64_t bytes = 0;
  if (record.native_string_result) {
    bytes = saturating_add(bytes,
                           record.native_string_result->size() + sizeof(std::string));
  }
  if (record.result) {
    bytes = saturating_add(bytes, owner_future_frozen_bytes(&record.result->value));
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
  assert(terminal_all_by_time_.size() == terminal_all_time_index_.size());
  assert(terminal_reapable_by_time_.size() ==
         terminal_reapable_time_index_.size());
  // Lifecycle slot invariant: pending + terminal never exceeds the reserved
  // slot cap for admitted records.
  assert(static_cast<size_t>(pending_.load(std::memory_order_relaxed)) +
             terminal_records_ <=
         kMaxTerminalRecords);
#endif
}

void OwnerFutureStore::index_terminal_record_locked(const OwnerFutureRecord &record) {
  if (record.state == "pending" || record.terminal_at_ns == 0) {
    return;
  }
  // All-terminal index: backs oldest_terminal_age_ns() for every terminal
  // state, payload-bearing records included.
  auto existing_all = terminal_all_time_index_.find(record.future_id);
  if (existing_all != terminal_all_time_index_.end() &&
      existing_all->second != terminal_all_by_time_.end()) {
    terminal_all_by_time_.erase(existing_all->second);
  }
  terminal_all_time_index_[record.future_id] =
      terminal_all_by_time_.emplace(record.terminal_at_ns, record.future_id);

  // Reapable index: payload-free records only, so reap scans stay bounded
  // and payload-bearing records are never auto-dropped.
  const bool has_payload =
      record.result != nullptr || record.native_string_result != nullptr;
  if (has_payload) {
    auto existing_reap = terminal_reapable_time_index_.find(record.future_id);
    if (existing_reap != terminal_reapable_time_index_.end()) {
      terminal_reapable_by_time_.erase(existing_reap->second);
      terminal_reapable_time_index_.erase(existing_reap);
    }
    return;
  }
  auto existing_reap = terminal_reapable_time_index_.find(record.future_id);
  if (existing_reap != terminal_reapable_time_index_.end() &&
      existing_reap->second != terminal_reapable_by_time_.end()) {
    terminal_reapable_by_time_.erase(existing_reap->second);
  }
  terminal_reapable_time_index_[record.future_id] =
      terminal_reapable_by_time_.emplace(record.terminal_at_ns, record.future_id);
}

void OwnerFutureStore::unindex_terminal_record_locked(const OwnerFutureRecord &record) {
  if (record.state == "pending") {
    return;
  }
  auto it_all = terminal_all_time_index_.find(record.future_id);
  if (it_all != terminal_all_time_index_.end()) {
    if (it_all->second != terminal_all_by_time_.end()) {
      terminal_all_by_time_.erase(it_all->second);
    }
    terminal_all_time_index_.erase(it_all);
  }
  auto it_reap = terminal_reapable_time_index_.find(record.future_id);
  if (it_reap != terminal_reapable_time_index_.end()) {
    if (it_reap->second != terminal_reapable_by_time_.end()) {
      terminal_reapable_by_time_.erase(it_reap->second);
    }
    terminal_reapable_time_index_.erase(it_reap);
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
  record.cancelled = false;
  record.timed_out = false;
  pending_.fetch_sub(1, std::memory_order_relaxed);
  failed_.fetch_add(1, std::memory_order_relaxed);
  // Keep the record: it occupies the lifecycle slot reserved at admission.
  // A successful admission must stay queryable (poll/state/take -> failed
  // with the stable error) until take(), TTL reaping or cancellation.
  terminal_records_++;
  index_terminal_record_locked(record);
  assert_counts_locked();
  return record;
}

bool OwnerFutureStore::admit_pending(OwnerFutureRecord record) {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
  if (record.state != "pending") {
    return false;
  }
  auto future_id = record.future_id;
  auto existing = futures_.find(future_id);
  const bool replacing_pending =
      existing != futures_.end() && existing->second.state == "pending";
  if (existing != futures_.end() && existing->second.state != "pending") {
    // A terminal id cannot be re-admitted as pending: the slot is occupied
    // until take/reap. restore_terminal_checked is the only terminal path.
    return false;
  }
  const int64_t pending_after =
      pending_.load(std::memory_order_relaxed) - (replacing_pending ? 1 : 0) + 1;
  // Lifecycle slot reservation: every pending future reserves the terminal
  // slot it will occupy at completion, so pending + terminal can never
  // exceed the slot cap and no completion can ever be forced to drop a
  // record. This is what makes 'admission success -> queryable terminal'
  // an invariant instead of a best effort.
  const size_t reserved_after =
      static_cast<size_t>(pending_after) + terminal_records_;
  if (reserved_after > kMaxTerminalRecords) {
    capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
  // Absolute backstop on the pending pool (unreachable under the
  // reservation contract; guards future admission paths).
  if (pending_after > static_cast<int64_t>(kMaxPendingRecords)) {
    capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  if (existing != futures_.end()) {
    erase_task_index_entry(existing->second.target_task_id, future_id);
  }
  auto target_task_id = record.target_task_id;
  futures_[future_id] = std::move(record);
  future_ids_by_task_.emplace(target_task_id, future_id);
  if (!replacing_pending) {
    pending_.fetch_add(1, std::memory_order_relaxed);
  }
  assert_counts_locked();
  return true;
}

bool OwnerFutureStore::restore_terminal_checked(OwnerFutureRecord record) {
  std::lock_guard<std::mutex> lock(mutex_);
  reap_expired_terminal_locked();
  if (record.state == "pending" || record.terminal_at_ns == 0) {
    return false;
  }
  auto future_id = record.future_id;
  auto existing = futures_.find(future_id);
  const bool replacing_terminal =
      existing != futures_.end() && existing->second.state != "pending";
  const bool replacing_pending =
      existing != futures_.end() && existing->second.state == "pending";
  if (replacing_pending) {
    return false;
  }
  // Full record cap check: the restored record must fit, otherwise reject
  // instead of breaching the bound.
  const size_t terminal_after = terminal_records_ + (replacing_terminal ? 0 : 1);
  if (terminal_after > kMaxTerminalRecords) {
    capacity_rejects_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
  const uint64_t payload_bytes = owner_future_payload_bytes(record);
  const bool single_cap_breach = payload_bytes > kMaxSinglePayloadBytes;
  const bool total_cap_breach =
      terminal_payload_bytes_ - (replacing_terminal
                                     ? static_cast<int64_t>(
                                           owner_future_payload_bytes(existing->second))
                                     : 0) +
          static_cast<int64_t>(payload_bytes) >
      static_cast<int64_t>(kMaxTotalPayloadBytes);
  if (single_cap_breach || total_cap_breach) {
    byte_rejects_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  if (replacing_terminal) {
    unindex_terminal_record_locked(existing->second);
    terminal_records_--;
    terminal_payload_bytes_ -=
        static_cast<int64_t>(owner_future_payload_bytes(existing->second));
    erase_task_index_entry(existing->second.target_task_id, future_id);
  }
  auto target_task_id = record.target_task_id;
  futures_[future_id] = std::move(record);
  future_ids_by_task_.emplace(target_task_id, future_id);
  terminal_records_++;
  terminal_payload_bytes_ += static_cast<int64_t>(payload_bytes);
  if (terminal_payload_bytes_ > peak_terminal_payload_bytes_) {
    peak_terminal_payload_bytes_ = terminal_payload_bytes_;
  }
  index_terminal_record_locked(futures_[future_id]);
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
  auto completion = complete_record(it->second, state, result_key, error, std::move(result), nullptr);
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
      auto completion = complete_record(future_it->second, state, result_key, error, std::move(result), nullptr);
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
    auto native = std::make_shared<const std::string>(std::move(result));
    auto completion = complete_record(record, "completed", result_key, "",
                                      nullptr, std::move(native));
    if (completion.quota_rejected) {
      lock.unlock();
      completion.target_status = VMObjectHandleResolveStatus::kCurrent;
      return completion;
    }
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
    // The lifecycle slot was reserved at admission, so the terminal cap
    // cannot be hit here for an admitted future; the defensive path below
    // still keeps a failed tombstone instead of erasing the record.
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
  if (terminal_all_by_time_.empty()) {
    return 0;
  }
  auto now = now_ns();
  auto oldest_at = terminal_all_by_time_.begin()->first;
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
  if (terminal_reapable_by_time_.empty()) {
    return;
  }
  auto now = now_ns();
  size_t scanned = 0;
  auto it = terminal_reapable_by_time_.begin();
  while (it != terminal_reapable_by_time_.end() && scanned < kReapScanBudget) {
    // The reapable index only contains payload-free terminal records, so
    // every entry is a reap candidate once its TTL has elapsed.
    if (now < it->first || now - it->first < kTerminalTtlNs) {
      break;
    }
    scanned++;
    auto future_id = it->second;
    auto future_it = futures_.find(future_id);
    auto next = std::next(it);
    terminal_reapable_by_time_.erase(it);
    terminal_reapable_time_index_.erase(future_id);
    if (future_it == futures_.end() || future_it->second.state == "pending") {
      // Stale index entry; counters were already maintained at removal time.
      it = next;
      continue;
    }
    const bool has_payload =
        future_it->second.result != nullptr || future_it->second.native_string_result != nullptr;
    if (has_payload) {
      // Never silently drop payload-bearing terminal records (defensive;
      // payload-bearing records are not in the reapable index).
      it = next;
      continue;
    }
    // Remove from the all-terminal index as well.
    auto it_all = terminal_all_time_index_.find(future_id);
    if (it_all != terminal_all_time_index_.end()) {
      terminal_all_by_time_.erase(it_all->second);
      terminal_all_time_index_.erase(it_all);
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
                                                        std::shared_ptr<VMFrozenValue> result,
                                                        std::shared_ptr<const std::string> native_string) {
  // Enforce quotas before transitioning pending -> terminal. A breach is a
  // deterministic rejection: the record is terminalized as a payload-free
  // FAILED tombstone in its reserved slot (never erased, never unknown) and
  // the error code is stable and queryable.
  const bool wants_frozen_result = result != nullptr;
  const bool wants_native_result = native_string != nullptr;
  const uint64_t payload_bytes =
      wants_frozen_result ? owner_future_frozen_bytes(&result->value)
                          : (wants_native_result
                                 ? native_string->size() + sizeof(std::string)
                                 : 0);
  const bool single_cap_breach = payload_bytes > kMaxSinglePayloadBytes;
  const bool total_cap_breach =
      terminal_payload_bytes_ + static_cast<int64_t>(payload_bytes) >
      static_cast<int64_t>(kMaxTotalPayloadBytes);
  // The lifecycle slot was reserved at admission, so the terminal record cap
  // cannot be breached by an admitted pending; this stays as a defensive
  // check that also keeps a tombstone rather than erasing the record.
  if (terminal_records_ >= kMaxTerminalRecords ||
      ((wants_frozen_result || wants_native_result) &&
       (single_cap_breach || total_cap_breach))) {
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
  record.native_string_result = std::move(native_string);
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
