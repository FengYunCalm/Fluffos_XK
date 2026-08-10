#pragma once

#include "vm/frozen_value.h"
#include "vm/object_handle.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

struct OwnerFutureRecord {
  uint64_t future_id{0};
  uint64_t target_task_id{0};
  VMObjectHandle target_handle;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string message_type;
  std::string payload_key;
  std::string state;
  std::string result_key;
  std::string error;
  uint64_t created_at_ms{0};
  uint64_t deadline_ms{0};
  uint64_t terminal_at_ns{0};
  bool cancelled{false};
  bool timed_out{false};
  bool terminal_cleanup_required{false};
  bool has_target_handle{false};
  std::shared_ptr<VMFrozenValue> result;
  std::shared_ptr<const std::string> native_string_result;
};

struct OwnerFutureCompletion {
  OwnerFutureRecord record;
  VMObjectHandleResolveStatus target_status{VMObjectHandleResolveStatus::kCurrent};
  bool completed_with_frozen_result{false};
};

struct OwnerFutureTerminalResult {
  bool found{false};
  bool changed{false};
  OwnerFutureRecord record;
  VMObjectHandleResolveStatus target_status{VMObjectHandleResolveStatus::kCurrent};
};

struct OwnerFutureTakeResult {
  bool found{false};
  bool consumed{false};
  OwnerFutureRecord record;
};

enum class OwnerFutureState {
  kUnknown,
  kPending,
  kCompleted,
  kFailed,
};

class OwnerFutureStore {
 public:
  using ClockFn = std::function<uint64_t()>;

  // Test hook: replace the monotonic clock source. Defaults to
  // steady_clock-based ns. Tests install a fake clock to advance across
  // TTL boundaries deterministically.
  void set_clock_for_test(ClockFn clock);

  // Terminal records without payload are reaped after this age. Records that
  // still carry a frozen/native payload are never auto-reaped (no silent
  // drop); only a consumer take() removes them.
  static constexpr uint64_t kTerminalTtlNs = 300ULL * 1000 * 1000 * 1000;  // 300s
  // Hard cap on terminal (completed/failed) records kept for take().
  // Submissions beyond this cap are rejected with future_store_capacity.
  static constexpr size_t kMaxTerminalRecords = 4096;

  bool insert(OwnerFutureRecord record);
  std::optional<OwnerFutureRecord> poll(uint64_t future_id);
  OwnerFutureState state(uint64_t future_id);
  OwnerFutureTakeResult take(uint64_t future_id);
  bool has_pending_for_task(uint64_t target_task_id) const;
  std::optional<OwnerFutureCompletion> complete(uint64_t future_id, const char *state, const char *result_key,
                                                const char *error,
                                                std::shared_ptr<VMFrozenValue> result = nullptr);
  std::optional<OwnerFutureCompletion> complete_for_task(uint64_t target_task_id, const char *state,
                                                         const char *result_key, const char *error,
                                                         std::shared_ptr<VMFrozenValue> result = nullptr);
  std::optional<OwnerFutureCompletion> complete_string_for_task(
      uint64_t target_task_id, const char *result_key, std::string result);
  OwnerFutureTerminalResult fail_terminal(uint64_t future_id, const char *reason, bool cancelled, bool timed_out);

  // Reap expired payload-free terminal records (TTL-based). Safe to call
  // anytime; also invoked lazily from insert/poll/state.
  void reap_expired_terminal();

  int64_t pending_count() const;
  int64_t size() const;
  uint64_t completed_count() const;
  uint64_t failed_count() const;
  // Number of terminal records currently retained (awaiting take).
  size_t terminal_record_count() const;
  // Age of the oldest retained terminal record, in ns (0 when none).
  uint64_t oldest_terminal_age_ns() const;
  uint64_t reaped_terminal_count() const;
  uint64_t capacity_reject_count() const;

#ifdef DEBUGMALLOC_EXTENSIONS
  void mark_debug_refs(std::unordered_set<const VMFrozenValue *> &seen) const;
#endif

 private:
  static const char *normalize_text(const char *text, const char *fallback);
  static VMObjectHandleResolveStatus target_status(const OwnerFutureRecord &record);
  void erase_task_index_entry(uint64_t target_task_id, uint64_t future_id);
  OwnerFutureCompletion complete_record(OwnerFutureRecord &record, const char *state, const char *result_key,
                                        const char *error, std::shared_ptr<VMFrozenValue> result);
  // Requires mutex_ held. Removes terminal records that are past TTL and carry
  // no payload (never silently drops payload-bearing records).
  void reap_expired_terminal_locked();

  mutable std::mutex mutex_;
  std::unordered_map<uint64_t, OwnerFutureRecord> futures_;
  std::unordered_multimap<uint64_t, uint64_t> future_ids_by_task_;
  std::atomic<int64_t> pending_{0};
  std::atomic<uint64_t> completed_{0};
  std::atomic<uint64_t> failed_{0};
  std::atomic<uint64_t> reaped_terminal_{0};
  std::atomic<uint64_t> capacity_rejects_{0};
  ClockFn clock_{default_clock};

 private:
  static uint64_t default_clock();
  uint64_t now_ns() const { return clock_ ? clock_() : default_clock(); }
};
