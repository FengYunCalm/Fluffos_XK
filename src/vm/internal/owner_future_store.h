#pragma once

#include "vm/frozen_value.h"
#include "vm/object_handle.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
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
  // True when the pending->terminal transition was rejected by a record or
  // byte quota. The record is terminalized as a payload-free FAILED
  // tombstone that REMAINS queryable via poll/state/take (it occupies the
  // lifecycle slot reserved at admission); it is never erased here, so a
  // successful admission can never become unknown through a quota path.
  bool quota_rejected{false};
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
  // LIFECYCLE slot cap (R2-F05): pending admission reserves a terminal slot,
  // so the store holds at most this many records in total (pending +
  // terminal). pending -> terminal is a state transition inside the reserved
  // slot; quota-rejected completions keep a payload-free failed tombstone in
  // the same slot. A successfully admitted future id therefore stays
  // queryable until take(), TTL reaping or explicit cancellation.
  static constexpr size_t kMaxTerminalRecords = 4096;
  // Absolute backstop on concurrently pending records. With the reservation
  // contract above the effective pending bound is min(kMaxPendingRecords,
  // kMaxTerminalRecords - terminal_records_); this constant protects against
  // future admission paths that bypass the reservation.
  static constexpr size_t kMaxPendingRecords = 65536;
  // Per-payload byte cap (frozen value estimate or native string size).
  static constexpr size_t kMaxSinglePayloadBytes = 8 * 1024 * 1024;  // 8 MiB
  // Aggregate byte cap across all retained terminal payloads.
  static constexpr size_t kMaxTotalPayloadBytes = 64 * 1024 * 1024;  // 64 MiB
  // Per-call scan budget for lazy TTL reaping: poll/state/insert never scan
  // more than this many time-index entries, keeping hot paths O(budget).
  static constexpr size_t kReapScanBudget = 64;

  // Production admission: reserves a future terminal slot (lifecycle slot
  // cap) and enforces the pending backstop. Rejects (returns false) without
  // side effects when either cap would be exceeded.
  bool admit_pending(OwnerFutureRecord record);
  // Restoration of a terminal (completed/failed) record, e.g. by recovery or
  // tests. Enforces the full record and payload byte caps; rejects (returns
  // false) instead of breaching them.
  bool restore_terminal_checked(OwnerFutureRecord record);
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
  // anytime; also invoked lazily from insert/poll/state with a bounded scan.
  void reap_expired_terminal();

  int64_t pending_count() const;
  int64_t size() const;
  uint64_t completed_count() const;
  uint64_t failed_count() const;
  // Number of terminal records currently retained (awaiting take). O(1).
  size_t terminal_record_count() const;
  // Age of the oldest retained terminal record, in ns (0 when none). O(1).
  uint64_t oldest_terminal_age_ns() const;
  // Retained terminal payload bytes (frozen estimate + native strings).
  int64_t terminal_payload_bytes() const;
  // High-water mark of retained terminal payload bytes.
  int64_t peak_terminal_payload_bytes() const;
  uint64_t reaped_terminal_count() const;
  // Rejections due to the terminal record cap (future_store_capacity).
  uint64_t capacity_reject_count() const;
  // Rejections due to single/aggregate payload byte caps.
  uint64_t byte_reject_count() const;

#ifdef DEBUGMALLOC_EXTENSIONS
  void mark_debug_refs(std::unordered_set<const VMFrozenValue *> &seen) const;
#endif

 private:
  static const char *normalize_text(const char *text, const char *fallback);
  static VMObjectHandleResolveStatus target_status(const OwnerFutureRecord &record);
  void erase_task_index_entry(uint64_t target_task_id, uint64_t future_id);
  // Requires mutex_ held. Single completion path shared by every entry
  // point (complete, complete_for_task, complete_string_for_task,
  // fail_terminal, cancellation): enforces quotas, converts pending ->
  // terminal inside the reserved slot, and keeps a failed tombstone on
  // rejection. At most one of result/native_string may be non-null.
  OwnerFutureCompletion complete_record(OwnerFutureRecord &record, const char *state, const char *result_key,
                                        const char *error, std::shared_ptr<VMFrozenValue> result,
                                        std::shared_ptr<const std::string> native_string);
  // Requires mutex_ held. Removes terminal records that are past TTL and carry
  // no payload (never silently drops payload-bearing records). Scans at most
  // kReapScanBudget time-index entries.
  void reap_expired_terminal_locked();
  // Requires mutex_ held. Maintains counters and the TTL time index for a
  // record that just became terminal (or was inserted as terminal).
  void index_terminal_record_locked(const OwnerFutureRecord &record);
  // Requires mutex_ held. Undoes counters and the TTL time index for a
  // terminal record being removed/replaced.
  void unindex_terminal_record_locked(const OwnerFutureRecord &record);
  // Requires mutex_ held. Terminates a pending record as failed due to a
  // quota breach. The record is KEPT as a payload-free failed tombstone in
  // its reserved lifecycle slot: it remains queryable via poll/state/take
  // until take(), TTL reaping or cancellation, and its error code is stable.
  OwnerFutureRecord reject_pending_by_quota_locked(uint64_t future_id, const char *reason);
  // Debug-only invariant check; no-op in release builds.
  void assert_counts_locked() const;

  mutable std::mutex mutex_;
  std::unordered_map<uint64_t, OwnerFutureRecord> futures_;
  std::unordered_multimap<uint64_t, uint64_t> future_ids_by_task_;
  // ALL-terminal time index (terminal_at_ns -> future_id), payload-bearing
  // records included: backs oldest_terminal_age_ns().
  std::multimap<uint64_t, uint64_t> terminal_all_by_time_;
  std::unordered_map<uint64_t, std::multimap<uint64_t, uint64_t>::iterator>
      terminal_all_time_index_;
  // Reapable-terminal time index: payload-free records only, so reap scans
  // stay bounded and payload-bearing records are never auto-dropped.
  std::multimap<uint64_t, uint64_t> terminal_reapable_by_time_;
  std::unordered_map<uint64_t, std::multimap<uint64_t, uint64_t>::iterator>
      terminal_reapable_time_index_;
  std::atomic<int64_t> pending_{0};
  std::atomic<uint64_t> completed_{0};
  std::atomic<uint64_t> failed_{0};
  std::atomic<uint64_t> reaped_terminal_{0};
  std::atomic<uint64_t> capacity_rejects_{0};
  std::atomic<uint64_t> byte_rejects_{0};
  // Lock-protected precise counters (kept in sync with futures_).
  size_t terminal_records_{0};
  int64_t terminal_payload_bytes_{0};
  int64_t peak_terminal_payload_bytes_{0};
  ClockFn clock_{default_clock};

 private:
  static uint64_t default_clock();
  uint64_t now_ns() const { return clock_ ? clock_() : default_clock(); }
};
