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
  bool cancelled{false};
  bool timed_out{false};
  bool terminal_cleanup_required{false};
  bool has_target_handle{false};
  std::shared_ptr<VMFrozenValue> result;
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

class OwnerFutureStore {
 public:
  void insert(OwnerFutureRecord record);
  std::optional<OwnerFutureRecord> poll(uint64_t future_id) const;
  std::optional<OwnerFutureCompletion> complete(uint64_t future_id, const char *state, const char *result_key,
                                                const char *error,
                                                std::shared_ptr<VMFrozenValue> result = nullptr);
  std::optional<OwnerFutureCompletion> complete_for_task(uint64_t target_task_id, const char *state,
                                                         const char *result_key, const char *error,
                                                         std::shared_ptr<VMFrozenValue> result = nullptr);
  OwnerFutureTerminalResult fail_terminal(uint64_t future_id, const char *reason, bool cancelled, bool timed_out);

  long pending_count() const;
  long size() const;
  uint64_t completed_count() const;
  uint64_t failed_count() const;

#ifdef DEBUGMALLOC_EXTENSIONS
  void mark_debug_refs(std::unordered_set<const VMFrozenValue *> &seen) const;
#endif

 private:
  static const char *normalize_text(const char *text, const char *fallback);
  static VMObjectHandleResolveStatus target_status(const OwnerFutureRecord &record);
  OwnerFutureCompletion complete_record(OwnerFutureRecord &record, const char *state, const char *result_key,
                                        const char *error, std::shared_ptr<VMFrozenValue> result);

  mutable std::mutex mutex_;
  std::unordered_map<uint64_t, OwnerFutureRecord> futures_;
  std::atomic<uint64_t> completed_{0};
  std::atomic<uint64_t> failed_{0};
};
