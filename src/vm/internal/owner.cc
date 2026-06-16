#include "base/package_api.h"

#include "vm/context.h"
#include "vm/object_handle.h"
#include "vm/owner.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {
constexpr const char *kDefaultOwnerId = "legacy/main";
constexpr size_t kOwnerTraceLimit = 256;
constexpr size_t kOwnerAccessTraceLimit = 256;
constexpr size_t kOwnerMessageTraceLimit = 256;
constexpr size_t kOwnerCommitTraceLimit = 256;
std::atomic<uint64_t> total_checks{0};
std::atomic<uint64_t> mismatch_checks{0};
std::atomic<uint64_t> next_mailbox_task_id{1};
std::atomic<uint64_t> next_trace_id{1};
std::atomic<uint64_t> total_enqueued{0};
std::atomic<uint64_t> total_drained{0};
std::atomic<uint64_t> total_traced{0};
std::atomic<uint64_t> next_access_trace_id{1};
std::atomic<uint64_t> total_access_traced{0};
std::atomic<uint64_t> total_cross_owner_accesses{0};
std::atomic<uint64_t> total_cross_owner_snapshot_accesses{0};
std::atomic<uint64_t> total_cross_owner_message_accesses{0};
std::atomic<uint64_t> total_cross_owner_rejected_accesses{0};
std::atomic<uint64_t> total_cross_owner_enforced_blocks{0};
std::atomic<uint64_t> next_message_trace_id{1};
std::atomic<uint64_t> total_message_traced{0};
std::atomic<uint64_t> total_futures_completed{0};
std::atomic<uint64_t> total_futures_failed{0};
std::atomic<uint64_t> next_commit_trace_id{1};
std::atomic<uint64_t> total_commit_traced{0};
std::atomic<uint64_t> owner_thread_dispatched{0};
std::atomic<uint64_t> owner_executor_budget_yields{0};
std::atomic<uint64_t> owner_thread_starts{0};
std::atomic<uint64_t> owner_thread_stops{0};
std::atomic<uint64_t> owner_thread_context_bound{0};
std::atomic<uint64_t> owner_thread_object_store_isolated{0};
std::atomic<uint64_t> owner_thread_owner_bound{0};
std::atomic<uint64_t> owner_thread_owner_cleared{0};
std::atomic<uint64_t> owner_thread_execution_cleared{0};
std::atomic<uint64_t> owner_thread_lpc_canary_flag_cleared{0};
std::atomic<uint64_t> owner_thread_context_leak_detected{0};
std::atomic<uint64_t> owner_thread_lpc_rejected{0};
std::atomic<uint64_t> owner_thread_owner_state_guarded{0};
std::atomic<uint64_t> owner_thread_message_dispatched{0};
std::atomic<uint64_t> owner_thread_lpc_probe_executed{0};
std::atomic<uint64_t> owner_thread_lpc_probe_failed{0};
std::atomic<uint64_t> owner_thread_lpc_probe_guarded{0};
std::atomic<uint64_t> owner_thread_lpc_canary_executed{0};
std::atomic<uint64_t> owner_thread_lpc_canary_succeeded{0};
std::atomic<uint64_t> owner_thread_lpc_canary_failed{0};
std::atomic<uint64_t> owner_thread_lpc_canary_rejected{0};
std::atomic<uint64_t> owner_thread_lpc_task_executed{0};
std::atomic<uint64_t> owner_thread_lpc_task_succeeded{0};
std::atomic<uint64_t> owner_thread_lpc_task_failed{0};
std::atomic<uint64_t> owner_thread_lpc_task_rejected{0};
std::atomic<uint64_t> owner_executor_owner_claims{0};
std::atomic<uint64_t> owner_executor_owner_releases{0};
std::atomic<uint64_t> owner_main_queued{0};
std::atomic<uint64_t> owner_main_dispatched{0};
std::atomic<uint64_t> owner_main_stale{0};
std::atomic<uint64_t> owner_main_destructed{0};
std::atomic<uint64_t> owner_main_budget_yields{0};
std::atomic<uint64_t> owner_main_owner_claims{0};
std::atomic<uint64_t> owner_main_owner_releases{0};

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
  object_t *target{nullptr};
  bool has_target_handle{false};
  std::shared_ptr<struct OwnerFrozenValue> payload;
};

struct OwnerTaskTrace {
  uint64_t trace_id;
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::string state;
};

struct OwnerAccessTrace {
  uint64_t access_id;
  uint64_t sequence;
  uint64_t source_owner_epoch;
  uint64_t target_owner_epoch;
  bool cross_owner;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string source_object;
  std::string target_object;
  std::string operation;
};

struct OwnerMessageTrace {
  uint64_t message_id;
  uint64_t sequence;
  uint64_t target_task_id;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string message_type;
  std::string payload_key;
  std::string state;
};

struct OwnerCommitTrace {
  uint64_t commit_id;
  uint64_t sequence;
  uint64_t message_id;
  bool direct_write;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string operation;
  std::string state;
};

struct OwnerFutureRecord {
  uint64_t future_id;
  uint64_t target_task_id;
  VMObjectHandle target_handle;
  std::string source_owner_id;
  std::string target_owner_id;
  std::string message_type;
  std::string payload_key;
  std::string state;
  std::string result_key;
  std::string error;
  bool has_target_handle{false};
  std::shared_ptr<struct OwnerFrozenValue> result;
};

struct OwnerFrozenValue {
  svalue_t value{const0u};

  OwnerFrozenValue() = default;
  OwnerFrozenValue(const OwnerFrozenValue &) = delete;
  OwnerFrozenValue &operator=(const OwnerFrozenValue &) = delete;
  ~OwnerFrozenValue() { free_svalue(&value, "owner frozen value"); }
};

struct OwnerMainTask {
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
  std::string target_object;
  object_t *target{nullptr};
  std::function<void()> callback;
  std::function<void()> drop_callback;
};

std::unordered_map<std::string, std::deque<OwnerMailboxTask>> owner_mailboxes;
std::unordered_map<std::string, std::deque<OwnerMainTask>> owner_main_queues;
std::deque<std::string> schedulable_owners;
std::deque<std::string> main_schedulable_owners;
std::unordered_set<std::string> schedulable_owner_set;
std::unordered_set<std::string> main_schedulable_owner_set;
std::unordered_set<std::string> active_owner_set;
std::unordered_set<std::string> active_main_owner_set;
std::deque<OwnerTaskTrace> owner_task_traces;
std::deque<OwnerAccessTrace> owner_access_traces;
std::deque<OwnerMessageTrace> owner_message_traces;
std::deque<OwnerCommitTrace> owner_commit_traces;
std::unordered_map<uint64_t, OwnerFutureRecord> owner_futures;
std::vector<object_t *> owner_deferred_target_releases;
std::mutex owner_runtime_mutex;
std::condition_variable owner_runtime_cv;
bool owner_thread_stopping{false};
bool owner_main_draining{false};
std::vector<std::thread> owner_threads;

bool valid_owner_id(const char *owner_id) {
  return owner_id && owner_id[0] != '\0';
}

const char *normalize_owner_id(const char *owner_id) {
  return valid_owner_id(owner_id) ? owner_id : kDefaultOwnerId;
}

bool owner_id_is_default(const char *owner_id) { return std::strcmp(normalize_owner_id(owner_id), kDefaultOwnerId) == 0; }

const char *normalize_task_text(const char *text, const char *fallback) {
  return text && text[0] != '\0' ? text : fallback;
}

const char *owner_object_name(object_t *object) {
  return object && object->obname ? object->obname : "";
}

bool copy_owner_frozen_svalue(svalue_t *dest, svalue_t *source);

bool copy_owner_frozen_array(svalue_t *dest, array_t *source) {
  auto *array = allocate_array(source ? source->size : 0);
  for (int i = 0; source && i < source->size; i++) {
    if (!copy_owner_frozen_svalue(&array->item[i], &source->item[i])) {
      free_array(array);
      return false;
    }
  }
  dest->type = T_ARRAY;
  dest->subtype = 0;
  dest->u.arr = array;
  return true;
}

bool copy_owner_frozen_mapping(svalue_t *dest, mapping_t *source) {
  auto *map = allocate_mapping(source ? MAP_COUNT(source) : 0);
  if (source) {
    for (unsigned int i = 0; i <= source->table_size; i++) {
      for (auto *node = source->table[i]; node; node = node->next) {
        if (node->values[0].type != T_STRING) {
          free_mapping(map);
          return false;
        }
        svalue_t key{T_STRING, STRING_SHARED, {0}};
        key.u.string = make_shared_string(node->values[0].u.string ? node->values[0].u.string : "");
        auto *slot = find_for_insert(map, &key, 1);
        free_svalue(&key, "owner frozen mapping key");
        if (!copy_owner_frozen_svalue(slot, &node->values[1])) {
          free_mapping(map);
          return false;
        }
      }
    }
  }
  dest->type = T_MAPPING;
  dest->subtype = 0;
  dest->u.map = map;
  return true;
}

bool copy_owner_frozen_svalue(svalue_t *dest, svalue_t *source) {
  if (!source) {
    *dest = const0u;
    return true;
  }
  switch (source->type) {
    case T_NUMBER:
    case T_REAL:
      *dest = *source;
      return true;
    case T_STRING:
      dest->type = T_STRING;
      dest->subtype = STRING_SHARED;
      dest->u.string = make_shared_string(source->u.string ? source->u.string : "");
      return true;
    case T_ARRAY:
      return copy_owner_frozen_array(dest, source->u.arr);
    case T_MAPPING:
      return copy_owner_frozen_mapping(dest, source->u.map);
    default:
      return false;
  }
}

std::shared_ptr<OwnerFrozenValue> clone_owner_frozen_value(svalue_t *source) {
  auto value = std::make_shared<OwnerFrozenValue>();
  if (!copy_owner_frozen_svalue(&value->value, source)) {
    return nullptr;
  }
  return value;
}

void add_mapping_svalue(mapping_t *map, const char *key, svalue_t *value) {
  svalue_t key_sv{T_STRING, STRING_SHARED, {0}};
  key_sv.u.string = make_shared_string(key ? key : "");
  auto *slot = find_for_insert(map, &key_sv, 1);
  free_svalue(&key_sv, "owner future result key");
  assign_svalue_no_free(slot, value);
}

bool command_giver_owner_applies(object_t *source, object_t *target) {
  return vm_context().owner.current_owner_id == kDefaultOwnerId && vm_owner_has_explicit_id(command_giver) &&
         (source == command_giver || target == command_giver);
}

const char *effective_source_owner_id(object_t *source, object_t *target) {
  if (!vm_context().owner.current_owner_id.empty() && vm_context().owner.current_owner_id != kDefaultOwnerId) {
    if (owner_id_is_default(vm_owner_id(source))) {
      return vm_owner_id(source);
    }
    return vm_context().owner.current_owner_id.c_str();
  }
  if (command_giver_owner_applies(source, target)) {
    return vm_owner_id(command_giver);
  }
  return vm_owner_id(source);
}

uint64_t effective_source_owner_epoch(object_t *source, object_t *target) {
  if (!vm_context().owner.current_owner_id.empty() && vm_context().owner.current_owner_id != kDefaultOwnerId) {
    if (owner_id_is_default(vm_owner_id(source))) {
      return vm_owner_epoch(source);
    }
    return vm_context().owner.current_owner_epoch;
  }
  if (command_giver_owner_applies(source, target)) {
    return vm_owner_epoch(command_giver);
  }
  return vm_owner_epoch(source);
}

const char *owner_access_policy_mode(const char *operation, bool cross_owner) {
  if (!cross_owner) {
    return "same_owner";
  }
  if (std::strcmp(operation, "environment") == 0 || std::strcmp(operation, "all_inventory") == 0 ||
      std::strcmp(operation, "present") == 0) {
    return "snapshot";
  }
  if (std::strcmp(operation, "call_other") == 0 || std::strcmp(operation, "move_object") == 0 ||
      std::strcmp(operation, "destruct") == 0) {
    return "message";
  }
  return "reject";
}

bool owner_policy_allows_direct_access(const char *policy_mode) {
  return std::strcmp(policy_mode, "same_owner") == 0 || std::strcmp(policy_mode, "snapshot") == 0;
}

void record_owner_access_policy_counter(const char *policy_mode) {
  if (std::strcmp(policy_mode, "snapshot") == 0) {
    total_cross_owner_snapshot_accesses.fetch_add(1, std::memory_order_relaxed);
  } else if (std::strcmp(policy_mode, "message") == 0) {
    total_cross_owner_message_accesses.fetch_add(1, std::memory_order_relaxed);
  } else if (std::strcmp(policy_mode, "reject") == 0) {
    total_cross_owner_rejected_accesses.fetch_add(1, std::memory_order_relaxed);
  }
}

long owner_mailbox_depth(const std::string &owner_id) {
  auto it = owner_mailboxes.find(owner_id);
  return it == owner_mailboxes.end() ? 0 : static_cast<long>(it->second.size());
}

long owner_mailbox_total_depth() {
  long depth = 0;
  for (const auto &entry : owner_mailboxes) {
    depth += static_cast<long>(entry.second.size());
  }
  return depth;
}

long owner_main_queue_total_depth() {
  long depth = 0;
  for (const auto &entry : owner_main_queues) {
    depth += static_cast<long>(entry.second.size());
  }
  return depth;
}

long owner_mailbox_active_owners() {
  long owners = 0;
  for (const auto &entry : owner_mailboxes) {
    if (!entry.second.empty()) {
      owners++;
    }
  }
  return owners;
}

mapping_t *owner_mailbox_task_mapping(const OwnerMailboxTask &task) {
  auto *map = allocate_mapping(10);
  add_mapping_pair(map, "task_id", static_cast<long>(task.task_id));
  add_mapping_pair(map, "future_target_task_id", static_cast<long>(task.future_target_task_id));
  add_mapping_pair(map, "sequence", static_cast<long>(task.sequence));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(task.owner_epoch));
  add_mapping_string(map, "owner_id", task.owner_id.c_str());
  add_mapping_string(map, "task_type", task.task_type.c_str());
  add_mapping_string(map, "task_key", task.task_key.c_str());
  add_mapping_string(map, "future_state", task.future_state.c_str());
  add_mapping_string(map, "future_error", task.future_error.c_str());
  add_mapping_string(map, "target_object",
                     task.target_object.empty() ? owner_object_name(task.target) : task.target_object.c_str());
  return map;
}

mapping_t *owner_task_trace_mapping(const OwnerTaskTrace &trace) {
  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "trace_id", static_cast<long>(trace.trace_id));
  add_mapping_pair(map, "task_id", static_cast<long>(trace.task_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(trace.owner_epoch));
  add_mapping_string(map, "owner_id", trace.owner_id.c_str());
  add_mapping_string(map, "task_type", trace.task_type.c_str());
  add_mapping_string(map, "task_key", trace.task_key.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  return map;
}

void release_owner_task_target(OwnerMailboxTask *task) {
  if (task && task->target) {
    auto *target = task->target;
    if (vm_context_is_main_thread()) {
      free_object(&target, "owner mailbox task");
    } else {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      owner_deferred_target_releases.push_back(target);
    }
    task->target = nullptr;
  }
}

void release_owner_main_task_target(OwnerMainTask *task) {
  if (task && task->target) {
    auto *target = task->target;
    if (vm_context_is_main_thread()) {
      free_object(&target, "owner main task");
    } else {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      owner_deferred_target_releases.push_back(target);
    }
    task->target = nullptr;
  }
}

void release_deferred_owner_targets_on_main() {
  if (!vm_context_is_main_thread()) {
    return;
  }
  std::vector<object_t *> releases;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    releases.swap(owner_deferred_target_releases);
  }
  for (auto *target : releases) {
    if (target) {
      free_object(&target, "owner mailbox task deferred release");
    }
  }
}

void record_owner_mailbox_task_drained(const OwnerMailboxTask &task) {
  if (task.task_type == "owner_message") {
    vm_object_store_remove_message(task.owner_id.c_str(), task.task_id);
  }
}

mapping_t *owner_access_trace_mapping(const OwnerAccessTrace &trace) {
  auto policy_mode = owner_access_policy_mode(trace.operation.c_str(), trace.cross_owner);
  auto *map = allocate_mapping(15);
  add_mapping_pair(map, "access_id", static_cast<long>(trace.access_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "source_owner_epoch", static_cast<long>(trace.source_owner_epoch));
  add_mapping_pair(map, "target_owner_epoch", static_cast<long>(trace.target_owner_epoch));
  add_mapping_pair(map, "cross_owner", trace.cross_owner ? 1 : 0);
  add_mapping_string(map, "source_owner_id", trace.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", trace.target_owner_id.c_str());
  add_mapping_string(map, "source_object", trace.source_object.c_str());
  add_mapping_string(map, "target_object", trace.target_object.c_str());
  add_mapping_string(map, "operation", trace.operation.c_str());
  add_mapping_string(map, "access_mode", policy_mode);
  add_mapping_pair(map, "snapshot_only", std::strcmp(policy_mode, "snapshot") == 0 ? 1 : 0);
  add_mapping_pair(map, "message_only_cross_owner", std::strcmp(policy_mode, "message") == 0 ? 1 : 0);
  add_mapping_pair(map, "rejected_by_default", std::strcmp(policy_mode, "reject") == 0 ? 1 : 0);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *owner_message_trace_mapping(const OwnerMessageTrace &trace) {
  auto *map = allocate_mapping(10);
  add_mapping_pair(map, "message_id", static_cast<long>(trace.message_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "target_task_id", static_cast<long>(trace.target_task_id));
  add_mapping_string(map, "source_owner_id", trace.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", trace.target_owner_id.c_str());
  add_mapping_string(map, "message_type", trace.message_type.c_str());
  add_mapping_string(map, "payload_key", trace.payload_key.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_pair(map, "payload_frozen", 1);
  return map;
}

mapping_t *owner_commit_trace_mapping(const OwnerCommitTrace &trace) {
  auto *map = allocate_mapping(9);
  add_mapping_pair(map, "commit_id", static_cast<long>(trace.commit_id));
  add_mapping_pair(map, "sequence", static_cast<long>(trace.sequence));
  add_mapping_pair(map, "message_id", static_cast<long>(trace.message_id));
  add_mapping_pair(map, "direct_write", trace.direct_write ? 1 : 0);
  add_mapping_string(map, "source_owner_id", trace.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", trace.target_owner_id.c_str());
  add_mapping_string(map, "operation", trace.operation.c_str());
  add_mapping_string(map, "state", trace.state.c_str());
  add_mapping_pair(map, "commit_boundary_only", 1);
  return map;
}

uint64_t append_owner_task_trace(uint64_t task_id, uint64_t sequence, const std::string &owner_id,
                                 uint64_t owner_epoch, const std::string &task_type,
                                 const std::string &task_key, const char *state) {
  OwnerTaskTrace trace;
  trace.trace_id = next_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.task_id = task_id;
  trace.sequence = sequence;
  trace.owner_epoch = owner_epoch;
  trace.owner_id = owner_id;
  trace.task_type = task_type;
  trace.task_key = task_key;
  trace.state = normalize_task_text(state, "observed");
  owner_task_traces.push_back(std::move(trace));
  while (owner_task_traces.size() > kOwnerTraceLimit) {
    owner_task_traces.pop_front();
  }
  total_traced.fetch_add(1, std::memory_order_relaxed);
  return owner_task_traces.back().trace_id;
}

uint64_t append_owner_task_trace(const OwnerMailboxTask &task, const char *state) {
  return append_owner_task_trace(task.task_id, task.sequence, task.owner_id, task.owner_epoch, task.task_type,
                                 task.task_key, state);
}

uint64_t append_owner_task_trace(const OwnerMainTask &task, const char *state) {
  return append_owner_task_trace(task.task_id, task.sequence, task.owner_id, task.owner_epoch, task.task_type,
                                 task.task_key, state);
}

uint64_t append_owner_task_trace_threadsafe(const OwnerMailboxTask &task, const char *state) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return append_owner_task_trace(task, state);
}

mapping_t *owner_future_mapping(const OwnerFutureRecord &record) {
  auto *map = allocate_mapping(20);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "future_id", static_cast<long>(record.future_id));
  add_mapping_pair(map, "target_task_id", static_cast<long>(record.target_task_id));
  add_mapping_string(map, "source_owner_id", record.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", record.target_owner_id.c_str());
  add_mapping_string(map, "message_type", record.message_type.c_str());
  add_mapping_string(map, "payload_key", record.payload_key.c_str());
  add_mapping_string(map, "state", record.state.c_str());
  add_mapping_string(map, "result_key", record.result_key.c_str());
  add_mapping_string(map, "error", record.error.c_str());
  add_mapping_pair(map, "requires_owner_message_completion", record.state == "pending" ? 1 : 0);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "frozen_result", record.state == "completed" ? 1 : 0);
  add_mapping_pair(map, "has_target_handle", record.has_target_handle ? 1 : 0);
  add_mapping_pair(map, "target_handle_current",
                   !record.has_target_handle || vm_object_handle_is_current(record.target_handle) ? 1 : 0);
  add_mapping_pair(map, "target_object_id", static_cast<long>(record.target_handle.object_id));
  add_mapping_string(map, "target_object_path", record.target_handle.object_path.c_str());
  add_mapping_pair(map, "target_owner_epoch", static_cast<long>(record.target_handle.owner_epoch));
  if (record.result) {
    add_mapping_svalue(map, "result", &record.result->value);
  }
  return map;
}

bool owner_message_target_current(const OwnerMailboxTask &task) {
  return !task.has_target_handle || vm_object_handle_is_current(task.target_handle);
}

void complete_owner_future_locked(uint64_t future_id, const char *state, const char *result_key, const char *error,
                                  std::shared_ptr<OwnerFrozenValue> result = nullptr) {
  auto it = owner_futures.find(future_id);
  if (it == owner_futures.end()) {
    return;
  }
  if (it->second.state != "pending") {
    return;
  }
  it->second.state = normalize_task_text(state, "completed");
  it->second.result_key = normalize_task_text(result_key, "");
  it->second.error = normalize_task_text(error, "");
  it->second.result = std::move(result);
  if (it->second.state == "failed") {
    total_futures_failed.fetch_add(1, std::memory_order_relaxed);
  } else {
    total_futures_completed.fetch_add(1, std::memory_order_relaxed);
  }
}

void update_owner_message_trace_state_for_task_locked(uint64_t target_task_id, const char *state) {
  for (auto &trace : owner_message_traces) {
    if (trace.target_task_id == target_task_id) {
      trace.state = normalize_task_text(state, "completed");
      return;
    }
  }
}

void complete_owner_future_for_task_locked(uint64_t target_task_id, const char *state, const char *result_key,
                                            const char *error,
                                            std::shared_ptr<OwnerFrozenValue> result = nullptr) {
  for (auto &entry : owner_futures) {
    if (entry.second.target_task_id == target_task_id && entry.second.state == "pending") {
      entry.second.state = normalize_task_text(state, "completed");
      entry.second.result_key = normalize_task_text(result_key, "");
      entry.second.error = normalize_task_text(error, "");
      entry.second.result = std::move(result);
      update_owner_message_trace_state_for_task_locked(target_task_id, entry.second.state.c_str());
      if (entry.second.state == "failed") {
        total_futures_failed.fetch_add(1, std::memory_order_relaxed);
      } else {
        total_futures_completed.fetch_add(1, std::memory_order_relaxed);
      }
      return;
    }
  }
}

void complete_owner_message_task_locked(const OwnerMailboxTask &task) {
  if (owner_message_target_current(task)) {
    complete_owner_future_for_task_locked(task.task_id, "completed", task.task_key.c_str(), "");
  } else {
    complete_owner_future_for_task_locked(task.task_id, "failed", "", "stale target");
  }
}

void complete_owner_message_task_threadsafe(const OwnerMailboxTask &task, const char *state,
                                            const char *result_key, const char *error,
                                            std::shared_ptr<OwnerFrozenValue> result = nullptr) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  complete_owner_future_for_task_locked(task.task_id, state, result_key, error, std::move(result));
}

void dispatch_owner_message_on_main(const OwnerMailboxTask &task) {
  if (!task.has_target_handle) {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    complete_owner_message_task_locked(task);
    return;
  }
  if (!owner_message_target_current(task)) {
    complete_owner_message_task_threadsafe(task, "failed", "", "stale target");
    return;
  }

  auto *target = vm_object_handle_resolve(task.target_handle);
  if (!target || (target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(target, task.owner_id.c_str(), task.owner_epoch)) {
    complete_owner_message_task_threadsafe(task, "failed", "", "stale target");
    return;
  }

  VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
  set_eval(max_eval_cost);
  int num_args = 0;
  if (task.payload) {
    push_svalue(&task.payload->value);
    num_args = 1;
  }
  auto *result = safe_apply(task.task_key.c_str(), target, num_args, ORIGIN_DRIVER);
  if (!result) {
    complete_owner_message_task_threadsafe(task, "failed", "", "lpc call failed");
    return;
  }
  auto frozen_result = clone_owner_frozen_value(result);
  if (!frozen_result) {
    complete_owner_message_task_threadsafe(task, "failed", "", "owner async result must be frozen data");
    return;
  }
  complete_owner_message_task_threadsafe(task, "completed", task.task_key.c_str(), "", std::move(frozen_result));
}

void complete_owner_compute_result_task_locked(const OwnerMailboxTask &task) {
  auto target_task_id = task.future_target_task_id == 0 ? task.task_id : task.future_target_task_id;
  auto state = task.future_state.empty() ? "completed" : task.future_state.c_str();
  auto result_key = std::strcmp(state, "failed") == 0 ? "" : task.task_key.c_str();
  complete_owner_future_for_task_locked(target_task_id, state, result_key, task.future_error.c_str());
}

void mark_owner_schedulable(const std::string &owner_id);
void mark_main_owner_schedulable(const std::string &owner_id);

bool owner_task_requires_main_drain(const OwnerMailboxTask &task) {
  return task.task_type == "owner_message" && task.has_target_handle;
}

bool owner_queue_has_thread_task(const std::deque<OwnerMailboxTask> &queue) {
  for (const auto &task : queue) {
    if (!owner_task_requires_main_drain(task)) {
      return true;
    }
  }
  return false;
}

void enqueue_owner_task_locked(OwnerMailboxTask task, const std::string &owner_id, bool *notify_owner_thread) {
  append_owner_task_trace(task, "queued");
  auto &queue = owner_mailboxes[owner_id];
  auto had_thread_task = owner_queue_has_thread_task(queue);
  auto task_requires_main = owner_task_requires_main_drain(task);
  queue.push_back(std::move(task));
  if (!task_requires_main && !had_thread_task && active_owner_set.count(owner_id) == 0) {
    mark_owner_schedulable(owner_id);
    *notify_owner_thread = true;
  }
}

void mark_owner_schedulable(const std::string &owner_id) {
  if (schedulable_owner_set.insert(owner_id).second) {
    schedulable_owners.push_back(owner_id);
  }
}

void mark_main_owner_schedulable(const std::string &owner_id) {
  if (main_schedulable_owner_set.insert(owner_id).second) {
    main_schedulable_owners.push_back(owner_id);
  }
}

void finish_active_main_owner_task(const std::string &owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  if (active_main_owner_set.erase(owner_id) > 0) {
    owner_main_owner_releases.fetch_add(1, std::memory_order_relaxed);
  }
  auto it = owner_main_queues.find(owner_id);
  if (it != owner_main_queues.end() && !it->second.empty()) {
    mark_main_owner_schedulable(owner_id);
  }
}

void finish_active_owner_task(const std::string &owner_id) {
  bool notify_owner_thread = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (active_owner_set.erase(owner_id) > 0) {
      owner_executor_owner_releases.fetch_add(1, std::memory_order_relaxed);
    }
    auto it = owner_mailboxes.find(owner_id);
    if (it != owner_mailboxes.end() && owner_queue_has_thread_task(it->second)) {
      mark_owner_schedulable(owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
}

bool pop_next_schedulable_task(OwnerMailboxTask *out, bool claim_owner) {
  while (!schedulable_owners.empty()) {
    auto owner_id = schedulable_owners.front();
    schedulable_owners.pop_front();
    if (schedulable_owner_set.erase(owner_id) == 0) {
      continue;
    }
    if (active_owner_set.count(owner_id) > 0) {
      continue;
    }

    auto it = owner_mailboxes.find(owner_id);
    if (it == owner_mailboxes.end() || it->second.empty()) {
      owner_mailboxes.erase(owner_id);
      continue;
    }

    auto task_it = it->second.begin();
    while (task_it != it->second.end() && owner_task_requires_main_drain(*task_it)) {
      ++task_it;
    }
    if (task_it == it->second.end()) {
      continue;
    }

    *out = *task_it;
    it->second.erase(task_it);
    if (it->second.empty()) {
      owner_mailboxes.erase(it);
    } else if (!claim_owner && owner_queue_has_thread_task(it->second)) {
      mark_owner_schedulable(owner_id);
    }
    if (claim_owner) {
      active_owner_set.insert(owner_id);
      owner_executor_owner_claims.fetch_add(1, std::memory_order_relaxed);
    }
    return true;
  }

  return false;
}

bool pop_next_main_task(OwnerMainTask *out, bool claim_owner) {
  while (!main_schedulable_owners.empty()) {
    auto owner_id = main_schedulable_owners.front();
    main_schedulable_owners.pop_front();
    if (main_schedulable_owner_set.erase(owner_id) == 0) {
      continue;
    }
    if (claim_owner && active_main_owner_set.count(owner_id) > 0) {
      continue;
    }

    auto it = owner_main_queues.find(owner_id);
    if (it == owner_main_queues.end() || it->second.empty()) {
      owner_main_queues.erase(owner_id);
      continue;
    }

    *out = std::move(it->second.front());
    it->second.pop_front();
    if (it->second.empty()) {
      owner_main_queues.erase(it);
    } else if (!claim_owner) {
      mark_main_owner_schedulable(owner_id);
    }
    if (claim_owner) {
      active_main_owner_set.insert(owner_id);
      owner_main_owner_claims.fetch_add(1, std::memory_order_relaxed);
    }
    return true;
  }

  return false;
}

bool owner_execution_state_cleared() {
  const auto &execution = vm_context().execution;
  const auto &error = vm_context().error;
  const auto &object_store = vm_context().object_store;
  return execution.current_object == nullptr && execution.command_giver == nullptr &&
         execution.current_interactive == nullptr && execution.previous_ob == nullptr &&
         execution.current_prog == nullptr && execution.caller_type == 0 &&
         execution.call_origin == 0 &&
         execution.function_index_offset == 0 && execution.variable_index_offset == 0 &&
         execution.stack_in_use_as_temporary == 0 &&
         error.current_error_context == nullptr && error.too_deep_error == 0 &&
         error.max_eval_error == 0 && error.error_depth == 0 &&
         error.mudlib_error_depth == 0 && object_store.load_object_depth == 0 &&
         object_store.restricted_destruct_object == nullptr;
}

constexpr std::array<const char *, 18> kRegisteredOwnerLpcTasks = {
    "owner_task_readonly",    "owner_task_player", "owner_task_room",       "owner_task_session",
    "owner_task_item",        "owner_task_economy", "owner_task_combat",     "owner_task_mail",
    "owner_task_reward",      "owner_task_world",   "owner_task_persistence", "owner_task_team",
    "owner_task_guild",       "owner_task_sect",    "owner_task_quest",      "owner_task_rank",
    "owner_task_crafting",    "owner_task_life_skill"};

constexpr int kOwnerExecutorTaskBudget = 32;

bool owner_lpc_task_allowed(const OwnerMailboxTask &task) {
  for (const auto *method : kRegisteredOwnerLpcTasks) {
    if (task.task_key == method) {
      return true;
    }
  }
  return false;
}

void record_owner_context_cleanup(const OwnerMailboxTask &task) {
  auto owner_cleared = vm_context().owner.current_owner_id.empty() &&
                       vm_context().owner.current_owner_epoch == 0;
  auto execution_cleared = owner_execution_state_cleared();
  auto canary_cleared = !vm_context().owner.lpc_canary_active;

  if (owner_cleared) {
    owner_thread_owner_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  if (execution_cleared) {
    owner_thread_execution_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  if (canary_cleared) {
    owner_thread_lpc_canary_flag_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  if (!owner_cleared || !execution_cleared || !canary_cleared) {
    append_owner_task_trace_threadsafe(task, "thread_context_leak_detected");
    owner_thread_context_leak_detected.fetch_add(1, std::memory_order_relaxed);
  }
}

void run_owner_lpc_probe(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;
  if (off_main_context && object_store_isolated && owner_bound && !task.target_object.empty()) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_probe_guarded");
    owner_thread_lpc_probe_guarded.fetch_add(1, std::memory_order_relaxed);
  } else {
    append_owner_task_trace_threadsafe(task, "thread_lpc_probe_failed");
    owner_thread_lpc_probe_failed.fetch_add(1, std::memory_order_relaxed);
  }
}

void run_owner_lpc_canary(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;
  auto method_allowed = task.task_key == "owner_lpc_canary";

  if (!off_main_context || !object_store_isolated || !owner_bound || !task.target ||
      !method_allowed || (task.target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(task.target, task.owner_id.c_str(), task.owner_epoch)) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_canary_rejected");
    owner_thread_lpc_canary_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  VMExecutionState execution;
  execution.current_object = task.target;
  execution.current_prog = task.target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  auto saved_canary = vm_context().owner.lpc_canary_active;
  vm_context().owner.lpc_canary_active = true;
  owner_thread_lpc_canary_executed.fetch_add(1, std::memory_order_relaxed);
  auto *result = safe_apply(task.task_key.c_str(), task.target, 0, ORIGIN_DRIVER);
  vm_context().owner.lpc_canary_active = saved_canary;

  if (result && result->type == T_NUMBER && result->u.number == 1) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_canary_succeeded");
    owner_thread_lpc_canary_succeeded.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  append_owner_task_trace_threadsafe(task, "thread_lpc_canary_failed");
  owner_thread_lpc_canary_failed.fetch_add(1, std::memory_order_relaxed);
}

void run_owner_lpc_task(const OwnerMailboxTask &task) {
  auto off_main_context = &vm_context() != &vm_main_context();
  auto object_store_isolated = !vm_context().object_store.main_thread_owned &&
                               vm_context().object_store.objects == nullptr;
  auto owner_bound = vm_context().owner.current_owner_id == task.owner_id &&
                     vm_context().owner.current_owner_epoch == task.owner_epoch;

  if (!off_main_context || !object_store_isolated || !owner_bound || !task.target ||
      !owner_lpc_task_allowed(task) || (task.target->flags & O_DESTRUCTED) ||
      !vm_owner_epoch_matches(task.target, task.owner_id.c_str(), task.owner_epoch)) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_rejected");
    owner_thread_lpc_task_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  VMExecutionState execution;
  execution.current_object = task.target;
  execution.current_prog = task.target->prog;
  VMExecutionScope execution_scope(vm_context(), execution);
  owner_thread_lpc_task_executed.fetch_add(1, std::memory_order_relaxed);
  auto *result = safe_apply(task.task_key.c_str(), task.target, 0, ORIGIN_DRIVER);

  if (result && result->type == T_NUMBER && result->u.number == 1) {
    append_owner_task_trace_threadsafe(task, "thread_lpc_task_succeeded");
    owner_thread_lpc_task_succeeded.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  append_owner_task_trace_threadsafe(task, "thread_lpc_task_failed");
  owner_thread_lpc_task_failed.fetch_add(1, std::memory_order_relaxed);
}

void owner_thread_loop() {
  VMContext owner_context;
  VMContextThreadScope context_scope(owner_context);
  if (&vm_context() != &vm_main_context()) {
    owner_thread_context_bound.fetch_add(1, std::memory_order_relaxed);
  }
  if (!vm_context().object_store.main_thread_owned && vm_context().object_store.objects == nullptr) {
    owner_thread_object_store_isolated.fetch_add(1, std::memory_order_relaxed);
  }
  reset_machine(1);

  while (true) {
    std::string claimed_owner;
    int budget_used = 0;
    {
      std::unique_lock<std::mutex> lock(owner_runtime_mutex);
      owner_runtime_cv.wait(lock, [] { return owner_thread_stopping || !schedulable_owners.empty(); });
      if (owner_thread_stopping) {
        return;
      }
      OwnerMailboxTask first_task;
      if (!pop_next_schedulable_task(&first_task, true)) {
        continue;
      }
      claimed_owner = first_task.owner_id;
      owner_mailboxes[claimed_owner].push_front(std::move(first_task));
    }

    while (budget_used < kOwnerExecutorTaskBudget) {
      OwnerMailboxTask task;
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        auto it = owner_mailboxes.find(claimed_owner);
        if (it == owner_mailboxes.end() || it->second.empty()) {
          owner_mailboxes.erase(claimed_owner);
          break;
        }
        task = it->second.front();
        it->second.pop_front();
        if (it->second.empty()) {
          owner_mailboxes.erase(it);
        }
      }
      record_owner_mailbox_task_drained(task);

      {
        VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
        if (vm_context().owner.current_owner_id == task.owner_id &&
            vm_context().owner.current_owner_epoch == task.owner_epoch) {
          owner_thread_owner_bound.fetch_add(1, std::memory_order_relaxed);
        }
        append_owner_task_trace_threadsafe(task, "thread_dispatched");
        if (task.task_type == "lpc_probe") {
          run_owner_lpc_probe(task);
        } else if (task.task_type == "lpc_canary") {
          run_owner_lpc_canary(task);
        } else if (task.task_type == "lpc_task") {
          run_owner_lpc_task(task);
        } else if (task.task_type == "lpc") {
          append_owner_task_trace_threadsafe(task, "thread_lpc_rejected");
          owner_thread_lpc_rejected.fetch_add(1, std::memory_order_relaxed);
        } else if (task.task_type == "owner_state") {
          append_owner_task_trace_threadsafe(task, "thread_owner_state_guarded");
          owner_thread_owner_state_guarded.fetch_add(1, std::memory_order_relaxed);
        } else if (task.task_type == "owner_message") {
          append_owner_task_trace_threadsafe(task, "thread_message_dispatched");
          owner_thread_message_dispatched.fetch_add(1, std::memory_order_relaxed);
          std::lock_guard<std::mutex> lock(owner_runtime_mutex);
          complete_owner_message_task_locked(task);
        } else if (task.task_type == "compute_result") {
          append_owner_task_trace_threadsafe(task, "thread_compute_result_completed");
          std::lock_guard<std::mutex> lock(owner_runtime_mutex);
          complete_owner_compute_result_task_locked(task);
        }
        total_drained.fetch_add(1, std::memory_order_relaxed);
        owner_thread_dispatched.fetch_add(1, std::memory_order_relaxed);
      }

      record_owner_context_cleanup(task);
      release_owner_task_target(&task);
      budget_used++;
    }
    if (budget_used >= kOwnerExecutorTaskBudget) {
      owner_executor_budget_yields.fetch_add(1, std::memory_order_relaxed);
    }
    finish_active_owner_task(claimed_owner);
  }
}
}  // namespace

const char *vm_owner_default_id() { return kDefaultOwnerId; }

int vm_multicore_mode() {
  auto mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  if (mode < VM_MULTICORE_MODE_OFF || mode > VM_MULTICORE_MODE_ENFORCED) {
    return VM_MULTICORE_MODE_AUDIT;
  }
  return mode;
}

const char *vm_multicore_mode_name(int mode) {
  switch (mode) {
    case VM_MULTICORE_MODE_OFF:
      return "off";
    case VM_MULTICORE_MODE_ENFORCED:
      return "enforced";
    case VM_MULTICORE_MODE_AUDIT:
    default:
      return "audit";
  }
}

bool vm_multicore_audit_enabled() { return vm_multicore_mode() != VM_MULTICORE_MODE_OFF; }

bool vm_multicore_enforced() { return vm_multicore_mode() == VM_MULTICORE_MODE_ENFORCED; }

const char *vm_owner_id(object_t *object) {
  if (!object || !valid_owner_id(object->vm_owner_id)) {
    return kDefaultOwnerId;
  }
  return object->vm_owner_id;
}

bool vm_owner_has_explicit_id(object_t *object) { return object && valid_owner_id(object->vm_owner_id); }

uint64_t vm_owner_epoch(object_t *object) { return object ? object->vm_owner_epoch : 0; }

void vm_owner_set_id(object_t *object, const char *owner_id) {
  if (!object) {
    return;
  }
  if (!valid_owner_id(owner_id)) {
    owner_id = kDefaultOwnerId;
  }
  if (object->vm_owner_id && std::strcmp(object->vm_owner_id, owner_id) == 0) {
    return;
  }
  if (object->vm_owner_id) {
    free_string(object->vm_owner_id);
  }
  object->vm_owner_id = make_shared_string(owner_id);
  object->vm_owner_epoch++;
  vm_object_store_update_owner(object);
}

void vm_owner_assign_default(object_t *object, object_t *context_object, const char *fallback_owner_id) {
  if (!object || valid_owner_id(object->vm_owner_id)) {
    return;
  }
  const char *owner_id = nullptr;
  if (valid_owner_id(fallback_owner_id)) {
    owner_id = fallback_owner_id;
  } else if (context_object && valid_owner_id(context_object->vm_owner_id)) {
    owner_id = vm_owner_id(context_object);
  } else if (!vm_context().owner.current_owner_id.empty()) {
    owner_id = vm_context().owner.current_owner_id.c_str();
  } else {
    owner_id = kDefaultOwnerId;
  }
  vm_owner_set_id(object, owner_id);
}

void vm_owner_clear_id(object_t *object) {
  if (object && object->vm_owner_id) {
    free_string(object->vm_owner_id);
    object->vm_owner_id = nullptr;
    object->vm_owner_epoch++;
    vm_object_store_update_owner(object);
  }
}

bool vm_owner_matches(object_t *object, const char *expected_owner_id) {
  if (!valid_owner_id(expected_owner_id)) {
    expected_owner_id = kDefaultOwnerId;
  }
  return std::strcmp(vm_owner_id(object), expected_owner_id) == 0;
}

bool vm_owner_epoch_matches(object_t *object, const char *expected_owner_id, uint64_t expected_epoch) {
  return vm_owner_matches(object, expected_owner_id) && vm_owner_epoch(object) == expected_epoch;
}

void vm_owner_record_check(object_t *object, const char *expected_owner_id, bool matched) {
  total_checks.fetch_add(1, std::memory_order_relaxed);
  if (!matched) {
    mismatch_checks.fetch_add(1, std::memory_order_relaxed);
  }
}

uint64_t vm_owner_total_checks() { return total_checks.load(std::memory_order_relaxed); }

uint64_t vm_owner_mismatch_checks() { return mismatch_checks.load(std::memory_order_relaxed); }

mapping_t *vm_owner_status(object_t *object) {
  auto *map = allocate_mapping(10);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "default_owner_id", kDefaultOwnerId);
  add_mapping_pair(map, "multicore_mode", vm_multicore_mode());
  add_mapping_string(map, "multicore_mode_name", vm_multicore_mode_name(vm_multicore_mode()));
  add_mapping_pair(map, "multicore_enforced", vm_multicore_enforced() ? 1 : 0);
  add_mapping_pair(map, "total_checks", static_cast<long>(vm_owner_total_checks()));
  add_mapping_pair(map, "mismatch_checks", static_cast<long>(vm_owner_mismatch_checks()));
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  add_mapping_pair(map, "has_explicit_owner", object && object->vm_owner_id ? 1 : 0);
  return map;
}

mapping_t *vm_owner_guard(object_t *object, const char *expected_owner_id) {
  const char *normalized_owner_id = normalize_owner_id(expected_owner_id);
  auto matched = vm_owner_matches(object, normalized_owner_id);
  vm_owner_record_check(object, normalized_owner_id, matched);
  if (!matched) {
    error("vm_owner_guard(): owner mismatch: object owner '%s', expected '%s'.\n", vm_owner_id(object),
          normalized_owner_id);
  }

  auto *map = allocate_mapping(5);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "expected_owner_id", normalized_owner_id);
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  return map;
}

mapping_t *vm_owner_guard_epoch(object_t *object, const char *expected_owner_id, uint64_t expected_epoch) {
  const char *normalized_owner_id = normalize_owner_id(expected_owner_id);
  auto matched = vm_owner_epoch_matches(object, normalized_owner_id, expected_epoch);
  vm_owner_record_check(object, normalized_owner_id, matched);
  if (!matched) {
    error("vm_owner_guard_epoch(): owner epoch mismatch: object owner '%s' epoch %llu, expected '%s' epoch %llu.\n",
          vm_owner_id(object), static_cast<unsigned long long>(vm_owner_epoch(object)), normalized_owner_id,
          static_cast<unsigned long long>(expected_epoch));
  }

  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "expected_owner_id", normalized_owner_id);
  add_mapping_pair(map, "expected_owner_epoch", static_cast<long>(expected_epoch));
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  return map;
}

uint64_t vm_owner_enqueue_task(const char *owner_id, const char *task_type, const char *task_key) {
  return vm_owner_enqueue_task_epoch(owner_id, task_type, task_key, 0);
}

uint64_t vm_owner_enqueue_task_epoch(const char *owner_id, const char *task_type, const char *task_key,
                                      uint64_t owner_epoch) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = owner_epoch;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = normalize_task_text(task_type, "generic");
  task.task_key = normalize_task_text(task_key, "");
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto was_empty = queue.empty();
    queue.push_back(std::move(task));
    if (was_empty && active_owner_set.count(normalized_owner_id) == 0) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

mapping_t *vm_owner_lpc_probe(object_t *target, const char *owner_id, const char *method) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target ? vm_owner_epoch(target) : 0;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = "lpc_probe";
  task.task_key = normalize_task_text(method, "owner_lpc_probe");
  task.target_object = owner_object_name(target);
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;
  auto target_name = task.target_object;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto was_empty = queue.empty();
    queue.push_back(std::move(task));
    if (was_empty && active_owner_set.count(normalized_owner_id) == 0) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "task_type", "lpc_probe");
  add_mapping_string(map, "method", normalize_task_text(method, "owner_lpc_probe"));
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *vm_owner_lpc_canary(object_t *target, const char *owner_id, const char *method) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target ? vm_owner_epoch(target) : 0;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = "lpc_canary";
  task.task_key = normalize_task_text(method, "owner_lpc_canary");
  task.target_object = owner_object_name(target);
  task.target = target;
  if (task.target) {
    add_ref(task.target, "owner lpc canary task");
  }
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;
  auto target_name = task.target_object;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto was_empty = queue.empty();
    queue.push_back(std::move(task));
    if (was_empty && active_owner_set.count(normalized_owner_id) == 0) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(9);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "task_type", "lpc_canary");
  add_mapping_string(map, "method", normalize_task_text(method, "owner_lpc_canary"));
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(target ? vm_owner_epoch(target) : 0));
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

mapping_t *vm_owner_lpc_task(object_t *target, const char *owner_id, const char *method) {
  OwnerMailboxTask task;
  uint64_t task_id;
  bool notify_owner_thread = false;

  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target ? vm_owner_epoch(target) : 0;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = "lpc_task";
  task.task_key = normalize_task_text(method, "");
  task.target_object = owner_object_name(target);
  task.target = target;
  if (task.target) {
    add_ref(task.target, "owner lpc task");
  }
  task_id = task.task_id;
  auto normalized_owner_id = task.owner_id;
  auto target_name = task.target_object;
  auto method_name = task.task_key;
  auto allowed = owner_lpc_task_allowed(task) ? 1 : 0;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "queued");
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto was_empty = queue.empty();
    queue.push_back(std::move(task));
    if (was_empty && active_owner_set.count(normalized_owner_id) == 0) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(11);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "task_id", static_cast<long>(task_id));
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_string(map, "task_type", "lpc_task");
  add_mapping_string(map, "method", method_name.c_str());
  add_mapping_string(map, "target_object", target_name.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(target ? vm_owner_epoch(target) : 0));
  add_mapping_pair(map, "requires_owner_thread", 1);
  add_mapping_pair(map, "registered_task", allowed);
  add_mapping_pair(map, "ordinary_lpc_default_closed", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  return map;
}

uint64_t vm_owner_record_task_trace(const char *owner_id, const char *task_type, const char *task_key,
                                     uint64_t owner_epoch, const char *state) {
  auto sequence = total_traced.load(std::memory_order_relaxed) + 1;
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return append_owner_task_trace(0, sequence, normalize_owner_id(owner_id), owner_epoch,
                                  normalize_task_text(task_type, "generic"), normalize_task_text(task_key, ""), state);
}

uint64_t vm_owner_enqueue_main_task(object_t *target, const char *task_type, const char *task_key,
                                    std::function<void()> callback, std::function<void()> drop_callback) {
  if (!target || !callback) {
    return 0;
  }

  OwnerMainTask task;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_id = normalize_owner_id(vm_owner_id(target));
  task.owner_epoch = vm_owner_epoch(target);
  task.task_type = normalize_task_text(task_type, "main");
  task.task_key = normalize_task_text(task_key, "");
  task.target_object = owner_object_name(target);
  task.target = target;
  task.callback = std::move(callback);
  task.drop_callback = std::move(drop_callback);
  add_ref(target, "owner main task");

  auto task_id = task.task_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    append_owner_task_trace(task, "main_queued");
    auto &queue = owner_main_queues[task.owner_id];
    auto was_empty = queue.empty();
    queue.push_back(std::move(task));
    if (was_empty && active_main_owner_set.count(queue.back().owner_id) == 0) {
      mark_main_owner_schedulable(queue.back().owner_id);
    }
  }
  owner_main_queued.fetch_add(1, std::memory_order_relaxed);
  return task_id;
}

int vm_owner_drain_main_tasks(int limit) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (owner_main_draining) {
      return 0;
    }
    owner_main_draining = true;
  }

  int dispatched = 0;
  auto budget = limit <= 0 ? kOwnerExecutorTaskBudget : limit;
  while (dispatched < budget) {
    OwnerMainTask task;
    {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      if (!pop_next_main_task(&task, true)) {
        break;
      }
    }

    auto *target = task.target;
    bool stale = !target || (target->flags & O_DESTRUCTED) || task.owner_id != vm_owner_id(target) ||
                 task.owner_epoch != vm_owner_epoch(target);
    if (stale) {
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        append_owner_task_trace(task, target && (target->flags & O_DESTRUCTED) ? "main_destructed" : "main_stale");
        if (target && (target->flags & O_DESTRUCTED)) {
          owner_main_destructed.fetch_add(1, std::memory_order_relaxed);
        } else {
          owner_main_stale.fetch_add(1, std::memory_order_relaxed);
        }
      }
      if (task.drop_callback) {
        task.drop_callback();
      }
    } else {
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        append_owner_task_trace(task, "main_dispatched");
      }
      VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
      task.callback();
      owner_main_dispatched.fetch_add(1, std::memory_order_relaxed);
    }

    dispatched++;
    finish_active_main_owner_task(task.owner_id);
    release_owner_main_task_target(&task);
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (dispatched >= budget && owner_main_queue_total_depth() > 0) {
      owner_main_budget_yields.fetch_add(1, std::memory_order_relaxed);
    }
    owner_main_draining = false;
  }
  return dispatched;
}

uint64_t vm_owner_record_access(object_t *source, object_t *target, const char *operation) {
  if (!vm_multicore_audit_enabled()) {
    return 0;
  }
  OwnerAccessTrace trace;
  uint64_t access_id;
  trace.access_id = next_access_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_access_traced.fetch_add(1, std::memory_order_relaxed) + 1;
  trace.source_owner_epoch = effective_source_owner_epoch(source, target);
  trace.target_owner_epoch = vm_owner_epoch(target);
  trace.source_owner_id = effective_source_owner_id(source, target);
  trace.target_owner_id = vm_owner_id(target);
  trace.source_object = owner_object_name(source);
  trace.target_object = owner_object_name(target);
  trace.operation = normalize_task_text(operation, "access");
  trace.cross_owner = trace.source_owner_id != trace.target_owner_id;
  if (trace.cross_owner) {
    total_cross_owner_accesses.fetch_add(1, std::memory_order_relaxed);
    record_owner_access_policy_counter(owner_access_policy_mode(trace.operation.c_str(), trace.cross_owner));
  }
  access_id = trace.access_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_access_traces.push_back(std::move(trace));
    while (owner_access_traces.size() > kOwnerAccessTraceLimit) {
      owner_access_traces.pop_front();
    }
  }
  return access_id;
}

uint64_t vm_owner_record_cross_owner_access(object_t *source, object_t *target, const char *operation) {
  if (!source || !target || std::strcmp(effective_source_owner_id(source, target), vm_owner_id(target)) == 0) {
    return 0;
  }
  return vm_owner_record_access(source, target, operation);
}

bool vm_owner_cross_owner_access_blocked(object_t *source, object_t *target, const char *operation) {
  if (!source || !target || !vm_multicore_enforced()) {
    return false;
  }
  auto source_owner = effective_source_owner_id(source, target);
  auto target_owner = vm_owner_id(target);
  if (std::strcmp(source_owner, target_owner) == 0 || owner_id_is_default(source_owner) ||
      owner_id_is_default(target_owner)) {
    return false;
  }
  auto policy_mode = owner_access_policy_mode(normalize_task_text(operation, "access"), true);
  if (owner_policy_allows_direct_access(policy_mode)) {
    return false;
  }
  total_cross_owner_enforced_blocks.fetch_add(1, std::memory_order_relaxed);
  return true;
}

mapping_t *vm_owner_drain_mailbox(const char *owner_id, int limit) {
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  std::vector<OwnerMailboxTask> drained_tasks;

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    auto &queue = owner_mailboxes[normalized_owner_id];
    auto requested = limit <= 0 || static_cast<size_t>(limit) > queue.size() ? queue.size() : static_cast<size_t>(limit);

    drained_tasks.reserve(requested);
    for (size_t i = 0; i < requested; i++) {
      auto task = queue.front();
      queue.pop_front();
      append_owner_task_trace(task, "drained");
      record_owner_mailbox_task_drained(task);
      drained_tasks.push_back(std::move(task));
    }
    if (queue.empty()) {
      owner_mailboxes.erase(normalized_owner_id);
      schedulable_owner_set.erase(normalized_owner_id);
    }
    total_drained.fetch_add(drained_tasks.size(), std::memory_order_relaxed);
  }

  auto requested = drained_tasks.size();
  auto *tasks = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto &task = drained_tasks[i];
    if (task.task_type == "owner_message") {
      dispatch_owner_message_on_main(task);
    } else if (task.task_type == "compute_result") {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      complete_owner_compute_result_task_locked(task);
    }
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[i].type = T_MAPPING;
    tasks->item[i].subtype = 0;
    tasks->item[i].u.map = task_map;
    release_owner_task_target(&task);
  }

  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_pair(map, "drained", static_cast<long>(requested));
  add_mapping_pair(map, "remaining", owner_mailbox_depth(normalized_owner_id));
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_array(map, "tasks", tasks);
  free_array(tasks);
  return map;
}

mapping_t *vm_owner_purge_mailbox(const char *owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  auto purged = owner_mailbox_depth(normalized_owner_id);
  auto it = owner_mailboxes.find(normalized_owner_id);
  if (it != owner_mailboxes.end()) {
    for (const auto &task : it->second) {
      append_owner_task_trace(task, "purged");
    }
    for (auto &task : it->second) {
      if (task.task_type == "owner_message" || task.task_type == "compute_result") {
        auto target_task_id = task.future_target_task_id == 0 ? task.task_id : task.future_target_task_id;
        complete_owner_future_for_task_locked(target_task_id, "failed", "", "purged");
      }
      record_owner_mailbox_task_drained(task);
      release_owner_task_target(&task);
    }
  }
  owner_mailboxes.erase(normalized_owner_id);
  schedulable_owner_set.erase(normalized_owner_id);
  total_drained.fetch_add(purged, std::memory_order_relaxed);

  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_pair(map, "purged", purged);
  add_mapping_pair(map, "remaining", owner_mailbox_depth(normalized_owner_id));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_schedule(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto requested = limit <= 0 ? static_cast<size_t>(owner_mailbox_total_depth()) : static_cast<size_t>(limit);
  auto *tasks = allocate_array(static_cast<int>(requested));
  size_t dispatched = 0;

  while (dispatched < requested) {
    OwnerMailboxTask task;
    if (!pop_next_schedulable_task(&task, false)) {
      break;
    }
    append_owner_task_trace(task, "dispatched");
    if (task.task_type == "owner_message") {
      complete_owner_message_task_locked(task);
    } else if (task.task_type == "compute_result") {
      complete_owner_compute_result_task_locked(task);
    }
    record_owner_mailbox_task_drained(task);
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[dispatched].type = T_MAPPING;
    tasks->item[dispatched].subtype = 0;
    tasks->item[dispatched].u.map = task_map;
    release_owner_task_target(&task);
    dispatched++;
  }

  tasks->size = static_cast<int>(dispatched);
  total_drained.fetch_add(dispatched, std::memory_order_relaxed);

  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "dispatched", static_cast<long>(dispatched));
  add_mapping_pair(map, "remaining", owner_mailbox_total_depth());
  add_mapping_pair(map, "active_owners", owner_mailbox_active_owners());
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_array(map, "tasks", tasks);
  free_array(tasks);
  return map;
}

mapping_t *vm_owner_mailbox_status(const char *owner_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", normalized_owner_id.c_str());
  add_mapping_pair(map, "owner_queue_depth", owner_mailbox_depth(normalized_owner_id));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "active_owners", owner_mailbox_active_owners());
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_task_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_task_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_task_trace_mapping(owner_task_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(4);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_access_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_access_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_access_trace_mapping(owner_access_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(12);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "multicore_mode", vm_multicore_mode());
  add_mapping_string(map, "multicore_mode_name", vm_multicore_mode_name(vm_multicore_mode()));
  add_mapping_pair(map, "enforced_blocks",
                   static_cast<long>(total_cross_owner_enforced_blocks.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_access_traced.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "cross_owner", static_cast<long>(total_cross_owner_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "snapshot_required",
                   static_cast<long>(total_cross_owner_snapshot_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "message_required",
                   static_cast<long>(total_cross_owner_message_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "rejected_by_default",
                   static_cast<long>(total_cross_owner_rejected_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *submit_owner_message(const char *source_owner_id, const char *target_owner_id, const char *message_type,
                                const char *payload_key, const VMObjectHandle *target_handle, svalue_t *payload) {
  std::string source_owner = normalize_owner_id(source_owner_id);
  std::string target_owner = target_handle && !target_handle->owner_id.empty() ? target_handle->owner_id
                                                                              : normalize_owner_id(target_owner_id);
  std::string normalized_type = normalize_task_text(message_type, "message");
  std::string normalized_payload = normalize_task_text(payload_key, "");
  auto frozen_payload = payload ? clone_owner_frozen_value(payload) : nullptr;
  if (payload && !frozen_payload) {
    auto *map = allocate_mapping(4);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "frozen_payload", 0);
    add_mapping_string(map, "state", "rejected");
    add_mapping_string(map, "error", "owner payload must be frozen data");
    return map;
  }
  auto message_id = next_message_trace_id.fetch_add(1, std::memory_order_relaxed);

  OwnerMailboxTask task;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = target_handle ? target_handle->owner_epoch : 0;
  task.owner_id = target_owner;
  task.task_type = "owner_message";
  task.task_key = normalized_type;
  task.has_target_handle = target_handle != nullptr;
  task.payload = std::move(frozen_payload);
  if (target_handle) {
    task.target_handle = *target_handle;
    task.target_object = target_handle->object_path;
  }
  auto target_task_id = task.task_id;

  OwnerMessageTrace trace;
  trace.message_id = message_id;
  trace.sequence = total_message_traced.fetch_add(1, std::memory_order_relaxed) + 1;
  trace.target_task_id = target_task_id;
  trace.source_owner_id = source_owner;
  trace.target_owner_id = target_owner;
  trace.message_type = normalized_type;
  trace.payload_key = normalized_payload;
  trace.state = "message_submitted";

  OwnerFutureRecord future;
  future.future_id = message_id;
  future.target_task_id = target_task_id;
  future.has_target_handle = target_handle != nullptr;
  if (target_handle) {
    future.target_handle = *target_handle;
  }
  future.source_owner_id = source_owner;
  future.target_owner_id = target_owner;
  future.message_type = normalized_type;
  future.payload_key = normalized_payload;
  future.state = "pending";

  bool notify_owner_thread = false;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    vm_object_store_record_message(target_owner.c_str(), target_task_id);
    owner_futures[future.future_id] = std::move(future);
    owner_message_traces.push_back(std::move(trace));
    while (owner_message_traces.size() > kOwnerMessageTraceLimit) {
      owner_message_traces.pop_front();
    }
    enqueue_owner_task_locked(std::move(task), target_owner, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }

  auto *map = allocate_mapping(17);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "message_id", static_cast<long>(message_id));
  add_mapping_pair(map, "future_id", static_cast<long>(message_id));
  add_mapping_pair(map, "target_task_id", static_cast<long>(target_task_id));
  add_mapping_string(map, "source_owner_id", source_owner.c_str());
  add_mapping_string(map, "target_owner_id", target_owner.c_str());
  add_mapping_string(map, "message_type", normalized_type.c_str());
  add_mapping_string(map, "payload_key", normalized_payload.c_str());
  add_mapping_pair(map, "requires_owner_mailbox", 1);
  add_mapping_pair(map, "message_only_cross_owner", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_pair(map, "payload_frozen", 1);
  add_mapping_pair(map, "has_target_handle", target_handle ? 1 : 0);
  add_mapping_pair(map, "target_handle_current",
                   !target_handle || vm_object_handle_is_current(*target_handle) ? 1 : 0);
  add_mapping_pair(map, "target_object_id", target_handle ? static_cast<long>(target_handle->object_id) : 0);
  add_mapping_string(map, "target_object_path", target_handle ? target_handle->object_path.c_str() : "");
  add_mapping_pair(map, "target_owner_epoch", target_handle ? static_cast<long>(target_handle->owner_epoch) : 0);
  return map;
}

mapping_t *vm_owner_submit_message(const char *source_owner_id, const char *target_owner_id, const char *message_type,
                                    const char *payload_key) {
  return submit_owner_message(source_owner_id, target_owner_id, message_type, payload_key, nullptr, nullptr);
}

mapping_t *vm_owner_submit_object_message(const char *source_owner_id, const VMObjectHandle &target_handle,
                                          const char *message_type, const char *payload_key, svalue_t *payload) {
  return submit_owner_message(source_owner_id, target_handle.owner_id.c_str(), message_type, payload_key, &target_handle,
                              payload);
}

uint64_t vm_owner_register_compute_future(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                          const char *payload_key) {
  std::string normalized_owner = normalize_owner_id(owner_id);
  std::string normalized_type = normalize_task_text(task_type, "compute_result");
  std::string normalized_payload = normalize_task_text(payload_key, "");
  auto future_id = next_message_trace_id.fetch_add(1, std::memory_order_relaxed);

  OwnerFutureRecord future;
  future.future_id = future_id;
  future.target_task_id = worker_task_id;
  future.source_owner_id = normalized_owner;
  future.target_owner_id = normalized_owner;
  future.message_type = normalized_type;
  future.payload_key = normalized_payload;
  future.state = "pending";

  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  owner_futures[future.future_id] = std::move(future);
  return future_id;
}

uint64_t vm_owner_enqueue_compute_result(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                         const char *state, const char *result_key, const char *error) {
  std::string normalized_owner = normalize_owner_id(owner_id);
  OwnerMailboxTask task;
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.future_target_task_id = worker_task_id;
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_id = normalized_owner;
  task.task_type = "compute_result";
  task.task_key = normalize_task_text(result_key, task_type);
  task.future_state = normalize_task_text(state, "completed");
  task.future_error = normalize_task_text(error, "");

  bool notify_owner_thread = false;
  auto task_id = task.task_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    enqueue_owner_task_locked(std::move(task), normalized_owner, &notify_owner_thread);
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

mapping_t *vm_owner_message_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_message_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_message_trace_mapping(owner_message_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(4);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_message_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

mapping_t *vm_owner_future_poll(uint64_t future_id) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto it = owner_futures.find(future_id);
  if (it == owner_futures.end()) {
    auto *map = allocate_mapping(6);
    add_mapping_pair(map, "success", 0);
    add_mapping_pair(map, "future_id", static_cast<long>(future_id));
    add_mapping_string(map, "state", "unknown");
    add_mapping_string(map, "error", "unknown future");
    add_mapping_pair(map, "requires_owner_message_completion", 0);
    add_mapping_pair(map, "direct_cross_owner_write", 0);
    return map;
  }
  return owner_future_mapping(it->second);
}

mapping_t *vm_owner_record_commit_boundary(const char *source_owner_id, const char *target_owner_id,
                                           const char *operation, uint64_t message_id, const char *state) {
  OwnerCommitTrace trace;
  trace.commit_id = next_commit_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_commit_traced.fetch_add(1, std::memory_order_relaxed) + 1;
  trace.message_id = message_id;
  trace.direct_write = false;
  trace.source_owner_id = normalize_owner_id(source_owner_id);
  trace.target_owner_id = normalize_owner_id(target_owner_id);
  trace.operation = normalize_task_text(operation, "commit");
  trace.state = normalize_task_text(state, "commit_guarded");
  auto result = trace;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_commit_traces.push_back(std::move(trace));
    while (owner_commit_traces.size() > kOwnerCommitTraceLimit) {
      owner_commit_traces.pop_front();
    }
  }
  auto *map = allocate_mapping(9);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "commit_id", static_cast<long>(result.commit_id));
  add_mapping_pair(map, "message_id", static_cast<long>(result.message_id));
  add_mapping_pair(map, "direct_write", 0);
  add_mapping_string(map, "source_owner_id", result.source_owner_id.c_str());
  add_mapping_string(map, "target_owner_id", result.target_owner_id.c_str());
  add_mapping_string(map, "operation", result.operation.c_str());
  add_mapping_string(map, "state", result.state.c_str());
  add_mapping_pair(map, "commit_boundary_only", 1);
  return map;
}

mapping_t *vm_owner_commit_trace(int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto available = owner_commit_traces.size();
  auto requested = limit <= 0 || static_cast<size_t>(limit) > available ? available : static_cast<size_t>(limit);
  auto *events = allocate_array(static_cast<int>(requested));
  auto start = available - requested;

  for (size_t i = 0; i < requested; i++) {
    auto *event_map = owner_commit_trace_mapping(owner_commit_traces[start + i]);
    events->item[i].type = T_MAPPING;
    events->item[i].subtype = 0;
    events->item[i].u.map = event_map;
  }

  auto *map = allocate_mapping(4);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_commit_traced.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

void vm_owner_thread_start(int requested_threads) {
  auto thread_count = requested_threads <= 0 ? 1 : requested_threads;
  if (thread_count > 4) {
    thread_count = 4;
  }

  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (!owner_threads.empty()) {
      return;
    }
    owner_thread_stopping = false;
    owner_threads.reserve(static_cast<size_t>(thread_count));
    for (int i = 0; i < thread_count; i++) {
      owner_threads.emplace_back(owner_thread_loop);
    }
    owner_thread_starts.fetch_add(1, std::memory_order_relaxed);
  }
  owner_runtime_cv.notify_all();
}

void vm_owner_thread_stop() {
  std::vector<std::thread> threads;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    if (owner_threads.empty()) {
      owner_thread_stopping = false;
      return;
    }
    owner_thread_stopping = true;
    threads.swap(owner_threads);
  }
  owner_runtime_cv.notify_all();
  for (auto &thread : threads) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  release_deferred_owner_targets_on_main();
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_thread_stopping = false;
    owner_thread_stops.fetch_add(1, std::memory_order_relaxed);
  }
}

mapping_t *vm_owner_thread_status() {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto *map = allocate_mapping(47);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "enabled", owner_threads.empty() ? 0 : 1);
  add_mapping_pair(map, "thread_count", static_cast<long>(owner_threads.size()));
  add_mapping_pair(map, "stopping", owner_thread_stopping ? 1 : 0);
  add_mapping_pair(map, "thread_dispatched", static_cast<long>(owner_thread_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_context_bound",
                   static_cast<long>(owner_thread_context_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_object_store_isolated",
                   static_cast<long>(owner_thread_object_store_isolated.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_owner_bound",
                   static_cast<long>(owner_thread_owner_bound.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_owner_cleared",
                   static_cast<long>(owner_thread_owner_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_execution_cleared",
                   static_cast<long>(owner_thread_execution_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_flag_cleared",
                   static_cast<long>(owner_thread_lpc_canary_flag_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_context_leak_detected",
                   static_cast<long>(owner_thread_context_leak_detected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_rejected",
                   static_cast<long>(owner_thread_lpc_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_owner_state_guarded",
                   static_cast<long>(owner_thread_owner_state_guarded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_message_dispatched",
                   static_cast<long>(owner_thread_message_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_probe_executed",
                   static_cast<long>(owner_thread_lpc_probe_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_probe_failed",
                   static_cast<long>(owner_thread_lpc_probe_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_probe_guarded",
                   static_cast<long>(owner_thread_lpc_probe_guarded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_executed",
                   static_cast<long>(owner_thread_lpc_canary_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_succeeded",
                   static_cast<long>(owner_thread_lpc_canary_succeeded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_failed",
                   static_cast<long>(owner_thread_lpc_canary_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_canary_rejected",
                   static_cast<long>(owner_thread_lpc_canary_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_executed",
                   static_cast<long>(owner_thread_lpc_task_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_succeeded",
                   static_cast<long>(owner_thread_lpc_task_succeeded.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_failed",
                   static_cast<long>(owner_thread_lpc_task_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_lpc_task_rejected",
                   static_cast<long>(owner_thread_lpc_task_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "active_owners", static_cast<long>(active_owner_set.size()));
  add_mapping_pair(map, "max_owner_threads", 4);
  add_mapping_pair(map, "executor_task_budget", kOwnerExecutorTaskBudget);
  add_mapping_pair(map, "executor_budget_yields",
                   static_cast<long>(owner_executor_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_owner_claims",
                   static_cast<long>(owner_executor_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_owner_releases",
                   static_cast<long>(owner_executor_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "deferred_target_releases", static_cast<long>(owner_deferred_target_releases.size()));
  add_mapping_pair(map, "thread_starts", static_cast<long>(owner_thread_starts.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_stops", static_cast<long>(owner_thread_stops.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "main_queue_depth", owner_main_queue_total_depth());
  add_mapping_pair(map, "main_active_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "main_queued", static_cast<long>(owner_main_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_dispatched", static_cast<long>(owner_main_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_stale", static_cast<long>(owner_main_stale.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_destructed", static_cast<long>(owner_main_destructed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_budget_yields", static_cast<long>(owner_main_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_claims", static_cast<long>(owner_main_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_releases", static_cast<long>(owner_main_owner_releases.load(std::memory_order_relaxed)));
  return map;
}

mapping_t *vm_owner_runtime_status() {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto *map = allocate_mapping(32);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "multicore_mode", vm_multicore_mode());
  add_mapping_string(map, "multicore_mode_name", vm_multicore_mode_name(vm_multicore_mode()));
  add_mapping_pair(map, "audit_enabled", vm_multicore_audit_enabled() ? 1 : 0);
  add_mapping_pair(map, "enforced", vm_multicore_enforced() ? 1 : 0);
  add_mapping_string(map, "default_owner_id", kDefaultOwnerId);
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  add_mapping_pair(map, "main_queue_depth", owner_main_queue_total_depth());
  add_mapping_pair(map, "main_active_owners", static_cast<long>(active_main_owner_set.size()));
  add_mapping_pair(map, "main_queued", static_cast<long>(owner_main_queued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_dispatched", static_cast<long>(owner_main_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_stale", static_cast<long>(owner_main_stale.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_destructed", static_cast<long>(owner_main_destructed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_budget_yields", static_cast<long>(owner_main_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_claims", static_cast<long>(owner_main_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "main_owner_releases", static_cast<long>(owner_main_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "active_owners", static_cast<long>(active_owner_set.size()));
  add_mapping_pair(map, "owner_threads", static_cast<long>(owner_threads.size()));
  add_mapping_pair(map, "total_enqueued", static_cast<long>(total_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "total_drained", static_cast<long>(total_drained.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "future_count", static_cast<long>(owner_futures.size()));
  add_mapping_pair(map, "futures_completed", static_cast<long>(total_futures_completed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "futures_failed", static_cast<long>(total_futures_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_budget_yields",
                   static_cast<long>(owner_executor_budget_yields.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_owner_claims",
                   static_cast<long>(owner_executor_owner_claims.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "executor_owner_releases",
                   static_cast<long>(owner_executor_owner_releases.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "cross_owner", static_cast<long>(total_cross_owner_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "snapshot_required",
                   static_cast<long>(total_cross_owner_snapshot_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "message_required",
                   static_cast<long>(total_cross_owner_message_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "rejected_by_default",
                   static_cast<long>(total_cross_owner_rejected_accesses.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "enforced_blocks",
                   static_cast<long>(total_cross_owner_enforced_blocks.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "object_store_sync_rejections",
                   static_cast<long>(vm_context_object_store_sync_rejections()));
  return map;
}

// Safe read-only properties that can be queried across owners without requiring message/future
static const std::unordered_set<std::string> safe_read_only_properties = {
  "name", "id", "short", "living", "is_character", "is_npc", "is_player",
  "query_temp/is_dying", "environment"
};

bool vm_owner_is_safe_read_only_property(const char *property_name) {
  if (!property_name) return false;
  return safe_read_only_properties.find(property_name) != safe_read_only_properties.end();
}

// Query object snapshot for safe cross-owner read-only access
// Returns a mapping with basic properties that don't require synchronous call_other
mapping_t *vm_owner_query_object_snapshot(object_t *target, const char *requesting_owner_id) {
  if (!target) {
    return nullptr;
  }

  const char *target_owner_id = vm_owner_id(target);

  // Record this as a snapshot access
  vm_owner_record_cross_owner_access(current_object, target, "snapshot");

  // If same owner or target is default owner, allow direct access
  if (std::strcmp(target_owner_id, requesting_owner_id) == 0 ||
      std::strcmp(target_owner_id, kDefaultOwnerId) == 0) {
    return nullptr;  // Signal that direct access is safe
  }

  // Cross-owner access - return a safe snapshot
  total_cross_owner_snapshot_accesses.fetch_add(1, std::memory_order_relaxed);

  auto *snapshot = allocate_mapping(8);

  // Object identity
  add_mapping_string(snapshot, "object_name", target->obname);
  add_mapping_string(snapshot, "owner_id", target_owner_id);

  // Living status (check flags directly without calling methods)
  int living_flag = (target->flags & O_ENABLE_COMMANDS) ? 1 : 0;
  add_mapping_pair(snapshot, "living", living_flag);

  // Object type flags (check if methods exist without calling them)
  int has_is_npc = 0;
  int has_is_player = 0;
  int has_is_character = 0;

  // Check if methods exist (pass 0 as third argument for local function check)
  if (function_exists("is_npc", target, 0)) {
    has_is_npc = 1;
  }
  if (function_exists("is_player", target, 0)) {
    has_is_player = 1;
  }
  if (function_exists("is_character", target, 0)) {
    has_is_character = 1;
  }

  add_mapping_pair(snapshot, "has_is_npc", has_is_npc);
  add_mapping_pair(snapshot, "has_is_player", has_is_player);
  add_mapping_pair(snapshot, "has_is_character", has_is_character);
  add_mapping_pair(snapshot, "living_flag", living_flag);

  return snapshot;
}

// Safely query a read-only method on a cross-owner object
// Returns the result with error suppression, or null on error
svalue_t *vm_owner_safe_query(object_t *target, const char *method, const char *requesting_owner_id) {
  if (!target || !method) {
    return nullptr;
  }

  const char *target_owner_id = vm_owner_id(target);

  // If same owner or target is default owner, allow direct query
  if (std::strcmp(target_owner_id, requesting_owner_id) == 0 ||
      std::strcmp(target_owner_id, kDefaultOwnerId) == 0) {
    // Safe to query directly - return nullptr to signal direct access
    return nullptr;
  }

  // Cross-owner query - use catch to suppress errors
  if (!function_exists(method, target, 0)) {
    return &const0u;
  }

  // Temporarily allow cross-owner access for read-only queries
  // by catching and suppressing any errors
  error_context_t econ;
  save_context(&econ);

  svalue_t *result = nullptr;
  try {
    result = safe_apply(method, target, 0, ORIGIN_EFUN);
  } catch (...) {
    // Suppress error - return const0
    result = &const0u;
  }

  restore_context(&econ);
  return result ? result : &const0u;
}
