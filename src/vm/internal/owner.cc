#include "base/package_api.h"

#include "vm/owner.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {
constexpr const char *kDefaultOwnerId = "owner/global";
constexpr size_t kOwnerTraceLimit = 256;
constexpr size_t kOwnerAccessTraceLimit = 256;
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
std::atomic<uint64_t> owner_thread_dispatched{0};
std::atomic<uint64_t> owner_thread_starts{0};
std::atomic<uint64_t> owner_thread_stops{0};

struct OwnerMailboxTask {
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
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

std::unordered_map<std::string, std::deque<OwnerMailboxTask>> owner_mailboxes;
std::deque<std::string> schedulable_owners;
std::unordered_set<std::string> schedulable_owner_set;
std::deque<OwnerTaskTrace> owner_task_traces;
std::deque<OwnerAccessTrace> owner_access_traces;
std::mutex owner_runtime_mutex;
std::condition_variable owner_runtime_cv;
bool owner_thread_stopping{false};
std::vector<std::thread> owner_threads;

bool valid_owner_id(const char *owner_id) {
  return owner_id && owner_id[0] != '\0';
}

const char *normalize_owner_id(const char *owner_id) {
  return valid_owner_id(owner_id) ? owner_id : kDefaultOwnerId;
}

const char *normalize_task_text(const char *text, const char *fallback) {
  return text && text[0] != '\0' ? text : fallback;
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
  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "task_id", static_cast<long>(task.task_id));
  add_mapping_pair(map, "sequence", static_cast<long>(task.sequence));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(task.owner_epoch));
  add_mapping_string(map, "owner_id", task.owner_id.c_str());
  add_mapping_string(map, "task_type", task.task_type.c_str());
  add_mapping_string(map, "task_key", task.task_key.c_str());
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

const char *owner_object_name(object_t *object) {
  return object && object->obname ? object->obname : "";
}

mapping_t *owner_access_trace_mapping(const OwnerAccessTrace &trace) {
  auto *map = allocate_mapping(10);
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

void mark_owner_schedulable(const std::string &owner_id) {
  if (schedulable_owner_set.insert(owner_id).second) {
    schedulable_owners.push_back(owner_id);
  }
}

bool pop_next_schedulable_task(OwnerMailboxTask *out) {
  while (!schedulable_owners.empty()) {
    auto owner_id = schedulable_owners.front();
    schedulable_owners.pop_front();
    if (schedulable_owner_set.erase(owner_id) == 0) {
      continue;
    }

    auto it = owner_mailboxes.find(owner_id);
    if (it == owner_mailboxes.end() || it->second.empty()) {
      owner_mailboxes.erase(owner_id);
      continue;
    }

    *out = it->second.front();
    it->second.pop_front();
    if (it->second.empty()) {
      owner_mailboxes.erase(it);
    } else {
      mark_owner_schedulable(owner_id);
    }
    return true;
  }

  return false;
}

void owner_thread_loop() {
  while (true) {
    OwnerMailboxTask task;
    {
      std::unique_lock<std::mutex> lock(owner_runtime_mutex);
      owner_runtime_cv.wait(lock, [] { return owner_thread_stopping || !schedulable_owners.empty(); });
      if (owner_thread_stopping) {
        return;
      }
      if (!pop_next_schedulable_task(&task)) {
        continue;
      }
      append_owner_task_trace(task, "thread_dispatched");
      total_drained.fetch_add(1, std::memory_order_relaxed);
      owner_thread_dispatched.fetch_add(1, std::memory_order_relaxed);
    }
  }
}
}  // namespace

const char *vm_owner_default_id() { return kDefaultOwnerId; }

const char *vm_owner_id(object_t *object) {
  if (!object || !valid_owner_id(object->vm_owner_id)) {
    return kDefaultOwnerId;
  }
  return object->vm_owner_id;
}

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
  vm_owner_clear_id(object);
  object->vm_owner_id = make_shared_string(owner_id);
  object->vm_owner_epoch++;
}

void vm_owner_clear_id(object_t *object) {
  if (object && object->vm_owner_id) {
    free_string(object->vm_owner_id);
    object->vm_owner_id = nullptr;
    object->vm_owner_epoch++;
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
  auto *map = allocate_mapping(7);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(object)));
  add_mapping_string(map, "default_owner_id", kDefaultOwnerId);
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
    if (was_empty) {
      mark_owner_schedulable(normalized_owner_id);
      notify_owner_thread = true;
    }
  }
  if (notify_owner_thread) {
    owner_runtime_cv.notify_one();
  }
  return task_id;
}

uint64_t vm_owner_record_task_trace(const char *owner_id, const char *task_type, const char *task_key,
                                     uint64_t owner_epoch, const char *state) {
  auto sequence = total_traced.load(std::memory_order_relaxed) + 1;
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  return append_owner_task_trace(0, sequence, normalize_owner_id(owner_id), owner_epoch,
                                  normalize_task_text(task_type, "generic"), normalize_task_text(task_key, ""), state);
}

uint64_t vm_owner_record_access(object_t *source, object_t *target, const char *operation) {
  OwnerAccessTrace trace;
  uint64_t access_id;
  trace.access_id = next_access_trace_id.fetch_add(1, std::memory_order_relaxed);
  trace.sequence = total_access_traced.load(std::memory_order_relaxed) + 1;
  trace.source_owner_epoch = vm_owner_epoch(source);
  trace.target_owner_epoch = vm_owner_epoch(target);
  trace.source_owner_id = vm_owner_id(source);
  trace.target_owner_id = vm_owner_id(target);
  trace.source_object = owner_object_name(source);
  trace.target_object = owner_object_name(target);
  trace.operation = normalize_task_text(operation, "access");
  trace.cross_owner = trace.source_owner_id != trace.target_owner_id;
  if (trace.cross_owner) {
    total_cross_owner_accesses.fetch_add(1, std::memory_order_relaxed);
  }
  access_id = trace.access_id;
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_access_traces.push_back(std::move(trace));
    while (owner_access_traces.size() > kOwnerAccessTraceLimit) {
      owner_access_traces.pop_front();
    }
  }
  total_access_traced.fetch_add(1, std::memory_order_relaxed);
  return access_id;
}

mapping_t *vm_owner_drain_mailbox(const char *owner_id, int limit) {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  auto &queue = owner_mailboxes[normalized_owner_id];
  auto requested = limit <= 0 || static_cast<size_t>(limit) > queue.size() ? queue.size() : static_cast<size_t>(limit);
  auto *tasks = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto task = queue.front();
    queue.pop_front();
    append_owner_task_trace(task, "drained");
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[i].type = T_MAPPING;
    tasks->item[i].subtype = 0;
    tasks->item[i].u.map = task_map;
  }
  if (queue.empty()) {
    owner_mailboxes.erase(normalized_owner_id);
    schedulable_owner_set.erase(normalized_owner_id);
  }
  total_drained.fetch_add(requested, std::memory_order_relaxed);

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
    if (!pop_next_schedulable_task(&task)) {
      break;
    }
    append_owner_task_trace(task, "dispatched");
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[dispatched].type = T_MAPPING;
    tasks->item[dispatched].subtype = 0;
    tasks->item[dispatched].u.map = task_map;
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

  auto *map = allocate_mapping(5);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "returned", static_cast<long>(requested));
  add_mapping_pair(map, "total_traced", static_cast<long>(total_access_traced.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "cross_owner", static_cast<long>(total_cross_owner_accesses.load(std::memory_order_relaxed)));
  add_mapping_array(map, "events", events);
  free_array(events);
  return map;
}

void vm_owner_thread_start(int requested_threads) {
  auto thread_count = requested_threads <= 0 ? 1 : requested_threads;
  if (thread_count > 1) {
    thread_count = 1;
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
  {
    std::lock_guard<std::mutex> lock(owner_runtime_mutex);
    owner_thread_stopping = false;
    owner_thread_stops.fetch_add(1, std::memory_order_relaxed);
  }
}

mapping_t *vm_owner_thread_status() {
  std::lock_guard<std::mutex> lock(owner_runtime_mutex);
  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "enabled", owner_threads.empty() ? 0 : 1);
  add_mapping_pair(map, "thread_count", static_cast<long>(owner_threads.size()));
  add_mapping_pair(map, "stopping", owner_thread_stopping ? 1 : 0);
  add_mapping_pair(map, "thread_dispatched", static_cast<long>(owner_thread_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_starts", static_cast<long>(owner_thread_starts.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "thread_stops", static_cast<long>(owner_thread_stops.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "queue_depth", owner_mailbox_total_depth());
  return map;
}
