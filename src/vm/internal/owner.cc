#include "base/package_api.h"

#include "vm/owner.h"

#include <atomic>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace {
constexpr const char *kDefaultOwnerId = "owner/global";
std::atomic<uint64_t> total_checks{0};
std::atomic<uint64_t> mismatch_checks{0};
std::atomic<uint64_t> next_mailbox_task_id{1};
std::atomic<uint64_t> total_enqueued{0};
std::atomic<uint64_t> total_drained{0};

struct OwnerMailboxTask {
  uint64_t task_id;
  uint64_t sequence;
  uint64_t owner_epoch;
  std::string owner_id;
  std::string task_type;
  std::string task_key;
};

std::unordered_map<std::string, std::deque<OwnerMailboxTask>> owner_mailboxes;
std::deque<std::string> schedulable_owners;
std::unordered_set<std::string> schedulable_owner_set;

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

void mark_owner_schedulable(const std::string &owner_id) {
  if (schedulable_owner_set.insert(owner_id).second) {
    schedulable_owners.push_back(owner_id);
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
  task.task_id = next_mailbox_task_id.fetch_add(1, std::memory_order_relaxed);
  task.sequence = total_enqueued.fetch_add(1, std::memory_order_relaxed) + 1;
  task.owner_epoch = owner_epoch;
  task.owner_id = normalize_owner_id(owner_id);
  task.task_type = normalize_task_text(task_type, "generic");
  task.task_key = normalize_task_text(task_key, "");
  auto normalized_owner_id = task.owner_id;
  auto &queue = owner_mailboxes[normalized_owner_id];
  auto was_empty = queue.empty();
  queue.push_back(std::move(task));
  if (was_empty) {
    mark_owner_schedulable(normalized_owner_id);
  }
  return task.task_id;
}

mapping_t *vm_owner_drain_mailbox(const char *owner_id, int limit) {
  std::string normalized_owner_id = normalize_owner_id(owner_id);
  auto &queue = owner_mailboxes[normalized_owner_id];
  auto requested = limit <= 0 || static_cast<size_t>(limit) > queue.size() ? queue.size() : static_cast<size_t>(limit);
  auto *tasks = allocate_array(static_cast<int>(requested));

  for (size_t i = 0; i < requested; i++) {
    auto task = queue.front();
    queue.pop_front();
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

mapping_t *vm_owner_schedule(int limit) {
  auto requested = limit <= 0 ? static_cast<size_t>(owner_mailbox_total_depth()) : static_cast<size_t>(limit);
  auto *tasks = allocate_array(static_cast<int>(requested));
  size_t dispatched = 0;

  while (dispatched < requested && !schedulable_owners.empty()) {
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

    auto task = it->second.front();
    it->second.pop_front();
    auto *task_map = owner_mailbox_task_mapping(task);
    tasks->item[dispatched].type = T_MAPPING;
    tasks->item[dispatched].subtype = 0;
    tasks->item[dispatched].u.map = task_map;
    dispatched++;

    if (it->second.empty()) {
      owner_mailboxes.erase(it);
    } else {
      mark_owner_schedulable(owner_id);
    }
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
