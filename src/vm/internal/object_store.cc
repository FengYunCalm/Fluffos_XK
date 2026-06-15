#include "base/package_api.h"

#include "vm/object_handle.h"

#include "vm/internal/otable.h"
#include "vm/owner.h"

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace {
struct ObjectRecord {
  uint64_t object_id{0};
  std::string owner_id;
  uint64_t owner_epoch{0};
  std::string object_path;
  bool destructed{false};
};

struct ObjectShardRecord {
  std::string owner_id;
  std::unordered_set<uint64_t> objects;
  uint64_t registered{0};
  uint64_t destructed{0};
  uint64_t heartbeats{0};
  uint64_t callouts{0};
  uint64_t messages{0};
};

std::mutex object_store_mutex;
std::atomic<uint64_t> next_object_id{1};
std::unordered_map<object_t *, ObjectRecord> object_records;
std::unordered_map<std::string, ObjectShardRecord> owner_shards;

const char *safe_owner_id(const char *owner_id) {
  return owner_id && owner_id[0] != '\0' ? owner_id : vm_owner_default_id();
}

std::string safe_object_path(object_t *object) { return object && object->obname ? object->obname : ""; }

ObjectShardRecord &shard_for_owner(const std::string &owner_id) {
  auto &shard = owner_shards[owner_id];
  if (shard.owner_id.empty()) {
    shard.owner_id = owner_id;
  }
  return shard;
}

ObjectRecord &register_locked(object_t *object) {
  auto &record = object_records[object];
  if (record.object_id == 0) {
    record.object_id = next_object_id.fetch_add(1, std::memory_order_relaxed);
    record.owner_id = safe_owner_id(vm_owner_id(object));
    record.owner_epoch = vm_owner_epoch(object);
    record.object_path = safe_object_path(object);
    auto &shard = shard_for_owner(record.owner_id);
    shard.objects.insert(record.object_id);
    shard.registered++;
  }
  return record;
}

void move_record_owner_locked(ObjectRecord &record, const std::string &new_owner_id) {
  if (record.owner_id == new_owner_id) {
    return;
  }
  auto old_it = owner_shards.find(record.owner_id);
  if (old_it != owner_shards.end()) {
    old_it->second.objects.erase(record.object_id);
  }
  record.owner_id = new_owner_id;
  auto &new_shard = shard_for_owner(record.owner_id);
  new_shard.objects.insert(record.object_id);
}

mapping_t *shard_mapping(const ObjectShardRecord &shard) {
  auto *map = allocate_mapping(7);
  add_mapping_string(map, "owner_id", shard.owner_id.c_str());
  add_mapping_pair(map, "objects", static_cast<long>(shard.objects.size()));
  add_mapping_pair(map, "registered", static_cast<long>(shard.registered));
  add_mapping_pair(map, "destructed", static_cast<long>(shard.destructed));
  add_mapping_pair(map, "heartbeats", static_cast<long>(shard.heartbeats));
  add_mapping_pair(map, "callouts", static_cast<long>(shard.callouts));
  add_mapping_pair(map, "messages", static_cast<long>(shard.messages));
  return map;
}
}  // namespace

VMObjectHandle vm_object_handle(object_t *object) {
  VMObjectHandle handle;
  if (!object) {
    return handle;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto &record = register_locked(object);
  handle.object_id = record.object_id;
  handle.owner_id = record.owner_id;
  handle.owner_epoch = record.owner_epoch;
  handle.object_path = record.object_path;
  handle.valid = !record.destructed;
  return handle;
}

object_t *vm_object_handle_resolve(const VMObjectHandle &handle) {
  if (!handle.valid || handle.object_path.empty()) {
    return nullptr;
  }
  auto *object = ObjectTable::instance().find(handle.object_path);
  if (!object || (object->flags & O_DESTRUCTED)) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto it = object_records.find(object);
  if (it == object_records.end()) {
    return nullptr;
  }
  const auto &record = it->second;
  if (record.destructed || record.object_id != handle.object_id || record.object_path != handle.object_path) {
    return nullptr;
  }
  if (record.owner_epoch != handle.owner_epoch || record.owner_id != handle.owner_id) {
    return nullptr;
  }
  if (vm_owner_epoch(object) != handle.owner_epoch || handle.owner_id != vm_owner_id(object)) {
    return nullptr;
  }
  return object;
}

bool vm_object_handle_is_current(const VMObjectHandle &handle) { return vm_object_handle_resolve(handle) != nullptr; }

void vm_object_store_register(object_t *object) {
  if (!object) {
    return;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto &record = register_locked(object);
  move_record_owner_locked(record, safe_owner_id(vm_owner_id(object)));
  record.owner_epoch = vm_owner_epoch(object);
  record.object_path = safe_object_path(object);
  record.destructed = (object->flags & O_DESTRUCTED) != 0;
}

mapping_t *vm_object_handle_status(object_t *object) {
  auto handle = vm_object_handle(object);
  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", handle.valid ? 1 : 0);
  add_mapping_pair(map, "object_id", static_cast<long>(handle.object_id));
  add_mapping_string(map, "owner_id", handle.owner_id.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(handle.owner_epoch));
  add_mapping_string(map, "object_path", handle.object_path.c_str());
  add_mapping_pair(map, "valid", handle.valid ? 1 : 0);
  add_mapping_pair(map, "current", vm_object_handle_is_current(handle) ? 1 : 0);
  return map;
}

void vm_object_store_update_owner(object_t *object) {
  if (!object) {
    return;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto &record = register_locked(object);
  move_record_owner_locked(record, safe_owner_id(vm_owner_id(object)));
  record.owner_epoch = vm_owner_epoch(object);
  record.object_path = safe_object_path(object);
}

void vm_object_store_mark_destructed(object_t *object) {
  if (!object) {
    return;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto &record = register_locked(object);
  record.destructed = true;
  auto &shard = shard_for_owner(record.owner_id);
  shard.destructed++;
}

void vm_object_store_record_callout(object_t *object) {
  if (!object) {
    return;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto &record = register_locked(object);
  shard_for_owner(record.owner_id).callouts++;
}

void vm_object_store_record_heartbeat(object_t *object) {
  if (!object) {
    return;
  }
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto &record = register_locked(object);
  shard_for_owner(record.owner_id).heartbeats++;
}

void vm_object_store_record_message(const char *owner_id) {
  std::lock_guard<std::mutex> lock(object_store_mutex);
  shard_for_owner(safe_owner_id(owner_id)).messages++;
}

mapping_t *vm_object_store_status() {
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto *shards = allocate_array(static_cast<int>(owner_shards.size()));
  int i = 0;
  for (const auto &entry : owner_shards) {
    shards->item[i].type = T_MAPPING;
    shards->item[i].subtype = 0;
    shards->item[i].u.map = shard_mapping(entry.second);
    i++;
  }
  auto *map = allocate_mapping(5);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "registered_objects", static_cast<long>(object_records.size()));
  add_mapping_pair(map, "owner_shards", static_cast<long>(owner_shards.size()));
  add_mapping_string(map, "default_owner_id", vm_owner_default_id());
  add_mapping_array(map, "shards", shards);
  free_array(shards);
  return map;
}

mapping_t *vm_object_store_owner_status(const char *owner_id) {
  std::lock_guard<std::mutex> lock(object_store_mutex);
  auto normalized = safe_owner_id(owner_id);
  auto it = owner_shards.find(normalized);
  if (it == owner_shards.end()) {
    auto *map = allocate_mapping(3);
    add_mapping_pair(map, "success", 1);
    add_mapping_string(map, "owner_id", normalized);
    add_mapping_pair(map, "objects", 0);
    return map;
  }
  auto *map = shard_mapping(it->second);
  add_mapping_pair(map, "success", 1);
  return map;
}
