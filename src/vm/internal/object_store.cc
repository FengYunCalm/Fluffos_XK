#include "base/package_api.h"

#include "vm/object_handle.h"

#include "vm/internal/otable.h"
#include "vm/internal/simulate.h"
#include "vm/owner.h"

#include <atomic>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace {
constexpr size_t kObjectStoreMigrationTraceLimit = 128;
constexpr const char *kGlobalLiveObjectBridgeSource = "ObjectTable.global_live_object_bridge";
constexpr const char *kGlobalRecordBridgeSource = "global_object_records";
constexpr const char *kGlobalRecordIdScanBridgeSource = "global_object_records.object_id_scan_bridge";
constexpr const char *kGlobalRecordPointerBridgeSource = "global_object_records.pointer_bridge";
constexpr const char *kGlobalRecordScanBridgeSource = "global_object_records.path_scan_bridge";
constexpr const char *kOwnerLocalStoreCompleteBlockerGlobalIndexBridge = "global_index_bridge_active";
constexpr const char *kOwnerLocalStoreCompleteBlockerGlobalObjectTable = "global_object_table_active";
constexpr const char *kOwnerLocalStoreCompleteBlockerNotMarkedComplete = "owner_local_store_not_marked_complete";
constexpr const char *kOwnerLocalDeferredDestructBlocker = "deferred_destruct_main_thread_list";
constexpr const char *kGlobalIndexPhysicalRetirementBlocker = "global_object_records_compatibility_index";

struct ObjectRecord {
  uint64_t object_id{0};
  std::string owner_id;
  uint64_t owner_epoch{0};
  std::string object_path;
  bool destructed{false};
};

struct ObjectShardStatusRecord {
  std::string owner_id;
  std::unordered_set<uint64_t> objects;
  uint64_t registered{0};
  uint64_t destructed{0};
  uint64_t heartbeats{0};
  uint64_t callouts{0};
  uint64_t messages{0};
};

struct ObjectExecutionShardRecord {
  std::string owner_id;
  std::unordered_set<uint64_t> active_heartbeats;
  std::unordered_set<uint64_t> pending_callouts;
  std::unordered_set<uint64_t> pending_messages;
};

struct VMObjectShard {
  ObjectShardStatusRecord status;
  ObjectExecutionShardRecord execution;
  std::unordered_set<uint64_t> object_directory;
  std::unordered_map<uint64_t, ObjectRecord> local_records;
  std::unordered_map<uint64_t, ObjectRecord> destructed_records;
  std::unordered_map<uint64_t, object_t *> local_objects;
  std::unordered_map<object_t *, uint64_t> local_object_index;
  std::unordered_map<std::string, uint64_t> object_path_index;
  std::unordered_map<std::string, uint64_t> destructed_path_index;
  bool owner_local_directory_ready{true};
  bool owner_local_directory_from_shard{true};
  bool owner_local_store_ready{false};
  bool owner_local_store_complete{false};
  bool uses_global_object_table{true};
  bool global_index_bridge{true};
};

struct ObjectMigrationRecord {
  uint64_t migration_id{0};
  uint64_t object_id{0};
  uint64_t owner_epoch{0};
  std::string from_owner_id;
  std::string to_owner_id;
  std::string object_path;
};

struct OwnerLocalLookupResult {
  std::string owner_id;
  std::string query_path;
  uint64_t object_id{0};
  const ObjectRecord *local_record{nullptr};
  const ObjectRecord *destructed_record{nullptr};
  const ObjectRecord *cross_owner_record{nullptr};
  const ObjectRecord *global_record{nullptr};
  const ObjectRecord *record{nullptr};
  std::string cross_owner_record_source;
  std::string global_record_source;
  std::string global_record_id_scan_bridge_source;
  std::string global_record_pointer_bridge_source;
  std::string global_record_scan_bridge_source;
  std::string global_live_object_source;
  std::string global_record_fallback_reason;
  std::string global_record_id_scan_bridge_skip_reason;
  std::string global_record_pointer_bridge_skip_reason;
  std::string global_record_scan_bridge_skip_reason;
  std::string global_live_object_fallback_reason;
  object_t *resolved_object{nullptr};
  bool shard_contains{false};
  bool same_owner{false};
  bool local_object_ref_found{false};
  bool local_object_ref_index_found{false};
  bool live_path_index_found{false};
  bool destructed_path_index_found{false};
  bool global_live_object_found{false};
  bool global_record_id_scan_bridge_used{false};
  bool global_record_id_scan_bridge_found{false};
  bool global_record_id_scan_bridge_skipped{false};
  bool global_record_pointer_bridge_used{false};
  bool global_record_pointer_bridge_found{false};
  bool global_record_pointer_bridge_skipped{false};
  bool global_record_scan_bridge_used{false};
  bool global_record_scan_bridge_found{false};
  bool global_record_scan_bridge_skipped{false};
  bool owner_local_canonical_record_ready{true};
  bool global_record_bridge_retirement_ready{false};
  bool global_live_object_bridge_retirement_ready{false};
  bool global_record_fallback_skipped{false};
  bool global_live_object_fallback_skipped{false};
  bool found{false};
};

struct OwnerLocalBridgeSummary {
  size_t live_records{0};
  size_t object_refs{0};
  size_t object_ref_indexes{0};
  size_t destructed_records{0};
  size_t live_path_index_entries{0};
  size_t destructed_path_index_entries{0};
  size_t orphan_records{0};
  size_t owner_local_to_global_mismatch_records{0};
  size_t global_to_owner_local_record_mismatch_records{0};
  size_t global_records{0};
  size_t global_live_records{0};
  size_t global_destructed_records{0};
  size_t global_to_owner_local_mismatch_records{0};
  bool owner_local_record_index_ready{true};
  bool owner_local_canonical_record_ready{true};
  bool owner_local_to_global_bridge_consistent{true};
  bool global_record_bridge_consistent{true};
  bool global_to_owner_local_bridge_consistent{true};
  bool global_record_bridge_retirement_ready{false};
  bool global_live_object_bridge_retirement_ready{false};
  bool global_bridge_consistent{true};
};

struct GlobalLiveObjectBridgeResult {
  object_t *object{nullptr};
  const ObjectRecord *record{nullptr};
  bool record_pointer_bridge_used{false};
  bool record_pointer_bridge_found{false};
  bool record_pointer_bridge_skipped{false};
};

struct GlobalRecordByPathBridgeResult {
  const ObjectRecord *record{nullptr};
  bool live_object_found{false};
  bool record_pointer_bridge_used{false};
  bool record_pointer_bridge_found{false};
  bool record_pointer_bridge_skipped{false};
  bool record_scan_bridge_used{false};
  bool record_scan_bridge_found{false};
};

std::shared_mutex object_store_directory_mutex;
std::atomic<uint64_t> next_object_id{1};
std::atomic<uint64_t> next_migration_id{1};
std::unordered_map<object_t *, ObjectRecord> object_records;
std::unordered_map<std::string, VMObjectShard> owner_shards;
std::deque<ObjectMigrationRecord> object_migration_traces;

using ObjectStoreReadLock = std::shared_lock<std::shared_mutex>;
using ObjectStoreWriteLock = std::unique_lock<std::shared_mutex>;

const char *safe_owner_id(const char *owner_id) {
  return owner_id && owner_id[0] != '\0' ? owner_id : vm_owner_default_id();
}

std::string safe_object_path(object_t *object) { return object && object->obname ? object->obname : ""; }

std::string safe_permission_intent(const char *permission_intent) {
  return permission_intent && permission_intent[0] != '\0' ? permission_intent
                                                          : kVMObjectHandleDefaultPermissionIntent;
}

const char *owner_local_store_complete_blocker(bool owner_local_store_complete, bool global_index_bridge,
                                               bool uses_global_object_table) {
  if (owner_local_store_complete) {
    return "";
  }
  if (global_index_bridge) {
    return kOwnerLocalStoreCompleteBlockerGlobalIndexBridge;
  }
  if (uses_global_object_table) {
    return kOwnerLocalStoreCompleteBlockerGlobalObjectTable;
  }
  return kOwnerLocalStoreCompleteBlockerNotMarkedComplete;
}

GlobalLiveObjectBridgeResult find_global_live_object_bridge_by_path_locked(const std::string &object_path,
                                                                           bool include_record_bridge = true);

const ObjectRecord *find_global_record_id_scan_bridge_locked(uint64_t object_id) {
  for (const auto &entry : object_records) {
    if (entry.second.object_id == object_id) {
      return &entry.second;
    }
  }
  return nullptr;
}

const ObjectRecord *find_global_record_by_object_id_locked(uint64_t object_id) {
  return find_global_record_id_scan_bridge_locked(object_id);
}

const ObjectRecord *find_global_record_pointer_bridge_locked(object_t *object) {
  auto it = object_records.find(object);
  return it == object_records.end() ? nullptr : &it->second;
}

const ObjectRecord *find_global_record_by_object_pointer_locked(object_t *object) {
  return find_global_record_pointer_bridge_locked(object);
}

const ObjectRecord *find_global_record_scan_bridge_by_path_locked(const std::string &object_path) {
  const ObjectRecord *destructed_record = nullptr;
  for (const auto &entry : object_records) {
    if (entry.second.object_path == object_path) {
      if (!entry.second.destructed) {
        return &entry.second;
      }
      destructed_record = &entry.second;
    }
  }
  return destructed_record;
}

GlobalRecordByPathBridgeResult find_global_record_by_object_path_locked(const std::string &object_path,
                                                                        bool allow_live_object_bridge = true) {
  GlobalRecordByPathBridgeResult result;
  if (object_path.empty()) {
    return result;
  }
  if (allow_live_object_bridge) {
    auto live_object = find_global_live_object_bridge_by_path_locked(object_path);
    result.live_object_found = live_object.object != nullptr;
    result.record_pointer_bridge_used = live_object.record_pointer_bridge_used;
    result.record_pointer_bridge_found = live_object.record_pointer_bridge_found;
    result.record_pointer_bridge_skipped = live_object.record_pointer_bridge_skipped;
    if (live_object.record) {
      result.record = live_object.record;
      return result;
    }
  }
  result.record_scan_bridge_used = true;
  result.record = find_global_record_scan_bridge_by_path_locked(object_path);
  result.record_scan_bridge_found = result.record != nullptr;
  return result;
}

GlobalLiveObjectBridgeResult find_global_live_object_bridge_by_path_locked(const std::string &object_path,
                                                                           bool include_record_bridge) {
  GlobalLiveObjectBridgeResult result;
  if (object_path.empty()) {
    return result;
  }
  result.object = ObjectTable::instance().find(object_path);
  if (result.object && include_record_bridge) {
    result.record_pointer_bridge_used = true;
    result.record = find_global_record_pointer_bridge_locked(result.object);
    result.record_pointer_bridge_found = result.record != nullptr;
  } else if (result.object && !include_record_bridge) {
    result.record_pointer_bridge_skipped = true;
  }
  return result;
}

void add_mapping_map(mapping_t *map, const char *key_name, mapping_t *value) {
  auto key = const0u;
  key.type = T_STRING;
  key.subtype = STRING_CONSTANT;
  key.u.string = key_name;
  auto *slot = find_for_insert(map, &key, 1);
  free_string(key.u.string);
  slot->type = T_MAPPING;
  slot->u.map = value;
  value->ref++;
}

void add_owner_local_lifecycle_contract(mapping_t *map, bool lookup_resolve_ready,
                                        bool canonical_write_ready) {
  constexpr bool deferred_destruct_ready = true;
  constexpr bool global_index_physical_retirement_ready = true;
  const auto lifecycle_ready = lookup_resolve_ready && canonical_write_ready &&
                               deferred_destruct_ready &&
                               global_index_physical_retirement_ready;
  add_mapping_pair(map, "owner_local_lifecycle_contract_version", 1);
  add_mapping_pair(map, "owner_local_lookup_resolve_ready", lookup_resolve_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_create_canonical_ready", canonical_write_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_move_canonical_ready", canonical_write_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_destruct_canonical_ready", canonical_write_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_deferred_destruct_ready", deferred_destruct_ready ? 1 : 0);
  add_mapping_string(map, "owner_local_deferred_destruct_blocker",
                     deferred_destruct_ready ? "" : kOwnerLocalDeferredDestructBlocker);
  add_mapping_pair(map, "global_index_physical_retirement_ready",
                   global_index_physical_retirement_ready ? 1 : 0);
  add_mapping_string(map, "global_index_physical_retirement_blocker",
                     global_index_physical_retirement_ready ? "" : kGlobalIndexPhysicalRetirementBlocker);
  add_mapping_pair(map, "owner_local_lifecycle_ready", lifecycle_ready ? 1 : 0);
  add_mapping_string(map, "owner_local_lifecycle_blocker",
                     lifecycle_ready ? "" : kOwnerLocalStoreCompleteBlockerNotMarkedComplete);
}

VMObjectShard &shard_for_owner(const std::string &owner_id) {
  auto &shard = owner_shards[owner_id];
  if (shard.status.owner_id.empty()) {
    shard.status.owner_id = owner_id;
  }
  if (shard.execution.owner_id.empty()) {
    shard.execution.owner_id = owner_id;
  }
  return shard;
}

const ObjectRecord *find_local_record_locked(const VMObjectShard &shard, uint64_t object_id) {
  auto it = shard.local_records.find(object_id);
  return it == shard.local_records.end() ? nullptr : &it->second;
}

const ObjectRecord *find_destructed_record_locked(const VMObjectShard &shard, uint64_t object_id) {
  auto it = shard.destructed_records.find(object_id);
  return it == shard.destructed_records.end() ? nullptr : &it->second;
}

const ObjectRecord *find_live_record_by_object_pointer_locked(const char *owner_id, object_t *object) {
  if (!object) {
    return nullptr;
  }
  auto shard_it = owner_shards.find(safe_owner_id(owner_id));
  if (shard_it == owner_shards.end()) {
    return nullptr;
  }
  auto object_index = shard_it->second.local_object_index.find(object);
  if (object_index == shard_it->second.local_object_index.end()) {
    return nullptr;
  }
  return find_local_record_locked(shard_it->second, object_index->second);
}

const ObjectRecord *find_record_by_owner_local_object_id_locked(uint64_t object_id) {
  if (object_id == 0) {
    return nullptr;
  }
  const ObjectRecord *destructed_record = nullptr;
  for (const auto &entry : owner_shards) {
    if (auto *record = find_local_record_locked(entry.second, object_id)) {
      return record;
    }
  }
  for (const auto &entry : owner_shards) {
    if (auto *record = find_destructed_record_locked(entry.second, object_id)) {
      destructed_record = record;
    }
  }
  return destructed_record;
}

const ObjectRecord *find_record_by_owner_local_path_locked(const std::string &object_path) {
  if (object_path.empty()) {
    return nullptr;
  }
  const ObjectRecord *destructed_record = nullptr;
  for (const auto &entry : owner_shards) {
    const auto &shard = entry.second;
    auto live_path = shard.object_path_index.find(object_path);
    if (live_path != shard.object_path_index.end()) {
      if (auto *record = find_local_record_locked(shard, live_path->second)) {
        return record;
      }
    }
  }
  for (const auto &entry : owner_shards) {
    const auto &shard = entry.second;
    auto destructed_path = shard.destructed_path_index.find(object_path);
    if (destructed_path != shard.destructed_path_index.end()) {
      if (auto *record = find_destructed_record_locked(shard, destructed_path->second)) {
        destructed_record = record;
      }
    }
  }
  return destructed_record;
}

object_t *shard_resolve_live_object_locked(const VMObjectShard &shard, uint64_t object_id) {
  auto record = shard.local_records.find(object_id);
  if (record == shard.local_records.end() || record->second.destructed ||
      record->second.owner_id != shard.status.owner_id || shard.object_directory.count(object_id) == 0) {
    return nullptr;
  }
  auto object = shard.local_objects.find(object_id);
  if (object == shard.local_objects.end() || !object->second || (object->second->flags & O_DESTRUCTED) != 0) {
    return nullptr;
  }
  auto object_index = shard.local_object_index.find(object->second);
  if (object_index == shard.local_object_index.end() || object_index->second != object_id) {
    return nullptr;
  }
  if (safe_object_path(object->second) != record->second.object_path) {
    return nullptr;
  }
  return object->second;
}

object_t *shard_resolve_live_path_locked(const VMObjectShard &shard, const std::string &object_path) {
  if (object_path.empty()) {
    return nullptr;
  }
  auto path = shard.object_path_index.find(object_path);
  if (path == shard.object_path_index.end()) {
    return nullptr;
  }
  return shard_resolve_live_object_locked(shard, path->second);
}

object_t *owner_local_resolve_object_fast_path_locked(const char *owner_id, uint64_t object_id) {
  auto shard_it = owner_shards.find(safe_owner_id(owner_id));
  if (shard_it == owner_shards.end()) {
    return nullptr;
  }
  return shard_resolve_live_object_locked(shard_it->second, object_id);
}

object_t *owner_local_resolve_path_fast_path_locked(const char *owner_id, const char *object_path) {
  auto shard_it = owner_shards.find(safe_owner_id(owner_id));
  if (shard_it == owner_shards.end()) {
    return nullptr;
  }
  return shard_resolve_live_path_locked(shard_it->second, object_path ? object_path : "");
}

bool shard_has_local_object_ref_locked(const VMObjectShard &shard, uint64_t object_id) {
  auto object_it = shard.local_objects.find(object_id);
  return object_it != shard.local_objects.end() && object_it->second != nullptr;
}

bool shard_has_local_object_ref_index_locked(const VMObjectShard &shard, uint64_t object_id) {
  auto object_it = shard.local_objects.find(object_id);
  if (object_it == shard.local_objects.end() || object_it->second == nullptr) {
    return false;
  }
  auto object_index = shard.local_object_index.find(object_it->second);
  return object_index != shard.local_object_index.end() && object_index->second == object_id;
}

bool shard_path_index_matches_locked(const std::unordered_map<std::string, uint64_t> &index,
                                     const std::string &object_path, uint64_t object_id) {
  if (object_path.empty() || object_id == 0) {
    return false;
  }
  auto path_it = index.find(object_path);
  return path_it != index.end() && path_it->second == object_id;
}

bool owner_local_live_path_index_contains_locked(const std::string &object_path) {
  if (object_path.empty()) {
    return false;
  }
  for (const auto &entry : owner_shards) {
    if (entry.second.object_path_index.find(object_path) != entry.second.object_path_index.end()) {
      return true;
    }
  }
  return false;
}

bool shard_live_path_index_covers_path_locked(const VMObjectShard &shard, const std::string &object_path) {
  if (object_path.empty()) {
    return true;
  }
  auto path = shard.object_path_index.find(object_path);
  if (path == shard.object_path_index.end()) {
    return false;
  }
  auto *record = find_local_record_locked(shard, path->second);
  return record && !record->destructed && record->object_path == object_path;
}

const ObjectRecord *find_cross_owner_record_by_object_id_locked(const std::string &owner_id, uint64_t object_id,
                                                                std::string &record_source) {
  for (const auto &entry : owner_shards) {
    if (entry.first == owner_id) {
      continue;
    }
    if (auto *record = find_local_record_locked(entry.second, object_id)) {
      record_source = "vm_object_shard.local_records";
      return record;
    }
  }
  for (const auto &entry : owner_shards) {
    if (entry.first == owner_id) {
      continue;
    }
    if (auto *record = find_destructed_record_locked(entry.second, object_id)) {
      record_source = "vm_object_shard.destructed_records";
      return record;
    }
  }
  record_source.clear();
  return nullptr;
}

const ObjectRecord *find_cross_owner_record_by_path_locked(const std::string &owner_id,
                                                           const std::string &object_path,
                                                           std::string &record_source) {
  if (object_path.empty()) {
    record_source.clear();
    return nullptr;
  }
  for (const auto &entry : owner_shards) {
    if (entry.first == owner_id) {
      continue;
    }
    auto path = entry.second.object_path_index.find(object_path);
    if (path != entry.second.object_path_index.end()) {
      if (auto *record = find_local_record_locked(entry.second, path->second)) {
        record_source = "vm_object_shard.object_path_index";
        return record;
      }
    }
  }
  for (const auto &entry : owner_shards) {
    if (entry.first == owner_id) {
      continue;
    }
    auto path = entry.second.destructed_path_index.find(object_path);
    if (path != entry.second.destructed_path_index.end()) {
      if (auto *record = find_destructed_record_locked(entry.second, path->second)) {
        record_source = "vm_object_shard.destructed_path_index";
        return record;
      }
    }
  }
  record_source.clear();
  return nullptr;
}

bool resolve_handle_from_owner_local_shard_locked(const VMObjectHandle &handle,
                                                  VMObjectHandleResolveResult &result) {
  auto shard_it = owner_shards.find(safe_owner_id(handle.owner_id.c_str()));
  if (shard_it == owner_shards.end()) {
    return false;
  }
  auto *record = find_local_record_locked(shard_it->second, handle.object_id);
  auto *object = shard_resolve_live_object_locked(shard_it->second, handle.object_id);
  if (!record || !object || record->object_path != handle.object_path || record->owner_id != handle.owner_id ||
      record->owner_epoch != handle.owner_epoch || handle.owner_id != vm_owner_id(object) ||
      vm_owner_epoch(object) != handle.owner_epoch) {
    return false;
  }
  result.object = object;
  result.status = VMObjectHandleResolveStatus::kCurrent;
  result.resolved_via_owner_local_store = true;
  result.owner_local_fast_path_used = true;
  result.owner_local_object_pointer_index_found = true;
  return true;
}

void finalize_owner_local_lookup_locked(OwnerLocalLookupResult &result, const VMObjectShard *shard,
                                        bool require_live_path_index_for_found) {
  result.record = result.local_record
                      ? result.local_record
                      : (result.destructed_record
                             ? result.destructed_record
                             : (result.cross_owner_record ? result.cross_owner_record : result.global_record));
  if (result.record) {
    result.object_id = result.record->object_id;
  }
  result.shard_contains =
      shard && result.object_id != 0 && shard->object_directory.count(result.object_id) > 0;
  result.same_owner = result.record && result.record->owner_id == result.owner_id;
  result.local_object_ref_found = shard && result.local_record && shard_has_local_object_ref_locked(*shard, result.object_id);
  result.local_object_ref_index_found =
      shard && result.local_record && shard_has_local_object_ref_index_locked(*shard, result.object_id);
  if (shard && result.record) {
    result.live_path_index_found =
        shard_path_index_matches_locked(shard->object_path_index, result.record->object_path, result.object_id);
    result.destructed_path_index_found =
        shard_path_index_matches_locked(shard->destructed_path_index, result.record->object_path, result.object_id);
  }
  result.found = result.local_record && result.same_owner && !result.record->destructed && result.shard_contains &&
                 result.local_object_ref_found && result.local_object_ref_index_found &&
                 (!require_live_path_index_for_found || result.live_path_index_found);
  result.resolved_object = result.found && shard ? shard_resolve_live_object_locked(*shard, result.object_id) : nullptr;
  result.found = result.found && result.resolved_object != nullptr;
}

bool shard_live_counts_consistent(const VMObjectShard &shard) {
  return shard.object_directory.size() == shard.local_records.size() &&
         shard.local_records.size() == shard.local_objects.size() &&
         shard.local_objects.size() == shard.local_object_index.size();
}

bool shard_live_object_ref_index_consistent(const VMObjectShard &shard) {
  if (shard.local_objects.size() != shard.local_object_index.size()) {
    return false;
  }
  for (const auto &entry : shard.local_objects) {
    if (!entry.second) {
      return false;
    }
    auto reverse = shard.local_object_index.find(entry.second);
    if (reverse == shard.local_object_index.end() || reverse->second != entry.first) {
      return false;
    }
  }
  for (const auto &entry : shard.local_object_index) {
    auto forward = shard.local_objects.find(entry.second);
    if (forward == shard.local_objects.end() || forward->second != entry.first) {
      return false;
    }
  }
  return true;
}

bool shard_live_path_index_consistent(const VMObjectShard &shard) {
  std::unordered_set<std::string> expected_paths;
  for (const auto &entry : shard.local_records) {
    if (!entry.second.object_path.empty()) {
      expected_paths.insert(entry.second.object_path);
    }
  }
  if (shard.object_path_index.size() != expected_paths.size()) {
    return false;
  }
  for (const auto &entry : shard.object_path_index) {
    if (expected_paths.count(entry.first) == 0) {
      return false;
    }
    auto *record = find_local_record_locked(shard, entry.second);
    if (!record || record->object_path != entry.first || record->destructed) {
      return false;
    }
  }
  for (const auto &object_path : expected_paths) {
    auto path = shard.object_path_index.find(object_path);
    if (path == shard.object_path_index.end()) {
      return false;
    }
    auto *record = find_local_record_locked(shard, path->second);
    if (!record || record->object_path != object_path || record->destructed) {
      return false;
    }
  }
  return true;
}

bool shard_destructed_path_index_consistent(const VMObjectShard &shard) {
  std::unordered_set<std::string> expected_paths;
  for (const auto &entry : shard.destructed_records) {
    if (!entry.second.object_path.empty() && !owner_local_live_path_index_contains_locked(entry.second.object_path)) {
      expected_paths.insert(entry.second.object_path);
    }
  }
  if (shard.destructed_path_index.size() != expected_paths.size()) {
    return false;
  }
  for (const auto &entry : shard.destructed_path_index) {
    if (expected_paths.count(entry.first) == 0) {
      return false;
    }
    auto *record = find_destructed_record_locked(shard, entry.second);
    if (!record || record->object_path != entry.first || !record->destructed) {
      return false;
    }
  }
  for (const auto &object_path : expected_paths) {
    auto path = shard.destructed_path_index.find(object_path);
    if (path == shard.destructed_path_index.end()) {
      return false;
    }
    auto *record = find_destructed_record_locked(shard, path->second);
    if (!record || record->object_path != object_path || !record->destructed) {
      return false;
    }
  }
  return true;
}

bool object_record_equal(const ObjectRecord &lhs, const ObjectRecord &rhs) {
  return lhs.object_id == rhs.object_id && lhs.owner_id == rhs.owner_id && lhs.owner_epoch == rhs.owner_epoch &&
         lhs.object_path == rhs.object_path && lhs.destructed == rhs.destructed;
}

bool object_is_pending_destruct(object_t *object) {
  for (auto *pending = obj_list_destruct; pending; pending = pending->next_all) {
    if (pending == object) {
      return true;
    }
  }
  return false;
}

bool shard_canonical_record_ready(const VMObjectShard &shard) {
  return shard_live_counts_consistent(shard) && shard_live_object_ref_index_consistent(shard) &&
         shard_live_path_index_consistent(shard) && shard_destructed_path_index_consistent(shard);
}

bool shard_record_index_ready(const VMObjectShard &shard) {
  return shard.object_directory.size() == shard.local_records.size() &&
         shard.object_path_index.size() <= shard.local_records.size() &&
         shard.destructed_path_index.size() <= shard.destructed_records.size() &&
         shard_live_path_index_consistent(shard) && shard_destructed_path_index_consistent(shard);
}

bool owner_local_store_ready_for_shard(const VMObjectShard &shard, const OwnerLocalBridgeSummary &summary) {
  return shard.owner_local_directory_ready && shard_canonical_record_ready(shard) &&
         summary.global_live_object_bridge_retirement_ready;
}

bool owner_local_store_complete_for_shard(const VMObjectShard &shard, const OwnerLocalBridgeSummary &summary) {
  return owner_local_store_ready_for_shard(shard, summary) &&
         summary.global_record_bridge_retirement_ready && summary.global_live_object_bridge_retirement_ready;
}

OwnerLocalBridgeSummary owner_local_bridge_summary_locked() {
  OwnerLocalBridgeSummary summary;
  for (const auto &entry : owner_shards) {
    const auto &shard = entry.second;
    auto shard_record_ready = shard_record_index_ready(shard);
    auto shard_ready = shard_canonical_record_ready(shard);
    summary.live_records += shard.local_records.size();
    summary.object_refs += shard.local_objects.size();
    summary.object_ref_indexes += shard.local_object_index.size();
    summary.destructed_records += shard.destructed_records.size();
    summary.live_path_index_entries += shard.object_path_index.size();
    summary.destructed_path_index_entries += shard.destructed_path_index.size();
    summary.owner_local_record_index_ready = summary.owner_local_record_index_ready && shard_record_ready;
    summary.owner_local_canonical_record_ready = summary.owner_local_canonical_record_ready && shard_ready;
    summary.global_record_bridge_consistent = summary.global_record_bridge_consistent && shard_record_ready;
    summary.owner_local_to_global_bridge_consistent =
        summary.owner_local_to_global_bridge_consistent && shard_ready;
    for (const auto &record_entry : shard.local_records) {
      auto *global_record = find_global_record_by_object_id_locked(record_entry.first);
      if (!global_record || !object_record_equal(*global_record, record_entry.second) || global_record->destructed) {
        summary.global_record_bridge_consistent = false;
        summary.owner_local_to_global_bridge_consistent = false;
        summary.orphan_records++;
        summary.owner_local_to_global_mismatch_records++;
      }
    }
    for (const auto &record_entry : shard.destructed_records) {
      auto *global_record = find_global_record_by_object_id_locked(record_entry.first);
      if (!global_record || !object_record_equal(*global_record, record_entry.second) || !global_record->destructed) {
        summary.global_record_bridge_consistent = false;
        summary.owner_local_to_global_bridge_consistent = false;
        summary.orphan_records++;
        summary.owner_local_to_global_mismatch_records++;
      }
    }
  }

  for (const auto &entry : object_records) {
    auto *object = entry.first;
    const auto &record = entry.second;
    summary.global_records++;
    if (record.destructed) {
      summary.global_destructed_records++;
    } else {
      summary.global_live_records++;
    }
    auto shard_it = owner_shards.find(record.owner_id);
    if (shard_it == owner_shards.end()) {
      summary.global_record_bridge_consistent = false;
      summary.global_to_owner_local_record_mismatch_records++;
      summary.global_to_owner_local_bridge_consistent = false;
      summary.global_to_owner_local_mismatch_records++;
      continue;
    }
    const auto &shard = shard_it->second;
    if (record.destructed) {
      auto *destructed_record = find_destructed_record_locked(shard, record.object_id);
      auto record_bridge_match =
          destructed_record && object_record_equal(*destructed_record, record) &&
          shard.local_records.count(record.object_id) == 0 && shard.object_directory.count(record.object_id) == 0;
      if (!record_bridge_match) {
        summary.global_record_bridge_consistent = false;
        summary.global_to_owner_local_record_mismatch_records++;
      }
      if (!record_bridge_match || shard.local_objects.count(record.object_id) != 0 ||
          shard.local_object_index.count(object) != 0) {
        summary.global_to_owner_local_bridge_consistent = false;
        summary.global_to_owner_local_mismatch_records++;
      }
      continue;
    }

    auto *local_record = find_local_record_locked(shard, record.object_id);
    auto object_ref = shard.local_objects.find(record.object_id);
    auto object_index_ref = shard.local_object_index.find(object);
    auto record_bridge_match =
        local_record && object_record_equal(*local_record, record) &&
        shard.object_directory.count(record.object_id) != 0 &&
        shard_live_path_index_covers_path_locked(shard, record.object_path) &&
        shard.destructed_records.count(record.object_id) == 0;
    if (!record_bridge_match) {
      summary.global_record_bridge_consistent = false;
      summary.global_to_owner_local_record_mismatch_records++;
    }
    if (!record_bridge_match || object_ref == shard.local_objects.end() || object_ref->second != object ||
        object_index_ref == shard.local_object_index.end() || object_index_ref->second != record.object_id) {
      summary.global_to_owner_local_bridge_consistent = false;
      summary.global_to_owner_local_mismatch_records++;
    }
  }

  summary.global_record_bridge_consistent =
      summary.global_record_bridge_consistent && summary.owner_local_to_global_mismatch_records == 0 &&
      summary.global_to_owner_local_record_mismatch_records == 0;
  summary.global_bridge_consistent =
      summary.owner_local_to_global_bridge_consistent && summary.global_to_owner_local_bridge_consistent &&
      summary.owner_local_to_global_mismatch_records == 0 && summary.global_to_owner_local_mismatch_records == 0;
  summary.global_record_bridge_retirement_ready =
      summary.owner_local_record_index_ready && summary.global_record_bridge_consistent &&
      summary.global_records == summary.live_records + summary.destructed_records &&
      summary.global_live_records == summary.live_records &&
      summary.global_destructed_records == summary.destructed_records;
  summary.global_live_object_bridge_retirement_ready =
      summary.global_record_bridge_retirement_ready && summary.owner_local_canonical_record_ready &&
      summary.global_bridge_consistent && summary.live_records == summary.object_refs &&
      summary.live_records == summary.object_ref_indexes && summary.live_path_index_entries <= summary.live_records;
  return summary;
}

OwnerLocalLookupResult owner_local_lookup_by_object_locked(const char *owner_id, uint64_t object_id) {
  OwnerLocalLookupResult result;
  result.owner_id = safe_owner_id(owner_id);
  result.object_id = object_id;
  auto shard_it = owner_shards.find(result.owner_id);
  auto *shard = shard_it == owner_shards.end() ? nullptr : &shard_it->second;
  result.owner_local_canonical_record_ready = shard ? shard_canonical_record_ready(*shard) : true;
  auto bridge_summary = owner_local_bridge_summary_locked();
  result.global_record_bridge_retirement_ready = bridge_summary.global_record_bridge_retirement_ready;
  result.global_live_object_bridge_retirement_ready = bridge_summary.global_live_object_bridge_retirement_ready;
  if (shard) {
    result.local_record = find_local_record_locked(*shard, object_id);
    result.destructed_record = find_destructed_record_locked(*shard, object_id);
  }
  if (!result.local_record && !result.destructed_record) {
    result.cross_owner_record =
        find_cross_owner_record_by_object_id_locked(result.owner_id, object_id, result.cross_owner_record_source);
  }
  if (!result.local_record && !result.destructed_record && !result.cross_owner_record) {
    if (result.global_record_bridge_retirement_ready) {
      result.global_record_fallback_skipped = true;
      result.global_record_fallback_reason = "global_record_bridge_retirement_ready";
      result.global_record_id_scan_bridge_skipped = true;
      result.global_record_id_scan_bridge_skip_reason = "global_record_bridge_retirement_ready";
    } else {
      result.global_record_id_scan_bridge_used = true;
      result.global_record = find_global_record_id_scan_bridge_locked(object_id);
      result.global_record_id_scan_bridge_found = result.global_record != nullptr;
      result.global_record_id_scan_bridge_source = kGlobalRecordIdScanBridgeSource;
      if (result.global_record) {
        result.global_record_source = kGlobalRecordBridgeSource;
      }
    }
  }
  finalize_owner_local_lookup_locked(result, shard, false);
  return result;
}

OwnerLocalLookupResult owner_local_lookup_by_path_locked(const char *owner_id, const char *object_path) {
  OwnerLocalLookupResult result;
  result.owner_id = safe_owner_id(owner_id);
  result.query_path = object_path ? object_path : "";
  auto shard_it = owner_shards.find(result.owner_id);
  auto *shard = shard_it == owner_shards.end() ? nullptr : &shard_it->second;
  result.owner_local_canonical_record_ready = shard ? shard_canonical_record_ready(*shard) : true;
  auto bridge_summary = owner_local_bridge_summary_locked();
  result.global_record_bridge_retirement_ready = bridge_summary.global_record_bridge_retirement_ready;
  result.global_live_object_bridge_retirement_ready = bridge_summary.global_live_object_bridge_retirement_ready;
  if (shard && !result.query_path.empty()) {
    auto live_path = shard->object_path_index.find(result.query_path);
    if (live_path != shard->object_path_index.end()) {
      result.local_record = find_local_record_locked(*shard, live_path->second);
    }
    auto destructed_path = shard->destructed_path_index.find(result.query_path);
    if (destructed_path != shard->destructed_path_index.end()) {
      result.destructed_record = find_destructed_record_locked(*shard, destructed_path->second);
    }
  }
  if (!result.local_record && !result.destructed_record) {
    result.cross_owner_record =
        find_cross_owner_record_by_path_locked(result.owner_id, result.query_path, result.cross_owner_record_source);
  }
  if (!result.local_record && !result.destructed_record && !result.cross_owner_record && !result.query_path.empty()) {
    if (result.global_live_object_bridge_retirement_ready) {
      result.global_live_object_fallback_skipped = true;
      result.global_live_object_fallback_reason = "global_live_object_bridge_retirement_ready";
    } else {
      auto live_object = find_global_live_object_bridge_by_path_locked(
          result.query_path, !result.global_record_bridge_retirement_ready);
      result.global_live_object_found = live_object.object != nullptr;
      result.global_record_pointer_bridge_used = live_object.record_pointer_bridge_used;
      result.global_record_pointer_bridge_found = live_object.record_pointer_bridge_found;
      result.global_record_pointer_bridge_skipped = live_object.record_pointer_bridge_skipped;
      if (result.global_record_pointer_bridge_used) {
        result.global_record_pointer_bridge_source = kGlobalRecordPointerBridgeSource;
      }
      if (result.global_record_pointer_bridge_skipped) {
        result.global_record_pointer_bridge_skip_reason = "global_record_bridge_retirement_ready";
      }
      if (result.global_live_object_found) {
        result.global_live_object_source = kGlobalLiveObjectBridgeSource;
      }
      result.global_record = live_object.record;
    }
    if (result.global_record_bridge_retirement_ready) {
      result.global_record_fallback_skipped = true;
      result.global_record_fallback_reason = "global_record_bridge_retirement_ready";
      result.global_record_scan_bridge_skipped = true;
      result.global_record_scan_bridge_skip_reason = "global_record_bridge_retirement_ready";
    } else if (!result.global_record) {
      result.global_record_scan_bridge_used = true;
      result.global_record = find_global_record_scan_bridge_by_path_locked(result.query_path);
      result.global_record_scan_bridge_found = result.global_record != nullptr;
      if (result.global_record_scan_bridge_used) {
        result.global_record_scan_bridge_source = kGlobalRecordScanBridgeSource;
      }
    }
    if (result.global_record) {
      result.global_record_source = kGlobalRecordBridgeSource;
    }
  }
  finalize_owner_local_lookup_locked(result, shard, true);
  return result;
}

bool diagnose_handle_from_owner_local_store_locked(const VMObjectHandle &handle,
                                                   VMObjectHandleResolveResult &result) {
  auto lookup = owner_local_lookup_by_object_locked(handle.owner_id.c_str(), handle.object_id);
  auto *record = lookup.local_record
                     ? lookup.local_record
                     : (lookup.destructed_record ? lookup.destructed_record : lookup.cross_owner_record);
  bool diagnosed_via_path_index = false;
  if (!record) {
    lookup = owner_local_lookup_by_path_locked(handle.owner_id.c_str(), handle.object_path.c_str());
    record = lookup.local_record
                 ? lookup.local_record
                 : (lookup.destructed_record ? lookup.destructed_record : lookup.cross_owner_record);
    diagnosed_via_path_index = record != nullptr;
  }
  if (!record) {
    return false;
  }
  if (record->object_id != handle.object_id) {
    result.status = VMObjectHandleResolveStatus::kObjectIdMismatch;
  } else if (record->object_path != handle.object_path) {
    result.status = VMObjectHandleResolveStatus::kPathMismatch;
  } else if (record->owner_id != handle.owner_id) {
    result.status = VMObjectHandleResolveStatus::kOwnerMismatch;
  } else if (record->owner_epoch != handle.owner_epoch) {
    result.status = VMObjectHandleResolveStatus::kOwnerEpochMismatch;
  } else if (record->destructed || lookup.destructed_record) {
    result.status = VMObjectHandleResolveStatus::kRecordDestructed;
  } else {
    result.status = VMObjectHandleResolveStatus::kObjectNotFound;
  }
  result.diagnosed_via_owner_local_store = true;
  result.diagnosed_via_owner_local_path_index = diagnosed_via_path_index;
  result.diagnosed_via_owner_local_cross_shard = lookup.cross_owner_record != nullptr;
  return true;
}

bool resolve_handle_from_owner_local_object_pointer_locked(const VMObjectHandle &handle, object_t *object,
                                                           VMObjectHandleResolveResult &result) {
  const auto *record = find_live_record_by_object_pointer_locked(handle.owner_id.c_str(), object);
  if (!record) {
    return false;
  }

  result.owner_local_object_pointer_index_found = true;
  if (record->object_id != handle.object_id) {
    result.diagnosed_via_owner_local_store = true;
    result.status = VMObjectHandleResolveStatus::kObjectIdMismatch;
    return true;
  }
  if (record->object_path != handle.object_path) {
    result.diagnosed_via_owner_local_store = true;
    result.status = VMObjectHandleResolveStatus::kPathMismatch;
    return true;
  }
  if (record->owner_id != handle.owner_id) {
    result.diagnosed_via_owner_local_store = true;
    result.status = VMObjectHandleResolveStatus::kOwnerMismatch;
    return true;
  }
  if (record->owner_epoch != handle.owner_epoch) {
    result.diagnosed_via_owner_local_store = true;
    result.status = VMObjectHandleResolveStatus::kOwnerEpochMismatch;
    return true;
  }
  if (handle.owner_id != vm_owner_id(object)) {
    result.status = VMObjectHandleResolveStatus::kLiveOwnerMismatch;
    return true;
  }
  if (vm_owner_epoch(object) != handle.owner_epoch) {
    result.status = VMObjectHandleResolveStatus::kLiveOwnerEpochMismatch;
    return true;
  }

  result.object = object;
  result.status = VMObjectHandleResolveStatus::kCurrent;
  result.resolved_via_owner_local_store = true;
  return true;
}

bool diagnose_handle_from_global_record_locked(const VMObjectHandle &handle, const ObjectRecord &record,
                                               bool destructed_first, VMObjectHandleResolveResult &result) {
  result.diagnosed_via_global_index = true;
  if (destructed_first && record.destructed) {
    result.status = VMObjectHandleResolveStatus::kRecordDestructed;
    return true;
  }
  if (record.object_id != handle.object_id) {
    result.status = VMObjectHandleResolveStatus::kObjectIdMismatch;
    return true;
  }
  if (record.object_path != handle.object_path) {
    result.status = VMObjectHandleResolveStatus::kPathMismatch;
    return true;
  }
  if (record.owner_id != handle.owner_id) {
    result.status = VMObjectHandleResolveStatus::kOwnerMismatch;
    return true;
  }
  if (record.owner_epoch != handle.owner_epoch) {
    result.status = VMObjectHandleResolveStatus::kOwnerEpochMismatch;
    return true;
  }
  if (!destructed_first && record.destructed) {
    result.status = VMObjectHandleResolveStatus::kRecordDestructed;
    return true;
  }
  return false;
}

void shard_erase_path_index(std::unordered_map<std::string, uint64_t> &index, const std::string &object_path,
                            uint64_t object_id) {
  if (object_path.empty()) {
    return;
  }
  auto it = index.find(object_path);
  if (it != index.end() && it->second == object_id) {
    index.erase(it);
  }
}

void shard_remove_live_path_index(VMObjectShard &shard, uint64_t object_id) {
  auto it = shard.local_records.find(object_id);
  if (it != shard.local_records.end()) {
    shard_erase_path_index(shard.object_path_index, it->second.object_path, object_id);
  }
}

void shard_remove_destructed_path_index(VMObjectShard &shard, uint64_t object_id) {
  auto it = shard.destructed_records.find(object_id);
  if (it != shard.destructed_records.end()) {
    shard_erase_path_index(shard.destructed_path_index, it->second.object_path, object_id);
  }
}

void erase_destructed_path_index_for_live_path_locked(const std::string &object_path) {
  if (object_path.empty()) {
    return;
  }
  for (auto &entry : owner_shards) {
    entry.second.destructed_path_index.erase(object_path);
  }
}

void refresh_live_path_index_for_path_locked(const std::string &object_path) {
  if (object_path.empty()) {
    return;
  }
  for (auto &entry : owner_shards) {
    auto &shard = entry.second;
    shard.object_path_index.erase(object_path);
    uint64_t selected_object_id = 0;
    for (const auto &record_entry : shard.local_records) {
      if (record_entry.second.object_path == object_path && !record_entry.second.destructed &&
          record_entry.first > selected_object_id) {
        selected_object_id = record_entry.first;
      }
    }
    if (selected_object_id != 0) {
      shard.object_path_index[object_path] = selected_object_id;
    }
  }
}

void refresh_destructed_path_index_for_path_locked(const std::string &object_path) {
  if (object_path.empty()) {
    return;
  }
  for (auto &entry : owner_shards) {
    entry.second.destructed_path_index.erase(object_path);
  }
  if (owner_local_live_path_index_contains_locked(object_path)) {
    return;
  }
  for (auto &entry : owner_shards) {
    uint64_t selected_object_id = 0;
    for (const auto &record_entry : entry.second.destructed_records) {
      if (record_entry.second.object_path == object_path && record_entry.first > selected_object_id) {
        selected_object_id = record_entry.first;
      }
    }
    if (selected_object_id != 0) {
      entry.second.destructed_path_index[object_path] = selected_object_id;
    }
  }
}

void shard_remove_live_object_ref(VMObjectShard &shard, uint64_t object_id) {
  auto object_it = shard.local_objects.find(object_id);
  if (object_it != shard.local_objects.end() && object_it->second) {
    auto reverse = shard.local_object_index.find(object_it->second);
    if (reverse != shard.local_object_index.end() && reverse->second == object_id) {
      shard.local_object_index.erase(reverse);
    }
  }
  shard.local_objects.erase(object_id);
}

void shard_set_live_object_ref(VMObjectShard &shard, uint64_t object_id, object_t *object) {
  shard_remove_live_object_ref(shard, object_id);
  if (!object) {
    return;
  }
  auto existing = shard.local_object_index.find(object);
  if (existing != shard.local_object_index.end() && existing->second != object_id) {
    shard.local_objects.erase(existing->second);
  }
  shard.local_objects[object_id] = object;
  shard.local_object_index[object] = object_id;
}

void shard_add_live_object(VMObjectShard &shard, const ObjectRecord &record, object_t *object) {
  // status.objects is still exposed as a compatibility count while the directory is shard-owned.
  shard_remove_live_path_index(shard, record.object_id);
  shard_remove_destructed_path_index(shard, record.object_id);
  if (!record.object_path.empty()) {
    erase_destructed_path_index_for_live_path_locked(record.object_path);
  }
  shard.status.objects.insert(record.object_id);
  shard.object_directory.insert(record.object_id);
  shard.local_records[record.object_id] = record;
  shard_set_live_object_ref(shard, record.object_id, object);
  shard.destructed_records.erase(record.object_id);
  if (!record.object_path.empty()) {
    refresh_live_path_index_for_path_locked(record.object_path);
  }
}

void shard_remove_object(VMObjectShard &shard, uint64_t object_id) {
  std::string object_path;
  auto live_record = shard.local_records.find(object_id);
  if (live_record != shard.local_records.end()) {
    object_path = live_record->second.object_path;
  } else {
    auto destructed_record = shard.destructed_records.find(object_id);
    if (destructed_record != shard.destructed_records.end()) {
      object_path = destructed_record->second.object_path;
    }
  }
  shard_remove_live_path_index(shard, object_id);
  shard_remove_destructed_path_index(shard, object_id);
  shard.status.objects.erase(object_id);
  shard.object_directory.erase(object_id);
  shard.local_records.erase(object_id);
  shard_remove_live_object_ref(shard, object_id);
  shard.destructed_records.erase(object_id);
  refresh_live_path_index_for_path_locked(object_path);
  refresh_destructed_path_index_for_path_locked(object_path);
}

void shard_mark_destructed_object(VMObjectShard &shard, const ObjectRecord &record) {
  shard_remove_live_path_index(shard, record.object_id);
  shard_remove_destructed_path_index(shard, record.object_id);
  shard.status.objects.erase(record.object_id);
  shard.object_directory.erase(record.object_id);
  shard.local_records.erase(record.object_id);
  shard_remove_live_object_ref(shard, record.object_id);
  shard.destructed_records[record.object_id] = record;
  refresh_live_path_index_for_path_locked(record.object_path);
  refresh_destructed_path_index_for_path_locked(record.object_path);
}

mapping_t *vm_object_shard_contract_mapping(const VMObjectShard &shard, const OwnerLocalBridgeSummary &summary) {
  auto shard_ready = shard_canonical_record_ready(shard);
  auto store_ready = owner_local_store_ready_for_shard(shard, summary);
  auto store_complete = owner_local_store_complete_for_shard(shard, summary);
  auto *map = allocate_mapping(35);
  add_mapping_string(map, "owner_id", shard.status.owner_id.c_str());
  add_mapping_string(map, "shard_kind", "vm_object_shard");
  add_mapping_string(map, "status_model", "owner_status_record");
  add_mapping_string(map, "execution_model", "owner_execution_shard");
  add_mapping_string(map, "directory_model", "owner_local_object_directory");
  add_mapping_string(map, "storage_model", store_complete ? "owner_local_store" : "global_index_bridge");
  add_mapping_pair(map, "object_directory_count", static_cast<long>(shard.object_directory.size()));
  add_mapping_pair(map, "owner_local_record_count", static_cast<long>(shard.local_records.size()));
  add_mapping_pair(map, "owner_local_destructed_record_count", static_cast<long>(shard.destructed_records.size()));
  add_mapping_pair(map, "owner_local_object_ref_count", static_cast<long>(shard.local_objects.size()));
  add_mapping_string(map, "owner_local_object_ref_source", "vm_object_shard.local_objects");
  add_mapping_pair(map, "owner_local_object_ref_index_count", static_cast<long>(shard.local_object_index.size()));
  add_mapping_string(map, "owner_local_object_ref_index_source", "vm_object_shard.local_object_index");
  add_mapping_pair(map, "owner_local_path_index_count", static_cast<long>(shard.object_path_index.size()));
  add_mapping_pair(map, "owner_local_destructed_path_index_count",
                   static_cast<long>(shard.destructed_path_index.size()));
  add_mapping_pair(map, "owner_local_path_index_ready", 1);
  add_mapping_string(map, "owner_local_path_index_source", "vm_object_shard.object_path_index");
  add_mapping_string(map, "owner_local_destructed_path_index_source", "vm_object_shard.destructed_path_index");
  add_mapping_pair(map, "owner_local_live_index_consistent", shard_live_counts_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_object_ref_index_consistent",
                   shard_live_object_ref_index_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_live_path_index_consistent",
                   shard_live_path_index_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_destructed_path_index_consistent",
                   shard_destructed_path_index_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_canonical_record_ready", shard_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_directory_ready", shard.owner_local_directory_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_directory_from_shard", shard.owner_local_directory_from_shard ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_ready", store_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_complete", store_complete ? 1 : 0);
  add_mapping_string(map, "owner_local_store_complete_blocker",
                     owner_local_store_complete_blocker(store_complete, !store_complete, !store_complete));
  add_mapping_pair(map, "uses_global_object_table", store_complete ? 0 : 1);
  add_mapping_pair(map, "global_index_bridge", store_complete ? 0 : 1);
  add_mapping_pair(map, "global_live_object_bridge_ready", store_complete ? 0 : 1);
  add_mapping_string(map, "global_live_object_bridge_source", store_complete ? "" : kGlobalLiveObjectBridgeSource);
  add_mapping_pair(map, "global_record_bridge_ready", store_complete ? 0 : 1);
  add_mapping_string(map, "global_record_bridge_source", store_complete ? "" : kGlobalRecordBridgeSource);
  add_owner_local_lifecycle_contract(map, store_complete, shard_ready);
  add_mapping_pair(map, "contract_version", 1);
  return map;
}

void append_migration_trace_locked(const ObjectRecord &record, const std::string &from_owner_id,
                                   const std::string &to_owner_id);

ObjectRecord &write_owner_local_lifecycle_record_locked(object_t *object, bool force_destructed = false,
                                                        bool *was_destructed_out = nullptr) {
  auto &compat_record = object_records[object];
  auto previous_record = compat_record;
  auto had_previous_record = previous_record.object_id != 0;
  auto object_already_destructed = object && (object->flags & O_DESTRUCTED) != 0;
  auto object_pending_destruct = object_is_pending_destruct(object);
  auto live_destructed =
      object_already_destructed || force_destructed ||
      (had_previous_record && previous_record.destructed && object_pending_destruct);
  auto record_reused_by_live_object =
      had_previous_record && previous_record.destructed && !live_destructed && !object_pending_destruct;
  auto current_owner_explicit = vm_owner_has_explicit_id(object);
  auto preserve_destructed_snapshot =
      had_previous_record && previous_record.destructed && live_destructed && !current_owner_explicit;
  if (was_destructed_out) {
    *was_destructed_out = had_previous_record ? previous_record.destructed && !record_reused_by_live_object
                                              : object_already_destructed;
  }

  ObjectRecord record;
  record.object_id = (!had_previous_record || record_reused_by_live_object)
                         ? next_object_id.fetch_add(1, std::memory_order_relaxed)
                         : previous_record.object_id;
  record.owner_id = preserve_destructed_snapshot ? previous_record.owner_id : safe_owner_id(vm_owner_id(object));
  record.owner_epoch = preserve_destructed_snapshot ? previous_record.owner_epoch : vm_owner_epoch(object);
  record.object_path = preserve_destructed_snapshot ? previous_record.object_path : safe_object_path(object);
  record.destructed = live_destructed;

  if (had_previous_record &&
      (record_reused_by_live_object || previous_record.owner_id != record.owner_id)) {
    auto old_it = owner_shards.find(previous_record.owner_id);
    if (old_it != owner_shards.end()) {
      shard_remove_object(old_it->second, previous_record.object_id);
    }
  }

  auto &new_shard = shard_for_owner(record.owner_id);
  if (record.destructed) {
    shard_mark_destructed_object(new_shard, record);
  } else {
    shard_add_live_object(new_shard, record, object);
  }
  if (!had_previous_record || record_reused_by_live_object) {
    new_shard.status.registered++;
  }
  if (had_previous_record && !record_reused_by_live_object && previous_record.owner_id != record.owner_id) {
    append_migration_trace_locked(record, previous_record.owner_id, record.owner_id);
  }

  compat_record = record;
  return compat_record;
}

void append_migration_trace_locked(const ObjectRecord &record, const std::string &from_owner_id,
                                   const std::string &to_owner_id) {
  ObjectMigrationRecord trace;
  trace.migration_id = next_migration_id.fetch_add(1, std::memory_order_relaxed);
  trace.object_id = record.object_id;
  trace.owner_epoch = record.owner_epoch;
  trace.from_owner_id = from_owner_id;
  trace.to_owner_id = to_owner_id;
  trace.object_path = record.object_path;
  object_migration_traces.push_back(std::move(trace));
  while (object_migration_traces.size() > kObjectStoreMigrationTraceLimit) {
    object_migration_traces.pop_front();
  }
}

mapping_t *migration_trace_mapping(const ObjectMigrationRecord &trace) {
  auto *map = allocate_mapping(6);
  add_mapping_pair(map, "migration_id", static_cast<long>(trace.migration_id));
  add_mapping_pair(map, "object_id", static_cast<long>(trace.object_id));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(trace.owner_epoch));
  add_mapping_string(map, "from_owner_id", trace.from_owner_id.c_str());
  add_mapping_string(map, "to_owner_id", trace.to_owner_id.c_str());
  add_mapping_string(map, "object_path", trace.object_path.c_str());
  return map;
}

mapping_t *object_record_mapping(const ObjectRecord &record) {
  auto *map = allocate_mapping(18);
  add_mapping_pair(map, "object_id", static_cast<long>(record.object_id));
  add_mapping_string(map, "owner_id", record.owner_id.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(record.owner_epoch));
  add_mapping_string(map, "object_path", record.object_path.c_str());
  add_mapping_pair(map, "destructed", record.destructed ? 1 : 0);
  add_mapping_pair(map, "live", record.destructed ? 0 : 1);
  add_mapping_pair(map, "owner_local_directory_entry", 1);
  add_mapping_string(map, "owner_local_directory_source", "vm_object_shard.object_directory");
  add_mapping_pair(map, "owner_local_record_snapshot", 1);
  add_mapping_string(map, "owner_local_record_source", "vm_object_shard.local_records");
  add_mapping_pair(map, "owner_local_object_ref_entry", 1);
  add_mapping_string(map, "owner_local_object_ref_source", "vm_object_shard.local_objects");
  add_mapping_pair(map, "owner_local_object_ref_index_entry", 1);
  add_mapping_string(map, "owner_local_object_ref_index_source", "vm_object_shard.local_object_index");
  add_mapping_pair(map, "owner_local_path_index_entry", 1);
  add_mapping_string(map, "owner_local_path_index_source", "vm_object_shard.object_path_index");
  add_mapping_pair(map, "resolved_via_owner_local_store", 1);
  add_mapping_pair(map, "resolved_via_global_index", 0);
  add_mapping_pair(map, "snapshot_record", 1);
  return map;
}

array_t *object_directory_for_owner_locked(const VMObjectShard &shard) {
  std::vector<const ObjectRecord *> records;
  records.reserve(shard.object_directory.size());
  for (auto object_id : shard.object_directory) {
    auto *record = find_local_record_locked(shard, object_id);
    if (record && shard_has_local_object_ref_locked(shard, object_id) &&
        record->owner_id == shard.status.owner_id && !record->destructed) {
      records.push_back(record);
    }
  }

  auto *directory = allocate_array(static_cast<int>(records.size()));
  for (size_t i = 0; i < records.size(); i++) {
    directory->item[i].type = T_MAPPING;
    directory->item[i].subtype = 0;
    directory->item[i].u.map = object_record_mapping(*records[i]);
  }
  return directory;
}

long execution_runnable_tasks(const ObjectExecutionShardRecord &execution) {
  return static_cast<long>(execution.active_heartbeats.size() + execution.pending_callouts.size() +
                           execution.pending_messages.size());
}

mapping_t *status_record_mapping(const ObjectShardStatusRecord &status) {
  auto *map = allocate_mapping(7);
  add_mapping_string(map, "owner_id", status.owner_id.c_str());
  add_mapping_pair(map, "objects", static_cast<long>(status.objects.size()));
  add_mapping_pair(map, "registered", static_cast<long>(status.registered));
  add_mapping_pair(map, "destructed", static_cast<long>(status.destructed));
  add_mapping_pair(map, "heartbeats", static_cast<long>(status.heartbeats));
  add_mapping_pair(map, "callouts", static_cast<long>(status.callouts));
  add_mapping_pair(map, "messages", static_cast<long>(status.messages));
  return map;
}

mapping_t *execution_shard_mapping(const ObjectExecutionShardRecord &execution) {
  auto runnable_tasks = execution_runnable_tasks(execution);
  auto *map = allocate_mapping(6);
  add_mapping_string(map, "owner_id", execution.owner_id.c_str());
  add_mapping_pair(map, "active_heartbeats", static_cast<long>(execution.active_heartbeats.size()));
  add_mapping_pair(map, "pending_callouts", static_cast<long>(execution.pending_callouts.size()));
  add_mapping_pair(map, "pending_messages", static_cast<long>(execution.pending_messages.size()));
  add_mapping_pair(map, "runnable_tasks", static_cast<long>(runnable_tasks));
  add_mapping_pair(map, "executor_ready", runnable_tasks > 0 ? 1 : 0);
  return map;
}

mapping_t *shard_mapping(const VMObjectShard &shard, const OwnerLocalBridgeSummary &summary) {
  auto runnable_tasks = execution_runnable_tasks(shard.execution);
  auto shard_ready = shard_canonical_record_ready(shard);
  auto store_ready = owner_local_store_ready_for_shard(shard, summary);
  auto store_complete = owner_local_store_complete_for_shard(shard, summary);
  auto *status_record = status_record_mapping(shard.status);
  auto *execution_shard = execution_shard_mapping(shard.execution);
  auto *object_directory = object_directory_for_owner_locked(shard);
  auto *shard_contract = vm_object_shard_contract_mapping(shard, summary);
  auto *map = allocate_mapping(48);
  add_mapping_string(map, "owner_id", shard.status.owner_id.c_str());
  add_mapping_pair(map, "objects", static_cast<long>(shard.status.objects.size()));
  add_mapping_pair(map, "registered", static_cast<long>(shard.status.registered));
  add_mapping_pair(map, "destructed", static_cast<long>(shard.status.destructed));
  add_mapping_pair(map, "heartbeats", static_cast<long>(shard.status.heartbeats));
  add_mapping_pair(map, "active_heartbeats", static_cast<long>(shard.execution.active_heartbeats.size()));
  add_mapping_pair(map, "callouts", static_cast<long>(shard.status.callouts));
  add_mapping_pair(map, "pending_callouts", static_cast<long>(shard.execution.pending_callouts.size()));
  add_mapping_pair(map, "messages", static_cast<long>(shard.status.messages));
  add_mapping_pair(map, "pending_messages", static_cast<long>(shard.execution.pending_messages.size()));
  add_mapping_pair(map, "runnable_tasks", runnable_tasks);
  add_mapping_pair(map, "executor_ready", runnable_tasks > 0 ? 1 : 0);
  add_mapping_map(map, "vm_object_shard", shard_contract);
  add_mapping_map(map, "status_record", status_record);
  add_mapping_map(map, "execution_shard", execution_shard);
  add_mapping_pair(map, "shard_contract_version", 1);
  add_mapping_pair(map, "status_record_version", 1);
  add_mapping_pair(map, "execution_shard_ready", runnable_tasks > 0 ? 1 : 0);
  add_mapping_array(map, "object_directory", object_directory);
  add_mapping_pair(map, "object_directory_count", static_cast<long>(object_directory->size));
  add_mapping_pair(map, "owner_local_directory_count", static_cast<long>(shard.object_directory.size()));
  add_mapping_pair(map, "owner_local_record_count", static_cast<long>(shard.local_records.size()));
  add_mapping_pair(map, "owner_local_destructed_record_count", static_cast<long>(shard.destructed_records.size()));
  add_mapping_pair(map, "owner_local_object_ref_count", static_cast<long>(shard.local_objects.size()));
  add_mapping_string(map, "owner_local_object_ref_source", "vm_object_shard.local_objects");
  add_mapping_pair(map, "owner_local_object_ref_index_count", static_cast<long>(shard.local_object_index.size()));
  add_mapping_string(map, "owner_local_object_ref_index_source", "vm_object_shard.local_object_index");
  add_mapping_pair(map, "owner_local_path_index_count", static_cast<long>(shard.object_path_index.size()));
  add_mapping_pair(map, "owner_local_destructed_path_index_count",
                   static_cast<long>(shard.destructed_path_index.size()));
  add_mapping_pair(map, "owner_local_path_index_ready", 1);
  add_mapping_string(map, "owner_local_path_index_source", "vm_object_shard.object_path_index");
  add_mapping_string(map, "owner_local_destructed_path_index_source", "vm_object_shard.destructed_path_index");
  add_mapping_pair(map, "owner_local_live_index_consistent", shard_live_counts_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_object_ref_index_consistent",
                   shard_live_object_ref_index_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_live_path_index_consistent",
                   shard_live_path_index_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_destructed_path_index_consistent",
                   shard_destructed_path_index_consistent(shard) ? 1 : 0);
  add_mapping_pair(map, "owner_local_canonical_record_ready", shard_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_directory_ready", shard.owner_local_directory_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_directory_from_shard", shard.owner_local_directory_from_shard ? 1 : 0);
  add_mapping_string(map, "owner_local_directory_source", "vm_object_shard.object_directory");
  add_mapping_pair(map, "owner_local_store_ready", store_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_complete", store_complete ? 1 : 0);
  add_mapping_string(map, "owner_local_store_complete_blocker",
                     owner_local_store_complete_blocker(store_complete, !store_complete, !store_complete));
  add_mapping_pair(map, "uses_global_object_table", store_complete ? 0 : 1);
  add_mapping_pair(map, "global_index_bridge", store_complete ? 0 : 1);
  add_mapping_pair(map, "global_live_object_bridge_ready", store_complete ? 0 : 1);
  add_mapping_string(map, "global_live_object_bridge_source", store_complete ? "" : kGlobalLiveObjectBridgeSource);
  add_mapping_pair(map, "global_record_bridge_ready", store_complete ? 0 : 1);
  add_mapping_string(map, "global_record_bridge_source", store_complete ? "" : kGlobalRecordBridgeSource);
  add_owner_local_lifecycle_contract(map, store_complete, shard_ready);
  free_mapping(shard_contract);
  free_mapping(status_record);
  free_mapping(execution_shard);
  free_array(object_directory);
  return map;
}
}  // namespace

VMObjectHandle vm_object_handle_with_intent(object_t *object, const char *permission_intent) {
  VMObjectHandle handle;
  handle.permission_intent = safe_permission_intent(permission_intent);
  if (!object) {
    return handle;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  auto &record = write_owner_local_lifecycle_record_locked(object);
  handle.object_id = record.object_id;
  handle.owner_id = record.owner_id;
  handle.owner_epoch = record.owner_epoch;
  handle.object_path = record.object_path;
  handle.snapshot_version = record.owner_epoch;
  handle.valid = !record.destructed;
  return handle;
}

VMObjectHandle vm_object_handle(object_t *object) {
  return vm_object_handle_with_intent(object, kVMObjectHandleDefaultPermissionIntent);
}

object_t *vm_object_handle_resolve(const VMObjectHandle &handle) {
  auto result = vm_object_handle_resolve_status(handle);
  return result.status == VMObjectHandleResolveStatus::kCurrent ? result.object : nullptr;
}

VMObjectHandleResolveResult vm_object_handle_resolve_status(const VMObjectHandle &handle) {
  VMObjectHandleResolveResult result;
  if (!handle.valid) {
    result.status = VMObjectHandleResolveStatus::kInvalidHandle;
    return result;
  }
  if (handle.object_path.empty()) {
    result.status = VMObjectHandleResolveStatus::kMissingPath;
    return result;
  }

  {
    ObjectStoreReadLock lock(object_store_directory_mutex);
    if (resolve_handle_from_owner_local_shard_locked(handle, result)) {
      return result;
    }
    auto bridge_summary = owner_local_bridge_summary_locked();
    result.global_record_bridge_retirement_ready = bridge_summary.global_record_bridge_retirement_ready;
    result.global_live_object_bridge_retirement_ready = bridge_summary.global_live_object_bridge_retirement_ready;
    if (diagnose_handle_from_owner_local_store_locked(handle, result)) {
      return result;
    }
  }

  ObjectStoreReadLock lock(object_store_directory_mutex);
  auto bridge_summary = owner_local_bridge_summary_locked();
  result.global_record_bridge_retirement_ready = bridge_summary.global_record_bridge_retirement_ready;
  result.global_live_object_bridge_retirement_ready = bridge_summary.global_live_object_bridge_retirement_ready;
  if (result.global_live_object_bridge_retirement_ready) {
    result.global_live_object_fallback_skipped = true;
    result.global_live_object_fallback_reason = "global_live_object_bridge_retirement_ready";
    if (result.global_record_bridge_retirement_ready) {
      result.global_record_fallback_skipped = true;
      result.global_record_fallback_reason = "global_record_bridge_retirement_ready";
      result.global_record_id_scan_bridge_skipped = true;
      result.global_record_id_scan_bridge_skip_reason = "global_record_bridge_retirement_ready";
    }
    result.status = VMObjectHandleResolveStatus::kObjectNotFound;
    return result;
  }
  auto global_object = find_global_live_object_bridge_by_path_locked(
      handle.object_path, !result.global_record_bridge_retirement_ready);
  result.global_live_object_found = global_object.object != nullptr;
  if (result.global_live_object_found) {
    result.global_live_object_source = kGlobalLiveObjectBridgeSource;
  }
  result.global_record_pointer_bridge_used = global_object.record_pointer_bridge_used;
  result.global_record_pointer_bridge_found = global_object.record_pointer_bridge_found;
  result.global_record_pointer_bridge_skipped = global_object.record_pointer_bridge_skipped;
  if (result.global_record_pointer_bridge_used) {
    result.global_record_pointer_bridge_source = kGlobalRecordPointerBridgeSource;
  }
  if (result.global_record_pointer_bridge_skipped) {
    result.global_record_pointer_bridge_skip_reason = "global_record_bridge_retirement_ready";
  }
  if (!global_object.object) {
    if (result.global_record_bridge_retirement_ready) {
      result.global_record_fallback_skipped = true;
      result.global_record_fallback_reason = "global_record_bridge_retirement_ready";
      result.global_record_id_scan_bridge_skipped = true;
      result.global_record_id_scan_bridge_skip_reason = "global_record_bridge_retirement_ready";
    } else {
      result.global_record_id_scan_bridge_used = true;
      auto *record = find_global_record_id_scan_bridge_locked(handle.object_id);
      result.global_record_id_scan_bridge_found = record != nullptr;
      result.global_record_id_scan_bridge_source = kGlobalRecordIdScanBridgeSource;
      if (record) {
        result.global_record_found = true;
        result.global_record_source = kGlobalRecordBridgeSource;
        if (diagnose_handle_from_global_record_locked(handle, *record, false, result)) {
          return result;
        }
      }
    }
    result.status = VMObjectHandleResolveStatus::kObjectNotFound;
    return result;
  }
  if (global_object.object->flags & O_DESTRUCTED) {
    result.status = VMObjectHandleResolveStatus::kObjectDestructed;
    return result;
  }

  if (resolve_handle_from_owner_local_object_pointer_locked(handle, global_object.object, result)) {
    return result;
  }

  if (result.global_record_bridge_retirement_ready) {
    result.global_record_fallback_skipped = true;
    result.global_record_fallback_reason = "global_record_bridge_retirement_ready";
    result.status = VMObjectHandleResolveStatus::kObjectNotFound;
    return result;
  }

  if (!global_object.record) {
    result.status = VMObjectHandleResolveStatus::kUnregistered;
    return result;
  }
  result.global_record_found = true;
  result.global_record_source = kGlobalRecordBridgeSource;
  if (diagnose_handle_from_global_record_locked(handle, *global_object.record, true, result)) {
    return result;
  }
  if (handle.owner_id != vm_owner_id(global_object.object)) {
    result.status = VMObjectHandleResolveStatus::kLiveOwnerMismatch;
    return result;
  }
  if (vm_owner_epoch(global_object.object) != handle.owner_epoch) {
    result.status = VMObjectHandleResolveStatus::kLiveOwnerEpochMismatch;
    return result;
  }

  result.object = global_object.object;
  result.status = VMObjectHandleResolveStatus::kCurrent;
  result.resolved_via_global_index = true;
  return result;
}

const char *vm_object_handle_resolve_status_name(VMObjectHandleResolveStatus status) {
  switch (status) {
    case VMObjectHandleResolveStatus::kCurrent:
      return "current";
    case VMObjectHandleResolveStatus::kInvalidHandle:
      return "invalid_handle";
    case VMObjectHandleResolveStatus::kMissingPath:
      return "missing_path";
    case VMObjectHandleResolveStatus::kObjectNotFound:
      return "object_not_found";
    case VMObjectHandleResolveStatus::kObjectDestructed:
      return "object_destructed";
    case VMObjectHandleResolveStatus::kUnregistered:
      return "unregistered";
    case VMObjectHandleResolveStatus::kRecordDestructed:
      return "record_destructed";
    case VMObjectHandleResolveStatus::kObjectIdMismatch:
      return "object_id_mismatch";
    case VMObjectHandleResolveStatus::kPathMismatch:
      return "path_mismatch";
    case VMObjectHandleResolveStatus::kOwnerMismatch:
      return "owner_mismatch";
    case VMObjectHandleResolveStatus::kOwnerEpochMismatch:
      return "owner_epoch_mismatch";
    case VMObjectHandleResolveStatus::kLiveOwnerMismatch:
      return "live_owner_mismatch";
    case VMObjectHandleResolveStatus::kLiveOwnerEpochMismatch:
      return "live_owner_epoch_mismatch";
  }
  return "unknown";
}

bool vm_object_handle_is_current(const VMObjectHandle &handle) { return vm_object_handle_resolve(handle) != nullptr; }

void vm_object_store_register(object_t *object) {
  if (!object) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  write_owner_local_lifecycle_record_locked(object);
}

// C++ regression hook for bridge-readiness tests; not part of the LPC/runtime API.
bool vm_object_store_test_support_remove_live_object_ref_for_bridge_readiness(const char *owner_id,
                                                                              uint64_t object_id) {
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  auto shard_it = owner_shards.find(safe_owner_id(owner_id));
  if (shard_it == owner_shards.end()) {
    return false;
  }
  auto &shard = shard_it->second;
  auto object_it = shard.local_objects.find(object_id);
  if (object_it == shard.local_objects.end()) {
    return false;
  }
  if (object_it->second) {
    auto reverse = shard.local_object_index.find(object_it->second);
    if (reverse != shard.local_object_index.end() && reverse->second == object_id) {
      shard.local_object_index.erase(reverse);
    }
  }
  shard.local_objects.erase(object_it);
  return true;
}

mapping_t *vm_object_handle_status_with_intent(object_t *object, const char *permission_intent) {
  auto handle = vm_object_handle_with_intent(object, permission_intent);
  auto status = vm_object_handle_resolve_status(handle);
  auto *map = allocate_mapping(43);
  add_mapping_pair(map, "success", handle.valid ? 1 : 0);
  add_mapping_pair(map, "object_handle_capability_ready", 1);
  add_mapping_string(map, "capability_model", kVMObjectHandleCapabilityModelV1);
  add_mapping_pair(map, "object_id", static_cast<long>(handle.object_id));
  add_mapping_string(map, "owner_id", handle.owner_id.c_str());
  add_mapping_pair(map, "owner_epoch", static_cast<long>(handle.owner_epoch));
  add_mapping_string(map, "object_path", handle.object_path.c_str());
  add_mapping_string(map, "permission_intent", handle.permission_intent.c_str());
  add_mapping_pair(map, "snapshot_version", static_cast<long>(handle.snapshot_version));
  add_mapping_pair(map, "capability_epoch_guard", handle.owner_epoch == handle.snapshot_version ? 1 : 0);
  add_mapping_pair(map, "valid", handle.valid ? 1 : 0);
  add_mapping_pair(map, "current", status.status == VMObjectHandleResolveStatus::kCurrent ? 1 : 0);
  add_mapping_string(map, "resolve_status", vm_object_handle_resolve_status_name(status.status));
  add_mapping_pair(map, "resolved_via_owner_local_store", status.resolved_via_owner_local_store ? 1 : 0);
  add_mapping_pair(map, "owner_local_fast_path_used", status.owner_local_fast_path_used ? 1 : 0);
  add_mapping_string(map, "owner_local_fast_path_lock_model",
                     status.owner_local_fast_path_used ? "shared_mutex_read_lock" : "");
  add_mapping_pair(map, "owner_local_fast_path_global_fallback",
                   status.owner_local_fast_path_used && status.resolved_via_global_index ? 1 : 0);
  add_mapping_pair(map, "diagnosed_via_owner_local_store", status.diagnosed_via_owner_local_store ? 1 : 0);
  add_mapping_pair(map, "diagnosed_via_owner_local_path_index",
                   status.diagnosed_via_owner_local_path_index ? 1 : 0);
  add_mapping_pair(map, "diagnosed_via_owner_local_cross_shard",
                   status.diagnosed_via_owner_local_cross_shard ? 1 : 0);
  add_mapping_pair(map, "owner_local_object_pointer_index_found",
                   status.owner_local_object_pointer_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_pointer_index_source",
                     status.owner_local_object_pointer_index_found ? "vm_object_shard.local_object_index" : "");
  add_mapping_pair(map, "global_live_object_found", status.global_live_object_found ? 1 : 0);
  add_mapping_string(map, "global_live_object_source",
                     status.global_live_object_found ? status.global_live_object_source.c_str() : "");
  add_mapping_pair(map, "global_live_object_bridge_retirement_ready",
                   status.global_live_object_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "global_live_object_fallback_skipped",
                   status.global_live_object_fallback_skipped ? 1 : 0);
  add_mapping_string(map, "global_live_object_fallback_reason",
                     status.global_live_object_fallback_skipped
                         ? status.global_live_object_fallback_reason.c_str()
                         : "");
  add_mapping_pair(map, "global_record_found", status.global_record_found ? 1 : 0);
  add_mapping_string(map, "global_record_source",
                     status.global_record_found ? status.global_record_source.c_str() : "");
  add_mapping_pair(map, "global_record_id_scan_bridge_used",
                   status.global_record_id_scan_bridge_used ? 1 : 0);
  add_mapping_pair(map, "global_record_id_scan_bridge_found",
                   status.global_record_id_scan_bridge_found ? 1 : 0);
  add_mapping_string(map, "global_record_id_scan_bridge_source",
                     status.global_record_id_scan_bridge_used
                         ? status.global_record_id_scan_bridge_source.c_str()
                         : "");
  add_mapping_pair(map, "global_record_id_scan_bridge_skipped",
                   status.global_record_id_scan_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "global_record_id_scan_bridge_skip_reason",
                     status.global_record_id_scan_bridge_skipped
                         ? status.global_record_id_scan_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "global_record_pointer_bridge_used",
                   status.global_record_pointer_bridge_used ? 1 : 0);
  add_mapping_pair(map, "global_record_pointer_bridge_found",
                   status.global_record_pointer_bridge_found ? 1 : 0);
  add_mapping_string(map, "global_record_pointer_bridge_source",
                     status.global_record_pointer_bridge_used
                         ? status.global_record_pointer_bridge_source.c_str()
                         : "");
  add_mapping_pair(map, "global_record_pointer_bridge_skipped",
                   status.global_record_pointer_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "global_record_pointer_bridge_skip_reason",
                     status.global_record_pointer_bridge_skipped
                         ? status.global_record_pointer_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "global_record_bridge_retirement_ready",
                   status.global_record_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "global_record_fallback_skipped", status.global_record_fallback_skipped ? 1 : 0);
  add_mapping_string(map, "global_record_fallback_reason",
                     status.global_record_fallback_skipped ? status.global_record_fallback_reason.c_str() : "");
  add_mapping_pair(map, "diagnosed_via_global_index", status.diagnosed_via_global_index ? 1 : 0);
  add_mapping_pair(map, "resolved_via_global_index", status.resolved_via_global_index ? 1 : 0);
  return map;
}

mapping_t *vm_object_handle_status(object_t *object) {
  return vm_object_handle_status_with_intent(object, kVMObjectHandleDefaultPermissionIntent);
}

void vm_object_store_update_owner(object_t *object) {
  if (!object) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  write_owner_local_lifecycle_record_locked(object);
}

void vm_object_store_mark_destructed(object_t *object) {
  if (!object) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  bool was_destructed = false;
  auto &record = write_owner_local_lifecycle_record_locked(object, true, &was_destructed);
  auto &shard = shard_for_owner(record.owner_id);
  shard.execution.active_heartbeats.erase(record.object_id);
  if (!was_destructed) {
    shard.status.destructed++;
  }
}

void vm_object_store_record_callout(object_t *object, uint64_t callout_id) {
  if (!object) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  auto &record = write_owner_local_lifecycle_record_locked(object);
  auto &shard = shard_for_owner(record.owner_id);
  shard.status.callouts++;
  if (callout_id != 0) {
    shard.execution.pending_callouts.insert(callout_id);
  }
}

void vm_object_store_remove_callout(const char *owner_id, uint64_t callout_id) {
  if (callout_id == 0) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  shard_for_owner(safe_owner_id(owner_id)).execution.pending_callouts.erase(callout_id);
}

void vm_object_store_record_heartbeat(object_t *object) {
  if (!object) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  auto &record = write_owner_local_lifecycle_record_locked(object);
  auto &shard = shard_for_owner(record.owner_id);
  shard.status.heartbeats++;
  if (!record.destructed) {
    shard.execution.active_heartbeats.insert(record.object_id);
  }
}

void vm_object_store_remove_heartbeat(object_t *object) {
  if (!object) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  auto &record = write_owner_local_lifecycle_record_locked(object);
  shard_for_owner(record.owner_id).execution.active_heartbeats.erase(record.object_id);
}

void vm_object_store_record_message(const char *owner_id, uint64_t task_id) {
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  auto &shard = shard_for_owner(safe_owner_id(owner_id));
  shard.status.messages++;
  if (task_id != 0) {
    shard.execution.pending_messages.insert(task_id);
  }
}

void vm_object_store_remove_message(const char *owner_id, uint64_t task_id) {
  if (task_id == 0) {
    return;
  }
  ObjectStoreWriteLock lock(object_store_directory_mutex);
  shard_for_owner(safe_owner_id(owner_id)).execution.pending_messages.erase(task_id);
}

mapping_t *vm_object_store_status() {
  ObjectStoreReadLock lock(object_store_directory_mutex);
  auto owner_local_bridge = owner_local_bridge_summary_locked();
  auto *shards = allocate_array(static_cast<int>(owner_shards.size()));
  bool owner_local_store_ready = true;
  bool owner_local_store_complete = true;
  int i = 0;
  for (const auto &entry : owner_shards) {
    owner_local_store_ready =
        owner_local_store_ready && owner_local_store_ready_for_shard(entry.second, owner_local_bridge);
    owner_local_store_complete =
        owner_local_store_complete && owner_local_store_complete_for_shard(entry.second, owner_local_bridge);
    shards->item[i].type = T_MAPPING;
    shards->item[i].subtype = 0;
    shards->item[i].u.map = shard_mapping(entry.second, owner_local_bridge);
    i++;
  }
  auto *migrations = allocate_array(static_cast<int>(object_migration_traces.size()));
  int migration_index = 0;
  for (const auto &trace : object_migration_traces) {
    migrations->item[migration_index].type = T_MAPPING;
    migrations->item[migration_index].subtype = 0;
    migrations->item[migration_index].u.map = migration_trace_mapping(trace);
    migration_index++;
  }
  auto *map = allocate_mapping(51);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "store_kind", "vm_object_store");
  add_mapping_string(map, "status_model", "object_store_status");
  add_mapping_string(map, "directory_model", "owner_local_object_directory");
  add_mapping_string(map, "storage_model", owner_local_store_complete ? "owner_local_store" : "global_index_bridge");
  add_mapping_pair(map, "object_store_owner_fast_path_ready", 1);
  add_mapping_pair(map, "owner_local_fast_path_ready", 1);
  add_mapping_string(map, "owner_local_fast_path_lock_model", "shared_mutex_read_lock");
  add_mapping_pair(map, "object_store_global_fallback_on_owner_fast_path", 0);
  add_mapping_string(map, "object_store_owner_fast_path_scope", "same_owner_handle_resolve");
  add_mapping_string(map, "owner_local_lifecycle_write_model",
                     "owner_shard_canonical_with_global_compat_mirror");
  add_mapping_string(map, "global_record_write_model", "compatibility_mirror");
  add_mapping_pair(map, "global_record_canonical_write", 0);
  add_mapping_pair(map, "registered_objects", static_cast<long>(object_records.size()));
  add_mapping_pair(map, "global_record_total", static_cast<long>(owner_local_bridge.global_records));
  add_mapping_pair(map, "global_live_record_total", static_cast<long>(owner_local_bridge.global_live_records));
  add_mapping_pair(map, "global_destructed_record_total",
                   static_cast<long>(owner_local_bridge.global_destructed_records));
  add_mapping_pair(map, "owner_local_record_total", static_cast<long>(owner_local_bridge.live_records));
  add_mapping_pair(map, "owner_local_object_ref_total", static_cast<long>(owner_local_bridge.object_refs));
  add_mapping_pair(map, "owner_local_object_ref_index_total",
                   static_cast<long>(owner_local_bridge.object_ref_indexes));
  add_mapping_pair(map, "owner_local_destructed_record_total",
                   static_cast<long>(owner_local_bridge.destructed_records));
  add_mapping_pair(map, "owner_local_path_index_total",
                   static_cast<long>(owner_local_bridge.live_path_index_entries));
  add_mapping_pair(map, "owner_local_destructed_path_index_total",
                   static_cast<long>(owner_local_bridge.destructed_path_index_entries));
  add_mapping_pair(map, "owner_local_orphan_record_total",
                   static_cast<long>(owner_local_bridge.orphan_records));
  add_mapping_pair(map, "owner_local_to_global_mismatch_record_total",
                   static_cast<long>(owner_local_bridge.owner_local_to_global_mismatch_records));
  add_mapping_pair(map, "global_to_owner_local_record_mismatch_record_total",
                   static_cast<long>(owner_local_bridge.global_to_owner_local_record_mismatch_records));
  add_mapping_pair(map, "global_to_owner_local_mismatch_record_total",
                   static_cast<long>(owner_local_bridge.global_to_owner_local_mismatch_records));
  add_mapping_pair(map, "owner_local_record_index_ready",
                   owner_local_bridge.owner_local_record_index_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_canonical_record_ready",
                   owner_local_bridge.owner_local_canonical_record_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_ready", owner_local_store_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_complete", owner_local_store_complete ? 1 : 0);
  add_mapping_string(map, "owner_local_store_complete_blocker",
                     owner_local_store_complete_blocker(owner_local_store_complete,
                                                        !owner_local_store_complete,
                                                        !owner_local_store_complete));
  add_mapping_pair(map, "uses_global_object_table", owner_local_store_complete ? 0 : 1);
  add_mapping_pair(map, "global_index_bridge", owner_local_store_complete ? 0 : 1);
  add_mapping_pair(map, "owner_local_to_global_bridge_consistent",
                   owner_local_bridge.owner_local_to_global_bridge_consistent ? 1 : 0);
  add_mapping_pair(map, "global_to_owner_local_bridge_consistent",
                   owner_local_bridge.global_to_owner_local_bridge_consistent ? 1 : 0);
  add_mapping_pair(map, "global_record_bridge_consistent",
                   owner_local_bridge.global_record_bridge_consistent ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_bridge_consistent",
                   owner_local_bridge.global_bridge_consistent ? 1 : 0);
  add_mapping_pair(map, "global_record_bridge_retirement_ready",
                   owner_local_bridge.global_record_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "global_live_object_bridge_retirement_ready",
                   owner_local_bridge.global_live_object_bridge_retirement_ready ? 1 : 0);
  add_mapping_string(map, "owner_local_global_bridge_check", "bidirectional");
  add_mapping_string(map, "owner_local_global_bridge_source", "vm_object_shard");
  add_mapping_pair(map, "global_live_object_bridge_ready", owner_local_store_complete ? 0 : 1);
  add_mapping_string(map, "global_live_object_bridge_source",
                     owner_local_store_complete ? "" : kGlobalLiveObjectBridgeSource);
  add_mapping_pair(map, "global_record_bridge_ready", owner_local_store_complete ? 0 : 1);
  add_mapping_string(map, "global_record_bridge_source",
                     owner_local_store_complete ? "" : kGlobalRecordBridgeSource);
  add_owner_local_lifecycle_contract(map, owner_local_store_complete,
                                     owner_local_bridge.owner_local_canonical_record_ready);
  add_mapping_pair(map, "owner_shards", static_cast<long>(owner_shards.size()));
  add_mapping_string(map, "default_owner_id", vm_owner_default_id());
  add_mapping_pair(map, "migration_count",
                   static_cast<long>(next_migration_id.load(std::memory_order_relaxed) - 1));
  add_mapping_array(map, "migrations", migrations);
  add_mapping_array(map, "shards", shards);
  free_array(migrations);
  free_array(shards);
  return map;
}

mapping_t *vm_object_store_owner_status(const char *owner_id) {
  ObjectStoreReadLock lock(object_store_directory_mutex);
  auto normalized = safe_owner_id(owner_id);
  auto owner_local_bridge = owner_local_bridge_summary_locked();
  auto it = owner_shards.find(normalized);
  if (it == owner_shards.end()) {
    auto *object_directory = allocate_array(0);
    VMObjectShard empty_shard;
    empty_shard.status.owner_id = normalized;
    empty_shard.execution.owner_id = normalized;
    auto empty_store_ready = owner_local_store_ready_for_shard(empty_shard, owner_local_bridge);
    auto empty_store_complete = owner_local_store_complete_for_shard(empty_shard, owner_local_bridge);
    auto *shard_contract = vm_object_shard_contract_mapping(empty_shard, owner_local_bridge);
    auto *map = allocate_mapping(36);
    add_mapping_pair(map, "success", 1);
    add_mapping_string(map, "owner_id", normalized);
    add_mapping_pair(map, "objects", 0);
    add_mapping_map(map, "vm_object_shard", shard_contract);
    add_mapping_pair(map, "shard_contract_version", 1);
    add_mapping_array(map, "object_directory", object_directory);
    add_mapping_pair(map, "object_directory_count", 0);
    add_mapping_pair(map, "owner_local_directory_count", 0);
    add_mapping_pair(map, "owner_local_record_count", 0);
    add_mapping_pair(map, "owner_local_destructed_record_count", 0);
    add_mapping_pair(map, "owner_local_object_ref_count", 0);
    add_mapping_string(map, "owner_local_object_ref_source", "vm_object_shard.local_objects");
    add_mapping_pair(map, "owner_local_object_ref_index_count", 0);
    add_mapping_string(map, "owner_local_object_ref_index_source", "vm_object_shard.local_object_index");
    add_mapping_pair(map, "owner_local_path_index_count", 0);
    add_mapping_pair(map, "owner_local_destructed_path_index_count", 0);
    add_mapping_pair(map, "owner_local_path_index_ready", 1);
    add_mapping_string(map, "owner_local_path_index_source", "vm_object_shard.object_path_index");
    add_mapping_pair(map, "owner_local_live_index_consistent", 1);
    add_mapping_pair(map, "owner_local_object_ref_index_consistent", 1);
    add_mapping_pair(map, "owner_local_live_path_index_consistent", 1);
    add_mapping_pair(map, "owner_local_destructed_path_index_consistent", 1);
    add_mapping_pair(map, "owner_local_canonical_record_ready", 1);
    add_mapping_pair(map, "owner_local_directory_ready", 1);
    add_mapping_pair(map, "owner_local_directory_from_shard", 1);
    add_mapping_string(map, "owner_local_directory_source", "vm_object_shard.object_directory");
    add_mapping_pair(map, "owner_local_store_ready", empty_store_ready ? 1 : 0);
    add_mapping_pair(map, "owner_local_store_complete", empty_store_complete ? 1 : 0);
    add_mapping_string(map, "owner_local_store_complete_blocker",
                       owner_local_store_complete_blocker(empty_store_complete,
                                                          !empty_store_complete,
                                                          !empty_store_complete));
    add_mapping_pair(map, "uses_global_object_table", empty_store_complete ? 0 : 1);
    add_mapping_pair(map, "global_index_bridge", empty_store_complete ? 0 : 1);
    add_mapping_pair(map, "global_live_object_bridge_ready", empty_store_complete ? 0 : 1);
    add_mapping_string(map, "global_live_object_bridge_source",
                       empty_store_complete ? "" : kGlobalLiveObjectBridgeSource);
    add_mapping_pair(map, "global_record_bridge_ready", empty_store_complete ? 0 : 1);
    add_mapping_string(map, "global_record_bridge_source", empty_store_complete ? "" : kGlobalRecordBridgeSource);
    add_owner_local_lifecycle_contract(map, empty_store_complete, true);
    add_mapping_pair(map, "executor_ready", 0);
    free_mapping(shard_contract);
    free_array(object_directory);
    return map;
  }
  auto *map = shard_mapping(it->second, owner_local_bridge);
  add_mapping_pair(map, "success", 1);
  return map;
}

object_t *vm_object_store_owner_resolve(const char *owner_id, uint64_t object_id) {
  ObjectStoreReadLock lock(object_store_directory_mutex);
  return owner_local_resolve_object_fast_path_locked(owner_id, object_id);
}

object_t *vm_object_store_owner_path_resolve(const char *owner_id, const char *object_path) {
  ObjectStoreReadLock lock(object_store_directory_mutex);
  return owner_local_resolve_path_fast_path_locked(owner_id, object_path);
}

mapping_t *vm_object_store_owner_lookup_status(const char *owner_id, uint64_t object_id) {
  ObjectStoreReadLock lock(object_store_directory_mutex);
  auto result = owner_local_lookup_by_object_locked(owner_id, object_id);

  auto *map = allocate_mapping(62);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", result.owner_id.c_str());
  add_mapping_pair(map, "object_id", static_cast<long>(object_id));
  add_mapping_pair(map, "record_found", result.record ? 1 : 0);
  add_mapping_pair(map, "found", result.found ? 1 : 0);
  add_mapping_string(map, "record_owner_id", result.record ? result.record->owner_id.c_str() : "");
  add_mapping_pair(map, "owner_epoch", result.record ? static_cast<long>(result.record->owner_epoch) : 0);
  add_mapping_string(map, "object_path", result.record ? result.record->object_path.c_str() : "");
  add_mapping_pair(map, "destructed", result.record && result.record->destructed ? 1 : 0);
  add_mapping_pair(map, "owner_mismatch", result.record && !result.same_owner ? 1 : 0);
  add_mapping_pair(map, "owner_local_directory_entry", result.found ? 1 : 0);
  add_mapping_pair(map, "owner_local_record_found", result.local_record || result.destructed_record ? 1 : 0);
  add_mapping_pair(map, "owner_local_destructed_record_found", result.destructed_record ? 1 : 0);
  add_mapping_string(map, "owner_local_record_source",
                     result.local_record ? "vm_object_shard.local_records"
                                         : (result.destructed_record ? "vm_object_shard.destructed_records" : ""));
  add_mapping_pair(map, "owner_local_record_destructed", result.destructed_record ? 1 : 0);
  add_mapping_pair(map, "owner_local_cross_shard_record_found", result.cross_owner_record ? 1 : 0);
  add_mapping_string(map, "owner_local_cross_shard_record_source",
                     result.cross_owner_record ? result.cross_owner_record_source.c_str() : "");
  add_mapping_pair(map, "owner_local_global_record_found", result.global_record ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_source",
                     result.global_record ? result.global_record_source.c_str() : "");
  add_mapping_pair(map, "owner_local_global_record_id_scan_bridge_used",
                   result.global_record_id_scan_bridge_used ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_record_id_scan_bridge_found",
                   result.global_record_id_scan_bridge_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_id_scan_bridge_source",
                     result.global_record_id_scan_bridge_used
                         ? result.global_record_id_scan_bridge_source.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_id_scan_bridge_skipped",
                   result.global_record_id_scan_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_id_scan_bridge_skip_reason",
                     result.global_record_id_scan_bridge_skipped
                         ? result.global_record_id_scan_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_pointer_bridge_used",
                   result.global_record_pointer_bridge_used ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_record_pointer_bridge_found",
                   result.global_record_pointer_bridge_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_pointer_bridge_source",
                     result.global_record_pointer_bridge_used
                         ? result.global_record_pointer_bridge_source.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_pointer_bridge_skipped",
                   result.global_record_pointer_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_pointer_bridge_skip_reason",
                     result.global_record_pointer_bridge_skipped
                         ? result.global_record_pointer_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_scan_bridge_used",
                   result.global_record_scan_bridge_used ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_record_scan_bridge_found",
                   result.global_record_scan_bridge_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_scan_bridge_source",
                     result.global_record_scan_bridge_used ? result.global_record_scan_bridge_source.c_str() : "");
  add_mapping_pair(map, "owner_local_global_record_scan_bridge_skipped",
                   result.global_record_scan_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_scan_bridge_skip_reason",
                     result.global_record_scan_bridge_skipped
                         ? result.global_record_scan_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_fallback_skipped",
                   result.global_record_fallback_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_fallback_reason",
                     result.global_record_fallback_skipped ? result.global_record_fallback_reason.c_str() : "");
  add_mapping_pair(map, "global_record_bridge_retirement_ready",
                   result.global_record_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_live_object_found", result.global_live_object_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_live_object_source",
                     result.global_live_object_found ? result.global_live_object_source.c_str() : "");
  add_mapping_pair(map, "global_live_object_bridge_retirement_ready",
                   result.global_live_object_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_live_object_fallback_skipped",
                   result.global_live_object_fallback_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_live_object_fallback_reason",
                     result.global_live_object_fallback_skipped
                         ? result.global_live_object_fallback_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_object_ref_found", result.local_object_ref_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_ref_source",
                     result.local_object_ref_found ? "vm_object_shard.local_objects" : "");
  add_mapping_pair(map, "owner_local_object_ref_index_found", result.local_object_ref_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_ref_index_source",
                     result.local_object_ref_index_found ? "vm_object_shard.local_object_index" : "");
  add_mapping_pair(map, "owner_local_object_pointer_index_found", result.local_object_ref_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_pointer_index_source",
                     result.local_object_ref_index_found ? "vm_object_shard.local_object_index" : "");
  add_mapping_pair(map, "owner_local_resolve_found", result.resolved_object ? 1 : 0);
  add_mapping_string(map, "owner_local_resolve_source",
                     result.resolved_object ? "vm_object_shard.local_objects" : "");
  add_mapping_pair(map, "owner_local_path_index_found", result.live_path_index_found ? 1 : 0);
  add_mapping_pair(map, "owner_local_destructed_path_index_found", result.destructed_path_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_path_index_source",
                     result.live_path_index_found
                         ? "vm_object_shard.object_path_index"
                         : (result.destructed_path_index_found ? "vm_object_shard.destructed_path_index" : ""));
  add_mapping_pair(map, "owner_local_path_index_ready", 1);
  add_mapping_pair(map, "owner_local_directory_ready", 1);
  add_mapping_pair(map, "owner_local_canonical_record_ready",
                   result.owner_local_canonical_record_ready ? 1 : 0);
  auto owner_local_store_ready = result.owner_local_canonical_record_ready &&
                                 result.global_live_object_bridge_retirement_ready;
  auto owner_local_store_complete = owner_local_store_ready &&
                                    result.global_record_bridge_retirement_ready &&
                                    result.global_live_object_bridge_retirement_ready;
  add_mapping_pair(map, "owner_local_store_ready", owner_local_store_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_complete", owner_local_store_complete ? 1 : 0);
  add_mapping_string(map, "owner_local_store_complete_blocker",
                     owner_local_store_complete_blocker(owner_local_store_complete,
                                                        !owner_local_store_complete,
                                                        !owner_local_store_complete));
  add_mapping_pair(map, "uses_global_object_table", owner_local_store_complete ? 0 : 1);
  add_mapping_pair(map, "global_index_bridge", owner_local_store_complete ? 0 : 1);
  return map;
}

mapping_t *vm_object_store_owner_path_lookup_status(const char *owner_id, const char *object_path) {
  ObjectStoreReadLock lock(object_store_directory_mutex);
  auto result = owner_local_lookup_by_path_locked(owner_id, object_path);

  auto *map = allocate_mapping(62);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", result.owner_id.c_str());
  add_mapping_string(map, "object_path", result.query_path.c_str());
  add_mapping_pair(map, "object_id", static_cast<long>(result.object_id));
  add_mapping_pair(map, "record_found", result.record ? 1 : 0);
  add_mapping_pair(map, "found", result.found ? 1 : 0);
  add_mapping_string(map, "record_owner_id", result.record ? result.record->owner_id.c_str() : "");
  add_mapping_pair(map, "owner_epoch", result.record ? static_cast<long>(result.record->owner_epoch) : 0);
  add_mapping_pair(map, "destructed", result.record && result.record->destructed ? 1 : 0);
  add_mapping_pair(map, "owner_mismatch", result.record && !result.same_owner ? 1 : 0);
  add_mapping_pair(map, "owner_local_directory_entry", result.found ? 1 : 0);
  add_mapping_pair(map, "owner_local_record_found", result.local_record || result.destructed_record ? 1 : 0);
  add_mapping_pair(map, "owner_local_destructed_record_found", result.destructed_record ? 1 : 0);
  add_mapping_string(map, "owner_local_record_source",
                     result.local_record ? "vm_object_shard.local_records"
                                         : (result.destructed_record ? "vm_object_shard.destructed_records" : ""));
  add_mapping_pair(map, "owner_local_record_destructed", result.destructed_record ? 1 : 0);
  add_mapping_pair(map, "owner_local_cross_shard_record_found", result.cross_owner_record ? 1 : 0);
  add_mapping_string(map, "owner_local_cross_shard_record_source",
                     result.cross_owner_record ? result.cross_owner_record_source.c_str() : "");
  add_mapping_pair(map, "owner_local_global_record_found", result.global_record ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_source",
                     result.global_record ? result.global_record_source.c_str() : "");
  add_mapping_pair(map, "owner_local_global_record_id_scan_bridge_used",
                   result.global_record_id_scan_bridge_used ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_record_id_scan_bridge_found",
                   result.global_record_id_scan_bridge_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_id_scan_bridge_source",
                     result.global_record_id_scan_bridge_used
                         ? result.global_record_id_scan_bridge_source.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_id_scan_bridge_skipped",
                   result.global_record_id_scan_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_id_scan_bridge_skip_reason",
                     result.global_record_id_scan_bridge_skipped
                         ? result.global_record_id_scan_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_pointer_bridge_used",
                   result.global_record_pointer_bridge_used ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_record_pointer_bridge_found",
                   result.global_record_pointer_bridge_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_pointer_bridge_source",
                     result.global_record_pointer_bridge_used
                         ? result.global_record_pointer_bridge_source.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_pointer_bridge_skipped",
                   result.global_record_pointer_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_pointer_bridge_skip_reason",
                     result.global_record_pointer_bridge_skipped
                         ? result.global_record_pointer_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_scan_bridge_used",
                   result.global_record_scan_bridge_used ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_record_scan_bridge_found",
                   result.global_record_scan_bridge_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_scan_bridge_source",
                     result.global_record_scan_bridge_used ? result.global_record_scan_bridge_source.c_str() : "");
  add_mapping_pair(map, "owner_local_global_record_scan_bridge_skipped",
                   result.global_record_scan_bridge_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_scan_bridge_skip_reason",
                     result.global_record_scan_bridge_skipped
                         ? result.global_record_scan_bridge_skip_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_global_record_fallback_skipped",
                   result.global_record_fallback_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_record_fallback_reason",
                     result.global_record_fallback_skipped ? result.global_record_fallback_reason.c_str() : "");
  add_mapping_pair(map, "global_record_bridge_retirement_ready",
                   result.global_record_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_live_object_found", result.global_live_object_found ? 1 : 0);
  add_mapping_string(map, "owner_local_global_live_object_source",
                     result.global_live_object_found ? result.global_live_object_source.c_str() : "");
  add_mapping_pair(map, "global_live_object_bridge_retirement_ready",
                   result.global_live_object_bridge_retirement_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_global_live_object_fallback_skipped",
                   result.global_live_object_fallback_skipped ? 1 : 0);
  add_mapping_string(map, "owner_local_global_live_object_fallback_reason",
                     result.global_live_object_fallback_skipped
                         ? result.global_live_object_fallback_reason.c_str()
                         : "");
  add_mapping_pair(map, "owner_local_object_ref_found", result.local_object_ref_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_ref_source",
                     result.local_object_ref_found ? "vm_object_shard.local_objects" : "");
  add_mapping_pair(map, "owner_local_object_ref_index_found", result.local_object_ref_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_ref_index_source",
                     result.local_object_ref_index_found ? "vm_object_shard.local_object_index" : "");
  add_mapping_pair(map, "owner_local_object_pointer_index_found", result.local_object_ref_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_object_pointer_index_source",
                     result.local_object_ref_index_found ? "vm_object_shard.local_object_index" : "");
  add_mapping_pair(map, "owner_local_resolve_found", result.resolved_object ? 1 : 0);
  add_mapping_string(map, "owner_local_resolve_source",
                     result.resolved_object ? "vm_object_shard.local_objects" : "");
  add_mapping_pair(map, "owner_local_path_index_found", result.live_path_index_found ? 1 : 0);
  add_mapping_pair(map, "owner_local_destructed_path_index_found", result.destructed_path_index_found ? 1 : 0);
  add_mapping_string(map, "owner_local_path_index_source",
                     result.live_path_index_found
                         ? "vm_object_shard.object_path_index"
                         : (result.destructed_path_index_found ? "vm_object_shard.destructed_path_index" : ""));
  add_mapping_pair(map, "owner_local_path_index_ready", 1);
  add_mapping_pair(map, "owner_local_directory_ready", 1);
  add_mapping_pair(map, "owner_local_canonical_record_ready",
                   result.owner_local_canonical_record_ready ? 1 : 0);
  auto owner_local_store_ready = result.owner_local_canonical_record_ready &&
                                 result.global_live_object_bridge_retirement_ready;
  auto owner_local_store_complete = owner_local_store_ready &&
                                    result.global_record_bridge_retirement_ready &&
                                    result.global_live_object_bridge_retirement_ready;
  add_mapping_pair(map, "owner_local_store_ready", owner_local_store_ready ? 1 : 0);
  add_mapping_pair(map, "owner_local_store_complete", owner_local_store_complete ? 1 : 0);
  add_mapping_string(map, "owner_local_store_complete_blocker",
                     owner_local_store_complete_blocker(owner_local_store_complete,
                                                        !owner_local_store_complete,
                                                        !owner_local_store_complete));
  add_mapping_pair(map, "uses_global_object_table", owner_local_store_complete ? 0 : 1);
  add_mapping_pair(map, "global_index_bridge", owner_local_store_complete ? 0 : 1);
  return map;
}
