#ifndef SRC_VM_OBJECT_HANDLE_H_
#define SRC_VM_OBJECT_HANDLE_H_

#include <cstdint>
#include <string>

struct mapping_t;
struct object_t;

constexpr const char *kVMObjectHandleCapabilityModelV1 = "object_handle_capability_v1";
constexpr const char *kVMObjectHandleDefaultPermissionIntent = "owner_runtime";

struct VMObjectHandle {
  uint64_t object_id{0};
  std::string owner_id;
  uint64_t owner_epoch{0};
  std::string object_path;
  std::string permission_intent{kVMObjectHandleDefaultPermissionIntent};
  uint64_t snapshot_version{0};
  bool valid{false};
};

enum class VMObjectHandleResolveStatus {
  kCurrent,
  kInvalidHandle,
  kMissingPath,
  kObjectNotFound,
  kObjectDestructed,
  kUnregistered,
  kRecordDestructed,
  kObjectIdMismatch,
  kPathMismatch,
  kOwnerMismatch,
  kOwnerEpochMismatch,
  kLiveOwnerMismatch,
  kLiveOwnerEpochMismatch,
};

struct VMObjectHandleResolveResult {
  object_t *object{nullptr};
  VMObjectHandleResolveStatus status{VMObjectHandleResolveStatus::kInvalidHandle};
  bool resolved_via_owner_local_store{false};
  bool owner_local_fast_path_used{false};
  bool diagnosed_via_owner_local_store{false};
  bool diagnosed_via_owner_local_path_index{false};
  bool diagnosed_via_owner_local_cross_shard{false};
  bool owner_local_object_pointer_index_found{false};
  bool global_live_object_found{false};
  std::string global_live_object_source;
  bool global_live_object_bridge_retirement_ready{false};
  bool global_live_object_fallback_skipped{false};
  std::string global_live_object_fallback_reason;
  bool global_record_found{false};
  std::string global_record_source;
  bool global_record_id_scan_bridge_used{false};
  bool global_record_id_scan_bridge_found{false};
  std::string global_record_id_scan_bridge_source;
  bool global_record_id_scan_bridge_skipped{false};
  std::string global_record_id_scan_bridge_skip_reason;
  bool global_record_pointer_bridge_used{false};
  bool global_record_pointer_bridge_found{false};
  std::string global_record_pointer_bridge_source;
  bool global_record_pointer_bridge_skipped{false};
  std::string global_record_pointer_bridge_skip_reason;
  bool global_record_bridge_retirement_ready{false};
  bool global_record_fallback_skipped{false};
  std::string global_record_fallback_reason;
  bool diagnosed_via_global_index{false};
  bool resolved_via_global_index{false};
};

VMObjectHandle vm_object_handle(object_t *object);
VMObjectHandle vm_object_handle_with_intent(object_t *object, const char *permission_intent);
mapping_t *vm_object_handle_status(object_t *object);
mapping_t *vm_object_handle_status_with_intent(object_t *object, const char *permission_intent);
VMObjectHandleResolveResult vm_object_handle_resolve_status(const VMObjectHandle &handle);
const char *vm_object_handle_resolve_status_name(VMObjectHandleResolveStatus status);
object_t *vm_object_handle_resolve(const VMObjectHandle &handle);
bool vm_object_handle_is_current(const VMObjectHandle &handle);
void vm_object_store_register(object_t *object);
void vm_object_store_update_owner(object_t *object);
void vm_object_store_mark_destructed(object_t *object);
void vm_object_store_record_callout(object_t *object, uint64_t callout_id);
void vm_object_store_remove_callout(const char *owner_id, uint64_t callout_id);
void vm_object_store_record_heartbeat(object_t *object);
void vm_object_store_remove_heartbeat(object_t *object);
void vm_object_store_record_message(const char *owner_id, uint64_t task_id);
void vm_object_store_remove_message(const char *owner_id, uint64_t task_id);
mapping_t *vm_object_store_status();
mapping_t *vm_object_store_owner_status(const char *owner_id);
object_t *vm_object_store_owner_resolve(const char *owner_id, uint64_t object_id);
object_t *vm_object_store_owner_path_resolve(const char *owner_id, const char *object_path);
mapping_t *vm_object_store_owner_lookup_status(const char *owner_id, uint64_t object_id);
mapping_t *vm_object_store_owner_path_lookup_status(const char *owner_id, const char *object_path);

#endif /* SRC_VM_OBJECT_HANDLE_H_ */
