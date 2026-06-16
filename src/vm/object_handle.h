#ifndef SRC_VM_OBJECT_HANDLE_H_
#define SRC_VM_OBJECT_HANDLE_H_

#include <cstdint>
#include <string>

struct mapping_t;
struct object_t;

struct VMObjectHandle {
  uint64_t object_id{0};
  std::string owner_id;
  uint64_t owner_epoch{0};
  std::string object_path;
  bool valid{false};
};

VMObjectHandle vm_object_handle(object_t *object);
mapping_t *vm_object_handle_status(object_t *object);
object_t *vm_object_handle_resolve(const VMObjectHandle &handle);
bool vm_object_handle_is_current(const VMObjectHandle &handle);
void vm_object_store_register(object_t *object);
void vm_object_store_update_owner(object_t *object);
void vm_object_store_mark_destructed(object_t *object);
void vm_object_store_record_callout(object_t *object, uint64_t callout_id);
void vm_object_store_remove_callout(const char *owner_id, uint64_t callout_id);
void vm_object_store_record_heartbeat(object_t *object);
void vm_object_store_remove_heartbeat(object_t *object);
void vm_object_store_record_message(const char *owner_id);
mapping_t *vm_object_store_status();
mapping_t *vm_object_store_owner_status(const char *owner_id);

#endif /* SRC_VM_OBJECT_HANDLE_H_ */
