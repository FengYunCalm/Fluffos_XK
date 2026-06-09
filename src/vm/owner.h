#ifndef SRC_VM_OWNER_H_
#define SRC_VM_OWNER_H_

#include <cstdint>

struct mapping_t;
struct object_t;

const char *vm_owner_default_id();
const char *vm_owner_id(object_t *object);
uint64_t vm_owner_epoch(object_t *object);
void vm_owner_set_id(object_t *object, const char *owner_id);
void vm_owner_clear_id(object_t *object);
bool vm_owner_matches(object_t *object, const char *expected_owner_id);
bool vm_owner_epoch_matches(object_t *object, const char *expected_owner_id, uint64_t expected_epoch);
void vm_owner_record_check(object_t *object, const char *expected_owner_id, bool matched);
uint64_t vm_owner_total_checks();
uint64_t vm_owner_mismatch_checks();
mapping_t *vm_owner_status(object_t *object);
mapping_t *vm_owner_guard(object_t *object, const char *expected_owner_id);
mapping_t *vm_owner_guard_epoch(object_t *object, const char *expected_owner_id, uint64_t expected_epoch);
uint64_t vm_owner_enqueue_task(const char *owner_id, const char *task_type, const char *task_key);
uint64_t vm_owner_enqueue_task_epoch(const char *owner_id, const char *task_type, const char *task_key,
                                     uint64_t owner_epoch);
uint64_t vm_owner_record_task_trace(const char *owner_id, const char *task_type, const char *task_key,
                                    uint64_t owner_epoch, const char *state);
mapping_t *vm_owner_drain_mailbox(const char *owner_id, int limit);
mapping_t *vm_owner_purge_mailbox(const char *owner_id);
mapping_t *vm_owner_mailbox_status(const char *owner_id);
mapping_t *vm_owner_schedule(int limit);
mapping_t *vm_owner_task_trace(int limit);

#endif /* SRC_VM_OWNER_H_ */
