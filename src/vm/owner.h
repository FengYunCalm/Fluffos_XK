#ifndef SRC_VM_OWNER_H_
#define SRC_VM_OWNER_H_

#include <cstdint>

struct mapping_t;
struct object_t;

const char *vm_owner_default_id();
const char *vm_owner_id(object_t *object);
void vm_owner_set_id(object_t *object, const char *owner_id);
void vm_owner_clear_id(object_t *object);
bool vm_owner_matches(object_t *object, const char *expected_owner_id);
void vm_owner_record_check(object_t *object, const char *expected_owner_id, bool matched);
uint64_t vm_owner_total_checks();
uint64_t vm_owner_mismatch_checks();
mapping_t *vm_owner_status(object_t *object);

#endif /* SRC_VM_OWNER_H_ */
