#include "base/package_api.h"

#include "vm/owner.h"

#ifdef F_VM_OWNER_ID
void f_vm_owner_id() {
  auto *object = sp->u.ob;
  auto *owner_id = string_copy(vm_owner_id(object), "f_vm_owner_id");
  free_object(&sp->u.ob, "f_vm_owner_id");
  put_malloced_string(owner_id);
}
#endif

#ifdef F_VM_SET_OWNER_ID
void f_vm_set_owner_id() {
  auto *owner_id = sp;
  auto *object = sp - 1;
  vm_owner_set_id(object->u.ob, owner_id->u.string);
  pop_2_elems();
  push_number(1);
}
#endif

#ifdef F_VM_OWNER_CHECK
void f_vm_owner_check() {
  auto *expected_owner_id = sp;
  auto *object = sp - 1;
  auto matched = vm_owner_matches(object->u.ob, expected_owner_id->u.string);
  vm_owner_record_check(object->u.ob, expected_owner_id->u.string, matched);
  pop_2_elems();
  push_number(matched ? 1 : 0);
}
#endif

#ifdef F_VM_OWNER_STATUS
void f_vm_owner_status() {
  auto *status = vm_owner_status(sp->u.ob);
  free_object(&sp->u.ob, "f_vm_owner_status");
  sp->type = T_MAPPING;
  sp->subtype = 0;
  sp->u.map = status;
}
#endif
