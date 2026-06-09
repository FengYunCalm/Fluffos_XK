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

#ifdef F_VM_OWNER_EPOCH
void f_vm_owner_epoch() {
  auto epoch = vm_owner_epoch(sp->u.ob);
  free_object(&sp->u.ob, "f_vm_owner_epoch");
  put_number(static_cast<long>(epoch));
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

#ifdef F_VM_OWNER_GUARD
void f_vm_owner_guard() {
  auto *expected_owner_id = sp;
  auto *object = sp - 1;
  auto *result = vm_owner_guard(object->u.ob, expected_owner_id->u.string);
  pop_2_elems();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_GUARD_EPOCH
void f_vm_owner_guard_epoch() {
  auto expected_epoch = sp->u.number;
  auto *expected_owner_id = sp - 1;
  auto *object = sp - 2;
  auto *result = vm_owner_guard_epoch(object->u.ob, expected_owner_id->u.string, static_cast<uint64_t>(expected_epoch));
  pop_n_elems(3);
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_ENQUEUE
void f_vm_owner_enqueue() {
  auto *task_key = sp;
  auto *task_type = sp - 1;
  auto *owner_id = sp - 2;
  auto task_id = vm_owner_enqueue_task(owner_id->u.string, task_type->u.string, task_key->u.string);
  pop_n_elems(3);
  push_number(static_cast<long>(task_id));
}
#endif

#ifdef F_VM_OWNER_ENQUEUE_EPOCH
void f_vm_owner_enqueue_epoch() {
  auto owner_epoch = sp->u.number;
  auto *task_key = sp - 1;
  auto *task_type = sp - 2;
  auto *owner_id = sp - 3;
  auto task_id = vm_owner_enqueue_task_epoch(owner_id->u.string, task_type->u.string, task_key->u.string,
                                            static_cast<uint64_t>(owner_epoch));
  pop_n_elems(4);
  push_number(static_cast<long>(task_id));
}
#endif

#ifdef F_VM_OWNER_RECORD
void f_vm_owner_record() {
  auto *state = sp;
  auto owner_epoch = (sp - 1)->u.number;
  auto *task_key = sp - 2;
  auto *task_type = sp - 3;
  auto *owner_id = sp - 4;
  auto trace_id = vm_owner_record_task_trace(owner_id->u.string, task_type->u.string, task_key->u.string,
                                            static_cast<uint64_t>(owner_epoch), state->u.string);
  pop_n_elems(5);
  push_number(static_cast<long>(trace_id));
}
#endif

#ifdef F_VM_OWNER_RECORD_ACCESS
void f_vm_owner_record_access() {
  auto *operation = sp;
  auto *target = sp - 1;
  auto *source = sp - 2;
  auto access_id = vm_owner_record_access(source->u.ob, target->u.ob, operation->u.string);
  pop_n_elems(3);
  push_number(static_cast<long>(access_id));
}
#endif

#ifdef F_VM_OWNER_DRAIN
void f_vm_owner_drain() {
  auto limit = sp->u.number;
  auto *owner_id = sp - 1;
  auto *result = vm_owner_drain_mailbox(owner_id->u.string, static_cast<int>(limit));
  pop_2_elems();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_TRACE
void f_vm_owner_trace() {
  auto *result = vm_owner_task_trace(static_cast<int>(sp->u.number));
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_ACCESS_TRACE
void f_vm_owner_access_trace() {
  auto *result = vm_owner_access_trace(static_cast<int>(sp->u.number));
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_PURGE
void f_vm_owner_purge() {
  auto *result = vm_owner_purge_mailbox(sp->u.string);
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_MAILBOX_STATUS
void f_vm_owner_mailbox_status() {
  auto *result = vm_owner_mailbox_status(sp->u.string);
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_SCHEDULE
void f_vm_owner_schedule() {
  auto *result = vm_owner_schedule(static_cast<int>(sp->u.number));
  pop_stack();
  push_refed_mapping(result);
}
#endif
