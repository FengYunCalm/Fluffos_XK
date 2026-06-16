#include "base/package_api.h"

#include "vm/context.h"
#include "vm/object_handle.h"
#include "vm/owner.h"

#include <string>

namespace {
bool owner_payload_safe(svalue_t *value, int depth, std::string *error) {
  if (depth > 8) {
    *error = "owner payload nesting is too deep";
    return false;
  }
  switch (value->type) {
    case T_NUMBER:
    case T_REAL:
    case T_STRING:
      return true;
    case T_ARRAY:
      for (int i = 0; i < value->u.arr->size; i++) {
        if (!owner_payload_safe(&value->u.arr->item[i], depth + 1, error)) {
          return false;
        }
      }
      return true;
    case T_MAPPING:
      for (unsigned int i = 0; i <= value->u.map->table_size; i++) {
        for (auto *node = value->u.map->table[i]; node; node = node->next) {
          if (node->values[0].type != T_STRING) {
            *error = "owner payload mapping keys must be strings";
            return false;
          }
          if (!owner_payload_safe(&node->values[1], depth + 1, error)) {
            return false;
          }
        }
      }
      return true;
    default:
      *error = "owner payload must be frozen data, not object/function/buffer/class";
      return false;
  }
}

bool owner_payload_mapping_safe(svalue_t *value, std::string *error) {
  if (value->type != T_MAPPING) {
    *error = "owner payload top-level value must be a mapping";
    return false;
  }
  return owner_payload_safe(value, 0, error);
}

std::string owner_mapping_string(mapping_t *map, const char *key, const char *fallback) {
  auto *value = find_string_in_mapping(map, key);
  if (value && value->type == T_STRING && value->u.string) {
    return value->u.string;
  }
  return fallback ? fallback : "";
}

const char *current_owner_id_for_message() {
  if (current_object) {
    return vm_owner_id(current_object);
  }
  if (!vm_context().owner.current_owner_id.empty()) {
    return vm_context().owner.current_owner_id.c_str();
  }
  return vm_owner_default_id();
}

mapping_t *owner_payload_error(const std::string &error_text) {
  auto *map = allocate_mapping(3);
  add_mapping_pair(map, "success", 0);
  add_mapping_string(map, "error", error_text.c_str());
  add_mapping_pair(map, "frozen_payload", 0);
  return map;
}
}  // namespace

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

#ifdef F_VM_OWNER_MESSAGE_SUBMIT
void f_vm_owner_message_submit() {
  auto *payload_key = sp;
  auto *message_type = sp - 1;
  auto *target_owner_id = sp - 2;
  auto *source_owner_id = sp - 3;
  auto *result = vm_owner_submit_message(source_owner_id->u.string, target_owner_id->u.string,
                                        message_type->u.string, payload_key->u.string);
  pop_n_elems(4);
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_MESSAGE_TRACE
void f_vm_owner_message_trace() {
  auto *result = vm_owner_message_trace(static_cast<int>(sp->u.number));
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_COMMIT_RECORD
void f_vm_owner_commit_record() {
  auto *state = sp;
  auto message_id = (sp - 1)->u.number;
  auto *operation = sp - 2;
  auto *target_owner_id = sp - 3;
  auto *source_owner_id = sp - 4;
  auto *result = vm_owner_record_commit_boundary(source_owner_id->u.string, target_owner_id->u.string,
                                                operation->u.string, static_cast<uint64_t>(message_id),
                                                state->u.string);
  pop_n_elems(5);
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_COMMIT_TRACE
void f_vm_owner_commit_trace() {
  auto *result = vm_owner_commit_trace(static_cast<int>(sp->u.number));
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_LPC_PROBE
void f_vm_owner_lpc_probe() {
  auto *method = sp;
  auto *owner_id = sp - 1;
  auto *target = sp - 2;
  auto *result = vm_owner_lpc_probe(target->u.ob, owner_id->u.string, method->u.string);
  pop_n_elems(3);
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_LPC_CANARY
void f_vm_owner_lpc_canary() {
  auto *method = sp;
  auto *owner_id = sp - 1;
  auto *target = sp - 2;
  auto *result = vm_owner_lpc_canary(target->u.ob, owner_id->u.string, method->u.string);
  pop_n_elems(3);
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_LPC_TASK
void f_vm_owner_lpc_task() {
  auto *method = sp;
  auto *owner_id = sp - 1;
  auto *target = sp - 2;
  auto *result = vm_owner_lpc_task(target->u.ob, owner_id->u.string, method->u.string);
  pop_n_elems(3);
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_CONTEXT_IS_MAIN_THREAD
void f_vm_context_is_main_thread() { push_number(vm_context_is_main_thread() ? 1 : 0); }
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

#ifdef F_VM_OWNER_THREAD_START
void f_vm_owner_thread_start() {
  vm_owner_thread_start(static_cast<int>(sp->u.number));
  pop_stack();
  push_number(1);
}
#endif

#ifdef F_VM_OWNER_THREAD_STOP
void f_vm_owner_thread_stop() {
  vm_owner_thread_stop();
  push_number(1);
}
#endif

#ifdef F_VM_OWNER_THREAD_STATUS
void f_vm_owner_thread_status() {
  auto *result = vm_owner_thread_status();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OWNER_RUNTIME_STATUS
void f_vm_owner_runtime_status() {
  auto *result = vm_owner_runtime_status();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OBJECT_HANDLE
void f_vm_object_handle() {
  auto *result = vm_object_handle_status(sp->u.ob);
  free_object(&sp->u.ob, "f_vm_object_handle");
  sp->type = T_MAPPING;
  sp->subtype = 0;
  sp->u.map = result;
}
#endif

#ifdef F_VM_OBJECT_STORE_STATUS
void f_vm_object_store_status() {
  auto *result = vm_object_store_status();
  push_refed_mapping(result);
}
#endif

#ifdef F_VM_OBJECT_STORE_OWNER_STATUS
void f_vm_object_store_owner_status() {
  auto *result = vm_object_store_owner_status(sp->u.string);
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_OWNER_SEND
void f_owner_send() {
  auto *payload = sp;
  auto *target_owner = sp - 1;
  std::string error_text;
  if (!owner_payload_mapping_safe(payload, &error_text)) {
    pop_2_elems();
    push_refed_mapping(owner_payload_error(error_text));
    return;
  }
  auto message_type = owner_mapping_string(payload->u.map, "type", "message");
  auto payload_key = owner_mapping_string(payload->u.map, "payload_key", message_type.c_str());
  auto *result = vm_owner_submit_message(current_owner_id_for_message(), target_owner->u.string,
                                         message_type.c_str(), payload_key.c_str());
  add_mapping_pair(result, "frozen_payload", 1);
  pop_2_elems();
  push_refed_mapping(result);
}
#endif

#ifdef F_OWNER_CALL_ASYNC
void f_owner_call_async() {
  auto *payload = sp;
  auto *method = sp - 1;
  auto *target = sp - 2;
  std::string error_text;
  if (!owner_payload_mapping_safe(payload, &error_text)) {
    pop_n_elems(3);
    push_refed_mapping(owner_payload_error(error_text));
    return;
  }
  auto payload_key = owner_mapping_string(payload->u.map, "payload_key", method->u.string);
  auto *result = vm_owner_submit_message(current_owner_id_for_message(), vm_owner_id(target->u.ob),
                                          method->u.string, payload_key.c_str());
  auto handle = vm_object_handle(target->u.ob);
  add_mapping_pair(result, "frozen_payload", 1);
  add_mapping_pair(result, "async_only", 1);
  add_mapping_pair(result, "target_object_id", static_cast<long>(handle.object_id));
  add_mapping_string(result, "target_object_path", handle.object_path.c_str());
  add_mapping_pair(result, "target_owner_epoch", static_cast<long>(handle.owner_epoch));
  add_mapping_pair(result, "target_handle_valid", handle.valid ? 1 : 0);
  pop_n_elems(3);
  push_refed_mapping(result);
}
#endif

#ifdef F_OWNER_FUTURE_POLL
void f_owner_future_poll() {
  auto future_id = sp->u.number;
  pop_stack();
  push_refed_mapping(vm_owner_future_poll(static_cast<uint64_t>(future_id)));
}
#endif

#ifdef F_OWNER_SNAPSHOT
void f_owner_snapshot() {
  auto *result = vm_object_handle_status(sp->u.ob);
  add_mapping_pair(result, "snapshot_only", 1);
  free_object(&sp->u.ob, "f_owner_snapshot");
  sp->type = T_MAPPING;
  sp->subtype = 0;
  sp->u.map = result;
}
#endif

#ifdef F_OWNER_PUBLISH_SNAPSHOT
void f_owner_publish_snapshot() {
  std::string error_text;
  if (!owner_payload_mapping_safe(sp, &error_text)) {
    pop_stack();
    push_refed_mapping(owner_payload_error(error_text));
    return;
  }
  auto owner_id = current_owner_id_for_message();
  auto *map = allocate_mapping(7);
  add_mapping_pair(map, "success", 1);
  add_mapping_string(map, "owner_id", owner_id);
  add_mapping_pair(map, "owner_epoch", current_object ? static_cast<long>(vm_owner_epoch(current_object)) : 0);
  add_mapping_pair(map, "frozen_payload", 1);
  add_mapping_pair(map, "snapshot_only", 1);
  add_mapping_pair(map, "direct_cross_owner_write", 0);
  add_mapping_string(map, "state", "snapshot_published");
  pop_stack();
  push_refed_mapping(map);
}
#endif
