#include "base/package_api.h"

#include "vm/context.h"
#include "vm/frozen_value.h"
#include "vm/internal/base/object.h"
#include "vm/object_handle.h"
#include "vm/owner.h"

#include <cstring>
#include <string>
#include <vector>

namespace {
bool owner_payload_mapping_safe(svalue_t *value, std::string *error) {
  if (value->type != T_MAPPING) {
    *error = "owner payload top-level value must be a mapping";
    return false;
  }
  return vm_frozen_value_safe(value, 0, "owner payload", error);
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

void owner_api_mark_success(mapping_t *map, const char *api_name) {
  add_mapping_pair(map, "ok", 1);
  add_mapping_string(map, "reason", "");
  add_mapping_string(map, "failure_schema", "owner_safe_lpc_api_failure_v1");
  add_mapping_pair(map, "modern_lpc_api", 1);
  if (api_name && api_name[0]) {
    add_mapping_string(map, "api", api_name);
  }
}

void owner_api_mark_failure(mapping_t *map, const char *code, const char *reason) {
  add_mapping_pair(map, "ok", 0);
  add_mapping_string(map, "code", code);
  add_mapping_string(map, "error", reason);
  add_mapping_string(map, "reason", reason);
  add_mapping_string(map, "failure_schema", "owner_safe_lpc_api_failure_v1");
  add_mapping_pair(map, "modern_lpc_api", 1);
}

mapping_t *owner_payload_error(const std::string &error_text) {
  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", 0);
  owner_api_mark_failure(map, "invalid_frozen_payload", error_text.c_str());
  add_mapping_pair(map, "frozen_payload", 0);
  return map;
}

mapping_t *owner_api_error(const char *code, const char *error_text) {
  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "success", 0);
  owner_api_mark_failure(map, code, error_text);
  add_mapping_pair(map, "frozen_payload", 0);
  return map;
}

long owner_mapping_number(mapping_t *map, const char *key, long fallback) {
  auto *value = find_string_in_mapping(map, key);
  if (value && value->type == T_NUMBER) {
    return value->u.number;
  }
  return fallback;
}

bool add_mapping_frozen_value(mapping_t *map, const char *key, svalue_t *value) {
  svalue_t key_value{T_STRING, STRING_SHARED, {0}};
  key_value.u.string = make_shared_string(key);
  auto *slot = find_for_insert(map, &key_value, 1);
  free_svalue(&key_value, "add_mapping_frozen_value key");
  return vm_copy_frozen_svalue(slot, value);
}

mapping_t *owner_frozen_value_result(svalue_t *value, const char *api_name) {
  std::string error_text;
  if (!vm_frozen_value_safe(value, 0, api_name, &error_text)) {
    return owner_payload_error(error_text);
  }

  auto *map = allocate_mapping(12);
  add_mapping_pair(map, "success", 1);
  owner_api_mark_success(map, api_name);
  add_mapping_pair(map, "frozen_payload", 1);
  add_mapping_pair(map, "deep_copy", 1);
  add_mapping_pair(map, "snapshot_only", 1);
  add_mapping_pair(map, "immutable_runtime_type", 0);
  add_mapping_string(map, "immutability_model", "validated_deep_copy");
  add_mapping_pair(map, "value_object_profile_ready", 1);
  add_mapping_string(map, "value_object_model", "frozen_snapshot_value_object_v1");
  add_mapping_pair(map, "live_object_lifecycle_member", 0);
  add_mapping_pair(map, "traditional_destruct_chain_member", 0);
  add_mapping_pair(map, "cross_owner_payload_safe", 1);
  add_mapping_string(map, "canonical_payload_encoding", "utf-8");
  if (!add_mapping_frozen_value(map, "value", value)) {
    free_mapping(map);
    return owner_api_error("frozen_copy_failed", "failed to deep-copy frozen-safe value");
  }
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

#ifdef F_VM_OWNER_EXECUTOR_TRACE
void f_vm_owner_executor_trace() {
  auto *result = vm_owner_executor_trace(static_cast<int>(sp->u.number));
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

#ifdef F_VM_OWNER_ORDINARY_LPC_TASK
void f_vm_owner_ordinary_lpc_task() {
  auto *explicit_open = sp;
  auto *method = sp - 1;
  auto *owner_id = sp - 2;
  auto *target = sp - 3;
  auto *result = vm_owner_ordinary_lpc_task(target->u.ob, owner_id->u.string, method->u.string,
                                           explicit_open->u.number != 0);
  pop_n_elems(4);
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

#ifdef F_VM_OWNER_DRAIN_MAIN
void f_vm_owner_drain_main() {
  auto drained = vm_owner_drain_main_tasks(static_cast<int>(sp->u.number));
  pop_stack();
  push_number(drained);
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
  auto *result = vm_object_handle_status_with_intent(sp->u.ob, kVMObjectHandleDefaultPermissionIntent);
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
  auto handle = vm_object_handle_with_intent(target->u.ob, "owner_call_async_message");
  auto *result = vm_owner_submit_object_message(current_owner_id_for_message(), handle, method->u.string,
                                                payload_key.c_str(), payload);
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
  auto *result = vm_object_handle_status_with_intent(sp->u.ob, "owner_snapshot_payload");
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

#ifdef F_OWNER_QUERY_OBJECT_SNAPSHOT
void f_owner_query_object_snapshot() {
  object_t *target = sp->u.ob;
  if (!target) {
    free_object(&sp->u.ob, "f_owner_query_object_snapshot");
    *sp = const0u;
    return;
  }

  const char *requesting_owner_id = current_owner_id_for_message();
  auto *snapshot = vm_owner_query_object_snapshot(target, requesting_owner_id);

  free_object(&sp->u.ob, "f_owner_query_object_snapshot");

  if (!snapshot) {
    // Same owner or default owner - direct access is safe
    *sp = const0u;
    return;
  }

  sp->type = T_MAPPING;
  sp->subtype = 0;
  sp->u.map = snapshot;
}
#endif

#ifdef F_OWNER_ASYNC
void f_owner_async() {
  auto *payload = sp;
  auto *target = sp - 1;
  std::string error_text;
  if (!owner_payload_mapping_safe(payload, &error_text)) {
    pop_2_elems();
    push_refed_mapping(owner_payload_error(error_text));
    return;
  }

  mapping_t *result = nullptr;
  if (target->type == T_OBJECT) {
    auto method = owner_mapping_string(payload->u.map, "method", nullptr);
    if (method.empty()) {
      pop_2_elems();
      push_refed_mapping(owner_api_error("missing_method", "owner_async object target requires payload[\"method\"]"));
      return;
    }
    auto payload_key = owner_mapping_string(payload->u.map, "payload_key", method.c_str());
    auto handle = vm_object_handle_with_intent(target->u.ob, "owner_async_message");
    result = vm_owner_submit_object_message(current_owner_id_for_message(), handle, method.c_str(),
                                            payload_key.c_str(), payload);
    add_mapping_pair(result, "target_object_id", static_cast<long>(handle.object_id));
    add_mapping_string(result, "target_object_path", handle.object_path.c_str());
    add_mapping_pair(result, "target_owner_epoch", static_cast<long>(handle.owner_epoch));
    add_mapping_pair(result, "target_handle_valid", handle.valid ? 1 : 0);
  } else if (target->type == T_STRING) {
    auto message_type = owner_mapping_string(payload->u.map, "type", "owner_async");
    auto payload_key = owner_mapping_string(payload->u.map, "payload_key", message_type.c_str());
    result = vm_owner_submit_message(current_owner_id_for_message(), target->u.string,
                                     message_type.c_str(), payload_key.c_str());
  } else {
    pop_2_elems();
    push_refed_mapping(owner_api_error("unsupported_target",
                                       "owner_async target must be an object or owner id string"));
    return;
  }

  owner_api_mark_success(result, "owner_async");
  add_mapping_pair(result, "frozen_payload", 1);
  pop_2_elems();
  push_refed_mapping(result);
}
#endif

#ifdef F_OWNER_AWAIT
void f_owner_await() {
  auto future_id = static_cast<uint64_t>(sp->u.number);
  auto *result = vm_owner_future_poll(future_id);
  owner_api_mark_success(result, "owner_await");
  add_mapping_string(result, "await_model", "poll_adapter_until_coroutine_runtime");
  add_mapping_pair(result, "coroutine_runtime_ready", 0);
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_FREEZE
void f_freeze() {
  auto *result = owner_frozen_value_result(sp, "freeze");
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_SNAPSHOT
void f_snapshot() {
  if (sp->type == T_OBJECT) {
    auto *result = vm_object_handle_status_with_intent(sp->u.ob, "snapshot_payload");
    owner_api_mark_success(result, "snapshot");
    add_mapping_pair(result, "snapshot_only", 1);
    add_mapping_pair(result, "frozen_payload", 1);
    add_mapping_pair(result, "immutable_runtime_type", 0);
    add_mapping_string(result, "immutability_model", "object_handle_snapshot");
    free_object(&sp->u.ob, "f_snapshot");
    sp->type = T_MAPPING;
    sp->subtype = 0;
    sp->u.map = result;
    return;
  }

  auto *result = owner_frozen_value_result(sp, "snapshot");
  pop_stack();
  push_refed_mapping(result);
}
#endif

#ifdef F_OWNER_SNAPSHOT_PERSIST
void f_owner_snapshot_persist() {
  auto *options = sp;
  auto *target = sp - 1;
  std::string error_text;
  if (!owner_payload_mapping_safe(options, &error_text)) {
    pop_n_elems(2);
    push_refed_mapping(owner_payload_error(error_text));
    return;
  }

  auto handle = vm_object_handle_with_intent(target->u.ob, "snapshot_persistence");
  auto source_owner = current_owner_id_for_message();
  auto target_owner = handle.owner_id;
  auto target_status = vm_object_handle_resolve_status(handle);
  if (target_status.status != VMObjectHandleResolveStatus::kCurrent || !target_status.object) {
    auto *error = owner_api_error("stale_snapshot_target", "owner_snapshot_persist target handle is not current");
    add_mapping_string(error, "target_handle_status",
                       vm_object_handle_resolve_status_name(target_status.status));
    pop_n_elems(2);
    push_refed_mapping(error);
    return;
  }
  if (target_owner != source_owner) {
    auto *error = owner_api_error("cross_owner_snapshot_persist_rejected",
                                  "owner_snapshot_persist requires a same-owner target");
    add_mapping_string(error, "source_owner", source_owner);
    add_mapping_string(error, "target_owner", target_owner.c_str());
    add_mapping_string(error, "target_handle_status",
                       vm_object_handle_resolve_status_name(target_status.status));
    pop_n_elems(2);
    push_refed_mapping(error);
    return;
  }

  const auto max_string_length = CONFIG_INT(__MAX_STRING_LENGTH__);
  auto save_zeros = static_cast<int>(owner_mapping_number(options->u.map, "save_zeros", 0));
  std::vector<char> serialized(static_cast<size_t>(max_string_length) + 1, '\0');
  auto success = save_object_str(target_status.object, save_zeros, serialized.data(), max_string_length);
  if (!success) {
    auto *error = owner_api_error("snapshot_serialize_failed",
                                  "owner_snapshot_persist failed to serialize target object");
    add_mapping_string(error, "target_handle_status",
                       vm_object_handle_resolve_status_name(target_status.status));
    pop_n_elems(2);
    push_refed_mapping(error);
    return;
  }

  auto *result = allocate_mapping(25);
  add_mapping_pair(result, "success", 1);
  owner_api_mark_success(result, "owner_snapshot_persist");
  add_mapping_pair(result, "owner_snapshot_persistence_ready", 1);
  add_mapping_string(result, "snapshot_persistence_model", "owner_snapshot_serialized_payload_v1");
  add_mapping_string(result, "file_adapter_boundary", "main_thread_file_adapter");
  add_mapping_pair(result, "direct_save_hot_path", 0);
  add_mapping_pair(result, "frozen_options", 1);
  add_mapping_pair(result, "snapshot_only", 1);
  add_mapping_pair(result, "object_handle_capability_ready", 1);
  add_mapping_string(result, "capability_model", kVMObjectHandleCapabilityModelV1);
  add_mapping_string(result, "permission_intent", handle.permission_intent.c_str());
  add_mapping_pair(result, "target_object_id", static_cast<long>(handle.object_id));
  add_mapping_string(result, "target_object_path", handle.object_path.c_str());
  add_mapping_string(result, "owner_id", target_owner.c_str());
  add_mapping_pair(result, "owner_epoch", static_cast<long>(handle.owner_epoch));
  add_mapping_pair(result, "snapshot_version", static_cast<long>(handle.snapshot_version));
  add_mapping_pair(result, "save_zeros", save_zeros);
  add_mapping_pair(result, "serialized_bytes", static_cast<long>(strlen(serialized.data())));
  add_mapping_string(result, "serialized", serialized.data());
  add_mapping_string(result, "target_handle_status", vm_object_handle_resolve_status_name(target_status.status));
  add_mapping_pair(result, "current", 1);
  pop_n_elems(2);
  push_refed_mapping(result);
}
#endif

#ifdef F_OWNER_COMMIT
void f_owner_commit() {
  std::string error_text;
  if (!owner_payload_mapping_safe(sp, &error_text)) {
    pop_stack();
    push_refed_mapping(owner_payload_error(error_text));
    return;
  }

  auto source_owner = owner_mapping_string(sp->u.map, "source_owner", current_owner_id_for_message());
  auto target_owner = owner_mapping_string(sp->u.map, "target_owner", current_owner_id_for_message());
  auto operation = owner_mapping_string(sp->u.map, "operation", "owner_commit");
  auto state = owner_mapping_string(sp->u.map, "state", "prepared");
  auto message_id = static_cast<uint64_t>(owner_mapping_number(sp->u.map, "message_id", 0));
  auto *result = vm_owner_record_commit_boundary(source_owner.c_str(), target_owner.c_str(),
                                                operation.c_str(), message_id, state.c_str());
  owner_api_mark_success(result, "owner_commit");
  add_mapping_pair(result, "frozen_payload", 1);
  add_mapping_pair(result, "commit_proposal", 1);
  add_mapping_string(result, "commit_model", "owner_commit_boundary_record");
  pop_stack();
  push_refed_mapping(result);
}
#endif
