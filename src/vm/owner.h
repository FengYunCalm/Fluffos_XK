#ifndef SRC_VM_OWNER_H_
#define SRC_VM_OWNER_H_

#include <cstddef>
#include <cstdint>
#include <functional>

struct mapping_t;
struct VMObjectHandle;
struct object_t;
struct svalue_t;

struct VMOwnerComputeResultField {
  const char *key{nullptr};
  const char *string_value{nullptr};
  int64_t number_value{0};
  bool is_string{false};
};

constexpr int VM_MULTICORE_MODE_OFF = 0;
constexpr int VM_MULTICORE_MODE_AUDIT = 1;
constexpr int VM_MULTICORE_MODE_ENFORCED = 2;

const char *vm_owner_default_id();
int vm_multicore_mode();
const char *vm_multicore_mode_name(int mode);
bool vm_multicore_audit_enabled();
bool vm_multicore_enforced();
const char *vm_owner_id(object_t *object);
bool vm_owner_has_explicit_id(object_t *object);
uint64_t vm_owner_epoch(object_t *object);
void vm_owner_set_id(object_t *object, const char *owner_id);
void vm_owner_assign_default(object_t *object, object_t *context_object, const char *fallback_owner_id);
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
uint64_t vm_owner_enqueue_main_task(object_t *target, const char *task_type, const char *task_key,
                                    std::function<void()> callback,
                                    std::function<void()> drop_callback = nullptr);
bool vm_owner_executor_available();
uint64_t vm_owner_enqueue_executor_task(object_t *target, const char *task_type, const char *task_key,
                                        std::function<void()> callback,
                                        std::function<void()> drop_callback = nullptr);
uint64_t vm_owner_enqueue_main_task_with_payload(object_t *target, const char *task_type,
                                                 const char *task_key, const char *payload_key,
                                                 svalue_t *payload, std::function<void()> callback,
                                                 std::function<void()> drop_callback = nullptr,
                                                 const char *execution_frame_model = nullptr,
                                                 const char *execution_frame_policy = nullptr,
                                                 const char *command_consume_model = nullptr,
                                                 const char *command_consume_blocker = nullptr,
                                                 bool execution_frame_requires_current_interactive = false,
                                                 bool execution_frame_requires_command_giver = false,
                                                 const char *execution_frame_restore_policy = nullptr,
                                                 const char *execution_frame_restore_blocker = nullptr,
                                                 const char *command_text_snapshot = nullptr,
                                                 size_t command_text_snapshot_length = 0);
int vm_owner_drain_main_tasks(int limit);
uint64_t vm_owner_record_access(object_t *source, object_t *target, const char *operation);
uint64_t vm_owner_record_cross_owner_access(object_t *source, object_t *target, const char *operation);
bool vm_owner_cross_owner_access_blocked(object_t *source, object_t *target, const char *operation);
mapping_t *vm_owner_drain_mailbox(const char *owner_id, int limit);
mapping_t *vm_owner_purge_mailbox(const char *owner_id);
mapping_t *vm_owner_mailbox_status(const char *owner_id);
mapping_t *vm_owner_schedule(int limit);
mapping_t *vm_owner_task_trace(int limit);
mapping_t *vm_owner_executor_trace(int limit);
mapping_t *vm_owner_access_trace(int limit);
mapping_t *vm_owner_submit_message(const char *source_owner_id, const char *target_owner_id, const char *message_type,
                                    const char *payload_key);
mapping_t *vm_owner_submit_object_message(const char *source_owner_id, const VMObjectHandle &target_handle,
                                          const char *message_type, const char *payload_key,
                                          svalue_t *payload = nullptr);
uint64_t vm_owner_register_compute_future(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                          const char *payload_key);
uint64_t vm_owner_enqueue_compute_result(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                         const char *state, const char *result_key, const char *error);
uint64_t vm_owner_enqueue_compute_result_fields(const char *owner_id, uint64_t worker_task_id, const char *task_type,
                                                const char *state, const char *result_key, const char *error,
                                                const VMOwnerComputeResultField *fields, size_t field_count);
uint64_t vm_owner_enqueue_command_frame_restore(object_t *target);
mapping_t *vm_owner_message_trace(int limit);
mapping_t *vm_owner_future_poll(uint64_t future_id);
mapping_t *vm_owner_record_commit_boundary(const char *source_owner_id, const char *target_owner_id,
                                             const char *operation, uint64_t message_id, const char *state);
mapping_t *vm_owner_commit_trace(int limit);
mapping_t *vm_owner_lpc_probe(object_t *target, const char *owner_id, const char *method);
mapping_t *vm_owner_lpc_canary(object_t *target, const char *owner_id, const char *method);
mapping_t *vm_owner_lpc_task(object_t *target, const char *owner_id, const char *method);
mapping_t *vm_owner_ordinary_lpc_task(object_t *target, const char *owner_id, const char *method, int explicit_open);
void vm_owner_thread_start(int requested_threads);
void vm_owner_thread_stop();
mapping_t *vm_owner_thread_status();
mapping_t *vm_owner_runtime_status();

// Object snapshot API for safe cross-owner structure inspection.
mapping_t *vm_owner_query_object_snapshot(object_t *target, const char *requesting_owner_id);

#endif /* SRC_VM_OWNER_H_ */
