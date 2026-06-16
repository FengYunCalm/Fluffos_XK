#ifndef SRC_VM_CONTEXT_H_
#define SRC_VM_CONTEXT_H_

#include <cstdint>
#include <ctime>
#include <string>

struct event_base;
struct error_context_t;
struct object_t;
struct program_t;

struct VMExecutionState {
  object_t *current_object{nullptr};
  object_t *command_giver{nullptr};
  object_t *current_interactive{nullptr};
  object_t *previous_ob{nullptr};
  program_t *current_prog{nullptr};
  int caller_type{0};
  int call_origin{0};
  int function_index_offset{0};
  int variable_index_offset{0};
};

struct VMObjectStoreState {
  object_t *objects{nullptr};
  object_t *destructed_objects{nullptr};
  object_t *debug_dangling_objects{nullptr};
  bool main_thread_owned{false};
  uint64_t sync_rejections{0};
};

struct VMOwnerState {
  std::string current_owner_id;
  uint64_t current_owner_epoch{0};
  bool lpc_canary_active{false};
};

struct VMErrorState {
  error_context_t *current_error_context{nullptr};
  int too_deep_error{0};
  int max_eval_error{0};
};

struct VMContext {
  time_t boot_time{0};
  event_base *event_loop{nullptr};
  uint64_t current_gametick{0};
  VMOwnerState owner;
  VMExecutionState execution;
  VMErrorState error;
  VMObjectStoreState object_store;
};

VMContext &vm_context();
VMContext &vm_main_context();
VMContext *vm_context_bind_thread(VMContext *context);
bool vm_context_is_main_thread();

void vm_context_set_boot_time(VMContext &context, time_t boot_time);
void vm_context_set_event_base(VMContext &context, event_base *base);
void vm_context_set_current_gametick(VMContext &context, uint64_t gametick);
void vm_context_set_current_owner(VMContext &context, const char *owner_id, uint64_t owner_epoch);
void vm_context_set_current_object(VMContext &context, object_t *object);
void vm_context_set_command_giver(VMContext &context, object_t *giver);
void vm_context_set_current_interactive(VMContext &context, object_t *interactive);
void vm_context_set_previous_object(VMContext &context, object_t *object);
void vm_context_set_current_program(VMContext &context, program_t *program);
void vm_context_set_caller_type(VMContext &context, int type);
void vm_context_set_call_origin(VMContext &context, int origin);
void vm_context_set_inherit_offsets(VMContext &context, int function_offset, int variable_offset);
void vm_context_set_execution_frame(VMContext &context, object_t *object, program_t *program,
                                    object_t *previous, int type);
void vm_context_set_current_error_context(VMContext &context, error_context_t *error_context);
void vm_context_set_too_deep_error(VMContext &context, int value);
void vm_context_set_max_eval_error(VMContext &context, int value);
void vm_context_set_error_flags(VMContext &context, int too_deep, int max_eval);
void vm_context_reset_execution(VMContext &context);
VMExecutionState vm_context_capture_execution();
void vm_context_apply_execution(VMContext &context, const VMExecutionState &execution);
void vm_context_sync_execution(VMContext &context);
void vm_context_sync_object_store(VMContext &context);
uint64_t vm_context_object_store_sync_rejections();

class VMExecutionScope {
 public:
  VMExecutionScope(VMContext &context, const VMExecutionState &execution);
  ~VMExecutionScope();

  VMExecutionScope(const VMExecutionScope &) = delete;
  VMExecutionScope &operator=(const VMExecutionScope &) = delete;

 private:
  VMContext &context_;
  VMExecutionState saved_;
};

class VMContextThreadScope {
 public:
  explicit VMContextThreadScope(VMContext &context);
  ~VMContextThreadScope();

  VMContextThreadScope(const VMContextThreadScope &) = delete;
  VMContextThreadScope &operator=(const VMContextThreadScope &) = delete;

 private:
  VMContext *saved_;
};

class VMCurrentInteractiveScope {
 public:
  VMCurrentInteractiveScope(VMContext &context, object_t *interactive);
  ~VMCurrentInteractiveScope();

  VMCurrentInteractiveScope(const VMCurrentInteractiveScope &) = delete;
  VMCurrentInteractiveScope &operator=(const VMCurrentInteractiveScope &) = delete;

 private:
  VMContext &context_;
  object_t *saved_;
};

class VMOwnerScope {
 public:
  VMOwnerScope(VMContext &context, const char *owner_id, uint64_t owner_epoch);
  ~VMOwnerScope();

  VMOwnerScope(const VMOwnerScope &) = delete;
  VMOwnerScope &operator=(const VMOwnerScope &) = delete;

 private:
  VMContext &context_;
  VMOwnerState saved_;
};

#endif /* SRC_VM_CONTEXT_H_ */
