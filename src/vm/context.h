#ifndef SRC_VM_CONTEXT_H_
#define SRC_VM_CONTEXT_H_

#include <cstdint>
#include <ctime>

struct event_base;
struct object_t;
struct program_t;

struct VMExecutionState {
  object_t *current_object{nullptr};
  object_t *command_giver{nullptr};
  object_t *current_interactive{nullptr};
  object_t *previous_ob{nullptr};
  program_t *current_prog{nullptr};
  int caller_type{0};
};

struct VMObjectStoreState {
  object_t *objects{nullptr};
  object_t *destructed_objects{nullptr};
  object_t *debug_dangling_objects{nullptr};
};

struct VMContext {
  time_t boot_time{0};
  event_base *event_loop{nullptr};
  uint64_t current_gametick{0};
  VMExecutionState execution;
  VMObjectStoreState object_store;
};

VMContext &vm_context();
VMContext &vm_main_context();
VMContext *vm_context_bind_thread(VMContext *context);

void vm_context_set_boot_time(VMContext &context, time_t boot_time);
void vm_context_set_event_base(VMContext &context, event_base *base);
void vm_context_set_current_gametick(VMContext &context, uint64_t gametick);
void vm_context_reset_execution(VMContext &context);
VMExecutionState vm_context_capture_execution();
void vm_context_apply_execution(VMContext &context, const VMExecutionState &execution);
void vm_context_sync_execution(VMContext &context);
void vm_context_sync_object_store(VMContext &context);

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

#endif /* SRC_VM_CONTEXT_H_ */
