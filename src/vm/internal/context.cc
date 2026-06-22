#include "base/std.h"

#include "vm/context.h"

#include "vm/internal/apply.h"
#include "vm/internal/base/interpret.h"
#include "vm/internal/base/machine.h"
#include "vm/internal/simulate.h"

#include <atomic>
#include <thread>

namespace {
VMContext main_vm_context;
thread_local VMContext *thread_vm_context = &main_vm_context;
const std::thread::id main_vm_thread_id = std::this_thread::get_id();
std::atomic<uint64_t> object_store_sync_rejections{0};

bool can_sync_object_store_to_context(VMContext &context) {
  return &context == &main_vm_context && std::this_thread::get_id() == main_vm_thread_id;
}

bool is_current_thread_context(VMContext &context) { return &context == thread_vm_context; }

void clear_object_store_snapshot(VMObjectStoreState &object_store) {
  object_store.objects = nullptr;
  object_store.destructed_objects = nullptr;
  object_store.debug_dangling_objects = nullptr;
  object_store.main_thread_owned = false;
}
}

VMContext &vm_context() { return *thread_vm_context; }

VMContext &vm_main_context() { return main_vm_context; }

VMContext *vm_context_bind_thread(VMContext *context) {
  auto *previous = thread_vm_context;
  thread_vm_context = context ? context : &main_vm_context;
  return previous;
}

bool vm_context_is_main_thread() { return std::this_thread::get_id() == main_vm_thread_id; }

void vm_context_set_boot_time(VMContext &context, time_t boot_time) { context.boot_time = boot_time; }

void vm_context_set_event_base(VMContext &context, event_base *base) { context.event_loop = base; }

void vm_context_set_current_gametick(VMContext &context, uint64_t gametick) {
  context.current_gametick = gametick;
}

void vm_context_set_current_owner(VMContext &context, const char *owner_id, uint64_t owner_epoch) {
  context.owner.current_owner_id = owner_id ? owner_id : "";
  context.owner.current_owner_epoch = owner_epoch;
}

void vm_context_set_current_object(VMContext &context, object_t *object) {
  if (is_current_thread_context(context)) {
    current_object = object;
  }
  context.execution.current_object = object;
}

void vm_context_set_command_giver(VMContext &context, object_t *giver) {
  if (is_current_thread_context(context)) {
    command_giver = giver;
  }
  context.execution.command_giver = giver;
}

void vm_context_set_current_interactive(VMContext &context, object_t *interactive) {
  if (is_current_thread_context(context)) {
    current_interactive = interactive;
  }
  context.execution.current_interactive = interactive;
}

void vm_context_set_previous_object(VMContext &context, object_t *object) {
  if (is_current_thread_context(context)) {
    previous_ob = object;
  }
  context.execution.previous_ob = object;
}

void vm_context_set_current_program(VMContext &context, program_t *program) {
  if (is_current_thread_context(context)) {
    current_prog = program;
  }
  context.execution.current_prog = program;
}

void vm_context_set_caller_type(VMContext &context, int type) {
  if (is_current_thread_context(context)) {
    caller_type = type;
  }
  context.execution.caller_type = type;
}

void vm_context_set_call_origin(VMContext &context, int origin) {
  if (is_current_thread_context(context)) {
    call_origin = origin;
  }
  context.execution.call_origin = origin;
}

void vm_context_set_inherit_offsets(VMContext &context, int function_offset, int variable_offset) {
  if (is_current_thread_context(context)) {
    function_index_offset = function_offset;
    variable_index_offset = variable_offset;
  }
  context.execution.function_index_offset = function_offset;
  context.execution.variable_index_offset = variable_offset;
}

void vm_context_set_stack_temporary_depth(VMContext &context, int depth) {
#ifdef DEBUG
  if (is_current_thread_context(context)) {
    stack_in_use_as_temporary = depth;
  }
#endif
  context.execution.stack_in_use_as_temporary = depth;
}

void vm_context_adjust_stack_temporary_depth(VMContext &context, int delta) {
  vm_context_set_stack_temporary_depth(context,
                                       context.execution.stack_in_use_as_temporary + delta);
}

void vm_context_set_execution_frame(VMContext &context, object_t *object, program_t *program,
                                    object_t *previous, int type) {
  if (is_current_thread_context(context)) {
    current_object = object;
    current_prog = program;
    previous_ob = previous;
    caller_type = type;
  }
  context.execution.current_object = object;
  context.execution.current_prog = program;
  context.execution.previous_ob = previous;
  context.execution.caller_type = type;
}

void vm_context_set_current_error_context(VMContext &context, error_context_t *error_context) {
  if (is_current_thread_context(context)) {
    current_error_context = error_context;
  }
  context.error.current_error_context = error_context;
}

void vm_context_set_too_deep_error(VMContext &context, int value) {
  if (is_current_thread_context(context)) {
    too_deep_error = value;
  }
  context.error.too_deep_error = value;
}

void vm_context_set_max_eval_error(VMContext &context, int value) {
  if (is_current_thread_context(context)) {
    max_eval_error = value;
  }
  context.error.max_eval_error = value;
}

void vm_context_set_error_flags(VMContext &context, int too_deep, int max_eval) {
  if (is_current_thread_context(context)) {
    too_deep_error = too_deep;
    max_eval_error = max_eval;
  }
  context.error.too_deep_error = too_deep;
  context.error.max_eval_error = max_eval;
}

VMExecutionState vm_context_capture_execution() {
  VMExecutionState execution;
  execution.current_object = current_object;
  execution.command_giver = command_giver;
  execution.current_interactive = current_interactive;
  execution.previous_ob = previous_ob;
  execution.current_prog = current_prog;
  execution.caller_type = caller_type;
  execution.call_origin = call_origin;
  execution.function_index_offset = function_index_offset;
  execution.variable_index_offset = variable_index_offset;
#ifdef DEBUG
  execution.stack_in_use_as_temporary = stack_in_use_as_temporary;
#endif
  return execution;
}

void vm_context_apply_execution(VMContext &context, const VMExecutionState &execution) {
  if (is_current_thread_context(context)) {
    current_object = execution.current_object;
    command_giver = execution.command_giver;
    current_interactive = execution.current_interactive;
    previous_ob = execution.previous_ob;
    current_prog = execution.current_prog;
    caller_type = execution.caller_type;
    call_origin = execution.call_origin;
    function_index_offset = execution.function_index_offset;
    variable_index_offset = execution.variable_index_offset;
#ifdef DEBUG
    stack_in_use_as_temporary = execution.stack_in_use_as_temporary;
#endif
  }
  context.execution = execution;
}

void vm_context_reset_execution(VMContext &context) {
  vm_context_apply_execution(context, VMExecutionState{});
}

void vm_context_sync_execution(VMContext &context) {
  if (!is_current_thread_context(context)) {
    return;
  }
  context.execution = vm_context_capture_execution();
}

void vm_context_sync_eval_stack(VMContext &context) {
  if (!is_current_thread_context(context)) {
    return;
  }
  auto sync_count = context.eval_stack.sync_count + 1;
  context.eval_stack.owner_id = context.owner.current_owner_id;
  context.eval_stack.owner_epoch = context.owner.current_owner_epoch;
  context.eval_stack.depth = vm_eval_stack_depth();
  context.eval_stack.capacity = vm_eval_stack_capacity();
  context.eval_stack.thread_local_storage = vm_eval_stack_thread_local_storage_ready();
  context.eval_stack.context_bound = true;
  context.eval_stack.owner_bound = !context.owner.current_owner_id.empty();
  context.eval_stack.empty = context.eval_stack.depth == 0;
  context.eval_stack.sync_count = sync_count;
}

void vm_context_clear_eval_stack(VMContext &context) { context.eval_stack = VMEvalStackState{}; }

void vm_context_sync_value_stack(VMContext &context) {
  if (!is_current_thread_context(context)) {
    return;
  }
  auto sync_count = context.value_stack.sync_count + 1;
  context.value_stack.owner_id = context.owner.current_owner_id;
  context.value_stack.owner_epoch = context.owner.current_owner_epoch;
  context.value_stack.depth = vm_value_stack_depth();
  context.value_stack.capacity = vm_value_stack_capacity();
  context.value_stack.lvalue_ref_count = vm_value_stack_lvalue_ref_count();
  context.value_stack.thread_local_storage = vm_value_stack_thread_local_storage_ready();
  context.value_stack.context_bound = true;
  context.value_stack.owner_bound = !context.owner.current_owner_id.empty();
  context.value_stack.lvalue_refs_empty = context.value_stack.lvalue_ref_count == 0;
  context.value_stack.empty = context.value_stack.depth == 0 && context.value_stack.lvalue_refs_empty;
  context.value_stack.sync_count = sync_count;
}

void vm_context_clear_value_stack(VMContext &context) { context.value_stack = VMValueStackState{}; }

void vm_context_sync_apply_return(VMContext &context) {
  if (!is_current_thread_context(context)) {
    return;
  }
  auto sync_count = context.apply_return.sync_count + 1;
  context.apply_return.owner_id = context.owner.current_owner_id;
  context.apply_return.owner_epoch = context.owner.current_owner_epoch;
  context.apply_return.value_type = vm_apply_return_value_type();
  context.apply_return.value_subtype = vm_apply_return_value_subtype();
  context.apply_return.thread_local_storage = vm_apply_return_thread_local_storage_ready();
  context.apply_return.context_bound = true;
  context.apply_return.owner_bound = !context.owner.current_owner_id.empty();
  context.apply_return.empty = vm_apply_return_empty();
  context.apply_return.sync_count = sync_count;
}

void vm_context_clear_apply_return(VMContext &context) {
  if (is_current_thread_context(context)) {
    vm_apply_return_clear();
  }
  context.apply_return = VMApplyReturnState{};
}

void vm_context_sync_control_stack(VMContext &context) {
  if (!is_current_thread_context(context)) {
    return;
  }
  auto sync_count = context.control_stack.sync_count + 1;
  context.control_stack.owner_id = context.owner.current_owner_id;
  context.control_stack.owner_epoch = context.owner.current_owner_epoch;
  context.control_stack.depth = vm_control_stack_depth();
  context.control_stack.capacity = vm_control_stack_capacity();
  context.control_stack.thread_local_storage = vm_control_stack_thread_local_storage_ready();
  context.control_stack.context_bound = true;
  context.control_stack.owner_bound = !context.owner.current_owner_id.empty();
  context.control_stack.empty = context.control_stack.depth == 0;
  context.control_stack.sync_count = sync_count;
}

void vm_context_clear_control_stack(VMContext &context) { context.control_stack = VMControlStackState{}; }

void vm_context_sync_object_store(VMContext &context) {
  if (!can_sync_object_store_to_context(context)) {
    clear_object_store_snapshot(context.object_store);
    context.object_store.sync_rejections++;
    object_store_sync_rejections.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  context.object_store.objects = obj_list;
  context.object_store.destructed_objects = obj_list_destruct;
#ifdef DEBUG
  context.object_store.debug_dangling_objects = obj_list_dangling;
#else
  context.object_store.debug_dangling_objects = nullptr;
#endif
  context.object_store.main_thread_owned = true;
}

uint64_t vm_context_object_store_sync_rejections() {
  return object_store_sync_rejections.load(std::memory_order_relaxed);
}

VMExecutionScope::VMExecutionScope(VMContext &context, const VMExecutionState &execution)
    : context_(context), saved_(is_current_thread_context(context) ? vm_context_capture_execution() : context.execution) {
  vm_context_apply_execution(context_, execution);
}

VMExecutionScope::~VMExecutionScope() { vm_context_apply_execution(context_, saved_); }

VMContextThreadScope::VMContextThreadScope(VMContext &context) : saved_(vm_context_bind_thread(&context)) {}

VMContextThreadScope::~VMContextThreadScope() { vm_context_bind_thread(saved_); }

VMCurrentInteractiveScope::VMCurrentInteractiveScope(VMContext &context, object_t *interactive)
    : context_(context), saved_(context.execution.current_interactive) {
  vm_context_set_current_interactive(context_, interactive);
}

VMCurrentInteractiveScope::~VMCurrentInteractiveScope() {
  vm_context_set_current_interactive(context_, saved_);
}

VMOwnerScope::VMOwnerScope(VMContext &context, const char *owner_id, uint64_t owner_epoch)
    : context_(context), saved_(context.owner) {
  vm_context_set_current_owner(context_, owner_id, owner_epoch);
}

VMOwnerScope::~VMOwnerScope() { context_.owner = saved_; }
