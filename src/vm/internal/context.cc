#include "base/std.h"

#include "vm/context.h"

#include "vm/internal/base/machine.h"
#include "vm/internal/simulate.h"

namespace {
VMContext main_vm_context;
thread_local VMContext *thread_vm_context = &main_vm_context;
}

VMContext &vm_context() { return *thread_vm_context; }

VMContext &vm_main_context() { return main_vm_context; }

VMContext *vm_context_bind_thread(VMContext *context) {
  auto *previous = thread_vm_context;
  thread_vm_context = context ? context : &main_vm_context;
  return previous;
}

void vm_context_set_boot_time(VMContext &context, time_t boot_time) { context.boot_time = boot_time; }

void vm_context_set_event_base(VMContext &context, event_base *base) { context.event_loop = base; }

void vm_context_set_current_gametick(VMContext &context, uint64_t gametick) {
  context.current_gametick = gametick;
}

void vm_context_reset_execution(VMContext &context) { context.execution = VMExecutionState{}; }

VMExecutionState vm_context_capture_execution() {
  VMExecutionState execution;
  execution.current_object = current_object;
  execution.command_giver = command_giver;
  execution.current_interactive = current_interactive;
  execution.previous_ob = previous_ob;
  execution.current_prog = current_prog;
  execution.caller_type = caller_type;
  return execution;
}

void vm_context_apply_execution(VMContext &context, const VMExecutionState &execution) {
  current_object = execution.current_object;
  command_giver = execution.command_giver;
  current_interactive = execution.current_interactive;
  previous_ob = execution.previous_ob;
  current_prog = execution.current_prog;
  caller_type = execution.caller_type;
  context.execution = execution;
}

void vm_context_sync_execution(VMContext &context) {
  context.execution = vm_context_capture_execution();
}

void vm_context_sync_object_store(VMContext &context) {
  context.object_store.objects = obj_list;
  context.object_store.destructed_objects = obj_list_destruct;
#ifdef DEBUG
  context.object_store.debug_dangling_objects = obj_list_dangling;
#else
  context.object_store.debug_dangling_objects = nullptr;
#endif
}

VMExecutionScope::VMExecutionScope(VMContext &context, const VMExecutionState &execution)
    : context_(context), saved_(vm_context_capture_execution()) {
  vm_context_apply_execution(context_, execution);
}

VMExecutionScope::~VMExecutionScope() { vm_context_apply_execution(context_, saved_); }

VMContextThreadScope::VMContextThreadScope(VMContext &context) : saved_(vm_context_bind_thread(&context)) {}

VMContextThreadScope::~VMContextThreadScope() { vm_context_bind_thread(saved_); }
