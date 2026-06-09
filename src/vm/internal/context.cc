#include "base/std.h"

#include "vm/context.h"

#include "vm/internal/base/machine.h"
#include "vm/internal/simulate.h"

namespace {
VMContext main_vm_context;
}

VMContext &vm_context() { return main_vm_context; }

void vm_context_set_boot_time(VMContext &context, time_t boot_time) { context.boot_time = boot_time; }

void vm_context_set_event_base(VMContext &context, event_base *base) { context.event_loop = base; }

void vm_context_set_current_gametick(VMContext &context, uint64_t gametick) {
  context.current_gametick = gametick;
}

void vm_context_reset_execution(VMContext &context) { context.execution = VMExecutionState{}; }

void vm_context_sync_execution(VMContext &context) {
  context.execution.current_object = current_object;
  context.execution.command_giver = command_giver;
  context.execution.current_interactive = current_interactive;
  context.execution.previous_ob = previous_ob;
  context.execution.current_prog = current_prog;
  context.execution.caller_type = caller_type;
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
