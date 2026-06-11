#include "base/std.h"

#include "vm/context.h"

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
    : context_(context), saved_(vm_context_capture_execution()) {
  vm_context_apply_execution(context_, execution);
}

VMExecutionScope::~VMExecutionScope() { vm_context_apply_execution(context_, saved_); }

VMContextThreadScope::VMContextThreadScope(VMContext &context) : saved_(vm_context_bind_thread(&context)) {}

VMContextThreadScope::~VMContextThreadScope() { vm_context_bind_thread(saved_); }

VMOwnerScope::VMOwnerScope(VMContext &context, const char *owner_id, uint64_t owner_epoch)
    : context_(context), saved_(context.owner) {
  vm_context_set_current_owner(context_, owner_id, owner_epoch);
}

VMOwnerScope::~VMOwnerScope() { context_.owner = saved_; }
