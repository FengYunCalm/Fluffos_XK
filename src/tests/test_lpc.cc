#include <gtest/gtest.h>
#include <chrono>
#include <limits>
#include <string>
#include <thread>
#include "base/package_api.h"

#include "backend.h"
#include "mainlib.h"

#include "compiler/internal/compiler.h"
#include "packages/core/heartbeat.h"
#include "packages/gateway/gateway.h"
#include "vm/context.h"
#include "vm/internal/base/array.h"
#include "vm/internal/simulate.h"
#include "vm/object_handle.h"
#include "vm/owner.h"
#include "vm/worker.h"

// Test fixture class
class DriverTest : public ::testing::Test {
 public:
  static void SetUpTestSuite() {
    chdir(TESTSUITE_DIR);
    // Initialize libevent, This should be done before executing LPC.
    auto* base = init_main("etc/config.test");
    vm_start();
  }

 protected:
  void SetUp() override { clear_state(); }

  void TearDown() override {
    vm_owner_thread_stop();
    clear_state();
  }
};

namespace {
object_t* load_object_for_test(const char* path) {
  error_context_t econ{};
  object_t* object = nullptr;
  save_context(&econ);
  try {
    object = load_object(path, 1);
    pop_context(&econ);
  } catch (...) {
    restore_context(&econ);
    ADD_FAILURE() << "load_object failed for " << path;
  }
  return object;
}
}  // namespace

TEST_F(DriverTest, TestCompileDumpProgWorks) {
  current_object = master_ob;
  const char* file = "single/master.c";
  struct object_t* obj = nullptr;

  error_context_t econ{};
  save_context(&econ);
  try {
    obj = find_object(file);
  } catch (...) {
    restore_context(&econ);
    FAIL();
  }
  pop_context(&econ);

  ASSERT_NE(obj, nullptr);
  ASSERT_NE(obj->prog, nullptr);

  dump_prog(obj->prog, stdout, 1 | 2);

  free_object(&obj, "DriverTest::TestCompileDumpProgWorks");
}

TEST_F(DriverTest, TestVmContextTracksTopLevelState) {
  ASSERT_EQ(vm_context().event_loop, g_event_base);
  ASSERT_EQ(vm_context().current_gametick, g_current_gametick);
  ASSERT_EQ(vm_context().execution.current_object, nullptr);
  ASSERT_EQ(vm_context().execution.command_giver, nullptr);
  ASSERT_EQ(vm_context().execution.current_interactive, nullptr);
  ASSERT_EQ(vm_context().execution.previous_ob, nullptr);
  ASSERT_EQ(vm_context().execution.current_prog, nullptr);
  ASSERT_EQ(vm_context().execution.caller_type, 0);
  ASSERT_EQ(vm_context().execution.call_origin, 0);
  ASSERT_EQ(vm_context().execution.function_index_offset, 0);
  ASSERT_EQ(vm_context().execution.variable_index_offset, 0);
  ASSERT_EQ(vm_context().execution.stack_in_use_as_temporary, 0);
  ASSERT_EQ(vm_context().error.current_error_context, nullptr);
  ASSERT_EQ(vm_context().error.too_deep_error, 0);
  ASSERT_EQ(vm_context().error.max_eval_error, 0);
  ASSERT_EQ(vm_context().error.error_depth, 0);
  ASSERT_EQ(vm_context().error.mudlib_error_depth, 0);
  ASSERT_EQ(vm_context().object_store.objects, obj_list);
  ASSERT_EQ(vm_context().object_store.destructed_objects, obj_list_destruct);
  ASSERT_EQ(vm_context().object_store.load_object_depth, 0);
  ASSERT_EQ(vm_context().object_store.restricted_destruct_object, nullptr);
}

TEST_F(DriverTest, TestVmExecutionScopeRestoresGlobalState) {
  current_object = master_ob;
  command_giver = nullptr;
  current_interactive = nullptr;
  previous_ob = nullptr;
  current_prog = nullptr;
  caller_type = 0;
  vm_context_set_call_origin(vm_context(), 0);
  vm_context_set_inherit_offsets(vm_context(), 0, 0);
  vm_context_set_stack_temporary_depth(vm_context(), 0);
  vm_context_sync_execution(vm_context());

  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  VMExecutionState scoped = vm_context_capture_execution();
  scoped.current_object = obj;
  scoped.command_giver = obj;
  scoped.current_interactive = obj;
  scoped.previous_ob = obj;
  scoped.current_prog = obj->prog;
  scoped.caller_type = 42;
  scoped.call_origin = ORIGIN_EFUN;
  scoped.function_index_offset = 7;
  scoped.variable_index_offset = 11;
  scoped.stack_in_use_as_temporary = 2;

  {
    VMExecutionScope scope(vm_context(), scoped);
    ASSERT_EQ(current_object, obj);
    ASSERT_EQ(command_giver, obj);
    ASSERT_EQ(current_interactive, obj);
    ASSERT_EQ(previous_ob, obj);
    ASSERT_EQ(current_prog, obj->prog);
    ASSERT_EQ(caller_type, 42);
    ASSERT_EQ(call_origin, ORIGIN_EFUN);
    ASSERT_EQ(function_index_offset, 7);
    ASSERT_EQ(variable_index_offset, 11);
#ifdef DEBUG
    ASSERT_EQ(stack_in_use_as_temporary, 2);
#endif
    ASSERT_EQ(vm_context().execution.current_object, obj);
    ASSERT_EQ(vm_context().execution.command_giver, obj);
    ASSERT_EQ(vm_context().execution.current_interactive, obj);
    ASSERT_EQ(vm_context().execution.previous_ob, obj);
    ASSERT_EQ(vm_context().execution.current_prog, obj->prog);
    ASSERT_EQ(vm_context().execution.caller_type, 42);
    ASSERT_EQ(vm_context().execution.call_origin, ORIGIN_EFUN);
    ASSERT_EQ(vm_context().execution.function_index_offset, 7);
    ASSERT_EQ(vm_context().execution.variable_index_offset, 11);
    ASSERT_EQ(vm_context().execution.stack_in_use_as_temporary, 2);
  }

  ASSERT_EQ(current_object, master_ob);
  ASSERT_EQ(command_giver, nullptr);
  ASSERT_EQ(current_interactive, nullptr);
  ASSERT_EQ(previous_ob, nullptr);
  ASSERT_EQ(current_prog, nullptr);
  ASSERT_EQ(caller_type, 0);
  ASSERT_EQ(call_origin, 0);
  ASSERT_EQ(function_index_offset, 0);
  ASSERT_EQ(variable_index_offset, 0);
#ifdef DEBUG
  ASSERT_EQ(stack_in_use_as_temporary, 0);
#endif
  ASSERT_EQ(vm_context().execution.current_object, master_ob);
  ASSERT_EQ(vm_context().execution.command_giver, nullptr);
  ASSERT_EQ(vm_context().execution.current_interactive, nullptr);
  ASSERT_EQ(vm_context().execution.previous_ob, nullptr);
  ASSERT_EQ(vm_context().execution.current_prog, nullptr);
  ASSERT_EQ(vm_context().execution.caller_type, 0);
  ASSERT_EQ(vm_context().execution.call_origin, 0);
  ASSERT_EQ(vm_context().execution.function_index_offset, 0);
  ASSERT_EQ(vm_context().execution.variable_index_offset, 0);
  ASSERT_EQ(vm_context().execution.stack_in_use_as_temporary, 0);
}

TEST_F(DriverTest, TestVmCurrentInteractiveScopeRestoresState) {
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  current_interactive = nullptr;
  vm_context_sync_execution(vm_context());

  {
    VMCurrentInteractiveScope scope(vm_context(), obj);
    ASSERT_EQ(current_interactive, obj);
    ASSERT_EQ(vm_context().execution.current_interactive, obj);
  }

  ASSERT_EQ(current_interactive, nullptr);
  ASSERT_EQ(vm_context().execution.current_interactive, nullptr);
}

TEST_F(DriverTest, TestVmCommandGiverStackSyncsContext) {
  object_t* first = find_object("single/master.c");
  object_t* second = find_object("single/simul_efun.c");
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);

  set_command_giver(nullptr);
  ASSERT_EQ(command_giver, nullptr);
  ASSERT_EQ(vm_context().execution.command_giver, nullptr);

  save_command_giver(first);
  ASSERT_EQ(command_giver, first);
  ASSERT_EQ(vm_context().execution.command_giver, first);

  save_command_giver(second);
  ASSERT_EQ(command_giver, second);
  ASSERT_EQ(vm_context().execution.command_giver, second);

  restore_command_giver();
  ASSERT_EQ(command_giver, first);
  ASSERT_EQ(vm_context().execution.command_giver, first);

  restore_command_giver();
  ASSERT_EQ(command_giver, nullptr);
  ASSERT_EQ(vm_context().execution.command_giver, nullptr);
}

TEST_F(DriverTest, TestVmExecutionFrameSettersSyncContext) {
  object_t* first = find_object("single/master.c");
  object_t* second = find_object("single/simul_efun.c");
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  ASSERT_NE(first->prog, nullptr);
  ASSERT_NE(second->prog, nullptr);

  vm_context_set_execution_frame(vm_context(), first, first->prog, second, ORIGIN_DRIVER);
  ASSERT_EQ(current_object, first);
  ASSERT_EQ(current_prog, first->prog);
  ASSERT_EQ(previous_ob, second);
  ASSERT_EQ(caller_type, ORIGIN_DRIVER);
  ASSERT_EQ(vm_context().execution.current_object, first);
  ASSERT_EQ(vm_context().execution.current_prog, first->prog);
  ASSERT_EQ(vm_context().execution.previous_ob, second);
  ASSERT_EQ(vm_context().execution.caller_type, ORIGIN_DRIVER);

  vm_context_set_current_object(vm_context(), second);
  vm_context_set_current_program(vm_context(), second->prog);
  vm_context_set_previous_object(vm_context(), first);
  vm_context_set_caller_type(vm_context(), ORIGIN_LOCAL);
  vm_context_set_call_origin(vm_context(), ORIGIN_CALL_OTHER);
  vm_context_set_inherit_offsets(vm_context(), 3, 5);
  vm_context_set_stack_temporary_depth(vm_context(), 2);
  ASSERT_EQ(current_object, second);
  ASSERT_EQ(current_prog, second->prog);
  ASSERT_EQ(previous_ob, first);
  ASSERT_EQ(caller_type, ORIGIN_LOCAL);
  ASSERT_EQ(call_origin, ORIGIN_CALL_OTHER);
  ASSERT_EQ(function_index_offset, 3);
  ASSERT_EQ(variable_index_offset, 5);
#ifdef DEBUG
  ASSERT_EQ(stack_in_use_as_temporary, 2);
#endif
  ASSERT_EQ(vm_context().execution.current_object, second);
  ASSERT_EQ(vm_context().execution.current_prog, second->prog);
  ASSERT_EQ(vm_context().execution.previous_ob, first);
  ASSERT_EQ(vm_context().execution.caller_type, ORIGIN_LOCAL);
  ASSERT_EQ(vm_context().execution.call_origin, ORIGIN_CALL_OTHER);
  ASSERT_EQ(vm_context().execution.function_index_offset, 3);
  ASSERT_EQ(vm_context().execution.variable_index_offset, 5);
  ASSERT_EQ(vm_context().execution.stack_in_use_as_temporary, 2);

  vm_context_adjust_stack_temporary_depth(vm_context(), -1);
#ifdef DEBUG
  ASSERT_EQ(stack_in_use_as_temporary, 1);
#endif
  ASSERT_EQ(vm_context().execution.stack_in_use_as_temporary, 1);

  vm_context_set_execution_frame(vm_context(), master_ob, nullptr, nullptr, 0);
  vm_context_set_call_origin(vm_context(), 0);
  vm_context_set_inherit_offsets(vm_context(), 0, 0);
  vm_context_set_stack_temporary_depth(vm_context(), 0);
}

TEST_F(DriverTest, TestVmErrorContextStackSyncsContext) {
  vm_context_set_current_error_context(vm_context(), nullptr);
  ASSERT_EQ(current_error_context, nullptr);
  ASSERT_EQ(vm_context().error.current_error_context, nullptr);

  error_context_t first{};
  error_context_t second{};
  save_context(&first);
  ASSERT_EQ(current_error_context, &first);
  ASSERT_EQ(vm_context().error.current_error_context, &first);
  ASSERT_EQ(first.save_context, nullptr);

  save_context(&second);
  ASSERT_EQ(current_error_context, &second);
  ASSERT_EQ(vm_context().error.current_error_context, &second);
  ASSERT_EQ(second.save_context, &first);

  pop_context(&second);
  ASSERT_EQ(current_error_context, &first);
  ASSERT_EQ(vm_context().error.current_error_context, &first);

  pop_context(&first);
  ASSERT_EQ(current_error_context, nullptr);
  ASSERT_EQ(vm_context().error.current_error_context, nullptr);
}

TEST_F(DriverTest, TestVmErrorFlagsSyncContext) {
  vm_context_set_error_flags(vm_context(), 0, 0);
  vm_context_set_error_depths(vm_context(), 0, 0);
  ASSERT_EQ(too_deep_error, 0);
  ASSERT_EQ(max_eval_error, 0);
  ASSERT_EQ(vm_context().error.too_deep_error, 0);
  ASSERT_EQ(vm_context().error.max_eval_error, 0);
  ASSERT_EQ(vm_context().error.error_depth, 0);
  ASSERT_EQ(vm_context().error.mudlib_error_depth, 0);

  vm_context_set_too_deep_error(vm_context(), 1);
  ASSERT_EQ(too_deep_error, 1);
  ASSERT_EQ(max_eval_error, 0);
  ASSERT_EQ(vm_context().error.too_deep_error, 1);
  ASSERT_EQ(vm_context().error.max_eval_error, 0);

  vm_context_set_max_eval_error(vm_context(), 1);
  ASSERT_EQ(too_deep_error, 1);
  ASSERT_EQ(max_eval_error, 1);
  ASSERT_EQ(vm_context().error.too_deep_error, 1);
  ASSERT_EQ(vm_context().error.max_eval_error, 1);

  vm_context_adjust_error_depth(vm_context(), 1);
  vm_context_adjust_mudlib_error_depth(vm_context(), 2);
  ASSERT_EQ(vm_context().error.error_depth, 1);
  ASSERT_EQ(vm_context().error.mudlib_error_depth, 2);

  clear_state();
  ASSERT_EQ(too_deep_error, 0);
  ASSERT_EQ(max_eval_error, 0);
  ASSERT_EQ(vm_context().error.too_deep_error, 0);
  ASSERT_EQ(vm_context().error.max_eval_error, 0);
  ASSERT_EQ(vm_context().error.error_depth, 0);
  ASSERT_EQ(vm_context().error.mudlib_error_depth, 0);
}

TEST_F(DriverTest, TestVmObjectLifecycleStateSyncsContext) {
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  vm_context_set_load_object_depth(vm_context(), 0);
  vm_context_set_restricted_destruct_object(vm_context(), nullptr);
  ASSERT_EQ(vm_context().object_store.load_object_depth, 0);
  ASSERT_EQ(vm_context().object_store.restricted_destruct_object, nullptr);

  vm_context_adjust_load_object_depth(vm_context(), 2);
  ASSERT_EQ(vm_context().object_store.load_object_depth, 2);

  vm_context_adjust_load_object_depth(vm_context(), -1);
  ASSERT_EQ(vm_context().object_store.load_object_depth, 1);

  vm_context_set_restricted_destruct_object(vm_context(), obj);
  ASSERT_EQ(vm_context().object_store.restricted_destruct_object, obj);

  clear_state();
  ASSERT_EQ(vm_context().object_store.load_object_depth, 0);
  ASSERT_EQ(vm_context().object_store.restricted_destruct_object, nullptr);
}

TEST_F(DriverTest, TestVmContextThreadScopeBindsThreadLocalContext) {
  auto *main_context = &vm_context();
  ASSERT_EQ(main_context, &vm_main_context());

  bool worker_bound = false;
  uint64_t worker_gametick = 0;
  std::thread worker([&] {
    VMContext worker_context;
    VMContextThreadScope scope(worker_context);
    vm_context_set_current_gametick(vm_context(), 777);
    worker_bound = &vm_context() == &worker_context && &vm_context() != main_context;
    worker_gametick = worker_context.current_gametick;
  });
  worker.join();

  ASSERT_TRUE(worker_bound);
  ASSERT_EQ(worker_gametick, 777u);
  ASSERT_EQ(&vm_context(), main_context);
}

TEST_F(DriverTest, TestVmContextObjectStoreRemainsMainThreadOwned) {
  auto *main_context = &vm_context();
  vm_context_sync_object_store(*main_context);
  ASSERT_TRUE(main_context->object_store.main_thread_owned);
  ASSERT_EQ(main_context->object_store.objects, obj_list);

  auto before_rejections = vm_context_object_store_sync_rejections();
  bool worker_store_rejected = false;
  uint64_t worker_rejections = 0;
  std::thread worker([&] {
    VMContext worker_context;
    VMContextThreadScope scope(worker_context);
    vm_context_sync_object_store(vm_context());
    worker_store_rejected = !worker_context.object_store.main_thread_owned && worker_context.object_store.objects == nullptr;
    worker_rejections = worker_context.object_store.sync_rejections;
  });
  worker.join();

  ASSERT_TRUE(worker_store_rejected);
  ASSERT_EQ(worker_rejections, 1u);
  ASSERT_EQ(vm_context_object_store_sync_rejections(), before_rejections + 1);
  ASSERT_TRUE(main_context->object_store.main_thread_owned);
  ASSERT_EQ(main_context->object_store.objects, obj_list);
}

TEST_F(DriverTest, TestVmOwnerScopeBindsAndRestoresCurrentOwner) {
  auto *context = &vm_context();
  vm_context_set_current_owner(*context, "owner/test/original", 7);

  {
    VMOwnerScope scope(*context, "owner/test/scoped", 8);
    ASSERT_EQ(context->owner.current_owner_id, "owner/test/scoped");
    ASSERT_EQ(context->owner.current_owner_epoch, 8u);
  }

  ASSERT_EQ(context->owner.current_owner_id, "owner/test/original");
  ASSERT_EQ(context->owner.current_owner_epoch, 7u);
  vm_context_set_current_owner(*context, "", 0);
}

TEST_F(DriverTest, TestVmOwnerMetadataDefaultsAndChecks) {
  current_object = master_ob;
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(obj));
  auto default_epoch = vm_owner_epoch(obj);
  vm_owner_set_id(obj, "owner/test");
  ASSERT_STREQ("owner/test", vm_owner_id(obj));
  ASSERT_EQ(vm_owner_epoch(obj), default_epoch + 1);
  ASSERT_TRUE(vm_owner_matches(obj, "owner/test"));

  auto before_total = vm_owner_total_checks();
  auto before_mismatch = vm_owner_mismatch_checks();
  vm_owner_record_check(obj, "owner/other", false);
  ASSERT_EQ(vm_owner_total_checks(), before_total + 1);
  ASSERT_EQ(vm_owner_mismatch_checks(), before_mismatch + 1);

  vm_owner_clear_id(obj);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(obj));
  ASSERT_EQ(vm_owner_epoch(obj), default_epoch + 2);
}

TEST_F(DriverTest, TestVmOwnerMailboxDrainsOwnerFifo) {
  const char* owner_id = "owner/test/mailbox";
  auto first_id = vm_owner_enqueue_task(owner_id, "command", "first");
  auto second_id = vm_owner_enqueue_task(owner_id, "command", "second");
  ASSERT_LT(first_id, second_id);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* status = vm_owner_mailbox_status(owner_id);
  ASSERT_EQ(mapping_number(status, "owner_queue_depth"), 2);
  free_mapping(status);

  auto* first_drain = vm_owner_drain_mailbox(owner_id, 1);
  ASSERT_EQ(mapping_number(first_drain, "drained"), 1);
  ASSERT_EQ(mapping_number(first_drain, "remaining"), 1);
  auto* first_tasks = find_string_in_mapping(first_drain, "tasks");
  ASSERT_NE(first_tasks, nullptr);
  ASSERT_EQ(first_tasks->type, T_ARRAY);
  ASSERT_EQ(first_tasks->u.arr->size, 1);
  ASSERT_EQ(first_tasks->u.arr->item[0].type, T_MAPPING);
  ASSERT_EQ(mapping_number(first_tasks->u.arr->item[0].u.map, "task_id"), static_cast<long>(first_id));
  ASSERT_EQ(mapping_number(first_tasks->u.arr->item[0].u.map, "owner_epoch"), 0);
  ASSERT_STREQ(mapping_string(first_tasks->u.arr->item[0].u.map, "task_key"), "first");
  free_mapping(first_drain);

  auto* second_drain = vm_owner_drain_mailbox(owner_id, 0);
  ASSERT_EQ(mapping_number(second_drain, "drained"), 1);
  ASSERT_EQ(mapping_number(second_drain, "remaining"), 0);
  auto* second_tasks = find_string_in_mapping(second_drain, "tasks");
  ASSERT_NE(second_tasks, nullptr);
  ASSERT_EQ(second_tasks->type, T_ARRAY);
  ASSERT_EQ(second_tasks->u.arr->size, 1);
  ASSERT_EQ(second_tasks->u.arr->item[0].type, T_MAPPING);
  ASSERT_EQ(mapping_number(second_tasks->u.arr->item[0].u.map, "task_id"), static_cast<long>(second_id));
  ASSERT_STREQ(mapping_string(second_tasks->u.arr->item[0].u.map, "task_key"), "second");
  free_mapping(second_drain);
}

TEST_F(DriverTest, TestVmOwnerEpochRejectsStaleTask) {
  current_object = master_ob;
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  vm_owner_set_id(obj, "owner/test/epoch-a");
  auto epoch_a = vm_owner_epoch(obj);
  auto stale_task = vm_owner_enqueue_task_epoch("owner/test/epoch-a", "command", "stale", epoch_a);
  vm_owner_set_id(obj, "owner/test/epoch-b");
  auto epoch_b = vm_owner_epoch(obj);
  ASSERT_GT(epoch_b, epoch_a);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto* scheduled = vm_owner_schedule(1);
  auto* tasks = find_string_in_mapping(scheduled, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks->type, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  ASSERT_EQ(mapping_number(tasks->u.arr->item[0].u.map, "task_id"), static_cast<long>(stale_task));
  ASSERT_EQ(mapping_number(tasks->u.arr->item[0].u.map, "owner_epoch"), static_cast<long>(epoch_a));
  free_mapping(scheduled);

  error_context_t econ{};
  save_context(&econ);
  try {
    vm_owner_guard_epoch(obj, "owner/test/epoch-a", epoch_a);
    pop_context(&econ);
    FAIL() << "vm_owner_guard_epoch should reject stale owner task";
  } catch (...) {
    restore_context(&econ);
  }

  auto* guarded = vm_owner_guard_epoch(obj, "owner/test/epoch-b", epoch_b);
  ASSERT_NE(guarded, nullptr);
  ASSERT_EQ(mapping_number(guarded, "owner_epoch"), static_cast<long>(epoch_b));
  free_mapping(guarded);
  vm_owner_clear_id(obj);
}

TEST_F(DriverTest, TestVmOwnerPurgeRemovesOwnerQueueBeforeSchedule) {
  const char* owner = "owner/test/purge";
  const char* other = "owner/test/purge-other";
  vm_owner_enqueue_task(owner, "command", "first");
  vm_owner_enqueue_task(owner, "command", "second");
  auto other_task = vm_owner_enqueue_task(other, "command", "other");

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* purged = vm_owner_purge_mailbox(owner);
  ASSERT_EQ(mapping_number(purged, "purged"), 2);
  ASSERT_EQ(mapping_number(purged, "remaining"), 0);
  free_mapping(purged);

  auto* status = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(status, "owner_queue_depth"), 0);
  free_mapping(status);

  auto* scheduled = vm_owner_schedule(1);
  auto* tasks = find_string_in_mapping(scheduled, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks->type, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  ASSERT_EQ(mapping_number(tasks->u.arr->item[0].u.map, "task_id"), static_cast<long>(other_task));
  ASSERT_STREQ(mapping_string(tasks->u.arr->item[0].u.map, "owner_id"), other);
  free_mapping(scheduled);
}

TEST_F(DriverTest, TestVmOwnerTaskTraceRecordsObservedAndDispatchedEvents) {
  const char* owner = "owner/test/trace";
  auto trace_id = vm_owner_record_task_trace(owner, "command", "look", 7, "observed");
  auto task_id = vm_owner_enqueue_task_epoch(owner, "command", "inventory", 7);
  ASSERT_GT(trace_id, 0u);
  ASSERT_GT(task_id, 0u);

  auto* scheduled = vm_owner_schedule(1);
  free_mapping(scheduled);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* trace = vm_owner_task_trace(3);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 3);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "state"), "observed");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "task_key"), "look");
  ASSERT_STREQ(mapping_string(events->u.arr->item[1].u.map, "state"), "queued");
  ASSERT_STREQ(mapping_string(events->u.arr->item[2].u.map, "state"), "dispatched");
  ASSERT_EQ(mapping_number(events->u.arr->item[2].u.map, "task_id"), static_cast<long>(task_id));
  ASSERT_STREQ(mapping_string(events->u.arr->item[2].u.map, "owner_id"), owner);
  free_mapping(trace);
}

TEST_F(DriverTest, TestVmOwnerMainQueueDispatchesWithOwnerScope) {
  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/main-queue");

  bool ran = false;
  std::string seen_owner;
  auto task_id = vm_owner_enqueue_main_task(obj, "unit_main", "dispatch", [&] {
    ran = true;
    seen_owner = vm_context().owner.current_owner_id;
  });
  ASSERT_GT(task_id, 0u);
  ASSERT_EQ(vm_owner_drain_main_tasks(8), 1);
  ASSERT_TRUE(ran);
  ASSERT_EQ(seen_owner, "owner/test/main-queue");

  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto* trace = vm_owner_task_trace(2);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 2);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "state"), "main_queued");
  ASSERT_STREQ(mapping_string(events->u.arr->item[1].u.map, "state"), "main_dispatched");
  free_mapping(trace);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerMainQueueDropsStaleOwnerEpoch) {
  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/main-stale-old");

  bool ran = false;
  auto task_id = vm_owner_enqueue_main_task(obj, "unit_main", "stale", [&] { ran = true; });
  ASSERT_GT(task_id, 0u);
  vm_owner_set_id(obj, "owner/test/main-stale-new");
  ASSERT_EQ(vm_owner_drain_main_tasks(8), 1);
  ASSERT_FALSE(ran);

  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto* trace = vm_owner_task_trace(2);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 2);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "state"), "main_queued");
  ASSERT_STREQ(mapping_string(events->u.arr->item[1].u.map, "state"), "main_stale");
  free_mapping(trace);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerMainQueueRunsDropCallbackForStaleTask) {
  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/main-drop-old");

  bool ran = false;
  bool dropped = false;
  auto task_id = vm_owner_enqueue_main_task(
      obj, "unit_main", "drop", [&] { ran = true; }, [&] { dropped = true; });
  ASSERT_GT(task_id, 0u);
  vm_owner_set_id(obj, "owner/test/main-drop-new");
  ASSERT_EQ(vm_owner_drain_main_tasks(8), 1);
  ASSERT_FALSE(ran);
  ASSERT_TRUE(dropped);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerHeartbeatTraceRecordsScheduledEvent) {
  current_object = master_ob;
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/heartbeat");

  ASSERT_EQ(set_heart_beat(obj, 1), 1);

  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto* trace = vm_owner_task_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "task_type"), "heartbeat");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "state"), "scheduled");
  free_mapping(trace);

  set_heart_beat(obj, 0);
  vm_owner_clear_id(obj);
}

TEST_F(DriverTest, TestVmOwnerHeartbeatStaleOwnerSkipsExecution) {
  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/heartbeat-stale-old");

  auto call_number = [](const char* method, object_t* target) -> long {
    auto* ret = safe_apply(method, target, 0, ORIGIN_DRIVER);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret ? ret->type : T_INVALID, T_NUMBER);
    return ret && ret->type == T_NUMBER ? ret->u.number : -1;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  ASSERT_EQ(call_number("get_heartbeat_called", obj), 0);
  ASSERT_EQ(set_heart_beat(obj, 1), 1);
  vm_owner_set_id(obj, "owner/test/heartbeat-stale-new");

  call_heart_beat();
  clear_tick_events();

  ASSERT_EQ(call_number("get_heartbeat_called", obj), 0);
  auto* trace = vm_owner_task_trace(4);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  bool saw_stale = false;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (std::string(mapping_string(event, "task_type")) == "heartbeat" &&
        std::string(mapping_string(event, "state")) == "stale") {
      saw_stale = true;
    }
  }
  ASSERT_TRUE(saw_stale);
  free_mapping(trace);

  set_heart_beat(obj, 0);
  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerAccessTraceRecordsCrossOwnerAccess) {
  current_object = master_ob;
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);
  vm_owner_set_id(source, "owner/test/access/source");
  vm_owner_set_id(target, "owner/test/access/target");

  auto access_id = vm_owner_record_access(source, target, "unit-test");
  ASSERT_GT(access_id, 0u);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/access/source");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/access/target");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "unit-test");
  free_mapping(trace);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestVmOwnerCrossOwnerAccessTraceSkipsSameOwner) {
  current_object = master_ob;
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_access_trace(0);
  auto before_total = mapping_number(before, "total_traced");
  free_mapping(before);

  vm_owner_set_id(source, "owner/test/access/shared");
  vm_owner_set_id(target, "owner/test/access/shared");
  ASSERT_EQ(vm_owner_record_cross_owner_access(source, target, "environment"), 0u);

  auto* same_owner = vm_owner_access_trace(0);
  ASSERT_EQ(mapping_number(same_owner, "total_traced"), before_total);
  free_mapping(same_owner);

  vm_owner_set_id(target, "owner/test/access/target");
  auto access_id = vm_owner_record_cross_owner_access(source, target, "environment");
  ASSERT_GT(access_id, 0u);

  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "environment");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/access/shared");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/access/target");
  free_mapping(trace);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestVmOwnerCrossOwnerAccessTraceClassifiesPolicyModes) {
  current_object = master_ob;
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  vm_owner_set_id(source, "owner/test/access-policy/source");
  vm_owner_set_id(target, "owner/test/access-policy/target");
  ASSERT_GT(vm_owner_record_access(source, target, "environment"), 0u);
  ASSERT_GT(vm_owner_record_access(source, target, "call_other"), 0u);
  ASSERT_GT(vm_owner_record_access(source, target, "unknown_access"), 0u);

  auto* trace = vm_owner_access_trace(3);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 3);

  auto* snapshot_event = events->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(snapshot_event, "operation"), "environment");
  ASSERT_STREQ(mapping_string(snapshot_event, "access_mode"), "snapshot");
  ASSERT_EQ(mapping_number(snapshot_event, "snapshot_only"), 1);
  ASSERT_EQ(mapping_number(snapshot_event, "direct_cross_owner_write"), 0);

  auto* message_event = events->u.arr->item[1].u.map;
  ASSERT_STREQ(mapping_string(message_event, "operation"), "call_other");
  ASSERT_STREQ(mapping_string(message_event, "access_mode"), "message");
  ASSERT_EQ(mapping_number(message_event, "message_only_cross_owner"), 1);
  ASSERT_EQ(mapping_number(message_event, "direct_cross_owner_write"), 0);

  auto* rejected_event = events->u.arr->item[2].u.map;
  ASSERT_STREQ(mapping_string(rejected_event, "operation"), "unknown_access");
  ASSERT_STREQ(mapping_string(rejected_event, "access_mode"), "reject");
  ASSERT_EQ(mapping_number(rejected_event, "rejected_by_default"), 1);
  ASSERT_EQ(mapping_number(trace, "direct_cross_owner_write"), 0);
  free_mapping(trace);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestAllInventoryRecordsCrossOwnerAccessTrace) {
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_access_trace(0);
  auto before_total = mapping_number(before, "total_traced");
  free_mapping(before);

  current_object = source;
  vm_owner_set_id(source, "owner/test/inventory/shared");
  vm_owner_set_id(target, "owner/test/inventory/shared");
  ASSERT_EQ(all_inventory(target, 0), &the_null_array);

  auto* same_owner = vm_owner_access_trace(0);
  ASSERT_EQ(mapping_number(same_owner, "total_traced"), before_total);
  free_mapping(same_owner);

  vm_owner_set_id(target, "owner/test/inventory/target");
  ASSERT_EQ(all_inventory(target, 0), &the_null_array);

  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "all_inventory");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/inventory/shared");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/inventory/target");
  free_mapping(trace);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestPresentRecordsCrossOwnerAccessTrace) {
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_access_trace(0);
  auto before_total = mapping_number(before, "total_traced");
  free_mapping(before);

  svalue_t needle;
  needle.type = T_STRING;
  needle.subtype = STRING_CONSTANT;
  needle.u.string = "nonexistent";
  current_object = source;
  vm_owner_set_id(source, "owner/test/present/shared");
  vm_owner_set_id(target, "owner/test/present/shared");
  ASSERT_EQ(object_present(&needle, target), nullptr);

  auto* same_owner = vm_owner_access_trace(0);
  ASSERT_EQ(mapping_number(same_owner, "total_traced"), before_total);
  free_mapping(same_owner);

  vm_owner_set_id(target, "owner/test/present/target");
  ASSERT_EQ(object_present(&needle, target), nullptr);

  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "present");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/present/shared");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/present/target");
  free_mapping(trace);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestMoveObjectRecordsCrossOwnerAccessTrace) {
  object_t* item = load_object_for_test("single/void");
  object_t* dest = find_object("single/simul_efun.c");
  ASSERT_NE(item, nullptr);
  ASSERT_NE(dest, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_access_trace(0);
  auto before_total = mapping_number(before, "total_traced");
  free_mapping(before);

  vm_owner_set_id(item, "owner/test/move/shared");
  vm_owner_set_id(dest, "owner/test/move/shared");
  move_object(item, dest);

  auto* same_owner = vm_owner_access_trace(0);
  ASSERT_EQ(mapping_number(same_owner, "total_traced"), before_total);
  free_mapping(same_owner);

  vm_owner_set_id(dest, "owner/test/move/dest");
  move_object(item, dest);

  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "move_object");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/move/shared");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/move/dest");
  free_mapping(trace);

  vm_owner_clear_id(item);
  vm_owner_clear_id(dest);
  destruct_object(item);
}

TEST_F(DriverTest, TestDestructRecordsCrossOwnerAccessTrace) {
  object_t* source = find_object("single/master.c");
  object_t* target = load_object_for_test("single/on_destruct_good");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_access_trace(0);
  auto before_total = mapping_number(before, "total_traced");
  free_mapping(before);

  current_object = source;
  vm_owner_set_id(source, "owner/test/destruct/shared");
  vm_owner_set_id(target, "owner/test/destruct/shared");
  vm_owner_record_cross_owner_access(source, target, "destruct-primer");

  auto* same_owner = vm_owner_access_trace(0);
  ASSERT_EQ(mapping_number(same_owner, "total_traced"), before_total);
  free_mapping(same_owner);

  vm_owner_set_id(target, "owner/test/destruct/target");
  destruct_object(target);

  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "destruct");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/destruct/shared");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/destruct/target");
  free_mapping(trace);

  vm_owner_clear_id(source);
}

TEST_F(DriverTest, TestCallOtherRecordsCrossOwnerAccessTrace) {
  object_t* caller = load_object_for_test("single/void");
  object_t* target = load_object_for_test("single/on_destruct_good");
  ASSERT_NE(caller, nullptr);
  ASSERT_NE(target, nullptr);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_access_trace(0);
  auto before_total = mapping_number(before, "total_traced");
  free_mapping(before);

  vm_owner_set_id(caller, "owner/test/call/shared");
  vm_owner_set_id(target, "owner/test/call/shared");
  push_object(target);
  ASSERT_NE(safe_apply("call_target", caller, 1, ORIGIN_DRIVER), nullptr);

  auto* same_owner = vm_owner_access_trace(0);
  ASSERT_EQ(mapping_number(same_owner, "total_traced"), before_total);
  free_mapping(same_owner);

  vm_owner_set_id(target, "owner/test/call/target");
  push_object(target);
  ASSERT_NE(safe_apply("call_target", caller, 1, ORIGIN_DRIVER), nullptr);

  auto* trace = vm_owner_access_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "operation"), "call_other");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/call/shared");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/call/target");
  free_mapping(trace);

  vm_owner_clear_id(caller);
  vm_owner_clear_id(target);
  destruct_object(caller);
  destruct_object(target);
}

TEST_F(DriverTest, TestVmOwnerScheduleRoundsOwnersAndKeepsOwnerFifo) {
  const char* owner_a = "owner/test/schedule/a";
  const char* owner_b = "owner/test/schedule/b";
  auto a_first = vm_owner_enqueue_task(owner_a, "command", "a-first");
  auto a_second = vm_owner_enqueue_task(owner_a, "command", "a-second");
  auto b_first = vm_owner_enqueue_task(owner_b, "heartbeat", "b-first");

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* result = vm_owner_schedule(3);
  ASSERT_EQ(mapping_number(result, "dispatched"), 3);
  ASSERT_EQ(mapping_number(result, "remaining"), 0);
  auto* tasks = find_string_in_mapping(result, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks->type, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 3);
  ASSERT_EQ(mapping_number(tasks->u.arr->item[0].u.map, "task_id"), static_cast<long>(a_first));
  ASSERT_STREQ(mapping_string(tasks->u.arr->item[0].u.map, "task_key"), "a-first");
  ASSERT_EQ(mapping_number(tasks->u.arr->item[1].u.map, "task_id"), static_cast<long>(b_first));
  ASSERT_STREQ(mapping_string(tasks->u.arr->item[1].u.map, "task_key"), "b-first");
  ASSERT_EQ(mapping_number(tasks->u.arr->item[2].u.map, "task_id"), static_cast<long>(a_second));
  ASSERT_STREQ(mapping_string(tasks->u.arr->item[2].u.map, "task_key"), "a-second");
  free_mapping(result);
}

TEST_F(DriverTest, TestVmOwnerThreadExperimentIsOptInAndDispatchesMailboxTasks) {
  const char* owner = "owner/test/thread";

  vm_owner_thread_stop();
  auto* initial = vm_owner_thread_status();
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  ASSERT_EQ(mapping_number(initial, "enabled"), 0);
  ASSERT_EQ(mapping_number(initial, "thread_count"), 0);
  free_mapping(initial);

  auto task_id = vm_owner_enqueue_task(owner, "command", "threaded-look");
  ASSERT_GT(task_id, 0u);
  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 1);
  free_mapping(queued);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* drained = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(drained, "owner_queue_depth"), 0);
  free_mapping(drained);

  auto* trace = vm_owner_task_trace(2);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_GE(events->u.arr->size, 2);
  ASSERT_STREQ(mapping_string(events->u.arr->item[events->u.arr->size - 1].u.map, "state"), "thread_dispatched");
  ASSERT_EQ(mapping_number(events->u.arr->item[events->u.arr->size - 1].u.map, "task_id"),
            static_cast<long>(task_id));
  ASSERT_STREQ(mapping_string(events->u.arr->item[events->u.arr->size - 1].u.map, "owner_id"), owner);
  free_mapping(trace);

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "enabled"), 1);
  ASSERT_EQ(mapping_number(running, "thread_count"), 1);
  ASSERT_GE(mapping_number(running, "thread_dispatched"), 1);
  ASSERT_GE(mapping_number(running, "thread_context_bound"), 1);
  ASSERT_GE(mapping_number(running, "thread_object_store_isolated"), 1);
  ASSERT_GE(mapping_number(running, "thread_owner_bound"), 1);
  ASSERT_GE(mapping_number(running, "thread_owner_cleared"), 1);
  free_mapping(running);

  vm_owner_thread_stop();
  auto* stopped = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(stopped, "enabled"), 0);
  ASSERT_EQ(mapping_number(stopped, "thread_count"), 0);
  free_mapping(stopped);
}

TEST_F(DriverTest, TestVmOwnerThreadRejectsLpcAndKeepsMessageSpecs) {
  const char* owner = "owner/test/thread/safe-experiment";

  vm_owner_thread_stop();
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto lpc_task = vm_owner_enqueue_task(owner, "lpc", "off-main-dummy");
  auto state_task = vm_owner_enqueue_task(owner, "owner_state", "single-owner-state");
  auto message_task = vm_owner_enqueue_task(owner, "owner_message", "cross-owner-message");
  ASSERT_GT(lpc_task, 0u);
  ASSERT_GT(state_task, lpc_task);
  ASSERT_GT(message_task, state_task);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "thread_lpc_rejected"), 1);
  ASSERT_GE(mapping_number(running, "thread_owner_state_guarded"), 1);
  ASSERT_GE(mapping_number(running, "thread_message_dispatched"), 1);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(12);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int lpc_rejected = 0;
  int state_guarded = 0;
  int message_dispatched = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == static_cast<long>(lpc_task) &&
        std::string(mapping_string(event, "state")) == "thread_lpc_rejected") {
      lpc_rejected = 1;
    }
    if (mapping_number(event, "task_id") == static_cast<long>(state_task) &&
        std::string(mapping_string(event, "state")) == "thread_owner_state_guarded") {
      state_guarded = 1;
    }
    if (mapping_number(event, "task_id") == static_cast<long>(message_task) &&
        std::string(mapping_string(event, "state")) == "thread_message_dispatched") {
      message_dispatched = 1;
    }
  }
  ASSERT_EQ(lpc_rejected, 1);
  ASSERT_EQ(state_guarded, 1);
  ASSERT_EQ(message_dispatched, 1);
  free_mapping(trace);

  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmOwnerThreadGuardsControlledLpcProbeOffMain) {
  const char* owner = "owner/test/thread/lpc-probe";
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  object_t* probe = load_object_for_test("single/void");
  ASSERT_NE(probe, nullptr);
  vm_owner_set_id(probe, owner);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* submitted = vm_owner_lpc_probe(probe, owner, "owner_lpc_probe");
  auto task_id = mapping_number(submitted, "task_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_thread"), 1);
  ASSERT_EQ(mapping_number(submitted, "direct_cross_owner_write"), 0);
  ASSERT_STREQ(mapping_string(submitted, "task_type"), "lpc_probe");
  ASSERT_STREQ(mapping_string(submitted, "method"), "owner_lpc_probe");
  free_mapping(submitted);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "thread_lpc_probe_executed"), 0);
  ASSERT_GE(mapping_number(running, "thread_lpc_probe_guarded"), 1);
  ASSERT_EQ(mapping_number(running, "thread_lpc_probe_failed"), 0);
  ASSERT_GE(mapping_number(running, "thread_context_bound"), 1);
  ASSERT_GE(mapping_number(running, "thread_object_store_isolated"), 1);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(16);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int lpc_guarded = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == task_id &&
        std::string(mapping_string(event, "state")) == "thread_lpc_probe_guarded") {
      lpc_guarded = 1;
    }
  }
  ASSERT_EQ(lpc_guarded, 1);
  free_mapping(trace);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRunsRestrictedLpcCanaryOffMainDeferredRelease) {
  const char* owner = "owner/test/thread/lpc-canary";
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  object_t* probe = load_object_for_test("single/void");
  ASSERT_NE(probe, nullptr);
  vm_owner_set_id(probe, owner);
  auto owner_epoch = vm_owner_epoch(probe);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_thread_status();
  auto before_executed = mapping_number(before, "thread_lpc_canary_executed");
  auto before_succeeded = mapping_number(before, "thread_lpc_canary_succeeded");
  auto before_failed = mapping_number(before, "thread_lpc_canary_failed");
  auto before_rejected = mapping_number(before, "thread_lpc_canary_rejected");
  auto before_owner_cleared = mapping_number(before, "thread_owner_cleared");
  auto before_execution_cleared = mapping_number(before, "thread_execution_cleared");
  auto before_canary_flag_cleared = mapping_number(before, "thread_lpc_canary_flag_cleared");
  auto before_context_leaks = mapping_number(before, "thread_context_leak_detected");
  free_mapping(before);

  auto* submitted = vm_owner_lpc_canary(probe, owner, "owner_lpc_canary");
  auto task_id = mapping_number(submitted, "task_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_thread"), 1);
  ASSERT_EQ(mapping_number(submitted, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(submitted, "owner_epoch"), static_cast<long>(owner_epoch));
  ASSERT_STREQ(mapping_string(submitted, "task_type"), "lpc_canary");
  ASSERT_STREQ(mapping_string(submitted, "method"), "owner_lpc_canary");
  free_mapping(submitted);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "thread_lpc_canary_executed"), before_executed + 1);
  ASSERT_GE(mapping_number(running, "thread_lpc_canary_succeeded"), before_succeeded + 1);
  ASSERT_EQ(mapping_number(running, "thread_lpc_canary_failed"), before_failed);
  ASSERT_EQ(mapping_number(running, "thread_lpc_canary_rejected"), before_rejected);
  ASSERT_GE(mapping_number(running, "thread_owner_cleared"), before_owner_cleared + 1);
  ASSERT_GE(mapping_number(running, "thread_execution_cleared"), before_execution_cleared + 1);
  ASSERT_GE(mapping_number(running, "thread_lpc_canary_flag_cleared"), before_canary_flag_cleared + 1);
  ASSERT_EQ(mapping_number(running, "thread_context_leak_detected"), before_context_leaks);
  ASSERT_GE(mapping_number(running, "thread_context_bound"), 1);
  ASSERT_GE(mapping_number(running, "thread_object_store_isolated"), 1);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(16);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int canary_succeeded = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == task_id &&
        std::string(mapping_string(event, "state")) == "thread_lpc_canary_succeeded") {
      canary_succeeded = 1;
    }
  }
  ASSERT_EQ(canary_succeeded, 1);
  free_mapping(trace);

  vm_owner_thread_stop();
  auto* stopped = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(stopped, "deferred_target_releases"), 0);
  free_mapping(stopped);
  ASSERT_TRUE(vm_context_is_main_thread());
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRunsRegisteredLpcTaskWithMultipleWorkers) {
  const char* owner = "owner/test/thread/lpc-task";
  const char* other_owner = "owner/test/thread/lpc-task-other";
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  object_t* probe = load_object_for_test("single/void");
  ASSERT_NE(probe, nullptr);
  vm_owner_set_id(probe, owner);
  auto owner_epoch = vm_owner_epoch(probe);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* before = vm_owner_thread_status();
  auto before_executed = mapping_number(before, "thread_lpc_task_executed");
  auto before_succeeded = mapping_number(before, "thread_lpc_task_succeeded");
  auto before_failed = mapping_number(before, "thread_lpc_task_failed");
  auto before_rejected = mapping_number(before, "thread_lpc_task_rejected");
  auto before_context_leaks = mapping_number(before, "thread_context_leak_detected");
  free_mapping(before);

  auto* submitted = vm_owner_lpc_task(probe, owner, "owner_task_readonly");
  auto task_id = mapping_number(submitted, "task_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_thread"), 1);
  ASSERT_EQ(mapping_number(submitted, "registered_task"), 1);
  ASSERT_EQ(mapping_number(submitted, "ordinary_lpc_default_closed"), 1);
  ASSERT_EQ(mapping_number(submitted, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(submitted, "owner_epoch"), static_cast<long>(owner_epoch));
  ASSERT_STREQ(mapping_string(submitted, "task_type"), "lpc_task");
  ASSERT_STREQ(mapping_string(submitted, "method"), "owner_task_readonly");
  free_mapping(submitted);

  auto other_task = vm_owner_enqueue_task(other_owner, "owner_state", "other-owner-state");
  ASSERT_GT(other_task, 0u);

  vm_owner_thread_start(2);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto owner_depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    status = vm_owner_mailbox_status(other_owner);
    auto other_depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (owner_depth == 0 && other_depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "enabled"), 1);
  ASSERT_EQ(mapping_number(running, "thread_count"), 2);
  ASSERT_GE(mapping_number(running, "max_owner_threads"), 2);
  ASSERT_GE(mapping_number(running, "thread_lpc_task_executed"), before_executed + 1);
  ASSERT_GE(mapping_number(running, "thread_lpc_task_succeeded"), before_succeeded + 1);
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_failed"), before_failed);
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_rejected"), before_rejected);
  ASSERT_EQ(mapping_number(running, "thread_context_leak_detected"), before_context_leaks);
  ASSERT_EQ(mapping_number(running, "active_owners"), 0);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(24);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int lpc_task_succeeded = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == task_id &&
        std::string(mapping_string(event, "state")) == "thread_lpc_task_succeeded") {
      lpc_task_succeeded = 1;
    }
  }
  ASSERT_EQ(lpc_task_succeeded, 1);
  free_mapping(trace);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRejectsUnregisteredLpcTask) {
  const char* owner = "owner/test/thread/lpc-task-reject";
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  object_t* probe = load_object_for_test("single/void");
  ASSERT_NE(probe, nullptr);
  vm_owner_set_id(probe, owner);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  auto* before = vm_owner_thread_status();
  auto before_succeeded = mapping_number(before, "thread_lpc_task_succeeded");
  auto before_rejected = mapping_number(before, "thread_lpc_task_rejected");
  free_mapping(before);

  auto* submitted = vm_owner_lpc_task(probe, owner, "owner_task_unregistered");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_EQ(mapping_number(submitted, "registered_task"), 0);
  free_mapping(submitted);

  vm_owner_thread_start(2);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_succeeded"), before_succeeded);
  ASSERT_GE(mapping_number(running, "thread_lpc_task_rejected"), before_rejected + 1);
  free_mapping(running);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRunsRegisteredDomainLpcTasks) {
  const char* owner = "owner/test/thread/lpc-domain-task";
  const char* methods[] = {"owner_task_readonly", "owner_task_player",      "owner_task_room",
                           "owner_task_session",  "owner_task_item",        "owner_task_economy",
                           "owner_task_combat",   "owner_task_mail",        "owner_task_reward",
                           "owner_task_world",    "owner_task_persistence", "owner_task_team",
                           "owner_task_guild",    "owner_task_sect",        "owner_task_quest",
                           "owner_task_rank",     "owner_task_crafting",    "owner_task_life_skill"};
  const int method_count = static_cast<int>(sizeof(methods) / sizeof(methods[0]));
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  object_t* probe = load_object_for_test("single/void");
  ASSERT_NE(probe, nullptr);
  vm_owner_set_id(probe, owner);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  auto* before = vm_owner_thread_status();
  auto before_succeeded = mapping_number(before, "thread_lpc_task_succeeded");
  auto before_failed = mapping_number(before, "thread_lpc_task_failed");
  auto before_rejected = mapping_number(before, "thread_lpc_task_rejected");
  free_mapping(before);

  for (const auto* method : methods) {
    auto* submitted = vm_owner_lpc_task(probe, owner, method);
    ASSERT_EQ(mapping_number(submitted, "success"), 1);
    ASSERT_EQ(mapping_number(submitted, "registered_task"), 1) << method;
    free_mapping(submitted);
  }

  vm_owner_thread_start(4);
  for (int i = 0; i < 200; i++) {
    auto* status = vm_owner_thread_status();
    auto succeeded = mapping_number(status, "thread_lpc_task_succeeded");
    auto active = mapping_number(status, "active_owners");
    free_mapping(status);
    if (succeeded >= before_succeeded + method_count && active == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "enabled"), 1);
  ASSERT_EQ(mapping_number(running, "thread_count"), 4);
  ASSERT_GE(mapping_number(running, "thread_lpc_task_succeeded"), before_succeeded + method_count);
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_failed"), before_failed);
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_rejected"), before_rejected);
  ASSERT_EQ(mapping_number(running, "active_owners"), 0);
  free_mapping(running);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRejectsUnsafeLpcCanaryRequestsDeltas) {
  const char* owner = "owner/test/thread/lpc-canary-reject";
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  object_t* probe = load_object_for_test("single/void");
  ASSERT_NE(probe, nullptr);
  vm_owner_set_id(probe, owner);
  auto stale_epoch = vm_owner_epoch(probe);

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  auto* before = vm_owner_thread_status();
  auto before_succeeded = mapping_number(before, "thread_lpc_canary_succeeded");
  auto before_rejected = mapping_number(before, "thread_lpc_canary_rejected");
  auto before_owner_cleared = mapping_number(before, "thread_owner_cleared");
  auto before_execution_cleared = mapping_number(before, "thread_execution_cleared");
  auto before_canary_flag_cleared = mapping_number(before, "thread_lpc_canary_flag_cleared");
  auto before_context_leaks = mapping_number(before, "thread_context_leak_detected");
  free_mapping(before);

  auto* wrong_method = vm_owner_lpc_canary(probe, owner, "owner_lpc_probe");
  ASSERT_EQ(mapping_number(wrong_method, "success"), 1);
  free_mapping(wrong_method);
  vm_owner_set_id(probe, "owner/test/thread/lpc-canary-current");
  ASSERT_GT(vm_owner_epoch(probe), stale_epoch);
  auto* stale_owner = vm_owner_lpc_canary(probe, owner, "owner_lpc_canary");
  ASSERT_EQ(mapping_number(stale_owner, "success"), 1);
  free_mapping(stale_owner);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_thread_status();
    auto rejected = mapping_number(status, "thread_lpc_canary_rejected");
    free_mapping(status);
    if (rejected >= before_rejected + 2) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "thread_lpc_canary_rejected"), before_rejected + 2);
  ASSERT_EQ(mapping_number(running, "thread_lpc_canary_succeeded"), before_succeeded);
  ASSERT_GE(mapping_number(running, "thread_owner_cleared"), before_owner_cleared + 2);
  ASSERT_GE(mapping_number(running, "thread_execution_cleared"), before_execution_cleared + 2);
  ASSERT_GE(mapping_number(running, "thread_lpc_canary_flag_cleared"), before_canary_flag_cleared + 2);
  ASSERT_EQ(mapping_number(running, "thread_context_leak_detected"), before_context_leaks);
  free_mapping(running);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerMessageAndCommitTracesAreSpecOnly) {
  const char* source_owner = "owner/test/message/source";
  const char* target_owner = "owner/test/message/target";

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  free_mapping(vm_owner_purge_mailbox(target_owner));
  auto* submitted = vm_owner_submit_message(source_owner, target_owner, "room_snapshot", "room/v1");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_GT(mapping_number(submitted, "message_id"), 0);
  ASSERT_GT(mapping_number(submitted, "target_task_id"), 0);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_mailbox"), 1);
  ASSERT_EQ(mapping_number(submitted, "message_only_cross_owner"), 1);
  ASSERT_EQ(mapping_number(submitted, "direct_cross_owner_write"), 0);
  ASSERT_STREQ(mapping_string(submitted, "source_owner_id"), source_owner);
  ASSERT_STREQ(mapping_string(submitted, "target_owner_id"), target_owner);
  ASSERT_STREQ(mapping_string(submitted, "message_type"), "room_snapshot");

  auto message_id = mapping_number(submitted, "message_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  auto* queued = vm_owner_mailbox_status(target_owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 1);
  free_mapping(queued);

  auto* message_trace = vm_owner_message_trace(1);
  auto* message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  auto* message_event = message_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "message_id"), message_id);
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_EQ(mapping_number(message_event, "direct_cross_owner_write"), 0);
  ASSERT_STREQ(mapping_string(message_event, "state"), "message_submitted");
  free_mapping(message_trace);

  auto* commit = vm_owner_record_commit_boundary(source_owner, target_owner, "move_object", message_id, "prepared");
  ASSERT_EQ(mapping_number(commit, "success"), 1);
  ASSERT_EQ(mapping_number(commit, "message_id"), message_id);
  ASSERT_EQ(mapping_number(commit, "direct_write"), 0);
  ASSERT_EQ(mapping_number(commit, "commit_boundary_only"), 1);
  ASSERT_STREQ(mapping_string(commit, "operation"), "move_object");
  ASSERT_STREQ(mapping_string(commit, "state"), "prepared");
  free_mapping(commit);

  auto* commit_trace = vm_owner_commit_trace(1);
  auto* commit_events = find_string_in_mapping(commit_trace, "events");
  ASSERT_NE(commit_events, nullptr);
  ASSERT_EQ(commit_events->type, T_ARRAY);
  ASSERT_EQ(commit_events->u.arr->size, 1);
  auto* commit_event = commit_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(commit_event, "message_id"), message_id);
  ASSERT_EQ(mapping_number(commit_event, "direct_write"), 0);
  ASSERT_EQ(mapping_number(commit_event, "commit_boundary_only"), 1);
  ASSERT_STREQ(mapping_string(commit_event, "operation"), "move_object");
  free_mapping(commit_trace);

  auto* drained = vm_owner_drain_mailbox(target_owner, 1);
  auto* tasks = find_string_in_mapping(drained, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks->type, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  ASSERT_EQ(mapping_number(tasks->u.arr->item[0].u.map, "task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(tasks->u.arr->item[0].u.map, "task_type"), "owner_message");
  ASSERT_STREQ(mapping_string(tasks->u.arr->item[0].u.map, "task_key"), "room_snapshot");
  free_mapping(drained);
  free_mapping(submitted);
}

TEST_F(DriverTest, TestVmOwnerFuturePollTracksMessageCompletion) {
  const char* source_owner = "owner/test/future/source";
  const char* target_owner = "owner/test/future/target";

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  free_mapping(vm_owner_purge_mailbox(target_owner));
  auto* submitted = vm_owner_submit_message(source_owner, target_owner, "future_method", "future/payload");
  auto future_id = mapping_number(submitted, "future_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  ASSERT_GT(future_id, 0);
  ASSERT_GT(target_task_id, 0);

  auto* pending = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(pending, "success"), 1);
  ASSERT_EQ(mapping_number(pending, "future_id"), future_id);
  ASSERT_EQ(mapping_number(pending, "target_task_id"), target_task_id);
  ASSERT_EQ(mapping_number(pending, "requires_owner_message_completion"), 1);
  ASSERT_STREQ(mapping_string(pending, "state"), "pending");
  free_mapping(pending);

  free_mapping(vm_owner_drain_mailbox(target_owner, 1));
  auto* completed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(completed, "success"), 1);
  ASSERT_EQ(mapping_number(completed, "requires_owner_message_completion"), 0);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "future_method");
  free_mapping(completed);
  free_mapping(submitted);
}

TEST_F(DriverTest, TestVmOwnerFuturePollReportsUnknownFuture) {
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  auto* result = vm_owner_future_poll(999999999u);
  ASSERT_EQ(mapping_number(result, "success"), 0);
  ASSERT_EQ(mapping_number(result, "requires_owner_message_completion"), 0);
  ASSERT_STREQ(mapping_string(result, "state"), "unknown");
  free_mapping(result);
}

TEST_F(DriverTest, TestVmObjectHandleRejectsStaleOwnerEpoch) {
  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);

  vm_owner_set_id(obj, "owner/test/handle/a");
  auto handle = vm_object_handle(obj);
  ASSERT_TRUE(handle.valid);
  ASSERT_EQ(vm_object_handle_resolve(handle), obj);

  vm_owner_set_id(obj, "owner/test/handle/b");
  ASSERT_EQ(vm_object_handle_resolve(handle), nullptr);
  ASSERT_FALSE(vm_object_handle_is_current(handle));

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmObjectStoreShardRemovesDestructedObject) {
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/store/destruct");
  vm_object_store_register(obj);

  auto* before = vm_object_store_owner_status("owner/test/store/destruct");
  ASSERT_EQ(mapping_number(before, "objects"), 1);
  auto before_destructed = mapping_number(before, "destructed");
  free_mapping(before);

  destruct_object(obj);

  auto* after = vm_object_store_owner_status("owner/test/store/destruct");
  ASSERT_EQ(mapping_number(after, "objects"), 0);
  ASSERT_EQ(mapping_number(after, "destructed"), before_destructed + 1);
  free_mapping(after);
}

TEST_F(DriverTest, TestVmOwnerGuardFailsFastOnMismatch) {
  current_object = master_ob;
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  vm_owner_set_id(obj, "owner/test/guard");
  auto before_total = vm_owner_total_checks();
  auto before_mismatch = vm_owner_mismatch_checks();

  auto* result = vm_owner_guard(obj, "owner/test/guard");
  ASSERT_NE(result, nullptr);
  auto* success = find_string_in_mapping(result, "success");
  ASSERT_NE(success, nullptr);
  ASSERT_EQ(success->type, T_NUMBER);
  ASSERT_EQ(success->u.number, 1);
  free_mapping(result);
  ASSERT_EQ(vm_owner_total_checks(), before_total + 1);
  ASSERT_EQ(vm_owner_mismatch_checks(), before_mismatch);

  error_context_t econ{};
  save_context(&econ);
  try {
    vm_owner_guard(obj, "owner/test/other");
    pop_context(&econ);
    FAIL() << "vm_owner_guard should reject owner mismatch";
  } catch (...) {
    restore_context(&econ);
  }

  ASSERT_EQ(vm_owner_total_checks(), before_total + 2);
  ASSERT_EQ(vm_owner_mismatch_checks(), before_mismatch + 1);
  vm_owner_clear_id(obj);
}

TEST_F(DriverTest, TestVmWorkerRunsTasksInParallel) {
  auto result = vm_worker_benchmark(4, 80);
  ASSERT_GE(result.worker_count, 1);
  ASSERT_GE(result.max_parallel, std::min(2, result.worker_count));
  ASSERT_GT(result.checksum, 0u);
  ASSERT_LT(result.elapsed_ms, 260);
}

TEST_F(DriverTest, TestVmWorkerAsyncBenchmarkPollsResult) {
  auto task_id = vm_worker_submit_benchmark(4, 80);
  ASSERT_GT(task_id, 0u);

  VMWorkerTaskResult result;
  for (int i = 0; i < 100; i++) {
    result = vm_worker_poll_task(task_id);
    ASSERT_NE(result.state, VMWorkerTaskState::kUnknown);
    if (result.state == VMWorkerTaskState::kSucceeded) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ASSERT_EQ(result.state, VMWorkerTaskState::kSucceeded);
  ASSERT_GE(result.bench.worker_count, 1);
  ASSERT_GE(result.bench.max_parallel, std::min(2, result.bench.worker_count));
  ASSERT_GT(result.bench.checksum, 0u);
  ASSERT_LT(result.bench.elapsed_ms, 300);
  ASSERT_EQ(vm_worker_poll_task(task_id).state, VMWorkerTaskState::kUnknown);
}

TEST_F(DriverTest, TestVmWorkerActorKeysSerializePerOwner) {
  auto result = vm_worker_actor_benchmark(4, 2, 80);
  ASSERT_EQ(result.owners, 4);
  ASSERT_EQ(result.tasks_per_owner, 2);
  ASSERT_EQ(result.total_tasks, 8);
  ASSERT_GE(result.worker_count, 1);
  ASSERT_GE(result.max_parallel, std::min(2, result.worker_count));
  ASSERT_EQ(result.max_owner_parallel, 1);
  ASSERT_GT(result.checksum, 0u);
  ASSERT_LT(result.elapsed_ms, 360);
}

TEST_F(DriverTest, TestVmWorkerSnapshotDigestUsesOwnerKey) {
  auto result = vm_worker_snapshot_digest("actor/test", "{\"hp\":100,\"room\":\"test\"}", 16);
  ASSERT_EQ(result.owner_key, "actor/test");
  ASSERT_GE(result.worker_count, 1);
  ASSERT_EQ(result.input_bytes, 24u);
  ASSERT_EQ(result.repeat, 16);
  ASSERT_GT(result.checksum, 0u);
}

TEST_F(DriverTest, TestVmWorkerAsyncSnapshotDigestPollsResult) {
  auto task_id = vm_worker_submit_snapshot_digest("actor/async", "{\"hp\":100,\"room\":\"test\"}", 16);
  ASSERT_GT(task_id, 0u);

  VMWorkerTaskResult result;
  for (int i = 0; i < 100; i++) {
    result = vm_worker_poll_task(task_id);
    ASSERT_NE(result.state, VMWorkerTaskState::kUnknown);
    if (result.state == VMWorkerTaskState::kSucceeded) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ASSERT_EQ(result.state, VMWorkerTaskState::kSucceeded);
  ASSERT_EQ(result.type, "snapshot_digest");
  ASSERT_EQ(result.snapshot_digest.owner_key, "actor/async");
  ASSERT_GE(result.snapshot_digest.worker_count, 1);
  ASSERT_EQ(result.snapshot_digest.input_bytes, 24u);
  ASSERT_EQ(result.snapshot_digest.repeat, 16);
  ASSERT_GT(result.snapshot_digest.checksum, 0u);
  ASSERT_EQ(vm_worker_poll_task(task_id).state, VMWorkerTaskState::kUnknown);
}

TEST_F(DriverTest, TestVmWorkerActorScoreUsesSnapshotValues) {
  VMWorkerActorScoreInput input;
  input.hp = 80;
  input.max_hp = 100;
  input.mp = 50;
  input.max_mp = 100;
  input.ep = 100;
  input.max_ep = 100;

  auto result = vm_worker_actor_score("actor/score", input);
  ASSERT_EQ(result.owner_key, "actor/score");
  ASSERT_GE(result.worker_count, 1);
  ASSERT_EQ(result.hp_pct_bp, 8000);
  ASSERT_EQ(result.mp_pct_bp, 5000);
  ASSERT_EQ(result.ep_pct_bp, 10000);
  ASSERT_EQ(result.survival_score, 8000);
  ASSERT_EQ(result.resource_score, 7500);
  ASSERT_EQ(result.total_score, 7850);
  ASSERT_EQ(result.state, "strained");
}

TEST_F(DriverTest, TestVmWorkerAsyncActorScorePollsResult) {
  VMWorkerActorScoreInput input;
  input.hp = 80;
  input.max_hp = 100;
  input.mp = 50;
  input.max_mp = 100;
  input.ep = 100;
  input.max_ep = 100;

  auto task_id = vm_worker_submit_actor_score("actor/score-async", input);
  ASSERT_GT(task_id, 0u);

  VMWorkerTaskResult result;
  for (int i = 0; i < 100; i++) {
    result = vm_worker_poll_task(task_id);
    ASSERT_NE(result.state, VMWorkerTaskState::kUnknown);
    if (result.state == VMWorkerTaskState::kSucceeded) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ASSERT_EQ(result.state, VMWorkerTaskState::kSucceeded);
  ASSERT_EQ(result.type, "actor_score");
  ASSERT_EQ(result.actor_score.owner_key, "actor/score-async");
  ASSERT_GE(result.actor_score.worker_count, 1);
  ASSERT_EQ(result.actor_score.hp_pct_bp, 8000);
  ASSERT_EQ(result.actor_score.mp_pct_bp, 5000);
  ASSERT_EQ(result.actor_score.ep_pct_bp, 10000);
  ASSERT_EQ(result.actor_score.survival_score, 8000);
  ASSERT_EQ(result.actor_score.resource_score, 7500);
  ASSERT_EQ(result.actor_score.total_score, 7850);
  ASSERT_EQ(result.actor_score.state, "strained");
  ASSERT_EQ(vm_worker_poll_task(task_id).state, VMWorkerTaskState::kUnknown);
}

TEST_F(DriverTest, TestVmWorkerCombatDamageBindsHashToSnapshotAndFields) {
  VMWorkerCombatDamageInput input;
  input.attack = 100;
  input.defense = 50;
  input.armor_break = 0;
  input.critical = 0;
  input.critical_resist = 0;
  input.variance_roll_bp = 500;
  input.critical_roll = 100;
  input.snapshot_hash = 424242;

  auto result = vm_worker_combat_damage("combat/test", input);
  ASSERT_EQ(result.owner_key, "combat/test");
  ASSERT_GE(result.worker_count, 1);
  ASSERT_EQ(result.armor_break_bp, 0);
  ASSERT_EQ(result.reduction_bp, 500);
  ASSERT_EQ(result.critical_rate, 5);
  ASSERT_EQ(result.critical_hit, 0);
  ASSERT_EQ(result.damage, 95);
  ASSERT_EQ(result.snapshot_hash, 424242u);
  ASSERT_NE(result.input_hash, 424242u);

  auto changed_attack = input;
  changed_attack.attack = 101;
  auto changed_attack_result = vm_worker_combat_damage("combat/test", changed_attack);
  ASSERT_NE(changed_attack_result.input_hash, result.input_hash);

  auto changed_snapshot = input;
  changed_snapshot.snapshot_hash = 424243;
  auto changed_snapshot_result = vm_worker_combat_damage("combat/test", changed_snapshot);
  ASSERT_EQ(changed_snapshot_result.snapshot_hash, 424243u);
  ASSERT_NE(changed_snapshot_result.input_hash, result.input_hash);
}

TEST_F(DriverTest, TestVmWorkerCombatDamageNormalizesExtremeInput) {
  VMWorkerCombatDamageInput input;
  input.snapshot_hash = std::numeric_limits<int>::max();
  input.attack = std::numeric_limits<int>::max();
  input.defense = std::numeric_limits<int>::max();
  input.armor_break = std::numeric_limits<int>::max();
  input.critical = std::numeric_limits<int>::max();
  input.critical_resist = std::numeric_limits<int>::max();
  input.reduction_min_bp = 9000;
  input.reduction_max_bp = 1000;
  input.damage_base = std::numeric_limits<int>::max();
  input.damage_skill_factor_bp = std::numeric_limits<int>::max();
  input.damage_random_min_bp = 20000;
  input.damage_random_max_bp = 1000;
  input.variance_roll_bp = std::numeric_limits<int>::max();
  input.critical_min = 90;
  input.critical_max = 10;
  input.critical_roll = std::numeric_limits<int>::min();
  input.critical_damage_factor_bp = std::numeric_limits<int>::max();

  auto result = vm_worker_combat_damage("combat/extreme", input);
  ASSERT_EQ(result.owner_key, "combat/extreme");
  ASSERT_EQ(result.snapshot_hash, static_cast<uint64_t>(std::numeric_limits<int>::max()));
  ASSERT_GE(result.damage, 0);
  ASSERT_GE(result.reduction_bp, 1000);
  ASSERT_LE(result.reduction_bp, 9000);
  ASSERT_GE(result.critical_rate, 10);
  ASSERT_LE(result.critical_rate, 90);
  ASSERT_GT(result.input_hash, 0u);
}

TEST_F(DriverTest, TestVmWorkerAsyncCombatDamagePollsResult) {
  VMWorkerCombatDamageInput input;
  input.attack = 100;
  input.defense = 50;
  input.variance_roll_bp = 500;
  input.critical_roll = 100;
  input.snapshot_hash = 31337;

  auto task_id = vm_worker_submit_combat_damage_v2("combat/async", input, 1000, 5000);
  ASSERT_GT(task_id, 0u);

  VMWorkerTaskResult result;
  for (int i = 0; i < 100; i++) {
    result = vm_worker_poll_task(task_id);
    ASSERT_NE(result.state, VMWorkerTaskState::kUnknown);
    if (result.state == VMWorkerTaskState::kSucceeded) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ASSERT_EQ(result.state, VMWorkerTaskState::kSucceeded);
  ASSERT_EQ(result.type, "combat_damage");
  ASSERT_EQ(result.envelope.task_type, "combat_damage");
  ASSERT_EQ(result.envelope.owner_key, "combat/async");
  ASSERT_EQ(result.envelope.input_hash, result.combat_damage.input_hash);
  ASSERT_EQ(result.combat_damage.owner_key, "combat/async");
  ASSERT_EQ(result.combat_damage.damage, 95);
  ASSERT_EQ(result.combat_damage.critical_hit, 0);
  ASSERT_EQ(result.combat_damage.snapshot_hash, 31337u);
  ASSERT_NE(result.combat_damage.input_hash, 31337u);
}

TEST_F(DriverTest, TestVmWorkerV2EnvelopeKeepsResultUntilTtl) {
  auto task_id = vm_worker_submit_snapshot_digest_v2("actor/envelope", "{\"hp\":100}", 8, 1000, 5000);
  ASSERT_GT(task_id, 0u);

  VMWorkerTaskResult result;
  for (int i = 0; i < 100; i++) {
    result = vm_worker_poll_task(task_id);
    ASSERT_NE(result.state, VMWorkerTaskState::kUnknown);
    if (result.state == VMWorkerTaskState::kSucceeded) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ASSERT_EQ(result.state, VMWorkerTaskState::kSucceeded);
  ASSERT_EQ(result.envelope.task_id, task_id);
  ASSERT_EQ(result.envelope.task_type, "snapshot_digest");
  ASSERT_EQ(result.envelope.owner_key, "actor/envelope");
  ASSERT_GT(result.envelope.input_hash, 0u);
  ASSERT_GT(result.envelope.submitted_at_ms, 0u);
  ASSERT_GE(result.envelope.completed_at_ms, result.envelope.submitted_at_ms);
  ASSERT_GT(result.envelope.expires_at_ms, result.envelope.completed_at_ms);
  ASSERT_EQ(result.envelope.timeout_ms, 1000);
  ASSERT_EQ(result.envelope.ttl_ms, 5000);
  ASSERT_EQ(vm_worker_poll_task(task_id).state, VMWorkerTaskState::kSucceeded);
}

TEST_F(DriverTest, TestVmWorkerV2TimeoutFailsPendingTask) {
  auto task_id = vm_worker_submit_benchmark_v2(64, 80, 1, 5000);
  ASSERT_GT(task_id, 0u);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  auto result = vm_worker_poll_task(task_id);
  ASSERT_EQ(result.state, VMWorkerTaskState::kFailed);
  ASSERT_EQ(result.error, "worker task timed out");
  ASSERT_EQ(result.envelope.task_id, task_id);
  ASSERT_EQ(result.envelope.timeout_ms, 1);
  ASSERT_GT(result.envelope.completed_at_ms, 0u);
}

TEST_F(DriverTest, TestVmWorkerPollTasksReturnsBatchResults) {
  VMWorkerActorScoreInput input;
  input.hp = 100;
  input.max_hp = 100;
  input.mp = 80;
  input.max_mp = 100;
  input.ep = 60;
  input.max_ep = 100;

  std::vector<uint64_t> task_ids;
  task_ids.push_back(vm_worker_submit_actor_score_v2("actor/batch-a", input, 1000, 5000));
  task_ids.push_back(vm_worker_submit_actor_score_v2("actor/batch-b", input, 1000, 5000));

  std::vector<VMWorkerTaskResult> results;
  for (int i = 0; i < 100; i++) {
    results = vm_worker_poll_tasks(task_ids);
    ASSERT_EQ(results.size(), 2u);
    if (results[0].state == VMWorkerTaskState::kSucceeded &&
        results[1].state == VMWorkerTaskState::kSucceeded) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  ASSERT_EQ(results[0].state, VMWorkerTaskState::kSucceeded);
  ASSERT_EQ(results[1].state, VMWorkerTaskState::kSucceeded);
  ASSERT_EQ(results[0].actor_score.owner_key, "actor/batch-a");
  ASSERT_EQ(results[1].actor_score.owner_key, "actor/batch-b");
}

TEST_F(DriverTest, TestInMemoryCompileFile) {
  program_t* prog = nullptr;

  std::istringstream source("void test() {}");
  auto stream = std::make_unique<IStreamLexStream>(source);
  prog = compile_file(std::move(stream), "test");

  ASSERT_NE(prog, nullptr);
  deallocate_program(prog);
}

TEST_F(DriverTest, TestInMemoryCompileFileFail) {
  program_t* prog = nullptr;
  std::istringstream source("aksdljfaljdfiasejfaeslfjsaef");
  auto stream = std::make_unique<IStreamLexStream>(source);
  prog = compile_file(std::move(stream), "test");

  ASSERT_EQ(prog, nullptr);
}

TEST_F(DriverTest, TestValidLPC_FunctionDeafultArgument) {
  const char* source = R"(
// default case
void test1() {
}

// default case
void test2(int a, int b) {
  ASSERT_EQ(a, 1);
  ASSERT_EQ(b, 2);
}

// varargs
void test3(int a, int* b ...) {
  ASSERT_EQ(a, 1);
  ASSERT_EQ(b[0], 2);
  ASSERT_EQ(b[1], 3);
  ASSERT_EQ(b[2], 4);
  ASSERT_EQ(b[3], 5);
}

// can have multiple trailing arguments with a FP for calculating default value
void test4(int a, string b: (: "str" :), int c: (: 0 :)) {
  switch(a) {
    case 1: {
      ASSERT_EQ("str", b);
      ASSERT_EQ(0, c);
      break;
    }
    case 2: {
      ASSERT_EQ("aaa", b);
      ASSERT_EQ(0, c);
      break;
    }
    case 3: {
      ASSERT_EQ("bbb", b);
      ASSERT_EQ(3, c);
      break;
    }
  }
}

void do_tests() {
    test1();
    test2(1, 2);
    test3(1, 2, 3, 4, 5);
    // direct call
    test4(1);
    test4(2, "aaa");
    test4(3, "bbb", 3);
    // apply
    this_object()->test4(1);
    this_object()->test4(2, "aaa");
    this_object()->test4(3, "bbb", 3);
}
  )";
  std::istringstream iss(source);
  auto stream = std::make_unique<IStreamLexStream>(iss);
  auto *prog = compile_file(std::move(stream), "test");

  ASSERT_NE(prog, nullptr);
  dump_prog(prog, stdout, 1 | 2);
  deallocate_program(prog);
}


TEST_F(DriverTest, TestLPC_FunctionInherit) {
    // Load the inherited object first
    error_context_t econ{};
    save_context(&econ);
    try {
    auto obj = find_object("/single/tests/compiler/function");
    ASSERT_NE(obj , nullptr);

    auto obj2 = find_object("/single/tests/compiler/function_inherit");
    ASSERT_NE(obj2 , nullptr);

    auto obj3 = find_object("/single/tests/compiler/function_inherit_2");
    ASSERT_NE(obj3 , nullptr);

    dump_prog(obj3->prog, stdout, 1 | 2);
    } catch (...) {
        restore_context(&econ);
        FAIL();
    }
    pop_context(&econ);

}

namespace {

svalue_t *call_lpc_method(object_t *ob, const char *method, int num_args = 0) {
  save_command_giver(ob);
  set_eval(max_eval_cost);
  auto *ret = safe_apply(method, ob, num_args, ORIGIN_DRIVER);
  restore_command_giver();
  return ret;
}

object_t *create_gateway_session_for_test(const char *session_id, const char *login_file) {
  svalue_t data{};
  data.type = T_MAPPING;
  data.u.map = allocate_mapping(1);
  add_mapping_string(data.u.map, "ip", "127.0.0.1");
  copy_and_push_string(login_file);
  safe_apply("set_test_login_ob", master_ob, 1, ORIGIN_DRIVER);
  auto *ob = gateway_create_session_internal(session_id, &data, "127.0.0.1", 6040, -1);
  safe_apply("reset_test_login_ob", master_ob, 0, ORIGIN_DRIVER);
  free_svalue(&data, "create_gateway_session_for_test");
  return ob;
}

}  // namespace

TEST_F(DriverTest, TestGatewaySessionDestroyCallsGatewayDisconnected) {
  auto *ob = create_gateway_session_for_test("gw-test-destroy", "/clone/gateway_login_example");
  ASSERT_NE(ob, nullptr);
  ASSERT_NE(ob->interactive, nullptr);
  ASSERT_TRUE(gateway_is_session(ob));

  add_ref(ob, "TestGatewaySessionDestroyCallsGatewayDisconnected");

  ASSERT_EQ(gateway_destroy_session_internal("gw-test-destroy", "client_close", "bye"), 1);
  ASSERT_EQ(ob->interactive, nullptr);

  auto *code = call_lpc_method(ob, "query_last_disconnect_code");
  ASSERT_NE(code, nullptr);
  ASSERT_EQ(code->type, T_STRING);
  ASSERT_STREQ(code->u.string, "client_close");

  auto *text = call_lpc_method(ob, "query_last_disconnect_text");
  ASSERT_NE(text, nullptr);
  ASSERT_EQ(text->type, T_STRING);
  ASSERT_STREQ(text->u.string, "bye");

  destruct_object(ob);
  free_object(&ob, "TestGatewaySessionDestroyCallsGatewayDisconnected");
}

TEST_F(DriverTest, TestGatewaySessionExecLogonKeepsSessionLookupWorking) {
  auto *ob = create_gateway_session_for_test("gw-test-exec", "/clone/gateway_login_exec_example");
  ASSERT_NE(ob, nullptr);
  ASSERT_NE(ob->interactive, nullptr);
  ASSERT_TRUE(gateway_is_session(ob));
  ASSERT_NE(std::string(ob->obname).find("clone/gateway_exec_user"), std::string::npos);

  auto *info = call_lpc_method(ob, "query_gateway_session_snapshot");
  ASSERT_NE(info, nullptr);
  ASSERT_EQ(info->type, T_MAPPING);

  add_ref(ob, "TestGatewaySessionExecLogonKeepsSessionLookupWorking");
  ASSERT_EQ(gateway_destroy_session_internal("gw-test-exec", "test_done", "done"), 1);
  ASSERT_EQ(ob->interactive, nullptr);
  destruct_object(ob);
  free_object(&ob, "TestGatewaySessionExecLogonKeepsSessionLookupWorking");
}
