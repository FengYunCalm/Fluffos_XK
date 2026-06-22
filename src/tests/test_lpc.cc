#include <gtest/gtest.h>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "base/package_api.h"

#include "backend.h"
#include "interactive.h"
#include "mainlib.h"
#include "user.h"

#include "compiler/internal/compiler.h"
#include "packages/core/heartbeat.h"
#include "packages/gateway/gateway.h"
#include "vm/context.h"
#include "vm/internal/base/array.h"
#include "vm/internal/otable.h"
#include "vm/internal/simulate.h"
#include "vm/object_handle.h"
#include "vm/owner.h"
#include "vm/worker.h"

extern uint64_t vm_owner_enqueue_test_main_required_message(const char* owner_id, const char* task_key);
extern uint64_t vm_owner_enqueue_command_frame_restore(object_t* target);
extern bool vm_object_store_test_support_remove_live_object_ref_for_bridge_readiness(const char* owner_id,
                                                                                    uint64_t object_id);
extern int replace_interactive(object_t *ob, object_t *obfrom);
extern bool gateway_dispatch_message_for_test(int fd, const char *payload);

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

TEST_F(DriverTest, TestVmContextResetClearsThreadExecutionState) {
  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);

  vm_context_set_current_object(vm_context(), obj);
  vm_context_set_command_giver(vm_context(), obj);
  vm_context_set_current_interactive(vm_context(), obj);
  vm_context_set_previous_object(vm_context(), obj);
  vm_context_set_current_program(vm_context(), obj->prog);
  vm_context_set_caller_type(vm_context(), ORIGIN_DRIVER);
  vm_context_set_call_origin(vm_context(), ORIGIN_DRIVER);
  vm_context_set_inherit_offsets(vm_context(), 3, 5);
  vm_context_set_stack_temporary_depth(vm_context(), 7);

  vm_context_reset_execution(vm_context());
  auto execution = vm_context_capture_execution();

  ASSERT_EQ(execution.current_object, nullptr);
  ASSERT_EQ(execution.command_giver, nullptr);
  ASSERT_EQ(execution.current_interactive, nullptr);
  ASSERT_EQ(execution.previous_ob, nullptr);
  ASSERT_EQ(execution.current_prog, nullptr);
  ASSERT_EQ(execution.caller_type, 0);
  ASSERT_EQ(execution.call_origin, 0);
  ASSERT_EQ(execution.function_index_offset, 0);
  ASSERT_EQ(execution.variable_index_offset, 0);
  ASSERT_EQ(execution.stack_in_use_as_temporary, 0);
}

TEST_F(DriverTest, TestDetachedVmContextSettersDoNotClobberThreadState) {
  object_t* first = find_object("single/master.c");
  object_t* second = find_object("single/simul_efun.c");
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);

  current_object = master_ob;
  command_giver = nullptr;
  current_interactive = nullptr;
  previous_ob = nullptr;
  current_prog = nullptr;
  caller_type = 0;
  call_origin = 0;
  function_index_offset = 0;
  variable_index_offset = 0;
#ifdef DEBUG
  stack_in_use_as_temporary = 0;
#endif
  current_error_context = nullptr;
  too_deep_error = 0;
  max_eval_error = 0;
  vm_context_sync_execution(vm_context());

  VMContext detached;
  error_context_t error_context{};
  vm_context_set_current_object(detached, first);
  vm_context_set_command_giver(detached, first);
  vm_context_set_current_interactive(detached, first);
  vm_context_set_previous_object(detached, second);
  vm_context_set_current_program(detached, first->prog);
  vm_context_set_caller_type(detached, ORIGIN_DRIVER);
  vm_context_set_call_origin(detached, ORIGIN_EFUN);
  vm_context_set_inherit_offsets(detached, 9, 13);
  vm_context_set_stack_temporary_depth(detached, 4);
  vm_context_set_current_error_context(detached, &error_context);
  vm_context_set_error_flags(detached, 1, 1);

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
  ASSERT_EQ(current_error_context, nullptr);
  ASSERT_EQ(too_deep_error, 0);
  ASSERT_EQ(max_eval_error, 0);

  ASSERT_EQ(detached.execution.current_object, first);
  ASSERT_EQ(detached.execution.command_giver, first);
  ASSERT_EQ(detached.execution.current_interactive, first);
  ASSERT_EQ(detached.execution.previous_ob, second);
  ASSERT_EQ(detached.execution.current_prog, first->prog);
  ASSERT_EQ(detached.execution.caller_type, ORIGIN_DRIVER);
  ASSERT_EQ(detached.execution.call_origin, ORIGIN_EFUN);
  ASSERT_EQ(detached.execution.function_index_offset, 9);
  ASSERT_EQ(detached.execution.variable_index_offset, 13);
  ASSERT_EQ(detached.execution.stack_in_use_as_temporary, 4);
  ASSERT_EQ(detached.error.current_error_context, &error_context);
  ASSERT_EQ(detached.error.too_deep_error, 1);
  ASSERT_EQ(detached.error.max_eval_error, 1);

  VMExecutionState applied;
  applied.current_object = second;
  applied.current_prog = second->prog;
  applied.previous_ob = first;
  applied.caller_type = ORIGIN_CALL_OTHER;
  vm_context_apply_execution(detached, applied);
  ASSERT_EQ(current_object, master_ob);
  ASSERT_EQ(current_prog, nullptr);
  ASSERT_EQ(previous_ob, nullptr);
  ASSERT_EQ(caller_type, 0);
  ASSERT_EQ(detached.execution.current_object, second);
  ASSERT_EQ(detached.execution.current_prog, second->prog);
  ASSERT_EQ(detached.execution.previous_ob, first);
  ASSERT_EQ(detached.execution.caller_type, ORIGIN_CALL_OTHER);

  detached.execution.current_object = first;
  vm_context_sync_execution(detached);
  ASSERT_EQ(detached.execution.current_object, first);

  vm_context_reset_execution(detached);
  ASSERT_EQ(current_object, master_ob);
  ASSERT_EQ(detached.execution.current_object, nullptr);
  ASSERT_EQ(detached.execution.current_prog, nullptr);
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

TEST_F(DriverTest, TestVmOwnerQueryObjectSnapshotOnlyForCrossOwnerTargets) {
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

  current_object = source;
  vm_owner_set_id(source, "owner/test/snapshot/source");
  vm_owner_set_id(target, "owner/test/snapshot/source");
  ASSERT_EQ(vm_owner_query_object_snapshot(target, vm_owner_id(source)), nullptr);

  vm_owner_clear_id(target);
  ASSERT_EQ(vm_owner_query_object_snapshot(target, vm_owner_id(source)), nullptr);

  vm_owner_set_id(target, "owner/test/snapshot/target");
  auto* snapshot = vm_owner_query_object_snapshot(target, vm_owner_id(source));
  ASSERT_NE(snapshot, nullptr);
  ASSERT_STREQ(mapping_string(snapshot, "object_name"), target->obname);
  ASSERT_STREQ(mapping_string(snapshot, "owner_id"), "owner/test/snapshot/target");
  ASSERT_EQ(mapping_number(snapshot, "living"), 0);
  ASSERT_EQ(mapping_number(snapshot, "living_flag"), 0);
  ASSERT_EQ(mapping_number(snapshot, "has_is_npc"), 0);
  ASSERT_EQ(mapping_number(snapshot, "has_is_player"), 0);
  ASSERT_EQ(mapping_number(snapshot, "has_is_character"), 0);
  free_mapping(snapshot);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestLoadedSingletonUsesDefaultOwnerInsideOwnerScope) {
  if (auto* existing = find_object("single/owner_singleton.c")) {
    destruct_object(existing);
  }

  VMOwnerScope scope(vm_context(), "owner/test/player", 1);
  current_object = master_ob;
  auto* obj = load_object_for_test("single/owner_singleton.c");

  ASSERT_NE(obj, nullptr);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(obj));
  destruct_object(obj);
}

TEST_F(DriverTest, TestCommandSingletonUsesDefaultOwnerInsidePlayerOwnerScope) {
  if (auto* existing = find_object("command/refs.c")) {
    destruct_object(existing);
  }
  current_object = master_ob;
  auto* player = clone_object("single/owner_singleton", 0);
  ASSERT_NE(player, nullptr);
  vm_owner_set_id(player, "owner/test/command/player");

  VMOwnerScope scope(vm_context(), vm_owner_id(player), vm_owner_epoch(player));
  current_object = player;
  auto* command = load_object_for_test("command/refs.c");

  ASSERT_NE(command, nullptr);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(command));
  ASSERT_NE(vm_owner_id(command), vm_owner_id(player));

  destruct_object(command);
  destruct_object(player);
}

TEST_F(DriverTest, TestStdServiceUsesDefaultOwnerInsidePlayerOwnerScope) {
  if (auto* existing = find_object("std/database.c")) {
    destruct_object(existing);
  }
  current_object = master_ob;
  auto* player = clone_object("single/owner_singleton", 0);
  ASSERT_NE(player, nullptr);
  vm_owner_set_id(player, "owner/test/std-service/player");

  VMOwnerScope scope(vm_context(), vm_owner_id(player), vm_owner_epoch(player));
  current_object = player;
  auto* service = load_object_for_test("std/database.c");

  ASSERT_NE(service, nullptr);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(service));
  ASSERT_NE(vm_owner_id(service), vm_owner_id(player));

  destruct_object(service);
  destruct_object(player);
}

TEST_F(DriverTest, TestSharedStdServicesUseDefaultOwnerInsidePlayerOwnerScope) {
  const char* service_paths[] = {"std/http.c", "std/present_clone.c", "std/telnet.c"};
  for (auto* path : service_paths) {
    if (auto* existing = find_object(path)) {
      destruct_object(existing);
    }
  }

  current_object = master_ob;
  auto* player = clone_object("single/owner_singleton", 0);
  ASSERT_NE(player, nullptr);
  vm_owner_set_id(player, "owner/test/shared-service/player");

  VMOwnerScope scope(vm_context(), vm_owner_id(player), vm_owner_epoch(player));
  current_object = player;

  for (auto* path : service_paths) {
    auto* service = load_object_for_test(path);
    ASSERT_NE(service, nullptr) << path;
    ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(service)) << path;
    ASSERT_NE(vm_owner_id(service), vm_owner_id(player)) << path;
  }

  for (auto* path : service_paths) {
    if (auto* service = find_object(path)) {
      destruct_object(service);
    }
  }
  destruct_object(player);
}

TEST_F(DriverTest, TestSimulEfunSingletonKeepsDefaultOwnerInsidePlayerOwnerScope) {
  current_object = master_ob;
  auto* player = clone_object("single/owner_singleton", 0);
  ASSERT_NE(player, nullptr);
  vm_owner_set_id(player, "owner/test/simul-efun/player");

  VMOwnerScope scope(vm_context(), vm_owner_id(player), vm_owner_epoch(player));
  current_object = player;

  const char* singleton_paths[] = {"single/simul_efun.c", "std/all_environment.c", "std/json.c"};
  for (auto* path : singleton_paths) {
    auto* service = load_object_for_test(path);
    ASSERT_NE(service, nullptr) << path;
    ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(service)) << path;
    ASSERT_NE(vm_owner_id(service), vm_owner_id(player)) << path;
  }

  destruct_object(player);
}

TEST_F(DriverTest, TestVirtualObjectUsesDefaultOwnerAndUpdatesStorePath) {
  if (auto* existing = find_object("test/virtual")) {
    destruct_object(existing);
  }
  if (auto* source = find_object("single/void.c")) {
    destruct_object(source);
  }

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

  current_object = master_ob;
  auto* player = clone_object("single/owner_singleton", 0);
  ASSERT_NE(player, nullptr);
  vm_owner_set_id(player, "owner/test/virtual/player");

  VMOwnerScope scope(vm_context(), vm_owner_id(player), vm_owner_epoch(player));
  current_object = player;
  auto* virtual_object = load_object_for_test("test/virtual");
  ASSERT_NE(virtual_object, nullptr);
  ASSERT_TRUE((virtual_object->flags & O_VIRTUAL) != 0);
  ASSERT_STREQ("test/virtual", virtual_object->obname);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(virtual_object));
  ASSERT_NE(vm_owner_id(virtual_object), vm_owner_id(player));

  auto handle = vm_object_handle(virtual_object);
  ASSERT_TRUE(handle.valid);
  auto handle_resolve = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(handle_resolve.object, virtual_object);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(handle_resolve.status), "current");
  ASSERT_TRUE(handle_resolve.resolved_via_owner_local_store);
  ASSERT_FALSE(handle_resolve.global_live_object_found);
  ASSERT_FALSE(handle_resolve.resolved_via_global_index);
  ASSERT_EQ(vm_object_handle_resolve(handle), virtual_object);
  ASSERT_STREQ(handle.object_path.c_str(), "test/virtual");
  ASSERT_EQ(vm_object_store_owner_resolve(vm_owner_default_id(), handle.object_id), virtual_object);
  ASSERT_EQ(vm_object_store_owner_path_resolve(vm_owner_default_id(), "test/virtual"), virtual_object);
  auto* handle_status = vm_object_handle_status(virtual_object);
  ASSERT_EQ(mapping_number(handle_status, "current"), 1);
  ASSERT_STREQ(mapping_string(handle_status, "resolve_status"), "current");
  ASSERT_EQ(mapping_number(handle_status, "resolved_via_owner_local_store"), 1);
  ASSERT_EQ(mapping_number(handle_status, "diagnosed_via_owner_local_store"), 0);
  ASSERT_EQ(mapping_number(handle_status, "diagnosed_via_owner_local_path_index"), 0);
  ASSERT_EQ(mapping_number(handle_status, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(handle_status, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(handle_status, "global_live_object_found"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_live_object_source"), "");
  auto handle_live_object_bridge_ready = mapping_number(handle_status, "global_live_object_bridge_retirement_ready");
  ASSERT_TRUE(handle_live_object_bridge_ready == 0 || handle_live_object_bridge_ready == 1);
  ASSERT_EQ(mapping_number(handle_status, "global_live_object_fallback_skipped"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_live_object_fallback_reason"), "");
  ASSERT_EQ(mapping_number(handle_status, "global_record_found"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_record_source"), "");
  ASSERT_EQ(mapping_number(handle_status, "global_record_id_scan_bridge_used"), 0);
  ASSERT_EQ(mapping_number(handle_status, "global_record_id_scan_bridge_found"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_record_id_scan_bridge_source"), "");
  ASSERT_EQ(mapping_number(handle_status, "global_record_id_scan_bridge_skipped"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_record_id_scan_bridge_skip_reason"), "");
  ASSERT_EQ(mapping_number(handle_status, "global_record_pointer_bridge_used"), 0);
  ASSERT_EQ(mapping_number(handle_status, "global_record_pointer_bridge_found"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_record_pointer_bridge_source"), "");
  ASSERT_EQ(mapping_number(handle_status, "global_record_pointer_bridge_skipped"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_record_pointer_bridge_skip_reason"), "");
  auto handle_record_bridge_ready = mapping_number(handle_status, "global_record_bridge_retirement_ready");
  ASSERT_TRUE(handle_record_bridge_ready == 0 || handle_record_bridge_ready == 1);
  ASSERT_EQ(mapping_number(handle_status, "global_record_fallback_skipped"), 0);
  ASSERT_STREQ(mapping_string(handle_status, "global_record_fallback_reason"), "");
  ASSERT_EQ(mapping_number(handle_status, "resolved_via_global_index"), 0);
  free_mapping(handle_status);

  auto* owner_status = vm_object_store_owner_status(vm_owner_default_id());
  auto* directory = find_string_in_mapping(owner_status, "object_directory");
  ASSERT_NE(directory, nullptr);
  ASSERT_EQ(directory->type, T_ARRAY);
  bool found_virtual_record = false;
  for (int i = 0; i < directory->u.arr->size; i++) {
    auto* record = directory->u.arr->item[i].u.map;
    if (std::string(mapping_string(record, "object_path")) == "test/virtual") {
      found_virtual_record = true;
      ASSERT_EQ(mapping_number(record, "object_id"), static_cast<long>(handle.object_id));
      ASSERT_STREQ(mapping_string(record, "owner_id"), vm_owner_default_id());
      ASSERT_EQ(mapping_number(record, "owner_epoch"), static_cast<long>(vm_owner_epoch(virtual_object)));
      ASSERT_EQ(mapping_number(record, "destructed"), 0);
      ASSERT_EQ(mapping_number(record, "live"), 1);
      ASSERT_EQ(mapping_number(record, "owner_local_object_ref_entry"), 1);
      ASSERT_STREQ(mapping_string(record, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
      ASSERT_EQ(mapping_number(record, "owner_local_object_ref_index_entry"), 1);
      ASSERT_STREQ(mapping_string(record, "owner_local_object_ref_index_source"),
                   "vm_object_shard.local_object_index");
      ASSERT_EQ(mapping_number(record, "owner_local_path_index_entry"), 1);
      ASSERT_STREQ(mapping_string(record, "owner_local_path_index_source"), "vm_object_shard.object_path_index");
      break;
    }
  }
  ASSERT_TRUE(found_virtual_record);
  free_mapping(owner_status);
  auto* virtual_lookup = vm_object_store_owner_lookup_status(vm_owner_default_id(), handle.object_id);
  ASSERT_EQ(mapping_number(virtual_lookup, "success"), 1);
  ASSERT_EQ(mapping_number(virtual_lookup, "found"), 1);
  ASSERT_EQ(mapping_number(virtual_lookup, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_lookup, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(virtual_lookup, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_lookup, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(virtual_lookup, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_lookup, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(virtual_lookup, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_lookup, "owner_local_resolve_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(virtual_lookup, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(virtual_lookup, "owner_local_destructed_path_index_found"), 0);
  ASSERT_STREQ(mapping_string(virtual_lookup, "owner_local_path_index_source"), "vm_object_shard.object_path_index");
  ASSERT_STREQ(mapping_string(virtual_lookup, "object_path"), "test/virtual");
  free_mapping(virtual_lookup);
  auto* virtual_path_lookup = vm_object_store_owner_path_lookup_status(vm_owner_default_id(), "test/virtual");
  ASSERT_EQ(mapping_number(virtual_path_lookup, "success"), 1);
  ASSERT_EQ(mapping_number(virtual_path_lookup, "record_found"), 1);
  ASSERT_EQ(mapping_number(virtual_path_lookup, "found"), 1);
  ASSERT_EQ(mapping_number(virtual_path_lookup, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(virtual_path_lookup, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_path_lookup, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(virtual_path_lookup, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_path_lookup, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(virtual_path_lookup, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_path_lookup, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(virtual_path_lookup, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(virtual_path_lookup, "owner_local_resolve_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(virtual_path_lookup, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(virtual_path_lookup, "owner_local_destructed_path_index_found"), 0);
  ASSERT_STREQ(mapping_string(virtual_path_lookup, "owner_local_path_index_source"),
               "vm_object_shard.object_path_index");
  ASSERT_STREQ(mapping_string(virtual_path_lookup, "record_owner_id"), vm_owner_default_id());
  free_mapping(virtual_path_lookup);

  destruct_object(virtual_object);
  destruct_object(player);
}

TEST_F(DriverTest, TestCloneOwnerUsesCurrentObjectNotAmbientScope) {
  if (auto* existing = find_object("single/owner_singleton.c")) {
    destruct_object(existing);
  }
  auto* prototype = load_object_for_test("single/owner_singleton.c");
  ASSERT_NE(prototype, nullptr);

  VMOwnerScope scope(vm_context(), "owner/test/player", 1);
  current_object = master_ob;
  auto* shared_clone = clone_object("single/owner_singleton", 0);
  ASSERT_NE(shared_clone, nullptr);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(shared_clone));
  destruct_object(shared_clone);

  vm_owner_set_id(prototype, "owner/test/factory");
  current_object = prototype;
  auto* owned_clone = clone_object("single/owner_singleton", 0);
  ASSERT_NE(owned_clone, nullptr);
  ASSERT_STREQ("owner/test/factory", vm_owner_id(owned_clone));
  destruct_object(owned_clone);
  destruct_object(prototype);
}

TEST_F(DriverTest, TestMoveObjectOwnerInheritanceRespectsExplicitOwner) {
  auto* dest = find_object("single/simul_efun.c");
  ASSERT_NE(dest, nullptr);

  current_object = master_ob;
  auto* inherited_item = clone_object("single/owner_singleton", 0);
  ASSERT_NE(inherited_item, nullptr);
  vm_owner_clear_id(inherited_item);
  auto inherited_epoch = vm_owner_epoch(inherited_item);
  ASSERT_FALSE(vm_owner_has_explicit_id(inherited_item));

  vm_owner_set_id(dest, "owner/test/move/inherit-dest");
  move_object(inherited_item, dest);
  ASSERT_TRUE(vm_owner_has_explicit_id(inherited_item));
  ASSERT_STREQ("owner/test/move/inherit-dest", vm_owner_id(inherited_item));
  ASSERT_GT(vm_owner_epoch(inherited_item), inherited_epoch);
  destruct_object(inherited_item);

  auto* explicit_item = clone_object("single/owner_singleton", 0);
  ASSERT_NE(explicit_item, nullptr);
  vm_owner_set_id(explicit_item, "owner/test/move/explicit-item");
  auto explicit_epoch = vm_owner_epoch(explicit_item);
  vm_owner_set_id(dest, "owner/test/move/explicit-dest");
  move_object(explicit_item, dest);
  ASSERT_TRUE(vm_owner_has_explicit_id(explicit_item));
  ASSERT_STREQ("owner/test/move/explicit-item", vm_owner_id(explicit_item));
  ASSERT_EQ(vm_owner_epoch(explicit_item), explicit_epoch);
  destruct_object(explicit_item);

  vm_owner_clear_id(dest);
}

TEST_F(DriverTest, TestInteractiveExecPreservesNewObjectOwner) {
  current_object = master_ob;
  auto* old_user = clone_object("single/owner_singleton", 0);
  auto* new_user = clone_object("single/owner_singleton", 0);
  ASSERT_NE(old_user, nullptr);
  ASSERT_NE(new_user, nullptr);

  add_ref(old_user, "TestInteractiveExecPreservesNewObjectOwner");
  add_ref(new_user, "TestInteractiveExecPreservesNewObjectOwner");

  vm_owner_set_id(old_user, "owner/test/interactive/login");
  vm_owner_set_id(new_user, "owner/test/interactive/exec-user");
  auto old_epoch = vm_owner_epoch(old_user);
  auto new_epoch = vm_owner_epoch(new_user);

  auto* ip = user_add();
  ASSERT_NE(ip, nullptr);
  ip->ob = old_user;
  ip->fd = -1;
  old_user->interactive = ip;
  old_user->flags |= O_ONCE_INTERACTIVE;
  set_command_giver(old_user);

  ASSERT_EQ(replace_interactive(new_user, old_user), 1);
  ASSERT_EQ(new_user->interactive, ip);
  ASSERT_EQ(ip->ob, new_user);
  ASSERT_EQ(old_user->interactive, nullptr);
  ASSERT_EQ(command_giver, new_user);
  ASSERT_STREQ("owner/test/interactive/login", vm_owner_id(old_user));
  ASSERT_EQ(vm_owner_epoch(old_user), old_epoch);
  ASSERT_STREQ("owner/test/interactive/exec-user", vm_owner_id(new_user));
  ASSERT_EQ(vm_owner_epoch(new_user), new_epoch);

  set_command_giver(nullptr);
  remove_interactive(new_user, 1);
  ASSERT_EQ(new_user->interactive, nullptr);
  destruct_object(old_user);
  destruct_object(new_user);
  free_object(&old_user, "TestInteractiveExecPreservesNewObjectOwner");
  free_object(&new_user, "TestInteractiveExecPreservesNewObjectOwner");
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
  ASSERT_STREQ(mapping_string(trace, "trace_kind"), "owner_task_trace");
  ASSERT_STREQ(mapping_string(trace, "trace_model"), "owner_task_lifecycle_trace");
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 3);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "trace_model"), "owner_task_lifecycle_event");
  ASSERT_STREQ(mapping_string(events->u.arr->item[1].u.map, "trace_model"), "owner_task_lifecycle_event");
  ASSERT_STREQ(mapping_string(events->u.arr->item[2].u.map, "trace_model"), "owner_task_lifecycle_event");
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

  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  bool ran = false;
  std::string seen_owner;
  long active_owners_during_callback = 0;
  auto* before = vm_owner_thread_status();
  auto before_claims = mapping_number(before, "main_owner_claims");
  auto before_releases = mapping_number(before, "main_owner_releases");
  free_mapping(before);

  auto task_id = vm_owner_enqueue_main_task(obj, "unit_main", "dispatch", [&] {
    ran = true;
    seen_owner = vm_context().owner.current_owner_id;
    auto* running = vm_owner_thread_status();
    active_owners_during_callback = mapping_number(running, "main_active_owners");
    free_mapping(running);
  });
  ASSERT_GT(task_id, 0u);
  ASSERT_EQ(vm_owner_drain_main_tasks(8), 1);
  ASSERT_TRUE(ran);
  ASSERT_EQ(seen_owner, "owner/test/main-queue");
  ASSERT_EQ(active_owners_during_callback, 1);

  auto* after = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(after, "main_active_owners"), 0);
  ASSERT_EQ(mapping_number(after, "main_owner_claims"), before_claims + 1);
  ASSERT_EQ(mapping_number(after, "main_owner_releases"), before_releases + 1);
  free_mapping(after);

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
  auto* trace = vm_owner_task_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "task_type"), "heartbeat");
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "state"), "scheduled");
  free_mapping(trace);

  auto* owner_status = vm_object_store_owner_status("owner/test/heartbeat");
  auto* status_record = find_string_in_mapping(owner_status, "status_record");
  auto* execution_shard = find_string_in_mapping(owner_status, "execution_shard");
  ASSERT_NE(status_record, nullptr);
  ASSERT_EQ(status_record->type, T_MAPPING);
  ASSERT_NE(execution_shard, nullptr);
  ASSERT_EQ(execution_shard->type, T_MAPPING);
  ASSERT_EQ(mapping_number(owner_status, "active_heartbeats"), 1);
  ASSERT_EQ(mapping_number(owner_status, "runnable_tasks"), 1);
  ASSERT_EQ(mapping_number(owner_status, "executor_ready"), 1);
  ASSERT_EQ(mapping_number(status_record->u.map, "heartbeats"), 1);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "active_heartbeats"), 1);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "runnable_tasks"), 1);
  free_mapping(owner_status);

  set_heart_beat(obj, 0);
  owner_status = vm_object_store_owner_status("owner/test/heartbeat");
  execution_shard = find_string_in_mapping(owner_status, "execution_shard");
  ASSERT_NE(execution_shard, nullptr);
  ASSERT_EQ(execution_shard->type, T_MAPPING);
  ASSERT_EQ(mapping_number(owner_status, "active_heartbeats"), 0);
  ASSERT_EQ(mapping_number(owner_status, "runnable_tasks"), 0);
  ASSERT_EQ(mapping_number(owner_status, "executor_ready"), 0);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "active_heartbeats"), 0);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "runnable_tasks"), 0);
  free_mapping(owner_status);
  vm_owner_clear_id(obj);
}

TEST_F(DriverTest, TestVmObjectStoreTracksPendingCallouts) {
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  object_t* obj = find_object("single/master.c");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/callout-store");
  vm_object_store_record_callout(obj, 12345);

  auto* owner_status = vm_object_store_owner_status("owner/test/callout-store");
  auto* status_record = find_string_in_mapping(owner_status, "status_record");
  auto* execution_shard = find_string_in_mapping(owner_status, "execution_shard");
  ASSERT_NE(status_record, nullptr);
  ASSERT_EQ(status_record->type, T_MAPPING);
  ASSERT_NE(execution_shard, nullptr);
  ASSERT_EQ(execution_shard->type, T_MAPPING);
  ASSERT_EQ(mapping_number(owner_status, "pending_callouts"), 1);
  ASSERT_EQ(mapping_number(owner_status, "runnable_tasks"), 1);
  ASSERT_EQ(mapping_number(owner_status, "executor_ready"), 1);
  ASSERT_EQ(mapping_number(status_record->u.map, "callouts"), 1);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "pending_callouts"), 1);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "runnable_tasks"), 1);
  free_mapping(owner_status);

  vm_object_store_remove_callout("owner/test/callout-store", 12345);
  owner_status = vm_object_store_owner_status("owner/test/callout-store");
  execution_shard = find_string_in_mapping(owner_status, "execution_shard");
  ASSERT_NE(execution_shard, nullptr);
  ASSERT_EQ(execution_shard->type, T_MAPPING);
  ASSERT_EQ(mapping_number(owner_status, "pending_callouts"), 0);
  ASSERT_EQ(mapping_number(owner_status, "runnable_tasks"), 0);
  ASSERT_EQ(mapping_number(owner_status, "executor_ready"), 0);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "pending_callouts"), 0);
  ASSERT_EQ(mapping_number(execution_shard->u.map, "runnable_tasks"), 0);
  free_mapping(owner_status);
  vm_owner_clear_id(obj);
}

TEST_F(DriverTest, TestVmObjectStoreTracksPendingOwnerMessages) {
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  auto assert_pending_messages = [&](const char* owner_id, long expected) {
    auto* owner_status = vm_object_store_owner_status(owner_id);
    auto* status_record = find_string_in_mapping(owner_status, "status_record");
    auto* execution_shard = find_string_in_mapping(owner_status, "execution_shard");
    ASSERT_NE(status_record, nullptr);
    ASSERT_EQ(status_record->type, T_MAPPING);
    ASSERT_NE(execution_shard, nullptr);
    ASSERT_EQ(execution_shard->type, T_MAPPING);
    ASSERT_EQ(mapping_number(owner_status, "pending_messages"), expected);
    ASSERT_EQ(mapping_number(owner_status, "runnable_tasks"), expected);
    ASSERT_EQ(mapping_number(owner_status, "executor_ready"), expected > 0 ? 1 : 0);
    ASSERT_EQ(mapping_number(status_record->u.map, "messages"), 1);
    ASSERT_EQ(mapping_number(execution_shard->u.map, "pending_messages"), expected);
    ASSERT_EQ(mapping_number(execution_shard->u.map, "runnable_tasks"), expected);
    free_mapping(owner_status);
  };

  auto* drained = vm_owner_submit_message("owner/test/message/source", "owner/test/message/drain",
                                         "message", "payload/drain");
  ASSERT_EQ(mapping_number(drained, "success"), 1);
  free_mapping(drained);
  assert_pending_messages("owner/test/message/drain", 1);
  auto* drain_result = vm_owner_drain_mailbox("owner/test/message/drain", 1);
  ASSERT_EQ(mapping_number(drain_result, "drained"), 1);
  free_mapping(drain_result);
  assert_pending_messages("owner/test/message/drain", 0);

  auto* scheduled = vm_owner_submit_message("owner/test/message/source", "owner/test/message/schedule",
                                           "message", "payload/schedule");
  ASSERT_EQ(mapping_number(scheduled, "success"), 1);
  free_mapping(scheduled);
  assert_pending_messages("owner/test/message/schedule", 1);
  auto* schedule_result = vm_owner_schedule(1);
  ASSERT_EQ(mapping_number(schedule_result, "dispatched"), 1);
  free_mapping(schedule_result);
  assert_pending_messages("owner/test/message/schedule", 0);

  auto* purged = vm_owner_submit_message("owner/test/message/source", "owner/test/message/purge",
                                        "message", "payload/purge");
  ASSERT_EQ(mapping_number(purged, "success"), 1);
  free_mapping(purged);
  assert_pending_messages("owner/test/message/purge", 1);
  auto* purge_result = vm_owner_purge_mailbox("owner/test/message/purge");
  ASSERT_EQ(mapping_number(purge_result, "purged"), 1);
  free_mapping(purge_result);
  assert_pending_messages("owner/test/message/purge", 0);
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
      ASSERT_STREQ(mapping_string(event, "owner_id"), "owner/test/heartbeat-stale-old");
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
  ASSERT_STREQ(mapping_string(trace, "trace_kind"), "owner_access_trace");
  ASSERT_STREQ(mapping_string(trace, "trace_model"), "cross_owner_access_policy_trace");
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "trace_model"), "cross_owner_access_policy_event");
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
  ASSERT_GT(vm_owner_record_access(source, target, "present"), 0u);
  ASSERT_GT(vm_owner_record_access(source, target, "unknown_access"), 0u);

  auto* trace = vm_owner_access_trace(4);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 4);

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

  auto* present_event = events->u.arr->item[2].u.map;
  ASSERT_STREQ(mapping_string(present_event, "operation"), "present");
  ASSERT_STREQ(mapping_string(present_event, "access_mode"), "message");
  ASSERT_EQ(mapping_number(present_event, "message_only_cross_owner"), 1);
  ASSERT_EQ(mapping_number(present_event, "direct_cross_owner_write"), 0);

  auto* rejected_event = events->u.arr->item[3].u.map;
  ASSERT_STREQ(mapping_string(rejected_event, "operation"), "unknown_access");
  ASSERT_STREQ(mapping_string(rejected_event, "access_mode"), "reject");
  ASSERT_EQ(mapping_number(rejected_event, "rejected_by_default"), 1);
  ASSERT_EQ(mapping_number(trace, "direct_cross_owner_write"), 0);
  free_mapping(trace);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestVmMulticoreModeControlsCrossOwnerBlocking) {
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);
  vm_owner_set_id(source, "owner/test/mode/source");
  vm_owner_set_id(target, "owner/test/mode/target");

  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_OFF;
  ASSERT_STREQ(vm_multicore_mode_name(vm_multicore_mode()), "off");
  ASSERT_FALSE(vm_multicore_audit_enabled());
  ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));

  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_AUDIT;
  ASSERT_STREQ(vm_multicore_mode_name(vm_multicore_mode()), "audit");
  ASSERT_TRUE(vm_multicore_audit_enabled());
  ASSERT_FALSE(vm_multicore_enforced());
  ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));

  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;
  ASSERT_STREQ(vm_multicore_mode_name(vm_multicore_mode()), "enforced");
  ASSERT_TRUE(vm_multicore_enforced());
  ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "environment"));
  ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "present"));
  ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "parser"));
  ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "unknown_access"));

  CONFIG_INT(__RC_MULTICORE_MODE__) = 999;
  ASSERT_STREQ(vm_multicore_mode_name(vm_multicore_mode()), "audit");
  ASSERT_FALSE(vm_multicore_enforced());

  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestCurrentOwnerScopeControlsCrossOwnerBlocking) {
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;

  vm_owner_set_id(source, "owner/test/scope/source-object");
  vm_owner_set_id(target, "owner/test/scope/target");

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

  ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  {
    VMOwnerScope scope(vm_context(), "owner/test/scope/target", vm_owner_epoch(target));
    ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
    ASSERT_EQ(vm_owner_record_cross_owner_access(source, target, "call_other"), 0u);
  }
  {
    VMOwnerScope scope(vm_context(), "owner/test/scope/other", 1);
    ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  }
  vm_owner_clear_id(target);
  ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  vm_owner_set_id(target, "owner/test/scope/target");
  vm_owner_clear_id(source);
  ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  {
    VMOwnerScope scope(vm_context(), "owner/test/scope/other", 1);
    ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  }
  vm_owner_set_id(source, "owner/test/scope/source-object");
  {
    VMOwnerScope scope(vm_context(), vm_owner_default_id(), 0);
    vm_owner_set_id(source, "owner/test/scope/target");
    set_command_giver(source);
    ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
    ASSERT_EQ(vm_owner_record_cross_owner_access(source, target, "call_other"), 0u);
    ASSERT_GT(vm_owner_record_access(source, target, "call_other"), 0u);
    auto* trace = vm_owner_access_trace(1);
    auto* events = find_string_in_mapping(trace, "events");
    ASSERT_NE(events, nullptr);
    ASSERT_EQ(events->type, T_ARRAY);
    ASSERT_EQ(events->u.arr->size, 1);
    ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 0);
    ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/scope/target");
    ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/scope/target");
    free_mapping(trace);

    vm_owner_set_id(source, "owner/test/scope/source-object");
    set_command_giver(source);
    ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));

    set_command_giver(target);
    ASSERT_FALSE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
    ASSERT_GT(vm_owner_record_access(source, target, "call_other"), 0u);
    trace = vm_owner_access_trace(1);
    events = find_string_in_mapping(trace, "events");
    ASSERT_NE(events, nullptr);
    ASSERT_EQ(events->type, T_ARRAY);
    ASSERT_EQ(events->u.arr->size, 1);
    ASSERT_EQ(mapping_number(events->u.arr->item[0].u.map, "cross_owner"), 0);
    ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "source_owner_id"), "owner/test/scope/target");
    ASSERT_STREQ(mapping_string(events->u.arr->item[0].u.map, "target_owner_id"), "owner/test/scope/target");
    free_mapping(trace);
    set_command_giver(nullptr);
  }
  set_command_giver(target);
  ASSERT_TRUE(vm_owner_cross_owner_access_blocked(source, target, "call_other"));
  set_command_giver(nullptr);

  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
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

TEST_F(DriverTest, TestPresentEnforcedModeBlocksCrossOwnerIdSearch) {
  object_t* source = find_object("single/master.c");
  object_t* target = find_object("single/simul_efun.c");
  ASSERT_NE(source, nullptr);
  ASSERT_NE(target, nullptr);

  current_object = source;
  vm_owner_set_id(source, "owner/test/present/enforced/source");
  vm_owner_set_id(target, "owner/test/present/enforced/target");

  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;

  svalue_t needle;
  needle.type = T_STRING;
  needle.subtype = STRING_CONSTANT;
  needle.u.string = "anything";

  bool blocked = false;
  error_context_t econ{};
  save_context(&econ);
  try {
    (void)object_present(&needle, target);
    pop_context(&econ);
  } catch (...) {
    restore_context(&econ);
    blocked = true;
  }

  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
  ASSERT_TRUE(blocked);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
}

TEST_F(DriverTest, TestParserEnforcedModeBlocksCrossOwnerInterrogateApply) {
  object_t* parser = load_object_for_test("single/tests/efuns/parser_owner_probe");
  object_t* item = clone_object("single/tests/efuns/parser_owner_probe", 0);
  ASSERT_NE(parser, nullptr);
  ASSERT_NE(item, nullptr);

  current_object = parser;
  vm_owner_set_id(parser, "owner/test/parser/enforced/source");
  vm_owner_set_id(item, "owner/test/parser/enforced/target");
  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;

  auto* targets = allocate_array(1);
  targets->item[0].type = T_OBJECT;
  targets->item[0].u.ob = item;
  add_ref(item, "parser owner probe target");
  push_refed_array(targets);

  auto* ret = safe_apply("parse_targets", parser, 1, ORIGIN_DRIVER);
  ASSERT_NE(ret, nullptr);
  ASSERT_EQ(ret->type, T_NUMBER);
  ASSERT_EQ(ret->u.number, 0);

  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
  vm_owner_clear_id(parser);
  vm_owner_clear_id(item);
  destruct_object(item);
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

TEST_F(DriverTest, TestMoveObjectEnforcedModeBlocksCrossOwnerMove) {
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

  vm_owner_set_id(item, "owner/test/move/enforced/source");
  vm_owner_set_id(dest, "owner/test/move/enforced/dest");
  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;
  auto* before = vm_owner_access_trace(0);
  auto before_blocks = mapping_number(before, "enforced_blocks");
  free_mapping(before);

  bool blocked = false;
  error_context_t econ{};
  save_context(&econ);
  try {
    move_object(item, dest);
    pop_context(&econ);
  } catch (...) {
    restore_context(&econ);
    blocked = true;
  }

  auto* after = vm_owner_access_trace(0);
  auto after_blocks = mapping_number(after, "enforced_blocks");
  free_mapping(after);
  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
  ASSERT_TRUE(blocked);
  ASSERT_GT(after_blocks, before_blocks);

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

TEST_F(DriverTest, TestDestructEnforcedModeBlocksCrossOwnerDestruct) {
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

  current_object = source;
  vm_owner_set_id(source, "owner/test/destruct/enforced/source");
  vm_owner_set_id(target, "owner/test/destruct/enforced/target");
  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;
  auto* before = vm_owner_access_trace(0);
  auto before_blocks = mapping_number(before, "enforced_blocks");
  free_mapping(before);

  bool blocked = false;
  error_context_t econ{};
  save_context(&econ);
  try {
    destruct_object(target);
    pop_context(&econ);
  } catch (...) {
    restore_context(&econ);
    blocked = true;
  }

  auto* after = vm_owner_access_trace(0);
  auto after_blocks = mapping_number(after, "enforced_blocks");
  free_mapping(after);
  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
  ASSERT_TRUE(blocked);
  ASSERT_GT(after_blocks, before_blocks);
  ASSERT_EQ(target->flags & O_DESTRUCTED, 0);

  vm_owner_clear_id(source);
  vm_owner_clear_id(target);
  destruct_object(target);
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

TEST_F(DriverTest, TestCallOtherEnforcedModeBlocksCrossOwnerCall) {
  object_t* caller = load_object_for_test("single/void");
  object_t* target = load_object_for_test("single/on_destruct_good");
  ASSERT_NE(caller, nullptr);
  ASSERT_NE(target, nullptr);

  vm_owner_set_id(caller, "owner/test/call/enforced/source");
  vm_owner_set_id(target, "owner/test/call/enforced/target");

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

  auto saved_mode = CONFIG_INT(__RC_MULTICORE_MODE__);
  CONFIG_INT(__RC_MULTICORE_MODE__) = VM_MULTICORE_MODE_ENFORCED;
  auto* before = vm_owner_access_trace(0);
  auto before_blocks = mapping_number(before, "enforced_blocks");
  free_mapping(before);

  bool blocked = false;
  error_context_t econ{};
  save_context(&econ);
  try {
    push_object(target);
    blocked = safe_apply("call_target", caller, 1, ORIGIN_DRIVER) == nullptr;
    pop_context(&econ);
  } catch (...) {
    restore_context(&econ);
    blocked = true;
  }

  auto* after = vm_owner_access_trace(0);
  auto after_blocks = mapping_number(after, "enforced_blocks");
  free_mapping(after);
  ASSERT_TRUE(blocked);
  ASSERT_GT(after_blocks, before_blocks);

  push_object(target);
  auto* submitted = safe_apply("call_owner_async_echo", caller, 1, ORIGIN_DRIVER);
  ASSERT_NE(submitted, nullptr);
  ASSERT_EQ(submitted->type, T_MAPPING);
  auto* submitted_map = submitted->u.map;
  auto future_id = mapping_number(submitted_map, "future_id");
  ASSERT_EQ(mapping_number(submitted_map, "success"), 1);
  ASSERT_GT(future_id, 0);
  ASSERT_EQ(mapping_number(submitted_map, "async_only"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "frozen_payload"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(submitted_map, "requires_owner_main_queue"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "main_required"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "queued_on_main"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "message_only_cross_owner"), 1);
  ASSERT_EQ(mapping_number(submitted_map, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(submitted_map, "target_handle_current"), 1);
  ASSERT_STREQ(mapping_string(submitted_map, "source_owner_id"), "owner/test/call/enforced/source");
  ASSERT_STREQ(mapping_string(submitted_map, "target_owner_id"), "owner/test/call/enforced/target");
  ASSERT_STREQ(mapping_string(submitted_map, "message_type"), "owner_async_echo");
  ASSERT_STREQ(mapping_string(submitted_map, "payload_key"), "cross-owner/echo/v1");

  auto* pending = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(pending, "success"), 1);
  ASSERT_STREQ(mapping_string(pending, "state"), "pending");
  ASSERT_EQ(mapping_number(pending, "requires_owner_message_completion"), 1);
  ASSERT_EQ(mapping_number(pending, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(pending, "frozen_result"), 0);
  free_mapping(pending);

  ASSERT_EQ(vm_owner_drain_main_tasks(1), 1);
  auto* completed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(completed, "success"), 1);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "owner_async_echo");
  ASSERT_EQ(mapping_number(completed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(completed, "frozen_result"), 1);
  ASSERT_EQ(mapping_number(completed, "direct_cross_owner_write"), 0);
  auto* result = find_string_in_mapping(completed, "result");
  ASSERT_NE(result, nullptr);
  ASSERT_EQ(result->type, T_MAPPING);
  ASSERT_EQ(mapping_number(result->u.map, "reply"), 42);
  ASSERT_STREQ(mapping_string(result->u.map, "payload_key"), "cross-owner/echo/v1");
  ASSERT_STREQ(mapping_string(result->u.map, "target_owner_id"), "owner/test/call/enforced/target");
  free_mapping(completed);

  auto* trace = vm_owner_message_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  auto* message_event = events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "message_id"), future_id);
  ASSERT_STREQ(mapping_string(message_event, "source_owner_id"), "owner/test/call/enforced/source");
  ASSERT_STREQ(mapping_string(message_event, "target_owner_id"), "owner/test/call/enforced/target");
  ASSERT_STREQ(mapping_string(message_event, "message_type"), "owner_async_echo");
  ASSERT_STREQ(mapping_string(message_event, "state"), "completed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(message_event, "result_key"), "owner_async_echo");
  ASSERT_STREQ(mapping_string(message_event, "error"), "");
  ASSERT_STREQ(mapping_string(message_event, "target_handle_status"), "current");
  ASSERT_EQ(mapping_number(message_event, "pending"), 0);
  ASSERT_EQ(mapping_number(message_event, "completed"), 1);
  ASSERT_EQ(mapping_number(message_event, "failed"), 0);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(message_event, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 1);
  ASSERT_EQ(mapping_number(message_event, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(message_event, "target_handle_current"), 1);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_main_queue"), 1);
  ASSERT_EQ(mapping_number(message_event, "main_required"), 1);
  ASSERT_EQ(mapping_number(message_event, "queued_on_main"), 1);
  ASSERT_EQ(mapping_number(message_event, "message_only_cross_owner"), 1);
  free_mapping(trace);

  CONFIG_INT(__RC_MULTICORE_MODE__) = saved_mode;
  vm_owner_clear_id(caller);
  vm_owner_clear_id(target);
  destruct_object(caller);
  destruct_object(target);
}

TEST_F(DriverTest, TestVmOwnerObjectMessageRejectsNonFrozenResult) {
  const char* source_owner = "owner/test/async/non-frozen/source";
  const char* target_owner = "owner/test/async/non-frozen/target";

  object_t* target = load_object_for_test("single/on_destruct_good");
  ASSERT_NE(target, nullptr);
  vm_owner_set_id(target, target_owner);
  auto handle = vm_object_handle(target);

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

  auto* submitted = vm_owner_submit_object_message(source_owner, handle, "owner_async_non_frozen_result",
                                                   "cross-owner/non-frozen/v1");
  auto future_id = mapping_number(submitted, "future_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_GT(future_id, 0);
  ASSERT_GT(target_task_id, 0);
  ASSERT_EQ(mapping_number(submitted, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(submitted, "target_handle_current"), 1);
  ASSERT_EQ(mapping_number(submitted, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(submitted, "queued_on_main"), 1);
  ASSERT_STREQ(mapping_string(submitted, "source_owner_id"), source_owner);
  ASSERT_STREQ(mapping_string(submitted, "target_owner_id"), target_owner);
  free_mapping(submitted);

  ASSERT_EQ(vm_owner_drain_main_tasks(1), 1);

  auto* failed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(failed, "success"), 1);
  ASSERT_EQ(mapping_number(failed, "target_task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "owner async result must be frozen data");
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  ASSERT_EQ(mapping_number(failed, "direct_cross_owner_write"), 0);
  free_mapping(failed);

  auto* trace = vm_owner_message_trace(1);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  ASSERT_EQ(events->u.arr->size, 1);
  auto* message_event = events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "message_id"), future_id);
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(message_event, "message_type"), "owner_async_non_frozen_result");
  ASSERT_STREQ(mapping_string(message_event, "state"), "failed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(message_event, "result_key"), "");
  ASSERT_STREQ(mapping_string(message_event, "error"), "owner async result must be frozen data");
  ASSERT_STREQ(mapping_string(message_event, "target_handle_status"), "current");
  ASSERT_EQ(mapping_number(message_event, "pending"), 0);
  ASSERT_EQ(mapping_number(message_event, "completed"), 0);
  ASSERT_EQ(mapping_number(message_event, "failed"), 1);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(message_event, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  ASSERT_EQ(mapping_number(message_event, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(message_event, "target_handle_current"), 1);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_main_queue"), 1);
  ASSERT_EQ(mapping_number(message_event, "main_required"), 1);
  ASSERT_EQ(mapping_number(message_event, "queued_on_main"), 1);
  free_mapping(trace);

  auto* owner_status = vm_object_store_owner_status(target_owner);
  ASSERT_EQ(mapping_number(owner_status, "pending_messages"), 0);
  free_mapping(owner_status);

  vm_owner_clear_id(target);
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

TEST_F(DriverTest, TestVmOwnerExecutorCommandConsumeEntryDispatchesWithoutLpc) {
  const char* owner = "owner/test/executor/command-consume";

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

  auto* before = vm_owner_thread_status();
  auto before_consume = mapping_number(before, "executor_command_consume_entry_executed");
  auto before_safe = mapping_number(before, "executor_safe_task_dispatched");
  free_mapping(before);

  auto task_id = vm_owner_enqueue_task(owner, "command_consume", "gateway-command-consume-entry");
  ASSERT_GT(task_id, 0u);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_thread_status();
    auto consume_done = mapping_number(status, "executor_command_consume_entry_executed");
    free_mapping(status);
    if (consume_done >= before_consume + 1) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "executor_command_consume_entry_executed"), before_consume + 1);
  ASSERT_GE(mapping_number(running, "executor_safe_task_dispatched"), before_safe + 1);
  ASSERT_EQ(mapping_number(running, "ordinary_lpc_default_closed"), 1);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(8);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  bool found_entry_ready = false;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == static_cast<long>(task_id) &&
        std::string(mapping_string(event, "state")) == "thread_command_consume_entry_ready") {
      found_entry_ready = true;
      ASSERT_STREQ(mapping_string(event, "task_type"), "command_consume");
      ASSERT_STREQ(mapping_string(event, "task_key"), "gateway-command-consume-entry");
      ASSERT_STREQ(mapping_string(event, "owner_id"), owner);
    }
  }
  ASSERT_TRUE(found_entry_ready);
  free_mapping(trace);

  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmOwnerExecutorCommandFrameRestoreDispatchesWithoutLpc) {
  const char* owner = "owner/test/executor/command-frame-restore";

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
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_frame_restore = mapping_number(before, "executor_command_frame_restore_entry_executed");
  auto before_safe = mapping_number(before, "executor_safe_task_dispatched");
  auto before_execution_cleared = mapping_number(before, "thread_execution_cleared");
  auto before_eval_stack_owner_bound = mapping_number(before, "thread_eval_stack_owner_bound");
  auto before_eval_stack_cleared = mapping_number(before, "thread_eval_stack_cleared");
  auto before_eval_stack_leaks = mapping_number(before, "thread_eval_stack_leak_detected");
  auto before_control_stack_owner_bound = mapping_number(before, "thread_control_stack_owner_bound");
  auto before_control_stack_cleared = mapping_number(before, "thread_control_stack_cleared");
  auto before_control_stack_leaks = mapping_number(before, "thread_control_stack_leak_detected");
  auto before_value_stack_owner_bound = mapping_number(before, "thread_value_stack_owner_bound");
  auto before_value_stack_cleared = mapping_number(before, "thread_value_stack_cleared");
  auto before_value_stack_leaks = mapping_number(before, "thread_value_stack_leak_detected");
  auto before_apply_return_owner_bound = mapping_number(before, "thread_apply_return_owner_bound");
  auto before_apply_return_cleared = mapping_number(before, "thread_apply_return_cleared");
  auto before_apply_return_leaks = mapping_number(before, "thread_apply_return_leak_detected");
  auto before_context_leaks = mapping_number(before, "thread_context_leak_detected");
  free_mapping(before);

  auto task_id = vm_owner_enqueue_command_frame_restore(probe);
  ASSERT_GT(task_id, 0u);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_thread_status();
    auto frame_restore_done = mapping_number(status, "executor_command_frame_restore_entry_executed");
    free_mapping(status);
    if (frame_restore_done >= before_frame_restore + 1) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "executor_command_frame_restore_entry_executed"), before_frame_restore + 1);
  ASSERT_GE(mapping_number(running, "executor_safe_task_dispatched"), before_safe + 1);
  ASSERT_GE(mapping_number(running, "thread_execution_cleared"), before_execution_cleared + 1);
  ASSERT_GE(mapping_number(running, "thread_eval_stack_owner_bound"), before_eval_stack_owner_bound + 1);
  ASSERT_GE(mapping_number(running, "thread_eval_stack_cleared"), before_eval_stack_cleared + 1);
  ASSERT_EQ(mapping_number(running, "thread_eval_stack_leak_detected"), before_eval_stack_leaks);
  ASSERT_GE(mapping_number(running, "thread_control_stack_owner_bound"), before_control_stack_owner_bound + 1);
  ASSERT_GE(mapping_number(running, "thread_control_stack_cleared"), before_control_stack_cleared + 1);
  ASSERT_EQ(mapping_number(running, "thread_control_stack_leak_detected"), before_control_stack_leaks);
  ASSERT_GE(mapping_number(running, "thread_value_stack_owner_bound"), before_value_stack_owner_bound + 1);
  ASSERT_GE(mapping_number(running, "thread_value_stack_cleared"), before_value_stack_cleared + 1);
  ASSERT_EQ(mapping_number(running, "thread_value_stack_leak_detected"), before_value_stack_leaks);
  ASSERT_GE(mapping_number(running, "thread_apply_return_owner_bound"), before_apply_return_owner_bound + 1);
  ASSERT_GE(mapping_number(running, "thread_apply_return_cleared"), before_apply_return_cleared + 1);
  ASSERT_EQ(mapping_number(running, "thread_apply_return_leak_detected"), before_apply_return_leaks);
  ASSERT_EQ(mapping_number(running, "thread_context_leak_detected"), before_context_leaks);
  ASSERT_EQ(mapping_number(running, "ordinary_lpc_default_closed"), 1);
  auto* vm_context_contract = mapping_entry(running, "vm_context_contract");
  ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_ready"), 1);
  ASSERT_EQ(mapping_number(vm_context_contract, "eval_stack_owner_local"), 1);
  ASSERT_EQ(mapping_number(vm_context_contract, "control_stack_owner_local"), 1);
  ASSERT_EQ(mapping_number(vm_context_contract, "value_stack_owner_local"), 1);
  ASSERT_EQ(mapping_number(vm_context_contract, "apply_return_owner_local"), 1);
  ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_next_blocker"), "");
  free_mapping(running);

  auto* trace = vm_owner_task_trace(16);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  bool found_frame_restore_ready = false;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == static_cast<long>(task_id) &&
        std::string(mapping_string(event, "state")) == "thread_command_frame_restore_ready") {
      found_frame_restore_ready = true;
      ASSERT_STREQ(mapping_string(event, "task_type"), "command_frame_restore");
      ASSERT_STREQ(mapping_string(event, "task_key"), "gateway-command-frame-restore");
      ASSERT_STREQ(mapping_string(event, "owner_id"), owner);
    }
  }
  ASSERT_TRUE(found_frame_restore_ready);
  free_mapping(trace);

  vm_owner_thread_stop();
  ASSERT_TRUE(vm_context_is_main_thread());
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadDrainsPendingOwnerMessages) {
  const char* owner = "owner/test/thread/pending-message";

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

  auto* submitted = vm_owner_submit_message("owner/test/thread/source", owner, "message", "payload/thread");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  auto future_id = mapping_number(submitted, "future_id");
  free_mapping(submitted);

  auto* owner_status = vm_object_store_owner_status(owner);
  ASSERT_EQ(mapping_number(owner_status, "pending_messages"), 1);
  free_mapping(owner_status);

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

  owner_status = vm_object_store_owner_status(owner);
  ASSERT_EQ(mapping_number(owner_status, "pending_messages"), 0);
  free_mapping(owner_status);

  auto* future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(future, "success"), 1);
  ASSERT_STREQ(mapping_string(future, "state"), "completed");
  free_mapping(future);

  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmOwnerObjectMessageUsesMainQueueBridge) {
  const char* owner = "owner/test/executor/main-required";
  const char* source_owner = "owner/test/executor/main-source";

  vm_owner_thread_stop();
  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, owner);
  auto handle = vm_object_handle(obj);

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
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto before_safe = mapping_number(before, "executor_safe_task_dispatched");
  auto before_skipped = mapping_number(before, "executor_main_required_skipped");
  auto before_main_queued = mapping_number(before, "main_queued");
  auto before_main_dispatched = mapping_number(before, "main_dispatched");
  free_mapping(before);

  auto* submitted = vm_owner_submit_object_message(source_owner, handle, "owner_lpc_probe", "main-required/payload");
  auto future_id = mapping_number(submitted, "future_id");
  ASSERT_EQ(mapping_number(submitted, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(submitted, "target_handle_current"), 1);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_main_queue"), 1);
  ASSERT_EQ(mapping_number(submitted, "main_required"), 1);
  ASSERT_EQ(mapping_number(submitted, "queued_on_main"), 1);
  free_mapping(submitted);
  auto probe_task = vm_owner_enqueue_task(owner, "executor_probe", "safe-after-main-required");
  ASSERT_GT(probe_task, 0u);

  vm_owner_thread_start(2);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_thread_status();
    auto probe_done = mapping_number(status, "executor_probe_executed");
    free_mapping(status);
    if (probe_done >= before_probe + 1) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "executor_probe_executed"), before_probe + 1);
  ASSERT_GE(mapping_number(running, "executor_safe_task_dispatched"), before_safe + 1);
  ASSERT_EQ(mapping_number(running, "executor_main_required_skipped"), before_skipped);
  ASSERT_EQ(mapping_number(running, "executor_same_owner_claim_conflicts"), 0);
  ASSERT_GE(mapping_number(running, "main_queued"), before_main_queued + 1);
  ASSERT_EQ(mapping_number(running, "main_dispatched"), before_main_dispatched);
  free_mapping(running);

  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 0);
  ASSERT_EQ(mapping_number(queued, "owner_main_queue_depth"), 1);
  ASSERT_GE(mapping_number(queued, "main_queue_depth"), 1);
  free_mapping(queued);

  auto* pending = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_STREQ(mapping_string(pending, "state"), "pending");
  ASSERT_EQ(mapping_number(pending, "requires_owner_message_completion"), 1);
  free_mapping(pending);
  auto* pending_trace = vm_owner_message_trace(1);
  auto* pending_events = find_string_in_mapping(pending_trace, "events");
  ASSERT_NE(pending_events, nullptr);
  ASSERT_EQ(pending_events->type, T_ARRAY);
  ASSERT_EQ(pending_events->u.arr->size, 1);
  auto* pending_event = pending_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(pending_event, "message_id"), future_id);
  ASSERT_STREQ(mapping_string(pending_event, "state"), "message_submitted");
  ASSERT_STREQ(mapping_string(pending_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(pending_event, "target_handle_status"), "current");
  ASSERT_EQ(mapping_number(pending_event, "pending"), 1);
  ASSERT_EQ(mapping_number(pending_event, "terminal"), 0);
  ASSERT_EQ(mapping_number(pending_event, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(pending_event, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(pending_event, "requires_owner_main_queue"), 1);
  ASSERT_EQ(mapping_number(pending_event, "queued_on_main"), 1);
  free_mapping(pending_trace);

  vm_owner_thread_stop();
  ASSERT_EQ(vm_owner_drain_main_tasks(1), 1);
  auto* completed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_EQ(mapping_number(completed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed, "frozen_result"), 1);
  free_mapping(completed);
  auto* after = vm_owner_thread_status();
  ASSERT_GE(mapping_number(after, "main_dispatched"), before_main_dispatched + 1);
  free_mapping(after);
  auto* drained = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(drained, "owner_queue_depth"), 0);
  ASSERT_EQ(mapping_number(drained, "owner_main_queue_depth"), 0);
  free_mapping(drained);
  auto* completed_trace = vm_owner_message_trace(1);
  auto* completed_events = find_string_in_mapping(completed_trace, "events");
  ASSERT_NE(completed_events, nullptr);
  ASSERT_EQ(completed_events->type, T_ARRAY);
  ASSERT_EQ(completed_events->u.arr->size, 1);
  auto* completed_event = completed_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(completed_event, "message_id"), future_id);
  ASSERT_STREQ(mapping_string(completed_event, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(completed_event, "result_key"), "owner_lpc_probe");
  ASSERT_STREQ(mapping_string(completed_event, "error"), "");
  ASSERT_EQ(mapping_number(completed_event, "pending"), 0);
  ASSERT_EQ(mapping_number(completed_event, "completed"), 1);
  ASSERT_EQ(mapping_number(completed_event, "failed"), 0);
  ASSERT_EQ(mapping_number(completed_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(completed_event, "frozen_result"), 1);
  ASSERT_EQ(mapping_number(completed_event, "queued_on_main"), 1);
  free_mapping(completed_trace);
  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerExecutorSkipsMainRequiredMailboxHead) {
  const char* owner = "owner/test/executor/skip-main-required-head";

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
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };
  auto* before = vm_owner_thread_status();
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto before_safe = mapping_number(before, "executor_safe_task_dispatched");
  auto before_skipped = mapping_number(before, "executor_main_required_skipped");
  free_mapping(before);

  auto main_required_task = vm_owner_enqueue_test_main_required_message(owner, "blocked-object-message");
  auto probe_task = vm_owner_enqueue_task(owner, "executor_probe", "safe-after-main-required-head");
  ASSERT_GT(main_required_task, 0u);
  ASSERT_GT(probe_task, main_required_task);

  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 2);
  ASSERT_EQ(mapping_number(queued, "owner_executor_safe_queue_depth"), 1);
  ASSERT_EQ(mapping_number(queued, "owner_main_required_queue_depth"), 1);
  free_mapping(queued);
  auto* queued_thread = vm_owner_thread_status();
  ASSERT_GE(mapping_number(queued_thread, "runnable_owner_count"), 1);
  auto* queued_fairness = mapping_entry(queued_thread, "executor_queue_fairness");
  ASSERT_GE(mapping_number(queued_fairness, "executor_ready_owner_count"), 1);
  ASSERT_GE(mapping_number(queued_fairness, "mixed_backlog_owner_count"), 1);
  ASSERT_GE(mapping_number(queued_fairness, "max_executor_safe_backlog"), 1);
  ASSERT_GE(mapping_number(queued_fairness, "max_main_required_backlog"), 1);
  free_mapping(queued_thread);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_thread_status();
    auto probe_done = mapping_number(status, "executor_probe_executed");
    free_mapping(status);
    if (probe_done >= before_probe + 1) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "executor_probe_executed"), before_probe + 1);
  ASSERT_GE(mapping_number(running, "executor_safe_task_dispatched"), before_safe + 1);
  ASSERT_GE(mapping_number(running, "executor_main_required_skipped"), before_skipped + 1);
  ASSERT_EQ(mapping_number(running, "executor_same_owner_claim_conflicts"), 0);
  free_mapping(running);

  auto* after = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(after, "owner_queue_depth"), 1);
  ASSERT_EQ(mapping_number(after, "owner_executor_safe_queue_depth"), 0);
  ASSERT_EQ(mapping_number(after, "owner_main_required_queue_depth"), 1);
  free_mapping(after);
  auto* after_thread = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(after_thread, "runnable_owner_count"), 0);
  auto* after_fairness = mapping_entry(after_thread, "executor_queue_fairness");
  ASSERT_GE(mapping_number(after_fairness, "main_required_only_owner_count"), 1);
  ASSERT_EQ(mapping_number(after_fairness, "mixed_backlog_owner_count"), 0);
  free_mapping(after_thread);

  auto* trace = vm_owner_task_trace(16);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int main_required_dispatched = 0;
  int probe_completed = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == static_cast<long>(main_required_task) &&
        std::string(mapping_string(event, "state")) == "thread_dispatched") {
      main_required_dispatched = 1;
    }
    if (mapping_number(event, "task_id") == static_cast<long>(probe_task) &&
        std::string(mapping_string(event, "state")) == "executor_probe_completed") {
      probe_completed = 1;
    }
  }
  ASSERT_EQ(main_required_dispatched, 0);
  ASSERT_EQ(probe_completed, 1);
  free_mapping(trace);

  auto* purged = vm_owner_purge_mailbox(owner);
  ASSERT_EQ(mapping_number(purged, "purged"), 1);
  free_mapping(purged);
  auto* purged_status = vm_owner_thread_status();
  auto* purged_fairness = mapping_entry(purged_status, "executor_queue_fairness");
  ASSERT_EQ(mapping_number(purged_fairness, "main_required_only_owner_count"), 0);
  ASSERT_EQ(mapping_number(purged_fairness, "max_main_required_backlog"), 0);
  free_mapping(purged_status);
  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmOwnerRuntimeReportsExecutorTaskContract) {
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = map ? find_string_in_mapping(map, key) : nullptr;
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = map ? find_string_in_mapping(map, key) : nullptr;
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = map ? find_string_in_mapping(map, key) : nullptr;
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };
  auto mapping_array = [](mapping_t* map, const char* key) -> array_t* {
    auto* value = map ? find_string_in_mapping(map, key) : nullptr;
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_ARRAY);
    return value && value->type == T_ARRAY ? value->u.arr : nullptr;
  };

  auto assert_contract = [&](mapping_t* status) {
    ASSERT_STREQ(mapping_string(status, "executor_contract_version"), "owner_executor_v1");
    ASSERT_STREQ(mapping_string(status, "executor_model"), "owner_executor");
    ASSERT_STREQ(mapping_string(status, "executor_dispatch_model"), "descriptor_manifest");
    ASSERT_STREQ(mapping_string(status, "executor_lpc_model"), "default_closed_explicit_open");
    ASSERT_STREQ(mapping_string(status, "ordinary_lpc_default_policy"), "default_closed_explicit_open");
    ASSERT_EQ(mapping_number(status, "ordinary_lpc_default_closed"), 1);
    ASSERT_EQ(mapping_number(status, "ordinary_lpc_activation_policy_ready"), 1);
    ASSERT_EQ(mapping_number(status, "ordinary_lpc_dispatch_path_ready"), 1);
    ASSERT_EQ(mapping_number(status, "ordinary_lpc_explicit_open_required"), 1);
    ASSERT_STREQ(mapping_string(status, "ordinary_lpc_activation_policy"), "default_closed_explicit_open");
    ASSERT_STREQ(mapping_string(status, "ordinary_lpc_next_blocker"), "");
    auto* vm_context_contract = mapping_entry(status, "vm_context_contract");
    ASSERT_NE(vm_context_contract, nullptr);
    ASSERT_EQ(mapping_number(vm_context_contract, "contract_version"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "context_model"), "thread_local_vm_context");
    ASSERT_STREQ(mapping_string(vm_context_contract, "execution_state_model"), "vm_context_execution_snapshot");
    ASSERT_STREQ(mapping_string(vm_context_contract, "owner_state_model"), "vm_context_owner_scope");
    ASSERT_STREQ(mapping_string(vm_context_contract, "error_state_model"), "vm_context_error_snapshot");
    ASSERT_STREQ(mapping_string(vm_context_contract, "object_store_model"), "owner_local_object_store");
    ASSERT_STREQ(mapping_string(vm_context_contract, "object_store_off_main_policy"), "owner_local_lookup_only");
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_ready"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_blocker"), "");
    ASSERT_EQ(mapping_number(vm_context_contract, "controlled_lpc_ready"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "controlled_lpc_policy"), "descriptor_manifest_only");
    ASSERT_STREQ(mapping_string(vm_context_contract, "eval_stack_model"),
                 "thread_local_owner_execution_stack");
    ASSERT_EQ(mapping_number(vm_context_contract, "eval_stack_thread_local"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "eval_stack_owner_bound_on_executor"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "eval_stack_cleared_after_task"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "eval_stack_owner_local"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "control_stack_model"),
                 "thread_local_owner_control_stack");
    ASSERT_EQ(mapping_number(vm_context_contract, "control_stack_thread_local"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "control_stack_owner_bound_on_executor"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "control_stack_cleared_after_task"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "control_stack_owner_local"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "value_stack_model"),
                 "thread_local_owner_value_stack");
    ASSERT_EQ(mapping_number(vm_context_contract, "value_stack_thread_local"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "value_stack_lvalue_refs_cleared_after_task"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "value_stack_owner_bound_on_executor"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "value_stack_cleared_after_task"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "value_stack_owner_local"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "apply_return_model"),
                 "thread_local_owner_apply_return");
    ASSERT_EQ(mapping_number(vm_context_contract, "apply_return_thread_local"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "apply_return_owner_bound_on_executor"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "apply_return_cleared_after_task"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "apply_return_owner_local"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "object_refs_model"), "object_handle_boundary");
    ASSERT_EQ(mapping_number(vm_context_contract, "object_refs_owner_local"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "cross_owner_object_refs_policy"),
                 "object_handle_or_frozen_payload_only");
    ASSERT_EQ(mapping_number(vm_context_contract, "cross_owner_payload_rejects_objects"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "cross_owner_result_rejects_objects"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "owner_message_target_handle_guard"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "owner_executor_same_owner_object_refs_only"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_object_store_gate_required"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "object_store_owner_local_complete"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_activation_required"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_activation_policy_ready"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_dispatch_path_ready"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_default_closed"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_explicit_open_required"), 1);
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_dispatch_model"),
                 "generic_owner_lpc_dispatch");
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_activation_policy"),
                 "default_closed_explicit_open");
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_activation_rollout"),
                 "explicit_open_only_until_gateway_migration");
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_activation_rollback"),
                 "disable_explicit_open_submission");
    ASSERT_EQ(mapping_number(vm_context_contract, "error_state_contextualized"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "execution_state_contextualized"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "owner_scope_contextualized"), 1);
    ASSERT_EQ(mapping_number(vm_context_contract, "object_store_main_thread_only"), 0);
    ASSERT_GE(mapping_number(vm_context_contract, "object_store_sync_rejections"), 0);
    ASSERT_EQ(mapping_number(vm_context_contract, "off_main_object_store_sync_allowed"), 0);
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_readiness_gate_model"),
                 "all_gates_required_before_open");
    ASSERT_STREQ(mapping_string(vm_context_contract, "ordinary_lpc_next_blocker"), "");
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_readiness_gate_count"), 13);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_satisfied_gate_count"), 13);
    ASSERT_EQ(mapping_number(vm_context_contract, "ordinary_lpc_blocked_gate_count"), 0);
    auto* readiness_gates = mapping_array(vm_context_contract, "ordinary_lpc_readiness_gates");
    ASSERT_NE(readiness_gates, nullptr);
    ASSERT_EQ(readiness_gates->size, 13);
    std::unordered_map<std::string, mapping_t*> gates_by_name;
    for (int i = 0; i < readiness_gates->size; i++) {
      ASSERT_EQ(readiness_gates->item[i].type, T_MAPPING);
      auto* gate = readiness_gates->item[i].u.map;
      gates_by_name[mapping_string(gate, "gate")] = gate;
      ASSERT_NE(find_string_in_mapping(gate, "model"), nullptr);
      ASSERT_NE(find_string_in_mapping(gate, "blocker"), nullptr);
      ASSERT_NE(find_string_in_mapping(gate, "next_action"), nullptr);
    }
    auto gate_entry = [&](const std::string& gate_name) -> mapping_t* {
      auto it = gates_by_name.find(gate_name);
      EXPECT_NE(it, gates_by_name.end());
      return it == gates_by_name.end() ? nullptr : it->second;
    };
    ASSERT_EQ(mapping_number(gate_entry("thread_local_vm_context"), "satisfied"), 1);
    ASSERT_EQ(mapping_number(gate_entry("execution_state_contextualized"), "satisfied"), 1);
    ASSERT_EQ(mapping_number(gate_entry("error_state_contextualized"), "satisfied"), 1);
    ASSERT_EQ(mapping_number(gate_entry("eval_stack_owner_local"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("eval_stack_owner_local"), "model"),
                 "thread_local_owner_execution_stack");
    ASSERT_STREQ(mapping_string(gate_entry("eval_stack_owner_local"), "blocker"), "");
    ASSERT_EQ(mapping_number(gate_entry("control_stack_owner_local"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("control_stack_owner_local"), "model"),
                 "thread_local_owner_control_stack");
    ASSERT_STREQ(mapping_string(gate_entry("control_stack_owner_local"), "blocker"), "");
    ASSERT_EQ(mapping_number(gate_entry("value_stack_owner_local"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("value_stack_owner_local"), "model"),
                 "thread_local_owner_value_stack");
    ASSERT_STREQ(mapping_string(gate_entry("value_stack_owner_local"), "blocker"), "");
    ASSERT_EQ(mapping_number(gate_entry("apply_return_owner_local"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("apply_return_owner_local"), "model"),
                 "thread_local_owner_apply_return");
    ASSERT_STREQ(mapping_string(gate_entry("apply_return_owner_local"), "blocker"), "");
    ASSERT_EQ(mapping_number(gate_entry("object_refs_owner_local"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("object_refs_owner_local"), "blocker"), "");
    ASSERT_STREQ(mapping_string(gate_entry("object_refs_owner_local"), "next_action"),
                 "keep_cross_owner_object_refs_handle_or_frozen_payload_only");
    ASSERT_EQ(mapping_number(gate_entry("object_store_owner_local_complete"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("object_store_owner_local_complete"), "blocker"), "");
    ASSERT_STREQ(mapping_string(gate_entry("object_store_owner_local_complete"), "next_action"),
                 "keep_owner_local_store_canonical_without_global_fallback");
    ASSERT_EQ(mapping_number(gate_entry("ordinary_lpc_activation_policy"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("ordinary_lpc_activation_policy"), "blocker"), "");
    ASSERT_STREQ(mapping_string(gate_entry("ordinary_lpc_activation_policy"), "next_action"),
                 "keep_default_closed_until_dispatch_path_ready");
    ASSERT_EQ(mapping_number(gate_entry("ordinary_lpc_dispatch_path"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(gate_entry("ordinary_lpc_dispatch_path"), "blocker"), "");
    ASSERT_STREQ(mapping_string(gate_entry("ordinary_lpc_dispatch_path"), "next_action"),
                 "keep_generic_dispatch_explicit_open_and_frozen_result_guarded");

    auto* frozen_payload_contract = mapping_entry(status, "frozen_payload_contract");
    ASSERT_NE(frozen_payload_contract, nullptr);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "contract_version"), 1);
    ASSERT_STREQ(mapping_string(frozen_payload_contract, "validator"), "vm_frozen_value_safe");
    ASSERT_EQ(mapping_number(frozen_payload_contract, "deep_copy"), 1);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "max_depth"), 8);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "mapping_keys_must_be_strings"), 1);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "top_level_owner_payload_must_be_mapping"), 1);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "object_allowed"), 0);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "function_allowed"), 0);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "buffer_allowed"), 0);
    ASSERT_EQ(mapping_number(frozen_payload_contract, "class_allowed"), 0);
    auto* allowed_types = mapping_array(frozen_payload_contract, "allowed_types");
    ASSERT_NE(allowed_types, nullptr);
    ASSERT_EQ(allowed_types->size, 5);
    auto* rejected_types = mapping_array(frozen_payload_contract, "rejected_types");
    ASSERT_NE(rejected_types, nullptr);
    ASSERT_EQ(rejected_types->size, 4);
    std::unordered_set<std::string> rejected_type_names;
    for (int i = 0; i < rejected_types->size; i++) {
      ASSERT_EQ(rejected_types->item[i].type, T_STRING);
      rejected_type_names.insert(rejected_types->item[i].u.string);
    }
    ASSERT_NE(rejected_type_names.find("object"), rejected_type_names.end());
    ASSERT_NE(rejected_type_names.find("function"), rejected_type_names.end());
    ASSERT_NE(rejected_type_names.find("buffer"), rejected_type_names.end());
    ASSERT_NE(rejected_type_names.find("class"), rejected_type_names.end());
    auto* frozen_paths = mapping_array(frozen_payload_contract, "paths");
    ASSERT_NE(frozen_paths, nullptr);
    ASSERT_EQ(frozen_paths->size, 4);
    std::unordered_map<std::string, mapping_t*> frozen_paths_by_name;
    for (int i = 0; i < frozen_paths->size; i++) {
      ASSERT_EQ(frozen_paths->item[i].type, T_MAPPING);
      auto* path = frozen_paths->item[i].u.map;
      frozen_paths_by_name.emplace(mapping_string(path, "path"), path);
      ASSERT_EQ(mapping_number(path, "uses_shared_validator"), 1);
    }
    auto frozen_path = [&](const char* path_name) -> mapping_t* {
      auto it = frozen_paths_by_name.find(path_name);
      EXPECT_NE(it, frozen_paths_by_name.end());
      return it == frozen_paths_by_name.end() ? nullptr : it->second;
    };
    ASSERT_EQ(mapping_number(frozen_path("owner_send"), "top_level_mapping_required"), 1);
    ASSERT_EQ(mapping_number(frozen_path("owner_send"), "frozen_result_required"), 0);
    ASSERT_STREQ(mapping_string(frozen_path("owner_call_async"), "result_policy"), "frozen_result_required");
    ASSERT_EQ(mapping_number(frozen_path("owner_call_async"), "frozen_result_required"), 1);
    ASSERT_STREQ(mapping_string(frozen_path("owner_publish_snapshot"), "result_policy"), "snapshot_only");
    ASSERT_EQ(mapping_number(frozen_path("worker_snapshot"), "top_level_mapping_required"), 0);
    ASSERT_STREQ(mapping_string(frozen_path("worker_snapshot"), "result_policy"),
                 "owner_future_frozen_result_required");

    auto* gateway_contract = mapping_entry(status, "gateway_owner_task_contract");
    ASSERT_NE(gateway_contract, nullptr);
    ASSERT_EQ(mapping_number(gateway_contract, "contract_version"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "input_model"), "owner_main_queue_bridge");
    ASSERT_STREQ(mapping_string(gateway_contract, "executor_migration_state"),
                 "main_required_before_owner_executor");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_payload_model"),
                 "gateway_command_buffer_metadata_v1");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_input_source"), "interactive_text_buffer");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_text_snapshot_policy"),
                 "owner_private_redacted_from_trace");
    ASSERT_EQ(mapping_number(gateway_contract, "command_text_snapshot_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "command_input_callback_state_policy"),
                 "redacted_input_to_get_char_state_v1");
    ASSERT_EQ(mapping_number(gateway_contract, "command_input_callback_snapshot_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "command_input_callback_blocker"),
                 "input_to_get_char_state_main_thread_bound");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_executor_blocker"),
                 "interactive_command_side_effects_main_thread_bound");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_consume_model"),
                 "owner_owned_snapshot_main_thread_consume");
    ASSERT_EQ(mapping_number(gateway_contract, "command_consume_snapshot_ready"), 1);
    ASSERT_EQ(mapping_number(gateway_contract, "command_consume_executor_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "command_consume_blocker"), "");
    ASSERT_STREQ(mapping_string(gateway_contract, "raw_input_trace_policy"),
                 "no_raw_command_text_in_trace");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_execution_frame_model"),
                 "gateway_command_execution_frame_v1");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_execution_frame_policy"),
                 "owner_scope_current_interactive_command_giver");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_execution_frame_restore_policy"),
                 "owner_executor_vmcontext_restore");
    ASSERT_EQ(mapping_number(gateway_contract, "command_execution_frame_restore_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "command_execution_frame_restore_blocker"), "");
    ASSERT_EQ(mapping_number(gateway_contract, "command_execution_frame_executor_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "command_stale_guard"), "owner_epoch_target_handle_guard");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_stale_trace_state"), "main_stale");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_stale_target_status"), "owner_epoch_mismatch");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_executor_readiness_gate_model"),
                 "all_gates_required_before_owner_executor");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_executor_next_gate"),
                 "gateway_command_executor_activation");
    ASSERT_STREQ(mapping_string(gateway_contract, "command_executor_next_blocker"),
                 "interactive_command_side_effects_main_thread_bound");
    ASSERT_GE(mapping_number(status, "thread_gateway_command_rejected"), 0);
    ASSERT_EQ(mapping_number(gateway_contract, "command_executor_readiness_gate_count"), 7);
    ASSERT_EQ(mapping_number(gateway_contract, "command_executor_satisfied_gate_count"), 6);
    ASSERT_EQ(mapping_number(gateway_contract, "command_executor_blocked_gate_count"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "command_side_effect_readiness_gate_model"),
                 "all_side_effect_gates_required_before_activation");
    ASSERT_EQ(mapping_number(gateway_contract, "command_side_effect_readiness_gate_count"), 5);
    ASSERT_EQ(mapping_number(gateway_contract, "command_side_effect_satisfied_gate_count"), 1);
    ASSERT_EQ(mapping_number(gateway_contract, "command_side_effect_blocked_gate_count"), 4);
    auto* command_executor_gates = mapping_array(gateway_contract, "command_executor_readiness_gates");
    ASSERT_NE(command_executor_gates, nullptr);
    ASSERT_EQ(command_executor_gates->size, 7);
    std::unordered_map<std::string, mapping_t*> command_executor_gates_by_name;
    for (int i = 0; i < command_executor_gates->size; i++) {
      ASSERT_EQ(command_executor_gates->item[i].type, T_MAPPING);
      auto* gate = command_executor_gates->item[i].u.map;
      command_executor_gates_by_name[mapping_string(gate, "gate")] = gate;
      ASSERT_NE(mapping_string(gate, "model"), nullptr);
      ASSERT_NE(mapping_string(gate, "blocker"), nullptr);
      ASSERT_NE(mapping_string(gate, "next_action"), nullptr);
    }
    auto command_executor_gate = [&](const std::string& gate_name) -> mapping_t* {
      auto it = command_executor_gates_by_name.find(gate_name);
      EXPECT_NE(it, command_executor_gates_by_name.end());
      return it == command_executor_gates_by_name.end() ? nullptr : it->second;
    };
    ASSERT_EQ(mapping_number(command_executor_gate("owner_epoch_target_handle_guard"), "satisfied"), 1);
    ASSERT_EQ(mapping_number(command_executor_gate("owner_owned_command_snapshot"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(command_executor_gate("owner_owned_command_snapshot"), "blocker"), "");
    ASSERT_EQ(mapping_number(command_executor_gate("owner_owned_command_consume"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(command_executor_gate("owner_owned_command_consume"), "blocker"), "");
    ASSERT_EQ(mapping_number(command_executor_gate("owner_executor_command_consume_entry"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(command_executor_gate("owner_executor_command_consume_entry"), "blocker"), "");
    ASSERT_EQ(mapping_number(command_executor_gate("owner_executor_frame_restore"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(command_executor_gate("owner_executor_frame_restore"), "blocker"), "");
    ASSERT_EQ(mapping_number(command_executor_gate("ordinary_lpc_ready"), "satisfied"), 1);
    ASSERT_STREQ(mapping_string(command_executor_gate("ordinary_lpc_ready"), "blocker"), "");
    ASSERT_EQ(mapping_number(command_executor_gate("gateway_command_executor_activation"), "satisfied"), 0);
    ASSERT_STREQ(mapping_string(command_executor_gate("gateway_command_executor_activation"), "blocker"),
                 "interactive_command_side_effects_main_thread_bound");
    auto* command_side_effect_gates = mapping_array(gateway_contract, "command_side_effect_readiness_gates");
    ASSERT_NE(command_side_effect_gates, nullptr);
    ASSERT_EQ(command_side_effect_gates->size, 5);
    std::unordered_map<std::string, mapping_t*> command_side_effect_gates_by_name;
    for (int i = 0; i < command_side_effect_gates->size; i++) {
      ASSERT_EQ(command_side_effect_gates->item[i].type, T_MAPPING);
      auto* gate = command_side_effect_gates->item[i].u.map;
      command_side_effect_gates_by_name[mapping_string(gate, "gate")] = gate;
      ASSERT_NE(mapping_string(gate, "model"), nullptr);
      ASSERT_NE(mapping_string(gate, "blocker"), nullptr);
      ASSERT_NE(mapping_string(gate, "next_action"), nullptr);
      ASSERT_NE(mapping_string(gate, "state_owner"), nullptr);
      ASSERT_NE(mapping_string(gate, "migration_boundary"), nullptr);
      ASSERT_NE(mapping_string(gate, "side_effect_class"), nullptr);
      ASSERT_GE(mapping_number(gate, "blocks_activation"), 0);
    }
    auto command_side_effect_gate = [&](const std::string& gate_name) -> mapping_t* {
      auto it = command_side_effect_gates_by_name.find(gate_name);
      EXPECT_NE(it, command_side_effect_gates_by_name.end());
      return it == command_side_effect_gates_by_name.end() ? nullptr : it->second;
    };
    ASSERT_EQ(mapping_number(command_side_effect_gate("interactive_buffer_consume"), "satisfied"), 1);
    ASSERT_EQ(mapping_number(command_side_effect_gate("interactive_buffer_consume"), "blocks_activation"), 0);
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_buffer_consume"), "blocker"), "");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_buffer_consume"), "state_owner"),
                 "owner_command_snapshot");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_buffer_consume"), "migration_boundary"),
                 "main_thread_consume_before_executor_activation");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_buffer_consume"), "side_effect_class"),
                 "input_buffer_consume");
    ASSERT_EQ(mapping_number(command_side_effect_gate("input_to_get_char_state"), "satisfied"), 0);
    ASSERT_EQ(mapping_number(command_side_effect_gate("input_to_get_char_state"), "blocks_activation"), 1);
    ASSERT_STREQ(mapping_string(command_side_effect_gate("input_to_get_char_state"), "blocker"),
                 "input_to_get_char_state_main_thread_bound");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("input_to_get_char_state"), "state_owner"),
                 "interactive_t");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("input_to_get_char_state"), "migration_boundary"),
                 "owner_command_frame_input_callback_snapshot");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("input_to_get_char_state"), "side_effect_class"),
                 "input_callback_state");
    ASSERT_EQ(mapping_number(command_side_effect_gate("process_input_add_action_parser"), "satisfied"), 0);
    ASSERT_EQ(mapping_number(command_side_effect_gate("process_input_add_action_parser"), "blocks_activation"), 1);
    ASSERT_STREQ(mapping_string(command_side_effect_gate("process_input_add_action_parser"), "blocker"),
                 "add_action_parser_command_giver_main_thread_bound");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("process_input_add_action_parser"), "state_owner"),
                 "interactive_t_and_command_giver");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("process_input_add_action_parser"), "migration_boundary"),
                 "owner_command_parser_context");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("process_input_add_action_parser"), "side_effect_class"),
                 "parser_command_giver_state");
    ASSERT_EQ(mapping_number(command_side_effect_gate("prompt_telnet_reschedule_io"), "satisfied"), 0);
    ASSERT_EQ(mapping_number(command_side_effect_gate("prompt_telnet_reschedule_io"), "blocks_activation"), 1);
    ASSERT_STREQ(mapping_string(command_side_effect_gate("prompt_telnet_reschedule_io"), "blocker"),
                 "prompt_telnet_reschedule_main_thread_bound");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("prompt_telnet_reschedule_io"), "state_owner"),
                 "interactive_t_and_network_io");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("prompt_telnet_reschedule_io"), "migration_boundary"),
                 "main_reply_queue_after_owner_command");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("prompt_telnet_reschedule_io"), "side_effect_class"),
                 "prompt_telnet_reschedule_io");
    ASSERT_EQ(mapping_number(command_side_effect_gate("interactive_mode_flags"), "satisfied"), 0);
    ASSERT_EQ(mapping_number(command_side_effect_gate("interactive_mode_flags"), "blocks_activation"), 1);
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_mode_flags"), "blocker"),
                 "interactive_mode_flags_main_thread_bound");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_mode_flags"), "state_owner"), "interactive_t");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_mode_flags"), "migration_boundary"),
                 "owner_command_frame_mode_delta");
    ASSERT_STREQ(mapping_string(command_side_effect_gate("interactive_mode_flags"), "side_effect_class"),
                 "echo_mxp_ed_mode_flags");
    ASSERT_EQ(mapping_number(gateway_contract, "ordinary_lpc_ready_required"), 0);
    ASSERT_EQ(mapping_number(gateway_contract, "main_required"), 1);
    ASSERT_STREQ(mapping_string(gateway_contract, "next_blocker"),
                 "gateway_command_executor_activation");
    ASSERT_STREQ(mapping_string(gateway_contract, "next_blocker_chain"),
                 "gateway_command_executor/gateway_command_executor_activation");
    auto* gateway_tasks = mapping_array(gateway_contract, "tasks");
    ASSERT_NE(gateway_tasks, nullptr);
    ASSERT_EQ(gateway_tasks->size, 4);
    std::unordered_map<std::string, mapping_t*> gateway_tasks_by_key;
    for (int i = 0; i < gateway_tasks->size; i++) {
      ASSERT_EQ(gateway_tasks->item[i].type, T_MAPPING);
      auto* task = gateway_tasks->item[i].u.map;
      gateway_tasks_by_key.emplace(mapping_string(task, "task_key"), task);
      ASSERT_STREQ(mapping_string(task, "task_type"), "gateway");
      ASSERT_EQ(mapping_number(task, "main_required"), 1);
      ASSERT_EQ(mapping_number(task, "executor_safe"), 0);
      ASSERT_EQ(mapping_number(task, "requires_owner_scope"), 1);
      ASSERT_EQ(mapping_number(task, "requires_current_interactive"), 1);
      ASSERT_EQ(mapping_number(task, "requires_command_giver"), 1);
      ASSERT_EQ(mapping_number(task, "ordinary_lpc_ready_required"), 0);
      ASSERT_EQ(mapping_number(task, "command_serial_per_owner"), 1);
      ASSERT_NE(mapping_string(task, "payload_key"), nullptr);
      ASSERT_NE(mapping_string(task, "input_payload_policy"), nullptr);
      ASSERT_NE(mapping_string(task, "command_consume_model"), nullptr);
      ASSERT_GE(mapping_number(task, "command_consume_snapshot_ready"), 0);
      ASSERT_LE(mapping_number(task, "command_consume_snapshot_ready"), 1);
      ASSERT_GE(mapping_number(task, "command_consume_executor_ready"), 0);
      ASSERT_LE(mapping_number(task, "command_consume_executor_ready"), 1);
      ASSERT_NE(mapping_string(task, "command_consume_blocker"), nullptr);
      ASSERT_NE(mapping_string(task, "execution_frame_model"), nullptr);
      ASSERT_NE(mapping_string(task, "execution_frame_policy"), nullptr);
      ASSERT_NE(mapping_string(task, "execution_frame_restore_policy"), nullptr);
      ASSERT_GE(mapping_number(task, "execution_frame_restore_ready"), 0);
      ASSERT_LE(mapping_number(task, "execution_frame_restore_ready"), 1);
      ASSERT_NE(mapping_string(task, "execution_frame_restore_blocker"), nullptr);
      ASSERT_GE(mapping_number(task, "execution_frame_executor_ready"), 0);
      ASSERT_LE(mapping_number(task, "execution_frame_executor_ready"), 1);
    }
    auto gateway_task = [&](const char* task_key) -> mapping_t* {
      auto it = gateway_tasks_by_key.find(task_key);
      EXPECT_NE(it, gateway_tasks_by_key.end());
      return it == gateway_tasks_by_key.end() ? nullptr : it->second;
    };
    auto assert_gateway_task = [&](const char* task_key, const char* route, long requires_main_queue,
                                   const char* owner_scope_model, const char* stale_policy) {
      auto* task = gateway_task(task_key);
      ASSERT_NE(task, nullptr);
      ASSERT_STREQ(mapping_string(task, "executor_mode"), "main_required");
      ASSERT_STREQ(mapping_string(task, "route"), route);
      ASSERT_EQ(mapping_number(task, "requires_owner_main_queue"), requires_main_queue);
      ASSERT_STREQ(mapping_string(task, "owner_scope_model"), owner_scope_model);
      ASSERT_STREQ(mapping_string(task, "stale_policy"), stale_policy);
    };
    assert_gateway_task("gateway_receive", "owner_main_queue", 1, "owner_scope_and_current_interactive",
                        "owner_epoch_target_guard");
    assert_gateway_task("process_user_command", "owner_main_queue", 1, "interactive_owner_scope_frame",
                        "owner_epoch_target_guard");
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "payload_key"), "gateway_command_input");
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "input_payload_policy"),
                 "buffer_metadata_no_raw_command_text");
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "command_consume_model"),
                 "owner_owned_snapshot_main_thread_consume");
    ASSERT_EQ(mapping_number(gateway_task("process_user_command"), "command_consume_snapshot_ready"), 1);
    ASSERT_EQ(mapping_number(gateway_task("process_user_command"), "command_consume_executor_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "command_consume_blocker"), "");
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "execution_frame_model"),
                 "gateway_command_execution_frame_v1");
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "execution_frame_policy"),
                 "owner_scope_current_interactive_command_giver");
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "execution_frame_restore_policy"),
                 "owner_executor_vmcontext_restore");
    ASSERT_EQ(mapping_number(gateway_task("process_user_command"), "execution_frame_restore_ready"), 1);
    ASSERT_STREQ(mapping_string(gateway_task("process_user_command"), "execution_frame_restore_blocker"), "");
    ASSERT_EQ(mapping_number(gateway_task("process_user_command"), "execution_frame_executor_ready"), 1);
    ASSERT_EQ(mapping_number(gateway_task("process_user_command"), "requires_target_handle"), 1);
    ASSERT_EQ(mapping_number(gateway_task("process_user_command"), "requires_frozen_payload"), 1);
    assert_gateway_task("gateway_logon", "direct_main_owner_scope", 0, "owner_scope_and_current_interactive",
                        "session_owner_resolve_after_exec");
    assert_gateway_task("gateway_disconnected", "direct_main_owner_scope", 0,
                        "owner_scope_and_current_interactive", "session_owner_resolve_after_exec");

    auto* contract = mapping_entry(status, "executor_task_contract");
    ASSERT_NE(contract, nullptr);
    auto* lpc_contracts = mapping_array(status, "executor_lpc_task_contracts");
    ASSERT_NE(lpc_contracts, nullptr);
    ASSERT_EQ(lpc_contracts->size, 1);
    ASSERT_EQ(lpc_contracts->item[0].type, T_MAPPING);
    auto* readonly_contract = lpc_contracts->item[0].u.map;
    ASSERT_STREQ(mapping_string(readonly_contract, "method"), "owner_task_readonly");
    ASSERT_STREQ(mapping_string(readonly_contract, "executor_mode"), "executor_safe_allowlist");
    ASSERT_STREQ(mapping_string(readonly_contract, "route"), "owner_executor");
    ASSERT_STREQ(mapping_string(readonly_contract, "result_policy"), "frozen_result_required");
    ASSERT_EQ(mapping_number(readonly_contract, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(readonly_contract, "main_required"), 0);
    ASSERT_EQ(mapping_number(readonly_contract, "rejected"), 0);
    ASSERT_EQ(mapping_number(readonly_contract, "requires_target"), 1);
    ASSERT_EQ(mapping_number(readonly_contract, "requires_owner_thread"), 1);
    ASSERT_EQ(mapping_number(readonly_contract, "requires_owner_message_completion"), 1);
    ASSERT_EQ(mapping_number(readonly_contract, "frozen_result_required"), 1);
    ASSERT_EQ(mapping_number(readonly_contract, "direct_cross_owner_write"), 0);

    auto* dispatch_contracts = mapping_array(status, "executor_task_dispatch_contracts");
    ASSERT_NE(dispatch_contracts, nullptr);
    ASSERT_EQ(dispatch_contracts->size, 12);
    std::unordered_map<std::string, mapping_t*> dispatch_by_type;
    for (int i = 0; i < dispatch_contracts->size; i++) {
      ASSERT_EQ(dispatch_contracts->item[i].type, T_MAPPING);
      auto* entry = dispatch_contracts->item[i].u.map;
      dispatch_by_type.emplace(mapping_string(entry, "task_type"), entry);
      ASSERT_EQ(mapping_number(entry, "requires_owner_mailbox"), 1);
      ASSERT_EQ(mapping_number(entry, "requires_owner_main_queue"), 0);
    }
    auto dispatch_entry = [&](const char* task_type) -> mapping_t* {
      auto it = dispatch_by_type.find(task_type);
      EXPECT_NE(it, dispatch_by_type.end());
      return it == dispatch_by_type.end() ? nullptr : it->second;
    };
    auto assert_dispatch = [&](const char* task_type, const char* contract_key, const char* dispatch_kind,
                               const char* executor_mode, long executor_runnable, long executor_safe,
                               long rejected) {
      auto* entry = dispatch_entry(task_type);
      ASSERT_NE(entry, nullptr);
      ASSERT_STREQ(mapping_string(entry, "contract_key"), contract_key);
      ASSERT_STREQ(mapping_string(entry, "dispatch_kind"), dispatch_kind);
      ASSERT_STREQ(mapping_string(entry, "executor_mode"), executor_mode);
      ASSERT_STREQ(mapping_string(entry, "route"), "owner_executor");
      ASSERT_EQ(mapping_number(entry, "executor_runnable"), executor_runnable);
      ASSERT_EQ(mapping_number(entry, "executor_safe"), executor_safe);
      ASSERT_EQ(mapping_number(entry, "main_required"), 0);
      ASSERT_EQ(mapping_number(entry, "rejected"), rejected);
    };
    assert_dispatch("executor_probe", "executor_probe", "executor_probe", "executor_safe", 1, 1, 0);
    assert_dispatch("lpc_probe", "lpc_probe", "lpc_probe", "executor_safe", 1, 1, 0);
    assert_dispatch("lpc_canary", "lpc_canary", "lpc_canary", "executor_safe", 1, 1, 0);
    assert_dispatch("lpc_task", "lpc_task_allowlist", "lpc_task", "executor_safe_allowlist", 1, 1, 0);
    assert_dispatch("ordinary_lpc", "ordinary_lpc_dispatch", "ordinary_lpc", "executor_safe_explicit_open", 1, 1, 0);
    assert_dispatch("owner_message", "owner_message_mailbox", "owner_message", "executor_safe", 1, 1, 0);
    assert_dispatch("command_consume", "owner_executor_command_consumer", "command_consume", "executor_safe", 1,
                    1, 0);
    assert_dispatch("command_frame_restore", "owner_executor_command_frame_restore", "command_frame_restore",
                    "executor_safe", 1, 1, 0);
    assert_dispatch("gateway_command", "gateway_command_executor_activation", "gateway_command", "rejected", 1, 0,
                    1);
    assert_dispatch("compute_result", "compute_result", "compute_result", "executor_safe", 1, 1, 0);
    assert_dispatch("lpc", "lpc", "reject_lpc", "rejected", 1, 0, 1);
    assert_dispatch("owner_state", "owner_state", "guard_owner_state", "rejected", 1, 0, 1);

    auto* compute = mapping_entry(contract, "compute_result");
    ASSERT_STREQ(mapping_string(compute, "executor_mode"), "executor_safe");
    ASSERT_STREQ(mapping_string(compute, "route"), "owner_executor");
    ASSERT_EQ(mapping_number(compute, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(compute, "main_required"), 0);
    ASSERT_EQ(mapping_number(compute, "rejected"), 0);

    auto* command_consume = mapping_entry(contract, "owner_executor_command_consumer");
    ASSERT_STREQ(mapping_string(command_consume, "executor_mode"), "executor_safe");
    ASSERT_STREQ(mapping_string(command_consume, "route"), "owner_executor");
    ASSERT_EQ(mapping_number(command_consume, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(command_consume, "main_required"), 0);
    ASSERT_EQ(mapping_number(command_consume, "rejected"), 0);

    auto* command_frame_restore = mapping_entry(contract, "owner_executor_command_frame_restore");
    ASSERT_STREQ(mapping_string(command_frame_restore, "executor_mode"), "executor_safe");
    ASSERT_STREQ(mapping_string(command_frame_restore, "route"), "owner_executor");
    ASSERT_EQ(mapping_number(command_frame_restore, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(command_frame_restore, "main_required"), 0);
    ASSERT_EQ(mapping_number(command_frame_restore, "rejected"), 0);

    auto* gateway_command = mapping_entry(contract, "gateway_command_executor_activation");
    ASSERT_STREQ(mapping_string(gateway_command, "executor_mode"), "rejected");
    ASSERT_STREQ(mapping_string(gateway_command, "route"), "owner_executor");
    ASSERT_EQ(mapping_number(gateway_command, "executor_safe"), 0);
    ASSERT_EQ(mapping_number(gateway_command, "main_required"), 0);
    ASSERT_EQ(mapping_number(gateway_command, "rejected"), 1);

    auto* mailbox_message = mapping_entry(contract, "owner_message_mailbox");
    ASSERT_EQ(mapping_number(mailbox_message, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(mailbox_message, "main_required"), 0);
    ASSERT_EQ(mapping_number(mailbox_message, "requires_owner_mailbox"), 1);
    ASSERT_EQ(mapping_number(mailbox_message, "requires_owner_main_queue"), 0);
    ASSERT_STREQ(mapping_string(mailbox_message, "route"), "owner_executor");

    auto* target_message = mapping_entry(contract, "owner_message_target_handle");
    ASSERT_STREQ(mapping_string(target_message, "executor_mode"), "main_required");
    ASSERT_STREQ(mapping_string(target_message, "route"), "owner_main_queue");
    ASSERT_EQ(mapping_number(target_message, "executor_safe"), 0);
    ASSERT_EQ(mapping_number(target_message, "main_required"), 1);
    ASSERT_EQ(mapping_number(target_message, "requires_owner_mailbox"), 0);
    ASSERT_EQ(mapping_number(target_message, "requires_owner_main_queue"), 1);
    ASSERT_EQ(mapping_number(target_message, "rejected"), 0);

    auto* allowlist = mapping_entry(contract, "lpc_task_allowlist");
    ASSERT_STREQ(mapping_string(allowlist, "executor_mode"), "executor_safe_allowlist");
    ASSERT_EQ(mapping_number(allowlist, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(allowlist, "rejected"), 0);
    auto* nested_lpc_contracts = mapping_array(allowlist, "contracts");
    ASSERT_NE(nested_lpc_contracts, nullptr);
    ASSERT_EQ(nested_lpc_contracts->size, 1);
    ASSERT_EQ(nested_lpc_contracts->item[0].type, T_MAPPING);
    ASSERT_STREQ(mapping_string(nested_lpc_contracts->item[0].u.map, "method"), "owner_task_readonly");

    auto* ordinary_lpc = mapping_entry(contract, "ordinary_lpc");
    ASSERT_STREQ(mapping_string(ordinary_lpc, "executor_mode"), "executor_safe_explicit_open");
    ASSERT_STREQ(mapping_string(ordinary_lpc, "route"), "owner_executor");
    ASSERT_EQ(mapping_number(ordinary_lpc, "executor_safe"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "main_required"), 0);
    ASSERT_EQ(mapping_number(ordinary_lpc, "rejected"), 0);
    ASSERT_STREQ(mapping_string(ordinary_lpc, "dispatch_model"), "generic_owner_lpc_dispatch");
    ASSERT_STREQ(mapping_string(ordinary_lpc, "activation_policy"), "default_closed_explicit_open");
    ASSERT_EQ(mapping_number(ordinary_lpc, "default_closed"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "explicit_open_required"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "requires_target"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "requires_owner_thread"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "requires_owner_message_completion"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "frozen_result_required"), 1);
    ASSERT_EQ(mapping_number(ordinary_lpc, "direct_cross_owner_write"), 0);

    auto* legacy_lpc = mapping_entry(contract, "lpc");
    ASSERT_STREQ(mapping_string(legacy_lpc, "executor_mode"), "rejected");
    ASSERT_STREQ(mapping_string(legacy_lpc, "route"), "owner_executor");
    ASSERT_EQ(mapping_number(legacy_lpc, "executor_safe"), 0);
    ASSERT_EQ(mapping_number(legacy_lpc, "main_required"), 0);
    ASSERT_EQ(mapping_number(legacy_lpc, "rejected"), 1);
  };

  auto* runtime_status = vm_owner_runtime_status();
  assert_contract(runtime_status);
  ASSERT_EQ(mapping_number(runtime_status, "ordinary_lpc_default_closed"), 1);
  free_mapping(runtime_status);

  auto* thread_status = vm_owner_thread_status();
  assert_contract(thread_status);
  ASSERT_EQ(mapping_number(thread_status, "ordinary_lpc_default_closed"), 1);
  free_mapping(thread_status);
}

TEST_F(DriverTest, TestVmOwnerExecutorBudgetYieldsAndRequeuesSameOwnerBacklog) {
  const char* owner = "owner/test/executor/budget-yield";

  vm_owner_thread_stop();
  setenv("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS", "5", 1);
  struct ProbeDelayGuard {
    ~ProbeDelayGuard() { unsetenv("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS"); }
  } probe_delay_guard;
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

  auto mapping_array = [](mapping_t* map, const char* key) -> array_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_ARRAY);
    return value && value->type == T_ARRAY ? value->u.arr : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_budget_yields = mapping_number(before, "executor_budget_yields");
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto budget = mapping_number(before, "executor_task_budget");
  ASSERT_GT(budget, 0);
  free_mapping(before);

  auto task_count = budget * 3 + 1;
  for (long i = 0; i < task_count; i++) {
    auto task_id = vm_owner_enqueue_task(owner, "executor_probe", "budget-yield-probe");
    ASSERT_GT(task_id, 0u);
  }

  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), task_count);
  ASSERT_EQ(mapping_number(queued, "owner_executor_safe_queue_depth"), task_count);
  free_mapping(queued);

  vm_owner_thread_start(1);
  int observed_budget_yield = 0;
  for (int i = 0; i < 200; i++) {
    auto* status = vm_owner_thread_status();
    auto budget_yields = mapping_number(status, "executor_budget_yields");
    auto probe_done = mapping_number(status, "executor_probe_executed");
    auto last_yield_backlog = mapping_number(status, "executor_last_budget_yield_backlog");
    auto last_yield_safe_backlog = mapping_number(status, "executor_last_budget_yield_safe_backlog");
    auto last_yield_owner = std::string(mapping_string(status, "executor_last_budget_yield_owner"));
    free_mapping(status);
    auto* mailbox = vm_owner_mailbox_status(owner);
    auto owner_depth = mapping_number(mailbox, "owner_queue_depth");
    auto safe_depth = mapping_number(mailbox, "owner_executor_safe_queue_depth");
    free_mapping(mailbox);
    if (budget_yields >= before_budget_yields + 1 && probe_done >= before_probe + budget &&
        owner_depth > 0 && safe_depth > 0) {
      ASSERT_EQ(last_yield_owner, owner);
      ASSERT_GT(last_yield_backlog, 0);
      ASSERT_GT(last_yield_safe_backlog, 0);
      observed_budget_yield = 1;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  ASSERT_EQ(observed_budget_yield, 1);

  for (int i = 0; i < 200; i++) {
    auto* mailbox = vm_owner_mailbox_status(owner);
    auto owner_depth = mapping_number(mailbox, "owner_queue_depth");
    free_mapping(mailbox);
    auto* status = vm_owner_thread_status();
    auto probe_done = mapping_number(status, "executor_probe_executed");
    free_mapping(status);
    if (owner_depth == 0 && probe_done >= before_probe + task_count) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  auto* drained = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(drained, "owner_queue_depth"), 0);
  ASSERT_EQ(mapping_number(drained, "owner_executor_safe_queue_depth"), 0);
  free_mapping(drained);

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "executor_budget_yields"), before_budget_yields + 1);
  ASSERT_GE(mapping_number(running, "executor_probe_executed"), before_probe + task_count);
  ASSERT_STREQ(mapping_string(running, "executor_last_budget_yield_owner"), owner);
  ASSERT_EQ(mapping_number(running, "executor_same_owner_claim_conflicts"), 0);
  ASSERT_EQ(mapping_number(running, "claimed_owners"), 0);
  free_mapping(running);

  auto* runtime = vm_owner_runtime_status();
  ASSERT_STREQ(mapping_string(runtime, "executor_last_budget_yield_owner"), owner);
  ASSERT_GE(mapping_number(runtime, "executor_last_budget_yield_backlog"), 0);
  ASSERT_GE(mapping_number(runtime, "executor_last_budget_yield_safe_backlog"), 0);
  free_mapping(runtime);

  auto* executor_trace = vm_owner_executor_trace(32);
  ASSERT_EQ(mapping_number(executor_trace, "success"), 1);
  ASSERT_STREQ(mapping_string(executor_trace, "trace_kind"), "owner_executor_trace");
  ASSERT_STREQ(mapping_string(executor_trace, "trace_model"), "owner_executor_scheduler_trace");
  ASSERT_STREQ(mapping_string(executor_trace, "executor_contract_version"), "owner_executor_v1");
  ASSERT_STREQ(mapping_string(executor_trace, "executor_model"), "owner_executor");
  ASSERT_GT(mapping_number(executor_trace, "returned"), 0);
  auto* events = mapping_array(executor_trace, "events");
  ASSERT_NE(events, nullptr);
  int saw_claimed = 0;
  int saw_budget_yield = 0;
  int saw_released = 0;
  for (int i = 0; i < events->size; i++) {
    auto* event = events->item[i].u.map;
    if (std::string(mapping_string(event, "owner_id")) != owner) {
      continue;
    }
    ASSERT_STREQ(mapping_string(event, "trace_model"), "owner_executor_scheduler_event");
    ASSERT_STREQ(mapping_string(event, "executor_contract_version"), "owner_executor_v1");
    ASSERT_STREQ(mapping_string(event, "executor_model"), "owner_executor");
    ASSERT_STREQ(mapping_string(event, "executor_dispatch_model"), "descriptor_manifest");
    auto event_name = std::string(mapping_string(event, "event"));
    if (event_name == "owner_claimed") {
      saw_claimed = 1;
      ASSERT_GE(mapping_number(event, "claimed_owners"), 1);
    } else if (event_name == "budget_yield") {
      saw_budget_yield = 1;
      ASSERT_GT(mapping_number(event, "backlog"), 0);
      ASSERT_GT(mapping_number(event, "safe_backlog"), 0);
    } else if (event_name == "owner_released") {
      saw_released = 1;
      ASSERT_EQ(mapping_number(event, "claimed_owners"), 0);
    }
    ASSERT_GE(mapping_number(event, "runnable_owners"), 0);
    ASSERT_GE(mapping_number(event, "main_required_backlog"), 0);
    ASSERT_GE(mapping_number(event, "active_claims"), 0);
  }
  ASSERT_EQ(saw_claimed, 1);
  ASSERT_EQ(saw_budget_yield, 1);
  ASSERT_EQ(saw_released, 1);
  free_mapping(executor_trace);

  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmOwnerExecutorDoesNotYieldWhenExactBudgetDrainsBacklog) {
  const char* owner = "owner/test/executor/exact-budget";

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
  auto mapping_array = [](mapping_t* map, const char* key) -> array_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_ARRAY);
    return value && value->type == T_ARRAY ? value->u.arr : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_budget_yields = mapping_number(before, "executor_budget_yields");
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto before_last_yield_backlog = mapping_number(before, "executor_last_budget_yield_backlog");
  auto before_last_yield_safe_backlog = mapping_number(before, "executor_last_budget_yield_safe_backlog");
  auto before_last_yield_owner = std::string(mapping_string(before, "executor_last_budget_yield_owner"));
  auto budget = mapping_number(before, "executor_task_budget");
  ASSERT_GT(budget, 0);
  free_mapping(before);

  for (long i = 0; i < budget; i++) {
    auto task_id = vm_owner_enqueue_task(owner, "executor_probe", "exact-budget-probe");
    ASSERT_GT(task_id, 0u);
  }

  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), budget);
  ASSERT_EQ(mapping_number(queued, "owner_executor_safe_queue_depth"), budget);
  free_mapping(queued);

  vm_owner_thread_start(1);
  for (int i = 0; i < 200; i++) {
    auto* mailbox = vm_owner_mailbox_status(owner);
    auto owner_depth = mapping_number(mailbox, "owner_queue_depth");
    free_mapping(mailbox);
    auto* status = vm_owner_thread_status();
    auto probe_done = mapping_number(status, "executor_probe_executed");
    free_mapping(status);
    if (owner_depth == 0 && probe_done >= before_probe + budget) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  auto* drained = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(drained, "owner_queue_depth"), 0);
  ASSERT_EQ(mapping_number(drained, "owner_executor_safe_queue_depth"), 0);
  free_mapping(drained);

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "executor_budget_yields"), before_budget_yields);
  ASSERT_GE(mapping_number(running, "executor_probe_executed"), before_probe + budget);
  ASSERT_STREQ(mapping_string(running, "executor_last_budget_yield_owner"), before_last_yield_owner.c_str());
  ASSERT_EQ(mapping_number(running, "executor_last_budget_yield_backlog"), before_last_yield_backlog);
  ASSERT_EQ(mapping_number(running, "executor_last_budget_yield_safe_backlog"), before_last_yield_safe_backlog);
  ASSERT_EQ(mapping_number(running, "executor_same_owner_claim_conflicts"), 0);
  ASSERT_EQ(mapping_number(running, "claimed_owners"), 0);
  free_mapping(running);

  auto* executor_trace = vm_owner_executor_trace(64);
  ASSERT_EQ(mapping_number(executor_trace, "success"), 1);
  auto* events = mapping_array(executor_trace, "events");
  ASSERT_NE(events, nullptr);
  int saw_budget_yield = 0;
  for (int i = 0; i < events->size; i++) {
    auto* event = events->item[i].u.map;
    if (std::string(mapping_string(event, "owner_id")) == owner &&
        std::string(mapping_string(event, "event")) == "budget_yield") {
      saw_budget_yield = 1;
    }
  }
  ASSERT_EQ(saw_budget_yield, 0);
  free_mapping(executor_trace);

  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmOwnerExecutorRunsDifferentOwnersInParallel) {
  const char* owner_a = "owner/test/executor/parallel-a";
  const char* owner_b = "owner/test/executor/parallel-b";

  vm_owner_thread_stop();
  auto mapping_number = [](mapping_t* map, const char* key) -> long {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };

  auto* before = vm_owner_thread_status();
  auto before_probe = mapping_number(before, "executor_probe_executed");
  auto before_claims = mapping_number(before, "executor_owner_claims");
  auto before_releases = mapping_number(before, "executor_owner_releases");
  auto before_max_parallel = mapping_number(before, "executor_max_parallel_owners");
  auto before_max_owner_parallel = mapping_number(before, "executor_max_owner_parallel");
  free_mapping(before);

  auto task_a = vm_owner_enqueue_task(owner_a, "executor_probe", "parallel-a");
  auto task_b = vm_owner_enqueue_task(owner_b, "executor_probe", "parallel-b");
  ASSERT_GT(task_a, 0u);
  ASSERT_GT(task_b, task_a);

  setenv("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS", "80", 1);
  vm_owner_thread_start(2);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_thread_status();
    auto probe_done = mapping_number(status, "executor_probe_executed");
    free_mapping(status);
    if (probe_done >= before_probe + 2) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  unsetenv("FLUFFOS_OWNER_EXECUTOR_PROBE_DELAY_MS");

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "executor_probe_executed"), before_probe + 2);
  ASSERT_GE(mapping_number(running, "executor_owner_claims"), before_claims + 2);
  ASSERT_EQ(mapping_number(running, "executor_owner_claims") - before_claims,
            mapping_number(running, "executor_owner_releases") - before_releases);
  ASSERT_GE(mapping_number(running, "executor_max_parallel_owners"), std::max<long>(2, before_max_parallel));
  ASSERT_GE(mapping_number(running, "executor_max_owner_parallel"), std::max<long>(1, before_max_owner_parallel));
  ASSERT_LE(mapping_number(running, "executor_max_owner_parallel"), 1);
  ASSERT_EQ(mapping_number(running, "executor_same_owner_claim_conflicts"), 0);
  ASSERT_EQ(mapping_number(running, "active_owners"), 0);
  free_mapping(running);

  vm_owner_thread_stop();
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

  auto* before = vm_owner_thread_status();
  auto before_runnable = mapping_number(before, "executor_runnable_task_dispatched");
  auto before_safe = mapping_number(before, "executor_safe_task_dispatched");
  free_mapping(before);

  auto lpc_task = vm_owner_enqueue_task(owner, "lpc", "off-main-dummy");
  auto state_task = vm_owner_enqueue_task(owner, "owner_state", "single-owner-state");
  auto gateway_command_task = vm_owner_enqueue_task(owner, "gateway_command", "player-command-activation");
  auto message_task = vm_owner_enqueue_task(owner, "owner_message", "cross-owner-message");
  ASSERT_GT(lpc_task, 0u);
  ASSERT_GT(state_task, lpc_task);
  ASSERT_GT(gateway_command_task, state_task);
  ASSERT_GT(message_task, gateway_command_task);

  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 4);
  ASSERT_EQ(mapping_number(queued, "owner_executor_runnable_queue_depth"), 4);
  ASSERT_EQ(mapping_number(queued, "owner_executor_safe_queue_depth"), 1);
  ASSERT_EQ(mapping_number(queued, "owner_main_required_queue_depth"), 0);
  ASSERT_GE(mapping_number(queued, "executor_runnable_queue_depth"), 4);
  ASSERT_GE(mapping_number(queued, "executor_safe_queue_depth"), 1);
  free_mapping(queued);
  auto* queued_thread = vm_owner_thread_status();
  ASSERT_GE(mapping_number(queued_thread, "executor_runnable_queue_depth"), 4);
  auto* queued_fairness = find_string_in_mapping(queued_thread, "executor_queue_fairness");
  ASSERT_NE(queued_fairness, nullptr);
  ASSERT_EQ(queued_fairness->type, T_MAPPING);
  ASSERT_GE(mapping_number(queued_fairness->u.map, "executor_runnable_owner_count"), 1);
  ASSERT_GE(mapping_number(queued_fairness->u.map, "max_executor_runnable_backlog"), 4);
  ASSERT_GE(mapping_number(queued_fairness->u.map, "max_executor_safe_backlog"), 1);
  free_mapping(queued_thread);

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
  ASSERT_GE(mapping_number(running, "thread_gateway_command_rejected"), 1);
  ASSERT_GE(mapping_number(running, "thread_message_dispatched"), 1);
  ASSERT_EQ(mapping_number(running, "executor_runnable_task_dispatched"), before_runnable + 4);
  ASSERT_EQ(mapping_number(running, "executor_safe_task_dispatched"), before_safe + 1);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(16);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int lpc_rejected = 0;
  int state_guarded = 0;
  int gateway_command_rejected = 0;
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
    if (mapping_number(event, "task_id") == static_cast<long>(gateway_command_task) &&
        std::string(mapping_string(event, "state")) == "thread_gateway_command_rejected") {
      gateway_command_rejected = 1;
    }
    if (mapping_number(event, "task_id") == static_cast<long>(message_task) &&
        std::string(mapping_string(event, "state")) == "thread_message_dispatched") {
      message_dispatched = 1;
    }
  }
  ASSERT_EQ(lpc_rejected, 1);
  ASSERT_EQ(state_guarded, 1);
  ASSERT_EQ(gateway_command_rejected, 1);
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
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
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

TEST_F(DriverTest, TestVmOwnerThreadRunsRegisteredReadonlyLpcTaskWithMultipleWorkers) {
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
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_executed = mapping_number(before, "thread_lpc_task_executed");
  auto before_succeeded = mapping_number(before, "thread_lpc_task_succeeded");
  auto before_failed = mapping_number(before, "thread_lpc_task_failed");
  auto before_rejected = mapping_number(before, "thread_lpc_task_rejected");
  auto before_owner_cleared = mapping_number(before, "thread_owner_cleared");
  auto before_execution_cleared = mapping_number(before, "thread_execution_cleared");
  auto before_controlled_lpc_cleared = mapping_number(before, "thread_lpc_canary_flag_cleared");
  auto before_context_leaks = mapping_number(before, "thread_context_leak_detected");
  auto before_claims = mapping_number(before, "executor_owner_claims");
  auto before_releases = mapping_number(before, "executor_owner_releases");
  free_mapping(before);

  auto* submitted = vm_owner_lpc_task(probe, owner, "owner_task_readonly");
  auto task_id = mapping_number(submitted, "task_id");
  auto future_id = mapping_number(submitted, "future_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_GT(future_id, 0);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_thread"), 1);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_message_completion"), 1);
  ASSERT_EQ(mapping_number(submitted, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(submitted, "registered_task"), 1);
  ASSERT_EQ(mapping_number(submitted, "frozen_result_required"), 1);
  ASSERT_EQ(mapping_number(submitted, "ordinary_lpc_default_closed"), 1);
  ASSERT_EQ(mapping_number(submitted, "ordinary_lpc_activation_policy_ready"), 1);
  ASSERT_STREQ(mapping_string(submitted, "ordinary_lpc_activation_policy"), "default_closed_explicit_open");
  ASSERT_STREQ(mapping_string(submitted, "ordinary_lpc_next_blocker"), "");
  ASSERT_EQ(mapping_number(submitted, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(submitted, "owner_epoch"), static_cast<long>(owner_epoch));
  ASSERT_STREQ(mapping_string(submitted, "task_type"), "lpc_task");
  ASSERT_STREQ(mapping_string(submitted, "method"), "owner_task_readonly");
  ASSERT_STREQ(mapping_string(submitted, "executor_mode"), "executor_safe_allowlist");
  ASSERT_STREQ(mapping_string(submitted, "route"), "owner_executor");
  ASSERT_STREQ(mapping_string(submitted, "result_policy"), "frozen_result_required");
  ASSERT_STREQ(mapping_string(submitted, "contract_reason"), "registered readonly owner task with frozen result");
  auto* submitted_contract = mapping_entry(submitted, "task_contract");
  ASSERT_STREQ(mapping_string(submitted_contract, "method"), "owner_task_readonly");
  ASSERT_EQ(mapping_number(submitted_contract, "executor_safe"), 1);
  ASSERT_EQ(mapping_number(submitted_contract, "requires_target"), 1);
  ASSERT_EQ(mapping_number(submitted_contract, "frozen_result_required"), 1);
  free_mapping(submitted);
  auto* pending_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(pending_future, "success"), 1);
  ASSERT_STREQ(mapping_string(pending_future, "state"), "pending");
  ASSERT_EQ(mapping_number(pending_future, "target_task_id"), task_id);
  ASSERT_EQ(mapping_number(pending_future, "requires_owner_message_completion"), 1);
  free_mapping(pending_future);
  auto* pending_runtime = vm_owner_runtime_status();
  ASSERT_GE(mapping_number(pending_runtime, "pending_futures"), 1);
  ASSERT_EQ(mapping_number(pending_runtime, "lpc_task_allowlist_count"), 1);
  auto* runtime_allowlist = find_string_in_mapping(pending_runtime, "lpc_task_allowlist");
  ASSERT_NE(runtime_allowlist, nullptr);
  ASSERT_EQ(runtime_allowlist->type, T_ARRAY);
  ASSERT_EQ(runtime_allowlist->u.arr->size, 1);
  ASSERT_EQ(runtime_allowlist->u.arr->item[0].type, T_STRING);
  ASSERT_STREQ(runtime_allowlist->u.arr->item[0].u.string, "owner_task_readonly");
  free_mapping(pending_runtime);
  auto* pending_thread_status = vm_owner_thread_status();
  ASSERT_GE(mapping_number(pending_thread_status, "pending_futures"), 1);
  ASSERT_EQ(mapping_number(pending_thread_status, "lpc_task_allowlist_count"), 1);
  auto* thread_allowlist = find_string_in_mapping(pending_thread_status, "lpc_task_allowlist");
  ASSERT_NE(thread_allowlist, nullptr);
  ASSERT_EQ(thread_allowlist->type, T_ARRAY);
  ASSERT_EQ(thread_allowlist->u.arr->size, 1);
  ASSERT_EQ(thread_allowlist->u.arr->item[0].type, T_STRING);
  ASSERT_STREQ(thread_allowlist->u.arr->item[0].u.string, "owner_task_readonly");
  free_mapping(pending_thread_status);

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
    auto* polled = vm_owner_future_poll(static_cast<uint64_t>(future_id));
    auto completed = std::string(mapping_string(polled, "state")) == "completed";
    free_mapping(polled);
    if (owner_depth == 0 && other_depth == 0 && completed) {
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
  ASSERT_GE(mapping_number(running, "thread_owner_cleared"), before_owner_cleared + 1);
  ASSERT_GE(mapping_number(running, "thread_execution_cleared"), before_execution_cleared + 1);
  ASSERT_GE(mapping_number(running, "thread_lpc_canary_flag_cleared"), before_controlled_lpc_cleared + 1);
  ASSERT_EQ(mapping_number(running, "thread_context_leak_detected"), before_context_leaks);
  ASSERT_EQ(mapping_number(running, "active_owners"), 0);
  ASSERT_GE(mapping_number(running, "executor_owner_claims"), before_claims + 2);
  ASSERT_GE(mapping_number(running, "executor_owner_releases"), before_releases + 2);
  ASSERT_EQ(mapping_number(running, "executor_owner_claims") - before_claims,
            mapping_number(running, "executor_owner_releases") - before_releases);
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

  auto* completed_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(completed_future, "success"), 1);
  ASSERT_STREQ(mapping_string(completed_future, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed_future, "result_key"), "owner_task_readonly");
  ASSERT_EQ(mapping_number(completed_future, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed_future, "frozen_result"), 1);
  auto* result = find_string_in_mapping(completed_future, "result");
  ASSERT_NE(result, nullptr);
  ASSERT_EQ(result->type, T_NUMBER);
  ASSERT_EQ(result->u.number, 1);
  free_mapping(completed_future);
  auto* completed_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(completed_runtime, "pending_futures"), 0);
  free_mapping(completed_runtime);
  auto* completed_thread_status = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(completed_thread_status, "pending_futures"), 0);
  free_mapping(completed_thread_status);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerLpcTaskRejectsTargetOwnerMismatchAtSubmit) {
  const char* owner = "owner/test/thread/lpc-task-submit-owner";
  const char* other_owner = "owner/test/thread/lpc-task-submit-other";

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

  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  free_mapping(before_runtime);
  auto* before_owner_queue = vm_owner_mailbox_status(owner);
  auto before_owner_depth = mapping_number(before_owner_queue, "owner_queue_depth");
  free_mapping(before_owner_queue);
  auto* before_other_queue = vm_owner_mailbox_status(other_owner);
  auto before_other_depth = mapping_number(before_other_queue, "owner_queue_depth");
  free_mapping(before_other_queue);

  auto* submitted = vm_owner_lpc_task(probe, other_owner, "owner_task_readonly");
  ASSERT_EQ(mapping_number(submitted, "success"), 0);
  ASSERT_EQ(mapping_number(submitted, "future_id"), 0);
  ASSERT_EQ(mapping_number(submitted, "task_id"), 0);
  ASSERT_STREQ(mapping_string(submitted, "owner_id"), other_owner);
  ASSERT_STREQ(mapping_string(submitted, "target_owner_id"), owner);
  ASSERT_STREQ(mapping_string(submitted, "state"), "rejected");
  ASSERT_STREQ(mapping_string(submitted, "error"), "owner lpc task target owner mismatch");
  ASSERT_STREQ(mapping_string(submitted, "executor_mode"), "rejected");
  ASSERT_EQ(mapping_number(submitted, "requires_owner_thread"), 0);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(submitted, "direct_cross_owner_write"), 0);
  free_mapping(submitted);

  auto* after_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(after_runtime, "pending_futures"), before_pending_futures);
  free_mapping(after_runtime);
  auto* after_owner_queue = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(after_owner_queue, "owner_queue_depth"), before_owner_depth);
  free_mapping(after_owner_queue);
  auto* after_other_queue = vm_owner_mailbox_status(other_owner);
  ASSERT_EQ(mapping_number(after_other_queue, "owner_queue_depth"), before_other_depth);
  free_mapping(after_other_queue);

  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerOrdinaryLpcRequiresExplicitOpen) {
  const char* owner = "owner/test/thread/ordinary-lpc-closed";
  const char* other_owner = "owner/test/thread/ordinary-lpc-other";

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
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };

  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  free_mapping(before_runtime);
  auto* before_queue = vm_owner_mailbox_status(owner);
  auto before_depth = mapping_number(before_queue, "owner_queue_depth");
  free_mapping(before_queue);

  auto* closed = vm_owner_ordinary_lpc_task(probe, owner, "owner_task_player", 0);
  ASSERT_EQ(mapping_number(closed, "success"), 0);
  ASSERT_EQ(mapping_number(closed, "future_id"), 0);
  ASSERT_EQ(mapping_number(closed, "task_id"), 0);
  ASSERT_STREQ(mapping_string(closed, "task_type"), "ordinary_lpc");
  ASSERT_STREQ(mapping_string(closed, "method"), "owner_task_player");
  ASSERT_STREQ(mapping_string(closed, "state"), "rejected");
  ASSERT_STREQ(mapping_string(closed, "error"), "ordinary LPC requires explicit open");
  ASSERT_STREQ(mapping_string(closed, "contract_reason"), "ordinary LPC requires explicit open");
  ASSERT_STREQ(mapping_string(closed, "executor_mode"), "rejected");
  ASSERT_EQ(mapping_number(closed, "requires_owner_thread"), 0);
  ASSERT_EQ(mapping_number(closed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(closed, "ordinary_lpc_explicit_open"), 0);
  ASSERT_EQ(mapping_number(closed, "ordinary_lpc_dispatch_path_ready"), 1);
  ASSERT_STREQ(mapping_string(closed, "ordinary_lpc_next_blocker"), "");
  auto* closed_contract = mapping_entry(closed, "task_contract");
  ASSERT_EQ(mapping_number(closed_contract, "rejected"), 1);
  free_mapping(closed);

  auto* mismatch = vm_owner_ordinary_lpc_task(probe, other_owner, "owner_task_player", 1);
  ASSERT_EQ(mapping_number(mismatch, "success"), 0);
  ASSERT_EQ(mapping_number(mismatch, "future_id"), 0);
  ASSERT_EQ(mapping_number(mismatch, "task_id"), 0);
  ASSERT_STREQ(mapping_string(mismatch, "owner_id"), other_owner);
  ASSERT_STREQ(mapping_string(mismatch, "target_owner_id"), owner);
  ASSERT_STREQ(mapping_string(mismatch, "state"), "rejected");
  ASSERT_STREQ(mapping_string(mismatch, "error"), "ordinary LPC target owner mismatch");
  ASSERT_EQ(mapping_number(mismatch, "ordinary_lpc_explicit_open"), 1);
  free_mapping(mismatch);

  auto* after_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(after_runtime, "pending_futures"), before_pending_futures);
  free_mapping(after_runtime);
  auto* after_queue = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(after_queue, "owner_queue_depth"), before_depth);
  free_mapping(after_queue);

  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRunsExplicitOpenOrdinaryLpcTask) {
  const char* owner = "owner/test/thread/ordinary-lpc-open";
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
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_executed = mapping_number(before, "thread_ordinary_lpc_executed");
  auto before_succeeded = mapping_number(before, "thread_ordinary_lpc_succeeded");
  auto before_failed = mapping_number(before, "thread_ordinary_lpc_failed");
  auto before_rejected = mapping_number(before, "thread_ordinary_lpc_rejected");
  auto before_context_leaks = mapping_number(before, "thread_context_leak_detected");
  auto before_safe_dispatched = mapping_number(before, "executor_safe_task_dispatched");
  free_mapping(before);
  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  free_mapping(before_runtime);

  auto* submitted = vm_owner_ordinary_lpc_task(probe, owner, "owner_task_player", 1);
  auto task_id = mapping_number(submitted, "task_id");
  auto future_id = mapping_number(submitted, "future_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_GT(task_id, 0);
  ASSERT_GT(future_id, 0);
  ASSERT_STREQ(mapping_string(submitted, "task_type"), "ordinary_lpc");
  ASSERT_STREQ(mapping_string(submitted, "method"), "owner_task_player");
  ASSERT_EQ(mapping_number(submitted, "owner_epoch"), static_cast<long>(owner_epoch));
  ASSERT_STREQ(mapping_string(submitted, "executor_mode"), "executor_safe_explicit_open");
  ASSERT_STREQ(mapping_string(submitted, "route"), "owner_executor");
  ASSERT_STREQ(mapping_string(submitted, "result_policy"), "frozen_result_required");
  ASSERT_STREQ(mapping_string(submitted, "contract_reason"),
               "generic owner LPC dispatch requires explicit open and frozen result");
  ASSERT_EQ(mapping_number(submitted, "requires_owner_thread"), 1);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_message_completion"), 1);
  ASSERT_EQ(mapping_number(submitted, "ordinary_lpc_explicit_open"), 1);
  ASSERT_EQ(mapping_number(submitted, "ordinary_lpc_dispatch_path_ready"), 1);
  ASSERT_EQ(mapping_number(submitted, "frozen_result_required"), 1);
  auto* submitted_contract = mapping_entry(submitted, "task_contract");
  ASSERT_STREQ(mapping_string(submitted_contract, "dispatch_model"), "generic_owner_lpc_dispatch");
  ASSERT_EQ(mapping_number(submitted_contract, "explicit_open_required"), 1);
  ASSERT_EQ(mapping_number(submitted_contract, "frozen_result_required"), 1);
  free_mapping(submitted);

  auto* pending_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(pending_runtime, "pending_futures"), before_pending_futures + 1);
  free_mapping(pending_runtime);
  auto* pending_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_STREQ(mapping_string(pending_future, "state"), "pending");
  ASSERT_EQ(mapping_number(pending_future, "target_task_id"), task_id);
  ASSERT_EQ(mapping_number(pending_future, "requires_owner_message_completion"), 1);
  free_mapping(pending_future);

  vm_owner_thread_start(2);
  for (int i = 0; i < 100; i++) {
    auto* polled = vm_owner_future_poll(static_cast<uint64_t>(future_id));
    auto completed = std::string(mapping_string(polled, "state")) == "completed";
    free_mapping(polled);
    if (completed) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "thread_ordinary_lpc_executed"), before_executed + 1);
  ASSERT_GE(mapping_number(running, "thread_ordinary_lpc_succeeded"), before_succeeded + 1);
  ASSERT_EQ(mapping_number(running, "thread_ordinary_lpc_failed"), before_failed);
  ASSERT_EQ(mapping_number(running, "thread_ordinary_lpc_rejected"), before_rejected);
  ASSERT_GE(mapping_number(running, "executor_safe_task_dispatched"), before_safe_dispatched + 1);
  ASSERT_EQ(mapping_number(running, "thread_context_leak_detected"), before_context_leaks);
  free_mapping(running);

  auto* completed_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(completed_future, "success"), 1);
  ASSERT_STREQ(mapping_string(completed_future, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed_future, "result_key"), "owner_task_player");
  ASSERT_EQ(mapping_number(completed_future, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed_future, "frozen_result"), 1);
  auto* result = find_string_in_mapping(completed_future, "result");
  ASSERT_NE(result, nullptr);
  ASSERT_EQ(result->type, T_NUMBER);
  ASSERT_EQ(result->u.number, 1);
  free_mapping(completed_future);

  auto* trace = vm_owner_task_trace(32);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events->type, T_ARRAY);
  int ordinary_lpc_succeeded = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") == task_id &&
        std::string(mapping_string(event, "task_type")) == "ordinary_lpc" &&
        std::string(mapping_string(event, "state")) == "thread_ordinary_lpc_succeeded") {
      ordinary_lpc_succeeded = 1;
      ASSERT_STREQ(mapping_string(event, "task_key"), "owner_task_player");
      ASSERT_STREQ(mapping_string(event, "owner_id"), owner);
    }
  }
  ASSERT_EQ(ordinary_lpc_succeeded, 1);
  free_mapping(trace);

  auto* completed_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(completed_runtime, "pending_futures"), before_pending_futures);
  free_mapping(completed_runtime);

  vm_owner_thread_stop();
  ASSERT_TRUE(vm_context_is_main_thread());
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
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_succeeded = mapping_number(before, "thread_lpc_task_succeeded");
  auto before_rejected = mapping_number(before, "thread_lpc_task_rejected");
  free_mapping(before);
  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  auto before_future_failures = mapping_number(before_runtime, "futures_failed");
  free_mapping(before_runtime);

  auto* submitted = vm_owner_lpc_task(probe, owner, "owner_task_unregistered");
  auto task_id = mapping_number(submitted, "task_id");
  auto future_id = mapping_number(submitted, "future_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_EQ(mapping_number(submitted, "registered_task"), 0);
  ASSERT_STREQ(mapping_string(submitted, "executor_mode"), "rejected");
  ASSERT_STREQ(mapping_string(submitted, "route"), "owner_executor");
  ASSERT_STREQ(mapping_string(submitted, "result_policy"), "none");
  ASSERT_STREQ(mapping_string(submitted, "contract_reason"), "ordinary LPC remains default closed");
  ASSERT_EQ(mapping_number(submitted, "frozen_result_required"), 0);
  auto* submitted_contract = mapping_entry(submitted, "task_contract");
  ASSERT_STREQ(mapping_string(submitted_contract, "executor_mode"), "rejected");
  ASSERT_EQ(mapping_number(submitted_contract, "executor_safe"), 0);
  ASSERT_EQ(mapping_number(submitted_contract, "rejected"), 1);
  free_mapping(submitted);
  auto* pending_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(pending_future, "success"), 1);
  ASSERT_STREQ(mapping_string(pending_future, "state"), "pending");
  ASSERT_EQ(mapping_number(pending_future, "target_task_id"), task_id);
  ASSERT_EQ(mapping_number(pending_future, "requires_owner_message_completion"), 1);
  free_mapping(pending_future);
  auto* pending_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(pending_runtime, "pending_futures"), before_pending_futures + 1);
  free_mapping(pending_runtime);

  vm_owner_thread_start(2);
  for (int i = 0; i < 100; i++) {
    auto* status = vm_owner_mailbox_status(owner);
    auto depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    auto* polled = vm_owner_future_poll(static_cast<uint64_t>(future_id));
    auto failed = std::string(mapping_string(polled, "state")) == "failed";
    free_mapping(polled);
    if (depth == 0 && failed) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_succeeded"), before_succeeded);
  ASSERT_GE(mapping_number(running, "thread_lpc_task_rejected"), before_rejected + 1);
  free_mapping(running);

  auto* failed_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(failed_future, "success"), 1);
  ASSERT_STREQ(mapping_string(failed_future, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed_future, "error"), "owner lpc task rejected");
  ASSERT_EQ(mapping_number(failed_future, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed_future, "frozen_result"), 0);
  free_mapping(failed_future);
  auto* failed_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(failed_runtime, "pending_futures"), before_pending_futures);
  ASSERT_GE(mapping_number(failed_runtime, "futures_failed"), before_future_failures + 1);
  free_mapping(failed_runtime);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerThreadRejectsRegisteredDomainLpcTasks) {
  const char* owner = "owner/test/thread/lpc-domain-task";
  const char* methods[] = {"owner_task_player",      "owner_task_room",     "owner_task_session",
                           "owner_task_item",        "owner_task_economy",  "owner_task_combat",
                           "owner_task_mail",        "owner_task_reward",   "owner_task_world",
                           "owner_task_persistence", "owner_task_team",     "owner_task_guild",
                           "owner_task_sect",        "owner_task_quest",    "owner_task_rank",
                           "owner_task_crafting",    "owner_task_life_skill"};
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
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto mapping_entry = [](mapping_t* map, const char* key) -> mapping_t* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_MAPPING);
    return value && value->type == T_MAPPING ? value->u.map : nullptr;
  };

  auto* before = vm_owner_thread_status();
  auto before_succeeded = mapping_number(before, "thread_lpc_task_succeeded");
  auto before_failed = mapping_number(before, "thread_lpc_task_failed");
  auto before_rejected = mapping_number(before, "thread_lpc_task_rejected");
  auto before_claims = mapping_number(before, "executor_owner_claims");
  auto before_releases = mapping_number(before, "executor_owner_releases");
  free_mapping(before);
  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  auto before_future_failures = mapping_number(before_runtime, "futures_failed");
  free_mapping(before_runtime);

  std::vector<long> future_ids;
  future_ids.reserve(method_count);
  for (const auto* method : methods) {
    auto* submitted = vm_owner_lpc_task(probe, owner, method);
    auto future_id = mapping_number(submitted, "future_id");
    ASSERT_EQ(mapping_number(submitted, "success"), 1);
    ASSERT_GT(future_id, 0);
    ASSERT_EQ(mapping_number(submitted, "registered_task"), 0) << method;
    ASSERT_STREQ(mapping_string(submitted, "executor_mode"), "rejected") << method;
    ASSERT_STREQ(mapping_string(submitted, "contract_reason"), "ordinary LPC remains default closed") << method;
    auto* task_contract = mapping_entry(submitted, "task_contract");
    ASSERT_EQ(mapping_number(task_contract, "rejected"), 1) << method;
    free_mapping(submitted);
    auto* pending_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
    ASSERT_EQ(mapping_number(pending_future, "success"), 1);
    ASSERT_STREQ(mapping_string(pending_future, "state"), "pending") << method;
    ASSERT_EQ(mapping_number(pending_future, "requires_owner_message_completion"), 1) << method;
    free_mapping(pending_future);
    future_ids.push_back(future_id);
  }
  auto* pending_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(pending_runtime, "pending_futures"), before_pending_futures + method_count);
  free_mapping(pending_runtime);

  vm_owner_thread_start(4);
  for (int i = 0; i < 200; i++) {
    auto* status = vm_owner_thread_status();
    auto rejected = mapping_number(status, "thread_lpc_task_rejected");
    auto active = mapping_number(status, "active_owners");
    free_mapping(status);
    if (rejected >= before_rejected + method_count && active == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* running = vm_owner_thread_status();
  ASSERT_EQ(mapping_number(running, "enabled"), 1);
  ASSERT_EQ(mapping_number(running, "thread_count"), 4);
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_succeeded"), before_succeeded);
  ASSERT_EQ(mapping_number(running, "thread_lpc_task_failed"), before_failed);
  ASSERT_GE(mapping_number(running, "thread_lpc_task_rejected"), before_rejected + method_count);
  ASSERT_EQ(mapping_number(running, "active_owners"), 0);
  ASSERT_EQ(mapping_number(running, "executor_owner_claims"), before_claims + 1);
  ASSERT_EQ(mapping_number(running, "executor_owner_releases"), before_releases + 1);
  free_mapping(running);
  for (auto future_id : future_ids) {
    auto* failed_future = vm_owner_future_poll(static_cast<uint64_t>(future_id));
    ASSERT_EQ(mapping_number(failed_future, "success"), 1);
    ASSERT_STREQ(mapping_string(failed_future, "state"), "failed");
    ASSERT_STREQ(mapping_string(failed_future, "error"), "owner lpc task rejected");
    ASSERT_EQ(mapping_number(failed_future, "requires_owner_message_completion"), 0);
    free_mapping(failed_future);
  }
  auto* failed_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(failed_runtime, "pending_futures"), before_pending_futures);
  ASSERT_GE(mapping_number(failed_runtime, "futures_failed"), before_future_failures + method_count);
  free_mapping(failed_runtime);

  vm_owner_thread_stop();
  destruct_object(probe);
}

TEST_F(DriverTest, TestVmOwnerLpcTaskMainDrainAndScheduleFailPendingFuture) {
  const char* drain_owner = "owner/test/thread/lpc-task-main-drain";
  const char* schedule_owner = "owner/test/thread/lpc-task-schedule";
  ASSERT_TRUE(vm_context_is_main_thread());

  vm_owner_thread_stop();
  free_mapping(vm_owner_purge_mailbox(drain_owner));
  free_mapping(vm_owner_purge_mailbox(schedule_owner));
  object_t* drain_probe = load_object_for_test("single/void");
  object_t* schedule_probe = load_object_for_test("single/void");
  ASSERT_NE(drain_probe, nullptr);
  ASSERT_NE(schedule_probe, nullptr);
  vm_owner_set_id(drain_probe, drain_owner);
  vm_owner_set_id(schedule_probe, schedule_owner);

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

  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  auto before_future_failures = mapping_number(before_runtime, "futures_failed");
  free_mapping(before_runtime);

  auto* drain_submitted = vm_owner_lpc_task(drain_probe, drain_owner, "owner_task_readonly");
  auto drain_future_id = mapping_number(drain_submitted, "future_id");
  ASSERT_EQ(mapping_number(drain_submitted, "success"), 1);
  ASSERT_EQ(mapping_number(drain_submitted, "registered_task"), 1);
  free_mapping(drain_submitted);
  auto* drain_pending = vm_owner_future_poll(static_cast<uint64_t>(drain_future_id));
  ASSERT_STREQ(mapping_string(drain_pending, "state"), "pending");
  ASSERT_EQ(mapping_number(drain_pending, "requires_owner_message_completion"), 1);
  free_mapping(drain_pending);
  auto* after_drain_submit = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(after_drain_submit, "pending_futures"), before_pending_futures + 1);
  free_mapping(after_drain_submit);

  auto* drained = vm_owner_drain_mailbox(drain_owner, 1);
  ASSERT_EQ(mapping_number(drained, "drained"), 1);
  auto* drained_tasks = find_string_in_mapping(drained, "tasks");
  ASSERT_NE(drained_tasks, nullptr);
  ASSERT_EQ(drained_tasks->type, T_ARRAY);
  ASSERT_EQ(drained_tasks->u.arr->size, 1);
  ASSERT_STREQ(mapping_string(drained_tasks->u.arr->item[0].u.map, "task_type"), "lpc_task");
  ASSERT_STREQ(mapping_string(drained_tasks->u.arr->item[0].u.map, "task_key"), "owner_task_readonly");
  ASSERT_STREQ(mapping_string(drained_tasks->u.arr->item[0].u.map, "executor_mode"), "executor_safe");
  ASSERT_STREQ(mapping_string(drained_tasks->u.arr->item[0].u.map, "route"), "owner_executor");
  ASSERT_EQ(mapping_number(drained_tasks->u.arr->item[0].u.map, "executor_safe"), 1);
  ASSERT_EQ(mapping_number(drained_tasks->u.arr->item[0].u.map, "main_required"), 0);
  ASSERT_EQ(mapping_number(drained_tasks->u.arr->item[0].u.map, "requires_owner_mailbox"), 1);
  ASSERT_EQ(mapping_number(drained_tasks->u.arr->item[0].u.map, "requires_owner_main_queue"), 0);
  free_mapping(drained);
  auto* drain_failed = vm_owner_future_poll(static_cast<uint64_t>(drain_future_id));
  ASSERT_STREQ(mapping_string(drain_failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(drain_failed, "error"), "owner lpc task requires owner thread");
  ASSERT_EQ(mapping_number(drain_failed, "requires_owner_message_completion"), 0);
  free_mapping(drain_failed);

  auto* schedule_submitted = vm_owner_lpc_task(schedule_probe, schedule_owner, "owner_task_readonly");
  auto schedule_future_id = mapping_number(schedule_submitted, "future_id");
  ASSERT_EQ(mapping_number(schedule_submitted, "success"), 1);
  ASSERT_EQ(mapping_number(schedule_submitted, "registered_task"), 1);
  free_mapping(schedule_submitted);
  auto* schedule_pending = vm_owner_future_poll(static_cast<uint64_t>(schedule_future_id));
  ASSERT_STREQ(mapping_string(schedule_pending, "state"), "pending");
  ASSERT_EQ(mapping_number(schedule_pending, "requires_owner_message_completion"), 1);
  free_mapping(schedule_pending);
  auto* after_schedule_submit = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(after_schedule_submit, "pending_futures"), before_pending_futures + 1);
  free_mapping(after_schedule_submit);

  auto* scheduled = vm_owner_schedule(1);
  ASSERT_EQ(mapping_number(scheduled, "dispatched"), 1);
  auto* scheduled_tasks = find_string_in_mapping(scheduled, "tasks");
  ASSERT_NE(scheduled_tasks, nullptr);
  ASSERT_EQ(scheduled_tasks->type, T_ARRAY);
  ASSERT_EQ(scheduled_tasks->u.arr->size, 1);
  ASSERT_STREQ(mapping_string(scheduled_tasks->u.arr->item[0].u.map, "task_type"), "lpc_task");
  ASSERT_STREQ(mapping_string(scheduled_tasks->u.arr->item[0].u.map, "task_key"), "owner_task_readonly");
  ASSERT_STREQ(mapping_string(scheduled_tasks->u.arr->item[0].u.map, "executor_mode"), "executor_safe");
  ASSERT_STREQ(mapping_string(scheduled_tasks->u.arr->item[0].u.map, "route"), "owner_executor");
  ASSERT_EQ(mapping_number(scheduled_tasks->u.arr->item[0].u.map, "executor_safe"), 1);
  ASSERT_EQ(mapping_number(scheduled_tasks->u.arr->item[0].u.map, "main_required"), 0);
  ASSERT_EQ(mapping_number(scheduled_tasks->u.arr->item[0].u.map, "requires_owner_mailbox"), 1);
  ASSERT_EQ(mapping_number(scheduled_tasks->u.arr->item[0].u.map, "requires_owner_main_queue"), 0);
  free_mapping(scheduled);
  auto* schedule_failed = vm_owner_future_poll(static_cast<uint64_t>(schedule_future_id));
  ASSERT_STREQ(mapping_string(schedule_failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(schedule_failed, "error"), "owner lpc task requires owner thread");
  ASSERT_EQ(mapping_number(schedule_failed, "requires_owner_message_completion"), 0);
  free_mapping(schedule_failed);

  auto* failed_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(failed_runtime, "pending_futures"), before_pending_futures);
  ASSERT_GE(mapping_number(failed_runtime, "futures_failed"), before_future_failures + 2);
  free_mapping(failed_runtime);

  vm_owner_clear_id(drain_probe);
  vm_owner_clear_id(schedule_probe);
  destruct_object(drain_probe);
  destruct_object(schedule_probe);
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
  ASSERT_EQ(mapping_number(submitted, "payload_frozen"), 1);
  ASSERT_STREQ(mapping_string(submitted, "source_owner_id"), source_owner);
  ASSERT_STREQ(mapping_string(submitted, "target_owner_id"), target_owner);
  ASSERT_STREQ(mapping_string(submitted, "message_type"), "room_snapshot");

  auto message_id = mapping_number(submitted, "message_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  auto* queued = vm_owner_mailbox_status(target_owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 1);
  free_mapping(queued);

  auto* message_trace = vm_owner_message_trace(1);
  ASSERT_STREQ(mapping_string(message_trace, "trace_kind"), "owner_message_trace");
  ASSERT_STREQ(mapping_string(message_trace, "trace_model"), "owner_message_lifecycle_trace");
  auto* message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  auto* message_event = message_events->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(message_event, "trace_model"), "owner_message_lifecycle_event");
  ASSERT_EQ(mapping_number(message_event, "message_id"), message_id);
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_EQ(mapping_number(message_event, "direct_cross_owner_write"), 0);
  ASSERT_EQ(mapping_number(message_event, "payload_frozen"), 1);
  ASSERT_STREQ(mapping_string(message_event, "state"), "message_submitted");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_mailbox");
  ASSERT_STREQ(mapping_string(message_event, "result_key"), "");
  ASSERT_STREQ(mapping_string(message_event, "error"), "");
  ASSERT_STREQ(mapping_string(message_event, "target_handle_status"), "current");
  ASSERT_EQ(mapping_number(message_event, "pending"), 1);
  ASSERT_EQ(mapping_number(message_event, "completed"), 0);
  ASSERT_EQ(mapping_number(message_event, "failed"), 0);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 0);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  ASSERT_EQ(mapping_number(message_event, "has_target_handle"), 0);
  ASSERT_EQ(mapping_number(message_event, "target_handle_current"), 1);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_mailbox"), 1);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_main_queue"), 0);
  ASSERT_EQ(mapping_number(message_event, "main_required"), 0);
  ASSERT_EQ(mapping_number(message_event, "queued_on_main"), 0);
  ASSERT_EQ(mapping_number(message_event, "message_only_cross_owner"), 1);
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
  ASSERT_STREQ(mapping_string(commit_trace, "trace_kind"), "owner_commit_trace");
  ASSERT_STREQ(mapping_string(commit_trace, "trace_model"), "owner_commit_boundary_trace");
  auto* commit_events = find_string_in_mapping(commit_trace, "events");
  ASSERT_NE(commit_events, nullptr);
  ASSERT_EQ(commit_events->type, T_ARRAY);
  ASSERT_EQ(commit_events->u.arr->size, 1);
  auto* commit_event = commit_events->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(commit_event, "trace_model"), "owner_commit_boundary_event");
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

  message_trace = vm_owner_message_trace(1);
  message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  message_event = message_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "message_id"), message_id);
  ASSERT_EQ(mapping_number(message_event, "payload_frozen"), 1);
  ASSERT_STREQ(mapping_string(message_event, "state"), "completed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_mailbox");
  ASSERT_STREQ(mapping_string(message_event, "result_key"), "room_snapshot");
  ASSERT_STREQ(mapping_string(message_event, "error"), "");
  ASSERT_EQ(mapping_number(message_event, "pending"), 0);
  ASSERT_EQ(mapping_number(message_event, "completed"), 1);
  ASSERT_EQ(mapping_number(message_event, "failed"), 0);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_mailbox"), 1);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_main_queue"), 0);
  free_mapping(message_trace);
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
  ASSERT_EQ(mapping_number(pending, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(pending, "frozen_result"), 0);
  ASSERT_STREQ(mapping_string(pending, "state"), "pending");
  free_mapping(pending);

  free_mapping(vm_owner_drain_mailbox(target_owner, 1));
  auto* completed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(completed, "success"), 1);
  ASSERT_EQ(mapping_number(completed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(completed, "frozen_result"), 0);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "future_method");
  free_mapping(completed);
  free_mapping(submitted);
}

TEST_F(DriverTest, TestVmOwnerPurgeFailsPendingFuture) {
  const char* source_owner = "owner/test/future/purge-source";
  const char* target_owner = "owner/test/future/purge-target";

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
  auto* submitted = vm_owner_submit_message(source_owner, target_owner, "future_method", "future/purge");
  auto future_id = mapping_number(submitted, "future_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  ASSERT_GT(future_id, 0);
  ASSERT_GT(target_task_id, 0);
  free_mapping(submitted);

  auto* purged = vm_owner_purge_mailbox(target_owner);
  ASSERT_EQ(mapping_number(purged, "purged"), 1);
  free_mapping(purged);

  auto* failed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(failed, "success"), 1);
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "purged");
  free_mapping(failed);

  auto* message_trace = vm_owner_message_trace(1);
  auto* message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  auto* message_event = message_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(message_event, "state"), "failed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_mailbox");
  ASSERT_STREQ(mapping_string(message_event, "error"), "purged");
  ASSERT_EQ(mapping_number(message_event, "failed"), 1);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  free_mapping(message_trace);
}

TEST_F(DriverTest, TestVmOwnerObjectMessageFailsStaleTargetHandle) {
  const char* old_owner = "owner/test/future/object-old";
  const char* new_owner = "owner/test/future/object-new";

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

  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, old_owner);
  auto handle = vm_object_handle(obj);

  auto* submitted = vm_owner_submit_object_message("owner/test/future/object-source", handle,
                                                   "object_method", "object/payload");
  auto future_id = mapping_number(submitted, "future_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  ASSERT_EQ(mapping_number(submitted, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(submitted, "target_handle_current"), 1);
  ASSERT_STREQ(mapping_string(submitted, "target_handle_status"), "current");
  free_mapping(submitted);

  vm_owner_set_id(obj, new_owner);
  auto stale_status = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(stale_status.object, nullptr);
  ASSERT_EQ(stale_status.status, VMObjectHandleResolveStatus::kOwnerMismatch);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(stale_status.status), "owner_mismatch");
  ASSERT_TRUE(stale_status.diagnosed_via_owner_local_store);
  ASSERT_TRUE(stale_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(stale_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(stale_status.diagnosed_via_global_index);
  ASSERT_EQ(vm_owner_drain_main_tasks(1), 1);

  auto* failed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(failed, "success"), 1);
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(failed, "target_handle_current"), 0);
  ASSERT_STREQ(mapping_string(failed, "target_handle_status"), "owner_mismatch");
  ASSERT_EQ(mapping_number(failed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "stale target: owner_mismatch");
  free_mapping(failed);

  auto* owner_status = vm_object_store_owner_status(old_owner);
  ASSERT_EQ(mapping_number(owner_status, "pending_messages"), 0);
  free_mapping(owner_status);

  auto* message_trace = vm_owner_message_trace(1);
  auto* message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  auto* message_event = message_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(message_event, "state"), "failed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(message_event, "error"), "stale target: owner_mismatch");
  ASSERT_STREQ(mapping_string(message_event, "target_handle_status"), "owner_mismatch");
  ASSERT_EQ(mapping_number(message_event, "failed"), 1);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(message_event, "target_handle_current"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_main_queue"), 1);
  ASSERT_EQ(mapping_number(message_event, "queued_on_main"), 1);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  free_mapping(message_trace);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerObjectMessageRejectsStaleTargetHandleAtSubmit) {
  const char* old_owner = "owner/test/future/object-stale-submit-old";
  const char* new_owner = "owner/test/future/object-stale-submit-new";

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

  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, old_owner);
  auto handle = vm_object_handle(obj);
  vm_owner_set_id(obj, new_owner);

  auto stale_status = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(stale_status.object, nullptr);
  ASSERT_EQ(stale_status.status, VMObjectHandleResolveStatus::kOwnerMismatch);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(stale_status.status), "owner_mismatch");

  auto* submitted = vm_owner_submit_object_message("owner/test/future/object-source", handle,
                                                   "object_method", "stale-at-submit");
  auto future_id = mapping_number(submitted, "future_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  ASSERT_EQ(mapping_number(submitted, "success"), 1);
  ASSERT_EQ(mapping_number(submitted, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(submitted, "target_handle_current"), 0);
  ASSERT_STREQ(mapping_string(submitted, "target_handle_status"), "owner_mismatch");
  ASSERT_EQ(mapping_number(submitted, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(submitted, "requires_owner_main_queue"), 0);
  ASSERT_EQ(mapping_number(submitted, "main_required"), 1);
  ASSERT_EQ(mapping_number(submitted, "queued_on_main"), 0);
  free_mapping(submitted);

  auto* failed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(failed, "success"), 1);
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(failed, "target_handle_current"), 0);
  ASSERT_STREQ(mapping_string(failed, "target_handle_status"), "owner_mismatch");
  ASSERT_EQ(mapping_number(failed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "stale target: owner_mismatch");
  free_mapping(failed);

  auto* owner_status = vm_object_store_owner_status(old_owner);
  ASSERT_EQ(mapping_number(owner_status, "pending_messages"), 0);
  free_mapping(owner_status);
  ASSERT_EQ(vm_owner_drain_main_tasks(1), 0);

  auto* message_trace = vm_owner_message_trace(1);
  auto* message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  auto* message_event = message_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(message_event, "state"), "failed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(message_event, "error"), "stale target: owner_mismatch");
  ASSERT_STREQ(mapping_string(message_event, "target_handle_status"), "owner_mismatch");
  ASSERT_EQ(mapping_number(message_event, "failed"), 1);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(message_event, "target_handle_current"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_mailbox"), 0);
  ASSERT_EQ(mapping_number(message_event, "requires_owner_main_queue"), 0);
  ASSERT_EQ(mapping_number(message_event, "main_required"), 0);
  ASSERT_EQ(mapping_number(message_event, "queued_on_main"), 0);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  free_mapping(message_trace);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmOwnerObjectMessageReportsDestructedTargetHandle) {
  const char* owner = "owner/test/future/object-destructed";

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

  object_t* obj = load_object_for_test("single/on_destruct_good");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, owner);
  auto handle = vm_object_handle(obj);

  auto* submitted = vm_owner_submit_object_message("owner/test/future/object-source", handle,
                                                   "dummy", "object/destructed");
  auto future_id = mapping_number(submitted, "future_id");
  auto target_task_id = mapping_number(submitted, "target_task_id");
  ASSERT_EQ(mapping_number(submitted, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(submitted, "target_handle_current"), 1);
  ASSERT_STREQ(mapping_string(submitted, "target_handle_status"), "current");
  free_mapping(submitted);

  destruct_object(obj);
  auto stale_status = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(stale_status.object, nullptr);
  ASSERT_EQ(stale_status.status, VMObjectHandleResolveStatus::kRecordDestructed);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(stale_status.status), "record_destructed");
  ASSERT_TRUE(stale_status.diagnosed_via_owner_local_store);
  ASSERT_FALSE(stale_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(stale_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(stale_status.diagnosed_via_global_index);
  ASSERT_EQ(vm_owner_drain_main_tasks(1), 1);

  auto* failed = vm_owner_future_poll(static_cast<uint64_t>(future_id));
  ASSERT_EQ(mapping_number(failed, "success"), 1);
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(failed, "target_handle_current"), 0);
  ASSERT_STREQ(mapping_string(failed, "target_handle_status"), "record_destructed");
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "stale target: record_destructed");
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  free_mapping(failed);

  auto* owner_status = vm_object_store_owner_status(owner);
  ASSERT_EQ(mapping_number(owner_status, "pending_messages"), 0);
  free_mapping(owner_status);

  auto* message_trace = vm_owner_message_trace(1);
  auto* message_events = find_string_in_mapping(message_trace, "events");
  ASSERT_NE(message_events, nullptr);
  ASSERT_EQ(message_events->type, T_ARRAY);
  ASSERT_EQ(message_events->u.arr->size, 1);
  auto* message_event = message_events->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(message_event, "target_task_id"), target_task_id);
  ASSERT_STREQ(mapping_string(message_event, "state"), "failed");
  ASSERT_STREQ(mapping_string(message_event, "route"), "owner_main_queue");
  ASSERT_STREQ(mapping_string(message_event, "error"), "stale target: record_destructed");
  ASSERT_STREQ(mapping_string(message_event, "target_handle_status"), "record_destructed");
  ASSERT_EQ(mapping_number(message_event, "failed"), 1);
  ASSERT_EQ(mapping_number(message_event, "terminal"), 1);
  ASSERT_EQ(mapping_number(message_event, "has_target_handle"), 1);
  ASSERT_EQ(mapping_number(message_event, "target_handle_current"), 0);
  ASSERT_EQ(mapping_number(message_event, "queued_on_main"), 1);
  ASSERT_EQ(mapping_number(message_event, "frozen_result"), 0);
  free_mapping(message_trace);
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

  vm_owner_set_id(obj, "owner/test/handle/epoch");
  auto handle = vm_object_handle(obj);
  ASSERT_TRUE(handle.valid);
  ASSERT_EQ(vm_object_handle_resolve(handle), obj);

  vm_owner_clear_id(obj);
  vm_owner_set_id(obj, "owner/test/handle/epoch");
  auto stale_status = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(stale_status.object, nullptr);
  ASSERT_EQ(stale_status.status, VMObjectHandleResolveStatus::kOwnerEpochMismatch);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(stale_status.status), "owner_epoch_mismatch");
  ASSERT_TRUE(stale_status.diagnosed_via_owner_local_store);
  ASSERT_FALSE(stale_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(stale_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(stale_status.diagnosed_via_global_index);
  ASSERT_FALSE(vm_object_handle_is_current(handle));

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmObjectHandleReportsBasicResolveFailures) {
  VMObjectHandle invalid_handle;
  auto invalid_status = vm_object_handle_resolve_status(invalid_handle);
  ASSERT_EQ(invalid_status.object, nullptr);
  ASSERT_EQ(invalid_status.status, VMObjectHandleResolveStatus::kInvalidHandle);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(invalid_status.status), "invalid_handle");

  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/handle/basic");
  auto handle = vm_object_handle(obj);
  ASSERT_TRUE(handle.valid);

  auto missing_path_handle = handle;
  missing_path_handle.object_path.clear();
  auto missing_path_status = vm_object_handle_resolve_status(missing_path_handle);
  ASSERT_EQ(missing_path_status.object, nullptr);
  ASSERT_EQ(missing_path_status.status, VMObjectHandleResolveStatus::kMissingPath);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(missing_path_status.status), "missing_path");

  auto object_id_mismatch_handle = handle;
  object_id_mismatch_handle.object_id++;
  auto object_id_mismatch_status = vm_object_handle_resolve_status(object_id_mismatch_handle);
  ASSERT_EQ(object_id_mismatch_status.object, nullptr);
  ASSERT_EQ(object_id_mismatch_status.status, VMObjectHandleResolveStatus::kObjectIdMismatch);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(object_id_mismatch_status.status), "object_id_mismatch");
  ASSERT_TRUE(object_id_mismatch_status.diagnosed_via_owner_local_store);
  ASSERT_TRUE(object_id_mismatch_status.diagnosed_via_owner_local_path_index);
  ASSERT_FALSE(object_id_mismatch_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(object_id_mismatch_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(object_id_mismatch_status.global_live_object_found);
  ASSERT_TRUE(object_id_mismatch_status.global_live_object_source.empty());
  ASSERT_FALSE(object_id_mismatch_status.global_record_found);
  ASSERT_FALSE(object_id_mismatch_status.global_record_id_scan_bridge_used);
  ASSERT_FALSE(object_id_mismatch_status.global_record_id_scan_bridge_found);
  ASSERT_TRUE(object_id_mismatch_status.global_record_id_scan_bridge_source.empty());
  ASSERT_FALSE(object_id_mismatch_status.global_record_id_scan_bridge_skipped);
  ASSERT_TRUE(object_id_mismatch_status.global_record_id_scan_bridge_skip_reason.empty());
  ASSERT_FALSE(object_id_mismatch_status.global_record_pointer_bridge_used);
  ASSERT_FALSE(object_id_mismatch_status.global_record_pointer_bridge_found);
  ASSERT_TRUE(object_id_mismatch_status.global_record_pointer_bridge_source.empty());
  ASSERT_FALSE(object_id_mismatch_status.global_record_pointer_bridge_skipped);
  ASSERT_TRUE(object_id_mismatch_status.global_record_pointer_bridge_skip_reason.empty());
  ASSERT_FALSE(object_id_mismatch_status.diagnosed_via_global_index);

  auto object_not_found_handle = handle;
  object_not_found_handle.object_id += 1000000;
  object_not_found_handle.object_path += ".missing";
  auto object_not_found_status = vm_object_handle_resolve_status(object_not_found_handle);
  ASSERT_EQ(object_not_found_status.object, nullptr);
  ASSERT_EQ(object_not_found_status.status, VMObjectHandleResolveStatus::kObjectNotFound);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(object_not_found_status.status), "object_not_found");
  ASSERT_FALSE(object_not_found_status.diagnosed_via_owner_local_store);
  ASSERT_FALSE(object_not_found_status.diagnosed_via_owner_local_path_index);
  ASSERT_FALSE(object_not_found_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(object_not_found_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(object_not_found_status.global_live_object_found);
  ASSERT_TRUE(object_not_found_status.global_live_object_source.empty());
  ASSERT_TRUE(object_not_found_status.global_live_object_bridge_retirement_ready);
  ASSERT_TRUE(object_not_found_status.global_live_object_fallback_skipped);
  ASSERT_EQ(object_not_found_status.global_live_object_fallback_reason,
            "global_live_object_bridge_retirement_ready");
  ASSERT_FALSE(object_not_found_status.global_record_found);
  ASSERT_FALSE(object_not_found_status.global_record_id_scan_bridge_used);
  ASSERT_FALSE(object_not_found_status.global_record_id_scan_bridge_found);
  ASSERT_TRUE(object_not_found_status.global_record_id_scan_bridge_source.empty());
  ASSERT_TRUE(object_not_found_status.global_record_id_scan_bridge_skipped);
  ASSERT_EQ(object_not_found_status.global_record_id_scan_bridge_skip_reason,
            "global_record_bridge_retirement_ready");
  ASSERT_FALSE(object_not_found_status.global_record_pointer_bridge_used);
  ASSERT_FALSE(object_not_found_status.global_record_pointer_bridge_found);
  ASSERT_TRUE(object_not_found_status.global_record_pointer_bridge_source.empty());
  ASSERT_FALSE(object_not_found_status.global_record_pointer_bridge_skipped);
  ASSERT_TRUE(object_not_found_status.global_record_pointer_bridge_skip_reason.empty());
  ASSERT_TRUE(object_not_found_status.global_record_bridge_retirement_ready);
  ASSERT_TRUE(object_not_found_status.global_record_fallback_skipped);
  ASSERT_EQ(object_not_found_status.global_record_fallback_reason, "global_record_bridge_retirement_ready");
  ASSERT_FALSE(object_not_found_status.diagnosed_via_global_index);
  ASSERT_FALSE(object_not_found_status.resolved_via_global_index);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmObjectStoreReportsPointerBridgeSkippedWhenRecordBridgeRetired) {
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

  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/pointer-bridge/record-ready");
  vm_object_store_register(obj);
  auto handle = vm_object_handle(obj);
  ASSERT_TRUE(handle.valid);
  ASSERT_TRUE(
      vm_object_store_test_support_remove_live_object_ref_for_bridge_readiness(handle.owner_id.c_str(),
                                                                              handle.object_id));

  auto* store_status = vm_object_store_status();
  ASSERT_EQ(mapping_number(store_status, "owner_local_record_index_ready"), 1);
  ASSERT_EQ(mapping_number(store_status, "owner_local_canonical_record_ready"), 0);
  ASSERT_EQ(mapping_number(store_status, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(store_status, "global_live_object_bridge_retirement_ready"), 0);
  free_mapping(store_status);

  std::string bridge_path = "test/pointer_bridge_live_only";
  object_t live_only_object{};
  live_only_object.obname = bridge_path.c_str();
  live_only_object.flags = 0;
  ASSERT_TRUE(ObjectTable::instance().insert(bridge_path, &live_only_object));
  struct ObjectTableEntryGuard {
    std::string path;
    ~ObjectTableEntryGuard() { ObjectTable::instance().remove(path); }
  } bridge_entry{bridge_path};

  VMObjectHandle bridge_handle;
  bridge_handle.valid = true;
  bridge_handle.object_id = handle.object_id + 1000000;
  bridge_handle.owner_id = "owner/test/pointer-bridge/missing";
  bridge_handle.owner_epoch = 1;
  bridge_handle.object_path = bridge_path;

  auto handle_status = vm_object_handle_resolve_status(bridge_handle);
  ASSERT_EQ(handle_status.object, nullptr);
  ASSERT_EQ(handle_status.status, VMObjectHandleResolveStatus::kObjectNotFound);
  ASSERT_TRUE(handle_status.global_live_object_found);
  ASSERT_EQ(handle_status.global_live_object_source, "ObjectTable.global_live_object_bridge");
  ASSERT_FALSE(handle_status.global_live_object_bridge_retirement_ready);
  ASSERT_FALSE(handle_status.global_live_object_fallback_skipped);
  ASSERT_FALSE(handle_status.global_record_pointer_bridge_used);
  ASSERT_FALSE(handle_status.global_record_pointer_bridge_found);
  ASSERT_TRUE(handle_status.global_record_pointer_bridge_source.empty());
  ASSERT_TRUE(handle_status.global_record_pointer_bridge_skipped);
  ASSERT_EQ(handle_status.global_record_pointer_bridge_skip_reason, "global_record_bridge_retirement_ready");
  ASSERT_TRUE(handle_status.global_record_bridge_retirement_ready);
  ASSERT_TRUE(handle_status.global_record_fallback_skipped);
  ASSERT_EQ(handle_status.global_record_fallback_reason, "global_record_bridge_retirement_ready");
  ASSERT_FALSE(handle_status.global_record_found);
  ASSERT_FALSE(handle_status.diagnosed_via_global_index);
  ASSERT_FALSE(handle_status.resolved_via_global_index);

  auto* path_lookup =
      vm_object_store_owner_path_lookup_status("owner/test/pointer-bridge/missing", bridge_path.c_str());
  ASSERT_EQ(mapping_number(path_lookup, "success"), 1);
  ASSERT_EQ(mapping_number(path_lookup, "found"), 0);
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_live_object_found"), 1);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_live_object_source"),
               "ObjectTable.global_live_object_bridge");
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_live_object_fallback_skipped"), 0);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_live_object_fallback_reason"), "");
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_pointer_bridge_used"), 0);
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_pointer_bridge_found"), 0);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_record_pointer_bridge_source"), "");
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_pointer_bridge_skipped"), 1);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_record_pointer_bridge_skip_reason"),
               "global_record_bridge_retirement_ready");
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_found"), 0);
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_fallback_skipped"), 1);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_record_fallback_reason"),
               "global_record_bridge_retirement_ready");
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_scan_bridge_used"), 0);
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_scan_bridge_found"), 0);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_record_scan_bridge_source"), "");
  ASSERT_EQ(mapping_number(path_lookup, "owner_local_global_record_scan_bridge_skipped"), 1);
  ASSERT_STREQ(mapping_string(path_lookup, "owner_local_global_record_scan_bridge_skip_reason"),
               "global_record_bridge_retirement_ready");
  ASSERT_EQ(mapping_number(path_lookup, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(path_lookup, "global_live_object_bridge_retirement_ready"), 0);
  free_mapping(path_lookup);

  vm_owner_clear_id(obj);
  destruct_object(obj);
}

TEST_F(DriverTest, TestVmObjectStoreRecordsOwnerMigrationTrace) {
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
  auto expect_owner_local_store_complete_contract = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_store_complete"), 1);
    ASSERT_STREQ(mapping_string(map, "owner_local_store_complete_blocker"), "");
    ASSERT_EQ(mapping_number(map, "uses_global_object_table"), 0);
    ASSERT_EQ(mapping_number(map, "global_index_bridge"), 0);
    ASSERT_EQ(mapping_number(map, "global_live_object_bridge_ready"), 0);
    ASSERT_STREQ(mapping_string(map, "global_live_object_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "global_record_bridge_ready"), 0);
    ASSERT_STREQ(mapping_string(map, "global_record_bridge_source"), "");
  };
  auto expect_no_lookup_global_live_object = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_live_object_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_live_object_source"), "");
    ASSERT_EQ(mapping_number(map, "global_live_object_bridge_retirement_ready"), 1);
    ASSERT_EQ(mapping_number(map, "owner_local_global_live_object_fallback_skipped"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_live_object_fallback_reason"), "");
  };
  auto expect_no_lookup_global_record_id_scan = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_id_scan_bridge_used"), 0);
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_id_scan_bridge_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_id_scan_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_id_scan_bridge_skipped"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_id_scan_bridge_skip_reason"), "");
  };
  auto expect_skipped_lookup_global_record_id_scan = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_id_scan_bridge_used"), 0);
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_id_scan_bridge_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_id_scan_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_id_scan_bridge_skipped"), 1);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_id_scan_bridge_skip_reason"),
                 "global_record_bridge_retirement_ready");
  };
  auto expect_no_lookup_global_record_pointer = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_pointer_bridge_used"), 0);
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_pointer_bridge_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_pointer_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_pointer_bridge_skipped"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_pointer_bridge_skip_reason"), "");
  };
  auto expect_no_lookup_global_record_scan = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_scan_bridge_used"), 0);
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_scan_bridge_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_scan_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_scan_bridge_skipped"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_scan_bridge_skip_reason"), "");
  };
  auto expect_skipped_lookup_global_record_scan = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_scan_bridge_used"), 0);
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_scan_bridge_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_scan_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "owner_local_global_record_scan_bridge_skipped"), 1);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_record_scan_bridge_skip_reason"),
                 "global_record_bridge_retirement_ready");
  };

  object_t* obj = load_object_for_test("single/void");
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/migration/a");
  vm_object_store_register(obj);

  auto* before = vm_object_store_status();
  auto before_migrations = mapping_number(before, "migration_count");
  ASSERT_STREQ(mapping_string(before, "store_kind"), "vm_object_store");
  ASSERT_STREQ(mapping_string(before, "status_model"), "object_store_status");
  ASSERT_STREQ(mapping_string(before, "directory_model"), "owner_local_object_directory");
  ASSERT_STREQ(mapping_string(before, "storage_model"), "owner_local_store");
  ASSERT_EQ(mapping_number(before, "owner_local_global_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_to_global_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "global_to_owner_local_bridge_consistent"), 1);
  ASSERT_STREQ(mapping_string(before, "owner_local_global_bridge_check"), "bidirectional");
  ASSERT_STREQ(mapping_string(before, "owner_local_global_bridge_source"), "vm_object_shard");
  expect_owner_local_store_complete_contract(before);
  ASSERT_EQ(mapping_number(before, "owner_local_orphan_record_total"), 0);
  ASSERT_EQ(mapping_number(before, "owner_local_to_global_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(before, "global_to_owner_local_record_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(before, "global_to_owner_local_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(before, "owner_local_record_index_ready"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(before, "global_record_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(before, "global_live_object_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(before, "global_record_total"), mapping_number(before, "registered_objects"));
  ASSERT_GE(mapping_number(before, "global_live_record_total"), 1);
  free_mapping(before);

  auto handle = vm_object_handle(obj);
  ASSERT_EQ(vm_object_store_owner_resolve("owner/test/migration/a", handle.object_id), obj);
  ASSERT_EQ(vm_object_store_owner_path_resolve("owner/test/migration/a", handle.object_path.c_str()), obj);
  auto* old_lookup_before = vm_object_store_owner_lookup_status("owner/test/migration/a", handle.object_id);
  ASSERT_EQ(mapping_number(old_lookup_before, "success"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "record_found"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "found"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_directory_entry"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_mismatch"), 0);
  ASSERT_EQ(mapping_number(old_lookup_before, "destructed"), 0);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_record_found"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_destructed_record_found"), 0);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_record_destructed"), 0);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_resolve_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_destructed_path_index_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_path_index_source"), "vm_object_shard.object_path_index");
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_record_source"), "vm_object_shard.local_records");
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(old_lookup_before, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_before, "owner_local_store_complete_blocker"), "");
  ASSERT_EQ(mapping_number(old_lookup_before, "global_index_bridge"), 0);
  expect_no_lookup_global_live_object(old_lookup_before);
  expect_no_lookup_global_record_id_scan(old_lookup_before);
  expect_no_lookup_global_record_pointer(old_lookup_before);
  expect_no_lookup_global_record_scan(old_lookup_before);
  ASSERT_STREQ(mapping_string(old_lookup_before, "record_owner_id"), "owner/test/migration/a");
  ASSERT_STREQ(mapping_string(old_lookup_before, "object_path"), handle.object_path.c_str());
  free_mapping(old_lookup_before);
  auto* old_path_lookup_before =
      vm_object_store_owner_path_lookup_status("owner/test/migration/a", handle.object_path.c_str());
  ASSERT_EQ(mapping_number(old_path_lookup_before, "success"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_before, "record_found"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_before, "found"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_before, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(old_path_lookup_before, "owner_local_object_ref_source"),
               "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(old_path_lookup_before, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(old_path_lookup_before, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(old_path_lookup_before, "owner_local_resolve_source"),
               "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_destructed_path_index_found"), 0);
  ASSERT_EQ(mapping_number(old_path_lookup_before, "owner_local_canonical_record_ready"), 1);
  expect_no_lookup_global_live_object(old_path_lookup_before);
  expect_no_lookup_global_record_id_scan(old_path_lookup_before);
  expect_no_lookup_global_record_pointer(old_path_lookup_before);
  expect_no_lookup_global_record_scan(old_path_lookup_before);
  ASSERT_STREQ(mapping_string(old_path_lookup_before, "owner_local_path_index_source"),
               "vm_object_shard.object_path_index");
  free_mapping(old_path_lookup_before);

  vm_owner_set_id(obj, "owner/test/migration/b");
  auto migrated_handle_status = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(migrated_handle_status.object, nullptr);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(migrated_handle_status.status), "owner_mismatch");
  ASSERT_FALSE(migrated_handle_status.resolved_via_owner_local_store);
  ASSERT_TRUE(migrated_handle_status.diagnosed_via_owner_local_store);
  ASSERT_FALSE(migrated_handle_status.diagnosed_via_owner_local_path_index);
  ASSERT_TRUE(migrated_handle_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(migrated_handle_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(migrated_handle_status.global_live_object_found);
  ASSERT_FALSE(migrated_handle_status.global_record_found);
  ASSERT_FALSE(migrated_handle_status.diagnosed_via_global_index);
  ASSERT_FALSE(migrated_handle_status.resolved_via_global_index);

  auto* status = vm_object_store_status();
  ASSERT_GE(mapping_number(status, "migration_count"), before_migrations + 1);
  ASSERT_STREQ(mapping_string(status, "store_kind"), "vm_object_store");
  ASSERT_STREQ(mapping_string(status, "status_model"), "object_store_status");
  ASSERT_STREQ(mapping_string(status, "directory_model"), "owner_local_object_directory");
  ASSERT_STREQ(mapping_string(status, "storage_model"), "owner_local_store");
  ASSERT_EQ(mapping_number(status, "owner_local_global_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(status, "owner_local_to_global_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(status, "global_to_owner_local_bridge_consistent"), 1);
  ASSERT_STREQ(mapping_string(status, "owner_local_global_bridge_check"), "bidirectional");
  ASSERT_STREQ(mapping_string(status, "owner_local_global_bridge_source"), "vm_object_shard");
  expect_owner_local_store_complete_contract(status);
  ASSERT_GE(mapping_number(status, "owner_local_record_total"), 1);
  ASSERT_GE(mapping_number(status, "owner_local_object_ref_total"), 1);
  ASSERT_GE(mapping_number(status, "owner_local_object_ref_index_total"), 1);
  ASSERT_GE(mapping_number(status, "owner_local_path_index_total"), 1);
  ASSERT_EQ(mapping_number(status, "owner_local_orphan_record_total"), 0);
  ASSERT_EQ(mapping_number(status, "owner_local_to_global_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(status, "global_to_owner_local_record_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(status, "global_to_owner_local_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(status, "owner_local_record_index_ready"), 1);
  ASSERT_EQ(mapping_number(status, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(status, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(status, "owner_local_store_complete"), 1);
  ASSERT_EQ(mapping_number(status, "uses_global_object_table"), 0);
  ASSERT_EQ(mapping_number(status, "global_index_bridge"), 0);
  ASSERT_EQ(mapping_number(status, "global_record_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(status, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(status, "global_record_total"), mapping_number(status, "registered_objects"));
  ASSERT_GE(mapping_number(status, "global_live_record_total"), 1);
  auto* migrations = find_string_in_mapping(status, "migrations");
  ASSERT_NE(migrations, nullptr);
  ASSERT_EQ(migrations->type, T_ARRAY);
  ASSERT_GE(migrations->u.arr->size, 1);
  auto* migration = migrations->u.arr->item[migrations->u.arr->size - 1].u.map;
  ASSERT_EQ(mapping_number(migration, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_STREQ(mapping_string(migration, "from_owner_id"), "owner/test/migration/a");
  ASSERT_STREQ(mapping_string(migration, "to_owner_id"), "owner/test/migration/b");
  ASSERT_STREQ(mapping_string(migration, "object_path"), handle.object_path.c_str());
  free_mapping(status);

  auto* old_owner = vm_object_store_owner_status("owner/test/migration/a");
  ASSERT_EQ(mapping_number(old_owner, "objects"), 0);
  ASSERT_EQ(mapping_number(old_owner, "object_directory_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_directory_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_record_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_destructed_record_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_object_ref_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_object_ref_index_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_path_index_count"), 0);
  ASSERT_EQ(mapping_number(old_owner, "owner_local_destructed_path_index_count"), 0);
  free_mapping(old_owner);
  auto* old_lookup_after = vm_object_store_owner_lookup_status("owner/test/migration/a", handle.object_id);
  ASSERT_EQ(mapping_number(old_lookup_after, "success"), 1);
  ASSERT_EQ(mapping_number(old_lookup_after, "record_found"), 1);
  ASSERT_EQ(mapping_number(old_lookup_after, "found"), 0);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_directory_entry"), 0);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_record_found"), 0);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_destructed_record_found"), 0);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_record_destructed"), 0);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_cross_shard_record_found"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_cross_shard_record_source"),
               "vm_object_shard.local_records");
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_global_record_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_global_record_source"), "");
  expect_no_lookup_global_live_object(old_lookup_after);
  expect_no_lookup_global_record_id_scan(old_lookup_after);
  expect_no_lookup_global_record_pointer(old_lookup_after);
  expect_no_lookup_global_record_scan(old_lookup_after);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_object_ref_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_object_ref_source"), "");
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_object_ref_index_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_object_ref_index_source"), "");
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_object_pointer_index_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_object_pointer_index_source"), "");
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_resolve_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_resolve_source"), "");
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_path_index_found"), 0);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_destructed_path_index_found"), 0);
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_record_source"), "");
  ASSERT_STREQ(mapping_string(old_lookup_after, "owner_local_path_index_source"), "");
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(old_lookup_after, "owner_mismatch"), 1);
  ASSERT_STREQ(mapping_string(old_lookup_after, "record_owner_id"), "owner/test/migration/b");
  free_mapping(old_lookup_after);
  ASSERT_EQ(vm_object_store_owner_resolve("owner/test/migration/a", handle.object_id), nullptr);
  ASSERT_EQ(vm_object_store_owner_path_resolve("owner/test/migration/a", handle.object_path.c_str()), nullptr);
  auto* old_path_lookup_after =
      vm_object_store_owner_path_lookup_status("owner/test/migration/a", handle.object_path.c_str());
  ASSERT_EQ(mapping_number(old_path_lookup_after, "success"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "record_found"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "found"), 0);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_cross_shard_record_found"), 1);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_cross_shard_record_source"),
               "vm_object_shard.object_path_index");
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_global_record_found"), 0);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_global_record_source"), "");
  expect_no_lookup_global_live_object(old_path_lookup_after);
  expect_no_lookup_global_record_id_scan(old_path_lookup_after);
  expect_no_lookup_global_record_pointer(old_path_lookup_after);
  expect_no_lookup_global_record_scan(old_path_lookup_after);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_object_ref_found"), 0);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_object_ref_source"), "");
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_object_ref_index_found"), 0);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_object_ref_index_source"), "");
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_object_pointer_index_found"), 0);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_object_pointer_index_source"), "");
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_resolve_found"), 0);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_resolve_source"), "");
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_path_index_found"), 0);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_destructed_path_index_found"), 0);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(old_path_lookup_after, "owner_mismatch"), 1);
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "record_owner_id"), "owner/test/migration/b");
  ASSERT_STREQ(mapping_string(old_path_lookup_after, "owner_local_path_index_source"), "");
  free_mapping(old_path_lookup_after);

  auto* new_owner = vm_object_store_owner_status("owner/test/migration/b");
  ASSERT_EQ(mapping_number(new_owner, "objects"), 1);
  ASSERT_EQ(mapping_number(new_owner, "object_directory_count"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_directory_count"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_record_count"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_destructed_record_count"), 0);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_object_ref_count"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_object_ref_index_count"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_path_index_count"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_destructed_path_index_count"), 0);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_live_index_consistent"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_live_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_destructed_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_directory_ready"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_path_index_ready"), 1);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(new_owner, "uses_global_object_table"), 0);
  ASSERT_EQ(mapping_number(new_owner, "owner_local_store_complete"), 1);
  ASSERT_EQ(mapping_number(new_owner, "global_index_bridge"), 0);
  expect_owner_local_store_complete_contract(new_owner);
  auto* shard_contract = find_string_in_mapping(new_owner, "vm_object_shard");
  ASSERT_NE(shard_contract, nullptr);
  ASSERT_EQ(shard_contract ? shard_contract->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "shard_kind"), "vm_object_shard");
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "status_model"), "owner_status_record");
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "execution_model"), "owner_execution_shard");
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "directory_model"), "owner_local_object_directory");
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "storage_model"), "owner_local_store");
  ASSERT_EQ(mapping_number(shard_contract->u.map, "object_directory_count"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_record_count"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_destructed_record_count"), 0);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_object_ref_count"), 1);
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "owner_local_object_ref_source"),
               "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_object_ref_index_count"), 1);
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_path_index_count"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_destructed_path_index_count"), 0);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_live_index_consistent"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_live_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_destructed_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_path_index_ready"), 1);
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "owner_local_path_index_source"),
               "vm_object_shard.object_path_index");
  ASSERT_STREQ(mapping_string(shard_contract->u.map, "owner_local_destructed_path_index_source"),
               "vm_object_shard.destructed_path_index");
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_directory_ready"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_directory_from_shard"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "owner_local_store_complete"), 1);
  ASSERT_EQ(mapping_number(shard_contract->u.map, "global_index_bridge"), 0);
  expect_owner_local_store_complete_contract(shard_contract->u.map);
  auto* directory = find_string_in_mapping(new_owner, "object_directory");
  ASSERT_NE(directory, nullptr);
  ASSERT_EQ(directory->type, T_ARRAY);
  ASSERT_EQ(directory->u.arr->size, 1);
  ASSERT_EQ(mapping_number(new_owner, "object_directory_count"),
            mapping_number(new_owner, "owner_local_directory_count"));
  auto* directory_record = directory->u.arr->item[0].u.map;
  ASSERT_EQ(mapping_number(directory_record, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(directory_record, "owner_epoch"), static_cast<long>(vm_owner_epoch(obj)));
  ASSERT_EQ(mapping_number(directory_record, "destructed"), 0);
  ASSERT_EQ(mapping_number(directory_record, "live"), 1);
  ASSERT_EQ(mapping_number(directory_record, "owner_local_directory_entry"), 1);
  ASSERT_STREQ(mapping_string(directory_record, "owner_local_directory_source"), "vm_object_shard.object_directory");
  ASSERT_EQ(mapping_number(directory_record, "owner_local_record_snapshot"), 1);
  ASSERT_STREQ(mapping_string(directory_record, "owner_local_record_source"), "vm_object_shard.local_records");
  ASSERT_EQ(mapping_number(directory_record, "owner_local_object_ref_entry"), 1);
  ASSERT_STREQ(mapping_string(directory_record, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(directory_record, "owner_local_path_index_entry"), 1);
  ASSERT_STREQ(mapping_string(directory_record, "owner_local_path_index_source"), "vm_object_shard.object_path_index");
  ASSERT_EQ(mapping_number(directory_record, "resolved_via_owner_local_store"), 1);
  ASSERT_EQ(mapping_number(directory_record, "resolved_via_global_index"), 0);
  ASSERT_STREQ(mapping_string(directory_record, "owner_id"), "owner/test/migration/b");
  ASSERT_STREQ(mapping_string(directory_record, "object_path"), handle.object_path.c_str());
  free_mapping(new_owner);
  auto* new_lookup_after = vm_object_store_owner_lookup_status("owner/test/migration/b", handle.object_id);
  ASSERT_EQ(mapping_number(new_lookup_after, "success"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "record_found"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "found"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_directory_entry"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_record_found"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_destructed_record_found"), 0);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_record_destructed"), 0);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_resolve_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_destructed_path_index_found"), 0);
  expect_no_lookup_global_live_object(new_lookup_after);
  expect_no_lookup_global_record_id_scan(new_lookup_after);
  expect_no_lookup_global_record_pointer(new_lookup_after);
  expect_no_lookup_global_record_scan(new_lookup_after);
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_record_source"), "vm_object_shard.local_records");
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_path_index_source"), "vm_object_shard.object_path_index");
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(new_lookup_after, "owner_local_store_complete_blocker"), "");
  ASSERT_EQ(mapping_number(new_lookup_after, "owner_mismatch"), 0);
  ASSERT_STREQ(mapping_string(new_lookup_after, "record_owner_id"), "owner/test/migration/b");
  ASSERT_STREQ(mapping_string(new_lookup_after, "object_path"), handle.object_path.c_str());
  free_mapping(new_lookup_after);
  ASSERT_EQ(vm_object_store_owner_resolve("owner/test/migration/b", handle.object_id), obj);
  ASSERT_EQ(vm_object_store_owner_path_resolve("owner/test/migration/b", handle.object_path.c_str()), obj);
  auto* new_path_lookup_after =
      vm_object_store_owner_path_lookup_status("owner/test/migration/b", handle.object_path.c_str());
  ASSERT_EQ(mapping_number(new_path_lookup_after, "success"), 1);
  ASSERT_EQ(mapping_number(new_path_lookup_after, "record_found"), 1);
  ASSERT_EQ(mapping_number(new_path_lookup_after, "found"), 1);
  ASSERT_EQ(mapping_number(new_path_lookup_after, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(new_path_lookup_after, "owner_local_object_ref_source"),
               "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(new_path_lookup_after, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(new_path_lookup_after, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(new_path_lookup_after, "owner_local_resolve_source"),
               "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_destructed_path_index_found"), 0);
  ASSERT_EQ(mapping_number(new_path_lookup_after, "owner_local_canonical_record_ready"), 1);
  expect_no_lookup_global_live_object(new_path_lookup_after);
  expect_no_lookup_global_record_id_scan(new_path_lookup_after);
  expect_no_lookup_global_record_pointer(new_path_lookup_after);
  expect_no_lookup_global_record_scan(new_path_lookup_after);
  ASSERT_STREQ(mapping_string(new_path_lookup_after, "owner_local_path_index_source"),
               "vm_object_shard.object_path_index");
  ASSERT_STREQ(mapping_string(new_path_lookup_after, "record_owner_id"), "owner/test/migration/b");
  free_mapping(new_path_lookup_after);

  auto* missing_object_lookup =
      vm_object_store_owner_lookup_status("owner/test/migration/b", handle.object_id + 1000000);
  ASSERT_EQ(mapping_number(missing_object_lookup, "success"), 1);
  ASSERT_EQ(mapping_number(missing_object_lookup, "record_found"), 0);
  ASSERT_EQ(mapping_number(missing_object_lookup, "found"), 0);
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(missing_object_lookup, "owner_local_store_complete_blocker"), "");
  ASSERT_EQ(mapping_number(missing_object_lookup, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_global_record_found"), 0);
  ASSERT_STREQ(mapping_string(missing_object_lookup, "owner_local_global_record_source"), "");
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_global_record_fallback_skipped"), 1);
  ASSERT_STREQ(mapping_string(missing_object_lookup, "owner_local_global_record_fallback_reason"),
               "global_record_bridge_retirement_ready");
  expect_skipped_lookup_global_record_id_scan(missing_object_lookup);
  expect_no_lookup_global_record_pointer(missing_object_lookup);
  expect_no_lookup_global_record_scan(missing_object_lookup);
  ASSERT_EQ(mapping_number(missing_object_lookup, "global_live_object_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_global_live_object_found"), 0);
  ASSERT_STREQ(mapping_string(missing_object_lookup, "owner_local_global_live_object_source"), "");
  ASSERT_EQ(mapping_number(missing_object_lookup, "owner_local_global_live_object_fallback_skipped"), 0);
  ASSERT_STREQ(mapping_string(missing_object_lookup, "owner_local_global_live_object_fallback_reason"),
               "");
  free_mapping(missing_object_lookup);

  std::string missing_path = handle.object_path + ".missing";
  auto* missing_path_lookup =
      vm_object_store_owner_path_lookup_status("owner/test/migration/b", missing_path.c_str());
  ASSERT_EQ(mapping_number(missing_path_lookup, "success"), 1);
  ASSERT_EQ(mapping_number(missing_path_lookup, "record_found"), 0);
  ASSERT_EQ(mapping_number(missing_path_lookup, "found"), 0);
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(missing_path_lookup, "owner_local_store_complete_blocker"), "");
  ASSERT_EQ(mapping_number(missing_path_lookup, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_global_record_found"), 0);
  ASSERT_STREQ(mapping_string(missing_path_lookup, "owner_local_global_record_source"), "");
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_global_record_fallback_skipped"), 1);
  ASSERT_STREQ(mapping_string(missing_path_lookup, "owner_local_global_record_fallback_reason"),
               "global_record_bridge_retirement_ready");
  expect_no_lookup_global_record_id_scan(missing_path_lookup);
  expect_no_lookup_global_record_pointer(missing_path_lookup);
  expect_skipped_lookup_global_record_scan(missing_path_lookup);
  ASSERT_EQ(mapping_number(missing_path_lookup, "global_live_object_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_global_live_object_found"), 0);
  ASSERT_STREQ(mapping_string(missing_path_lookup, "owner_local_global_live_object_source"), "");
  ASSERT_EQ(mapping_number(missing_path_lookup, "owner_local_global_live_object_fallback_skipped"), 1);
  ASSERT_STREQ(mapping_string(missing_path_lookup, "owner_local_global_live_object_fallback_reason"),
               "global_live_object_bridge_retirement_ready");
  free_mapping(missing_path_lookup);

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
  auto mapping_string = [](mapping_t* map, const char* key) -> const char* {
    auto* value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto expect_owner_local_store_complete_contract = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_store_complete"), 1);
    ASSERT_STREQ(mapping_string(map, "owner_local_store_complete_blocker"), "");
    ASSERT_EQ(mapping_number(map, "uses_global_object_table"), 0);
    ASSERT_EQ(mapping_number(map, "global_index_bridge"), 0);
    ASSERT_EQ(mapping_number(map, "global_live_object_bridge_ready"), 0);
    ASSERT_STREQ(mapping_string(map, "global_live_object_bridge_source"), "");
    ASSERT_EQ(mapping_number(map, "global_record_bridge_ready"), 0);
    ASSERT_STREQ(mapping_string(map, "global_record_bridge_source"), "");
  };
  auto expect_no_lookup_global_live_object = [&](mapping_t* map) {
    ASSERT_EQ(mapping_number(map, "owner_local_global_live_object_found"), 0);
    ASSERT_STREQ(mapping_string(map, "owner_local_global_live_object_source"), "");
  };

  auto* missing_owner = vm_object_store_owner_status("owner/test/store/missing");
  ASSERT_EQ(mapping_number(missing_owner, "objects"), 0);
  ASSERT_EQ(mapping_number(missing_owner, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(missing_owner, "owner_local_store_complete"), 1);
  ASSERT_EQ(mapping_number(missing_owner, "global_index_bridge"), 0);
  expect_owner_local_store_complete_contract(missing_owner);
  auto* missing_owner_shard_contract = find_string_in_mapping(missing_owner, "vm_object_shard");
  ASSERT_NE(missing_owner_shard_contract, nullptr);
  ASSERT_EQ(missing_owner_shard_contract ? missing_owner_shard_contract->type : T_INVALID, T_MAPPING);
  ASSERT_EQ(mapping_number(missing_owner_shard_contract->u.map, "owner_local_store_ready"), 1);
  expect_owner_local_store_complete_contract(missing_owner_shard_contract->u.map);
  free_mapping(missing_owner);

  object_t* obj = clone_object("single/void", 0);
  ASSERT_NE(obj, nullptr);
  vm_owner_set_id(obj, "owner/test/store/destruct");
  vm_object_store_register(obj);
  auto handle = vm_object_handle(obj);
  auto handle_resolve = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(handle_resolve.object, obj);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(handle_resolve.status), "current");
  ASSERT_TRUE(handle_resolve.resolved_via_owner_local_store);
  ASSERT_FALSE(handle_resolve.diagnosed_via_owner_local_store);
  ASSERT_FALSE(handle_resolve.diagnosed_via_owner_local_path_index);
  ASSERT_TRUE(handle_resolve.owner_local_object_pointer_index_found);
  ASSERT_FALSE(handle_resolve.global_live_object_found);
  ASSERT_FALSE(handle_resolve.global_record_found);
  ASSERT_FALSE(handle_resolve.resolved_via_global_index);
  ASSERT_EQ(vm_object_store_owner_resolve("owner/test/store/destruct", handle.object_id), obj);
  ASSERT_EQ(vm_object_store_owner_path_resolve("owner/test/store/destruct", handle.object_path.c_str()), obj);

  auto* before = vm_object_store_owner_status("owner/test/store/destruct");
  ASSERT_EQ(mapping_number(before, "objects"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_record_count"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_destructed_record_count"), 0);
  ASSERT_EQ(mapping_number(before, "owner_local_object_ref_count"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_object_ref_index_count"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_path_index_count"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_destructed_path_index_count"), 0);
  ASSERT_EQ(mapping_number(before, "owner_local_live_index_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_live_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_destructed_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(before, "owner_local_store_complete"), 1);
  expect_owner_local_store_complete_contract(before);
  auto before_destructed = mapping_number(before, "destructed");
  free_mapping(before);
  auto* lookup_before = vm_object_store_owner_lookup_status("owner/test/store/destruct", handle.object_id);
  ASSERT_EQ(mapping_number(lookup_before, "success"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "record_found"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "found"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_directory_entry"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_record_found"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_destructed_record_found"), 0);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_record_destructed"), 0);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_resolve_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_destructed_path_index_found"), 0);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(lookup_before, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_store_complete_blocker"), "");
  expect_no_lookup_global_live_object(lookup_before);
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_path_index_source"), "vm_object_shard.object_path_index");
  ASSERT_STREQ(mapping_string(lookup_before, "owner_local_record_source"), "vm_object_shard.local_records");
  ASSERT_EQ(mapping_number(lookup_before, "destructed"), 0);
  free_mapping(lookup_before);
  auto* path_lookup_before =
      vm_object_store_owner_path_lookup_status("owner/test/store/destruct", handle.object_path.c_str());
  ASSERT_EQ(mapping_number(path_lookup_before, "success"), 1);
  ASSERT_EQ(mapping_number(path_lookup_before, "record_found"), 1);
  ASSERT_EQ(mapping_number(path_lookup_before, "found"), 1);
  ASSERT_EQ(mapping_number(path_lookup_before, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_object_ref_found"), 1);
  ASSERT_STREQ(mapping_string(path_lookup_before, "owner_local_object_ref_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_object_ref_index_found"), 1);
  ASSERT_STREQ(mapping_string(path_lookup_before, "owner_local_object_ref_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_object_pointer_index_found"), 1);
  ASSERT_STREQ(mapping_string(path_lookup_before, "owner_local_object_pointer_index_source"),
               "vm_object_shard.local_object_index");
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_resolve_found"), 1);
  ASSERT_STREQ(mapping_string(path_lookup_before, "owner_local_resolve_source"), "vm_object_shard.local_objects");
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_path_index_found"), 1);
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_destructed_path_index_found"), 0);
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(path_lookup_before, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(path_lookup_before, "owner_local_store_complete_blocker"), "");
  expect_no_lookup_global_live_object(path_lookup_before);
  ASSERT_STREQ(mapping_string(path_lookup_before, "owner_local_path_index_source"),
               "vm_object_shard.object_path_index");
  free_mapping(path_lookup_before);

  destruct_object(obj);
  auto destructed_handle_status = vm_object_handle_resolve_status(handle);
  ASSERT_EQ(destructed_handle_status.object, nullptr);
  ASSERT_STREQ(vm_object_handle_resolve_status_name(destructed_handle_status.status), "record_destructed");
  ASSERT_FALSE(destructed_handle_status.resolved_via_owner_local_store);
  ASSERT_TRUE(destructed_handle_status.diagnosed_via_owner_local_store);
  ASSERT_FALSE(destructed_handle_status.diagnosed_via_owner_local_path_index);
  ASSERT_FALSE(destructed_handle_status.diagnosed_via_owner_local_cross_shard);
  ASSERT_FALSE(destructed_handle_status.owner_local_object_pointer_index_found);
  ASSERT_FALSE(destructed_handle_status.global_live_object_found);
  ASSERT_FALSE(destructed_handle_status.global_record_found);
  ASSERT_FALSE(destructed_handle_status.diagnosed_via_global_index);
  ASSERT_FALSE(destructed_handle_status.resolved_via_global_index);
  auto* store_after_destruct = vm_object_store_status();
  ASSERT_STREQ(mapping_string(store_after_destruct, "store_kind"), "vm_object_store");
  ASSERT_STREQ(mapping_string(store_after_destruct, "status_model"), "object_store_status");
  ASSERT_STREQ(mapping_string(store_after_destruct, "directory_model"), "owner_local_object_directory");
  ASSERT_STREQ(mapping_string(store_after_destruct, "storage_model"), "owner_local_store");
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_global_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_to_global_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_to_owner_local_bridge_consistent"), 1);
  ASSERT_STREQ(mapping_string(store_after_destruct, "owner_local_global_bridge_check"), "bidirectional");
  ASSERT_STREQ(mapping_string(store_after_destruct, "owner_local_global_bridge_source"), "vm_object_shard");
  expect_owner_local_store_complete_contract(store_after_destruct);
  ASSERT_GE(mapping_number(store_after_destruct, "owner_local_destructed_record_total"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_object_ref_total"),
            mapping_number(store_after_destruct, "owner_local_object_ref_index_total"));
  ASSERT_GE(mapping_number(store_after_destruct, "owner_local_destructed_path_index_total"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_orphan_record_total"), 0);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_to_global_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_to_owner_local_record_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_to_owner_local_mismatch_record_total"), 0);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_record_index_ready"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "owner_local_store_complete"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "uses_global_object_table"), 0);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_index_bridge"), 0);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_record_bridge_consistent"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_record_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_live_object_bridge_retirement_ready"), 1);
  ASSERT_EQ(mapping_number(store_after_destruct, "global_record_total"),
            mapping_number(store_after_destruct, "registered_objects"));
  ASSERT_GE(mapping_number(store_after_destruct, "global_destructed_record_total"), 1);
  free_mapping(store_after_destruct);
  ASSERT_EQ(vm_object_store_owner_resolve("owner/test/store/destruct", handle.object_id), nullptr);
  ASSERT_EQ(vm_object_store_owner_path_resolve("owner/test/store/destruct", handle.object_path.c_str()), nullptr);

  auto* after = vm_object_store_owner_status("owner/test/store/destruct");
  ASSERT_EQ(mapping_number(after, "objects"), 0);
  ASSERT_EQ(mapping_number(after, "object_directory_count"), 0);
  ASSERT_EQ(mapping_number(after, "owner_local_directory_count"), 0);
  ASSERT_EQ(mapping_number(after, "owner_local_record_count"), 0);
  ASSERT_EQ(mapping_number(after, "owner_local_destructed_record_count"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_object_ref_count"), 0);
  ASSERT_EQ(mapping_number(after, "owner_local_object_ref_index_count"), 0);
  ASSERT_EQ(mapping_number(after, "owner_local_path_index_count"), 0);
  ASSERT_EQ(mapping_number(after, "owner_local_destructed_path_index_count"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_live_index_consistent"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_live_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_destructed_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(after, "owner_local_store_complete"), 1);
  expect_owner_local_store_complete_contract(after);
  ASSERT_EQ(mapping_number(after, "destructed"), before_destructed + 1);
  free_mapping(after);
  auto* lookup_after = vm_object_store_owner_lookup_status("owner/test/store/destruct", handle.object_id);
  ASSERT_EQ(mapping_number(lookup_after, "success"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "record_found"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "found"), 0);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_directory_entry"), 0);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_record_found"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_destructed_record_found"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_record_destructed"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_object_ref_found"), 0);
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_object_ref_source"), "");
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_object_ref_index_found"), 0);
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_object_ref_index_source"), "");
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_object_pointer_index_found"), 0);
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_object_pointer_index_source"), "");
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_resolve_found"), 0);
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_resolve_source"), "");
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_path_index_found"), 0);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_destructed_path_index_found"), 1);
  expect_no_lookup_global_live_object(lookup_after);
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_record_source"), "vm_object_shard.destructed_records");
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_path_index_source"),
               "vm_object_shard.destructed_path_index");
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(lookup_after, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(lookup_after, "owner_local_store_complete_blocker"), "");
  ASSERT_EQ(mapping_number(lookup_after, "destructed"), 1);
  free_mapping(lookup_after);
  auto* path_lookup_after =
      vm_object_store_owner_path_lookup_status("owner/test/store/destruct", handle.object_path.c_str());
  ASSERT_EQ(mapping_number(path_lookup_after, "success"), 1);
  ASSERT_EQ(mapping_number(path_lookup_after, "record_found"), 1);
  ASSERT_EQ(mapping_number(path_lookup_after, "found"), 0);
  ASSERT_EQ(mapping_number(path_lookup_after, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_object_ref_found"), 0);
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_object_ref_source"), "");
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_object_ref_index_found"), 0);
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_object_ref_index_source"), "");
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_object_pointer_index_found"), 0);
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_object_pointer_index_source"), "");
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_resolve_found"), 0);
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_resolve_source"), "");
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_path_index_found"), 0);
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_destructed_path_index_found"), 1);
  expect_no_lookup_global_live_object(path_lookup_after);
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_directory_entry"), 0);
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_record_source"),
               "vm_object_shard.destructed_records");
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_path_index_source"),
               "vm_object_shard.destructed_path_index");
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(path_lookup_after, "owner_local_store_complete"), 1);
  ASSERT_STREQ(mapping_string(path_lookup_after, "owner_local_store_complete_blocker"), "");
  free_mapping(path_lookup_after);

  vm_owner_set_id(obj, "owner/test/store/destruct-after");
  ASSERT_EQ(vm_object_store_owner_resolve("owner/test/store/destruct-after", handle.object_id), nullptr);
  ASSERT_EQ(vm_object_store_owner_path_resolve("owner/test/store/destruct-after", handle.object_path.c_str()), nullptr);
  auto* moved_after_destruct = vm_object_store_owner_status("owner/test/store/destruct-after");
  ASSERT_EQ(mapping_number(moved_after_destruct, "objects"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "object_directory_count"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_directory_count"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_record_count"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_destructed_record_count"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_object_ref_count"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_object_ref_index_count"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_path_index_count"), 0);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_destructed_path_index_count"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_live_index_consistent"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_live_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_destructed_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(moved_after_destruct, "owner_local_store_complete"), 1);
  expect_owner_local_store_complete_contract(moved_after_destruct);
  auto* empty_shard_contract = find_string_in_mapping(moved_after_destruct, "vm_object_shard");
  ASSERT_NE(empty_shard_contract, nullptr);
  ASSERT_EQ(empty_shard_contract ? empty_shard_contract->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(empty_shard_contract->u.map, "directory_model"), "owner_local_object_directory");
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "object_directory_count"), 0);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_record_count"), 0);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_destructed_record_count"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_object_ref_count"), 0);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_object_ref_index_count"), 0);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_path_index_count"), 0);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_destructed_path_index_count"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_live_index_consistent"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_object_ref_index_consistent"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_live_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_destructed_path_index_consistent"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_canonical_record_ready"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_directory_ready"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_directory_from_shard"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_store_ready"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "owner_local_store_complete"), 1);
  ASSERT_EQ(mapping_number(empty_shard_contract->u.map, "global_index_bridge"), 0);
  expect_owner_local_store_complete_contract(empty_shard_contract->u.map);
  free_mapping(moved_after_destruct);
  auto* moved_lookup_after_destruct =
      vm_object_store_owner_lookup_status("owner/test/store/destruct-after", handle.object_id);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "success"), 1);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "record_found"), 1);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "found"), 0);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_directory_entry"), 0);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_record_found"), 1);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_destructed_record_found"), 1);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_record_destructed"), 1);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_object_ref_found"), 0);
  ASSERT_STREQ(mapping_string(moved_lookup_after_destruct, "owner_local_object_ref_source"), "");
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_resolve_found"), 0);
  ASSERT_STREQ(mapping_string(moved_lookup_after_destruct, "owner_local_resolve_source"), "");
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_path_index_found"), 0);
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "owner_local_destructed_path_index_found"), 1);
  expect_no_lookup_global_live_object(moved_lookup_after_destruct);
  ASSERT_STREQ(mapping_string(moved_lookup_after_destruct, "owner_local_record_source"),
               "vm_object_shard.destructed_records");
  ASSERT_STREQ(mapping_string(moved_lookup_after_destruct, "owner_local_path_index_source"),
               "vm_object_shard.destructed_path_index");
  ASSERT_EQ(mapping_number(moved_lookup_after_destruct, "destructed"), 1);
  free_mapping(moved_lookup_after_destruct);
  auto* moved_path_lookup_after_destruct =
      vm_object_store_owner_path_lookup_status("owner/test/store/destruct-after", handle.object_path.c_str());
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "success"), 1);
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "record_found"), 1);
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "found"), 0);
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "object_id"), static_cast<long>(handle.object_id));
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "owner_local_object_ref_found"), 0);
  ASSERT_STREQ(mapping_string(moved_path_lookup_after_destruct, "owner_local_object_ref_source"), "");
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "owner_local_path_index_found"), 0);
  ASSERT_EQ(mapping_number(moved_path_lookup_after_destruct, "owner_local_destructed_path_index_found"), 1);
  expect_no_lookup_global_live_object(moved_path_lookup_after_destruct);
  ASSERT_STREQ(mapping_string(moved_path_lookup_after_destruct, "owner_local_record_source"),
               "vm_object_shard.destructed_records");
  ASSERT_STREQ(mapping_string(moved_path_lookup_after_destruct, "owner_local_path_index_source"),
               "vm_object_shard.destructed_path_index");
  free_mapping(moved_path_lookup_after_destruct);
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

TEST_F(DriverTest, TestVmWorkerComputeResultCompletesOwnerFutureThroughQueue) {
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

  VMWorkerActorScoreInput input;
  input.hp = 100;
  input.max_hp = 100;
  input.mp = 80;
  input.max_mp = 100;
  input.ep = 60;
  input.max_ep = 100;

  auto task_id = vm_worker_submit_actor_score_v2("actor/owner-future", input, 1000, 5000);
  ASSERT_GT(task_id, 0u);
  auto future_id = vm_worker_owner_future_id(task_id);
  ASSERT_GT(future_id, 0u);

  auto* pending = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(pending, "state"), "pending");
  ASSERT_EQ(mapping_number(pending, "target_task_id"), static_cast<long>(task_id));
  ASSERT_STREQ(mapping_string(pending, "message_type"), "actor_score");
  ASSERT_STREQ(mapping_string(pending, "payload_key"), "worker_compute");
  free_mapping(pending);

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
  ASSERT_EQ(result.envelope.owner_future_id, future_id);
  auto* still_pending = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(still_pending, "state"), "pending");
  free_mapping(still_pending);

  auto* scheduled = vm_owner_drain_mailbox("actor/owner-future", 1);
  ASSERT_EQ(mapping_number(scheduled, "drained"), 1);
  auto* tasks = find_string_in_mapping(scheduled, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks ? tasks->type : T_INVALID, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  auto* task_map = tasks->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(task_map, "task_type"), "compute_result");
  ASSERT_STREQ(mapping_string(task_map, "task_key"), "actor_score");
  ASSERT_EQ(mapping_number(task_map, "future_target_task_id"), static_cast<long>(task_id));
  ASSERT_STREQ(mapping_string(task_map, "future_state"), "completed");
  free_mapping(scheduled);

  auto* completed = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "actor_score");
  ASSERT_EQ(mapping_number(completed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(completed, "frozen_result"), 1);
  ASSERT_EQ(mapping_number(completed, "direct_cross_owner_write"), 0);
  auto* result_map = find_string_in_mapping(completed, "result");
  ASSERT_NE(result_map, nullptr);
  ASSERT_EQ(result_map ? result_map->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(result_map->u.map, "type"), "actor_score");
  ASSERT_STREQ(mapping_string(result_map->u.map, "owner_key"), "actor/owner-future");
  ASSERT_EQ(mapping_number(result_map->u.map, "hp_pct_bp"), 10000);
  ASSERT_EQ(mapping_number(result_map->u.map, "mp_pct_bp"), 8000);
  ASSERT_EQ(mapping_number(result_map->u.map, "ep_pct_bp"), 6000);
  ASSERT_EQ(mapping_number(result_map->u.map, "total_score"), 9100);
  ASSERT_STREQ(mapping_string(result_map->u.map, "state"), "stable");
  free_mapping(completed);
}

TEST_F(DriverTest, TestVmWorkerComputeResultCompletesOwnerFutureThroughOwnerExecutor) {
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

  const char* owner = "actor/owner-future-thread";
  vm_owner_thread_stop();
  free_mapping(vm_owner_drain_mailbox(owner, 0));

  auto* before = vm_owner_thread_status();
  auto before_completed = mapping_number(before, "thread_compute_result_completed");
  auto before_dispatched = mapping_number(before, "executor_safe_task_dispatched");
  auto before_claims = mapping_number(before, "executor_owner_claims");
  auto before_releases = mapping_number(before, "executor_owner_releases");
  free_mapping(before);

  auto* before_runtime = vm_owner_runtime_status();
  auto before_pending_futures = mapping_number(before_runtime, "pending_futures");
  free_mapping(before_runtime);

  VMWorkerActorScoreInput input;
  input.hp = 100;
  input.max_hp = 100;
  input.mp = 80;
  input.max_mp = 100;
  input.ep = 60;
  input.max_ep = 100;

  auto task_id = vm_worker_submit_actor_score_v2(owner, input, 1000, 5000);
  ASSERT_GT(task_id, 0u);
  auto future_id = vm_worker_owner_future_id(task_id);
  ASSERT_GT(future_id, 0u);

  auto* pending_runtime = vm_owner_runtime_status();
  ASSERT_EQ(mapping_number(pending_runtime, "pending_futures"), before_pending_futures + 1);
  free_mapping(pending_runtime);

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
  ASSERT_EQ(result.envelope.owner_future_id, future_id);

  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 1);
  ASSERT_EQ(mapping_number(queued, "owner_executor_safe_queue_depth"), 1);
  ASSERT_EQ(mapping_number(queued, "owner_main_required_queue_depth"), 0);
  ASSERT_GE(mapping_number(queued, "executor_safe_queue_depth"), 1);
  free_mapping(queued);

  auto* still_pending = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(still_pending, "state"), "pending");
  ASSERT_EQ(mapping_number(still_pending, "target_task_id"), static_cast<long>(task_id));
  free_mapping(still_pending);

  vm_owner_thread_start(1);
  for (int i = 0; i < 100; i++) {
    auto* polled = vm_owner_future_poll(future_id);
    auto completed = std::string(mapping_string(polled, "state")) == "completed";
    free_mapping(polled);
    auto* status = vm_owner_mailbox_status(owner);
    auto owner_depth = mapping_number(status, "owner_queue_depth");
    free_mapping(status);
    if (completed && owner_depth == 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto* completed = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "actor_score");
  ASSERT_EQ(mapping_number(completed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed, "frozen_result"), 1);
  ASSERT_EQ(mapping_number(completed, "direct_cross_owner_write"), 0);
  auto* result_map = find_string_in_mapping(completed, "result");
  ASSERT_NE(result_map, nullptr);
  ASSERT_EQ(result_map ? result_map->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(result_map->u.map, "type"), "actor_score");
  ASSERT_STREQ(mapping_string(result_map->u.map, "owner_key"), owner);
  ASSERT_EQ(mapping_number(result_map->u.map, "hp_pct_bp"), 10000);
  ASSERT_EQ(mapping_number(result_map->u.map, "mp_pct_bp"), 8000);
  ASSERT_EQ(mapping_number(result_map->u.map, "ep_pct_bp"), 6000);
  ASSERT_EQ(mapping_number(result_map->u.map, "total_score"), 9100);
  ASSERT_STREQ(mapping_string(result_map->u.map, "state"), "stable");
  free_mapping(completed);

  auto* running = vm_owner_thread_status();
  ASSERT_GE(mapping_number(running, "thread_compute_result_completed"), before_completed + 1);
  ASSERT_GE(mapping_number(running, "executor_safe_task_dispatched"), before_dispatched + 1);
  ASSERT_GE(mapping_number(running, "executor_owner_claims"), before_claims + 1);
  ASSERT_EQ(mapping_number(running, "executor_owner_claims") - before_claims,
            mapping_number(running, "executor_owner_releases") - before_releases);
  ASSERT_EQ(mapping_number(running, "claimed_owners"), 0);
  ASSERT_EQ(mapping_number(running, "executor_safe_queue_depth"), 0);
  free_mapping(running);

  auto* trace = vm_owner_task_trace(32);
  auto* events = find_string_in_mapping(trace, "events");
  ASSERT_NE(events, nullptr);
  ASSERT_EQ(events ? events->type : T_INVALID, T_ARRAY);
  int compute_result_completed = 0;
  for (int i = 0; i < events->u.arr->size; i++) {
    auto* event = events->u.arr->item[i].u.map;
    if (mapping_number(event, "task_id") > 0 &&
        std::string(mapping_string(event, "task_type")) == "compute_result" &&
        std::string(mapping_string(event, "owner_id")) == owner &&
        std::string(mapping_string(event, "state")) == "thread_compute_result_completed") {
      compute_result_completed = 1;
    }
  }
  ASSERT_EQ(compute_result_completed, 1);
  free_mapping(trace);

  auto* completed_runtime = vm_owner_runtime_status();
  ASSERT_LE(mapping_number(completed_runtime, "pending_futures"), before_pending_futures);
  free_mapping(completed_runtime);
  vm_owner_thread_stop();
}

TEST_F(DriverTest, TestVmWorkerComputeResultRejectsCompletedWithoutFrozenFields) {
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

  const char* owner = "actor/owner-future-empty-result";
  const uint64_t worker_task_id = 987654321u;
  vm_owner_thread_stop();
  free_mapping(vm_owner_purge_mailbox(owner));

  auto future_id = vm_owner_register_compute_future(owner, worker_task_id, "empty_result", "worker_compute");
  ASSERT_GT(future_id, 0u);
  auto* pending = vm_owner_future_poll(future_id);
  ASSERT_EQ(mapping_number(pending, "success"), 1);
  ASSERT_STREQ(mapping_string(pending, "state"), "pending");
  ASSERT_EQ(mapping_number(pending, "target_task_id"), static_cast<long>(worker_task_id));
  ASSERT_EQ(mapping_number(pending, "frozen_result"), 0);
  free_mapping(pending);

  auto result_task_id = vm_owner_enqueue_compute_result(owner, worker_task_id, "empty_result", "completed",
                                                       "empty_result", "");
  ASSERT_GT(result_task_id, 0u);
  auto* queued = vm_owner_mailbox_status(owner);
  ASSERT_EQ(mapping_number(queued, "owner_queue_depth"), 1);
  ASSERT_EQ(mapping_number(queued, "owner_executor_safe_queue_depth"), 1);
  free_mapping(queued);

  auto* drained = vm_owner_drain_mailbox(owner, 1);
  ASSERT_EQ(mapping_number(drained, "drained"), 1);
  auto* tasks = find_string_in_mapping(drained, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks ? tasks->type : T_INVALID, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  auto* task_map = tasks->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(task_map, "task_type"), "compute_result");
  ASSERT_STREQ(mapping_string(task_map, "task_key"), "empty_result");
  ASSERT_STREQ(mapping_string(task_map, "future_state"), "completed");
  ASSERT_EQ(mapping_number(task_map, "future_target_task_id"), static_cast<long>(worker_task_id));
  free_mapping(drained);

  auto* failed = vm_owner_future_poll(future_id);
  ASSERT_EQ(mapping_number(failed, "success"), 1);
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "worker compute result must contain frozen data");
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "payload_frozen"), 1);
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  free_mapping(failed);
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

TEST_F(DriverTest, TestVmWorkerComputeResultFutureCarriesBenchmarkResult) {
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

  free_mapping(vm_owner_drain_mailbox("global", 0));
  auto task_id = vm_worker_submit_benchmark_v2(2, 10, 1000, 5000);
  ASSERT_GT(task_id, 0u);
  auto future_id = vm_worker_owner_future_id(task_id);
  ASSERT_GT(future_id, 0u);

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
  ASSERT_EQ(result.type, "bench");
  ASSERT_EQ(result.envelope.owner_future_id, future_id);
  ASSERT_EQ(result.bench.tasks, 2);
  ASSERT_GE(result.bench.worker_count, 1);
  ASSERT_GE(result.bench.max_parallel, 1);
  ASSERT_GT(result.bench.checksum, 0u);

  auto* scheduled = vm_owner_drain_mailbox("global", 1);
  ASSERT_EQ(mapping_number(scheduled, "drained"), 1);
  auto* tasks = find_string_in_mapping(scheduled, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks ? tasks->type : T_INVALID, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  auto* task_map = tasks->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(task_map, "task_type"), "compute_result");
  ASSERT_STREQ(mapping_string(task_map, "task_key"), "bench");
  ASSERT_EQ(mapping_number(task_map, "future_target_task_id"), static_cast<long>(task_id));
  ASSERT_STREQ(mapping_string(task_map, "future_state"), "completed");
  free_mapping(scheduled);

  auto* completed = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "bench");
  ASSERT_EQ(mapping_number(completed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(completed, "frozen_result"), 1);
  ASSERT_EQ(mapping_number(completed, "direct_cross_owner_write"), 0);
  auto* result_map = find_string_in_mapping(completed, "result");
  ASSERT_NE(result_map, nullptr);
  ASSERT_EQ(result_map ? result_map->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(result_map->u.map, "type"), "bench");
  ASSERT_EQ(mapping_number(result_map->u.map, "tasks"), result.bench.tasks);
  ASSERT_EQ(mapping_number(result_map->u.map, "worker_count"), result.bench.worker_count);
  ASSERT_EQ(mapping_number(result_map->u.map, "max_parallel"), result.bench.max_parallel);
  ASSERT_EQ(mapping_number(result_map->u.map, "checksum"), static_cast<long>(result.bench.checksum));
  free_mapping(completed);
}

TEST_F(DriverTest, TestVmWorkerV2TimeoutFailsPendingTask) {
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

  free_mapping(vm_owner_drain_mailbox("global", 0));
  auto task_id = vm_worker_submit_benchmark_v2(64, 80, 1, 5000);
  ASSERT_GT(task_id, 0u);
  auto future_id = vm_worker_owner_future_id(task_id);
  ASSERT_GT(future_id, 0u);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  auto result = vm_worker_poll_task(task_id);
  ASSERT_EQ(result.state, VMWorkerTaskState::kFailed);
  ASSERT_EQ(result.error, "worker task timed out");
  ASSERT_EQ(result.envelope.task_id, task_id);
  ASSERT_EQ(result.envelope.owner_future_id, future_id);
  ASSERT_EQ(result.envelope.timeout_ms, 1);
  ASSERT_GT(result.envelope.completed_at_ms, 0u);

  auto* still_pending = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(still_pending, "state"), "pending");
  ASSERT_EQ(mapping_number(still_pending, "target_task_id"), static_cast<long>(task_id));
  free_mapping(still_pending);

  auto* scheduled = vm_owner_drain_mailbox("global", 1);
  ASSERT_EQ(mapping_number(scheduled, "drained"), 1);
  auto* tasks = find_string_in_mapping(scheduled, "tasks");
  ASSERT_NE(tasks, nullptr);
  ASSERT_EQ(tasks ? tasks->type : T_INVALID, T_ARRAY);
  ASSERT_EQ(tasks->u.arr->size, 1);
  auto* task_map = tasks->u.arr->item[0].u.map;
  ASSERT_STREQ(mapping_string(task_map, "task_type"), "compute_result");
  ASSERT_STREQ(mapping_string(task_map, "task_key"), "bench");
  ASSERT_EQ(mapping_number(task_map, "future_target_task_id"), static_cast<long>(task_id));
  ASSERT_STREQ(mapping_string(task_map, "future_state"), "failed");
  ASSERT_STREQ(mapping_string(task_map, "future_error"), "worker task timed out");
  free_mapping(scheduled);

  auto* failed = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(failed, "state"), "failed");
  ASSERT_STREQ(mapping_string(failed, "error"), "worker task timed out");
  ASSERT_EQ(mapping_number(failed, "requires_owner_message_completion"), 0);
  ASSERT_EQ(mapping_number(failed, "frozen_result"), 0);
  ASSERT_EQ(mapping_number(failed, "direct_cross_owner_write"), 0);
  free_mapping(failed);
}

TEST_F(DriverTest, TestVmWorkerComputeResultFutureCarriesSnapshotDigestResult) {
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

  const char* owner = "actor/future-snapshot";
  free_mapping(vm_owner_drain_mailbox(owner, 0));
  auto task_id = vm_worker_submit_snapshot_digest_v2(owner, "{\"hp\":100}", 8, 1000, 5000);
  ASSERT_GT(task_id, 0u);
  auto future_id = vm_worker_owner_future_id(task_id);
  ASSERT_GT(future_id, 0u);

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

  free_mapping(vm_owner_drain_mailbox(owner, 1));
  auto* completed = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "snapshot_digest");
  auto* result_map = find_string_in_mapping(completed, "result");
  ASSERT_NE(result_map, nullptr);
  ASSERT_EQ(result_map ? result_map->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(result_map->u.map, "type"), "snapshot_digest");
  ASSERT_STREQ(mapping_string(result_map->u.map, "owner_key"), owner);
  ASSERT_EQ(mapping_number(result_map->u.map, "input_bytes"), 10);
  ASSERT_EQ(mapping_number(result_map->u.map, "repeat"), 8);
  ASSERT_NE(find_string_in_mapping(result_map->u.map, "checksum"), nullptr);
  free_mapping(completed);
}

TEST_F(DriverTest, TestVmWorkerComputeResultFutureCarriesCombatDamageResult) {
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

  const char* owner = "combat/future-damage";
  free_mapping(vm_owner_drain_mailbox(owner, 0));
  VMWorkerCombatDamageInput input;
  input.snapshot_hash = 31337;
  input.attack = 100;
  input.defense = 50;
  input.variance_roll_bp = 500;
  input.critical_roll = 100;

  auto task_id = vm_worker_submit_combat_damage_v2(owner, input, 1000, 5000);
  ASSERT_GT(task_id, 0u);
  auto future_id = vm_worker_owner_future_id(task_id);
  ASSERT_GT(future_id, 0u);

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

  free_mapping(vm_owner_drain_mailbox(owner, 1));
  auto* completed = vm_owner_future_poll(future_id);
  ASSERT_STREQ(mapping_string(completed, "state"), "completed");
  ASSERT_STREQ(mapping_string(completed, "result_key"), "combat_damage");
  auto* result_map = find_string_in_mapping(completed, "result");
  ASSERT_NE(result_map, nullptr);
  ASSERT_EQ(result_map ? result_map->type : T_INVALID, T_MAPPING);
  ASSERT_STREQ(mapping_string(result_map->u.map, "type"), "combat_damage");
  ASSERT_STREQ(mapping_string(result_map->u.map, "owner_key"), owner);
  ASSERT_EQ(mapping_number(result_map->u.map, "damage"), 95);
  ASSERT_EQ(mapping_number(result_map->u.map, "critical_hit"), 0);
  ASSERT_EQ(mapping_number(result_map->u.map, "snapshot_hash"), 31337);
  free_mapping(completed);
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

TEST_F(DriverTest, TestGatewayDaemonUsesDefaultOwnerForSystemMessages) {
  if (auto *existing = find_object("adm/daemons/gateway_d.c")) {
    destruct_object(existing);
  }
  current_object = master_ob;
  auto *player = clone_object("single/owner_singleton", 0);
  ASSERT_NE(player, nullptr);
  vm_owner_set_id(player, "owner/test/gateway/daemon-player");

  VMOwnerScope scope(vm_context(), vm_owner_id(player), vm_owner_epoch(player));
  current_object = player;
  auto *daemon = load_object_for_test("adm/daemons/gateway_d.c");
  ASSERT_NE(daemon, nullptr);
  ASSERT_STREQ(vm_owner_default_id(), vm_owner_id(daemon));
  ASSERT_NE(vm_owner_id(daemon), vm_owner_id(player));
  auto daemon_epoch = vm_owner_epoch(daemon);

  ASSERT_TRUE(gateway_dispatch_message_for_test(
      -1, R"({"type":"sys","action":"owner_probe","source":"cpp_test"})"));

  auto *info = call_lpc_method(daemon, "query_last_system_message");
  ASSERT_NE(info, nullptr);
  ASSERT_EQ(info->type, T_MAPPING);
  auto mapping_number = [](mapping_t *map, const char *key) -> long {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t *map, const char *key) -> const char * {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  ASSERT_STREQ(mapping_string(info->u.map, "owner_id"), vm_owner_default_id());
  ASSERT_EQ(mapping_number(info->u.map, "owner_epoch"), static_cast<long>(daemon_epoch));
  ASSERT_NE(std::string(mapping_string(info->u.map, "this_player")).find("adm/daemons/gateway_d"),
            std::string::npos);
  ASSERT_STREQ(mapping_string(info->u.map, "type"), "sys");
  ASSERT_STREQ(mapping_string(info->u.map, "action"), "owner_probe");
  ASSERT_STREQ(mapping_string(info->u.map, "source"), "cpp_test");

  auto *trace = vm_owner_task_trace(16);
  ASSERT_NE(trace, nullptr);
  ASSERT_EQ(mapping_number(trace, "success"), 1);
  auto *events_value = find_string_in_mapping(trace, "events");
  ASSERT_NE(events_value, nullptr);
  ASSERT_EQ(events_value ? events_value->type : T_INVALID, T_ARRAY);
  bool found_gateway_trace = false;
  if (events_value && events_value->type == T_ARRAY) {
    for (int i = 0; i < events_value->u.arr->size; i++) {
      auto *event = events_value->u.arr->item[i].u.map;
      if (std::string(mapping_string(event, "task_type")) == "gateway" &&
          std::string(mapping_string(event, "task_key")) == "receive_system_message" &&
          std::string(mapping_string(event, "owner_id")) == vm_owner_default_id() &&
          mapping_number(event, "owner_epoch") == static_cast<long>(daemon_epoch) &&
          std::string(mapping_string(event, "state")) == "dispatched") {
        found_gateway_trace = true;
        break;
      }
    }
  }
  ASSERT_TRUE(found_gateway_trace);
  free_mapping(trace);

  destruct_object(daemon);
  destruct_object(player);
}

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

TEST_F(DriverTest, TestGatewayReceiveRunsThroughOwnerMainQueue) {
  auto *ob = create_gateway_session_for_test("gw-test-receive", "/clone/gateway_login_example");
  ASSERT_NE(ob, nullptr);
  ASSERT_NE(ob->interactive, nullptr);
  ASSERT_TRUE(gateway_is_session(ob));
  auto owner_epoch = vm_owner_epoch(ob);

  auto mapping_number = [](mapping_t *map, const char *key) -> long {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t *map, const char *key) -> const char * {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  ASSERT_TRUE(gateway_dispatch_message_for_test(
      -1, R"({"type":"data","cid":"gw-test-receive","data":{"cmd":"look","seq":7}})"));

  auto *payload = call_lpc_method(ob, "query_last_gateway_payload");
  ASSERT_NE(payload, nullptr);
  ASSERT_EQ(payload->type, T_MAPPING);
  ASSERT_STREQ(mapping_string(payload->u.map, "cmd"), "look");
  ASSERT_EQ(mapping_number(payload->u.map, "seq"), 7);

  auto *context = call_lpc_method(ob, "query_last_gateway_receive_context");
  ASSERT_NE(context, nullptr);
  ASSERT_EQ(context->type, T_MAPPING);
  ASSERT_STREQ(mapping_string(context->u.map, "owner_id"), vm_owner_id(ob));
  ASSERT_EQ(mapping_number(context->u.map, "owner_epoch"), static_cast<long>(owner_epoch));
  ASSERT_NE(std::string(mapping_string(context->u.map, "this_player")).find(ob->obname), std::string::npos);

  auto *trace = vm_owner_task_trace(32);
  ASSERT_NE(trace, nullptr);
  ASSERT_EQ(mapping_number(trace, "success"), 1);
  auto *events_value = find_string_in_mapping(trace, "events");
  ASSERT_NE(events_value, nullptr);
  ASSERT_EQ(events_value ? events_value->type : T_INVALID, T_ARRAY);
  bool found_queued = false;
  bool found_main_dispatched = false;
  bool found_dispatched = false;
  if (events_value && events_value->type == T_ARRAY) {
    for (int i = 0; i < events_value->u.arr->size; i++) {
      auto *event = events_value->u.arr->item[i].u.map;
      if (std::string(mapping_string(event, "task_type")) == "gateway" &&
          std::string(mapping_string(event, "task_key")) == "gateway_receive" &&
          std::string(mapping_string(event, "owner_id")) == vm_owner_id(ob) &&
          mapping_number(event, "owner_epoch") == static_cast<long>(owner_epoch)) {
        auto state = std::string(mapping_string(event, "state"));
        found_queued = found_queued || state == "main_queued";
        found_main_dispatched = found_main_dispatched || state == "main_dispatched";
        found_dispatched = found_dispatched || state == "dispatched";
      }
    }
  }
  ASSERT_TRUE(found_queued);
  ASSERT_TRUE(found_main_dispatched);
  ASSERT_TRUE(found_dispatched);
  free_mapping(trace);
  ASSERT_EQ(vm_owner_drain_main_tasks(1), 0);

  add_ref(ob, "TestGatewayReceiveRunsThroughOwnerMainQueue");
  ASSERT_EQ(gateway_destroy_session_internal("gw-test-receive", "test_done", "done"), 1);
  ASSERT_EQ(ob->interactive, nullptr);
  destruct_object(ob);
  free_object(&ob, "TestGatewayReceiveRunsThroughOwnerMainQueue");
}

TEST_F(DriverTest, TestGatewayCommandTaskCarriesOwnerHandlePayload) {
  auto *ob = create_gateway_session_for_test("gw-test-command", "/clone/gateway_login_example");
  ASSERT_NE(ob, nullptr);
  ASSERT_NE(ob->interactive, nullptr);
  ASSERT_TRUE(gateway_is_session(ob));
  auto owner_epoch = vm_owner_epoch(ob);

  auto mapping_number = [](mapping_t *map, const char *key) -> long {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t *map, const char *key) -> const char * {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  auto mapping_has_string_key = [](mapping_t *map, const char *key) -> bool {
    auto *keys = mapping_indices(map);
    bool found = false;
    for (int i = 0; keys && i < keys->size; i++) {
      if (keys->item[i].type == T_STRING && std::strcmp(keys->item[i].u.string, key) == 0) {
        found = true;
        break;
      }
    }
    if (keys) {
      free_array(keys);
    }
    return found;
  };

  ASSERT_EQ(gateway_inject_input_internal(ob, "look"), 1);
  ASSERT_EQ(gateway_process_pending_command_internal(ob), 1);

  auto *trace = vm_owner_task_trace(48);
  ASSERT_NE(trace, nullptr);
  ASSERT_EQ(mapping_number(trace, "success"), 1);
  auto *events_value = find_string_in_mapping(trace, "events");
  ASSERT_NE(events_value, nullptr);
  ASSERT_EQ(events_value ? events_value->type : T_INVALID, T_ARRAY);
  bool found_command_task = false;
  if (events_value && events_value->type == T_ARRAY) {
    for (int i = 0; i < events_value->u.arr->size; i++) {
      auto *event = events_value->u.arr->item[i].u.map;
      if (std::string(mapping_string(event, "task_type")) == "gateway" &&
          std::string(mapping_string(event, "task_key")) == "process_user_command" &&
          std::string(mapping_string(event, "state")) == "main_queued" &&
          std::string(mapping_string(event, "owner_id")) == vm_owner_id(ob) &&
          mapping_number(event, "owner_epoch") == static_cast<long>(owner_epoch)) {
        found_command_task = true;
        ASSERT_EQ(mapping_number(event, "has_target_handle"), 1);
        ASSERT_EQ(mapping_number(event, "target_handle_current"), 1);
        ASSERT_STREQ(mapping_string(event, "target_handle_status"), "current");
        ASSERT_EQ(mapping_number(event, "target_owner_epoch"), static_cast<long>(owner_epoch));
        ASSERT_STREQ(mapping_string(event, "payload_key"), "gateway_command_input");
        ASSERT_STREQ(mapping_string(event, "command_text_snapshot_policy"), "owner_private_redacted_from_trace");
        ASSERT_EQ(mapping_number(event, "command_text_snapshot_ready"), 1);
        ASSERT_GT(mapping_number(event, "command_text_snapshot_bytes"), 0);
        ASSERT_EQ(mapping_number(event, "command_text_snapshot_redacted"), 1);
        ASSERT_STREQ(mapping_string(event, "command_text_snapshot_blocker"), "");
        ASSERT_STREQ(mapping_string(event, "command_consume_model"), "owner_owned_snapshot_main_thread_consume");
        ASSERT_EQ(mapping_number(event, "command_consume_snapshot_ready"), 1);
        ASSERT_EQ(mapping_number(event, "command_consume_executor_ready"), 1);
        ASSERT_STREQ(mapping_string(event, "command_consume_blocker"), "");
        ASSERT_STREQ(mapping_string(event, "execution_frame_model"), "gateway_command_execution_frame_v1");
        ASSERT_STREQ(mapping_string(event, "execution_frame_policy"), "owner_scope_current_interactive_command_giver");
        ASSERT_STREQ(mapping_string(event, "execution_frame_restore_policy"), "owner_executor_vmcontext_restore");
        ASSERT_EQ(mapping_number(event, "execution_frame_restore_ready"), 1);
        ASSERT_STREQ(mapping_string(event, "execution_frame_restore_blocker"), "");
        ASSERT_EQ(mapping_number(event, "execution_frame_requires_current_interactive"), 1);
        ASSERT_EQ(mapping_number(event, "execution_frame_requires_command_giver"), 1);
        ASSERT_EQ(mapping_number(event, "execution_frame_executor_ready"), 1);
        ASSERT_EQ(mapping_number(event, "payload_frozen"), 1);
        auto *payload_value = find_string_in_mapping(event, "payload");
        ASSERT_NE(payload_value, nullptr);
        ASSERT_EQ(payload_value ? payload_value->type : T_INVALID, T_MAPPING);
        auto *payload = payload_value->u.map;
        ASSERT_STREQ(mapping_string(payload, "payload_model"), "gateway_command_buffer_metadata_v1");
        ASSERT_STREQ(mapping_string(payload, "payload_policy"), "no_raw_command_text_in_trace");
        ASSERT_STREQ(mapping_string(payload, "input_source"), "interactive_text_buffer");
        ASSERT_STREQ(mapping_string(payload, "command_text_snapshot_policy"), "owner_private_redacted_from_trace");
        ASSERT_EQ(mapping_number(payload, "command_text_snapshot_ready"), 1);
        ASSERT_GT(mapping_number(payload, "command_text_snapshot_bytes"), 0);
        ASSERT_EQ(mapping_number(payload, "command_text_snapshot_redacted"), 1);
        ASSERT_STREQ(mapping_string(payload, "input_callback_state_policy"), "redacted_input_to_get_char_state_v1");
        ASSERT_EQ(mapping_number(payload, "input_callback_state_snapshot_ready"), 1);
        ASSERT_EQ(mapping_number(payload, "input_callback_state_redacted"), 1);
        ASSERT_EQ(mapping_number(payload, "input_callback_active"), 0);
        ASSERT_EQ(mapping_number(payload, "input_callback_single_char"), 0);
        ASSERT_EQ(mapping_number(payload, "input_callback_noescape"), 0);
        ASSERT_EQ(mapping_number(payload, "input_callback_noecho"), 0);
        ASSERT_EQ(mapping_number(payload, "input_callback_carryover_count"), 0);
        ASSERT_EQ(mapping_number(payload, "input_callback_function_redacted"), 0);
        ASSERT_EQ(mapping_number(payload, "input_callback_object_redacted"), 0);
        ASSERT_STREQ(mapping_string(payload, "command_executor_blocker"),
                     "interactive_command_side_effects_main_thread_bound");
        ASSERT_STREQ(mapping_string(payload, "command_consume_model"), "owner_owned_snapshot_main_thread_consume");
        ASSERT_EQ(mapping_number(payload, "command_consume_snapshot_ready"), 1);
        ASSERT_EQ(mapping_number(payload, "command_consume_executor_ready"), 1);
        ASSERT_STREQ(mapping_string(payload, "command_consume_blocker"), "");
        ASSERT_STREQ(mapping_string(payload, "execution_frame_restore_policy"), "owner_executor_vmcontext_restore");
        ASSERT_EQ(mapping_number(payload, "execution_frame_restore_ready"), 1);
        ASSERT_STREQ(mapping_string(payload, "execution_frame_restore_blocker"), "");
        ASSERT_FALSE(mapping_has_string_key(payload, "command_text"));
        ASSERT_STREQ(mapping_string(payload, "session_id"), "gw-test-command");
        ASSERT_EQ(mapping_number(payload, "cmd_in_buf"), 1);
        ASSERT_EQ(mapping_number(payload, "gateway_session"), 1);
        ASSERT_GT(mapping_number(payload, "pending_bytes"), 0);
      }
    }
  }
  ASSERT_TRUE(found_command_task);
  free_mapping(trace);

  add_ref(ob, "TestGatewayCommandTaskCarriesOwnerHandlePayload");
  ASSERT_EQ(gateway_destroy_session_internal("gw-test-command", "test_done", "done"), 1);
  ASSERT_EQ(ob->interactive, nullptr);
  destruct_object(ob);
  free_object(&ob, "TestGatewayCommandTaskCarriesOwnerHandlePayload");
}

TEST_F(DriverTest, TestGatewayCommandMainQueueDropsStaleOwnerEpoch) {
  auto *ob = create_gateway_session_for_test("gw-test-command-stale", "/clone/gateway_login_example");
  ASSERT_NE(ob, nullptr);
  ASSERT_NE(ob->interactive, nullptr);
  ASSERT_TRUE(gateway_is_session(ob));
  const std::string owner_id = vm_owner_id(ob);
  auto stale_epoch = vm_owner_epoch(ob);

  auto mapping_number = [](mapping_t *map, const char *key) -> long {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t *map, const char *key) -> const char * {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };

  ASSERT_EQ(gateway_inject_input_internal(ob, "look"), 1);
  auto task_id = gateway_enqueue_pending_command_internal(ob);
  ASSERT_GT(task_id, 0u);
  vm_owner_clear_id(ob);
  vm_owner_set_id(ob, owner_id.c_str());
  ASSERT_STREQ(vm_owner_id(ob), owner_id.c_str());
  auto current_epoch = vm_owner_epoch(ob);
  ASSERT_GT(current_epoch, stale_epoch);

  ASSERT_EQ(vm_owner_drain_main_tasks(8), 1);
  ASSERT_TRUE(ob->interactive->iflags & CMD_IN_BUF);

  auto *trace = vm_owner_task_trace(64);
  ASSERT_NE(trace, nullptr);
  ASSERT_EQ(mapping_number(trace, "success"), 1);
  auto *events_value = find_string_in_mapping(trace, "events");
  ASSERT_NE(events_value, nullptr);
  ASSERT_EQ(events_value ? events_value->type : T_INVALID, T_ARRAY);
  bool found_stale_command_task = false;
  bool found_interactive_dispatch = false;
  if (events_value && events_value->type == T_ARRAY) {
    for (int i = 0; i < events_value->u.arr->size; i++) {
      auto *event = events_value->u.arr->item[i].u.map;
      if (std::string(mapping_string(event, "task_type")) == "gateway" &&
          std::string(mapping_string(event, "task_key")) == "process_user_command" &&
          mapping_number(event, "task_id") == static_cast<long>(task_id)) {
        if (std::string(mapping_string(event, "state")) == "main_stale") {
          found_stale_command_task = true;
          ASSERT_STREQ(mapping_string(event, "owner_id"), owner_id.c_str());
          ASSERT_EQ(mapping_number(event, "owner_epoch"), static_cast<long>(stale_epoch));
          ASSERT_EQ(mapping_number(event, "has_target_handle"), 1);
          ASSERT_EQ(mapping_number(event, "target_handle_current"), 0);
          ASSERT_STREQ(mapping_string(event, "target_handle_status"), "owner_epoch_mismatch");
          ASSERT_EQ(mapping_number(event, "target_owner_epoch"), static_cast<long>(stale_epoch));
          ASSERT_STREQ(mapping_string(event, "command_text_snapshot_policy"), "owner_private_redacted_from_trace");
          ASSERT_EQ(mapping_number(event, "command_text_snapshot_ready"), 1);
          ASSERT_GT(mapping_number(event, "command_text_snapshot_bytes"), 0);
          ASSERT_EQ(mapping_number(event, "command_text_snapshot_redacted"), 1);
          ASSERT_STREQ(mapping_string(event, "command_text_snapshot_blocker"), "");
          ASSERT_STREQ(mapping_string(event, "command_consume_model"), "owner_owned_snapshot_main_thread_consume");
          ASSERT_EQ(mapping_number(event, "command_consume_snapshot_ready"), 1);
          ASSERT_EQ(mapping_number(event, "command_consume_executor_ready"), 1);
          ASSERT_STREQ(mapping_string(event, "command_consume_blocker"), "");
          ASSERT_STREQ(mapping_string(event, "execution_frame_model"), "gateway_command_execution_frame_v1");
          ASSERT_STREQ(mapping_string(event, "execution_frame_policy"),
                       "owner_scope_current_interactive_command_giver");
          ASSERT_STREQ(mapping_string(event, "execution_frame_restore_policy"), "owner_executor_vmcontext_restore");
          ASSERT_EQ(mapping_number(event, "execution_frame_restore_ready"), 1);
          ASSERT_STREQ(mapping_string(event, "execution_frame_restore_blocker"), "");
          ASSERT_EQ(mapping_number(event, "execution_frame_executor_ready"), 1);
          ASSERT_EQ(mapping_number(event, "payload_frozen"), 1);
        }
      }
      if (std::string(mapping_string(event, "task_type")) == "interactive" &&
          std::string(mapping_string(event, "task_key")) == "process_user_command" &&
          std::string(mapping_string(event, "owner_id")) == owner_id &&
          mapping_number(event, "owner_epoch") == static_cast<long>(current_epoch)) {
        found_interactive_dispatch = true;
      }
    }
  }
  ASSERT_TRUE(found_stale_command_task);
  ASSERT_FALSE(found_interactive_dispatch);
  free_mapping(trace);

  add_ref(ob, "TestGatewayCommandMainQueueDropsStaleOwnerEpoch");
  ASSERT_EQ(gateway_destroy_session_internal("gw-test-command-stale", "test_done", "done"), 1);
  ASSERT_EQ(ob->interactive, nullptr);
  destruct_object(ob);
  free_object(&ob, "TestGatewayCommandMainQueueDropsStaleOwnerEpoch");
}

TEST_F(DriverTest, TestGatewaySessionExecLogonKeepsSessionLookupWorking) {
  auto *ob = create_gateway_session_for_test("gw-test-exec", "/clone/gateway_login_exec_example");
  ASSERT_NE(ob, nullptr);
  ASSERT_NE(ob->interactive, nullptr);
  ASSERT_TRUE(gateway_is_session(ob));
  ASSERT_NE(std::string(ob->obname).find("clone/gateway_exec_user"), std::string::npos);
  ASSERT_STREQ("owner/test/gateway/exec-user", vm_owner_id(ob));
  auto owner_epoch = vm_owner_epoch(ob);

  auto *info = call_lpc_method(ob, "query_gateway_session_snapshot");
  ASSERT_NE(info, nullptr);
  ASSERT_EQ(info->type, T_MAPPING);
  auto mapping_number = [](mapping_t *map, const char *key) -> long {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_NUMBER);
    return value && value->type == T_NUMBER ? value->u.number : 0;
  };
  auto mapping_string = [](mapping_t *map, const char *key) -> const char * {
    auto *value = find_string_in_mapping(map, key);
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(value ? value->type : T_INVALID, T_STRING);
    return value && value->type == T_STRING ? value->u.string : "";
  };
  ASSERT_STREQ(mapping_string(info->u.map, "owner_id"), "owner/test/gateway/exec-user");
  ASSERT_EQ(mapping_number(info->u.map, "owner_epoch"), static_cast<long>(owner_epoch));
  ASSERT_STREQ(mapping_string(info->u.map, "object_name"), ob->obname);

  add_ref(ob, "TestGatewaySessionExecLogonKeepsSessionLookupWorking");
  ASSERT_EQ(gateway_destroy_session_internal("gw-test-exec", "test_done", "done"), 1);
  ASSERT_EQ(ob->interactive, nullptr);
  ASSERT_STREQ("owner/test/gateway/exec-user", vm_owner_id(ob));
  ASSERT_EQ(vm_owner_epoch(ob), owner_epoch);
  destruct_object(ob);
  free_object(&ob, "TestGatewaySessionExecLogonKeepsSessionLookupWorking");
}
