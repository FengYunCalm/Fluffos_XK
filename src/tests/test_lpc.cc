#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <thread>
#include "base/package_api.h"

#include "mainlib.h"

#include "compiler/internal/compiler.h"
#include "packages/gateway/gateway.h"
#include "vm/context.h"
#include "vm/internal/simulate.h"
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

  void TearDown() override { clear_state(); }
};

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
  ASSERT_EQ(vm_context().object_store.objects, obj_list);
  ASSERT_EQ(vm_context().object_store.destructed_objects, obj_list_destruct);
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
