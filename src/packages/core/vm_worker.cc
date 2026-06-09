#include "base/package_api.h"

#include <string>

#include "vm/worker.h"

namespace {

bool is_json_safe_value(const svalue_t *value, int depth, std::string *error) {
  if (depth > 8) {
    *error = "worker value nesting is too deep";
    return false;
  }
  switch (value->type) {
    case T_NUMBER:
    case T_REAL:
    case T_STRING:
      return true;
    case T_ARRAY:
      for (int i = 0; i < value->u.arr->size; i++) {
        if (!is_json_safe_value(&value->u.arr->item[i], depth + 1, error)) {
          return false;
        }
      }
      return true;
    case T_MAPPING:
      for (unsigned int i = 0; i < value->u.map->table_size; i++) {
        for (auto *node = value->u.map->table[i]; node; node = node->next) {
          if (node->values[0].type != T_STRING) {
            *error = "worker mapping keys must be strings";
            return false;
          }
          if (!is_json_safe_value(&node->values[1], depth + 1, error)) {
            return false;
          }
        }
      }
      return true;
    default:
      *error = "worker value contains unsupported type";
      return false;
  }
}

int mapping_number(mapping_t *map, const char *key, int fallback) {
  auto *value = find_string_in_mapping(map, key);
  if (value && value->type == T_NUMBER) {
    return static_cast<int>(value->u.number);
  }
  return fallback;
}

void add_actor_bench_result(mapping_t *map, const VMWorkerActorBenchResult &result) {
  add_mapping_string(map, "type", "actor_bench");
  add_mapping_pair(map, "owners", result.owners);
  add_mapping_pair(map, "tasks_per_owner", result.tasks_per_owner);
  add_mapping_pair(map, "total_tasks", result.total_tasks);
  add_mapping_pair(map, "worker_count", result.worker_count);
  add_mapping_pair(map, "max_parallel", result.max_parallel);
  add_mapping_pair(map, "max_owner_parallel", result.max_owner_parallel);
  add_mapping_pair(map, "elapsed_ms", result.elapsed_ms);
  add_mapping_pair(map, "checksum", static_cast<long>(result.checksum));
}

mapping_t *worker_failure_response(const char *error) {
  auto *map = allocate_mapping(2);
  add_mapping_pair(map, "success", 0);
  add_mapping_string(map, "error", error ? error : "worker task failed");
  return map;
}

const char *worker_task_state_name(VMWorkerTaskState state) {
  switch (state) {
    case VMWorkerTaskState::kPending:
      return "pending";
    case VMWorkerTaskState::kSucceeded:
      return "succeeded";
    case VMWorkerTaskState::kFailed:
      return "failed";
    case VMWorkerTaskState::kUnknown:
      return "unknown";
  }
  return "unknown";
}

void add_mapping_mapping(mapping_t *map, const char *key_name, mapping_t *value) {
  auto key = const0u;
  key.type = T_STRING;
  key.subtype = STRING_CONSTANT;
  key.u.string = key_name;
  auto *slot = find_for_insert(map, &key, 1);
  free_string(key.u.string);
  slot->type = T_MAPPING;
  slot->u.map = value;
  value->ref++;
}

mapping_t *worker_bench_response(mapping_t *options) {
  auto tasks = mapping_number(options, "tasks", 4);
  auto millis = mapping_number(options, "millis", 100);
  auto result = vm_worker_benchmark(tasks, millis);
  auto stats = vm_worker_stats();
  auto *result_spec = allocate_mapping(9);
  add_mapping_string(result_spec, "type", "bench");
  add_mapping_pair(result_spec, "tasks", result.tasks);
  add_mapping_pair(result_spec, "worker_count", result.worker_count);
  add_mapping_pair(result_spec, "max_parallel", result.max_parallel);
  add_mapping_pair(result_spec, "elapsed_ms", result.elapsed_ms);
  add_mapping_pair(result_spec, "checksum", static_cast<long>(result.checksum));
  add_mapping_pair(result_spec, "submitted", static_cast<long>(stats.submitted));
  add_mapping_pair(result_spec, "completed", static_cast<long>(stats.completed));
  add_mapping_pair(result_spec, "active", stats.active);

  auto *response = allocate_mapping(2);
  add_mapping_pair(response, "success", 1);
  add_mapping_mapping(response, "result_spec", result_spec);
  free_mapping(result_spec);
  return response;
}

mapping_t *worker_actor_bench_response(mapping_t *options) {
  auto owners = mapping_number(options, "owners", 4);
  auto tasks_per_owner = mapping_number(options, "tasks_per_owner", 2);
  auto millis = mapping_number(options, "millis", 100);
  auto result = vm_worker_actor_benchmark(owners, tasks_per_owner, millis);
  auto *result_spec = allocate_mapping(9);
  add_actor_bench_result(result_spec, result);

  auto *response = allocate_mapping(2);
  add_mapping_pair(response, "success", 1);
  add_mapping_mapping(response, "result_spec", result_spec);
  free_mapping(result_spec);
  return response;
}

mapping_t *worker_status_response() {
  auto stats = vm_worker_stats();
  auto *map = allocate_mapping(12);
  add_mapping_pair(map, "success", 1);
  add_mapping_pair(map, "worker_count", stats.worker_count);
  add_mapping_pair(map, "submitted", static_cast<long>(stats.submitted));
  add_mapping_pair(map, "completed", static_cast<long>(stats.completed));
  add_mapping_pair(map, "active", stats.active);
  add_mapping_pair(map, "queue_depth", static_cast<long>(stats.queue_depth));
  add_mapping_pair(map, "queue_high_watermark", static_cast<long>(stats.queue_high_watermark));
  add_mapping_pair(map, "owner_queue_depth", static_cast<long>(stats.owner_queue_depth));
  add_mapping_pair(map, "active_owners", stats.active_owners);
  add_mapping_pair(map, "async_pending", static_cast<long>(stats.async_pending));
  add_mapping_pair(map, "async_ready", static_cast<long>(stats.async_ready));
  add_mapping_pair(map, "async_failed", static_cast<long>(stats.async_failed));
  return map;
}

mapping_t *worker_submit_response(const char *task_name, mapping_t *options) {
  if (std::string(task_name) != "bench") {
    return worker_failure_response("unknown worker task");
  }

  auto tasks = mapping_number(options, "tasks", 4);
  auto millis = mapping_number(options, "millis", 100);
  auto task_id = vm_worker_submit_benchmark(tasks, millis);
  auto *response = allocate_mapping(4);
  add_mapping_pair(response, "success", 1);
  add_mapping_string(response, "status", "submitted");
  add_mapping_pair(response, "task_id", static_cast<long>(task_id));
  add_mapping_string(response, "task", task_name);
  return response;
}

mapping_t *worker_poll_response(uint64_t task_id) {
  auto result = vm_worker_poll_task(task_id);
  auto *response = allocate_mapping(5);
  add_mapping_pair(response, "task_id", static_cast<long>(task_id));
  add_mapping_string(response, "status", worker_task_state_name(result.state));

  if (result.state == VMWorkerTaskState::kUnknown || result.state == VMWorkerTaskState::kFailed) {
    add_mapping_pair(response, "success", 0);
    add_mapping_string(response, "error", result.error.empty() ? "worker task failed" : result.error.c_str());
    return response;
  }

  if (result.state == VMWorkerTaskState::kPending) {
    add_mapping_pair(response, "success", 0);
    add_mapping_string(response, "error", "worker task is still pending");
    return response;
  }

  auto *result_spec = allocate_mapping(6);
  add_mapping_string(result_spec, "type", "bench");
  add_mapping_pair(result_spec, "tasks", result.bench.tasks);
  add_mapping_pair(result_spec, "worker_count", result.bench.worker_count);
  add_mapping_pair(result_spec, "max_parallel", result.bench.max_parallel);
  add_mapping_pair(result_spec, "elapsed_ms", result.bench.elapsed_ms);
  add_mapping_pair(result_spec, "checksum", static_cast<long>(result.bench.checksum));
  add_mapping_pair(response, "success", 1);
  add_mapping_mapping(response, "result_spec", result_spec);
  free_mapping(result_spec);
  return response;
}

}  // namespace

#ifdef F_VM_WORKER_BENCH
void f_vm_worker_bench() {
  auto millis = sp->u.number;
  auto tasks = (sp - 1)->u.number;
  pop_2_elems();

  auto result = vm_worker_benchmark(static_cast<int>(tasks), static_cast<int>(millis));
  auto stats = vm_worker_stats();
  auto *map = allocate_mapping(8);
  add_mapping_pair(map, "tasks", result.tasks);
  add_mapping_pair(map, "worker_count", result.worker_count);
  add_mapping_pair(map, "max_parallel", result.max_parallel);
  add_mapping_pair(map, "elapsed_ms", result.elapsed_ms);
  add_mapping_pair(map, "checksum", static_cast<long>(result.checksum));
  add_mapping_pair(map, "submitted", static_cast<long>(stats.submitted));
  add_mapping_pair(map, "completed", static_cast<long>(stats.completed));
  add_mapping_pair(map, "active", stats.active);
  push_refed_mapping(map);
}
#endif

#ifdef F_VM_WORKER_TASK
void f_vm_worker_task() {
  auto *options = sp;
  auto *snapshot = sp - 1;
  auto *task = sp - 2;
  std::string error;
  mapping_t *response = nullptr;

  if (!is_json_safe_value(snapshot, 0, &error) || !is_json_safe_value(options, 0, &error)) {
    pop_3_elems();
    push_refed_mapping(worker_failure_response(error.c_str()));
    return;
  }

  std::string task_name(task->u.string);
  if (task_name == "bench") {
    response = worker_bench_response(options->u.map);
  } else if (task_name == "actor_bench") {
    response = worker_actor_bench_response(options->u.map);
  } else {
    response = worker_failure_response("unknown worker task");
  }

  pop_3_elems();
  push_refed_mapping(response);
}
#endif

#ifdef F_VM_WORKER_ACTOR_BENCH
void f_vm_worker_actor_bench() {
  auto millis = sp->u.number;
  auto tasks_per_owner = (sp - 1)->u.number;
  auto owners = (sp - 2)->u.number;
  pop_3_elems();

  auto result = vm_worker_actor_benchmark(static_cast<int>(owners), static_cast<int>(tasks_per_owner),
                                          static_cast<int>(millis));
  auto *map = allocate_mapping(9);
  add_actor_bench_result(map, result);
  push_refed_mapping(map);
}
#endif

#ifdef F_VM_WORKER_STATUS
void f_vm_worker_status() { push_refed_mapping(worker_status_response()); }
#endif

#ifdef F_VM_WORKER_SUBMIT
void f_vm_worker_submit() {
  auto *options = sp;
  auto *snapshot = sp - 1;
  auto *task = sp - 2;
  std::string error;
  mapping_t *response = nullptr;

  if (!is_json_safe_value(snapshot, 0, &error) || !is_json_safe_value(options, 0, &error)) {
    pop_3_elems();
    push_refed_mapping(worker_failure_response(error.c_str()));
    return;
  }

  response = worker_submit_response(task->u.string, options->u.map);
  pop_3_elems();
  push_refed_mapping(response);
}
#endif

#ifdef F_VM_WORKER_POLL
void f_vm_worker_poll() {
  auto task_id = static_cast<uint64_t>(sp->u.number);
  pop_stack();
  push_refed_mapping(worker_poll_response(task_id));
}
#endif
