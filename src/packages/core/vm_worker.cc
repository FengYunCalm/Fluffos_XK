#include "base/package_api.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

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

std::string mapping_string(mapping_t *map, const char *key, const char *fallback) {
  auto *value = find_string_in_mapping(map, key);
  if (value && value->type == T_STRING) {
    return value->u.string ? value->u.string : "";
  }
  return fallback ? fallback : "";
}

mapping_t *mapping_mapping(mapping_t *map, const char *key) {
  auto *value = find_string_in_mapping(map, key);
  if (value && value->type == T_MAPPING) {
    return value->u.map;
  }
  return nullptr;
}

void append_counted_string(std::string *out, const char *value) {
  auto length = value ? std::strlen(value) : 0;
  out->append(std::to_string(length));
  out->push_back(':');
  if (length > 0) {
    out->append(value, length);
  }
}

void append_snapshot_value(const svalue_t *value, int depth, std::string *out) {
  if (depth > 8) {
    out->append("depth");
    return;
  }

  switch (value->type) {
    case T_NUMBER:
      out->append("i");
      out->append(std::to_string(value->u.number));
      return;
    case T_REAL: {
      char buffer[64];
      std::snprintf(buffer, sizeof(buffer), "%.17g", value->u.real);
      out->append("f");
      out->append(buffer);
      return;
    }
    case T_STRING:
      out->append("s");
      append_counted_string(out, value->u.string);
      return;
    case T_ARRAY:
      out->append("a");
      out->append(std::to_string(value->u.arr->size));
      out->push_back('[');
      for (int i = 0; i < value->u.arr->size; i++) {
        append_snapshot_value(&value->u.arr->item[i], depth + 1, out);
        out->push_back(';');
      }
      out->push_back(']');
      return;
    case T_MAPPING: {
      std::vector<std::pair<std::string, std::string>> entries;
      for (unsigned int i = 0; i < value->u.map->table_size; i++) {
        for (auto *node = value->u.map->table[i]; node; node = node->next) {
          std::string encoded;
          append_snapshot_value(&node->values[1], depth + 1, &encoded);
          entries.emplace_back(node->values[0].u.string ? node->values[0].u.string : "", std::move(encoded));
        }
      }
      std::sort(entries.begin(), entries.end(), [](const auto &left, const auto &right) {
        return left.first < right.first;
      });
      out->append("m");
      out->append(std::to_string(entries.size()));
      out->push_back('{');
      for (const auto &entry : entries) {
        append_counted_string(out, entry.first.c_str());
        out->push_back('=');
        out->append(entry.second);
        out->push_back(';');
      }
      out->push_back('}');
      return;
    }
    default:
      out->append("unsupported");
      return;
  }
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

void add_snapshot_digest_result(mapping_t *map, const VMWorkerSnapshotDigestResult &result) {
  add_mapping_string(map, "type", "snapshot_digest");
  add_mapping_string(map, "owner_key", result.owner_key.c_str());
  add_mapping_pair(map, "worker_count", result.worker_count);
  add_mapping_pair(map, "elapsed_ms", result.elapsed_ms);
  add_mapping_pair(map, "input_bytes", static_cast<long>(result.input_bytes));
  add_mapping_pair(map, "repeat", result.repeat);
  add_mapping_pair(map, "checksum", static_cast<long>(result.checksum));
}

void add_actor_score_result(mapping_t *map, const VMWorkerActorScoreResult &result) {
  add_mapping_string(map, "type", "actor_score");
  add_mapping_string(map, "owner_key", result.owner_key.c_str());
  add_mapping_pair(map, "worker_count", result.worker_count);
  add_mapping_pair(map, "elapsed_ms", result.elapsed_ms);
  add_mapping_pair(map, "hp_pct_bp", result.hp_pct_bp);
  add_mapping_pair(map, "mp_pct_bp", result.mp_pct_bp);
  add_mapping_pair(map, "ep_pct_bp", result.ep_pct_bp);
  add_mapping_pair(map, "survival_score", result.survival_score);
  add_mapping_pair(map, "resource_score", result.resource_score);
  add_mapping_pair(map, "total_score", result.total_score);
  add_mapping_string(map, "state", result.state.c_str());
}

void add_combat_damage_result(mapping_t *map, const VMWorkerCombatDamageResult &result) {
  add_mapping_string(map, "type", "combat_damage");
  add_mapping_string(map, "owner_key", result.owner_key.c_str());
  add_mapping_pair(map, "worker_count", result.worker_count);
  add_mapping_pair(map, "elapsed_ms", result.elapsed_ms);
  add_mapping_pair(map, "damage", result.damage);
  add_mapping_pair(map, "armor_break_bp", result.armor_break_bp);
  add_mapping_pair(map, "reduction_bp", result.reduction_bp);
  add_mapping_pair(map, "critical_rate", result.critical_rate);
  add_mapping_pair(map, "critical_hit", result.critical_hit);
  add_mapping_pair(map, "input_hash", static_cast<long>(result.input_hash));
}

void add_task_envelope(mapping_t *map, const VMWorkerTaskEnvelope &envelope) {
  add_mapping_pair(map, "task_id", static_cast<long>(envelope.task_id));
  add_mapping_string(map, "task_type", envelope.task_type.c_str());
  add_mapping_string(map, "owner_key", envelope.owner_key.c_str());
  add_mapping_pair(map, "submitted_at_ms", static_cast<long>(envelope.submitted_at_ms));
  add_mapping_pair(map, "deadline_at_ms", static_cast<long>(envelope.deadline_at_ms));
  add_mapping_pair(map, "completed_at_ms", static_cast<long>(envelope.completed_at_ms));
  add_mapping_pair(map, "expires_at_ms", static_cast<long>(envelope.expires_at_ms));
  add_mapping_pair(map, "input_hash", static_cast<long>(envelope.input_hash));
  add_mapping_pair(map, "timeout_ms", envelope.timeout_ms);
  add_mapping_pair(map, "ttl_ms", envelope.ttl_ms);
}

bool read_actor_score_input(svalue_t *snapshot, mapping_t *options,
                            std::string *owner_key,
                            VMWorkerActorScoreInput *input,
                            std::string *error) {
  if (snapshot->type != T_MAPPING) {
    *error = "actor_score snapshot must be a mapping";
    return false;
  }

  auto *snapshot_map = snapshot->u.map;
  auto *combat = mapping_mapping(snapshot_map, "combat");
  if (!combat) {
    *error = "actor_score snapshot combat mapping is required";
    return false;
  }

  auto fallback_owner_key = mapping_string(snapshot_map, "owner_key", "global");
  *owner_key = mapping_string(options, "owner_key", fallback_owner_key.c_str());
  input->hp = mapping_number(combat, "hp", 0);
  input->max_hp = mapping_number(combat, "max_hp", 0);
  input->mp = mapping_number(combat, "mp", 0);
  input->max_mp = mapping_number(combat, "max_mp", 0);
  input->ep = mapping_number(combat, "ep", 0);
  input->max_ep = mapping_number(combat, "max_ep", 0);
  return true;
}

bool read_combat_damage_input(svalue_t *snapshot, mapping_t *options,
                              std::string *owner_key,
                              VMWorkerCombatDamageInput *input,
                              std::string *error) {
  if (snapshot->type != T_MAPPING) {
    *error = "combat_damage snapshot must be a mapping";
    return false;
  }

  auto *snapshot_map = snapshot->u.map;
  auto fallback_owner_key = mapping_string(snapshot_map, "owner_key", "global");
  *owner_key = mapping_string(options, "owner_key", fallback_owner_key.c_str());
  input->attack = mapping_number(snapshot_map, "attack", 0);
  input->defense = mapping_number(snapshot_map, "defense", 0);
  input->armor_break = mapping_number(snapshot_map, "armor_break", 0);
  input->critical = mapping_number(snapshot_map, "critical", 0);
  input->critical_resist = mapping_number(snapshot_map, "critical_resist", 0);
  input->armor_break_defense_factor_bp = mapping_number(snapshot_map, "armor_break_defense_factor_bp", 9000);
  input->armor_break_flat = mapping_number(snapshot_map, "armor_break_flat", 5000);
  input->armor_break_cap_bp = mapping_number(snapshot_map, "armor_break_cap_bp", 8000);
  input->reduction_attack_factor_bp = mapping_number(snapshot_map, "reduction_attack_factor_bp", 16000);
  input->reduction_flat = mapping_number(snapshot_map, "reduction_flat", 8000);
  input->reduction_min_bp = mapping_number(snapshot_map, "reduction_min_bp", 500);
  input->reduction_max_bp = mapping_number(snapshot_map, "reduction_max_bp", 7500);
  input->damage_base = mapping_number(snapshot_map, "damage_base", 1);
  input->damage_skill_factor_bp = mapping_number(snapshot_map, "damage_skill_factor_bp", 10000);
  input->damage_random_min_bp = mapping_number(snapshot_map, "damage_random_min_bp", 9500);
  input->damage_random_max_bp = mapping_number(snapshot_map, "damage_random_max_bp", 10500);
  input->damage_min = mapping_number(snapshot_map, "damage_min", 1);
  input->variance_roll_bp = mapping_number(snapshot_map, "variance_roll_bp", 0);
  input->critical_base_bp = mapping_number(snapshot_map, "critical_base_bp", 500);
  input->critical_swing_bp = mapping_number(snapshot_map, "critical_swing_bp", 3500);
  input->critical_flat = mapping_number(snapshot_map, "critical_flat", 6000);
  input->critical_min = mapping_number(snapshot_map, "critical_min", 0);
  input->critical_max = mapping_number(snapshot_map, "critical_max", 50);
  input->critical_roll = mapping_number(snapshot_map, "critical_roll", 100);
  input->critical_damage_factor_bp = mapping_number(snapshot_map, "critical_damage_factor_bp", 15000);
  return true;
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

mapping_t *worker_envelope_mapping(const VMWorkerTaskEnvelope &envelope) {
  auto *map = allocate_mapping(10);
  add_mapping_pair(map, "task_id", static_cast<long>(envelope.task_id));
  add_mapping_string(map, "task_type", envelope.task_type.c_str());
  add_mapping_string(map, "owner_key", envelope.owner_key.c_str());
  add_mapping_pair(map, "submitted_at_ms", static_cast<long>(envelope.submitted_at_ms));
  add_mapping_pair(map, "deadline_at_ms", static_cast<long>(envelope.deadline_at_ms));
  add_mapping_pair(map, "completed_at_ms", static_cast<long>(envelope.completed_at_ms));
  add_mapping_pair(map, "expires_at_ms", static_cast<long>(envelope.expires_at_ms));
  add_mapping_pair(map, "input_hash", static_cast<long>(envelope.input_hash));
  add_mapping_pair(map, "timeout_ms", envelope.timeout_ms);
  add_mapping_pair(map, "ttl_ms", envelope.ttl_ms);
  return map;
}

void add_worker_envelope(mapping_t *map, const VMWorkerTaskEnvelope &envelope) {
  auto *envelope_map = worker_envelope_mapping(envelope);
  add_mapping_mapping(map, "envelope", envelope_map);
  free_mapping(envelope_map);
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

mapping_t *worker_snapshot_digest_response(svalue_t *snapshot, mapping_t *options) {
  auto owner_key = mapping_string(options, "owner_key", "global");
  auto repeat = mapping_number(options, "repeat", 1);
  std::string snapshot_text;
  append_snapshot_value(snapshot, 0, &snapshot_text);
  auto result = vm_worker_snapshot_digest(owner_key, std::move(snapshot_text), repeat);
  auto *result_spec = allocate_mapping(7);
  add_snapshot_digest_result(result_spec, result);

  auto *response = allocate_mapping(2);
  add_mapping_pair(response, "success", 1);
  add_mapping_mapping(response, "result_spec", result_spec);
  free_mapping(result_spec);
  return response;
}

mapping_t *worker_actor_score_response(svalue_t *snapshot, mapping_t *options) {
  VMWorkerActorScoreInput input;
  std::string owner_key;
  std::string error;
  if (!read_actor_score_input(snapshot, options, &owner_key, &input, &error)) {
    return worker_failure_response(error.c_str());
  }

  auto result = vm_worker_actor_score(owner_key, input);
  auto *result_spec = allocate_mapping(11);
  add_actor_score_result(result_spec, result);

  auto *response = allocate_mapping(2);
  add_mapping_pair(response, "success", 1);
  add_mapping_mapping(response, "result_spec", result_spec);
  free_mapping(result_spec);
  return response;
}

mapping_t *worker_combat_damage_response(svalue_t *snapshot, mapping_t *options) {
  VMWorkerCombatDamageInput input;
  std::string owner_key;
  std::string error;
  if (!read_combat_damage_input(snapshot, options, &owner_key, &input, &error)) {
    return worker_failure_response(error.c_str());
  }

  auto result = vm_worker_combat_damage(owner_key, input);
  auto *result_spec = allocate_mapping(10);
  add_combat_damage_result(result_spec, result);

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

mapping_t *worker_submit_response(const char *task_name, svalue_t *snapshot, mapping_t *options) {
  std::string task(task_name);
  uint64_t task_id = 0;
  auto timeout_ms = mapping_number(options, "timeout_ms", 0);
  auto ttl_ms = mapping_number(options, "ttl_ms", 0);

  if (task == "bench") {
    auto tasks = mapping_number(options, "tasks", 4);
    auto millis = mapping_number(options, "millis", 100);
    task_id = vm_worker_submit_benchmark_v2(tasks, millis, timeout_ms, ttl_ms);
  } else if (task == "snapshot_digest") {
    auto owner_key = mapping_string(options, "owner_key", "global");
    auto repeat = mapping_number(options, "repeat", 1);
    std::string snapshot_text;
    append_snapshot_value(snapshot, 0, &snapshot_text);
    task_id = vm_worker_submit_snapshot_digest_v2(owner_key, std::move(snapshot_text), repeat,
                                                  timeout_ms, ttl_ms);
  } else if (task == "actor_score") {
    VMWorkerActorScoreInput input;
    std::string owner_key;
    std::string error;
    if (!read_actor_score_input(snapshot, options, &owner_key, &input, &error)) {
      return worker_failure_response(error.c_str());
    }
    task_id = vm_worker_submit_actor_score_v2(owner_key, input, timeout_ms, ttl_ms);
  } else if (task == "combat_damage") {
    VMWorkerCombatDamageInput input;
    std::string owner_key;
    std::string error;
    if (!read_combat_damage_input(snapshot, options, &owner_key, &input, &error)) {
      return worker_failure_response(error.c_str());
    }
    task_id = vm_worker_submit_combat_damage_v2(owner_key, input, timeout_ms, ttl_ms);
  } else {
    return worker_failure_response("unknown worker task");
  }

  auto *response = allocate_mapping(6);
  add_mapping_pair(response, "success", 1);
  add_mapping_string(response, "status", "submitted");
  add_mapping_pair(response, "task_id", static_cast<long>(task_id));
  add_mapping_string(response, "task", task_name);
  add_mapping_pair(response, "timeout_ms", timeout_ms);
  add_mapping_pair(response, "ttl_ms", ttl_ms);
  return response;
}

mapping_t *worker_poll_response(uint64_t task_id) {
  auto result = vm_worker_poll_task(task_id);
  auto *response = allocate_mapping(8);
  add_mapping_pair(response, "task_id", static_cast<long>(task_id));
  add_mapping_string(response, "status", worker_task_state_name(result.state));
  add_mapping_string(response, "task", result.type.c_str());
  auto *envelope = allocate_mapping(10);
  add_task_envelope(envelope, result.envelope);
  add_mapping_mapping(response, "envelope", envelope);
  free_mapping(envelope);

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

  mapping_t *result_spec = nullptr;
  if (result.type == "snapshot_digest") {
    result_spec = allocate_mapping(7);
    add_snapshot_digest_result(result_spec, result.snapshot_digest);
  } else if (result.type == "actor_score") {
    result_spec = allocate_mapping(11);
    add_actor_score_result(result_spec, result.actor_score);
  } else if (result.type == "combat_damage") {
    result_spec = allocate_mapping(10);
    add_combat_damage_result(result_spec, result.combat_damage);
  } else {
    result_spec = allocate_mapping(6);
    add_mapping_string(result_spec, "type", "bench");
    add_mapping_pair(result_spec, "tasks", result.bench.tasks);
    add_mapping_pair(result_spec, "worker_count", result.bench.worker_count);
    add_mapping_pair(result_spec, "max_parallel", result.bench.max_parallel);
    add_mapping_pair(result_spec, "elapsed_ms", result.bench.elapsed_ms);
    add_mapping_pair(result_spec, "checksum", static_cast<long>(result.bench.checksum));
  }
  add_mapping_pair(response, "success", 1);
  add_mapping_mapping(response, "result_spec", result_spec);
  free_mapping(result_spec);
  return response;
}

mapping_t *worker_submit_batch_response(array_t *batch) {
  auto *results = allocate_array(batch ? batch->size : 0);
  int accepted = 0;
  int rejected = 0;

  for (int i = 0; batch && i < batch->size; i++) {
    mapping_t *item_map = nullptr;
    mapping_t *options = nullptr;
    svalue_t *task = nullptr;
    svalue_t *snapshot = nullptr;
    mapping_t *response = nullptr;
    std::string error;

    if (batch->item[i].type == T_MAPPING) {
      item_map = batch->item[i].u.map;
      task = find_string_in_mapping(item_map, "task");
      snapshot = find_string_in_mapping(item_map, "snapshot");
      auto *options_value = find_string_in_mapping(item_map, "options");
      if (options_value && options_value->type == T_MAPPING) {
        options = options_value->u.map;
      }
    }

    if (!item_map || !task || task->type != T_STRING || !snapshot || !options) {
      response = worker_failure_response("batch item must include task, snapshot, and options");
      rejected++;
    } else if (!is_json_safe_value(snapshot, 0, &error)) {
      response = worker_failure_response(error.c_str());
      rejected++;
    } else {
      response = worker_submit_response(task->u.string, snapshot, options);
      if (find_string_in_mapping(response, "success") && find_string_in_mapping(response, "success")->u.number) {
        accepted++;
      } else {
        rejected++;
      }
    }

    results->item[i].type = T_MAPPING;
    results->item[i].subtype = 0;
    results->item[i].u.map = response;
  }

  auto *response = allocate_mapping(4);
  add_mapping_pair(response, "success", rejected == 0 ? 1 : 0);
  add_mapping_pair(response, "accepted", accepted);
  add_mapping_pair(response, "rejected", rejected);
  add_mapping_array(response, "results", results);
  free_array(results);
  return response;
}

mapping_t *worker_poll_batch_response(array_t *task_ids) {
  auto *results = allocate_array(task_ids ? task_ids->size : 0);
  int ready = 0;
  int pending = 0;
  int failed = 0;

  for (int i = 0; task_ids && i < task_ids->size; i++) {
    uint64_t task_id = 0;
    mapping_t *result;

    if (task_ids->item[i].type == T_NUMBER) {
      task_id = static_cast<uint64_t>(task_ids->item[i].u.number);
    }
    result = worker_poll_response(task_id);
    auto *status = find_string_in_mapping(result, "status");
    if (status && status->type == T_STRING && std::strcmp(status->u.string, "succeeded") == 0) {
      ready++;
    } else if (status && status->type == T_STRING && std::strcmp(status->u.string, "pending") == 0) {
      pending++;
    } else {
      failed++;
    }
    results->item[i].type = T_MAPPING;
    results->item[i].subtype = 0;
    results->item[i].u.map = result;
  }

  auto *response = allocate_mapping(5);
  add_mapping_pair(response, "success", failed == 0 ? 1 : 0);
  add_mapping_pair(response, "ready", ready);
  add_mapping_pair(response, "pending", pending);
  add_mapping_pair(response, "failed", failed);
  add_mapping_array(response, "results", results);
  free_array(results);
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
  } else if (task_name == "snapshot_digest") {
    response = worker_snapshot_digest_response(snapshot, options->u.map);
  } else if (task_name == "actor_score") {
    response = worker_actor_score_response(snapshot, options->u.map);
  } else if (task_name == "combat_damage") {
    response = worker_combat_damage_response(snapshot, options->u.map);
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

  response = worker_submit_response(task->u.string, snapshot, options->u.map);
  pop_3_elems();
  push_refed_mapping(response);
}
#endif

#ifdef F_VM_WORKER_SUBMIT_BATCH
void f_vm_worker_submit_batch() {
  auto *batch = sp;
  if (batch->type != T_ARRAY) {
    pop_stack();
    push_refed_mapping(worker_failure_response("worker submit batch expects an array"));
    return;
  }
  auto *response = worker_submit_batch_response(batch->u.arr);
  pop_stack();
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

#ifdef F_VM_WORKER_POLL_BATCH
void f_vm_worker_poll_batch() {
  auto *task_ids = sp;
  if (task_ids->type != T_ARRAY) {
    pop_stack();
    push_refed_mapping(worker_failure_response("worker poll batch expects an array"));
    return;
  }
  auto *response = worker_poll_batch_response(task_ids->u.arr);
  pop_stack();
  push_refed_mapping(response);
}
#endif
