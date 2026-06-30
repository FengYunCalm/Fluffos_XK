#include "vm/internal/owner_service_registry.h"

#include "vm/internal/owner_task_manifest.h"

namespace {
constexpr std::array<OwnerServiceShardDescriptor, 18> kOwnerServiceShardDescriptors = {{
    {"readonly", "owner_task_readonly", "snapshot_only", "single_readonly_service", "diagnostic",
     "frozen_result_only", 0},
    {"player", "owner_task_player", "owner_scheduler", "owner_id", "gateway_command",
     "same_owner_or_commit_proposal", 1},
    {"room", "owner_task_room", "owner_scheduler", "room_path", "service_tick",
     "same_owner_or_commit_proposal", 1},
    {"session", "owner_task_session", "owner_scheduler", "session_id", "gateway_command",
     "session_fifo", 1},
    {"item", "owner_task_item", "owner_scheduler", "object_id", "service_tick",
     "same_owner_or_commit_proposal", 1},
    {"economy", "owner_task_economy", "service_shard", "account_key", "service_tick",
     "commit_proposal", 1},
    {"combat", "owner_task_combat", "service_shard", "combat_instance", "heartbeat",
     "commit_proposal", 1},
    {"mail", "owner_task_mail", "service_shard", "mailbox_key", "service_tick",
     "commit_proposal", 1},
    {"reward", "owner_task_reward", "service_shard", "reward_key", "callout",
     "commit_proposal", 1},
    {"world", "owner_task_world", "owner_scheduler", "world_path", "service_tick",
     "same_owner_or_commit_proposal", 1},
    {"persistence", "owner_task_persistence", "service_shard", "snapshot_key", "service_tick",
     "snapshot_pipeline", 1},
    {"team", "owner_task_team", "service_owner", "team_id", "service_tick",
     "commit_proposal", 0},
    {"guild", "owner_task_guild", "service_shard", "guild_id", "service_tick",
     "commit_proposal", 1},
    {"sect", "owner_task_sect", "service_owner", "sect_id", "service_tick",
     "commit_proposal", 0},
    {"quest", "owner_task_quest", "service_shard", "quest_id", "service_tick",
     "commit_proposal", 1},
    {"rank", "owner_task_rank", "service_shard", "rank_board", "service_tick",
     "snapshot_then_commit", 1},
    {"crafting", "owner_task_crafting", "owner_scheduler", "crafting_session", "callout",
     "same_owner_or_commit_proposal", 0},
    {"life_skill", "owner_task_life_skill", "owner_scheduler", "skill_owner", "callout",
     "same_owner_or_commit_proposal", 0},
}};

constexpr std::array<OwnerTickGroupDescriptor, 6> kOwnerTickGroupDescriptors = {{
    {"gateway_command", 100, 32, 4096, "observe_then_reject_new_tasks"},
    {"heartbeat", 80, 64, 4096, "observe_then_reject_new_tasks"},
    {"callout", 70, 64, 4096, "observe_then_reject_new_tasks"},
    {"socket_async", 60, 64, 4096, "observe_then_reject_new_tasks"},
    {"service_tick", 50, 64, 4096, "observe_then_reject_new_tasks"},
    {"diagnostic", 10, 16, 1024, "observe_then_reject_new_tasks"},
}};

std::string join_domains() {
  std::string result;
  for (const auto &descriptor : kOwnerServiceShardDescriptors) {
    if (!result.empty()) {
      result += ",";
    }
    result += descriptor.domain;
  }
  return result;
}

std::string join_tick_groups() {
  std::string result;
  for (const auto &descriptor : kOwnerTickGroupDescriptors) {
    if (!result.empty()) {
      result += ",";
    }
    result += descriptor.name;
  }
  return result;
}
}  // namespace

const std::array<OwnerServiceShardDescriptor, 18> &owner_service_shard_descriptors() {
  return kOwnerServiceShardDescriptors;
}

const std::array<OwnerTickGroupDescriptor, 6> &owner_tick_group_descriptors() {
  return kOwnerTickGroupDescriptors;
}

const OwnerTickGroupDescriptor &owner_tick_group_for_executor_task(const char *task_type) {
  std::string task_type_value = task_type ? task_type : "";
  auto tick_group = "diagnostic";
  if (task_type_value == "gateway_command" || task_type_value == "gateway_command_execute") {
    tick_group = "gateway_command";
  } else if (task_type_value == "heartbeat") {
    tick_group = "heartbeat";
  } else if (task_type_value == "call_out") {
    tick_group = "callout";
  } else if (task_type_value == "socket_callback" || task_type_value == "async_callback" ||
             task_type_value == "dns_callback" || task_type_value == "ed_callback") {
    tick_group = "socket_async";
  } else if (task_type_value == "lpc_task" || task_type_value == "ordinary_lpc" ||
             task_type_value == "owner_message" || task_type_value == "compute_result") {
    tick_group = "service_tick";
  }

  for (const auto &descriptor : kOwnerTickGroupDescriptors) {
    if (std::string(descriptor.name) == tick_group) {
      return descriptor;
    }
  }
  return kOwnerTickGroupDescriptors.back();
}

bool owner_service_registry_matches_lpc_domains() {
  const auto &lpc_descriptors = owner_lpc_task_descriptors();
  if (lpc_descriptors.size() != kOwnerServiceShardDescriptors.size()) {
    return false;
  }
  for (const auto &lpc_descriptor : lpc_descriptors) {
    bool found = false;
    for (const auto &service_descriptor : kOwnerServiceShardDescriptors) {
      if (std::string(lpc_descriptor.method) == service_descriptor.task_method) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

std::string owner_service_shard_domain_list() { return join_domains(); }

std::string owner_tick_group_name_list() { return join_tick_groups(); }

long owner_service_hot_path_service_owner_count() {
  long count = 0;
  for (const auto &descriptor : kOwnerServiceShardDescriptors) {
    if (descriptor.hot_path && std::string(descriptor.owner_policy) == "service_owner") {
      count++;
    }
  }
  return count;
}

long owner_service_hot_path_service_shard_count() {
  long count = 0;
  for (const auto &descriptor : kOwnerServiceShardDescriptors) {
    if (descriptor.hot_path && std::string(descriptor.owner_policy) == "service_shard") {
      count++;
    }
  }
  return count;
}
