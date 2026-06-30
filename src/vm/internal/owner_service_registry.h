#pragma once

#include <array>
#include <string>

inline constexpr const char *kOwnerServiceShardRegistrySchemaV1 = "owner_service_shard_registry_v1";
inline constexpr const char *kOwnerTickGroupSchedulerSchemaV1 = "owner_tick_group_scheduler_v1";
inline constexpr const char *kOwnerSchedulerTuningConfigSchemaV1 = "owner_scheduler_tuning_v1";

struct OwnerServiceShardDescriptor {
  const char *domain;
  const char *task_method;
  const char *owner_policy;
  const char *shard_policy;
  const char *tick_group;
  const char *mutable_write_boundary;
  int hot_path;
};

struct OwnerTickGroupDescriptor {
  const char *name;
  int priority;
  int budget;
  int max_queue_depth;
  const char *backpressure_policy;
};

const std::array<OwnerServiceShardDescriptor, 18> &owner_service_shard_descriptors();
const std::array<OwnerTickGroupDescriptor, 6> &owner_tick_group_descriptors();

const OwnerTickGroupDescriptor &owner_tick_group_for_executor_task(const char *task_type);
bool owner_service_registry_matches_lpc_domains();
std::string owner_service_shard_domain_list();
std::string owner_tick_group_name_list();
long owner_service_hot_path_service_owner_count();
long owner_service_hot_path_service_shard_count();
