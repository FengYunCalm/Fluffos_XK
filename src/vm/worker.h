#ifndef SRC_VM_WORKER_H_
#define SRC_VM_WORKER_H_

#include <cstdint>
#include <string>
#include <vector>

enum class VMWorkerTaskState {
  kUnknown,
  kPending,
  kSucceeded,
  kFailed,
};

struct VMWorkerBenchResult {
  int tasks{0};
  int worker_count{0};
  int max_parallel{0};
  int64_t elapsed_ms{0};
  uint64_t checksum{0};
};

struct VMWorkerActorBenchResult {
  int owners{0};
  int tasks_per_owner{0};
  int total_tasks{0};
  int worker_count{0};
  int max_parallel{0};
  int max_owner_parallel{0};
  int64_t elapsed_ms{0};
  uint64_t checksum{0};
};

struct VMWorkerSnapshotDigestResult {
  std::string owner_key;
  int worker_count{0};
  int64_t elapsed_ms{0};
  uint64_t input_bytes{0};
  int repeat{0};
  uint64_t checksum{0};
};

struct VMWorkerActorScoreInput {
  int hp{0};
  int max_hp{0};
  int mp{0};
  int max_mp{0};
  int ep{0};
  int max_ep{0};
};

struct VMWorkerActorScoreResult {
  std::string owner_key;
  int worker_count{0};
  int64_t elapsed_ms{0};
  int hp_pct_bp{0};
  int mp_pct_bp{0};
  int ep_pct_bp{0};
  int survival_score{0};
  int resource_score{0};
  int total_score{0};
  std::string state;
};

struct VMWorkerCombatDamageInput {
  int snapshot_hash{0};
  int attack{0};
  int defense{0};
  int armor_break{0};
  int critical{0};
  int critical_resist{0};
  int armor_break_defense_factor_bp{9000};
  int armor_break_flat{5000};
  int armor_break_cap_bp{8000};
  int reduction_attack_factor_bp{16000};
  int reduction_flat{8000};
  int reduction_min_bp{500};
  int reduction_max_bp{7500};
  int damage_base{1};
  int damage_skill_factor_bp{10000};
  int damage_random_min_bp{9500};
  int damage_random_max_bp{10500};
  int damage_min{1};
  int variance_roll_bp{0};
  int critical_base_bp{500};
  int critical_swing_bp{3500};
  int critical_flat{6000};
  int critical_min{0};
  int critical_max{50};
  int critical_roll{100};
  int critical_damage_factor_bp{15000};
};

struct VMWorkerCombatDamageResult {
  std::string owner_key;
  int worker_count{0};
  int64_t elapsed_ms{0};
  int damage{0};
  int armor_break_bp{0};
  int reduction_bp{0};
  int critical_rate{0};
  int critical_hit{0};
  uint64_t snapshot_hash{0};
  uint64_t input_hash{0};
};

struct VMWorkerStats {
  int worker_count{0};
  uint64_t submitted{0};
  uint64_t completed{0};
  uint64_t async_pending{0};
  uint64_t async_ready{0};
  uint64_t async_failed{0};
  uint64_t queue_depth{0};
  uint64_t queue_high_watermark{0};
  uint64_t owner_queue_depth{0};
  int active_owners{0};
  int active{0};
};

struct VMWorkerTaskEnvelope {
  uint64_t task_id{0};
  std::string task_type;
  std::string owner_key;
  uint64_t submitted_at_ms{0};
  uint64_t deadline_at_ms{0};
  uint64_t completed_at_ms{0};
  uint64_t expires_at_ms{0};
  uint64_t owner_future_id{0};
  uint64_t input_hash{0};
  int timeout_ms{0};
  int ttl_ms{0};
};

struct VMWorkerTaskResult {
  uint64_t task_id{0};
  VMWorkerTaskState state{VMWorkerTaskState::kUnknown};
  std::string type;
  VMWorkerTaskEnvelope envelope;
  VMWorkerBenchResult bench;
  VMWorkerSnapshotDigestResult snapshot_digest;
  VMWorkerActorScoreResult actor_score;
  VMWorkerCombatDamageResult combat_damage;
  std::string error;
};

void vm_worker_start(int requested_workers = 0);
void vm_worker_stop();
VMWorkerStats vm_worker_stats();
VMWorkerBenchResult vm_worker_benchmark(int tasks, int millis);
VMWorkerActorBenchResult vm_worker_actor_benchmark(int owners, int tasks_per_owner, int millis);
VMWorkerSnapshotDigestResult vm_worker_snapshot_digest(std::string owner_key,
                                                       std::string snapshot_text,
                                                       int repeat);
VMWorkerActorScoreResult vm_worker_actor_score(std::string owner_key,
                                                VMWorkerActorScoreInput input);
VMWorkerCombatDamageResult vm_worker_combat_damage(std::string owner_key,
                                                   VMWorkerCombatDamageInput input);
uint64_t vm_worker_submit_benchmark(int tasks, int millis);
uint64_t vm_worker_submit_benchmark_v2(int tasks, int millis, int timeout_ms, int ttl_ms);
uint64_t vm_worker_submit_snapshot_digest(std::string owner_key,
                                           std::string snapshot_text,
                                           int repeat);
uint64_t vm_worker_submit_snapshot_digest_v2(std::string owner_key,
                                             std::string snapshot_text,
                                             int repeat,
                                             int timeout_ms,
                                             int ttl_ms);
uint64_t vm_worker_submit_actor_score(std::string owner_key,
                                       VMWorkerActorScoreInput input);
uint64_t vm_worker_submit_actor_score_v2(std::string owner_key,
                                          VMWorkerActorScoreInput input,
                                          int timeout_ms,
                                          int ttl_ms);
uint64_t vm_worker_submit_combat_damage_v2(std::string owner_key,
                                           VMWorkerCombatDamageInput input,
                                           int timeout_ms,
                                           int ttl_ms);
VMWorkerTaskResult vm_worker_poll_task(uint64_t task_id);
std::vector<VMWorkerTaskResult> vm_worker_poll_tasks(const std::vector<uint64_t> &task_ids);
uint64_t vm_worker_owner_future_id(uint64_t task_id);

#endif /* SRC_VM_WORKER_H_ */
