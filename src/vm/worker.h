#ifndef SRC_VM_WORKER_H_
#define SRC_VM_WORKER_H_

#include <cstdint>
#include <string>

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

struct VMWorkerTaskResult {
  uint64_t task_id{0};
  VMWorkerTaskState state{VMWorkerTaskState::kUnknown};
  std::string type;
  VMWorkerBenchResult bench;
  VMWorkerSnapshotDigestResult snapshot_digest;
  VMWorkerActorScoreResult actor_score;
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
uint64_t vm_worker_submit_benchmark(int tasks, int millis);
uint64_t vm_worker_submit_snapshot_digest(std::string owner_key,
                                          std::string snapshot_text,
                                          int repeat);
uint64_t vm_worker_submit_actor_score(std::string owner_key,
                                      VMWorkerActorScoreInput input);
VMWorkerTaskResult vm_worker_poll_task(uint64_t task_id);

#endif /* SRC_VM_WORKER_H_ */
