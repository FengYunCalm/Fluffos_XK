#ifndef SRC_VM_WORKER_H_
#define SRC_VM_WORKER_H_

#include <cstdint>

struct VMWorkerBenchResult {
  int tasks{0};
  int worker_count{0};
  int max_parallel{0};
  int64_t elapsed_ms{0};
  uint64_t checksum{0};
};

struct VMWorkerStats {
  int worker_count{0};
  uint64_t submitted{0};
  uint64_t completed{0};
  int active{0};
};

void vm_worker_start(int requested_workers = 0);
void vm_worker_stop();
VMWorkerStats vm_worker_stats();
VMWorkerBenchResult vm_worker_benchmark(int tasks, int millis);

#endif /* SRC_VM_WORKER_H_ */
