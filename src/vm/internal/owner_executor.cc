#include "vm/internal/owner_executor.h"

OwnerExecutor::OwnerExecutor(OwnerExecutorRuntime &runtime) : runtime_(runtime) {}

void OwnerExecutor::run() {
  runtime_.bind_context();
  while (true) {
    auto claimed_owner = runtime_.claim_next_owner();
    if (claimed_owner.empty()) {
      return;
    }
    runtime_.run_claimed_owner(claimed_owner);
    runtime_.release_owner_after_task(claimed_owner);
  }
}
