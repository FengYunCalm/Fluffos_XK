#include "vm/internal/owner_executor.h"

OwnerExecutor::OwnerExecutor(OwnerExecutorRuntime &runtime) : runtime_(runtime) {}

void OwnerExecutor::run() {
  runtime_.bind_context();
  while (true) {
    auto claimed_owner = runtime_.claim_next_owner();
    if (claimed_owner.empty()) {
      return;
    }
    // RAII: the owner claim is always released, even when task execution
    // throws. Without this, an unexpected exception would leave the owner
    // permanently claimed and the worker would exit mid-state.
    struct OwnerReleaseGuard {
      OwnerExecutorRuntime &runtime;
      const std::string &owner_id;
      ~OwnerReleaseGuard() { runtime.release_owner_after_task(owner_id); }
    } release_guard{runtime_, claimed_owner};

    try {
      runtime_.run_claimed_owner(claimed_owner);
    } catch (const std::bad_alloc &) {
      runtime_.record_owner_exception(claimed_owner, "bad_alloc");
    } catch (const std::exception &e) {
      runtime_.record_owner_exception(claimed_owner, e.what());
    } catch (...) {
      runtime_.record_owner_exception(claimed_owner, "unknown exception");
    }
  }
}
