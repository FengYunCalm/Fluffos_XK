#pragma once

#include <string>

class OwnerExecutorRuntime {
 public:
  virtual ~OwnerExecutorRuntime() = default;

  virtual void bind_context() = 0;
  virtual std::string claim_next_owner() = 0;
  virtual void run_claimed_owner(const std::string &owner_id) = 0;
  virtual void release_owner_after_task(const std::string &owner_id) = 0;
  // Called when an exception escapes run_claimed_owner; the runtime records
  // the classified failure so the owner claim is never silently leaked.
  virtual void record_owner_exception(const std::string &owner_id, const char *what) = 0;
};

class OwnerExecutor {
 public:
  explicit OwnerExecutor(OwnerExecutorRuntime &runtime);

  void run();

 private:
  OwnerExecutorRuntime &runtime_;
};
