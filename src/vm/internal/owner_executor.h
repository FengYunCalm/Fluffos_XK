#pragma once

// Included by owner.cc after owner runtime helpers are defined.

class OwnerExecutor {
 public:
  void run() {
    bind_context();
    while (true) {
      auto claimed_owner = claim_next_owner();
      if (claimed_owner.empty()) {
        return;
      }
      run_claimed_owner(claimed_owner);
      finish_active_owner_task(claimed_owner);
    }
  }

 private:
  VMContext owner_context_;

  void bind_context() {
    context_scope_.emplace(owner_context_);
    if (&vm_context() != &vm_main_context()) {
      owner_thread_context_bound.fetch_add(1, std::memory_order_relaxed);
    }
    if (!vm_context().object_store.main_thread_owned && vm_context().object_store.objects == nullptr) {
      owner_thread_object_store_isolated.fetch_add(1, std::memory_order_relaxed);
    }
    reset_machine(1);
    vm_context_sync_eval_stack(vm_context());
    vm_context_sync_control_stack(vm_context());
    vm_context_sync_value_stack(vm_context());
    vm_context_clear_apply_return(vm_context());
    vm_context_sync_apply_return(vm_context());
  }

  std::string claim_next_owner() {
    while (true) {
      std::unique_lock<std::mutex> lock(owner_runtime_mutex);
      owner_runtime_cv.wait(lock, [] { return owner_thread_stopping || !schedulable_owners.empty(); });
      if (owner_thread_stopping) {
        return "";
      }
      OwnerMailboxTask first_task;
      if (!pop_next_schedulable_task(&first_task, true)) {
        continue;
      }
      auto owner_id = first_task.owner_id;
      owner_mailboxes[owner_id].push_front(std::move(first_task));
      append_owner_executor_trace_locked(owner_id, "owner_claimed");
      return owner_id;
    }
  }

  void run_claimed_owner(const std::string &owner_id) {
    int budget_used = 0;
    while (budget_used < kOwnerExecutorTaskBudget) {
      OwnerMailboxTask task;
      {
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        if (!pop_next_executor_task_for_owner(owner_id, &task)) {
          break;
        }
      }
      run_task(task);
      budget_used++;
    }
    if (budget_used >= kOwnerExecutorTaskBudget) {
      std::lock_guard<std::mutex> lock(owner_runtime_mutex);
      auto it = owner_mailboxes.find(owner_id);
      if (it != owner_mailboxes.end() && owner_queue_has_thread_task(it->second)) {
        record_owner_executor_budget_yield_locked(owner_id);
      }
    }
  }

  void run_task(OwnerMailboxTask &task) {
    record_owner_mailbox_task_drained(task);
    {
      VMOwnerScope owner_scope(vm_context(), task.owner_id.c_str(), task.owner_epoch);
      if (vm_context().owner.current_owner_id == task.owner_id &&
          vm_context().owner.current_owner_epoch == task.owner_epoch) {
        owner_thread_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_eval_stack(vm_context());
      if (vm_context().eval_stack.thread_local_storage && vm_context().eval_stack.context_bound &&
          vm_context().eval_stack.owner_id == task.owner_id &&
          vm_context().eval_stack.owner_epoch == task.owner_epoch) {
        owner_thread_eval_stack_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_control_stack(vm_context());
      if (vm_context().control_stack.thread_local_storage && vm_context().control_stack.context_bound &&
          vm_context().control_stack.owner_id == task.owner_id &&
          vm_context().control_stack.owner_epoch == task.owner_epoch) {
        owner_thread_control_stack_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_value_stack(vm_context());
      if (vm_context().value_stack.thread_local_storage && vm_context().value_stack.context_bound &&
          vm_context().value_stack.owner_id == task.owner_id &&
          vm_context().value_stack.owner_epoch == task.owner_epoch) {
        owner_thread_value_stack_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      vm_context_sync_apply_return(vm_context());
      if (vm_context().apply_return.thread_local_storage && vm_context().apply_return.context_bound &&
          vm_context().apply_return.owner_id == task.owner_id &&
          vm_context().apply_return.owner_epoch == task.owner_epoch) {
        owner_thread_apply_return_owner_bound.fetch_add(1, std::memory_order_relaxed);
      }
      append_owner_task_trace_threadsafe(task, "thread_dispatched");
      owner_executor_runnable_task_dispatched.fetch_add(1, std::memory_order_relaxed);
      if (owner_task_executor_safe(task)) {
        owner_executor_safe_task_dispatched.fetch_add(1, std::memory_order_relaxed);
      }
      dispatch_task(task);
      total_drained.fetch_add(1, std::memory_order_relaxed);
      owner_thread_dispatched.fetch_add(1, std::memory_order_relaxed);
    }

    record_owner_context_cleanup(task);
    release_owner_task_target(&task);
  }

  void dispatch_task(const OwnerMailboxTask &task) {
    switch (owner_executor_task_descriptor(task).dispatch_kind) {
      case OwnerExecutorDispatchKind::ExecutorProbe:
        maybe_delay_owner_executor_probe();
        append_owner_task_trace_threadsafe(task, "executor_probe_completed");
        owner_executor_probe_executed.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::LpcProbe:
        run_owner_lpc_probe(task);
        break;
      case OwnerExecutorDispatchKind::LpcCanary:
        run_owner_lpc_canary(task);
        break;
      case OwnerExecutorDispatchKind::LpcTask:
        run_owner_lpc_task(task);
        break;
      case OwnerExecutorDispatchKind::OrdinaryLpc:
        run_owner_ordinary_lpc(task);
        break;
      case OwnerExecutorDispatchKind::RejectLpc:
        append_owner_task_trace_threadsafe(task, "thread_lpc_rejected");
        owner_thread_lpc_rejected.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::GuardOwnerState:
        append_owner_task_trace_threadsafe(task, "thread_owner_state_guarded");
        owner_thread_owner_state_guarded.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::OwnerMessage: {
        append_owner_task_trace_threadsafe(task, "thread_message_dispatched");
        owner_thread_message_dispatched.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        complete_owner_message_task_locked(task);
        break;
      }
      case OwnerExecutorDispatchKind::CommandConsume:
        append_owner_task_trace_threadsafe(task, "thread_command_consume_entry_ready");
        owner_executor_command_consume_entry_executed.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::CommandFrameRestore:
        run_owner_command_frame_restore(task);
        break;
      case OwnerExecutorDispatchKind::GatewayCommand:
        append_owner_task_trace_threadsafe(task, "thread_gateway_command_rejected");
        owner_thread_gateway_command_rejected.fetch_add(1, std::memory_order_relaxed);
        break;
      case OwnerExecutorDispatchKind::ComputeResult: {
        append_owner_task_trace_threadsafe(task, "thread_compute_result_completed");
        owner_thread_compute_result_completed.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(owner_runtime_mutex);
        complete_owner_compute_result_task_locked(task);
        break;
      }
      case OwnerExecutorDispatchKind::Generic:
        break;
    }
  }

  std::optional<VMContextThreadScope> context_scope_;
};
