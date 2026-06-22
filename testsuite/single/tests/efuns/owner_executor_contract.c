void assert_contract_entry(mapping contract, string key, string executor_mode,
                           string route, int executor_safe, int main_required,
                           int rejected) {
    mapping entry = contract[key];

    ASSERT(mapp(entry));
    ASSERT_EQ(executor_mode, entry["executor_mode"]);
    ASSERT_EQ(route, entry["route"]);
    ASSERT_EQ(executor_safe, entry["executor_safe"]);
    ASSERT_EQ(main_required, entry["main_required"]);
    ASSERT_EQ(rejected, entry["rejected"]);
    ASSERT(stringp(entry["reason"]));
}

void assert_owner_message_route_contract(mapping contract, string key,
                                         int requires_mailbox,
                                         int requires_main_queue) {
    mapping entry = contract[key];

    ASSERT(mapp(entry));
    ASSERT_EQ(requires_mailbox, entry["requires_owner_mailbox"]);
    ASSERT_EQ(requires_main_queue, entry["requires_owner_main_queue"]);
}

void assert_dispatch_entry(mapping dispatch_contract, string task_type,
                           string contract_key, string dispatch_kind,
                           string executor_mode, int executor_runnable,
                           int executor_safe, int rejected) {
    mapping entry = dispatch_contract[task_type];

    ASSERT(mapp(entry));
    ASSERT_EQ(contract_key, entry["contract_key"]);
    ASSERT_EQ(dispatch_kind, entry["dispatch_kind"]);
    ASSERT_EQ(executor_mode, entry["executor_mode"]);
    ASSERT_EQ("owner_executor", entry["route"]);
    ASSERT_EQ(executor_runnable, entry["executor_runnable"]);
    ASSERT_EQ(executor_safe, entry["executor_safe"]);
    ASSERT_EQ(0, entry["main_required"]);
    ASSERT_EQ(rejected, entry["rejected"]);
    ASSERT_EQ(1, entry["requires_owner_mailbox"]);
    ASSERT_EQ(0, entry["requires_owner_main_queue"]);
}

void assert_vm_context_contract(mapping contract) {
    mixed *gates = contract["ordinary_lpc_readiness_gates"];
    mapping gate_by_name = ([]);
    int i;

    ASSERT(mapp(contract));
    ASSERT_EQ(1, contract["contract_version"]);
    ASSERT_EQ("thread_local_vm_context", contract["context_model"]);
    ASSERT_EQ("vm_context_execution_snapshot", contract["execution_state_model"]);
    ASSERT_EQ("vm_context_owner_scope", contract["owner_state_model"]);
    ASSERT_EQ("vm_context_error_snapshot", contract["error_state_model"]);
    ASSERT_EQ("main_thread_owned_snapshot", contract["object_store_model"]);
    ASSERT_EQ("sync_rejected", contract["object_store_off_main_policy"]);
    ASSERT_EQ(0, contract["ordinary_lpc_ready"]);
    ASSERT_EQ("object_refs_and_object_store_not_owner_local", contract["ordinary_lpc_blocker"]);
    ASSERT_EQ(1, contract["controlled_lpc_ready"]);
    ASSERT_EQ("descriptor_manifest_only", contract["controlled_lpc_policy"]);
    ASSERT_EQ("thread_local_owner_execution_stack", contract["eval_stack_model"]);
    ASSERT_EQ(1, contract["eval_stack_thread_local"]);
    ASSERT_EQ(1, contract["eval_stack_owner_bound_on_executor"]);
    ASSERT_EQ(1, contract["eval_stack_cleared_after_task"]);
    ASSERT_EQ(1, contract["eval_stack_owner_local"]);
    ASSERT_EQ("thread_local_owner_control_stack", contract["control_stack_model"]);
    ASSERT_EQ(1, contract["control_stack_thread_local"]);
    ASSERT_EQ(1, contract["control_stack_owner_bound_on_executor"]);
    ASSERT_EQ(1, contract["control_stack_cleared_after_task"]);
    ASSERT_EQ(1, contract["control_stack_owner_local"]);
    ASSERT_EQ("thread_local_owner_value_stack", contract["value_stack_model"]);
    ASSERT_EQ(1, contract["value_stack_thread_local"]);
    ASSERT_EQ(1, contract["value_stack_lvalue_refs_cleared_after_task"]);
    ASSERT_EQ(1, contract["value_stack_owner_bound_on_executor"]);
    ASSERT_EQ(1, contract["value_stack_cleared_after_task"]);
    ASSERT_EQ(1, contract["value_stack_owner_local"]);
    ASSERT_EQ("thread_local_owner_apply_return", contract["apply_return_model"]);
    ASSERT_EQ(1, contract["apply_return_thread_local"]);
    ASSERT_EQ(1, contract["apply_return_owner_bound_on_executor"]);
    ASSERT_EQ(1, contract["apply_return_cleared_after_task"]);
    ASSERT_EQ(1, contract["apply_return_owner_local"]);
    ASSERT_EQ(0, contract["object_refs_owner_local"]);
    ASSERT_EQ(1, contract["error_state_contextualized"]);
    ASSERT_EQ(1, contract["execution_state_contextualized"]);
    ASSERT_EQ(1, contract["owner_scope_contextualized"]);
    ASSERT_EQ(1, contract["object_store_main_thread_only"]);
    ASSERT(intp(contract["object_store_sync_rejections"]));
    ASSERT_EQ(0, contract["off_main_object_store_sync_allowed"]);
    ASSERT_EQ("all_gates_required_before_open",
              contract["ordinary_lpc_readiness_gate_model"]);
    ASSERT_EQ("object_refs_owner_local", contract["ordinary_lpc_next_blocker"]);
    ASSERT_EQ(11, contract["ordinary_lpc_readiness_gate_count"]);
    ASSERT_EQ(9, contract["ordinary_lpc_satisfied_gate_count"]);
    ASSERT_EQ(2, contract["ordinary_lpc_blocked_gate_count"]);
    ASSERT(arrayp(gates));
    ASSERT_EQ(11, sizeof(gates));
    for (i = 0; i < sizeof(gates); i++) {
        mapping gate = gates[i];

        ASSERT(mapp(gate));
        ASSERT(stringp(gate["gate"]));
        ASSERT(stringp(gate["model"]));
        ASSERT(intp(gate["satisfied"]));
        ASSERT(stringp(gate["blocker"]));
        ASSERT(stringp(gate["next_action"]));
        gate_by_name[gate["gate"]] = gate;
    }
    ASSERT_EQ(1, gate_by_name["thread_local_vm_context"]["satisfied"]);
    ASSERT_EQ(1, gate_by_name["execution_state_contextualized"]["satisfied"]);
    ASSERT_EQ(1, gate_by_name["error_state_contextualized"]["satisfied"]);
    ASSERT_EQ(1, gate_by_name["eval_stack_owner_local"]["satisfied"]);
    ASSERT_EQ("thread_local_owner_execution_stack",
              gate_by_name["eval_stack_owner_local"]["model"]);
    ASSERT_EQ("",
              gate_by_name["eval_stack_owner_local"]["blocker"]);
    ASSERT_EQ(1, gate_by_name["control_stack_owner_local"]["satisfied"]);
    ASSERT_EQ("thread_local_owner_control_stack",
              gate_by_name["control_stack_owner_local"]["model"]);
    ASSERT_EQ("",
              gate_by_name["control_stack_owner_local"]["blocker"]);
    ASSERT_EQ(1, gate_by_name["value_stack_owner_local"]["satisfied"]);
    ASSERT_EQ("thread_local_owner_value_stack",
              gate_by_name["value_stack_owner_local"]["model"]);
    ASSERT_EQ("",
              gate_by_name["value_stack_owner_local"]["blocker"]);
    ASSERT_EQ(1, gate_by_name["apply_return_owner_local"]["satisfied"]);
    ASSERT_EQ("thread_local_owner_apply_return",
              gate_by_name["apply_return_owner_local"]["model"]);
    ASSERT_EQ("",
              gate_by_name["apply_return_owner_local"]["blocker"]);
    ASSERT_EQ(0, gate_by_name["object_refs_owner_local"]["satisfied"]);
    ASSERT_EQ("bare_object_pointer_cross_owner_refs",
              gate_by_name["object_refs_owner_local"]["blocker"]);
    ASSERT_EQ(0, gate_by_name["object_store_owner_local_complete"]["satisfied"]);
    ASSERT_EQ("global_index_bridge_active",
              gate_by_name["object_store_owner_local_complete"]["blocker"]);
}

void assert_frozen_payload_contract(mapping contract) {
    mixed *allowed_types = contract["allowed_types"];
    mixed *rejected_types = contract["rejected_types"];
    mixed *paths = contract["paths"];
    mapping path_by_name = ([]);
    int i;

    ASSERT(mapp(contract));
    ASSERT_EQ(1, contract["contract_version"]);
    ASSERT_EQ("vm_frozen_value_safe", contract["validator"]);
    ASSERT_EQ(1, contract["deep_copy"]);
    ASSERT_EQ(8, contract["max_depth"]);
    ASSERT_EQ(1, contract["mapping_keys_must_be_strings"]);
    ASSERT_EQ(1, contract["top_level_owner_payload_must_be_mapping"]);
    ASSERT_EQ(0, contract["object_allowed"]);
    ASSERT_EQ(0, contract["function_allowed"]);
    ASSERT_EQ(0, contract["buffer_allowed"]);
    ASSERT_EQ(0, contract["class_allowed"]);
    ASSERT(arrayp(allowed_types));
    ASSERT_EQ(5, sizeof(allowed_types));
    ASSERT(arrayp(rejected_types));
    ASSERT_EQ(4, sizeof(rejected_types));
    ASSERT(member_array("object", rejected_types) >= 0);
    ASSERT(member_array("function", rejected_types) >= 0);
    ASSERT(member_array("buffer", rejected_types) >= 0);
    ASSERT(member_array("class", rejected_types) >= 0);
    ASSERT(arrayp(paths));
    ASSERT_EQ(4, sizeof(paths));
    for (i = 0; i < sizeof(paths); i++) {
        mapping entry = paths[i];

        ASSERT(mapp(entry));
        ASSERT(stringp(entry["path"]));
        ASSERT(stringp(entry["input_policy"]));
        ASSERT(stringp(entry["result_policy"]));
        ASSERT_EQ(1, entry["uses_shared_validator"]);
        path_by_name[entry["path"]] = entry;
    }
    ASSERT_EQ(1, path_by_name["owner_send"]["top_level_mapping_required"]);
    ASSERT_EQ(0, path_by_name["owner_send"]["frozen_result_required"]);
    ASSERT_EQ("frozen_result_required",
              path_by_name["owner_call_async"]["result_policy"]);
    ASSERT_EQ(1, path_by_name["owner_call_async"]["frozen_result_required"]);
    ASSERT_EQ("snapshot_only",
              path_by_name["owner_publish_snapshot"]["result_policy"]);
    ASSERT_EQ(0, path_by_name["worker_snapshot"]["top_level_mapping_required"]);
    ASSERT_EQ("owner_future_frozen_result_required",
              path_by_name["worker_snapshot"]["result_policy"]);
}

void assert_gateway_contract_entry(mapping contract, string task_key,
                                   string route, int requires_main_queue,
                                   string owner_scope_model,
                                   string stale_policy) {
    mapping entry = contract[task_key];

    ASSERT(mapp(entry));
    ASSERT_EQ("gateway", entry["task_type"]);
    ASSERT_EQ("main_required", entry["executor_mode"]);
    ASSERT_EQ(route, entry["route"]);
    ASSERT_EQ(1, entry["main_required"]);
    ASSERT_EQ(0, entry["executor_safe"]);
    ASSERT_EQ(requires_main_queue, entry["requires_owner_main_queue"]);
    ASSERT_EQ(1, entry["requires_owner_scope"]);
    ASSERT_EQ(1, entry["requires_current_interactive"]);
    ASSERT_EQ(1, entry["requires_command_giver"]);
    ASSERT_EQ(0, entry["ordinary_lpc_ready_required"]);
    ASSERT_EQ(1, entry["command_serial_per_owner"]);
    ASSERT(stringp(entry["payload_key"]));
    ASSERT(stringp(entry["input_payload_policy"]));
    ASSERT(stringp(entry["command_consume_model"]));
    ASSERT(entry["command_consume_snapshot_ready"] == 0 ||
           entry["command_consume_snapshot_ready"] == 1);
    ASSERT(entry["command_consume_executor_ready"] == 0 ||
           entry["command_consume_executor_ready"] == 1);
    ASSERT(stringp(entry["command_consume_blocker"]));
    ASSERT(stringp(entry["execution_frame_model"]));
    ASSERT(stringp(entry["execution_frame_policy"]));
    ASSERT(stringp(entry["execution_frame_restore_policy"]));
    ASSERT(entry["execution_frame_restore_ready"] == 0 ||
           entry["execution_frame_restore_ready"] == 1);
    ASSERT(stringp(entry["execution_frame_restore_blocker"]));
    ASSERT(entry["execution_frame_executor_ready"] == 0 ||
           entry["execution_frame_executor_ready"] == 1);
    ASSERT(intp(entry["requires_target_handle"]));
    ASSERT(intp(entry["requires_frozen_payload"]));
    ASSERT_EQ(owner_scope_model, entry["owner_scope_model"]);
    ASSERT_EQ(stale_policy, entry["stale_policy"]);
}

void assert_gateway_owner_task_contract(mapping contract) {
    mixed *tasks = contract["tasks"];
    mixed *command_executor_gates = contract["command_executor_readiness_gates"];
    mapping task_by_key = ([]);
    mapping command_executor_gate_by_name = ([]);
    int i;

    ASSERT(mapp(contract));
    ASSERT_EQ(1, contract["contract_version"]);
    ASSERT_EQ("owner_main_queue_bridge", contract["input_model"]);
    ASSERT_EQ("main_required_before_owner_executor",
              contract["executor_migration_state"]);
    ASSERT_EQ("gateway_command_buffer_metadata_v1",
              contract["command_payload_model"]);
    ASSERT_EQ("interactive_text_buffer", contract["command_input_source"]);
    ASSERT_EQ("owner_private_redacted_from_trace",
              contract["command_text_snapshot_policy"]);
    ASSERT_EQ(1, contract["command_text_snapshot_ready"]);
    ASSERT_EQ("ordinary_lpc_not_ready",
              contract["command_executor_blocker"]);
    ASSERT_EQ("owner_owned_snapshot_main_thread_consume",
              contract["command_consume_model"]);
    ASSERT_EQ(1, contract["command_consume_snapshot_ready"]);
    ASSERT_EQ(1, contract["command_consume_executor_ready"]);
    ASSERT_EQ("", contract["command_consume_blocker"]);
    ASSERT_EQ("no_raw_command_text_in_trace",
              contract["raw_input_trace_policy"]);
    ASSERT_EQ("gateway_command_execution_frame_v1",
              contract["command_execution_frame_model"]);
    ASSERT_EQ("owner_scope_current_interactive_command_giver",
              contract["command_execution_frame_policy"]);
    ASSERT_EQ("owner_executor_vmcontext_restore",
              contract["command_execution_frame_restore_policy"]);
    ASSERT_EQ(1, contract["command_execution_frame_restore_ready"]);
    ASSERT_EQ("", contract["command_execution_frame_restore_blocker"]);
    ASSERT_EQ(1, contract["command_execution_frame_executor_ready"]);
    ASSERT_EQ("owner_epoch_target_handle_guard", contract["command_stale_guard"]);
    ASSERT_EQ("main_stale", contract["command_stale_trace_state"]);
    ASSERT_EQ("owner_epoch_mismatch", contract["command_stale_target_status"]);
    ASSERT_EQ("all_gates_required_before_owner_executor",
              contract["command_executor_readiness_gate_model"]);
    ASSERT_EQ("ordinary_lpc_ready", contract["command_executor_next_gate"]);
    ASSERT_EQ("object_refs_owner_local",
              contract["command_executor_next_blocker"]);
    ASSERT_EQ(5, contract["command_executor_readiness_gate_count"]);
    ASSERT_EQ(5, contract["command_executor_satisfied_gate_count"]);
    ASSERT_EQ(0, contract["command_executor_blocked_gate_count"]);
    ASSERT(arrayp(command_executor_gates));
    ASSERT_EQ(5, sizeof(command_executor_gates));
    for (i = 0; i < sizeof(command_executor_gates); i++) {
        mapping gate = command_executor_gates[i];

        ASSERT(mapp(gate));
        ASSERT(stringp(gate["gate"]));
        ASSERT(stringp(gate["model"]));
        ASSERT(intp(gate["satisfied"]));
        ASSERT(stringp(gate["blocker"]));
        ASSERT(stringp(gate["next_action"]));
        command_executor_gate_by_name[gate["gate"]] = gate;
    }
    ASSERT_EQ(1, command_executor_gate_by_name["owner_epoch_target_handle_guard"]["satisfied"]);
    ASSERT_EQ(1, command_executor_gate_by_name["owner_owned_command_snapshot"]["satisfied"]);
    ASSERT_EQ("", command_executor_gate_by_name["owner_owned_command_snapshot"]["blocker"]);
    ASSERT_EQ(1, command_executor_gate_by_name["owner_owned_command_consume"]["satisfied"]);
    ASSERT_EQ("", command_executor_gate_by_name["owner_owned_command_consume"]["blocker"]);
    ASSERT_EQ(1, command_executor_gate_by_name["owner_executor_command_consume_entry"]["satisfied"]);
    ASSERT_EQ("",
              command_executor_gate_by_name["owner_executor_command_consume_entry"]["blocker"]);
    ASSERT_EQ(1, command_executor_gate_by_name["owner_executor_frame_restore"]["satisfied"]);
    ASSERT_EQ("", command_executor_gate_by_name["owner_executor_frame_restore"]["blocker"]);
    ASSERT_EQ(0, contract["ordinary_lpc_ready_required"]);
    ASSERT_EQ(1, contract["main_required"]);
    ASSERT_EQ("object_refs_owner_local",
              contract["next_blocker"]);
    ASSERT_EQ("ordinary_lpc_ready/object_refs_owner_local",
              contract["next_blocker_chain"]);
    ASSERT(arrayp(tasks));
    ASSERT_EQ(4, sizeof(tasks));
    for (i = 0; i < sizeof(tasks); i++) {
        mapping task = tasks[i];

        ASSERT(mapp(task));
        ASSERT(stringp(task["task_key"]));
        task_by_key[task["task_key"]] = task;
    }
    assert_gateway_contract_entry(task_by_key, "gateway_receive",
                                  "owner_main_queue", 1,
                                  "owner_scope_and_current_interactive",
                                  "owner_epoch_target_guard");
    assert_gateway_contract_entry(task_by_key, "process_user_command",
                                  "owner_main_queue", 1,
                                  "interactive_owner_scope_frame",
                                  "owner_epoch_target_guard");
    ASSERT_EQ("gateway_command_input",
              task_by_key["process_user_command"]["payload_key"]);
    ASSERT_EQ("buffer_metadata_no_raw_command_text",
              task_by_key["process_user_command"]["input_payload_policy"]);
    ASSERT_EQ("owner_owned_snapshot_main_thread_consume",
              task_by_key["process_user_command"]["command_consume_model"]);
    ASSERT_EQ(1, task_by_key["process_user_command"]["command_consume_snapshot_ready"]);
    ASSERT_EQ(1, task_by_key["process_user_command"]["command_consume_executor_ready"]);
    ASSERT_EQ("", task_by_key["process_user_command"]["command_consume_blocker"]);
    ASSERT_EQ("gateway_command_execution_frame_v1",
              task_by_key["process_user_command"]["execution_frame_model"]);
    ASSERT_EQ("owner_scope_current_interactive_command_giver",
              task_by_key["process_user_command"]["execution_frame_policy"]);
    ASSERT_EQ("owner_executor_vmcontext_restore",
              task_by_key["process_user_command"]["execution_frame_restore_policy"]);
    ASSERT_EQ(1, task_by_key["process_user_command"]["execution_frame_restore_ready"]);
    ASSERT_EQ("", task_by_key["process_user_command"]["execution_frame_restore_blocker"]);
    ASSERT_EQ(1, task_by_key["process_user_command"]["execution_frame_executor_ready"]);
    ASSERT_EQ(1, task_by_key["process_user_command"]["requires_target_handle"]);
    ASSERT_EQ(1, task_by_key["process_user_command"]["requires_frozen_payload"]);
    assert_gateway_contract_entry(task_by_key, "gateway_logon",
                                  "direct_main_owner_scope", 0,
                                  "owner_scope_and_current_interactive",
                                  "session_owner_resolve_after_exec");
    assert_gateway_contract_entry(task_by_key, "gateway_disconnected",
                                  "direct_main_owner_scope", 0,
                                  "owner_scope_and_current_interactive",
                                  "session_owner_resolve_after_exec");
}

void assert_owner_executor_contract(mapping status) {
    mapping contract = status["executor_task_contract"];
    mapping vm_context_contract = status["vm_context_contract"];
    mapping frozen_payload_contract = status["frozen_payload_contract"];
    mapping gateway_contract = status["gateway_owner_task_contract"];
    mapping fairness = status["executor_queue_fairness"];
    mixed *lpc_contracts = status["executor_lpc_task_contracts"];
    mixed *dispatch_contracts = status["executor_task_dispatch_contracts"];
    mapping dispatch_contract = ([]);
    mapping readonly_contract;
    mixed *nested_lpc_contracts;
    int i;

    ASSERT(mapp(contract));
    ASSERT(mapp(vm_context_contract));
    assert_vm_context_contract(vm_context_contract);
    ASSERT(mapp(frozen_payload_contract));
    assert_frozen_payload_contract(frozen_payload_contract);
    ASSERT(mapp(gateway_contract));
    assert_gateway_owner_task_contract(gateway_contract);
    ASSERT(mapp(fairness));
    ASSERT_EQ("owner_executor_v1", status["executor_contract_version"]);
    ASSERT_EQ("owner_executor", status["executor_model"]);
    ASSERT_EQ("descriptor_manifest", status["executor_dispatch_model"]);
    ASSERT_EQ("default_closed_allowlist", status["executor_lpc_model"]);
    ASSERT_EQ("default_closed", status["ordinary_lpc_default_policy"]);
    ASSERT_EQ(1, status["ordinary_lpc_default_closed"]);
    ASSERT(arrayp(lpc_contracts));
    ASSERT_EQ(1, sizeof(lpc_contracts));
    readonly_contract = lpc_contracts[0];
    ASSERT(mapp(readonly_contract));
    ASSERT_EQ("owner_task_readonly", readonly_contract["method"]);
    ASSERT_EQ("executor_safe_allowlist", readonly_contract["executor_mode"]);
    ASSERT_EQ("owner_executor", readonly_contract["route"]);
    ASSERT_EQ("frozen_result_required", readonly_contract["result_policy"]);
    ASSERT_EQ(1, readonly_contract["executor_safe"]);
    ASSERT_EQ(0, readonly_contract["main_required"]);
    ASSERT_EQ(0, readonly_contract["rejected"]);
    ASSERT_EQ(1, readonly_contract["requires_target"]);
    ASSERT_EQ(1, readonly_contract["requires_owner_thread"]);
    ASSERT_EQ(1, readonly_contract["requires_owner_message_completion"]);
    ASSERT_EQ(1, readonly_contract["frozen_result_required"]);
    ASSERT_EQ(0, readonly_contract["direct_cross_owner_write"]);
    ASSERT(stringp(readonly_contract["reason"]));
    ASSERT(arrayp(dispatch_contracts));
    ASSERT_EQ(10, sizeof(dispatch_contracts));
    for (i = 0; i < sizeof(dispatch_contracts); i++) {
        mapping entry = dispatch_contracts[i];

        ASSERT(mapp(entry));
        ASSERT(stringp(entry["task_type"]));
        ASSERT(stringp(entry["reason"]));
        dispatch_contract[entry["task_type"]] = entry;
    }
    assert_dispatch_entry(dispatch_contract, "executor_probe", "executor_probe",
                          "executor_probe", "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "lpc_probe", "lpc_probe",
                          "lpc_probe", "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "lpc_canary", "lpc_canary",
                          "lpc_canary", "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "lpc_task", "lpc_task_allowlist",
                          "lpc_task", "executor_safe_allowlist", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "owner_message",
                          "owner_message_mailbox", "owner_message",
                          "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "command_consume",
                          "owner_executor_command_consumer", "command_consume",
                          "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "command_frame_restore",
                          "owner_executor_command_frame_restore", "command_frame_restore",
                          "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "compute_result", "compute_result",
                          "compute_result", "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "lpc", "lpc", "reject_lpc",
                          "rejected", 1, 0, 1);
    assert_dispatch_entry(dispatch_contract, "owner_state", "owner_state",
                          "guard_owner_state", "rejected", 1, 0, 1);
    ASSERT_EQ(1, status["ordinary_lpc_default_closed"]);
    ASSERT(stringp(status["executor_last_budget_yield_owner"]));
    ASSERT(intp(status["executor_last_budget_yield_backlog"]));
    ASSERT(intp(status["executor_last_budget_yield_safe_backlog"]));
    ASSERT(intp(status["executor_runnable_task_dispatched"]));
    ASSERT(intp(status["executor_safe_task_dispatched"]));
    ASSERT(intp(status["executor_command_consume_entry_executed"]));
    ASSERT(intp(status["executor_command_frame_restore_entry_executed"]));
    ASSERT(intp(status["thread_eval_stack_owner_bound"]));
    ASSERT(intp(status["thread_eval_stack_cleared"]));
    ASSERT(intp(status["thread_eval_stack_leak_detected"]));
    ASSERT(intp(status["thread_control_stack_owner_bound"]));
    ASSERT(intp(status["thread_control_stack_cleared"]));
    ASSERT(intp(status["thread_control_stack_leak_detected"]));
    ASSERT(intp(status["thread_value_stack_owner_bound"]));
    ASSERT(intp(status["thread_value_stack_cleared"]));
    ASSERT(intp(status["thread_value_stack_leak_detected"]));
    ASSERT(intp(status["thread_apply_return_owner_bound"]));
    ASSERT(intp(status["thread_apply_return_cleared"]));
    ASSERT(intp(status["thread_apply_return_leak_detected"]));
    ASSERT(intp(status["executor_runnable_queue_depth"]));
    ASSERT(intp(status["executor_safe_queue_depth"]));
    ASSERT(intp(fairness["owner_mailbox_owner_count"]));
    ASSERT(intp(fairness["executor_ready_owner_count"]));
    ASSERT(intp(fairness["executor_claim_blocked_owner_count"]));
    ASSERT(intp(fairness["executor_runnable_owner_count"]));
    ASSERT(intp(fairness["executor_runnable_claim_blocked_owner_count"]));
    ASSERT(intp(fairness["main_required_only_owner_count"]));
    ASSERT(intp(fairness["mixed_backlog_owner_count"]));
    ASSERT(intp(fairness["max_owner_backlog"]));
    ASSERT(intp(fairness["max_executor_runnable_backlog"]));
    ASSERT(intp(fairness["max_executor_safe_backlog"]));
    ASSERT(intp(fairness["max_main_required_backlog"]));
    ASSERT(intp(fairness["owner_main_queue_owner_count"]));
    ASSERT(intp(fairness["main_ready_owner_count"]));
    ASSERT(intp(fairness["main_claim_blocked_owner_count"]));
    ASSERT(intp(fairness["max_owner_main_queue_depth"]));
    assert_contract_entry(contract, "executor_probe", "executor_safe",
                          "owner_executor", 1, 0, 0);
    assert_contract_entry(contract, "compute_result", "executor_safe",
                          "owner_executor", 1, 0, 0);
    assert_contract_entry(contract, "owner_executor_command_consumer", "executor_safe",
                          "owner_executor", 1, 0, 0);
    assert_contract_entry(contract, "owner_executor_command_frame_restore", "executor_safe",
                          "owner_executor", 1, 0, 0);
    assert_contract_entry(contract, "owner_message_mailbox", "executor_safe",
                          "owner_executor", 1, 0, 0);
    assert_owner_message_route_contract(contract, "owner_message_mailbox", 1, 0);
    assert_contract_entry(contract, "owner_message_target_handle", "main_required",
                          "owner_main_queue", 0, 1, 0);
    assert_owner_message_route_contract(contract, "owner_message_target_handle", 0, 1);
    assert_contract_entry(contract, "lpc_task_allowlist", "executor_safe_allowlist",
                          "owner_executor", 1, 0, 0);
    nested_lpc_contracts = contract["lpc_task_allowlist"]["contracts"];
    ASSERT(arrayp(nested_lpc_contracts));
    ASSERT_EQ(1, sizeof(nested_lpc_contracts));
    ASSERT_EQ("owner_task_readonly", nested_lpc_contracts[0]["method"]);
    assert_contract_entry(contract, "lpc", "rejected", "owner_executor", 0, 0, 1);
}

void assert_owner_executor_trace(mapping trace) {
    mixed *events = trace["events"];
    int i;

    ASSERT(mapp(trace));
    ASSERT_EQ(1, trace["success"]);
    ASSERT_EQ("owner_executor_trace", trace["trace_kind"]);
    ASSERT_EQ("owner_executor_scheduler_trace", trace["trace_model"]);
    ASSERT_EQ("owner_executor_v1", trace["executor_contract_version"]);
    ASSERT_EQ("owner_executor", trace["executor_model"]);
    ASSERT(intp(trace["returned"]));
    ASSERT(intp(trace["total_traced"]));
    ASSERT(arrayp(events));

    for (i = 0; i < sizeof(events); i++) {
        mapping event = events[i];

        ASSERT(mapp(event));
        ASSERT(intp(event["trace_id"]));
        ASSERT(intp(event["sequence"]));
        ASSERT_EQ("owner_executor_scheduler_event", event["trace_model"]);
        ASSERT_EQ("owner_executor_v1", event["executor_contract_version"]);
        ASSERT_EQ("owner_executor", event["executor_model"]);
        ASSERT_EQ("descriptor_manifest", event["executor_dispatch_model"]);
        ASSERT(stringp(event["owner_id"]));
        ASSERT(stringp(event["event"]));
        ASSERT(intp(event["backlog"]));
        ASSERT(intp(event["runnable_backlog"]));
        ASSERT(intp(event["safe_backlog"]));
        ASSERT(intp(event["main_required_backlog"]));
        ASSERT(intp(event["runnable_owners"]));
        ASSERT(intp(event["claimed_owners"]));
        ASSERT(intp(event["active_claims"]));
    }
}

void assert_owner_trace_models() {
    string source_owner = "owner/test/lpc/trace/source";
    string target_owner = "owner/test/lpc/trace/target";
    int trace_id;
    int message_id;
    mapping trace;
    mapping event;
    mapping message;
    mapping commit;
    mixed *events;

    trace_id = vm_owner_record(source_owner, "lpc_contract", "trace_model", 0, "observed");
    ASSERT(trace_id > 0);
    trace = vm_owner_trace(1);
    events = trace["events"];
    ASSERT_EQ("owner_task_trace", trace["trace_kind"]);
    ASSERT_EQ("owner_task_lifecycle_trace", trace["trace_model"]);
    ASSERT(arrayp(events));
    ASSERT_EQ(1, sizeof(events));
    event = events[0];
    ASSERT_EQ("owner_task_lifecycle_event", event["trace_model"]);
    ASSERT_EQ(source_owner, event["owner_id"]);
    ASSERT_EQ("lpc_contract", event["task_type"]);
    ASSERT_EQ("trace_model", event["task_key"]);
    ASSERT_EQ("observed", event["state"]);

    trace = vm_owner_access_trace(0);
    ASSERT_EQ("owner_access_trace", trace["trace_kind"]);
    ASSERT_EQ("cross_owner_access_policy_trace", trace["trace_model"]);
    ASSERT(arrayp(trace["events"]));

    message = vm_owner_message_submit(source_owner, target_owner,
                                      "trace_contract", "payload/v1");
    ASSERT_EQ(1, message["success"]);
    ASSERT(message["message_id"] > 0);
    message_id = message["message_id"];
    trace = vm_owner_message_trace(1);
    events = trace["events"];
    ASSERT_EQ("owner_message_trace", trace["trace_kind"]);
    ASSERT_EQ("owner_message_lifecycle_trace", trace["trace_model"]);
    ASSERT(arrayp(events));
    ASSERT_EQ(1, sizeof(events));
    event = events[0];
    ASSERT_EQ("owner_message_lifecycle_event", event["trace_model"]);
    ASSERT_EQ(message_id, event["message_id"]);
    ASSERT_EQ(source_owner, event["source_owner_id"]);
    ASSERT_EQ(target_owner, event["target_owner_id"]);
    ASSERT_EQ("trace_contract", event["message_type"]);

    commit = vm_owner_commit_record(source_owner, target_owner,
                                    "trace_commit", message_id, "prepared");
    ASSERT_EQ(1, commit["success"]);
    trace = vm_owner_commit_trace(1);
    events = trace["events"];
    ASSERT_EQ("owner_commit_trace", trace["trace_kind"]);
    ASSERT_EQ("owner_commit_boundary_trace", trace["trace_model"]);
    ASSERT(arrayp(events));
    ASSERT_EQ(1, sizeof(events));
    event = events[0];
    ASSERT_EQ("owner_commit_boundary_event", event["trace_model"]);
    ASSERT_EQ(message_id, event["message_id"]);
    ASSERT_EQ("trace_commit", event["operation"]);
    ASSERT_EQ("prepared", event["state"]);

    vm_owner_purge(target_owner);
}

void do_tests() {
    assert_owner_executor_contract(vm_owner_runtime_status());
    assert_owner_executor_contract(vm_owner_thread_status());
    assert_owner_executor_trace(vm_owner_executor_trace(8));
    assert_owner_trace_models();
}
