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
    ASSERT_EQ("owner_local_object_store", contract["object_store_model"]);
    ASSERT_EQ("owner_local_lookup_only", contract["object_store_off_main_policy"]);
    ASSERT_EQ(1, contract["ordinary_lpc_ready"]);
    ASSERT_EQ("", contract["ordinary_lpc_blocker"]);
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
    ASSERT_EQ("object_handle_boundary", contract["object_refs_model"]);
    ASSERT_EQ(1, contract["object_refs_owner_local"]);
    ASSERT_EQ("object_handle_or_frozen_payload_only",
              contract["cross_owner_object_refs_policy"]);
    ASSERT_EQ(1, contract["cross_owner_payload_rejects_objects"]);
    ASSERT_EQ(1, contract["cross_owner_result_rejects_objects"]);
    ASSERT_EQ(1, contract["owner_message_target_handle_guard"]);
    ASSERT_EQ(1, contract["owner_executor_same_owner_object_refs_only"]);
    ASSERT_EQ(1, contract["ordinary_lpc_object_store_gate_required"]);
    ASSERT_EQ(1, contract["object_store_owner_local_complete"]);
    ASSERT_EQ(1, contract["ordinary_lpc_activation_required"]);
    ASSERT_EQ(1, contract["ordinary_lpc_activation_policy_ready"]);
    ASSERT_EQ(1, contract["ordinary_lpc_dispatch_path_ready"]);
    ASSERT_EQ(1, contract["ordinary_lpc_default_closed"]);
    ASSERT_EQ(1, contract["ordinary_lpc_explicit_open_required"]);
    ASSERT_EQ("generic_owner_lpc_dispatch",
              contract["ordinary_lpc_dispatch_model"]);
    ASSERT_EQ("default_closed_explicit_open",
              contract["ordinary_lpc_activation_policy"]);
    ASSERT_EQ("explicit_open_only_until_gateway_migration",
              contract["ordinary_lpc_activation_rollout"]);
    ASSERT_EQ("disable_explicit_open_submission",
              contract["ordinary_lpc_activation_rollback"]);
    ASSERT_EQ(1, contract["error_state_contextualized"]);
    ASSERT_EQ(1, contract["execution_state_contextualized"]);
    ASSERT_EQ(1, contract["owner_scope_contextualized"]);
    ASSERT_EQ(0, contract["object_store_main_thread_only"]);
    ASSERT(intp(contract["object_store_sync_rejections"]));
    ASSERT_EQ(0, contract["off_main_object_store_sync_allowed"]);
    ASSERT_EQ("all_gates_required_before_open",
              contract["ordinary_lpc_readiness_gate_model"]);
    ASSERT_EQ("", contract["ordinary_lpc_next_blocker"]);
    ASSERT_EQ(13, contract["ordinary_lpc_readiness_gate_count"]);
    ASSERT_EQ(13, contract["ordinary_lpc_satisfied_gate_count"]);
    ASSERT_EQ(0, contract["ordinary_lpc_blocked_gate_count"]);
    ASSERT(arrayp(gates));
    ASSERT_EQ(13, sizeof(gates));
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
    ASSERT_EQ(1, gate_by_name["object_refs_owner_local"]["satisfied"]);
    ASSERT_EQ("", gate_by_name["object_refs_owner_local"]["blocker"]);
    ASSERT_EQ("keep_cross_owner_object_refs_handle_or_frozen_payload_only",
              gate_by_name["object_refs_owner_local"]["next_action"]);
    ASSERT_EQ(1, gate_by_name["object_store_owner_local_complete"]["satisfied"]);
    ASSERT_EQ("", gate_by_name["object_store_owner_local_complete"]["blocker"]);
    ASSERT_EQ("keep_owner_local_store_canonical_without_global_fallback",
              gate_by_name["object_store_owner_local_complete"]["next_action"]);
    ASSERT_EQ(1, gate_by_name["ordinary_lpc_activation_policy"]["satisfied"]);
    ASSERT_EQ("", gate_by_name["ordinary_lpc_activation_policy"]["blocker"]);
    ASSERT_EQ("keep_default_closed_until_dispatch_path_ready",
              gate_by_name["ordinary_lpc_activation_policy"]["next_action"]);
    ASSERT_EQ(1, gate_by_name["ordinary_lpc_dispatch_path"]["satisfied"]);
    ASSERT_EQ("", gate_by_name["ordinary_lpc_dispatch_path"]["blocker"]);
    ASSERT_EQ("keep_generic_dispatch_explicit_open_and_frozen_result_guarded",
              gate_by_name["ordinary_lpc_dispatch_path"]["next_action"]);
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
    ASSERT_EQ(5, sizeof(paths));
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
    ASSERT_EQ(1, path_by_name["domain_task"]["top_level_mapping_required"]);
    ASSERT_EQ("domain_task_payload", path_by_name["domain_task"]["input_policy"]);
    ASSERT_EQ("owner_future_frozen_result_required",
              path_by_name["domain_task"]["result_policy"]);
    ASSERT_EQ(1, path_by_name["domain_task"]["frozen_result_required"]);
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
    mixed *command_side_effect_gates = contract["command_side_effect_readiness_gates"];
    mapping task_by_key = ([]);
    mapping command_executor_gate_by_name = ([]);
    mapping command_side_effect_gate_by_name = ([]);
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
    ASSERT_EQ("redacted_input_to_get_char_state_v1",
              contract["command_input_callback_state_policy"]);
    ASSERT_EQ(1, contract["command_input_callback_snapshot_ready"]);
    ASSERT_EQ("owner_command_frame_input_callback_detach_v1",
              contract["command_input_callback_frame_model"]);
    ASSERT_EQ(1, contract["command_input_callback_frame_detach_ready"]);
    ASSERT_EQ(1, contract["command_input_callback_frame_executor_ready"]);
    ASSERT_EQ("owner_command_frame_input_callback_apply",
              contract["command_input_callback_apply_frame_model"]);
    ASSERT_EQ("interactive_input_callback",
              contract["command_input_callback_apply_frame_task_type"]);
    ASSERT_EQ(1, contract["command_input_callback_apply_frame_ready"]);
    ASSERT_EQ(1, contract["command_input_callback_apply_frame_executor_ready"]);
    ASSERT_EQ("owner_command_frame_input_callback_mode_delta",
              contract["command_input_callback_mode_delta_model"]);
    ASSERT_EQ(1, contract["command_input_callback_mode_delta_ready"]);
    ASSERT_EQ(1, contract["command_input_callback_mode_delta_executor_ready"]);
    ASSERT_EQ("", contract["command_input_callback_blocker"]);
    ASSERT_EQ("owner_command_frame_process_input_apply",
              contract["process_input_apply_frame_model"]);
    ASSERT_EQ("interactive_command_parser",
              contract["process_input_apply_frame_task_type"]);
    ASSERT_EQ(1, contract["process_input_apply_frame_ready"]);
    ASSERT_EQ(0, contract["process_input_apply_frame_executor_ready"]);
    ASSERT_EQ("owner_command_parser_context_v1",
              contract["process_input_add_action_parser_frame_model"]);
    ASSERT_EQ(1, contract["process_input_add_action_parser_frame_ready"]);
    ASSERT_EQ(0, contract["process_input_add_action_parser_frame_executor_ready"]);
    ASSERT_EQ("add_action_parser_command_giver_main_thread_bound",
              contract["process_input_add_action_parser_blocker"]);
    ASSERT_EQ("interactive_command_side_effects_main_thread_bound",
              contract["command_executor_blocker"]);
    ASSERT_EQ("owner_owned_snapshot_main_thread_consume",
              contract["command_consume_model"]);
    ASSERT_EQ(1, contract["command_consume_snapshot_ready"]);
    ASSERT_EQ(1, contract["command_consume_executor_ready"]);
    ASSERT_EQ("", contract["command_consume_blocker"]);
    ASSERT_EQ("main_reply_queue_after_owner_command",
              contract["command_reply_queue_model"]);
    ASSERT_EQ("command_reply", contract["command_reply_queue_task_type"]);
    ASSERT_EQ("prompt_telnet_reschedule_io",
              contract["command_reply_queue_task_key"]);
    ASSERT_EQ("prompt_telnet_reschedule_io",
              contract["command_reply_queue_side_effects"]);
    ASSERT_EQ(1, contract["command_reply_queue_ready"]);
    ASSERT_EQ(1, contract["command_reply_queue_main_required"]);
    ASSERT_EQ("owner_command_frame_write_prompt_apply",
              contract["command_reply_write_prompt_apply_frame_model"]);
    ASSERT_EQ("command_reply",
              contract["command_reply_write_prompt_apply_frame_task_type"]);
    ASSERT_EQ(1, contract["command_reply_write_prompt_apply_frame_ready"]);
    ASSERT_EQ(0, contract["command_reply_write_prompt_apply_frame_executor_ready"]);
    ASSERT_EQ("owner_command_frame_mode_delta",
              contract["command_mode_delta_model"]);
    ASSERT_EQ("main_reply_queue_after_command_consume",
              contract["command_mode_delta_localecho_restore_boundary"]);
    ASSERT_EQ(1, contract["command_mode_delta_localecho_restore_ready"]);
    ASSERT_EQ("owner_command_frame_localecho_restore",
              contract["interactive_mode_localecho_restore_model"]);
    ASSERT_EQ("interactive_mode_flags",
              contract["interactive_mode_localecho_restore_task_type"]);
    ASSERT_EQ(1, contract["interactive_mode_localecho_restore_ready"]);
    ASSERT_EQ(0, contract["interactive_mode_localecho_restore_executor_ready"]);
    ASSERT_EQ("command_mode_delta",
              contract["command_mode_delta_terminal_mode_task_type"]);
    ASSERT_EQ("get_char_linemode_restore,single_char_escape_linemode,single_char_escape_charmode_restore",
              contract["command_mode_delta_terminal_mode_task_keys"]);
    ASSERT_EQ("main_mode_delta_queue_after_command_consume",
              contract["command_mode_delta_terminal_mode_boundary"]);
    ASSERT_EQ(1, contract["command_mode_delta_terminal_mode_ready"]);
    ASSERT_EQ(0, contract["command_mode_delta_ready"]);
    ASSERT_EQ("owner_command_frame_mxp_tag_filter",
              contract["interactive_mode_mxp_tag_filter_model"]);
    ASSERT_EQ("interactive_mode_flags",
              contract["interactive_mode_mxp_tag_filter_task_type"]);
    ASSERT_EQ(1, contract["interactive_mode_mxp_tag_filter_ready"]);
    ASSERT_EQ(0, contract["interactive_mode_mxp_tag_filter_executor_ready"]);
    ASSERT_EQ("owner_command_frame_ed_command",
              contract["interactive_mode_ed_command_model"]);
    ASSERT_EQ("interactive_mode_flags",
              contract["interactive_mode_ed_command_task_type"]);
    ASSERT_EQ(1, contract["interactive_mode_ed_command_ready"]);
    ASSERT_EQ(0, contract["interactive_mode_ed_command_executor_ready"]);
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
    ASSERT_EQ("gateway_command_executor_activation", contract["command_executor_next_gate"]);
    ASSERT_EQ("interactive_command_side_effects_main_thread_bound",
              contract["command_executor_next_blocker"]);
    ASSERT_EQ(7, contract["command_executor_readiness_gate_count"]);
    ASSERT_EQ(6, contract["command_executor_satisfied_gate_count"]);
    ASSERT_EQ(1, contract["command_executor_blocked_gate_count"]);
    ASSERT_EQ("all_side_effect_gates_required_before_activation",
              contract["command_side_effect_readiness_gate_model"]);
    ASSERT_EQ(5, contract["command_side_effect_readiness_gate_count"]);
    ASSERT_EQ(3, contract["command_side_effect_satisfied_gate_count"]);
    ASSERT_EQ(2, contract["command_side_effect_blocked_gate_count"]);
    ASSERT_EQ(5, contract["command_side_effect_snapshot_gate_count"]);
    ASSERT_EQ(5, contract["command_side_effect_snapshot_ready_count"]);
    ASSERT_EQ(1, contract["command_side_effect_observability_ready"]);
    ASSERT_EQ(0, contract["command_side_effect_activation_ready"]);
    ASSERT(arrayp(command_executor_gates));
    ASSERT_EQ(7, sizeof(command_executor_gates));
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
    ASSERT_EQ(1, command_executor_gate_by_name["ordinary_lpc_ready"]["satisfied"]);
    ASSERT_EQ("", command_executor_gate_by_name["ordinary_lpc_ready"]["blocker"]);
    ASSERT_EQ(0, command_executor_gate_by_name["gateway_command_executor_activation"]["satisfied"]);
    ASSERT_EQ("interactive_command_side_effects_main_thread_bound",
              command_executor_gate_by_name["gateway_command_executor_activation"]["blocker"]);
    ASSERT(arrayp(command_side_effect_gates));
    ASSERT_EQ(5, sizeof(command_side_effect_gates));
    for (i = 0; i < sizeof(command_side_effect_gates); i++) {
        mapping gate = command_side_effect_gates[i];

        ASSERT(mapp(gate));
        ASSERT(stringp(gate["gate"]));
        ASSERT(stringp(gate["model"]));
        ASSERT(intp(gate["satisfied"]));
        ASSERT(stringp(gate["blocker"]));
        ASSERT(stringp(gate["next_action"]));
        ASSERT(stringp(gate["state_owner"]));
        ASSERT(stringp(gate["migration_boundary"]));
        ASSERT(stringp(gate["side_effect_class"]));
        ASSERT(stringp(gate["snapshot_policy"]));
        ASSERT_EQ(1, gate["snapshot_ready"]);
        ASSERT_EQ(1, gate["state_redacted"]);
        ASSERT(intp(gate["blocks_activation"]));
        command_side_effect_gate_by_name[gate["gate"]] = gate;
    }
    ASSERT_EQ(1, command_side_effect_gate_by_name["interactive_buffer_consume"]["satisfied"]);
    ASSERT_EQ(0, command_side_effect_gate_by_name["interactive_buffer_consume"]["blocks_activation"]);
    ASSERT_EQ("", command_side_effect_gate_by_name["interactive_buffer_consume"]["blocker"]);
    ASSERT_EQ("owner_command_snapshot", command_side_effect_gate_by_name["interactive_buffer_consume"]["state_owner"]);
    ASSERT_EQ("main_thread_consume_before_executor_activation",
              command_side_effect_gate_by_name["interactive_buffer_consume"]["migration_boundary"]);
    ASSERT_EQ("input_buffer_consume", command_side_effect_gate_by_name["interactive_buffer_consume"]["side_effect_class"]);
    ASSERT_EQ("owner_private_command_text_snapshot_v1",
              command_side_effect_gate_by_name["interactive_buffer_consume"]["snapshot_policy"]);
    ASSERT_EQ(1, command_side_effect_gate_by_name["input_to_get_char_state"]["satisfied"]);
    ASSERT_EQ(0, command_side_effect_gate_by_name["input_to_get_char_state"]["blocks_activation"]);
    ASSERT_EQ("", command_side_effect_gate_by_name["input_to_get_char_state"]["blocker"]);
    ASSERT_EQ("owner_command_frame", command_side_effect_gate_by_name["input_to_get_char_state"]["state_owner"]);
    ASSERT_EQ("owner_command_frame_input_callback_executor",
              command_side_effect_gate_by_name["input_to_get_char_state"]["migration_boundary"]);
    ASSERT_EQ("input_callback_state", command_side_effect_gate_by_name["input_to_get_char_state"]["side_effect_class"]);
    ASSERT_EQ("redacted_input_to_get_char_state_v1",
              command_side_effect_gate_by_name["input_to_get_char_state"]["snapshot_policy"]);
    ASSERT_EQ(0, command_side_effect_gate_by_name["process_input_add_action_parser"]["satisfied"]);
    ASSERT_EQ(1, command_side_effect_gate_by_name["process_input_add_action_parser"]["blocks_activation"]);
    ASSERT_EQ("add_action_parser_command_giver_main_thread_bound",
              command_side_effect_gate_by_name["process_input_add_action_parser"]["blocker"]);
    ASSERT_EQ("interactive_t_and_command_giver",
              command_side_effect_gate_by_name["process_input_add_action_parser"]["state_owner"]);
    ASSERT_EQ("owner_command_parser_context",
              command_side_effect_gate_by_name["process_input_add_action_parser"]["migration_boundary"]);
    ASSERT_EQ("parser_command_giver_state",
              command_side_effect_gate_by_name["process_input_add_action_parser"]["side_effect_class"]);
    ASSERT_EQ("redacted_process_input_add_action_parser_state_v1",
              command_side_effect_gate_by_name["process_input_add_action_parser"]["snapshot_policy"]);
    ASSERT_EQ(1, command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["satisfied"]);
    ASSERT_EQ(0, command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["blocks_activation"]);
    ASSERT_EQ("", command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["blocker"]);
    ASSERT_EQ("main_reply_queue_and_network_io",
              command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["state_owner"]);
    ASSERT_EQ("main_reply_queue_after_owner_command",
              command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["migration_boundary"]);
    ASSERT_EQ("prompt_telnet_reschedule_io",
              command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["side_effect_class"]);
    ASSERT_EQ("redacted_prompt_telnet_reschedule_io_v1",
              command_side_effect_gate_by_name["prompt_telnet_reschedule_io"]["snapshot_policy"]);
    ASSERT_EQ(0, command_side_effect_gate_by_name["interactive_mode_flags"]["satisfied"]);
    ASSERT_EQ(1, command_side_effect_gate_by_name["interactive_mode_flags"]["blocks_activation"]);
    ASSERT_EQ("interactive_mode_flags_main_thread_bound",
              command_side_effect_gate_by_name["interactive_mode_flags"]["blocker"]);
    ASSERT_EQ("interactive_t", command_side_effect_gate_by_name["interactive_mode_flags"]["state_owner"]);
    ASSERT_EQ("owner_command_frame_mode_delta",
              command_side_effect_gate_by_name["interactive_mode_flags"]["migration_boundary"]);
    ASSERT_EQ("echo_mxp_ed_mode_flags", command_side_effect_gate_by_name["interactive_mode_flags"]["side_effect_class"]);
    ASSERT_EQ("redacted_interactive_mode_flags_v1",
              command_side_effect_gate_by_name["interactive_mode_flags"]["snapshot_policy"]);
    ASSERT_EQ(0, contract["ordinary_lpc_ready_required"]);
    ASSERT_EQ(1, contract["main_required"]);
    ASSERT_EQ("gateway_command_executor_activation",
              contract["next_blocker"]);
    ASSERT_EQ("gateway_command_executor/gateway_command_executor_activation",
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
    mapping boundary_contract = status["owner_executor_boundary_contract"];
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
    ASSERT(mapp(boundary_contract));
    ASSERT_EQ(1, boundary_contract["contract_version"]);
    ASSERT_EQ("owner_executor_boundary_v1", boundary_contract["boundary_model"]);
    ASSERT_EQ("compilation_unit_active", boundary_contract["implementation_state"]);
    ASSERT_EQ("OwnerExecutor", boundary_contract["class_name"]);
    ASSERT_EQ(1, boundary_contract["class_extracted"]);
    ASSERT_EQ(1, boundary_contract["module_extracted"]);
    ASSERT_EQ("vm/internal/owner_executor.h", boundary_contract["module_file"]);
    ASSERT_EQ(1, boundary_contract["compilation_unit_extracted"]);
    ASSERT_EQ("vm/internal/owner_executor.cc", boundary_contract["compilation_unit_file"]);
    ASSERT_EQ(1, boundary_contract["depends_on_owner_cc_internal_state"]);
    ASSERT_EQ(1, boundary_contract["dependency_manifest_ready"]);
    ASSERT_EQ(1, boundary_contract["runtime_dependency_contract_version"]);
    ASSERT_EQ("scheduler_state,mailbox_state,task_dispatch,vm_context,metric_counters,future_completion",
              boundary_contract["dependency_domains"]);
    ASSERT_EQ(1, boundary_contract["scheduler_state_dependency"]);
    ASSERT_EQ(1, boundary_contract["mailbox_state_dependency"]);
    ASSERT_EQ(1, boundary_contract["task_dispatch_dependency"]);
    ASSERT_EQ(1, boundary_contract["vm_context_dependency"]);
    ASSERT_EQ(1, boundary_contract["metric_counter_dependency"]);
    ASSERT_EQ(1, boundary_contract["future_completion_dependency"]);
    ASSERT_EQ(1, boundary_contract["owner_runtime_facade_required"]);
    ASSERT_EQ(1, boundary_contract["owner_runtime_facade_ready"]);
    ASSERT_EQ("owner_executor_runtime_facade_v1", boundary_contract["owner_runtime_facade_model"]);
    ASSERT_EQ("vm/internal/owner.cc", boundary_contract["owner_runtime_facade_file"]);
    ASSERT_EQ("scheduler_state,mailbox_state,future_completion", boundary_contract["owner_runtime_facade_domains"]);
    ASSERT_EQ(1, boundary_contract["owner_runtime_facade_scheduler_ready"]);
    ASSERT_EQ(1, boundary_contract["owner_runtime_facade_future_completion_ready"]);
    ASSERT_EQ("owner_cc_anonymous_runtime_state", boundary_contract["compilation_unit_blocker"]);
    ASSERT_EQ(1, boundary_contract["claim_release_boundary_ready"]);
    ASSERT_EQ(1, boundary_contract["budget_boundary_ready"]);
    ASSERT_EQ(1, boundary_contract["thread_context_boundary_ready"]);
    ASSERT_EQ(1, boundary_contract["dispatch_manifest_boundary_ready"]);
    ASSERT_EQ(1, boundary_contract["same_owner_serial_required"]);
    ASSERT_EQ(1, boundary_contract["main_required_tasks_excluded"]);
    ASSERT_EQ(1, boundary_contract["target_handle_messages_main_required"]);
    ASSERT_EQ(1, boundary_contract["compute_result_executor_safe"]);
    ASSERT_EQ(1, boundary_contract["gateway_command_rejected"]);
    ASSERT_EQ(0, boundary_contract["gateway_command_executor_activation_ready"]);
    ASSERT_EQ(1, boundary_contract["ordinary_lpc_default_closed"]);
    ASSERT_EQ(1, boundary_contract["ordinary_lpc_explicit_open_required"]);
    ASSERT_EQ("explicit_open_same_owner_only", boundary_contract["ordinary_lpc_policy"]);
    ASSERT_EQ(0, boundary_contract["lpc_surface_expanded"]);
    ASSERT_EQ("extract_owner_executor_compilation_unit_without_expanding_lpc_surface",
              boundary_contract["next_refactor_target"]);
    ASSERT(mapp(fairness));
    ASSERT_EQ("owner_executor_v1", status["executor_contract_version"]);
    ASSERT_EQ("owner_executor", status["executor_model"]);
    ASSERT_EQ("descriptor_manifest", status["executor_dispatch_model"]);
    ASSERT_EQ("default_closed_explicit_open", status["executor_lpc_model"]);
    ASSERT_EQ("default_closed_explicit_open", status["ordinary_lpc_default_policy"]);
    ASSERT_EQ(1, status["ordinary_lpc_default_closed"]);
    ASSERT_EQ(1, status["ordinary_lpc_activation_policy_ready"]);
    ASSERT_EQ(1, status["ordinary_lpc_dispatch_path_ready"]);
    ASSERT_EQ(1, status["ordinary_lpc_explicit_open_required"]);
    ASSERT_EQ("default_closed_explicit_open", status["ordinary_lpc_activation_policy"]);
    ASSERT_EQ("", status["ordinary_lpc_next_blocker"]);
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
    ASSERT_EQ(12, sizeof(dispatch_contracts));
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
    assert_dispatch_entry(dispatch_contract, "ordinary_lpc", "ordinary_lpc_dispatch",
                          "ordinary_lpc", "executor_safe_explicit_open", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "owner_message",
                          "owner_message_mailbox", "owner_message",
                          "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "command_consume",
                          "owner_executor_command_consumer", "command_consume",
                          "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "command_frame_restore",
                          "owner_executor_command_frame_restore", "command_frame_restore",
                          "executor_safe", 1, 1, 0);
    assert_dispatch_entry(dispatch_contract, "gateway_command",
                          "gateway_command_executor_activation", "gateway_command",
                          "rejected", 1, 0, 1);
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
    ASSERT(intp(status["thread_gateway_command_rejected"]));
    ASSERT(intp(status["thread_ordinary_lpc_executed"]));
    ASSERT(intp(status["thread_ordinary_lpc_succeeded"]));
    ASSERT(intp(status["thread_ordinary_lpc_failed"]));
    ASSERT(intp(status["thread_ordinary_lpc_rejected"]));
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
    assert_contract_entry(contract, "gateway_command_executor_activation", "rejected",
                          "owner_executor", 0, 0, 1);
    ASSERT_EQ(5, contract["gateway_command_executor_activation"]["side_effect_snapshot_gate_count"]);
    ASSERT_EQ(5, contract["gateway_command_executor_activation"]["side_effect_snapshot_ready_count"]);
    ASSERT_EQ(1, contract["gateway_command_executor_activation"]["side_effect_observability_ready"]);
    ASSERT_EQ(0, contract["gateway_command_executor_activation"]["side_effect_activation_ready"]);
    ASSERT_EQ("interactive_command_side_effects_main_thread_bound",
              contract["gateway_command_executor_activation"]["activation_blocker"]);
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
    assert_contract_entry(contract, "ordinary_lpc", "executor_safe_explicit_open",
                          "owner_executor", 1, 0, 0);
    ASSERT_EQ("generic_owner_lpc_dispatch", contract["ordinary_lpc"]["dispatch_model"]);
    ASSERT_EQ("default_closed_explicit_open", contract["ordinary_lpc"]["activation_policy"]);
    ASSERT_EQ(1, contract["ordinary_lpc"]["default_closed"]);
    ASSERT_EQ(1, contract["ordinary_lpc"]["explicit_open_required"]);
    ASSERT_EQ(1, contract["ordinary_lpc"]["requires_target"]);
    ASSERT_EQ(1, contract["ordinary_lpc"]["requires_owner_thread"]);
    ASSERT_EQ(1, contract["ordinary_lpc"]["requires_owner_message_completion"]);
    ASSERT_EQ(1, contract["ordinary_lpc"]["frozen_result_required"]);
    ASSERT_EQ(0, contract["ordinary_lpc"]["direct_cross_owner_write"]);
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
