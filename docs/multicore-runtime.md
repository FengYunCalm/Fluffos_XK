# FluffOS_XK 项目现状与多核化改造说明

## 结论

FluffOS_XK 当前已经从“单主线程、全局可变 VM 状态”的传统 driver 形态，推进到具备 owner 边界、线程本地 VMContext、受控 VM worker 和 owner mailbox 的运行时基础设施。

这次多核化改造的核心成果不是开放任意 LPC 后台线程执行，而是把可安全迁移的计算、快照处理、owner 调度和边界观测先从主线程模型中拆出来，为后续 actor-style 服务化和更细粒度的多核利用打基础。

## 当前项目状态

FluffOS_XK 是 FluffOS 的公开维护分支，面向实际运行项目提供源码级 driver 基线。仓库仍保持经典 FluffOS driver 模型，不绑定具体游戏 mudlib，不包含私有部署数据。

当前主线重点包括：

- 构建稳定性，尤其是 Linux、Windows/MSYS2 和 CMake install 路径。
- Gateway/session 集成，服务 WebSocket 客户端和服务化部署。
- VMContext、owner-runtime 和 VM worker 基础设施。
- 核心模块告警清理和第三方依赖告警控制。
- README、贡献指南、安全策略、变更记录等公开仓库基础整理。

关键代码位置：

- `src/vm/context.h` 和 `src/vm/internal/context.cc`：线程本地 VMContext 与主线程 object store 边界。
- `src/vm/worker.h` 和 `src/vm/internal/worker.cc`：VM worker runtime 与受控任务队列。
- `src/vm/owner.h` 和 `src/vm/internal/owner.cc`：owner metadata、mailbox、trace、owner thread。
- `src/packages/core/vm_worker.cc`：LPC 侧 worker efun 封装。
- `src/packages/core/vm_owner.cc`：LPC 侧 owner efun 封装。
- `src/packages/gateway/`：Gateway session runtime。
- `src/tests/test_lpc.cc`：当前主要 C++ 回归测试。

## 多核化改造做了什么

### 1. VMContext 线程隔离

传统 FluffOS 大量依赖全局 VM 状态，例如当前对象、命令发起者、当前 interactive、当前程序和对象链表。多线程改造如果直接共享这些状态，会引入对象生命周期、执行栈和跨线程访问风险。

当前改造加入了线程本地 `VMContext`：

- 主线程维护真实 object store 快照。
- 非主线程绑定自己的 `VMContext`。
- 非主线程尝试同步 object store 时会被拒绝，并清空对象链表快照。
- detached `VMContext` 的 setter、apply 和 sync 只更新自身 snapshot，不会改写当前线程绑定 context 的 thread-local execution state。
- `VMExecutionScope` 用于保存和恢复执行上下文。
- `VMOwnerScope` 用于在受控任务中绑定 owner id 和 owner epoch。

直接效果：worker 和 owner thread 不再默认继承主线程对象表，避免把非线程安全的对象系统误当作可并发访问资源。

### 2. VM worker 受控任务队列

`VMWorkerRuntime` 提供独立 worker 线程池。默认根据硬件线程数启动，线程数限制在 `1..64`。同一 `owner_key` 的任务会串行化，避免同一 actor 的任务并发执行。

当前 worker 支持的任务类型是固定白名单：

- `bench`：并行基准和调度验证。
- `snapshot_digest`：对快照文本做稳定 digest。
- `actor_score`：根据角色快照计算状态评分。
- `combat_damage`：根据输入快照计算战斗伤害。

LPC 侧接口支持同步执行、异步 submit/poll、批量 submit/poll、timeout 和 TTL。输入会经过公共 `vm_frozen_value_safe()` 检查，与 owner payload 使用同一冻结值策略，避免把任意对象、函数、非字符串 mapping key 或深层复杂结构送入后台线程。runtime/thread status 的 `frozen_payload_contract` 会把 validator、deep copy、最大深度、允许/拒绝类型，以及 `owner_send`、`owner_call_async`、`owner_publish_snapshot`、`worker_snapshot` 四条路径的 input/result policy 暴露为机器可读合同。v2 worker task 会注册 owner future，`bench`、`snapshot_digest`、`actor_score` 和 `combat_damage` 成功结果，以及 timeout 失败都会先进入 owner queue；成功结果在 owner runtime 边界生成 frozen mapping result 并反映为 completed，timeout/失败反映为 failed/error。

直接效果：计算型、快照型、确定性任务可以脱离主循环执行，主线程可以继续承担连接、命令、对象生命周期和 VM 主状态维护。

### 3. owner-runtime 与 mailbox

owner-runtime 给对象引入 owner id 和 owner epoch，用于标记执行归属和检测陈旧任务。

当前能力包括：

- `vm_owner_id`、`vm_owner_epoch`、`vm_owner_guard`、`vm_owner_guard_epoch`。
- owner mailbox 入队、调度、drain、purge 和状态查询。
- 主线程 owner queue，用于按 owner/epoch 投递和分发 gateway/player input、callout、heartbeat、async/db/file completion、DNS callback、socket read/write/close callback。
- ObjectHandle 与 owner shard 状态索引，用于记录 objects、active heartbeats、pending callouts、pending messages、runnable task 数、executor readiness、owner-local object directory、live object reference 和 live/destructed path index。状态接口现在暴露 `vm_object_shard` 合同，用 `status_model`、`execution_model`、`directory_model` 和 `storage_model` 区分状态记录、执行队列、`VMObjectShard.object_directory`、`VMObjectShard.local_records`、`VMObjectShard.local_objects`、`VMObjectShard.local_object_index`、`VMObjectShard.destructed_records`、`VMObjectShard.object_path_index`、`VMObjectShard.destructed_path_index` 和当前 storage bridge。当前 `object_directory` membership 已由 `VMObjectShard.object_directory` 驱动，live 目录记录快照来自 `VMObjectShard.local_records`，directory record 明确报告 `resolved_via_owner_local_store=1`、`resolved_via_global_index=0`，live object reference 和 owner-local resolve 来自 `VMObjectShard.local_objects` 与反向 `VMObjectShard.local_object_index`，live path index 来自 `VMObjectShard.object_path_index`，destruct 后诊断 tombstone 来自 `VMObjectShard.destructed_records` 和 `VMObjectShard.destructed_path_index`；按 owner/object_id 与 owner/path 的 lookup 都会优先报告 shard-local live/tombstone 命中状态，并用 `owner_local_object_ref_found`、`owner_local_object_ref_index_found`、`owner_local_object_ref_index_source`、`owner_local_object_pointer_index_found`、`owner_local_resolve_found`、`owner_local_resolve_source`、`owner_local_canonical_record_ready` 和 `owner_local_store_ready` 显式报告是否能从 shard-local 正反向 live ref 得到可解析 live object、当前 owner shard record/ref/path/tombstone 镜像是否满足 canonical readiness，以及 lookup/resolve 是否已经可由 owner-local 镜像承担；通用 object_id/path record fallback 查询也会先检查 owner shard 的 live/tombstone 索引；当 `global_record_bridge_retirement_ready=1` 时，缺失查询会跳过 global record fallback 并通过 `owner_local_global_record_fallback_skipped=1`、`owner_local_global_record_fallback_reason=global_record_bridge_retirement_ready` 暴露原因，path lookup 还会通过 `owner_local_global_record_scan_bridge_skipped=1`、`owner_local_global_record_scan_bridge_skip_reason=global_record_bridge_retirement_ready` 证明没有执行 `global_object_records.path_scan_bridge`；当 `global_live_object_bridge_retirement_ready=1` 时，缺失 path lookup 会跳过 global live-object fallback 并通过 `owner_local_global_live_object_fallback_skipped=1`、`owner_local_global_live_object_fallback_reason=global_live_object_bridge_retirement_ready` 暴露原因，path record fallback 在此状态下也不会先查 `ObjectTable`；只有 readiness 未满足时才通过显式 global object_id/path/pointer helper 回落 global object records，path record scan 会用 `owner_local_global_record_scan_bridge_used/found/source` 暴露 `global_object_records.path_scan_bridge` 是否被使用和命中；所有直接 `ObjectTable` 查找已集中到单一 global live-object bridge helper，owner lookup 的最后 fallback 只调用显式 global helper，混合 owner-local/global record helper 已移除，避免来源字段误报。跨 owner migration 后旧 owner lookup 的 mismatch 诊断会先扫描其他 owner shard 的 live/destructed record 或 path index，并通过 `owner_local_cross_shard_record_found`/`owner_local_cross_shard_record_source` 暴露来源，只有跨 shard 诊断缺失且 global record bridge retirement readiness 未满足时才回落到 global object record fallback。按 owner/object_id 与 owner/path 的 resolve 只在 shard-local live ref 完整命中时返回对象。`vm_object_handle_resolve_status()` 对 live/current handle 已先尝试 owner-local shard 快路径，只有 live record、local object ref、反向 object ref index、live path index、owner id 和 owner epoch 全部一致才返回 `current`，并通过 `owner_local_object_pointer_index_found` 暴露 object 指针反查命中；同 owner object id mismatch 会优先通过 owner-local path index 诊断，并通过 `diagnosed_via_owner_local_path_index` 暴露来源，path mismatch、owner epoch drift 和 destruct tombstone 会优先通过 owner-local live/tombstone record 诊断，并通过 `diagnosed_via_owner_local_store` 暴露来源；跨 owner migration 旧 handle 的 `owner_mismatch` 也会先用其他 owner shard 诊断，并设置 `diagnosed_via_owner_local_cross_shard`；最后的 `ObjectTable` live-object fallback 已收束为显式 global live-object bridge，ObjectHandle resolve result 和状态 mapping 均通过 `global_live_object_found`/`global_live_object_source` 暴露同一来源；ObjectHandle 和 owner lookup/path lookup 的 global fallback 也会分别用 `global_record_found/source`、`global_live_object_bridge_retirement_ready`、`owner_local_global_live_object_found/source`、`owner_local_global_live_object_fallback_skipped/reason` 与 `owner_local_global_record_found/source` 区分 live-object bridge 和 global record bridge。ObjectHandle 在 `global_live_object_bridge_retirement_ready=1` 时会跳过 global live-object fallback，并通过 `global_live_object_fallback_skipped=1`、`global_live_object_fallback_reason=global_live_object_bridge_retirement_ready` 暴露原因；在 `global_record_bridge_retirement_ready=1` 且 live-object bridge 缺失、已跳过或只允许查 live object 而不附带 global record 时会跳过 global record fallback，并通过 `global_record_fallback_skipped=1`、`global_record_fallback_reason=global_record_bridge_retirement_ready` 暴露原因。global object record 诊断只作为 fallback 并通过 `diagnosed_via_global_index` 暴露。`vm_object_store_status()` 额外报告 `store_kind=vm_object_store`、`status_model=object_store_status`、`directory_model=owner_local_object_directory`、`storage_model=owner_local_store`，并聚合 `owner_local_record_total`、`owner_local_object_ref_total`、`owner_local_object_ref_index_total`、`owner_local_destructed_record_total`、live/destructed path index total、`owner_local_orphan_record_total`、`global_record_total`、`global_live_record_total`、`global_destructed_record_total`、`owner_local_to_global_mismatch_record_total`、`global_to_owner_local_record_mismatch_record_total`、`global_to_owner_local_mismatch_record_total`、`owner_local_record_index_ready`、`owner_local_canonical_record_ready`、`owner_local_store_ready`、`global_record_bridge_consistent`、`global_record_bridge_retirement_ready`、`global_live_object_bridge_retirement_ready`、`owner_local_to_global_bridge_consistent`、`global_to_owner_local_bridge_consistent`、`owner_local_global_bridge_check=bidirectional`、`global_live_object_bridge_ready/source`、`global_record_bridge_ready/source` 以及兼容聚合字段 `owner_local_global_bridge_consistent`，用于证明当前 global bridge 与 owner-local live/tombstone/ref/path 索引双向没有漂移，并明确最后的 live object 与 global record fallback 来源；其中 owner-local record index readiness、global record bridge consistency、global record 总量和 record-only mismatch 计数是迁出 global canonical record 前的硬门禁。`owner_local_store_complete=1` 现在表示 owner-local canonical record、live object ref、path/tombstone 索引以及 global record/live-object bridge retirement 门禁已经足以承担 lookup/resolve；global bridge ready/source 字段为 0/空，retirement readiness 字段作为审计证据保留。对象生命周期、deferred destruct 和全局表物理删除仍属于后续 lifecycle 迁移，不是普通 LPC 已开放的理由。`status.objects` 仅作为兼容统计由同一 helper 同步增删；状态接口会明确报告 `owner_local_directory_ready=1`、`owner_local_record_count`、`owner_local_object_ref_count`、`owner_local_object_ref_index_count`、`owner_local_object_ref_index_consistent`、`owner_local_destructed_record_count`、`owner_local_path_index_count`、`owner_local_destructed_path_index_count`、`owner_local_live_index_consistent`、`owner_local_live_path_index_consistent`、`owner_local_destructed_path_index_consistent`、`owner_local_store_ready` 和 `owner_local_store_complete=1`，避免把 directory/record/ref/path/tombstone snapshot 误解为对象生命周期、deferred destruct 和全局索引物理迁出已经完成。
- object_id 方向的 global record fallback 也已显式命名为 `global_object_records.object_id_scan_bridge`；owner lookup status 暴露 `owner_local_global_record_id_scan_bridge_used/found/source/skipped/reason`，ObjectHandle status 暴露 `global_record_id_scan_bridge_used/found/source/skipped/reason`。当 `global_record_bridge_retirement_ready=1` 时，object_id 缺失查询和 ObjectHandle object-id fallback 会跳过该 bridge 并报告 `global_record_bridge_retirement_ready`，避免把剩余 `object_records` 扫描误认为 owner-local 命中或 live-object bridge 命中。
- object pointer 方向的 global record fallback 已显式命名为 `global_object_records.pointer_bridge`；owner path lookup status 暴露 `owner_local_global_record_pointer_bridge_used/found/source/skipped/reason`，ObjectHandle status 暴露 `global_record_pointer_bridge_used/found/source/skipped/reason`。当 live-object bridge 允许查到对象但 `global_record_bridge_retirement_ready=1` 时，pointer record bridge 会被跳过，避免通过 `ObjectTable` 找到 live object 后又隐式取回 global record。
- object store、owner shard、owner lookup/path lookup 与 shard contract 现在以 `owner_local_store_complete=1` 和 `owner_local_store_complete_blocker=""` 表示 owner-local lookup/resolve gate 已完成；`global_live_object_bridge_ready/source` 与 `global_record_bridge_ready/source` 为 0/空，retirement readiness 字段作为兼容审计证据保留。
- `current_object`/`current_prog`/`previous_ob`/`caller_type` execution frame setter，`call_origin`、inherit offset 和 stack temporary depth setter，`command_giver` 的 VMContext setter/保存栈同步，`current_interactive` 的 VMContext setter/scope，`current_error_context`、eval error flags 和 error handler depths 的 VMContext 同步，以及 object lifecycle guard 同步，用于收敛解释器执行状态的保存恢复；detached context 更新不会污染当前线程状态。
- `vm_context_reset_execution()` 会同步清理当前线程 thread-local execution state 和 VMContext snapshot。
- runtime/thread status 的 `vm_context_contract` 暴露 `ordinary_lpc_readiness_gates`、`ordinary_lpc_readiness_gate_count`、`ordinary_lpc_satisfied_gate_count`、`ordinary_lpc_blocked_gate_count`、`ordinary_lpc_next_blocker` 和 `ordinary_lpc_readiness_gate_model=all_gates_required_before_open`。当前 13 项门禁已全部满足：thread-local VMContext、execution state、owner scope、error state、eval stack owner-local、control stack owner-local、value stack owner-local、apply return owner-local、cross-owner object ref 边界、off-main object store 同步拒绝、owner-local lookup/resolve object store gate、activation policy 和 generic owner LPC dispatch path 均已具备；其中 eval/control/value stack 是 thread-local owner execution stack，apply return 是 thread-local owner apply return，并通过 VMContext snapshot 在 owner executor task 内 owner-bound、task 后 cleared；cross-owner object ref gate 的口径是跨 owner 边界只允许 ObjectHandle 或 frozen payload/result；object store gate 的口径是 lookup/resolve canonical 化，不代表对象生命周期已可由后台线程并发写入。`ordinary_lpc_ready=1` 表示显式开放的 same-owner generic LPC dispatch path 已可由 owner executor 执行，但 `ordinary_lpc_default_closed=1`、`ordinary_lpc_explicit_open_required=1` 仍是强合同，未显式开放的普通 LPC 和 legacy `lpc` task 仍默认关闭。
- runtime/thread status 的 `frozen_payload_contract` 暴露 `validator=vm_frozen_value_safe`、`deep_copy=1`、`max_depth=8`、`mapping_keys_must_be_strings=1`、允许类型 number/real/string/array/mapping、拒绝类型 object/function/buffer/class，以及 owner/worker/future/snapshot 四类 payload 路径。该合同表示跨 owner 数据必须是 frozen/deep-copy 风格数据，不表示普通 LPC 对象引用可跨线程共享。
- runtime/thread status 的 `gateway_owner_task_contract` 暴露阶段 8 input/gateway 的当前执行边界：`input_model=owner_main_queue_bridge`、`executor_migration_state=main_required_before_owner_executor`、`ordinary_lpc_ready_required=0`，并把 `gateway_receive`、`process_user_command`、`gateway_logon`、`gateway_disconnected` 固定为 `main_required` 合同。`gateway_receive` 和 `process_user_command` 必须经 `owner_main_queue` 串行桥接并使用 owner epoch stale guard；logon/disconnected 仍是 `direct_main_owner_scope`。`process_user_command` 合同额外声明 `payload_key=gateway_command_input`、`input_payload_policy=buffer_metadata_no_raw_command_text`、`command_input_source=interactive_text_buffer`、`command_text_snapshot_policy=owner_private_redacted_from_trace`、`command_text_snapshot_ready=1`、`command_executor_blocker=interactive_command_side_effects_main_thread_bound`、`command_consume_model=owner_owned_snapshot_main_thread_consume`、`command_consume_snapshot_ready=1`、`command_consume_executor_ready=1`、`command_consume_blocker=""`、`requires_target_handle=1`、`requires_frozen_payload=1`、`execution_frame_model=gateway_command_execution_frame_v1`、`execution_frame_policy=owner_scope_current_interactive_command_giver`、`command_execution_frame_restore_policy=owner_executor_vmcontext_restore`、`command_execution_frame_restore_ready=1`、`command_execution_frame_restore_blocker=\"\"` 和 `execution_frame_executor_ready=1`；合同还声明 `command_stale_guard=owner_epoch_target_handle_guard`、`command_stale_trace_state=main_stale`、`command_stale_target_status=owner_epoch_mismatch`。实际 gateway command main task trace 会携带 current ObjectHandle、owner epoch、`gateway_command_buffer_metadata_v1` frozen payload 元数据、interactive text buffer 的 owner-private 命令快照脱敏元数据、主线程 `process_user_command_snapshot()` 的 owner-owned snapshot 消费模型、execution-frame 捕获元数据以及 `execution_frame_restore_policy=owner_executor_vmcontext_restore` / `execution_frame_restore_ready=1` / `execution_frame_restore_blocker=\"\"`，但不会把原始命令文本写入 trace；如果入队后 owner epoch 漂移，main queue 会在 dispatch 前以 `main_stale` 丢弃旧 task，并通过 ObjectHandle 报告 `owner_epoch_mismatch`，不会消费旧命令。四类入口都要求恢复 owner scope、`current_interactive` 和 `command_giver`，这只证明 gateway 输入链路已可观测和可验收，不表示玩家命令已经在后台 owner executor 中执行；下一阻塞点被拆成 `command_executor_readiness_gates` 机器可读门禁，`command_executor_readiness_gate_model=all_gates_required_before_owner_executor`、gate count 为 7，其中 `owner_epoch_target_handle_guard`、`owner_owned_command_snapshot`、`owner_owned_command_consume`、`owner_executor_command_consume_entry`、`owner_executor_frame_restore` 和 `ordinary_lpc_ready` 均已满足；当前唯一未满足项是 `gateway_command_executor_activation`，`command_executor_next_gate=gateway_command_executor_activation`、`command_executor_next_blocker=interactive_command_side_effects_main_thread_bound`。普通 LPC 显式开放路径就绪不等于玩家命令已迁移，不能把 frame restore/consume entry 或 generic LPC readiness 误解为后台玩家命令已可执行。`executor_task_dispatch_contracts` 另有 `gateway_command` / `gateway_command_executor_activation` descriptor，但其 `executor_mode=rejected`、`executor_safe=0`、`rejected=1`，owner 线程只会记录 `thread_gateway_command_rejected`，用于防止玩家命令绕过 main-required gateway bridge 被误投递到 owner executor。`command_side_effect_readiness_gates` 进一步把 activation blocker 拆成 5 项：`interactive_buffer_consume` 已满足；`input_to_get_char_state`、`process_input_add_action_parser`、`prompt_telnet_reschedule_io`、`interactive_mode_flags` 仍分别被 `input_to/get_char` 状态、add_action/parser command_giver 状态、prompt/telnet/reschedule I/O、echo/MXP/ed/interactive flags 主线程副作用阻塞。每个 side-effect gate 同时暴露 `state_owner`、`migration_boundary`、`side_effect_class` 和 `blocks_activation`，用于把后续迁移边界固定为机器可读合同。gateway command payload 还暴露 `input_callback_state_policy=redacted_input_to_get_char_state_v1`、`input_callback_state_snapshot_ready=1`、`input_callback_active`、`input_callback_single_char`、`input_callback_noescape`、`input_callback_noecho`、`input_callback_carryover_count` 以及函数/对象 redacted 标志；当前 C++ 回归已覆盖 inactive input callback、active `input_to` 和 active `get_char`/single-char 三类 payload 快照，且验证不暴露 callback function、callback object 或 raw command text；这只是 input_to/get_char 状态的脱敏观测，`input_to_get_char_state` gate 仍保持 blocked。gateway command payload 同时暴露 `process_input_add_action_parser_state_policy=redacted_process_input_add_action_parser_state_v1`、`process_input_add_action_parser_has_process_input`、`process_input_add_action_parser_safe_parse_fallback`、`process_input_add_action_parser_requires_command_giver` 以及 command_giver/command_text redacted 标志；C++ 回归已验证这些字段存在且不暴露 command_giver 对象或命令文本；这只是 process_input/add_action/parser 状态的脱敏观测，`process_input_add_action_parser` gate 仍保持 blocked。
- task trace、executor scheduler trace、access trace、message trace、commit trace；task/access/message/commit trace 顶层都暴露 `trace_kind` 与 `trace_model`，事件 mapping 暴露对应事件 `trace_model`，用于把 owner task lifecycle、cross-owner access policy、owner message lifecycle 和 commit boundary 诊断结构固定下来；main task trace 事件现在也暴露 `has_target_handle`、`target_handle_status`、`target_object_id`、`target_object_path`、`target_owner_epoch`、`payload_key`、`execution_frame_model`、`execution_frame_policy`、`execution_frame_requires_current_interactive`、`execution_frame_requires_command_giver`、`execution_frame_executor_ready`、`payload_frozen` 和可选 frozen `payload`，用于验证 gateway command 这类主线程桥接任务已经携带后续 executor 化所需的只读元数据；executor scheduler trace 通过 `vm_owner_executor_trace()` 暴露 `trace_kind=owner_executor_trace`、`trace_model=owner_executor_scheduler_trace`、`executor_contract_version=owner_executor_v1`、`executor_model=owner_executor`，事件 mapping 暴露 `trace_model=owner_executor_scheduler_event`、`executor_dispatch_model=descriptor_manifest`、owner claim、budget yield、release 事件及当时 backlog/runnable/claimed 计数；message trace 会暴露 route、pending/completed/failed/terminal 分类、result/error、target handle 状态、main queue/mailbox 路由和 frozen result 标志。
- owner thread opt-in 启动，最大线程数为 `4`。
- owner executor claim/release 计数，用于验证同 owner 串行 claim 和任务结束释放。
- owner executor 对单次 claim 使用固定 `executor_task_budget`；同一 owner 的 executor-safe backlog 超过 budget 时会记录 yield、释放 claim 并重新调度剩余 backlog，避免单 owner 长队列长期独占 executor；runtime/thread status 会额外暴露最近一次 budget yield 的 owner、剩余总 backlog 和剩余 executor-safe backlog。
- runtime/thread/mailbox status 会区分 `executor_runnable_queue_depth`、`executor_safe_queue_depth`、`main_required_queue_depth`、`runnable_owner_count`、`main_runnable_owner_count`、`claimed_owners` 和 `claimed_main_owners`，并通过只读 `executor_queue_fairness` 汇总 executor-runnable owner、executor-safe owner、main-required-only owner、mixed backlog owner、claim-blocked owner 与最大 backlog，避免把“可由 executor 消费后完成/拒绝”和“业务逻辑可安全后台执行”混为一类。`executor_runnable_task_dispatched` 统计 executor 实际取走的 runnable task，`executor_safe_task_dispatched` 只统计 descriptor 标记为 executor-safe 的任务；普通 `lpc`/`owner_state` 被取走后拒绝或 guard 时只会增长 runnable 计数，不会增长 safe 计数。
- owner executor 在同一 owner mailbox 中遇到前置 main-required task 时，会跳过它并继续消费后续 executor-safe task；被跳过的 main-required task 仍保留在 owner mailbox/main bridge 边界，不会被后台 executor 执行。
- runtime/thread status 暴露只读 `executor_contract_version=owner_executor_v1`、`executor_model=owner_executor`、`executor_dispatch_model=descriptor_manifest`、`executor_lpc_model=default_closed_explicit_open`、`ordinary_lpc_default_policy=default_closed_explicit_open`、`executor_task_contract`、`executor_task_dispatch_contracts` 和 `executor_lpc_task_contracts`：`compute_result`、无目标 `owner_message`、`executor_probe`、受控注册 `lpc_task` 和显式开放的 `ordinary_lpc` 属于 executor-safe；有 target handle 的 `owner_message` 属于 main-required；legacy 普通 `lpc` 仍属于 rejected/default-closed，但仍由 executor 取走后拒绝，避免 rejected task 卡住 mailbox。`executor_task_dispatch_contracts` 是按 task type 注册的 dispatch manifest，字段包含 `task_type`、`contract_key`、`dispatch_kind`、`executor_runnable`、`executor_safe`、`main_required`、`rejected` 和 route 要求，用来约束 `executor_probe`、`lpc_probe`、`lpc_canary`、`lpc_task`、`ordinary_lpc`、`lpc`、`owner_state`、`owner_message`、`compute_result` 的调度分支；status、fairness 和 executor trace 会同时暴露 runnable backlog 与 safe backlog，并用 `executor_runnable_task_dispatched`/`executor_safe_task_dispatched` 分别呈现已消费 runnable 数和已安全执行数。`vm_owner_ordinary_lpc_task(object, owner, method, explicit_open)` 是 generic LPC 的显式开放入口：只有 `explicit_open=1`、target 存在、target owner 与提交 owner 一致时才创建 pending future 并入 owner mailbox；owner executor 执行时要求 off-main VMContext、owner-bound epoch、same-owner target 和 frozen result。未显式开放、owner mismatch 或 legacy `lpc` task 仍不会打开普通 LPC 后台执行。

mailbox 和主线程 owner queue 调度保持 owner 内 FIFO，同时在不同 owner 之间轮转。owner thread 会在独立 `VMContext` 中执行，并在每个任务结束后检查 owner、execution 和 canary 状态是否清理干净。`compute_result` 这类 executor-safe owner task 已能由 owner executor 消费，并通过统一 future 状态机把 worker v2 成功 frozen result 或失败 error 反映回 owner future；有 target handle 的 object message 仍保留主线程 owner queue bridge。

owner message/future 当前会同步记录 submitted、completed 和 failed 状态；message trace 会进一步记录 `owner_mailbox`/`owner_main_queue` route、失败原因、result key、target handle 状态、是否 queued_on_main 和是否 frozen result，便于把旧同步调用迁移到 message/future 时定位卡点。`owner_call_async()` 会返回目标对象 handle、path 和 owner epoch 快照。有 target handle 的 object message 会进入主线程 owner queue bridge，在主线程绑定 `VMOwnerScope` 后完成 `safe_apply()` 和 future 状态更新；stale handle 会以 `stale target: <resolve_status>` 形式失败并清理 pending message，例如 `owner_mismatch` 或 `object_not_found`，目标方法返回非 frozen 结果时 future 会失败，避免把 object/function/buffer/class 等不可跨 owner 共享的值透出边界。

主线程 owner queue 当前承担过渡职责：网络输入、gateway 命令、到期 callout、heartbeat、async/db/file completion、DNS callback 以及 socket read/write/close callback 先进入 per-owner 队列，再在主线程绑定 `VMOwnerScope` 后执行。这样能先固定 owner 调度语义和 stale epoch 防线，同时避免在全局 VM 状态还未完全迁出前贸然让后台线程执行任意 LPC。

cross-owner access 判定会优先使用当前 owner scope 作为 source owner；当 scope 仍是默认 `legacy/main` 且 `command_giver` 已有显式 owner 时，会使用 `command_giver` owner 作为 effective source owner。这覆盖 gateway 命令进入时先以 legacy scope 开始、随后 mudlib 给玩家对象补 owner 的过渡场景，但不放开无 scope 的普通对象调用。command/std shared service、`single/simul_efun` 关键 singleton 和 `/adm/daemons/gateway_d` 在玩家 owner scope 内都有默认 owner 污染防线；`/adm/daemons/gateway_d` system message 入口会绑定 daemon 自身 owner/epoch 的 `VMOwnerScope` 并记录 `receive_system_message` trace。当前回归只证明入口 owner 合同，不表示 gateway LPC 回调或 shared service LPC 已经后台并行。

直接效果：项目开始具备 actor-style 迁移所需的运行时形状，也可以观察跨 owner 访问、消息边界和任务生命周期。

### 4. 受限 owner LPC 任务

当前没有开放任意 LPC 方法后台执行。owner thread 对普通 `lpc` 任务默认拒绝。

已经开放的是受控路径：

- `lpc_probe`：验证 off-main context、object store isolation 和 owner 绑定。
- `lpc_canary`：只允许 `owner_lpc_canary`。
- `lpc_task`：普通方法仍默认关闭；当前只开放 descriptor 注册的 `owner_task_readonly` 作为受控只读样例，历史上预留的 owner domain task 名称仍拒绝。提交后会返回可轮询 `future_id`、`registered_task`、`task_contract`、`executor_mode`、`route`、`result_policy` 和 `contract_reason`；线程侧成功时写入 frozen result，拒绝、失败、purge 或被主线程兼容 drain/schedule 消费时都会完成为 failed，避免 pending future 堆积。

受控探针和 allowlist task 执行前必须满足：

- 当前上下文不是主线程 VMContext。
- object store 处于隔离状态。
- 当前 owner id 和 owner epoch 已绑定。
- 目标对象未析构。
- 目标对象 owner epoch 匹配。
- 方法名匹配受控探针或受控只读 task 合同。

直接效果：LPC 后台执行的边界被显式收窄，避免“为了多核化而破坏对象系统安全”。

### 5. 跨 owner 访问观测

当前 runtime 会记录关键跨 owner 访问路径，例如：

- `environment`
- `all_inventory`
- `present`
- `call_other`
- `move_object`
- `destruct`

access trace 会把跨 owner 操作分类为 snapshot、message 或 reject 风格。这一层当前更偏观测和迁移辅助，不应理解成已经完成所有跨 owner 写入隔离。

在 enforced 模式下，cross-owner `call_other`、`move_object` 和 `destruct` 的同步路径会被阻断，要求迁移到 owner message/future。当前已经有一条可验证的 `call_other` 替代样例：同步 cross-owner 调用被拒绝后，同一目标方法可通过 `owner_call_async()`、ObjectHandle、主线程 owner queue bridge 和 future 返回 frozen result；但这仍只是核心机制闭环，不等于旧 mudlib 中所有同步跨 owner 调用已经完成迁移。

直接效果：下游可以先看到哪些旧 LPC 逻辑仍然依赖全局对象互访，再逐步迁移到快照读取或消息提交模型。

## 改造效果

### 工程效果

- 主线程边界更清楚：对象表和核心 VM 状态仍归主线程管理。
- 后台任务边界更清楚：worker 只处理固定、可序列化、确定性的任务。
- owner 迁移路径更清楚：owner id、epoch、mailbox、trace 和默认关闭的 off-main LPC 边界已经具备。
- 风险可观测：跨 owner 访问、任务派发、上下文清理、canary 和 rejected task 都有计数或 trace。
- 下游集成更稳定：Gateway session 和 README/发布规范让引擎仓库更适合作为公开依赖。

### 性能方向效果

多核化当前最直接的收益是让部分计算型任务从主事件循环中剥离出来，降低主线程被 CPU 计算阻塞的概率。适合迁移的任务包括：

- 基于快照的摘要和校验。
- 角色状态评分。
- 战斗数值计算。
- 未来可白名单化的 owner domain 任务。

需要注意的是，当前仓库没有宣称完整生产压测数据，也没有把任意 LPC 对象操作搬到后台线程。当前成果更准确地说是“多核化运行时地基已经落地，并通过测试覆盖关键安全边界”。

### 可维护性效果

- 多核相关代码集中在 `context`、`worker`、`owner` 和 core efun 封装中。
- 关键行为有 `src/tests/test_lpc.cc` 覆盖。
- README 已明确项目范围，降低下游误用风险。
- off-main LPC task 默认关闭，新增后台 LPC 能力必须先证明对象隔离和 owner 合同安全，而不是注册后直接开放。

## 已验证内容

当前测试重点覆盖：

- VMContext 主线程和 worker 线程绑定。
- 非主线程 object store 同步拒绝。
- VMExecutionScope、execution frame/call origin/inherit offset/stack temporary depth setter、VMCurrentInteractiveScope、command_giver 保存栈、error context 栈、eval error flags、error handler depths、object lifecycle guard 和 VMOwnerScope 的保存恢复。
- owner id、epoch、guard、mailbox、schedule、purge。
- owner payload recursive frozen-data 检查、buffer/class 拒绝、message/future pending/completed/failed 状态同步、message trace route/result/error/handle 状态分类、async call 目标 handle 快照、cross-owner async bridge 成功、submitted/completed/failed trace 终态和非 frozen result 失败，runtime/thread/mailbox status 暴露 `pending_futures`、`frozen_payload_contract`、受控 LPC task descriptor manifest、executor task dispatch manifest、兼容 allowlist、executor-safe/main-required queue depth、runnable owner 和 claimed owner。
- owner thread opt-in、上下文绑定、对象表隔离和状态清理。
- owner executor claim/release 生命周期，覆盖同 owner 串行、多 owner 多 worker 分发、同 owner backlog 超过 budget 后 yield/requeue、同 owner 混合 mailbox 中跳过 main-required 头部并执行后续 executor-runnable task、executor task contract/dispatch contract 只读诊断面，以及 worker v2 `compute_result` 由 owner executor 消费并携带 frozen result 完成 owner future。
- owner shard runnable task/executor readiness 状态。
- 主线程 owner queue 的 owner scope 绑定和 stale owner epoch 丢弃。
- 普通 LPC 任务默认拒绝，descriptor 注册的 `owner_task_readonly` 受控只读任务可在 owner thread 执行。
- restricted canary、受控只读 owner LPC task 执行、未注册 owner LPC task 拒绝和预留 domain task 拒绝。
- VM worker 的同步、异步、批量、timeout、TTL 和结果轮询，包含成功 frozen result 与 timeout failed/error 反射到 owner future 的队列闭环；`testsuite/single/tests/efuns/worker_payload.c` 覆盖公开 worker efun 对 object/function/buffer/class、非字符串 mapping key、深层嵌套和 batch unsafe snapshot 的拒绝合同。
- Gateway session 创建、销毁、exec logon 后 session 绑定。
- detached `VMContext` setter/apply/sync 不会 clobber 当前线程 execution/error state。
- 加载型 singleton 对象默认归入 `legacy/main`，避免命令对象、daemon 等共享对象被首次触发加载的玩家 owner 污染；clone 仍继承当前 owner 或 prototype owner。
- XiaKeXing 运行树短验收：`multicore mode : off`、`audit` 和 `enforced` 的 WebSocket mixed 场景均通过 3 用户登录和命令闭环；最新 enforced 3 用户 mixed 结果为 109/109 命令成功、0 timeout、0 断线。

推荐验证命令：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
cd testsuite && ../build/bin/driver etc/config.test -ftest
```

## 当前边界

- 不支持任意 LPC 在后台线程自由执行。
- gateway/player input、callout、heartbeat、async/db/file completion、DNS callback、socket read/write/close callback 已进入主线程 owner queue；worker v2 `compute_result` 可由 owner executor 消费，但这些真实 LPC 回调尚未变成后台 owner executor 并行执行。
- apply/direct/function pointer 高频入口已通过 VMContext API 设置 `current_object`、`current_prog`、`previous_ob`、`caller_type`、`call_origin`、inherit offset 和 stack temporary depth；interactive/gateway 高频入口已通过 VMContext API 设置 `current_interactive`，`command_giver` 保存栈、`current_error_context`、eval error flags、error handler depths 和 object lifecycle guard 会同步 VMContext，`this_player()` 读取 VMContext execution 快照；eval stack/control stack/value stack/apply return 已具备 owner executor task 内 owner-bound 与 task 后 cleared 合同；cross-owner object ref 边界已收口为 ObjectHandle 或 frozen payload/result；owner-local lookup/resolve store gate 已完成，但对象生命周期和 deferred destruct 仍未开放为后台并发写入口。
- object store 仍保留全局 index，但 owner shard 已提供 `VMObjectShard` 合同、`VMObjectShard.object_directory`、`VMObjectShard.local_records`、`VMObjectShard.local_objects`、`VMObjectShard.local_object_index`、`VMObjectShard.destructed_records`、`VMObjectShard.object_path_index`、`VMObjectShard.destructed_path_index`、owner/object_id lookup/resolve、owner/path lookup/resolve、ObjectHandle live/current owner-local 快路径、live/ref/path/tombstone 一致性状态、owner-local/global bridge 双向一致性门禁、状态索引和可执行队列观测；directory/lookup/resolve 优先使用 shard-local directory、live record snapshot、正反向 live object reference、live path index、destruct tombstone 和 destruct path tombstone，`status.objects` 只是兼容统计。状态接口明确暴露 `uses_global_object_table=0`、`global_index_bridge=0`、`owner_local_store_ready`、`owner_local_store_complete=1`、`global_live_object_bridge_ready/source` 和 `global_record_bridge_ready/source`，并用 `global_record_total`、`global_live_record_total`、`global_destructed_record_total`、`owner_local_to_global_mismatch_record_total`、`global_to_owner_local_record_mismatch_record_total`、`global_to_owner_local_mismatch_record_total`、`owner_local_record_index_ready`、`owner_local_canonical_record_ready`、`owner_local_store_ready`、`global_record_bridge_consistent`、`global_record_bridge_retirement_ready`、`global_live_object_bridge_retirement_ready`、`owner_local_global_record_scan_bridge_used/found/source/skipped/reason`、`owner_local_to_global_bridge_consistent`、`global_to_owner_local_bridge_consistent` 和 `owner_local_global_bridge_consistent` 区分 global canonical record 基线、owner-local canonical record 是否可作为 lookup/resolve 镜像、path scan bridge 是否仍被 fallback 使用、bridge 漂移方向与总结果。这表示 owner-local lookup/resolve store gate 已完成；仍未完成的是对象生命周期、deferred destruct 和全局索引物理迁出的生产级并发化。
- object_id/path/pointer 三条 global record bridge 都已显式可观测：object_id 使用 `global_object_records.object_id_scan_bridge`，path 使用 `global_object_records.path_scan_bridge`，pointer 使用 `global_object_records.pointer_bridge`；三者现在主要作为显式审计名和历史兼容字段保留；在 retirement readiness 满足时缺失查询会跳过这些 bridge。
- `socket_release` callback 仍保持同步路径，因为 efun 返回值依赖 callback 是否立即完成 release/acquire 交接。
- 不应把 owner thread 理解为传统对象系统的并发写入口。
- 跨 owner access trace、message trace 和 commit trace 当前主要用于观测、分类和迁移辅助；`trace_kind`/`trace_model` 只固定诊断结构，它们能解释 route、失败原因、commit boundary 和 handle stale resolve 状态，但不代表所有旧同步调用都已经迁移。
- enforced 模式已通过 XiaKeXing 3 用户 WebSocket mixed 短验收，但不能视为完整生产压测；更长时长、更高并发和更多玩法路径仍需要继续验证。
- worker 任务必须是固定任务类型，并使用公共 frozen-value 校验后的可序列化输入。
- owner thread 是 opt-in，最大线程数为 `4`。
- 生产性能收益需要结合具体 mudlib、任务粒度和主线程负载继续压测。

## 面向下游的建议

下游项目如果要利用这次改造，建议按以下顺序推进：

1. 先把纯计算逻辑整理成基于快照的输入输出。
2. 用 `snapshot_digest`、`actor_score`、`combat_damage` 这类固定 worker task 验证任务切分收益。
3. 给关键服务对象设置 owner id，并观察 access trace。
4. 把跨 owner 直接调用逐步改成 snapshot 或 message 风格。
5. 对确实安全的 LPC domain task 先建立对象隔离证明、owner 合同和 canary 验证，再考虑开放执行入口。
6. 最后再做项目侧压测，比较主线程延迟、命令响应和 CPU 利用率。

## 对外表述口径

建议对外这样描述：

FluffOS_XK 已经完成第一阶段多核化运行时基础改造。它通过线程本地 VMContext、受控 VM worker、owner mailbox 和 owner-bound execution，把传统 LPC driver 从单一全局执行模型推进到可逐步 actor 化的架构。当前重点是安全边界和可验证迁移路径，而不是开放不受限制的后台 LPC 执行。
