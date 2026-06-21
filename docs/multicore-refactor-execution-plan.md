# FluffOS_XK 多核化重构可执行详细方案

## 最终结论

FluffOS_XK 的正确多核化路线是 owner/actor 分片 VM，不是给传统全局对象系统补锁。最终目标是：

- 同一 owner 内 LPC 严格串行。
- 不同 owner 可并行执行。
- 跨 owner 不允许直接写对象或同步调用目标 LPC。
- 跨 owner 只允许 snapshot、message、future 和 frozen/deep-copy payload。
- 主线程退化为事件接入、全局索引维护、兼容桥和不可迁移 legacy 边界，不再是唯一 LPC 执行点。

当前仓库已经完成第一阶段地基，并开始具备受控只读 off-main LPC 样例、owner-local object directory、object message 主线程 bridge、一条可验证的 cross-owner async 替代样例、owner executor 消费 worker v2 `compute_result` 并完成 owner future 的受控闭环，以及同 owner 混合 mailbox 中跳过 main-required 头部继续执行 executor-runnable task 的调度防卡死验证；但尚未完成真正并行 owner-local LPC 执行，也尚未完成旧 mudlib 的跨 owner 同步调用迁移。后续方案必须围绕“证明安全边界”推进，不能为了制造多核效果而打开任意后台 LPC。

## 当前基线

当前 HEAD：`6e6f60e9 Harden cross-owner LPC boundaries`。

已经落地：

- `multicore mode : off/audit/enforced` 配置。
- `VMContext` 线程本地化和主要执行状态迁移。
- object store 仅主线程可同步，非主线程 sync 被拒绝。
- owner id、owner epoch、owner guard。
- owner mailbox、main owner queue、task/access/message/commit trace；这些 trace 顶层已暴露 `trace_kind`/`trace_model`，事件 mapping 暴露对应事件 `trace_model`；message trace 已包含 route、pending/completed/failed/terminal 分类、result/error、target handle 状态、main queue/mailbox 路由和 frozen result 标志；LPC 层已显式暴露 `vm_owner_drain_main(int)`，用于测试和运维手动 drain main-required owner task。
- ObjectHandle 和 stale 校验；resolve 失败已能区分 invalid handle、missing path、object id mismatch、owner mismatch、owner epoch mismatch、record destructed 等状态。
- owner shard 状态索引、显式 `VMObjectShard` 合同、`VMObjectShard.object_directory`、`VMObjectShard.local_records`、`VMObjectShard.local_objects`、`VMObjectShard.local_object_index`、`VMObjectShard.destructed_records`、`VMObjectShard.object_path_index`、`VMObjectShard.destructed_path_index`、按 owner/object_id 和 owner/path 的只读 lookup/resolve API、ObjectHandle live/current owner-local 快路径、同 owner stale/tombstone owner-local 诊断、跨 owner shard mismatch 诊断、live/ref/path/tombstone 一致性状态、owner-local/global bridge 双向一致性门禁和 runnable 观测；状态接口明确暴露 `vm_object_shard`、`directory_model=owner_local_object_directory`、`owner_local_directory_ready=1`、`owner_local_record_count`、`owner_local_object_ref_count`、`owner_local_object_ref_index_count`、`owner_local_object_ref_index_consistent`、`owner_local_destructed_record_count`、`owner_local_path_index_count`、`owner_local_destructed_path_index_count`、`owner_local_live_index_consistent`、`owner_local_live_path_index_consistent`、`owner_local_destructed_path_index_consistent`、`global_record_total`、`global_live_record_total`、`global_destructed_record_total`、`owner_local_to_global_mismatch_record_total`、`global_to_owner_local_record_mismatch_record_total`、`global_to_owner_local_mismatch_record_total`、`owner_local_record_index_ready`、`owner_local_canonical_record_ready`、`global_record_bridge_consistent`、`global_record_bridge_retirement_ready`、`global_live_object_bridge_retirement_ready`、`owner_local_to_global_bridge_consistent`、`global_to_owner_local_bridge_consistent`、`owner_local_global_bridge_check=bidirectional`、`owner_local_global_bridge_consistent`、`owner_local_store_ready`、`owner_local_store_complete=0`、`global_index_bridge=1`、`global_live_object_bridge_ready/source`、`global_record_bridge_ready/source`。当前 directory membership 已由 `VMObjectShard.object_directory` 驱动，live 目录记录快照来自 `VMObjectShard.local_records`，directory record 报告 `resolved_via_owner_local_store=1` 和 `resolved_via_global_index=0`，live object reference 和 owner-local resolve 来自 `VMObjectShard.local_objects` 与反向 `VMObjectShard.local_object_index`，live path index 来自 `VMObjectShard.object_path_index`，destruct 后诊断 tombstone 和 path tombstone 来自 `VMObjectShard.destructed_records`/`VMObjectShard.destructed_path_index`，跨 owner migration 后旧 owner lookup 会先扫描其他 owner shard 的 live/destructed record 或 path index 并报告 `owner_local_cross_shard_record_found`/`owner_local_cross_shard_record_source`，旧 ObjectHandle 的 `owner_mismatch` 也会优先报告 `diagnosed_via_owner_local_store=1` 和 `diagnosed_via_owner_local_cross_shard=1`；`owner_local_store_ready=1` 只表示 canonical record/ref/path/tombstone 镜像和 live-object bridge 退休门禁已足以承担 lookup/resolve，不表示生命周期、destruct 或 global index 已迁出；global object record 只保留为缺失时的 fallback，owner lookup/path lookup 会通过 `global_live_object_bridge_retirement_ready`、`owner_local_global_live_object_found/source`、`owner_local_global_live_object_fallback_skipped/reason` 与 `owner_local_global_record_found/source` 区分 live-object bridge 和 record bridge，ObjectHandle 诊断也会通过 `global_live_object_found/source`、`global_record_found/source`、`global_record_fallback_skipped/reason` 和 `diagnosed_via_global_index` 暴露；`status.objects` 仅保留为兼容统计并由同一增删 helper 同步维护；ObjectHandle 解析会先在 owner-local shard 上验证 live record、正反向 local object ref、live path index、owner id 和 owner epoch，失败时优先用同 owner shard live/tombstone record 诊断 epoch drift/destruct，因此仍不是完整 owner-local object store。
- owner 生命周期入口已有回归覆盖 singleton load 默认 owner、command singleton、std database service、`std/http`、`std/present_clone` 和 `std/telnet` 这类共享 service 在玩家 owner scope 内仍默认 owner、`single/simul_efun` 及其关键继承 helper `std/all_environment`、`std/json` 不被玩家 owner scope 污染、`/adm/daemons/gateway_d` daemon singleton 在玩家 owner scope 内仍默认 owner 且 system message 以 daemon owner/epoch 记录 trace、master `compile_object` virtual object 默认 owner 且重命名后同步 owner-local directory path、clone 不继承裸 ambient owner scope、move 时非显式 owner 继承 destination owner、显式 owner move 后保持原 owner、普通 interactive `exec()` 保持新旧对象 owner/epoch 不被隐式改写、gateway `exec()` 后 session lookup 绑定新 user owner/epoch，以及 destruct 后 owner-local directory 清理。
- VM worker 确定性任务、owner-key 串行化、async poll/future。
- worker v2 task 的 owner future 注册、`bench`/`snapshot_digest`/`actor_score`/`combat_damage` 成功 frozen result 和 timeout failed/error 反射；`compute_result` 可以由 owner executor 消费并完成 owner future。
- 玩家输入、gateway、heartbeat、callout、async/db/file completion、DNS callback、socket callback、ED callback 已进入主线程 owner queue。
- 有 target handle 的 object message 已进入主线程 owner queue bridge，stale handle 会失败并清理 pending message，目标结果非 frozen 时 future 会失败。
- cross-owner `call_other`、`present`、parser、`move_object`、`destruct` 在 enforced 模式下有阻断。
- `owner_query_object_snapshot()` 安全结构快照 API。
- `owner_send()`、`owner_call_async()`、`owner_future_poll()` 等消息/future API；`owner_call_async()` 已有 enforced cross-owner `call_other` 替代样例测试。
- 普通 off-main LPC 默认关闭，`owner_task_readonly` 已从裸 allowlist 收敛为显式 LPC task descriptor/contract manifest，owner executor task type 也已收敛为只读 dispatch manifest；线程侧执行前必须满足 owner/context/object-store 边界，并通过 owner future 暴露 pending/completed/failed 与 frozen result。
- owner message trace 已覆盖 mailbox message、ObjectHandle/main queue bridge、purge、stale target resolve 状态、非 frozen result 等 completed/failed 可诊断路径；ObjectHandle 失败会以 `stale target: <resolve_status>` 暴露到 future 和 trace，destruct 后旧 handle 会报告 `record_destructed` 而不是被粗略归为 object not found。

尚未完成：

- 完全独立的 owner-local object store；当前已有 owner-local directory、shard-local live record snapshot、destruct tombstone 和 global index bridge，但还没有把对象指针解析、destruct/index 生命周期彻底迁出全局表。
- eval stack/value/object ref 的跨线程内存模型。
- 正式 OwnerExecutor 的完整 LPC 调度器形态；当前仅验证了 claim/release、executor-runnable task、main-required 跳过/保留隔离、executor task contract/dispatch contract 诊断、受控只读 allowlist 和 worker v2 `compute_result` 消费路径。
- heartbeat/callout/input 真正后台并行执行。
- 完整旧 mudlib 级 cross-owner `call_other` message/future 替代链。
- 长时间、高并发、真实 mudlib 验收。

## 不可违反的约束

1. 不允许把任意 `object_t *` 长期跨 owner 或跨线程保存。
2. 不允许后台线程直接遍历主线程 object list。
3. 不允许跨 owner 传 mutable array/mapping/object/function pointer。
4. 不允许同一 owner 被两个 executor 同时 claim。
5. 不允许在 enforced 模式下静默回退到同步 cross-owner `call_other`。
6. 不允许用全局大锁包装解释器作为最终方案。
7. 不允许把短压测结果当作生产完成证明。

## 成功标准

### 工程成功标准

- 所有 owner-bound 入口都有 owner id/epoch。
- 所有后台 LPC 执行都绑定 owner-local `VMContext`。
- 同一 owner 串行性有测试证明。
- 不同 owner 并行性有测试和压测证明。
- stale handle/task/future 均能失败而不是误执行。
- `off/audit/enforced` 三种模式行为清楚且可回滚。

### 性能成功标准

- 多用户命令延迟不因单 owner 的 CPU/heartbeat/callout 阻塞而整体上升。
- 多 owner workload 下 CPU 利用率能跨核心扩展。
- 单 owner workload 不破坏旧语义，也不因调度引入明显额外延迟。
- owner queue 长度、budget yield、executor claim/release 可观测。

### 安全成功标准

- enforced 模式下无未分类 direct cross-owner write。
- owner payload/future result 不包含裸 object/function/buffer/class。
- owner executor 无 VMContext 泄漏、owner 泄漏、execution state 泄漏。
- 旧 mudlib 迁移失败时可以回退到 audit/off。

## 阶段 0：冻结基线和观测口径

目标：确保后续每一步都能回归到可验证状态。

涉及文件：

- `README.md`
- `docs/multicore-runtime.md`
- `docs/multicore-actor-vm-plan.md`
- `src/base/internal/rc.cc`
- `src/include/runtime_config.h`
- `src/vm/internal/owner.cc`
- `src/tests/test_lpc.cc`

任务：

1. 固定 `off/audit/enforced` 配置语义，不再使用文档中的旧 `0/1/2` 作为用户入口。
2. 建立 baseline 指标输出：runtime status、owner thread status、mailbox status、object store status、task/access/message/commit trace、future count；trace 必须暴露稳定 `trace_kind`/`trace_model`，queue 指标必须区分 executor-safe、main-required、runnable owner 和 claimed owner。
3. 为每次重构记录基线命令和结果。
4. 将“当前主线程 owner queue 不是并行执行”写入文档边界。

验收：

- `vm_owner_runtime_status()` 能显示 multicore mode、queue、executor-safe/main-required queue depth、runnable owner、claimed owner、future、cross-owner 计数；`executor_queue_fairness` 能汇总 executor-ready、main-required-only、mixed backlog、claim-blocked owner 与最大 backlog；`vm_owner_executor_trace()` 能显示 `trace_kind=owner_executor_trace`、`trace_model=owner_executor_scheduler_trace`、`executor_contract_version=owner_executor_v1`、`executor_model=owner_executor`，并在事件 mapping 中显示 `trace_model=owner_executor_scheduler_event`、`executor_dispatch_model=descriptor_manifest`、owner claim、budget yield、release 这类调度事件。
- `testsuite/etc/config.test` 在 audit 下稳定运行。
- 文档不再暗示任意 LPC 已可后台并行。

## 阶段 1：补齐 owner 归属规则

目标：让每个对象的 owner 来源可解释、可审计、可复现。

涉及文件：

- `src/vm/internal/owner.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/simulate.cc`
- `src/packages/gateway/gateway.cc`
- `src/packages/gateway/gateway_session.cc`
- `src/comm.cc`
- `src/tests/test_lpc.cc`

任务：

1. 梳理对象创建路径：load、clone、move、exec、gateway session、interactive user、daemon singleton。
2. 保持加载型 singleton、daemon、命令对象默认归 `legacy/main`。
3. clone 继承 prototype owner 或 current object owner，不继承裸 ambient owner scope。
4. move 时仅在 item 没有显式 owner 时继承 destination owner。
5. destruct 时保留原 owner/epoch 用于 stale trace。
6. 新增测试覆盖每个对象生命周期入口。

验收：

- 启动测试 mudlib 后无大量空 owner 对象。
- singleton/command/std service object 不被首个玩家 owner 污染。
- owner epoch 在 owner 变化、clear、destruct 时按预期变化。
- ObjectHandle 能检测 owner/epoch stale，并在同 owner epoch 漂移时返回 `owner_epoch_mismatch`。
- `TestCommandSingletonUsesDefaultOwnerInsidePlayerOwnerScope` 覆盖 command object 在 current object 和 owner scope 均为玩家 owner 时仍归 `legacy/main`，避免命令 singleton 被玩家 owner 污染。
- `TestStdServiceUsesDefaultOwnerInsidePlayerOwnerScope` 覆盖 std shared service 在 current object 和 owner scope 均为玩家 owner 时仍归 `legacy/main`，避免共享服务被玩家 owner 污染。
- `TestSharedStdServicesUseDefaultOwnerInsidePlayerOwnerScope` 覆盖 `std/http`、`std/present_clone`、`std/telnet` 这类带回调状态、socket 状态或 object 查询逻辑的共享 service 在玩家 owner scope 内仍归 `legacy/main`。
- `TestSimulEfunSingletonKeepsDefaultOwnerInsidePlayerOwnerScope` 覆盖 `single/simul_efun` 以及其关键继承 helper `std/all_environment`、`std/json` 在玩家 owner scope 内仍归 `legacy/main`，避免启动核心 singleton/helper 被后续玩家执行上下文污染。
- `TestVirtualObjectUsesDefaultOwnerAndUpdatesStorePath` 覆盖 master `compile_object` 生成的 virtual object 在玩家 owner scope 内仍归 `legacy/main`，并且 object store 的 owner-local directory 记录重命名后的 `test/virtual`，不是临时来源对象路径。
- `TestMoveObjectOwnerInheritanceRespectsExplicitOwner` 覆盖非显式 owner move 继承 destination owner、显式 owner move 不被覆盖、相关 owner epoch 变化规则。
- `TestInteractiveExecPreservesNewObjectOwner` 覆盖普通 interactive `exec()` 迁移 interactive 指针和 command giver 后，新对象保持自身显式 owner/epoch，旧对象 owner/epoch 不被新连接状态污染。
- `TestGatewayDaemonUsesDefaultOwnerForSystemMessages` 覆盖 `/adm/daemons/gateway_d` 在玩家 owner scope 内加载时仍归 `legacy/main`，gateway system message 入口绑定 daemon owner/epoch 并记录 `receive_system_message` trace；`TestGatewaySessionExecLogonKeepsSessionLookupWorking` 覆盖 gateway `exec()` 后 session lookup 指向新 user object，`gateway_session_info()` 暴露的新 user `object_name`、`owner_id`、`owner_epoch` 与实际对象一致，disconnect/remove interactive 不改写该 owner/epoch。

风险：

- 过度自动继承 owner 会把共享 daemon 变成玩家私有 owner。
- 过度保留 `legacy/main` 会掩盖需要迁移的玩家/session 对象。

## 阶段 2：ObjectHandle 从观测升级为跨 owner 标准引用

目标：跨 owner 不能依赖裸 `object_t *`。

涉及文件：

- `src/vm/object_handle.h`
- `src/vm/internal/object_store.cc`
- `src/vm/internal/simulate.cc`
- `src/vm/internal/apply.cc`
- `src/packages/core/vm_owner.cc`
- `src/tests/test_lpc.cc`

任务：

1. 明确哪些 C++ API 可以返回裸 `object_t *`，哪些跨 owner API 必须返回 handle。
2. 为 owner message/future、snapshot、trace 统一携带 ObjectHandle 元信息。
3. 在 enforced 下禁止 cross-owner payload 携带 object。
4. 在 handle resolve 前强制 owner id、epoch、object id、path、destructed 状态全部匹配。
5. 对 handle resolve 失败路径做错误分类：destructed、owner changed、epoch changed、path missing。

验收：

- destruct 后旧 handle resolve 失败并返回 `record_destructed`。
- owner 变化后旧 handle resolve 失败并返回 `owner_mismatch`。
- 同 owner epoch 漂移后旧 handle resolve 失败并返回 `owner_epoch_mismatch`。
- invalid handle、missing path、object id mismatch 有独立 resolve 状态。
- owner async target stale 时 future failed。
- trace 能报告 target handle current 状态和具体 resolve 失败状态。

## 阶段 3：owner shard object store 正式化

目标：把当前状态索引升级为可执行分片模型。

涉及文件：

- `src/vm/internal/object_store.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/vm.cc`
- `src/vm/internal/context.cc`
- `src/packages/core/heartbeat.cc`
- `src/packages/core/call_out.cc`

任务：

1. `VMObjectShard` 最小结构和只读合同已引入，明确拆分 status record、execution shard、`object_directory`、`local_records`、`local_objects`、`local_object_index`、`destructed_records`、live/destructed path index 与当前 global index bridge storage model；`status.objects` 现在只作为兼容统计跟随 shard directory 增删，不再作为 directory lookup 来源。后续要把该合同从诊断面推进到真实 owner-local storage。
2. 每个 shard 维护 local objects、pending destruct、heartbeat queue、callout queue、message queue。
3. 主线程保留 global index，但不直接拥有所有执行队列。
4. owner executor 只能访问当前 claimed shard 的 local objects。
5. 设计 shard migration：对象 owner 改变时，必须走迁移协议，而不是直接改 map。
6. destruct 改成 owner-local deferred destruct，主线程只做全局 index 清理。

验收：

- `vm_object_store_status()` 显示每个 owner shard 的 local objects 和 runnable tasks，并在顶层暴露 `store_kind=vm_object_store`、`status_model=object_store_status`、`directory_model=owner_local_object_directory`、`storage_model=global_index_bridge`，并通过 `vm_object_shard` 合同明确报告 status model、execution model、`object_directory`、`local_records`、`local_objects`、`local_object_index`、`destructed_records`、live/destructed path index 与 global index bridge 边界；`object_directory_count`、`owner_local_directory_count`、`owner_local_record_count`、`owner_local_object_ref_count`、`owner_local_object_ref_index_count` 与 `owner_local_path_index_count` 在 live 路径保持一致，destruct 后 `owner_local_object_ref_count=0`、`owner_local_object_ref_index_count=0`，`owner_local_destructed_record_count` 和 `owner_local_destructed_path_index_count` 保留 tombstone 诊断但不产生 directory entry；`owner_local_live_index_consistent`、`owner_local_object_ref_index_consistent`、`owner_local_live_path_index_consistent` 和 `owner_local_destructed_path_index_consistent` 用于观测 live/ref/path/tombstone 索引是否漂移；聚合层额外报告 `owner_local_record_total`、`owner_local_object_ref_total`、`owner_local_object_ref_index_total`、`owner_local_destructed_record_total`、live/destructed path index total、`owner_local_orphan_record_total`、`global_record_total`、`global_live_record_total`、`global_destructed_record_total`、`owner_local_to_global_mismatch_record_total`、`global_to_owner_local_record_mismatch_record_total`、`global_to_owner_local_mismatch_record_total`、`owner_local_record_index_ready`、`owner_local_canonical_record_ready`、`owner_local_store_ready`、`global_record_bridge_consistent`、`global_record_bridge_retirement_ready`、`global_live_object_bridge_retirement_ready`、`owner_local_to_global_bridge_consistent`、`global_to_owner_local_bridge_consistent`、`owner_local_global_bridge_check=bidirectional`、`global_live_object_bridge_ready/source`、`global_record_bridge_ready/source` 和兼容聚合字段 `owner_local_global_bridge_consistent`，作为后续移除 global canonical record 前的双向门禁、owner-local canonical record readiness、global record 基线与 bridge 来源观测。
- `vm_object_store_owner_lookup_status(owner_id, object_id)` 与 `vm_object_store_owner_path_lookup_status(owner_id, object_path)` 能按 owner-local directory/path index 口径查询对象是否仍属于该 owner，并通过 `owner_local_object_ref_found`、`owner_local_object_ref_index_found`、`owner_local_object_ref_index_source`、`owner_local_object_pointer_index_found`、`owner_local_object_pointer_index_source`、`owner_local_resolve_found`、`owner_local_resolve_source`、`owner_local_canonical_record_ready` 和 `owner_local_store_ready` 报告是否能从 shard-local `local_objects` 与反向 `local_object_index` 得到可解析 live object，当前 owner shard record/ref/path/tombstone 镜像是否满足 canonical readiness，以及该镜像是否已经可承担 lookup/resolve；`owner_local_store_ready=1` 必须继续和 `owner_local_store_complete=0`、`global_index_bridge=1` 同时出现，防止把可查询状态误读为完整 owner-local object store。`vm_object_store_owner_resolve(owner_id, object_id)` 与 `vm_object_store_owner_path_resolve(owner_id, object_path)` 只在 shard-local live object reference 正反向完整命中时返回对象。owner migration 后旧 owner lookup 返回 `owner_mismatch` 且 live path index 清空，旧 owner resolve 返回空；该 mismatch 诊断优先来自其他 owner shard，并通过 `owner_local_cross_shard_record_found`/`owner_local_cross_shard_record_source` 与 `owner_local_global_record_found=0` 证明没有依赖 global fallback；新 owner lookup/resolve 命中 live record/path index/object ref；destruct 后 lookup 保留 record/path tombstone 但不再作为 directory entry，resolve 返回空。
- 通用 object_id/path record fallback 查询已先检查 `VMObjectShard.local_records`、`VMObjectShard.destructed_records`、`VMObjectShard.object_path_index` 和 `VMObjectShard.destructed_path_index`；当 `global_record_bridge_retirement_ready=1` 时，缺失查询会跳过 global record fallback 并通过 `owner_local_global_record_fallback_skipped=1`、`owner_local_global_record_fallback_reason=global_record_bridge_retirement_ready` 暴露原因，path lookup 还会通过 `owner_local_global_record_scan_bridge_skipped=1`、`owner_local_global_record_scan_bridge_skip_reason=global_record_bridge_retirement_ready` 证明没有执行 `global_object_records.path_scan_bridge`；当 `global_live_object_bridge_retirement_ready=1` 时，缺失 path lookup 会跳过 global live-object fallback，并通过 `owner_local_global_live_object_fallback_skipped=1`、`owner_local_global_live_object_fallback_reason=global_live_object_bridge_retirement_ready` 暴露原因；只有 readiness 未满足时才通过显式 global object_id/path/pointer helper 回落 global object records，path record fallback 在 live-object bridge 已可退休时也不会先查 `ObjectTable`，并通过 `owner_local_global_record_scan_bridge_used/found/source` 暴露显式 path scan bridge 是否被使用和命中；当 `global_record_bridge_retirement_ready=1` 且 live-object bridge 只允许查 live object、不附带 record 时，pointer record bridge 会被跳过，并通过 `owner_local_global_record_pointer_bridge_skipped=1`、`owner_local_global_record_pointer_bridge_skip_reason=global_record_bridge_retirement_ready` 暴露。所有直接 `ObjectTable` 查找已集中到单一 global live-object bridge helper，owner lookup 的最后 fallback 也只调用显式 global helper，混合 owner-local/global record helper 已移除，避免把 owner-local 命中误标成 global 来源。这只是减少 global bridge 依赖并让 bridge 来源可观测的中间态；status/contract 已明确暴露 `global_live_object_bridge_ready/source` 与 `global_record_bridge_ready/source`，lookup status 也暴露 `global_live_object_bridge_retirement_ready`、`owner_local_global_live_object_found/source`、`owner_local_global_live_object_fallback_skipped/reason`、`owner_local_global_record_found/source`、`owner_local_global_record_scan_bridge_used/found/source/skipped/reason` 与 `owner_local_global_record_pointer_bridge_used/found/source/skipped/reason`，ObjectHandle status 暴露 `global_live_object_found/source`、`global_live_object_fallback_skipped/reason`、`global_live_object_bridge_retirement_ready`、`global_record_found/source`、`global_record_pointer_bridge_used/found/source/skipped/reason`、`global_record_fallback_skipped/reason` 和 `global_record_bridge_retirement_ready`，但不改变 `owner_local_store_complete=0` 与 `global_index_bridge=1` 的状态口径。
- object_id 方向的 `object_records` 扫描已拆成显式 `global_object_records.object_id_scan_bridge`，owner lookup status 暴露 `owner_local_global_record_id_scan_bridge_used/found/source/skipped/reason`，ObjectHandle status 暴露 `global_record_id_scan_bridge_used/found/source/skipped/reason`。pointer 方向的 `object_records.find(object_t*)` 已拆成显式 `global_object_records.pointer_bridge`，owner path lookup status 暴露 `owner_local_global_record_pointer_bridge_used/found/source/skipped/reason`，ObjectHandle status 暴露 `global_record_pointer_bridge_used/found/source/skipped/reason`。当 `global_record_bridge_retirement_ready=1` 时，object_id 缺失查询、ObjectHandle object-id fallback，以及 live-object bridge 只允许找 live object 而不附带 global record 的 pointer fallback 都必须跳过对应 bridge，并用 `global_record_bridge_retirement_ready` 作为 skip reason；只有 readiness 未满足时才允许这些 bridge 作为迁出前诊断 fallback。
- object store、owner shard、owner lookup/path lookup 与 shard contract 必须在 `owner_local_store_complete=0` 时暴露 `owner_local_store_complete_blocker=global_index_bridge_active`，把“lookup/resolve ready 但 global index bridge 尚未退休”固定为机器可读合同，避免后续把 readiness 误判为完整 owner-local store。
- `vm_object_handle_resolve_status()` 对 live/current handle 优先使用 owner-local shard 快路径，只有 live record、local object ref、live path index、owner id 和 owner epoch 全部一致才返回 `current` 并报告 owner-local 来源；同 owner object id mismatch 会优先由 owner-local path index 诊断并报告 `diagnosed_via_owner_local_path_index`，path mismatch、owner epoch 漂移和 destruct tombstone 会优先由 owner-local live/tombstone record 诊断并报告 `diagnosed_via_owner_local_store`，跨 owner migration 旧 handle 的 `owner_mismatch` 会先由其他 owner shard 诊断并报告 `diagnosed_via_owner_local_cross_shard`。最后的 `ObjectTable` live-object fallback 已收束为显式 global live-object bridge，resolve result 和 `vm_object_handle_status()` mapping 均通过 `global_live_object_found`/`global_live_object_source` 暴露同一来源；global bridge 诊断路径仍作为当前未完成迁出项保留并报告 `diagnosed_via_global_index`；当 `global_live_object_bridge_retirement_ready=1` 时，ObjectHandle 会跳过 global live-object fallback 并报告 `global_live_object_fallback_skipped=1` 与 `global_live_object_fallback_reason=global_live_object_bridge_retirement_ready`；当 `global_record_bridge_retirement_ready=1` 且 live-object bridge 缺失、已跳过或只允许查 live object 而不附带 global record 时，会跳过 global record fallback 并报告 `global_record_fallback_skipped=1` 与 `global_record_fallback_reason=global_record_bridge_retirement_ready`。
- 同 owner 对象只在一个 shard。
- owner 改变产生 migration trace。
- 非 owner 线程不能同步或遍历全局 object store。

风险：

- object list 与 living table、environment/inventory 链表存在历史耦合。
- destruct 顺序和 `move_or_destruct` 语义容易破坏兼容性。

## 阶段 4：OwnerExecutor 替代实验 owner thread

目标：把 owner thread 从验证工具升级为正式 LPC 调度器。

涉及文件：

- `src/vm/internal/owner.cc`
- `src/vm/owner.h`
- `src/vm/internal/context.cc`
- `src/backend.cc`
- `src/tests/test_lpc.cc`

任务：

1. 新增 `OwnerExecutor` 抽象，封装 claim/release、budget、thread-local context、error cleanup。
2. 统一 runnable owner 队列，区分 main-required task 与 executor-safe task。
3. 保证同一 owner 只能被一个 executor claim。
4. 每个 owner 执行固定 task budget 后 yield。
5. 执行后必须检查 owner、execution、error、object_store、canary 状态已清理。
6. 把当前 owner thread counters 升级为 executor metrics。

验收：

- 两个不同 owner 的 executor-safe task 可并行。
- 同一 owner `max_owner_parallel == 1`。
- executor claim/release 数量匹配。
- context leak counter 为 0。
- worker v2 `compute_result` 可由 owner executor 消费，`thread_compute_result_completed` 增长，owner future 从 pending 进入 completed/failed；成功 future 携带 frozen mapping result，timeout/失败 future 携带 failed/error，且 pending future 不残留。
- 同一 owner mailbox 前部存在 main-required task 时，owner executor 可以跳过该任务并执行后续 executor-safe task；main-required task 不会被后台 executor 执行，仍可被状态接口观测为 main-required backlog。
- `vm_owner_runtime_status()` 与 `vm_owner_thread_status()` 暴露 `executor_contract_version=owner_executor_v1`、`executor_model=owner_executor`、`executor_dispatch_model=descriptor_manifest`、`executor_lpc_model=default_closed_allowlist`、`ordinary_lpc_default_policy=default_closed`、`executor_task_contract`、`executor_task_dispatch_contracts` 和逐方法 `executor_lpc_task_contracts`，明确 `compute_result`、无目标 `owner_message`、`executor_probe` 和受控注册 `lpc_task` 的 executor-safe 合同，有 target handle 的 `owner_message` 的 main-required 合同，以及普通 `lpc` 的 rejected/default-closed 合同；普通 `lpc` 与 `owner_state` 仍可由 executor 取走并拒绝/guard，避免拒绝型任务卡住 mailbox，但 `executor_safe=0`。status、fairness、mailbox mapping 和 executor trace 同时暴露 `executor_runnable`/runnable backlog 与 `executor_safe`/safe backlog，并拆分 `executor_runnable_task_dispatched` 与 `executor_safe_task_dispatched`，避免把“可消费/已拒绝”误解为“可后台安全执行”。`owner_message` 合同与 mailbox task mapping 共享 route 分类，并暴露 `requires_owner_mailbox`/`requires_owner_main_queue`；mailbox task mapping 额外暴露 `task_contract_key`、`task_executor_mode`、`dispatch_kind` 和 `executor_runnable`；`vm_owner_lpc_task()` 提交结果也暴露 `task_contract`、`executor_mode`、`route`、`result_policy` 和 `contract_reason`，未注册 task 仍 default-closed。该合同在 C++ 单测和 `testsuite/single/tests/efuns/owner_executor_contract.c` 的 LPC 层回归中同时验证；`testsuite/single/tests/efuns/owner_payload.c` 同时验证 target-handle `owner_call_async()` 必须经 `vm_owner_drain_main()` 显式处理 main-required route，并且 owner 迁移后的 stale target 会以 `owner_mismatch` 失败而不执行目标方法。
- 同一 owner 的 executor-safe backlog 超过 `executor_task_budget` 时，`executor_budget_yields` 增长，当前 claim 会释放并重新调度剩余 backlog；runtime/thread status 会记录最近一次 budget yield 的 owner 和剩余 backlog；`executor_queue_fairness` 会暴露 mixed backlog、main-required-only backlog 和最大 safe/main-required backlog；独立 `vm_owner_executor_trace()` 能通过顶层 `owner_executor_scheduler_trace` 与事件级 `owner_executor_scheduler_event` 合同观察 owner_claimed、budget_yield、owner_released 调度事件，且事件会绑定 `executor_contract_version=owner_executor_v1` 和 `executor_dispatch_model=descriptor_manifest`；最终 backlog 可 drain 完成，且 same-owner executor conflict 仍为 0。
- owner 卡住时其他 owner 可以继续执行，至少在可中断/budget 边界可观测。

风险：

- 如果 eval stack 未 owner-local，不能执行普通 LPC。
- executor-safe task 必须白名单化，不能默认开放。

## 阶段 5：VMContext 收口剩余全局状态

目标：让后台 owner executor 具备执行 LPC 的上下文前提。

涉及文件：

- `src/vm/context.h`
- `src/vm/internal/context.cc`
- `src/vm/internal/base/interpret.cc`
- `src/vm/internal/base/machine.h`
- `src/vm/internal/base/function.cc`
- `src/vm/internal/apply.cc`
- `src/vm/internal/simulate.cc`

任务：

1. 审计所有解释器全局状态，分类为 owner-local、thread-local、immutable global、main-only。
2. 将 eval stack、control stack、apply return 临时值纳入 `VMContext` 或 owner execution frame。
3. 将 error context、eval flags、handler depth 的所有写入口改为 VMContext API。
4. 将 `this_player()`、`previous_object()`、`origin()` 等语义绑定到当前 owner execution frame。
5. 禁止后台线程读取未迁移的 process-global mutable VM 状态。

验收：

- `rg` 不再出现绕过 VMContext API 的关键全局状态写入。
- detached context setter 测试继续通过。
- owner executor 中 probe/canary 能执行且状态清理为 0 泄漏。
- `vm_owner_runtime_status()` 与 `vm_owner_thread_status()` 的 `vm_context_contract` 暴露 `ordinary_lpc_readiness_gates`，并以 `ordinary_lpc_readiness_gate_model=all_gates_required_before_open` 固定普通后台 LPC 开放门禁。当前 gate 计数为 11，已满足 6 项，阻塞 5 项；`eval_stack_owner_local` 已完成：eval stack 是 thread-local owner execution stack，并通过 VMContext eval stack snapshot 在 owner executor task 内 owner-bound、task 后 cleared。剩余阻塞项包括 control stack、value stack、apply return、cross-owner object ref 和完整 owner-local object store，`ordinary_lpc_next_blocker=control_stack_owner_local`，`ordinary_lpc_ready=0` 不能被受控 allowlist task 误读为普通 LPC 已可后台执行。

风险：

- 解释器栈迁移影响面最大，必须小步提交、每步测试。

## 阶段 6：冻结值与跨 owner payload 协议正式化

目标：封住 mutable value 跨线程共享。

涉及文件：

- `src/packages/core/vm_owner.cc`
- `src/packages/core/vm_worker.cc`
- `src/vm/frozen_value.h`
- `src/vm/internal/frozen_value.cc`
- `src/vm/internal/owner.cc`
- `src/vm/internal/base/array.cc`
- `src/vm/internal/base/mapping.cc`
- `src/vm/internal/base/svalue.cc`
- `src/vm/internal/base/function.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/stralloc.cc`
- `testsuite/single/tests/efuns/owner_payload.c`
- `testsuite/single/tests/efuns/worker_payload.c`

任务：

1. 定义 `OwnerFrozenValue` 的正式语义：deep copy、不可含 object/function/buffer/class。
2. mapping key 继续限制为 string。
3. 对 string refcount 做 atomic 或确保跨线程只读共享安全。
4. 对 array/mapping/class 明确 owner-local mutable，不允许跨 owner 共享。
5. future result 必须 frozen/deep copy；受控 off-main LPC task 的 result 已进入 owner future，后续要把相同约束推广到正式 domain task。
6. worker snapshot 输入与 owner message payload 已接入同一 `vm_frozen_value_safe()` 安全检查库，避免双实现漂移；后续正式 domain task 也必须复用该库。
7. `vm_owner_runtime_status()` 与 `vm_owner_thread_status()` 暴露 `frozen_payload_contract`，把 validator、deep copy、最大深度、允许/拒绝类型和 owner/worker/future/snapshot 路径策略固定为机器可读合同。

验收：

- payload 嵌套、mapping traversal、非法类型、深度限制都有测试。
- worker 公开 efun 对 object/function/buffer/class、非字符串 mapping key、深层嵌套和 batch unsafe snapshot 有 LPC 层回归。
- future result 包含 frozen_result 标志。
- runtime/thread status 的 `frozen_payload_contract` 有 C++ 与 LPC 层合同测试。
- 跨 owner payload 中 object/function/buffer/class 全部拒绝。

## 阶段 7：cross-owner call_other 替代链

目标：让 enforced 模式不只是阻断，还能提供完整替代能力。

涉及文件：

- `src/packages/core/efuns_main.cc`
- `src/vm/internal/apply.cc`
- `src/vm/internal/simulate.cc`
- `src/packages/core/vm_owner.cc`
- `src/packages/core/core.spec`
- `src/tests/test_lpc.cc`

任务：

1. 保持 same owner `call_other` 同步 fast path。
2. audit 模式记录所有 cross-owner `call_other`，包含 source/target/method/owner/epoch。
3. enforced 模式继续阻断同步 `call_other`。
4. 完善 `owner_call_async(object, method, mapping payload)`，用 ObjectHandle、owner message、future 承载调用；当前最小样例已经可替代一个 enforced 下被阻断的 cross-owner `call_other`。
5. 目标 owner 执行 method 后，结果必须 frozen 后写入 future；非 frozen 结果必须 failed。
6. 调用方只能 poll future 或注册 continuation，不能同步等待跨 owner LPC。

验收：

- enforced 下 cross-owner `call_other` 必定失败。
- `owner_call_async()` 能替代一个核心读/写交互路径，且测试同时覆盖 direct call 被拒、async future completed、result frozen。
- target stale 时 future failed，并暴露具体 ObjectHandle resolve 状态。
- result 非 frozen 时 future failed。
- message trace 从 submitted 到 completed/failed 状态同步，并能暴露 `trace_kind=owner_message_trace`、`trace_model=owner_message_lifecycle_trace`、事件 `trace_model=owner_message_lifecycle_event`、`owner_mailbox`/`owner_main_queue` route、terminal 分类、result key、失败原因、queued_on_main、target handle resolve 状态和 frozen result；`testsuite/single/tests/efuns/owner_payload.c` 已在 LPC 层覆盖 `owner_call_async()` 的 submitted、completed 和 stale-target failed trace 合同。

风险：

- 旧 mudlib 大量同步调用依赖返回值，必须配套迁移业务逻辑。

## 阶段 8：input/gateway owner executor 化

目标：玩家命令从主线程 owner queue 迁移到 owner executor。

涉及文件：

- `src/comm.cc`
- `src/user.cc`
- `src/interactive.h`
- `src/packages/gateway/gateway.cc`
- `src/packages/gateway/gateway_session.cc`
- `src/vm/internal/owner.cc`
- `src/vm/internal/context.cc`

任务：

1. 网络层只负责读包、解析、session 定位、投递任务。
2. interactive/user 绑定 session owner。
3. command task 携带 ObjectHandle、owner id、owner epoch、input payload。
4. executor 执行命令前恢复 `current_interactive`、`command_giver`、execution frame。
5. 单 session owner 保持命令串行。
6. gateway create/destroy/send/inject 都按 owner 投递。

当前已落地的阶段 8 合同增量：

- `vm_owner_runtime_status()` 与 `vm_owner_thread_status()` 暴露 `gateway_owner_task_contract`，固定当前 input/gateway 仍处于 `owner_main_queue_bridge` 和 `main_required_before_owner_executor` 状态；`ordinary_lpc_ready_required=0`，不会打开普通 LPC 后台执行。
- 合同逐项声明 `gateway_receive`、`process_user_command`、`gateway_logon`、`gateway_disconnected` 的 route、owner scope、`current_interactive`、`command_giver`、stale policy 和单 owner 串行要求；其中 receive/command 走 `owner_main_queue`，logon/disconnected 仍是 `direct_main_owner_scope`。
- `process_user_command` main task 已通过 `vm_owner_enqueue_main_task_with_payload()` 携带 current ObjectHandle、owner id、owner epoch、`payload_key=gateway_command_input`、`gateway_command_buffer_metadata_v1` frozen payload 元数据，以及 `gateway_command_execution_frame_v1` / `owner_scope_current_interactive_command_giver` execution-frame 捕获元数据；trace 明确 `input_payload_policy=buffer_metadata_no_raw_command_text`，不把原始命令文本写入公开 trace，并明确 `execution_frame_executor_ready=1`。同一 trace 还暴露 `execution_frame_restore_policy=owner_executor_vmcontext_restore`、`execution_frame_restore_ready=1`、`execution_frame_restore_blocker=\"\"`，固定当前 command frame restore 已具备 owner executor 受控 VMContext 恢复入口，但该入口只恢复命令执行帧，不调用 LPC，也不表示玩家命令已可后台执行。
- gateway command 输入缓冲区 snapshot 合同已机器可读化：`command_input_source=interactive_text_buffer`、`command_text_snapshot_policy=owner_private_redacted_from_trace`、`command_text_snapshot_ready=1`、`command_executor_blocker=ordinary_lpc_not_ready`。实际 trace 只暴露 pending bytes、buffer offset、session id、snapshot bytes 和 redacted 标志，不暴露 raw command text；这固定了 owner-private snapshot 已具备，且 owner main task 已能用该 snapshot 在主线程消费首条命令；当前 owner executor 仍不能直接执行 `process_user_command` 的 LPC 逻辑，因为下一阻塞已转为普通 LPC readiness。
- gateway command 命令消费模型合同已机器可读化：`command_consume_model=owner_owned_snapshot_main_thread_consume`、`command_consume_snapshot_ready=1`、`command_consume_executor_ready=1`、`command_consume_blocker=""`。实际 main task trace 和 frozen payload 同步携带 `command_consume_*` 字段，说明 owner main task 已用 owner-private snapshot 在主线程校验并消费首条命令，`interactive_t::text/text_start/text_end/CMD_IN_BUF` 只作为 snapshot 匹配和 buffer 推进来源；这仍不是 owner executor 可独立执行玩家命令。`gateway_owner_task_contract` 进一步暴露 `command_executor_readiness_gates`：5 个 gate 中 `owner_epoch_target_handle_guard`、`owner_owned_command_snapshot`、`owner_owned_command_consume`、`owner_executor_command_consume_entry` 和 `owner_executor_frame_restore` 均已满足；当前 `command_executor_next_gate=ordinary_lpc_ready`、`command_executor_next_blocker=control_stack_owner_local`，说明 eval stack 已过 gate，下一阻塞是 control stack owner-local 化，因此不能绕过普通 LPC readiness 直接打开后台玩家命令执行。
- gateway command execution-frame restore 合同已机器可读化：`command_execution_frame_restore_policy=owner_executor_vmcontext_restore`、`command_execution_frame_restore_ready=1`、`command_execution_frame_restore_blocker=\"\"`；实际 main task trace 和 frozen payload 同步携带 `execution_frame_restore_*` 字段，说明 owner executor 已有受控 frame restore 入口，可恢复 owner scope、`current_interactive`、`command_giver` 与命令执行帧，但不会调用 `process_user_command` 或执行普通 LPC。
- gateway command stale 合同已机器可读化：`command_stale_guard=owner_epoch_target_handle_guard`、`command_stale_trace_state=main_stale`、`command_stale_target_status=owner_epoch_mismatch`。入队后 owner epoch 漂移时，主线程 owner queue 会在 dispatch 前丢弃旧 task，trace 保留 frozen payload 和 execution-frame 元数据但不消费旧命令。
- C++ 层 `TestVmOwnerRuntimeReportsExecutorTaskContract`、`TestVmOwnerExecutorCommandConsumeEntryDispatchesWithoutLpc`、`TestGatewayCommandTaskCarriesOwnerHandlePayload`、`TestGatewayCommandMainQueueDropsStaleOwnerEpoch` 和 LPC 层 `testsuite/single/tests/efuns/owner_executor_contract.c` 同时验证该合同，防止后续迁移时误把 consume entry 或主线程桥接解释为已完成后台 owner executor 玩家命令执行。

验收：

- 单玩家命令顺序不变。
- 多玩家不同 owner 命令可并行。
- `this_player()`、`current_interactive`、`command_giver` 语义正确。
- gateway session 生命周期不依赖主线程直接执行 LPC。
- 断线、reconnect、session stale 不误执行旧命令。
- 当前增量验收：`gateway_owner_task_contract` 可由 C++ 与 LPC 层读取，且明确 gateway/input 仍是 main-required bridge；`process_user_command` 的 main task trace 已可验证 ObjectHandle、owner epoch、frozen payload 元数据、interactive text buffer 未快照化 blocker、主线程 interactive buffer consume blocker 和 execution-frame 捕获元数据；入队后 owner epoch 漂移会以 `main_stale` / `owner_epoch_mismatch` 失败而不执行旧命令。`command_executor_readiness_gates` 现在把下一段拆成 owner-owned command snapshot、command consume ownership transfer、executor command consume entry、executor frame restore 四个未满足 gate。真正并行执行仍留待这些 gate 与 object store 门禁完成后再打开。

风险：

- command path 涉及 mudlib 行为最多，必须先从 audit 模式统计高频跨 owner 访问。

## 阶段 9：heartbeat/callout owner-local 化

目标：让世界 tick 能按 owner 分片并行。

涉及文件：

- `src/packages/core/heartbeat.cc`
- `src/packages/core/call_out.cc`
- `src/backend.cc`
- `src/vm/internal/object_store.cc`
- `src/vm/internal/owner.cc`

任务：

1. heartbeat 注册到 object owner shard。
2. callout 注册到目标 object/function owner shard。
3. backend 只推进时间，把到期任务标记为 runnable。
4. owner executor 执行到期 heartbeat/callout。
5. cross-owner callout 参数中 object 必须转换为 handle 或拒绝。
6. owner epoch 变化后 stale heartbeat/callout 必须跳过。

验收：

- 不同 owner heartbeat 可并行。
- 同 owner heartbeat/callout 顺序稳定。
- 高频 NPC/房间不会阻塞所有玩家。
- stale heartbeat/callout 不执行。

风险：

- heartbeat 修改 heartbeat 队列时的历史语义复杂，必须保持兼容。

## 阶段 10：async/db/file/DNS/socket 回调 owner executor 化

目标：外部 I/O 完成后回到正确 owner，而不是主线程直接执行 LPC。

涉及文件：

- `src/packages/async/`
- `src/packages/db/`
- `src/packages/core/file.cc`
- `src/packages/core/dns.cc`
- `src/packages/sockets/socket_efuns.cc`
- `src/packages/external/`

任务：

1. 每个 async request 捕获 callback owner handle。
2. completion 投递到 owner executor。
3. owner stale/destructed 时 drop callback 并记录 trace。
4. socket read/write/close callback owner executor 化。
5. `socket_release` 暂保留同步路径，直到设计替代 handshake。
6. DB/file result payload 必须 frozen/deep copy。

验收：

- async completion 不跨 owner 修改对象。
- DNS/socket/file/db 回调 stale 时安全丢弃。
- 登录、存档、网关事件闭环正常。
- `socket_release` 同步例外在文档和代码中都有明确边界。

## 阶段 11：VM worker 并入统一 future/message 体系

目标：compute worker 成为 owner runtime 的纯计算后端，而不是旁路系统。

涉及文件：

- `src/vm/internal/worker.cc`
- `src/vm/internal/owner.cc`
- `src/packages/core/vm_worker.cc`
- `src/packages/core/vm_owner.cc`

任务：

1. 保持 worker 只执行 pure/frozen CPU task。
2. worker 不允许触碰 object store。
3. worker async result 必须投递回发起 owner future；成功结果必须是 frozen/deep-copy data，失败只暴露 error。
4. worker task 与 owner message 使用统一 future 状态机。
5. 为 `snapshot_digest`、`actor_score`、`combat_damage` 增加真实业务 benchmark。

验收：

- worker task 的 owner future id 可查询。
- worker timeout/TTL/failure 正确反映到 future。
- worker v2 成功/失败结果先进入 owner queue，再可由 owner executor 消费 `compute_result` 并完成 owner future。
- worker v2 `bench`、`snapshot_digest`、`actor_score`、`combat_damage` 成功 future 携带 frozen mapping result，timeout/失败 future 不伪造 result。
- `vm_worker_task()`、`vm_worker_submit()` 和 `vm_worker_submit_batch()` 的输入拒绝合同与 owner payload 使用同一 frozen-value 规则。
- 同 owner worker task 串行，不同 owner 可并行。
- worker 不读取任何 `object_t *`。

## 阶段 12：真实 mudlib audit 迁移

目标：让引擎改造在真实业务上成立。

素材：

- 本地存在 XiaKeXing 运行树和 loadtest 工具，但这些属于本地验证素材，不应进入公开仓库规则。

执行：

1. 使用新 driver 替换测试运行树 driver。
2. `multicore mode : off` 下跑兼容 smoke。
3. 切 `audit`，收集 cross-owner `call_other`、present、move、destruct、parser、mutable payload、stale handle。
4. 按审计结果迁移 mudlib：daemon/service、player/session、room/NPC/item。
5. 对高频同步返回调用改成 snapshot 或 owner future。
6. 切 `enforced` 做短验收。
7. 扩展为长时间、多用户、多场景压测。

验收：

- 多用户登录稳定。
- 玩家命令进入 session owner。
- 主要 daemon 不被玩家 owner 污染。
- enforced 下核心命令闭环成功。
- 长压测无 timeout、断线、VMContext leak、future 堆积。

风险：

- 旧 mudlib 依赖同步返回值，迁移量可能大于 driver 侧改造。

## 阶段 13：清理 legacy/main 例外

目标：减少默认 owner 对真实问题的掩盖。

涉及文件：

- `src/vm/internal/owner.cc`
- `src/vm/internal/simulate.cc`
- `src/tests/test_lpc.cc`
- mudlib 侧 owner 规则

任务：

1. 统计 `legacy/main` 对象类型和访问频率。
2. 将真正共享 daemon/service 显式标记为 `service:<name>`。
3. 将玩家/session 相关对象迁移出 `legacy/main`。
4. 对不能迁移的 legacy 对象建立白名单和审计说明。
5. enforced 模式下逐步缩小默认 owner bypass 范围。

验收：

- `legacy/main` 只保留 master、simul_efun、系统命令、共享 daemon 等明确对象。
- audit 报告中无大面积玩家对象落在 `legacy/main`。
- enforced 仍能通过核心测试。

## 阶段 14：生产化压测与回滚

目标：证明多核化可部署，而不是只在单元测试里成立。

压测维度：

- 用户数：1、3、10、50、100。
- 模式：off、audit、enforced。
- 场景：登录、移动、聊天、战斗、物品、任务、存档、断线重连、socket/gateway。
- 时长：短 smoke、30 分钟、2 小时、隔夜。

指标：

- 命令成功率。
- timeout/断线数。
- 平均/P95/P99 命令延迟。
- owner queue depth。
- main queue depth。
- executor budget yields。
- future pending/completed/failed。
- VMContext leak counter。
- object_store sync rejection。
- CPU 核心利用率。

回滚：

- 任意阶段都必须可切回 `audit` 或 `off`。
- enforced 只在核心路径压测稳定后打开。
- 若 future pending 持续增长或 context leak 非 0，必须阻断发布。

## 推荐执行顺序

1. 固定文档和 baseline 指标。
2. 补 owner 归属规则测试。
3. 把 ObjectHandle 作为跨 owner 标准引用。
4. owner shard 从状态索引升级为执行模型。
5. 完成 VMContext 剩余执行栈/value 状态收口。
6. 完成 frozen payload/future 协议。
7. 补齐 OwnerExecutor scheduler trace、budget、公平性和 default-closed 合同诊断面。
8. 实现正式 OwnerExecutor。
9. 先迁移 compute result 和无 target message。
10. 再迁移 input/gateway。
11. 再迁移 heartbeat/callout。
12. 再迁移 async/db/file/DNS/socket callback。
13. 扩展受控 owner-local LPC task allowlist 到正式注册和审计模型。
14. 用真实 mudlib audit 迁移。
15. enforced 长压测。
15. 缩小 legacy/main 例外。

## 每阶段必须新增的测试

| 阶段 | 必测内容 |
| --- | --- |
| owner 归属 | load/clone/move/exec/destruct owner/epoch |
| ObjectHandle | stale path、owner changed、destructed、epoch mismatch |
| shard | owner shard runnable、migration、destruct queue |
| executor | same owner 串行、different owner 并行、budget yield、context cleanup |
| VMContext | 所有全局状态 setter/scope 不泄漏 |
| payload | deep copy、非法类型、mapping key、深度限制 |
| call async | completed、failed、stale target resolve 状态、non-frozen result |
| input | this_player/current_interactive/command_giver 语义 |
| heartbeat/callout | stale、顺序、跨 owner 参数 |
| async/socket | stale owner drop、result frozen、callback ordering |
| pressure | queue/future 不堆积，P95/P99 延迟稳定 |

## 禁止采用的捷径

- 用一个全局 mutex 包住所有 LPC 执行后宣称多核化。
- 让后台线程直接访问 `obj_list`。
- 把 object 指针塞进 owner payload。
- 在 enforced 下为了兼容静默执行 cross-owner 同步调用。
- 只看短命令 smoke 就宣布生产可用。
- 为单个 mudlib 特例污染 driver 通用规则。

## 下一步最小可执行任务

第一批真正应该做的不是继续开放后台 LPC，而是收口边界：

1. owner 归属规则已覆盖 load/clone/move/exec/destruct、command singleton、std database/http/present_clone/telnet shared service、`single/simul_efun` 关键 singleton、`/adm/daemons/gateway_d` daemon singleton、master virtual object、普通 interactive exec 和 gateway exec/session lookup 的关键合同；继续补更多真实 mudlib daemon/shared service 的入口级 owner/epoch 回归。
2. `/adm/daemons/gateway_d` 已建立 audit 观测和 owner/epoch 合同；`single/simul_efun` 和 std helper 已补默认 owner 污染防线。下一步继续选择有真实跨 owner 交互的 daemon/shared service，再决定是否迁移为 snapshot/message/future 交互。
3. `vm_frozen_value_safe()` 已抽出公共校验，并已接入 owner payload 与 worker snapshot；继续把同一库接入后续正式 domain task 的输入/输出协议，避免 payload/future 与 domain task 双实现漂移。
4. owner shard 已有 `VMObjectShard` 合同、`status_record`、`execution_shard`、`VMObjectShard.object_directory`、`VMObjectShard.local_records`、`VMObjectShard.local_objects`、`VMObjectShard.local_object_index`、`VMObjectShard.destructed_records`、`VMObjectShard.object_path_index`、`VMObjectShard.destructed_path_index`、owner/object_id lookup/resolve、owner/path lookup/resolve API、ObjectHandle live/current owner-local 快路径、ObjectHandle path-index stale 诊断、live/ref/path/tombstone 一致性状态、owner-local/global bridge 双向一致性门禁、`owner_local_store_ready` lookup/resolve readiness 和 `owner_local_store_complete=0` 状态口径；`status.objects` 只是兼容统计，directory/lookup/resolve 以 shard-local directory、live record snapshot、正反向 live object reference、live path index、destruct tombstone 和 destruct path tombstone 为准，global index bridge 仍负责失败诊断和未迁出的生命周期边界。继续把该合同收口为真实 owner-local object store，不迁移 destruct 语义，直到 resolve/destruct/index 彻底 owner-local 化。
5. OwnerExecutor 合同、trace、budget、公平性和最小 dispatch 已有；继续补正式设计文档和类边界，仍只接 `compute_result`/无 target message，不接普通 LPC。

这五步完成后，才具备继续迁移 input/gateway/heartbeat/callout 到后台 executor 的工程基础。
