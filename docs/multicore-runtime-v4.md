# Multicore Runtime v4 / 多核运行时 v4

## Scope / 范围

Runtime v4 keeps the production multicore contract from Runtime v2 and hardens
the engine around module boundaries, diagnostics, scheduling, backpressure,
object-store fast paths, VM profiling, gateway/session FIFO, and mudlib-facing
error reporting. It does not open arbitrary legacy LPC execution on background
threads.

Runtime v4 继承 Runtime v2 的生产多核合同，并围绕模块边界、诊断、调度、反压、
object-store fast path、VM profiling、gateway/session FIFO 和 mudlib-facing
错误报告做加固。它不会开放任意 legacy LPC 后台执行。

## Runtime Layering / Runtime 分层

Owner runtime modules are expected to stay in this order:

```text
owner_task_manifest -> admission -> owner_scheduler_state -> owner_executor
                                        |-> owner_future_store
                                        |-> owner_trace_store
                                        |-> owner_runtime_metrics
```

`owner.cc` is a facade for efuns, status mappings, and legacy glue. Runtime
state containers belong in dedicated modules. The source-level guard test
`DriverTest.TestOwnerRuntimeLayeringGuardKeepsStoresOutOfOwnerCc` protects that
boundary.

Owner runtime 模块应保持以下层级：

```text
owner_task_manifest -> admission -> owner_scheduler_state -> owner_executor
                                        |-> owner_future_store
                                        |-> owner_trace_store
                                        |-> owner_runtime_metrics
```

`owner.cc` 是 efun、status mapping 和 legacy glue facade。runtime 状态容器应留在专用模块中。
源码级 guard 测试 `DriverTest.TestOwnerRuntimeLayeringGuardKeepsStoresOutOfOwnerCc`
用于保护该边界。

Required status fields / 必须保持的状态字段：

- `owner_runtime_split_ready=1`
- `owner_runtime_v4_hardening_ready=1`
- `owner_runtime_layering_guard_ready=1`
- `owner_runtime_coordinator_module_ready=1`
- `owner_task_manifest_module_ready=1`
- `owner_trace_store_ready=1`
- `owner_future_store_ready=1`
- `owner_scheduler_state_ready=1`
- `owner_metrics_store_ready=1`
- `normal_path_main_fallback_count=0`

## Callback Diagnostics / Callback 诊断

Driver callbacks are admitted through the manifest registry and expose stable
diagnostic fields in task mappings and trace mappings:

- `trace_schema_version=2`
- `diagnostic_schema=owner_callback_diagnostics_v1`
- `failure_code_schema=owner_callback_failure_code_v1`
- `drop_reason_schema=owner_callback_drop_reason_v1`
- `failure_code`
- `failure_reason`
- `drop_reason`
- `owner_callback_payload_strict_diagnostics_ready=1`
- `owner_callback_payload_policy=frozen_payload_or_owner_handle_only`
- `owner_callback_human_reason_ready=1`

Driver callback 通过 manifest registry admission，并在 task mapping 与 trace mapping
中暴露稳定诊断字段：

- `trace_schema_version=2`
- `diagnostic_schema=owner_callback_diagnostics_v1`
- `failure_code_schema=owner_callback_failure_code_v1`
- `drop_reason_schema=owner_callback_drop_reason_v1`
- `failure_code`
- `failure_reason`
- `drop_reason`
- `owner_callback_payload_strict_diagnostics_ready=1`
- `owner_callback_payload_policy=frozen_payload_or_owner_handle_only`
- `owner_callback_human_reason_ready=1`

Current executor callback allowlist / 当前 executor callback allowlist：

```text
heartbeat,call_out,async_callback,dns_callback,socket_callback,gateway_command_execute,ed_callback
```

Common failure/drop codes / 常见 failure/drop code：

- `owner_scheduler_backpressure`
- `callback_not_allowlisted`
- `callback_invalid_target`
- `owner_epoch_mismatch`
- `target_destructed`
- `target_stale`
- `admission_rejected`
- `task_dropped`

## Object Store Fast Path / Object Store Fast Path

Same-owner `VMObjectHandle` resolution must prefer the owner shard and avoid the
global directory fallback. Runtime v4 keeps:

- `object_store_owner_fast_path_ready=1`
- `object_store_global_fallback_on_owner_fast_path=0`

The benchmark report emits `object_resolve_global_fallback_count`; stress smoke
requires it to stay `0`.

same-owner `VMObjectHandle` resolve 必须优先走 owner shard，避免 global directory fallback。
Runtime v4 保持：

- `object_store_owner_fast_path_ready=1`
- `object_store_global_fallback_on_owner_fast_path=0`

benchmark 报告会输出 `object_resolve_global_fallback_count`；stress smoke 要求它保持 `0`。

```bash
cmake --build build --target object_store_bench -j2
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

```bash
cmake --build build --target object_store_bench -j2
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

## Value Objects And Snapshot Persistence / Value Object 与 Snapshot Persistence

Frozen mapping and array payloads are represented as value objects for owner
runtime purposes. They are not live LPC objects, do not join the traditional
destruct chain, and are safe to move across owner boundaries after validation.

owner runtime 将 frozen mapping/array payload 表示为 value object。它们不是 live
LPC object，不进入传统 destruct 链，并且在校验后可安全跨 owner 边界传递。

Required fields / 必须字段：

- `lpc_value_object_profile_ready=1`
- `lpc_value_object_model=frozen_snapshot_value_object_v1`
- `lpc_value_object_live_lifecycle_member=0`
- `lpc_value_object_cross_owner_payload_safe=1`
- `object_handle_capability_ready=1`
- `owner_snapshot_persistence_ready=1`

`owner_snapshot_persist()` serializes same-owner object snapshots through the
owner persistence contract. The main thread remains a file I/O adapter, not the
normal business execution path.

`owner_snapshot_persist()` 通过 owner persistence 合同序列化 same-owner object snapshot。
main thread 只保留为文件 I/O adapter，不是正常业务执行路径。

## Scheduler And Backpressure / 调度与反压

Owner scheduler backpressure is observable through:

- `owner_scheduler_backpressure_ready=1`
- `owner_scheduler_max_owner_queue_depth`
- `owner_scheduler_backpressure_high_watermark`
- `owner_executor_backpressure_rejected`
- `executor_same_owner_claim_conflicts`
- `executor_queue_depth`
- `executor_runnable_queue_depth`
- `owner_executor_future_pending_backlog`

Owner scheduler 反压可通过以下字段观察：

- `owner_scheduler_backpressure_ready=1`
- `owner_scheduler_max_owner_queue_depth`
- `owner_scheduler_backpressure_high_watermark`
- `owner_executor_backpressure_rejected`
- `executor_same_owner_claim_conflicts`
- `executor_queue_depth`
- `executor_runnable_queue_depth`
- `owner_executor_future_pending_backlog`

Same-owner execution stays serial. Different owners may execute in parallel when
owner executor threads are available. Hot-path global gameplay domains should be
keyed service shards, not single `service_owner` bottlenecks.

same-owner 执行保持串行。不同 owner 在 owner executor 线程可用时可并行执行。热路径全局玩法
domain 应使用 keyed service shard，而不是单点 `service_owner` 瓶颈。

## Service Shards And Tick Groups / Service Shard 与 Tick Group

Runtime v4 exposes service shard and tick group contracts:

- `owner_service_shard_registry_ready=1`
- `owner_service_shard_registry_schema=owner_service_shard_registry_v1`
- `owner_tick_group_scheduler_ready=1`
- `owner_tick_group_scheduler_schema=owner_tick_group_scheduler_v1`
- `owner_scheduler_tick_group_backpressure_ready=1`
- `service_shard_executor_ready=1`
- `keyed_service_shard_ready=1`
- `owner_service_shard_policy_model=keyed_service_shard_for_hot_paths`

Runtime v4 暴露 service shard 和 tick group 合同：

- `owner_service_shard_registry_ready=1`
- `owner_service_shard_registry_schema=owner_service_shard_registry_v1`
- `owner_tick_group_scheduler_ready=1`
- `owner_tick_group_scheduler_schema=owner_tick_group_scheduler_v1`
- `owner_scheduler_tick_group_backpressure_ready=1`
- `service_shard_executor_ready=1`
- `keyed_service_shard_ready=1`
- `owner_service_shard_policy_model=keyed_service_shard_for_hot_paths`

Current hot-path shard domains include economy, combat, mail, reward,
persistence, guild, quest, and rank. Low-frequency domains may remain
`service_owner` only when they are not on the player command hot path.

当前热路径 shard domain 包括 economy、combat、mail、reward、persistence、guild、
quest 和 rank。低频 domain 只有在不处于玩家命令热路径时，才可保留为 `service_owner`。

## LPC VM Hot-Path Profiling / LPC VM 热路径 Profiling

Runtime v4 exposes hot-path profiling counters through `lpc_vm_profile_v1` and
`lpc_vm_bench_v1`. These are diagnostic signals, not machine-specific
performance thresholds.

Runtime v4 通过 `lpc_vm_profile_v1` 和 `lpc_vm_bench_v1` 暴露热路径 profiling 计数。
这些是诊断信号，不是依赖具体机器的性能硬阈值。

Tracked paths / 跟踪路径：

- opcode dispatch;
- efun dispatch and dispatch time;
- `call_other` dispatch;
- function pointer invocation;
- parser/add_action lookup;
- mapping lookup and insert;
- string push;
- apply dispatch cache hit, miss, and invalidation.

- opcode dispatch；
- efun dispatch 和 dispatch time；
- `call_other` dispatch；
- function pointer invocation；
- parser/add_action lookup；
- mapping lookup 和 insert；
- string push；
- apply dispatch cache hit、miss 和 invalidation。

## Benchmark And Stress Entry Points / Benchmark 与 Stress 入口

```bash
cmake --build build --target owner_runtime_bench lpc_vm_bench object_store_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
tools/owner-runtime-v4-stress.sh smoke
tools/lpc-modern-runtime-stress.sh smoke
```

```bash
cmake --build build --target owner_runtime_bench lpc_vm_bench object_store_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
tools/owner-runtime-v4-stress.sh smoke
tools/lpc-modern-runtime-stress.sh smoke
```

The stress scripts fail if these regression counters are non-zero:

- `normal_path_main_fallback_count`
- `executor_context_cleanup_leaks`
- `executor_same_owner_claim_conflicts`
- `object_resolve_global_fallback_count`

stress 脚本会在以下退化计数非零时失败：

- `normal_path_main_fallback_count`
- `executor_context_cleanup_leaks`
- `executor_same_owner_claim_conflicts`
- `object_resolve_global_fallback_count`

## Mudlib-Facing Contract / 面向 Mudlib 的合同

Mudlibs should integrate through explicit owner-safe contracts:

- ordinary legacy LPC remains default-closed;
- driver callback kinds must be registered in the manifest allowlist;
- cross-owner mutable writes must be rejected or converted to message, future,
  commit, or shard flows;
- callback payloads must be frozen data, snapshots, or ObjectHandle-routed
  references;
- session output must pass through the gateway session FIFO before the main IO
  adapter writes to the network;
- main-thread work is limited to IO adapters, cleanup adapters, and explicit
  compatibility fallback.

mudlib 应通过显式 owner-safe 合同接入：

- 普通 legacy LPC 默认不开放后台执行；
- driver callback kind 必须注册在 manifest allowlist 中；
- cross-owner mutable write 必须被拒绝，或转换为 message、future、commit 或 shard 流程；
- callback payload 必须是 frozen data、snapshot 或 ObjectHandle-routed reference；
- session output 必须先经过 gateway session FIFO，再由 main IO adapter 写网络；
- main-thread 工作只限 IO adapter、cleanup adapter 和显式兼容 fallback。

## Authoritative Checks / 权威检查

```bash
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
tools/lpc-modern-runtime-stress.sh smoke
```

```bash
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
tools/lpc-modern-runtime-stress.sh smoke
```
