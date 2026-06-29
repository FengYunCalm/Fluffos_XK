# Multicore Runtime v4 Hardening Baseline

Runtime v4 keeps the production multicore contract from Runtime v2 and hardens
the engine internals around diagnostics, scheduling, backpressure, object-store
fast paths, and mudlib-facing error reporting. It does not open arbitrary legacy
LPC execution on background threads.

## Runtime Layering

Owner runtime modules are expected to stay in this order:

```text
owner_task_manifest -> admission -> owner_scheduler_state -> owner_executor
                                        |-> owner_future_store
                                        |-> owner_trace_store
                                        |-> owner_runtime_metrics
```

`owner.cc` is a facade for efuns, status mappings, and legacy glue. Runtime
state containers belong in the dedicated modules above. The source-level guard
test `DriverTest.TestOwnerRuntimeLayeringGuardKeepsStoresOutOfOwnerCc` protects
that boundary.

Required status fields:

- `owner_runtime_split_ready=1`
- `owner_runtime_v4_hardening_ready=1`
- `owner_runtime_benchmark_smoke_ready=1`
- `owner_runtime_benchmark_schema=owner_runtime_bench_v1`
- `owner_runtime_stress_profile_ready=1`
- `owner_runtime_stress_entry=tools/owner-runtime-v4-stress.sh`
- `lpc_modern_runtime_stress_ready=1`
- `lpc_modern_runtime_stress_entry=tools/lpc-modern-runtime-stress.sh`
- `owner_runtime_layering_guard_ready=1`
- `owner_runtime_coordinator_module_ready=1`
- `owner_task_manifest_module_ready=1`
- `owner_trace_store_ready=1`
- `owner_future_store_ready=1`
- `owner_scheduler_state_ready=1`
- `owner_metrics_store_ready=1`
- `normal_path_main_fallback_count=0`

## Callback Diagnostics

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
- `owner_callback_payload_policy_schema=owner_callback_payload_policy_v1`
- `owner_callback_payload_policy=frozen_payload_or_owner_handle_only`
- `owner_callback_human_reason_ready=1`
- `owner_callback_failure_reason_schema=owner_callback_failure_reason_v1`

Current executor callback allowlist:

```text
heartbeat,call_out,async_callback,dns_callback,socket_callback,gateway_command_execute,ed_callback
```

Common failure/drop codes:

- `owner_scheduler_backpressure`
- `callback_not_allowlisted`
- `callback_invalid_target`
- `owner_epoch_mismatch`
- `target_destructed`
- `target_stale`
- `admission_rejected`
- `task_dropped`

## Object Store Fast Path

Same-owner `VMObjectHandle` resolution must prefer the owner shard and avoid the
global directory fallback. Runtime v4 keeps:

- `object_store_owner_fast_path_ready=1`
- `object_store_global_fallback_on_owner_fast_path=0`

The benchmark report also emits `object_resolve_global_fallback_count`; CI and
stress smoke require it to stay `0`.

The dedicated object-store benchmark is:

```bash
cmake --build build --target object_store_bench -j2
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

Its JSON uses `schema=object_store_bench_v1` and records owner-local resolve
latency, owner id lookup latency, owner path lookup latency, owner-local fast
path count, and global fallback count.

## Value Objects And Snapshot Persistence

Frozen mapping and array payloads are represented as value objects for owner
runtime purposes. They are not live LPC objects, do not join the traditional
destruct chain, and are safe to move across owner boundaries after validation.

Required fields:

- `lpc_value_object_profile_ready=1`
- `lpc_value_object_model=frozen_snapshot_value_object_v1`
- `lpc_value_object_live_lifecycle_member=0`
- `lpc_value_object_cross_owner_payload_safe=1`
- `object_handle_capability_ready=1`
- `owner_snapshot_persistence_ready=1`

`owner_snapshot_persist()` serializes same-owner object snapshots through the
owner persistence contract. The main thread remains a file I/O adapter; it is
not the normal business execution path.

## Scheduler And Backpressure

Owner scheduler backpressure is observable through:

- `owner_scheduler_backpressure_ready=1`
- `owner_scheduler_max_owner_queue_depth`
- `owner_scheduler_backpressure_high_watermark`
- `owner_executor_backpressure_rejected`
- `executor_same_owner_claim_conflicts`
- `executor_queue_depth`
- `executor_runnable_queue_depth`
- `owner_executor_future_pending_backlog`

Backpressure rejects new work after the per-owner queue reaches the configured
limit. Same-owner execution stays serial; different owners may execute in
parallel when owner executor threads are available.

Hot-path global gameplay domains must be keyed `service_shard` entries, not
single `service_owner` bottlenecks. Runtime status derives
`hot_path_service_owner_single_point` from the service registry so documentation
and status cannot drift from the registered domains. Current hot-path shard
domains include economy, combat, mail, reward, persistence, guild, quest, and
rank. Low-frequency domains may remain `service_owner` only when they are not on
the player command hot path.

## LPC VM Hot-Path Profiling

Runtime v4 exposes hot-path profiling counters through `lpc_vm_profile_v1` and
`lpc_vm_bench_v1`. These counters are diagnostic signals, not machine-specific
performance thresholds.

Tracked paths include:

- opcode dispatch;
- efun dispatch and dispatch time;
- `call_other` dispatch;
- function pointer invocation;
- parser/add_action lookup;
- mapping lookup and insert;
- string push;
- apply dispatch cache hit, miss, and invalidation.

The integrated `tools/lpc-modern-runtime-stress.sh smoke` gate requires the
benchmark JSON to record non-zero opcode, efun, `call_other`, mapping lookup,
and string push counters. This proves the probes are wired to live VM paths
instead of static status fields.

## Benchmark And Stress Entry Points

Build and run the owner runtime benchmark directly:

```bash
cmake --build build --target owner_runtime_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
```

Build and run the LPC VM benchmark directly:

```bash
cmake --build build --target lpc_vm_bench -j2
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
```

Run the Runtime v4 owner-only gate:

```bash
tools/owner-runtime-v4-stress.sh smoke
```

Run the full LPC Modern Runtime gate used by CI:

```bash
tools/lpc-modern-runtime-stress.sh smoke
```

Run a repeated local storm profile:

```bash
PROFILE=storm REPEAT=10 tools/lpc-modern-runtime-stress.sh
```

The benchmark JSON uses `schema=owner_runtime_bench_v1` and records:

- same-owner serial task throughput;
- different-owner parallel task throughput;
- scheduler enqueue API latency p50/p95/p99;
- future poll/cancel/timeout API latency p50/p95/p99;
- object handle resolve latency p50/p95/p99;
- callback admission latency p50/p95/p99;
- queue depth, fallback, drop, cleanup leak, and claim-conflict counters.

The stress script fails if these regression counters are non-zero:

- `normal_path_main_fallback_count`
- `executor_context_cleanup_leaks`
- `executor_same_owner_claim_conflicts`
- `object_resolve_global_fallback_count`

## CI Gate

The GitHub Actions CI runs the LPC Modern Runtime smoke gate on the
Ubuntu/GCC/Debug matrix entry. The gate builds `lpc_tests`, `driver`,
`owner_runtime_bench`, `lpc_vm_bench`, and `object_store_bench`; runs targeted
owner runtime and LPC Modern tests; runs all three benchmark smoke reports;
validates JSON schemas and regression counters; runs the LPC
`owner_executor_contract`; and uploads all benchmark JSON files as one artifact.

The wider CI matrix still runs the existing unit tests and full LPC testsuite.

## Mudlib-Facing Contract

Mudlibs should use owner runtime APIs through explicit owner-safe contracts:

- ordinary legacy LPC remains default-closed;
- driver callback kinds must be registered in the manifest allowlist;
- cross-owner mutable writes must be rejected or converted to owner
  message/future/commit flows;
- callback payloads must be frozen data, snapshots, or ObjectHandle-routed
  references;
- session output must pass through the gateway session FIFO before the main IO
  adapter writes to the network;
- main thread work is limited to IO adapters, cleanup adapters, and explicit
  compatibility fallback.

The authoritative runtime checks are:

```bash
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
```
