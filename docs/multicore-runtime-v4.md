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

## Benchmark And Stress Entry Points

Build and run the benchmark directly:

```bash
cmake --build build --target owner_runtime_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
```

Run the Runtime v4 gate used by CI:

```bash
tools/owner-runtime-v4-stress.sh smoke
```

Run a repeated local storm profile:

```bash
PROFILE=storm REPEAT=10 tools/owner-runtime-v4-stress.sh
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

The GitHub Actions CI runs the Runtime v4 smoke gate on the Ubuntu/GCC/Debug
matrix entry. The gate builds `lpc_tests`, `driver`, and `owner_runtime_bench`,
runs targeted owner runtime tests, runs the benchmark smoke, validates the JSON
regression counters, runs the LPC `owner_executor_contract`, and uploads the
benchmark JSON as an artifact.

The wider CI matrix still runs the existing unit tests and full LPC testsuite.

## Mudlib-Facing Contract

Mudlibs should use owner runtime APIs through explicit owner-safe contracts:

- ordinary legacy LPC remains default-closed;
- driver callback kinds must be registered in the manifest allowlist;
- cross-owner mutable writes must be rejected or converted to owner
  message/future/commit flows;
- callback payloads must be frozen data, snapshots, or ObjectHandle-routed
  references;
- main thread work is limited to IO adapters, cleanup adapters, and explicit
  compatibility fallback.

The authoritative runtime checks are:

```bash
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
```
