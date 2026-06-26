# Multicore Runtime v2 Contract

This document records the v2 owner runtime contract layered on top of the production-ready multicore gate.

## Baseline

- Branch: `codex/multicore-v2-engine`
- Baseline commit: `05a79c39`
- v2 commits:
  - `452d3eed multicore: add owner runtime v2 manifest contract`
  - `9c1c9bbc multicore: trace owner executor callback manifests`

## Contract Additions

- Owner executor tasks now expose a manifest-level contract for kind, owner id, owner epoch, payload policy, cleanup policy, deadline, trace id, and future/reply policy.
- Admission and drop counters are observable through owner runtime status.
- Callback task traces include manifest and admission fields for heartbeat, callout, async, DNS, socket, and gateway callback categories.
- Stale owner, destructed object, epoch mismatch, and admission rejection are classified separately.
- Ordinary legacy LPC execution remains default-closed; v2 does not open arbitrary background LPC execution.

## Verification

The v2 engine branch has passed:

- `git diff --check`
- `cmake --build build --target lpc_tests -j2`
- `build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract`
- `build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerSocketCallbacksDispatchThroughOwnerExecutor:DriverTest.TestVmOwnerSocketCallbackExecutorDropsStaleOwnerEpoch:DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract`
- `cmake --build build --target driver -j2`
- `../build/bin/driver etc/config.test '-ftest:single/tests/efuns/owner_executor_contract'`

## Downstream Pairing

The paired XiaKeXing v2 migration branch binds real mudlib services to this contract through explicit owner service routes, service-owner commit boundaries, and owner-routed callback metadata. The highest pressure acceptance target for v2 remains the user-approved 10-user, 30-minute audit run.
