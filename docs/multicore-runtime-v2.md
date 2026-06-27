# Multicore Runtime v2 Contract

This document records the owner runtime v2 contract and the production-perfect extension layered on top of the production-ready multicore gate.

## Baseline

- Branch: `codex/multicore-production-perfect-engine`
- Baseline: current `master` worktree baseline for the production-perfect engine branch.
- v2 commits:
  - `452d3eed multicore: add owner runtime v2 manifest contract`
  - `9c1c9bbc multicore: trace owner executor callback manifests`
  - `85b0393c multicore: make owner messages executor safe`
  - `27a37ab8 multicore: expose production perfect runtime contract`

## Contract Additions

- Owner executor tasks now expose a manifest-level contract for kind, owner id, owner epoch, payload policy, cleanup policy, deadline, trace id, and future/reply policy.
- Admission and drop counters are observable through owner runtime status.
- Callback task traces include manifest and admission fields for heartbeat, callout, async, DNS, socket, and gateway callback categories.
- Stale owner, destructed object, epoch mismatch, and admission rejection are classified separately.
- Ordinary legacy LPC execution remains default-closed; v2 does not open arbitrary background LPC execution.
- Production owner domains are explicitly registered in the owner task allowlist: `owner_task_readonly`, `owner_task_player`, `owner_task_room`, `owner_task_session`, `owner_task_item`, `owner_task_economy`, `owner_task_combat`, `owner_task_mail`, `owner_task_reward`, `owner_task_world`, `owner_task_persistence`, `owner_task_team`, `owner_task_guild`, `owner_task_sect`, `owner_task_quest`, `owner_task_rank`, `owner_task_crafting`, and `owner_task_life_skill`.
- Target-handle `owner_message` now routes through the target owner mailbox/executor with ObjectHandle stale, owner epoch, and destructed-object guards. It is no longer a normal-path owner main queue bridge.
- Runtime status must expose `registered_owner_task_domains_ready=1`, `registered_owner_task_domain_count=18`, `domain_task_registry_mudlib_aligned=1`, `target_owner_message_executor_ready=1`, `target_owner_message_main_fallback=0`, `service_shard_executor_ready=1`, `keyed_service_shard_ready=1`, `hot_path_service_owner_single_point=0`, and `facade_only_runtime_claims=0`.
- `normal_path_main_fallback_count` must remain `0` and `normal_path_main_fallback_ready` must remain `1` in the production path. Main-thread work is limited to IO adapters, cleanup adapters, explicit/off/failure fallback, and other documented main-required compatibility surfaces.
- `production_perfect_contract_ready=1` is only valid while the registered domain allowlist, target-owner message executor route, keyed service shard contract, and normal-path fallback counters all satisfy the fields above.

## Verification

The v2 engine branch verification set is:

- `git diff --check`
- `cmake --build build --target lpc_tests -j2`
- `build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract`
- `build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerSocketCallbacksDispatchThroughOwnerExecutor:DriverTest.TestVmOwnerSocketCallbackExecutorDropsStaleOwnerEpoch:DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract`
- `cmake --build build --target driver -j2`
- `../build/bin/driver etc/config.test '-ftest:single/tests/efuns/owner_executor_contract'`

## Production-Perfect Pairing

The paired XiaKeXing production-perfect migration branch binds real mudlib services to this contract through explicit owner service routes, service shard keys, owner commit boundaries, session FIFO output, and owner-routed callback metadata. The highest pressure acceptance target remains the user-approved 10-user, 30-minute audit run; code-level acceptance additionally requires no facade-only production claims, no normal-path main fallback, no hot-path `service_owner` bottleneck, and no direct cross-owner mutable write.
