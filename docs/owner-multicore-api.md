# Owner Multicore API / Owner 多核接口

## Overview / 概览

FluffOS_XK supports controlled owner/service execution for multicore mudlib
migration. It does not run arbitrary legacy LPC in parallel. A mudlib enters the
multicore path through explicit contracts: same-owner execution, owner mailbox
messages, ObjectHandle-routed async calls, futures, snapshots, commit proposals,
driver callback allowlists, or service shard domains.

FluffOS_XK 支持受控 owner/service 执行，用于 mudlib 多核迁移。它不会把任意
legacy LPC 自动并行执行。mudlib 通过明确合同进入多核路径：same-owner 执行、
owner mailbox message、ObjectHandle 路由的 async call、future、snapshot、
commit proposal、driver callback allowlist 或 service shard domain。

## Core Concepts / 核心概念

| Concept | English | 中文 |
|---|---|---|
| Owner ID | Runtime shard identity for object ownership. | 对象归属的运行时 shard 身份。 |
| Owner epoch | Lifecycle generation used to classify stale handles. | 生命周期世代，用于分类 stale handle。 |
| Same owner | Direct path remains allowed and fast. | same-owner 直接路径保持允许且快速。 |
| Cross owner | Must use snapshot, message, future, commit, or shard contracts. | cross-owner 必须使用 snapshot、message、future、commit 或 shard 合同。 |
| ObjectHandle | Capability handle carrying owner, epoch, object id, path, intent, and snapshot version. | 携带 owner、epoch、object id、path、intent 和 snapshot version 的 capability handle。 |
| Service shard | Keyed domain executor for global or shared gameplay services. | 面向全局或共享玩法服务的 keyed domain executor。 |

Default owner values remain compatibility details. New mudlib code should query
runtime state instead of hardcoding assumptions.

默认 owner 值属于兼容细节。新 mudlib 代码应查询 runtime state，而不是硬编码假设。

## Modern Owner-Safe APIs / 现代 Owner-Safe API

Use these APIs with `#pragma modern_lpc`; add `#pragma strict_owner` for new code
that should fail audit on unsafe owner patterns.

这些 API 建议配合 `#pragma modern_lpc` 使用；新代码若需要把 unsafe owner pattern
变成严格审计结果，应同时使用 `#pragma strict_owner`。

### `freeze(value)`

Validates and deep-copies values that are safe to pass through owner messages,
callbacks, futures, and service shard tasks. Allowed payload values are numbers,
reals, strings, arrays, and mappings. Live mutable objects and VM-bound values
are rejected.

校验并深拷贝可通过 owner message、callback、future 和 service shard task 传递的安全值。
允许的 payload 值包括 number、real、string、array 和 mapping。live mutable object
和 VM 绑定值会被拒绝。

### `snapshot(value)`

Creates a frozen value snapshot for mappings and arrays, or an ObjectHandle
capability snapshot for live objects. Value snapshots are not live LPC objects
and do not join the traditional destruct chain.

为 mapping/array 生成 frozen value snapshot，或为 live object 生成 ObjectHandle
capability snapshot。value snapshot 不是 live LPC object，也不进入传统 destruct 链。

### `owner_async(target, mapping payload)`

Submits owner-safe work and returns a future-oriented mapping. `target` may be an
owner id string or an object. Object targets require ObjectHandle routing and a
`payload["method"]` entry.

投递 owner-safe 工作并返回面向 future 的 mapping。`target` 可以是 owner id string
或 object。object target 需要 ObjectHandle route，并且 payload 中必须有
`payload["method"]`。

### `owner_await(int future_id)`

Returns the current future state through the owner future contract. It is a
polling adapter today; coroutine suspension is not enabled for legacy LPC.

通过 owner future 合同返回当前 future 状态。当前它是 polling adapter；legacy LPC
默认不启用 coroutine suspension。

### `owner_commit(mapping proposal)`

Records a proposal at the owner/service commit boundary. Use it for cross-owner
writes that should not mutate another owner directly. Proposals should include a
stable key, target owner or service shard, domain, frozen payload, and idempotent
commit identity.

在 owner/service commit 边界记录 proposal。跨 owner 写入不应直接修改目标 owner，
而应使用该入口。proposal 应包含稳定 key、目标 owner 或 service shard、domain、
frozen payload 和幂等 commit identity。

### `owner_snapshot_persist(object target, mapping options)`

Serializes a same-owner object snapshot for persistence. The owner/service
executor owns consistency; the main/file side remains an I/O adapter. In strict
owner migrations, direct hot-path `save_object` calls should be audited and
replaced where appropriate.

序列化 same-owner object snapshot 用于持久化。owner/service executor 负责一致性；
main/file 侧只作为 I/O adapter。在 strict owner 迁移中，热路径直接 `save_object`
应被审计，并在合适场景替换。

## Return Structure / 返回结构

Successful owner-safe APIs return machine-readable fields such as:

```c
([
    "success": 1,
    "ok": 1,
    "api": "owner_async",
    "future_id": 123,
    "trace_id": "owner-trace/...",
])
```

Failures return stable codes and readable reasons:

```c
([
    "success": 0,
    "ok": 0,
    "api": "owner_async",
    "code": "non_frozen_payload",
    "reason": "owner_async requires frozen or freeze-compatible payload",
])
```

成功的 owner-safe API 会返回机器可判定字段，例如：

```c
([
    "success": 1,
    "ok": 1,
    "api": "owner_async",
    "future_id": 123,
    "trace_id": "owner-trace/...",
])
```

失败结果会返回稳定 code 和可读 reason：

```c
([
    "success": 0,
    "ok": 0,
    "api": "owner_async",
    "code": "non_frozen_payload",
    "reason": "owner_async requires frozen or freeze-compatible payload",
])
```

## Minimal Modern Example / 最小现代示例

```c
#pragma modern_lpc
#pragma strict_owner

mapping submit_reward_commit(string player_id, mapping reward) {
    mapping frozen = freeze(([
        "player_id": player_id,
        "reward": reward,
    ]));

    if (!frozen["ok"]) {
        return frozen;
    }

    return owner_async("service/reward/" + player_id, ([
        "type": "owner_task_reward",
        "payload_key": "reward/commit/v1",
        "payload": frozen["value"],
    ]));
}
```

This pattern keeps live objects out of the cross-owner payload and routes the
write through a keyed service shard.

这个模式避免把 live object 放进 cross-owner payload，并把写入通过 keyed service shard
路由。

## Cross-Owner Snapshot / Cross-Owner Snapshot

Use `owner_query_object_snapshot(object target)` for read-only structural
information when the caller cannot safely execute target LPC directly.

当调用方不能安全地直接执行目标 LPC 时，可使用
`owner_query_object_snapshot(object target)` 读取只读结构信息。

```c
mapping maybe_snapshot = owner_query_object_snapshot(target);
if (mapp(maybe_snapshot)) {
    // Cross-owner target: use snapshot fields.
    return maybe_snapshot["object_name"];
}

// Same owner or default-safe target: direct path remains available.
return file_name(target);
```

```c
mapping maybe_snapshot = owner_query_object_snapshot(target);
if (mapp(maybe_snapshot)) {
    // cross-owner 目标：使用 snapshot 字段。
    return maybe_snapshot["object_name"];
}

// same-owner 或 default-safe 目标：仍可走直接路径。
return file_name(target);
```

Snapshot fields include object path, owner id, living flags, and method presence
bits used by compatibility code.

snapshot 字段包括 object path、owner id、living flag，以及兼容代码需要的方法存在性标志。

## Payload Rules / Payload 规则

Payload rules are shared by owner messages, async calls, snapshots, worker
results, and domain tasks:

- top-level owner payloads are mappings;
- mapping keys must be strings;
- allowed values are numbers, reals, strings, arrays, and mappings;
- nesting depth is limited;
- objects, functions, buffers, classes, and other VM-bound mutable values are
  rejected.

owner message、async call、snapshot、worker result 和 domain task 共用 payload 规则：

- top-level owner payload 必须是 mapping；
- mapping key 必须是 string；
- value 允许 number、real、string、array 和 mapping；
- nesting depth 有限制；
- object、function、buffer、class 和其他 VM 绑定可变值会被拒绝。

## Registered Domains / 已注册 Domain

The engine registers production owner task domains explicitly. Current domains:

```text
owner_task_readonly, owner_task_player, owner_task_room, owner_task_session,
owner_task_item, owner_task_economy, owner_task_combat, owner_task_mail,
owner_task_reward, owner_task_world, owner_task_persistence, owner_task_team,
owner_task_guild, owner_task_sect, owner_task_quest, owner_task_rank,
owner_task_crafting, owner_task_life_skill
```

引擎显式注册生产 owner task domain。当前 domain：

```text
owner_task_readonly, owner_task_player, owner_task_room, owner_task_session,
owner_task_item, owner_task_economy, owner_task_combat, owner_task_mail,
owner_task_reward, owner_task_world, owner_task_persistence, owner_task_team,
owner_task_guild, owner_task_sect, owner_task_quest, owner_task_rank,
owner_task_crafting, owner_task_life_skill
```

Use these domains to route real gameplay work by owner or keyed service shard.
Do not invent undocumented domain names in mudlib code.

真实玩法工作应按 owner 或 keyed service shard 路由到这些 domain。mudlib 代码不要发明未记录的
domain 名称。

## Runtime Status / 运行时状态

Use `vm_owner_runtime_status()` to verify integration. Important fields:

- `normal_path_main_fallback_count=0`;
- `target_owner_message_main_fallback=0`;
- `owner_service_shard_registry_ready=1`;
- `owner_tick_group_scheduler_ready=1`;
- `session_fifo_contract_ready=1`;
- `object_store_global_fallback_on_owner_fast_path=0`;
- `lpc_modern_profile_ready=1`;
- `lpc_source_encoding_ready=1`.

使用 `vm_owner_runtime_status()` 验证接入效果。关键字段：

- `normal_path_main_fallback_count=0`；
- `target_owner_message_main_fallback=0`；
- `owner_service_shard_registry_ready=1`；
- `owner_tick_group_scheduler_ready=1`；
- `session_fifo_contract_ready=1`；
- `object_store_global_fallback_on_owner_fast_path=0`；
- `lpc_modern_profile_ready=1`；
- `lpc_source_encoding_ready=1`。

## Verification / 验证

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

These checks prove the documented fields are runtime-backed and not just static
documentation claims.

这些检查用于证明文档字段有运行时合同支撑，而不是静态文档宣称。
