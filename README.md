# FluffOS_XK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMake](https://img.shields.io/badge/build-CMake-blue.svg)](CMakeLists.txt)
[![LPC Runtime](https://img.shields.io/badge/runtime-LPC%20%2F%20MUD-informational.svg)](https://www.fluffos.info)
[![Multicore](https://img.shields.io/badge/multicore-owner%2Fservice%20executor-success.svg)](docs/multicore-runtime-v2.md)

English | [简体中文](README_CN.md)

FluffOS_XK is a production-oriented FluffOS engine fork for modern LPC/MUD
projects. It keeps the classic FluffOS driver model, then adds a completed
owner/service multicore runtime baseline, stronger gateway integration, cleaner
build behavior, and downstream-friendly engine maintenance.

Use it when you want a practical source-level LPC runtime that can be rebuilt,
audited, and embedded by a real game repository without mixing engine work,
mudlib content, private deployment data, or account state.

## Why FluffOS_XK

- **Production multicore baseline**: owner/service executor execution is sealed
  for the current production contract, including object lifecycle, heartbeat,
  callout, async/file/db, DNS, socket callbacks, gateway commands,
  target-owner messages, and the `socket_release` release/acquire handshake.
- **Safe by default**: ordinary legacy LPC is still default-closed for arbitrary
  background execution. Multicore entry requires explicit ownership, allowlist,
  driver callback, frozen payload, ObjectHandle, or owner/service shard
  contracts.
- **Built for downstream games**: keep the engine in this repository and keep
  mudlib, world data, accounts, deployment secrets, and operations policy in
  your own game repository.
- **Modern client path**: gateway/session integration supports WebSocket-facing
  clients and service-managed deployments.
- **Auditable maintenance fork**: CMake, install behavior, warning hygiene,
  release notes, security policy, and project scope are kept visible for
  external review.

## What Is Included

FluffOS_XK focuses on engine runtime foundations:

- LPC interpreter, network server, EFUN/apply glue, and the classic FluffOS
  driver model;
- owner metadata, ObjectHandle routing, VMContext isolation, OwnerExecutor
  tasks, owner futures, shard-aware messages, and production gate contracts;
- gateway command execution and callback dispatch through controlled
  owner/service executor paths;
- Linux, WSL, Windows/MSYS2, and install-oriented CMake workflows;
- documentation for downstream projects that need a stable engine baseline.

It does not bundle a complete game mudlib, replace upstream FluffOS as the
canonical project, or open unsafe arbitrary LPC execution on background threads.

## Multicore Runtime

The current production baseline is a controlled multicore runtime for
owner/service execution. It is designed for projects that want to move mutable
game state away from global single-thread hot paths without breaking classic LPC
compatibility.

Key properties:

- same-owner execution remains direct and fast;
- cross-owner work uses snapshots, ObjectHandle routing, owner messages,
  futures, or service shard domains;
- stale owner, destructed object, epoch mismatch, payload policy, and cleanup
  failures are classified by the runtime contract;
- main-thread work is limited to IO adapters, cleanup adapters, explicit
  fallback, and documented compatibility surfaces;
- normal production paths keep `normal_path_main_fallback_count=0`.

Read the contract before integrating a mudlib:

- [Runtime v2 contract](docs/multicore-runtime-v2.md)
- [Production gate](docs/multicore-production-gate.md)
- [Owner multicore API](docs/owner-multicore-api.md)
- [Production baseline release note](docs/releases/multicore-production-baseline-2026-06-27.md)
- [Engine overview for integrators](docs/fluffos-xk-overview.md)

## Using The Multicore Interfaces

The new runtime APIs are intentionally explicit. A mudlib should not pass live
objects or mutable closures across owners; it should pass frozen data, snapshots,
ObjectHandle-routed async calls, or service-domain tasks.

Common LPC entry points:

| API | Use it for |
|---|---|
| `vm_owner_id(object)` / `vm_owner_epoch(object)` | Inspect the owner and lifecycle epoch of an object. |
| `vm_owner_guard(object, string)` / `vm_owner_guard_epoch(object, string, int)` | Check owner or owner+epoch before doing sensitive work. |
| `owner_query_object_snapshot(object)` | Read safe structural data from a cross-owner object without executing target LPC. |
| `owner_send(string owner_id, mapping payload)` | Send frozen data to an owner mailbox and get a future id. |
| `owner_call_async(object target, string method, mapping payload)` | Call a target object through ObjectHandle routing and owner executor guards. |
| `owner_future_poll(int future_id)` | Poll pending/completed/failed state and frozen results. |
| `owner_snapshot(object)` / `owner_publish_snapshot(mapping)` | Publish or consume snapshot-style data instead of sharing mutable objects. |
| `vm_owner_runtime_status()` | Inspect production gate fields, domain registry readiness, fallback counters, and executor state. |

Payload rules are shared by owner messages, async calls, snapshots, worker
results, and domain tasks:

- top-level owner payloads are mappings;
- mapping keys must be strings;
- allowed values are numbers, reals, strings, arrays, and mappings;
- nesting depth is limited;
- objects, functions, buffers, classes, and other VM-bound mutable values are
  rejected.

Minimal async example:

```c
mapping submit_player_save(object player) {
    mapping payload = ([
        "payload_key": "player/save/v1",
        "player_id": player->query_id(),
        "snapshot": owner_snapshot(player),
    ]);

    return owner_call_async(player, "owner_task_persistence", payload);
}

mapping wait_for_result(int future_id) {
    mapping future = owner_future_poll(future_id);

    if (future["state"] == "completed") {
        return future["result"];
    }

    if (future["state"] == "failed") {
        error("owner task failed: " + future["error"] + "\n");
    }

    return ([ "state": "pending" ]);
}
```

Production owner domains are explicitly registered by the engine. The current
allowlist contains `owner_task_readonly`, `owner_task_player`,
`owner_task_room`, `owner_task_session`, `owner_task_item`,
`owner_task_economy`, `owner_task_combat`, `owner_task_mail`,
`owner_task_reward`, `owner_task_world`, `owner_task_persistence`,
`owner_task_team`, `owner_task_guild`, `owner_task_sect`,
`owner_task_quest`, `owner_task_rank`, `owner_task_crafting`, and
`owner_task_life_skill`.

Use these domains to route real gameplay work by owner or service shard. Keep
ordinary legacy LPC on the classic path unless it has an explicit owner-safe
contract.

## Expected Performance Gains

The multicore baseline improves throughput by moving independent owner/service
work off the single global hot path. It does not make every individual LPC
function faster, and it does not make one player's same-owner command magically
parallel.

Expected behavior:

| Workload | Expected gain |
|---|---|
| Single player, light command path | Usually small; compatibility overhead can dominate. |
| Many players in different owners or rooms | Stronger throughput; commands can be distributed across owner executors. |
| Heartbeat/callout-heavy worlds | Better tail latency because callbacks no longer all compete for one business path. |
| Async/db/file/DNS/socket callback bursts | Better isolation; frozen results return to the callback owner instead of flooding main business execution. |
| Global services not split into shards | Limited by the remaining service bottleneck. |
| Keyed service shards and owner-safe mudlib code | Best scaling profile; gains become closer to available cores, bounded by serial work. |

The theoretical upper bound follows Amdahl's law:

```text
speedup = 1 / (serial_part + parallel_part / cores)
```

For example, if 70% of a workload is owner/service parallel and 30% remains
serial, an 8-core machine has a theoretical ceiling around 2.6x. If a mudlib
migration moves 90% of hot work into owner/service paths, the same 8-core
machine has a theoretical ceiling around 4.7x.

Real gains depend on mudlib structure, shard keys, IO behavior, persistence
costs, and how much work still uses explicit fallback. The engine exposes
runtime fields such as `normal_path_main_fallback_count`,
`target_owner_message_main_fallback`, owner executor queue state, stale/drop
classification, and future status so downstream projects can verify whether
they are actually using the multicore path.

## Quick Start

```bash
git clone https://github.com/FengYunCalm/Fluffos_XK.git
cd Fluffos_XK
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
tools/wsl-cmake-build.sh build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
```

For install-oriented environments:

```bash
tools/wsl-cmake-build.sh build --target install
```

The wrapper is a thin `cmake --build` helper for WSL-launched builds. Native
Linux users can also invoke CMake directly. Windows/MSYS2 users should prefer
the CMake install path instead of manually copying generated binaries.

## Downstream Integration

A downstream game should treat FluffOS_XK as the engine source tree or as the
source for rebuilt `driver` and `lpcc` binaries.

Recommended flow:

1. Pin a known FluffOS_XK commit or release tag.
2. Build `driver`, `lpcc`, and `lpc_tests`.
3. Run engine tests such as `build/src/tests/lpc_tests`.
4. Copy the resulting binaries into the downstream runtime tree.
5. Run project-level smoke tests for login, gateway, commands, movement,
   content loading, persistence, and reconnect behavior.
6. Keep mudlib code, accounts, secrets, deployment scripts, and operational
   reports outside the engine repository.

## Documentation

- [Documentation index](docs/index.md)
- [Engine overview](docs/fluffos-xk-overview.md)
- [Build guide](docs/build.md)
- [Driver CLI](docs/cli/driver.md)
- [LPC reference](docs/lpc/index.md)
- [Owner multicore API](docs/owner-multicore-api.md)
- [Multicore runtime v2](docs/multicore-runtime-v2.md)
- [Production gate](docs/multicore-production-gate.md)
- [Changelog](CHANGELOG.md)
- [Release notes](RELEASE.md)

## Contributing

Focused contributions are welcome: build fixes, warning cleanup, tests,
documentation, gateway/runtime maintenance, and narrowly scoped improvements
that fit this fork's role. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request.

Security issues should be reported responsibly. See [SECURITY.md](SECURITY.md).

## License And Attribution

- MIT License: see [LICENSE](LICENSE).
- Historical LPmud/MudOS notices still apply to legacy components: see
  [Copyright](Copyright).
- Third-party licenses: see [NOTICE](NOTICE) and `src/thirdparty/*`.

## Upstream

- Upstream FluffOS: https://github.com/fluffos/fluffos
- Official FluffOS documentation: https://www.fluffos.info
