# FluffOS_XK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMake](https://img.shields.io/badge/build-CMake-blue.svg)](CMakeLists.txt)
[![LPC Runtime](https://img.shields.io/badge/runtime-LPC%20%2F%20MUD-informational.svg)](https://www.fluffos.info)
[![Multicore](https://img.shields.io/badge/multicore-owner%2Fservice%20executor-success.svg)](docs/multicore-runtime-v4.md)

English first. Chinese follows each major section.
英文在前；每个主要章节后提供中文说明。

## What This Engine Is

FluffOS_XK is a production-oriented FluffOS engine fork for modern LPC/MUD
projects. It keeps LPC and the classic FluffOS driver model, then adds a
completed owner/service multicore runtime, opt-in modern LPC contracts,
source/session encoding boundaries, VM hot-path diagnostics, and
downstream-friendly maintenance practices.

Use this repository as an engine source tree or as the source for rebuilt
`driver` and `lpcc` binaries. Keep mudlib content, world data, accounts,
deployment secrets, and operations policy in your game repository.

FluffOS_XK 是面向现代 LPC/MUD 项目的生产型 FluffOS 引擎分支。它保留 LPC
和经典 FluffOS driver 模型，同时加入已经完成的 owner/service 多核运行时、
按需启用的现代 LPC 合同、源码/会话编码边界、VM 热路径诊断，以及适合下游项目长期维护的工程边界。

本仓库应作为引擎源码树，或作为重建 `driver` 与 `lpcc` 二进制的来源。
mudlib、世界内容、账号、部署密钥和运维策略应留在游戏项目仓库中。

## Why It Exists

- **Controlled multicore execution**: owner/service executor paths cover object
  lifecycle, heartbeat, callout, async/file/db, DNS, socket callbacks, gateway
  commands, target-owner messages, and socket release/acquire handshakes.
- **Modern LPC without breaking legacy code**: `#pragma modern_lpc` and
  `#pragma strict_owner` are opt-in. Existing mudlibs keep legacy behavior until
  they choose stricter contracts.
- **Explicit owner-safe APIs**: mudlibs can use `freeze`, `snapshot`,
  `owner_async`, `owner_await`, `owner_commit`, owner futures, ObjectHandle
  routing, and service shard domains instead of passing mutable objects across
  owner boundaries.
- **Encoding compatibility at the right boundary**: VM strings remain canonical
  UTF-8, while legacy source files, player sessions, gateway payloads, and
  external text can opt into GBK, GB2312, Big5, or other ICU-supported encodings
  at explicit boundaries.
- **Measurable runtime behavior**: VM profiling, owner runtime status, benchmark
  reports, stress scripts, queue/backpressure counters, fallback counters, and
  stale/drop classifications make production behavior auditable.

- **受控多核执行**：owner/service executor 路径覆盖 object lifecycle、heartbeat、
  callout、async/file/db、DNS、socket callback、gateway command、target-owner
  message 和 socket release/acquire handshake。
- **不破坏旧 LPC 的现代化**：`#pragma modern_lpc` 与 `#pragma strict_owner`
  是按需启用能力。旧 mudlib 默认保持原行为，只有新代码主动选择后才进入更严格合同。
- **显式 owner-safe API**：mudlib 可以使用 `freeze`、`snapshot`、
  `owner_async`、`owner_await`、`owner_commit`、owner future、ObjectHandle
  route 和 service shard domain，避免跨 owner 传递可变对象。
- **编码兼容放在正确边界**：VM 内部字符串保持规范 UTF-8；遗留源码、玩家会话、
  gateway payload 和外部文本可在明确边界使用 GBK、GB2312、Big5 或其他 ICU 支持编码。
- **运行行为可量化**：VM profiling、owner runtime status、benchmark report、
  stress script、队列/反压计数、fallback 计数和 stale/drop 分类让生产行为可审计。

## Runtime Boundaries

FluffOS_XK does not make arbitrary legacy LPC run freely on background threads.
That is deliberate. Normal LPC remains default-closed for background execution.
The multicore path requires one of these contracts:

- same-owner direct execution;
- driver callback allowlist;
- frozen mapping/array payload;
- ObjectHandle-routed target;
- owner message/future;
- owner/service commit proposal;
- keyed service shard domain.

The main thread remains available for IO adapters, cleanup adapters, explicit
compatibility fallback, and documented main-required surfaces. Production
business paths are expected to keep `normal_path_main_fallback_count=0`.

FluffOS_XK 不会把任意 legacy LPC 自动放到后台线程执行，这是有意保守的安全边界。
普通 LPC 默认不开放后台执行。进入多核路径必须满足以下合同之一：

- same-owner 直接执行；
- driver callback allowlist；
- frozen mapping/array payload；
- ObjectHandle route；
- owner message/future；
- owner/service commit proposal；
- keyed service shard domain。

main thread 仍可作为 IO adapter、cleanup adapter、显式兼容 fallback 和明确的
main-required 兼容面。生产业务正常路径要求 `normal_path_main_fallback_count=0`。

## Modern LPC Example

```c
#pragma modern_lpc
#pragma strict_owner
#pragma source_encoding("GBK")

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

Audit a file before migrating it:

```bash
build/bin/lpcc --owner-audit --format=json etc/config.test path/to/file.c
```

上面的示例展示了现代 LPC 的典型用法：用 pragma 显式启用现代 profile 和严格
owner 审计；用 `freeze` 生成 owner-safe payload；通过 `owner_async` 投递到
service shard。迁移旧代码前可使用 `lpcc --owner-audit --format=json` 输出机器可读审计结果。

## Expected Performance Model

The multicore runtime improves throughput when a mudlib moves independent
player, room, item, callback, and service work into owner/service paths. It does
not make one same-owner command automatically parallel, and it does not remove
serial work such as IO adapters or unavoidable global coordination.

| Workload | Expected result |
|---|---|
| Single player, light command path | Usually small gain; compatibility overhead may dominate. |
| Many players across owners or rooms | Higher throughput; commands distribute across owner executors. |
| Heartbeat/callout-heavy worlds | Better tail latency because callbacks are admitted and classified. |
| Async/db/file/DNS/socket callback bursts | Better isolation; frozen results return to the callback owner. |
| Unsharded global services | Limited by the remaining service bottleneck. |
| Keyed service shards and owner-safe mudlib code | Best scaling profile, bounded by serial work and core count. |

The theoretical ceiling follows Amdahl's law:

```text
speedup = 1 / (serial_part + parallel_part / cores)
```

If 70% of hot work is owner/service parallel and 30% remains serial, an 8-core
machine has a theoretical ceiling around 2.6x. If a mudlib moves 90% of hot work
into owner/service paths, the same machine has a theoretical ceiling around
4.7x. Real gains depend on shard keys, mudlib structure, persistence cost,
callback volume, and fallback counters.

多核收益来自把相互独立的玩家、房间、物品、callback 和服务工作迁移到 owner/service
路径。它不会让单个 same-owner 命令自动并行，也不会消除 IO adapter 或全局协调这类串行部分。

理论上限符合 Amdahl 定律。若 70% 热路径可按 owner/service 并行，30% 仍串行，
8 核机器理论上限约 2.6x；若 90% 热路径进入 owner/service，8 核理论上限约 4.7x。
真实收益取决于 shard key、mudlib 结构、持久化成本、callback 规模和 fallback 计数。

## Build And Verify

```bash
git clone https://github.com/FengYunCalm/Fluffos_XK.git
cd Fluffos_XK
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target driver lpcc lpc_tests -j2
build/src/tests/lpc_tests
```

Runtime-focused checks:

```bash
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
tools/lpc-modern-runtime-stress.sh smoke
```

Benchmarks and diagnostics:

```bash
cmake --build build --target owner_runtime_bench lpc_vm_bench object_store_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

构建入口使用 CMake。核心验证包括 C++ `lpc_tests`、LPC
`owner_executor_contract` 和 `tools/lpc-modern-runtime-stress.sh smoke`。
性能报告通过 `owner_runtime_bench`、`lpc_vm_bench` 和 `object_store_bench`
输出 JSON，用于趋势和退化定位，不建议用机器相关绝对耗时作为硬门槛。

## Downstream Integration

Recommended flow for a game repository:

1. Pin a FluffOS_XK commit or release tag.
2. Build `driver`, `lpcc`, and `lpc_tests`.
3. Run engine tests and runtime contracts.
4. Copy the rebuilt binaries into the game runtime tree.
5. Run game-level smoke tests for login, gateway, commands, movement,
   persistence, reconnect, heartbeat, callout, and callbacks.
6. Use `lpcc --owner-audit --format=json` and `vm_owner_runtime_status()` to
   verify real owner/service usage.

下游游戏仓库推荐流程：

1. 固定一个 FluffOS_XK commit 或 release tag。
2. 构建 `driver`、`lpcc` 和 `lpc_tests`。
3. 运行引擎测试和 runtime contract。
4. 将重建的二进制同步到游戏运行树。
5. 在项目侧验证登录、gateway、命令、移动、持久化、断线重连、heartbeat、callout 和 callback。
6. 使用 `lpcc --owner-audit --format=json` 与 `vm_owner_runtime_status()` 验证真实 owner/service 使用情况。

## Documentation

- [Documentation index / 文档入口](docs/index.md)
- [Engine overview / 引擎概览](docs/fluffos-xk-overview.md)
- [Build guide / 构建指南](docs/build.md)
- [LPC Modern Runtime / LPC 现代运行时](docs/lpc-modern-runtime.md)
- [Owner Multicore API / Owner 多核接口](docs/owner-multicore-api.md)
- [Multicore Runtime v4 / 多核运行时 v4](docs/multicore-runtime-v4.md)
- [Production Gate / 生产门禁](docs/multicore-production-gate.md)
- [Driver CLI](docs/cli/driver.md)
- [lpcc CLI](docs/cli/lpcc.md)
- [LPC Reference](docs/lpc/index.md)

## Upstream And License

Upstream FluffOS remains the canonical base: <https://github.com/fluffos/fluffos>
Official FluffOS documentation: <https://www.fluffos.info>

License: [MIT](LICENSE). Historical LPmud/MudOS notices remain in
[Copyright](Copyright), [NOTICE](NOTICE), and `src/thirdparty/*`.

上游 FluffOS 仍是 canonical base：<https://github.com/fluffos/fluffos>
官方文档：<https://www.fluffos.info>

许可证为 [MIT](LICENSE)。历史 LPmud/MudOS notice 保留在 [Copyright](Copyright)、
[NOTICE](NOTICE) 和 `src/thirdparty/*`。
