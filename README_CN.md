# FluffOS_XK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMake](https://img.shields.io/badge/build-CMake-blue.svg)](CMakeLists.txt)
[![LPC Runtime](https://img.shields.io/badge/runtime-LPC%20%2F%20MUD-informational.svg)](https://www.fluffos.info)
[![Multicore](https://img.shields.io/badge/multicore-owner%2Fservice%20executor-success.svg)](docs/multicore-runtime-v2.md)

[English](README.md) | 简体中文

FluffOS_XK 是面向现代 LPC/MUD 项目的生产型 FluffOS 引擎分支。它保留经典
FluffOS driver 模型，同时提供已经封版的 owner/service 多核运行时基线、
更清晰的 gateway 集成、更稳定的构建行为，以及适合下游项目长期维护的引擎边界。

当你需要一个可以重建、审计、接入真实游戏仓库的源码级 LPC 运行时时，可以使用
FluffOS_XK。引擎工作留在本仓库；mudlib、世界内容、账号、部署密钥和运维策略留在
你自己的游戏仓库。

## 为什么选择 FluffOS_XK

- **生产多核基线已完成**：当前 owner/service executor 合同已覆盖 object
  lifecycle、heartbeat、callout、async/file/db、DNS、socket callback、gateway
  command、target-owner message，以及 `socket_release` release/acquire handshake。
- **默认安全**：普通 legacy LPC 不会被任意放到后台线程执行。进入多核 executor
  必须满足显式 ownership、allowlist、driver callback、frozen payload、
  ObjectHandle 或 owner/service shard 合同。
- **适合下游游戏消费**：引擎仓库与游戏仓库分离，下游可以稳定同步 driver，同时避免把
  私有内容、账号数据或部署细节混进引擎。
- **现代客户端路径**：gateway/session 集成支持 WebSocket 客户端和服务化部署。
- **便于公开审查**：CMake、安装行为、告警清理、发布说明、安全策略和项目范围都保持
  明确，便于外部审查和二次集成。

## 包含什么

FluffOS_XK 聚焦引擎运行时基础能力：

- LPC 解释器、网络服务、EFUN/apply glue 和经典 FluffOS driver 模型；
- owner metadata、ObjectHandle route、VMContext isolation、OwnerExecutor task、
  owner future、shard-aware message 和生产门禁合同；
- 通过受控 owner/service executor 路径执行 gateway command 与 callback dispatch；
- Linux、WSL、Windows/MSYS2 和面向安装场景的 CMake 工作流；
- 面向下游项目的稳定引擎基线文档。

它不捆绑完整游戏 mudlib，不取代上游 FluffOS 的 canonical 地位，也不会在没有显式
ownership 合同的情况下开放不安全的任意后台 LPC 执行。

## 多核运行时

当前生产基线是一套受控的 owner/service 多核运行时。它适合希望把可变游戏状态从全局
单线程热点迁移出来，同时继续兼容经典 LPC 模型的项目。

关键性质：

- same-owner 执行保持直接快速；
- cross-owner 工作通过 snapshot、ObjectHandle route、owner message、future 或
  service shard domain 完成；
- stale owner、destructed object、epoch mismatch、payload policy 和 cleanup failure
  都由运行时合同分类；
- main thread 只保留 IO adapter、cleanup adapter、explicit fallback 和明确的兼容面；
- 生产正常路径要求 `normal_path_main_fallback_count=0`。

接入 mudlib 前请先阅读这些权威入口：

- [Runtime v2 contract](docs/multicore-runtime-v2.md)
- [Runtime v4 hardening baseline](docs/multicore-runtime-v4.md)
- [Production gate](docs/multicore-production-gate.md)
- [Owner multicore API](docs/owner-multicore-api.md)
- [Production baseline release note](docs/releases/multicore-production-baseline-2026-06-27.md)
- [Engine overview for integrators](docs/fluffos-xk-overview.md)

## 多核接口怎么用

新的运行时接口是显式的。mudlib 不应该把 live object 或可变 closure 跨 owner
传递，而应该传 frozen data、snapshot、ObjectHandle 路由的 async call，或者
service-domain task。

常用 LPC 入口：

| API | 用途 |
|---|---|
| `vm_owner_id(object)` / `vm_owner_epoch(object)` | 查询对象 owner 和生命周期 epoch。 |
| `vm_owner_guard(object, string)` / `vm_owner_guard_epoch(object, string, int)` | 在敏感写入前检查 owner 或 owner+epoch。 |
| `owner_query_object_snapshot(object)` | 不执行目标 LPC，读取 cross-owner 对象的安全结构信息。 |
| `owner_send(string owner_id, mapping payload)` | 向 owner mailbox 发送 frozen data，并返回 future id。 |
| `owner_call_async(object target, string method, mapping payload)` | 通过 ObjectHandle 和 owner executor guard 调用目标对象。 |
| `owner_future_poll(int future_id)` | 查询 pending/completed/failed 状态和 frozen result。 |
| `owner_snapshot(object)` / `owner_publish_snapshot(mapping)` | 用 snapshot 数据替代可变对象共享。 |
| `vm_owner_runtime_status()` | 查看生产门禁字段、domain registry、fallback counter 和 executor 状态。 |

payload 规则在 owner message、async call、snapshot、worker result 和 domain task
之间共享：

- top-level owner payload 必须是 mapping；
- mapping key 必须是 string；
- value 允许 number、real、string、array、mapping；
- nesting depth 有限制；
- object、function、buffer、class 和其他 VM 绑定的可变值会被拒绝。

最小 async 示例：

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

生产 owner domain 由引擎显式注册。当前 allowlist 包含
`owner_task_readonly`、`owner_task_player`、`owner_task_room`、
`owner_task_session`、`owner_task_item`、`owner_task_economy`、
`owner_task_combat`、`owner_task_mail`、`owner_task_reward`、
`owner_task_world`、`owner_task_persistence`、`owner_task_team`、
`owner_task_guild`、`owner_task_sect`、`owner_task_quest`、
`owner_task_rank`、`owner_task_crafting` 和 `owner_task_life_skill`。

真实玩法工作应按 owner 或 service shard 路由到这些 domain。普通 legacy LPC
继续走经典路径，除非它已经有明确的 owner-safe 合同。

## 理论性能提升

多核基线的收益来自把相互独立的 owner/service 工作移出单一全局热路径。它不会让每个
LPC 函数本身变快，也不会让单个玩家的 same-owner 命令自动并行。

预期表现：

| 负载类型 | 预期收益 |
|---|---|
| 单玩家轻命令路径 | 通常很小；兼容层开销可能盖过收益。 |
| 多玩家分布在不同 owner 或房间 | 吞吐提升明显；命令可分摊到 owner executor。 |
| heartbeat/callout 密集世界 | 尾延迟改善，因为 callback 不再全部挤同一条业务路径。 |
| async/db/file/DNS/socket callback 尖峰 | 隔离性更好；frozen result 回到 callback owner，而不是淹没主业务执行。 |
| 全局服务未拆 shard | 会受剩余 service bottleneck 限制。 |
| keyed service shard 和 owner-safe mudlib 改造充分 | 扩展性最好；收益更接近可用核心数，但仍受串行部分限制。 |

理论上限符合 Amdahl 定律：

```text
speedup = 1 / (serial_part + parallel_part / cores)
```

例如，若 70% 工作可按 owner/service 并行，30% 仍串行，8 核机器理论上限约为
2.6x。若 mudlib 把 90% 热路径迁入 owner/service，8 核理论上限约为 4.7x。

真实收益取决于 mudlib 结构、shard key、IO 行为、持久化成本，以及还有多少工作仍走
explicit fallback。引擎会暴露 `normal_path_main_fallback_count`、
`target_owner_message_main_fallback`、owner executor queue state、stale/drop
分类和 future 状态，方便下游项目确认自己是否真的跑在多核路径上。

## 快速开始

```bash
git clone https://github.com/FengYunCalm/Fluffos_XK.git
cd Fluffos_XK
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
tools/wsl-cmake-build.sh build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
```

面向安装的环境可以使用：

```bash
tools/wsl-cmake-build.sh build --target install
```

`tools/wsl-cmake-build.sh` 只是一个很薄的 `cmake --build` 包装，用于从 Windows shell
启动 WSL 构建时固定临时目录。原生 Linux 用户也可以直接调用 CMake。Windows/MSYS2
用户应优先使用 CMake install 路径，而不是手工复制生成的二进制。

## 下游集成方式

下游游戏项目应把 FluffOS_XK 当作引擎源码树，或者当作重建 `driver` 与 `lpcc`
二进制的来源。

推荐流程：

1. 固定一个明确的 FluffOS_XK commit 或 release tag。
2. 构建 `driver`、`lpcc` 和 `lpc_tests`。
3. 运行引擎测试，例如 `build/src/tests/lpc_tests`。
4. 将生成的二进制同步到下游运行树。
5. 在项目侧验证登录、网关、命令、移动、内容加载、持久化和断线重连。
6. mudlib、账号、密钥、部署脚本和运维报告不要放进引擎仓库。

## 文档

- [文档入口](docs/index.md)
- [引擎概览](docs/fluffos-xk-overview.md)
- [构建指南](docs/build.md)
- [Driver CLI](docs/cli/driver.md)
- [LPC reference](docs/lpc/index.md)
- [Owner multicore API](docs/owner-multicore-api.md)
- [Multicore runtime v2](docs/multicore-runtime-v2.md)
- [Multicore runtime v4](docs/multicore-runtime-v4.md)
- [Production gate](docs/multicore-production-gate.md)
- [变更记录](CHANGELOG.md)
- [发布说明](RELEASE.md)

## 贡献

欢迎聚焦的贡献：构建修复、告警清理、测试、文档、gateway/runtime 维护，以及符合本分支
定位的窄范围改进。提交 PR 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

安全问题请负责任地报告，详见 [SECURITY.md](SECURITY.md)。

## 许可与引用

- MIT License：见 [LICENSE](LICENSE)。
- 历史 LPmud/MudOS notice 仍适用于遗留组件：见 [Copyright](Copyright)。
- 第三方许可：见 [NOTICE](NOTICE) 与 `src/thirdparty/*`。

## 上游

- 上游 FluffOS：https://github.com/fluffos/fluffos
- FluffOS 官方文档：https://www.fluffos.info
