# FluffOS_XK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMake](https://img.shields.io/badge/build-CMake-blue.svg)](CMakeLists.txt)
[![LPC Runtime](https://img.shields.io/badge/runtime-LPC%20%2F%20MUD-informational.svg)](https://www.fluffos.info)

[English](README.md) | 简体中文

FluffOS_XK 是 [FluffOS](https://github.com/fluffos/fluffos) 的公开维护分支，面向现代 LPC/MUD 运行时项目。
它保留经典 FluffOS driver 模型，同时改进构建稳定性、网关集成、运行时 ownership 边界和下游引擎维护体验。

这个仓库适合作为源码级 FluffOS 引擎基线使用；它不是完整游戏服务端，也不是对 LPC 生态的重写。

## 特性亮点

- **适合下游项目消费的引擎分支**：引擎仓库与游戏 mudlib 分离，便于下游项目同步 driver 更新，而不会混入游戏内容。
- **owner-runtime 基础设施**：包含运行时 ownership 与 VM worker 基础工作，支持下游逐步迁移到 actor-style 服务边界，同时不开放不安全的任意后台 LPC 执行。
- **面向网关的运行路径**：维护现代 WebSocket 客户端和服务化部署所需的 gateway/session 集成。
- **Linux 与 Windows 构建更稳定**：改进 CMake 与 Windows/MSYS2 安装行为，包括 `cmake --install` 时更安全地覆盖二进制。
- **编译器与依赖卫生**：对核心模块做定向告警清理，并控制 vendored 第三方依赖的噪音告警。
- **开源仓库基础完善**：提供清晰的 license、贡献指南、安全策略、变更记录和明确的维护范围，便于外部审查。

## 为什么维护这个分支

上游 FluffOS 仍然是 driver 的 canonical 来源。FluffOS_XK 的定位是为实际运行项目保留一条生产可用的维护线，满足这些需求：

- 在当前 Linux 与 Windows 工具链上获得可预测的构建结果；
- 为 owner-runtime 与 VM worker 实验提供一个由下游实际使用验证的稳定位置；
- 支持 Web 和移动客户端需要的 gateway 集成；
- 提供一个不夹带私有项目产物、可以公开审查和集成的引擎仓库。

## 运行时重点

FluffOS_XK 关注引擎基础能力，不承载具体玩法规则。

- **owner-bound execution**：ownership 检查与运行时合同支持从全局可变服务逐步迁移到更安全的 owner/actor-style 执行边界。
- **VM worker infrastructure**：worker/context 清理为受控的 off-main 执行路径打基础。
- **Gateway sessions**：gateway session 生命周期与 logon 行为保持可测试，便于面向 WebSocket 客户端。
- **运行树隔离**：游戏仓库可以 pin 或重建这个 driver，而不继承引擎开发分支、私有文档或部署数据。

## 多核化运行时状态

当前多核化工作已经落地为受控运行时基础设施，而不是不受限制的后台 LPC 执行。driver 现在具备线程本地 VMContext、owner-aware worker runtime、owner mailbox、owner task trace，以及受保护的 owner LPC probe/canary 路径。

目前的实际效果：

- 快照摘要、角色评分、战斗伤害计算等 CPU 型任务可以通过 VM worker 执行。
- worker 队列按 owner key 约束，同一 owner 内保持串行，不同 owner 之间可以并行推进。
- owner id、epoch、mailbox trace、access trace、message/commit trace 为下游迁移到 actor-style 服务边界提供观测和迁移路径。
- 普通和注册 LPC task 仍默认禁止 off-main；只有受控 probe/canary 这类验证路径可以进入后台执行。

当前状态、改造效果、边界和下游迁移建议见 `docs/multicore-runtime.md`。

## 获取源码

```bash
git clone https://github.com/FengYunCalm/Fluffos_XK.git
cd Fluffos_XK
```

## 构建

构建步骤使用 `tools/wsl-cmake-build.sh`。它只是 `cmake --build` 的薄包装，
用于在从 Windows shell 启动 WSL 时把临时文件固定到 Linux `/tmp` 路径。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
tools/wsl-cmake-build.sh build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
```

面向安装的环境可以使用：

```bash
tools/wsl-cmake-build.sh build --target install
```

Windows/MSYS2 用户应优先使用 CMake install 路径，而不是手工复制生成的二进制。

## 给下游 MUD 项目

可以把本仓库作为引擎源码树，也可以用它重建 `driver` 与 `lpcc` 二进制。mudlib、世界内容、服务配置、账号和部署数据应留在你自己的项目仓库。

推荐下游流程：

1. 从确定的 FluffOS_XK commit 重建 `driver` 与 `lpcc`。
2. 运行上游引擎测试，例如 `lpc_tests`。
3. 将生成的二进制同步到下游运行树。
4. 在项目侧跑登录、网关、命令、内容加载和持久化 smoke test。

## 项目范围

本仓库接受：

- 构建稳定性、CMake 和安装修复；
- runtime ownership、VM worker 和 gateway 集成维护；
- 聚焦的编译告警清理；
- 让 fork 更容易审查和消费的源码卫生改进。

本仓库不做：

- 捆绑完整游戏 mudlib；
- 取代上游 FluffOS 的 canonical 项目地位；
- 在没有显式 ownership 合同的情况下开放任意后台 LPC 执行；
- 加入私有部署脚本、密钥、账号数据或游戏专属内容。

## 文档

- FluffOS 官方文档：https://www.fluffos.info
- 多核化运行时说明：`docs/multicore-runtime.md`
- 本地文档入口：`docs/index.md`
- 本分支变更记录：`CHANGELOG.md`
- 发布与工作流说明：`RELEASE.md`

## 贡献

欢迎聚焦的贡献，包括构建修复、告警清理、测试覆盖、文档，以及符合本分支定位的运行时维护。提交 PR 前请先阅读 `CONTRIBUTING.md`。

安全问题请负责任地报告，详见 `SECURITY.md`。

## 许可与引用

- MIT License：见 `LICENSE`。
- 历史 LPmud/MudOS notice 仍适用于遗留组件：见 `Copyright`。
- 第三方许可：见 `NOTICE` 与 `src/thirdparty/*`。

## 上游

- 上游项目：https://github.com/fluffos/fluffos
- 官方文档：https://www.fluffos.info
