# FluffOS_XK 项目现状与多核化改造说明

## 结论

FluffOS_XK 当前已经从“单主线程、全局可变 VM 状态”的传统 driver 形态，推进到具备 owner 边界、线程本地 VMContext、受控 VM worker 和 owner mailbox 的运行时基础设施。

这次多核化改造的核心成果不是开放任意 LPC 后台线程执行，而是把可安全迁移的计算、快照处理、owner 调度和边界观测先从主线程模型中拆出来，为后续 actor-style 服务化和更细粒度的多核利用打基础。

## 当前项目状态

FluffOS_XK 是 FluffOS 的公开维护分支，面向实际运行项目提供源码级 driver 基线。仓库仍保持经典 FluffOS driver 模型，不绑定具体游戏 mudlib，不包含私有部署数据。

当前主线重点包括：

- 构建稳定性，尤其是 Linux、Windows/MSYS2 和 CMake install 路径。
- Gateway/session 集成，服务 WebSocket 客户端和服务化部署。
- VMContext、owner-runtime 和 VM worker 基础设施。
- 核心模块告警清理和第三方依赖告警控制。
- README、贡献指南、安全策略、变更记录等公开仓库基础整理。

关键代码位置：

- `src/vm/context.h` 和 `src/vm/internal/context.cc`：线程本地 VMContext 与主线程 object store 边界。
- `src/vm/worker.h` 和 `src/vm/internal/worker.cc`：VM worker runtime 与受控任务队列。
- `src/vm/owner.h` 和 `src/vm/internal/owner.cc`：owner metadata、mailbox、trace、owner thread。
- `src/packages/core/vm_worker.cc`：LPC 侧 worker efun 封装。
- `src/packages/core/vm_owner.cc`：LPC 侧 owner efun 封装。
- `src/packages/gateway/`：Gateway session runtime。
- `src/tests/test_lpc.cc`：当前主要 C++ 回归测试。

## 多核化改造做了什么

### 1. VMContext 线程隔离

传统 FluffOS 大量依赖全局 VM 状态，例如当前对象、命令发起者、当前 interactive、当前程序和对象链表。多线程改造如果直接共享这些状态，会引入对象生命周期、执行栈和跨线程访问风险。

当前改造加入了线程本地 `VMContext`：

- 主线程维护真实 object store 快照。
- 非主线程绑定自己的 `VMContext`。
- 非主线程尝试同步 object store 时会被拒绝，并清空对象链表快照。
- `VMExecutionScope` 用于保存和恢复执行上下文。
- `VMOwnerScope` 用于在受控任务中绑定 owner id 和 owner epoch。

直接效果：worker 和 owner thread 不再默认继承主线程对象表，避免把非线程安全的对象系统误当作可并发访问资源。

### 2. VM worker 受控任务队列

`VMWorkerRuntime` 提供独立 worker 线程池。默认根据硬件线程数启动，线程数限制在 `1..64`。同一 `owner_key` 的任务会串行化，避免同一 actor 的任务并发执行。

当前 worker 支持的任务类型是固定白名单：

- `bench`：并行基准和调度验证。
- `snapshot_digest`：对快照文本做稳定 digest。
- `actor_score`：根据角色快照计算状态评分。
- `combat_damage`：根据输入快照计算战斗伤害。

LPC 侧接口支持同步执行、异步 submit/poll、批量 submit/poll、timeout 和 TTL。输入会经过可序列化检查，避免把任意对象、函数或深层复杂结构送入后台线程。

直接效果：计算型、快照型、确定性任务可以脱离主循环执行，主线程可以继续承担连接、命令、对象生命周期和 VM 主状态维护。

### 3. owner-runtime 与 mailbox

owner-runtime 给对象引入 owner id 和 owner epoch，用于标记执行归属和检测陈旧任务。

当前能力包括：

- `vm_owner_id`、`vm_owner_epoch`、`vm_owner_guard`、`vm_owner_guard_epoch`。
- owner mailbox 入队、调度、drain、purge 和状态查询。
- 主线程 owner queue，用于按 owner/epoch 投递和分发 gateway/player input、callout、heartbeat、async/db/file completion、DNS callback、socket read/write/close callback。
- `current_object`/`current_prog`/`previous_ob`/`caller_type` execution frame setter，`call_origin`、inherit offset 和 stack temporary depth setter，`command_giver` 的 VMContext setter/保存栈同步，`current_interactive` 的 VMContext setter/scope，以及 `current_error_context` 和 eval error flags 的 VMContext 同步，用于收敛解释器执行状态的保存恢复。
- task trace、access trace、message trace、commit trace。
- owner thread opt-in 启动，最大线程数为 `4`。

mailbox 和主线程 owner queue 调度保持 owner 内 FIFO，同时在不同 owner 之间轮转。owner thread 会在独立 `VMContext` 中执行，并在每个任务结束后检查 owner、execution 和 canary 状态是否清理干净。

主线程 owner queue 当前承担过渡职责：网络输入、gateway 命令、到期 callout、heartbeat、async/db/file completion、DNS callback 以及 socket read/write/close callback 先进入 per-owner 队列，再在主线程绑定 `VMOwnerScope` 后执行。这样能先固定 owner 调度语义和 stale epoch 防线，同时避免在全局 VM 状态还未完全迁出前贸然让后台线程执行任意 LPC。

直接效果：项目开始具备 actor-style 迁移所需的运行时形状，也可以观察跨 owner 访问、消息边界和任务生命周期。

### 4. 受限 owner LPC 任务

当前没有开放任意 LPC 方法后台执行。owner thread 对普通 `lpc` 任务默认拒绝。

已经开放的是受控路径：

- `lpc_probe`：验证 off-main context、object store isolation 和 owner 绑定。
- `lpc_canary`：只允许 `owner_lpc_canary`。
- `lpc_task`：只允许注册过的 owner domain task。

当前注册的 owner domain task 包括：

- `owner_task_readonly`
- `owner_task_player`
- `owner_task_room`
- `owner_task_session`
- `owner_task_item`
- `owner_task_economy`
- `owner_task_combat`
- `owner_task_mail`
- `owner_task_reward`
- `owner_task_world`
- `owner_task_persistence`
- `owner_task_team`
- `owner_task_guild`
- `owner_task_sect`
- `owner_task_quest`
- `owner_task_rank`
- `owner_task_crafting`
- `owner_task_life_skill`

这些任务执行前必须满足：

- 当前上下文不是主线程 VMContext。
- object store 处于隔离状态。
- 当前 owner id 和 owner epoch 已绑定。
- 目标对象未析构。
- 目标对象 owner epoch 匹配。
- 方法名在注册白名单内。

直接效果：LPC 后台执行的边界被显式收窄，避免“为了多核化而破坏对象系统安全”。

### 5. 跨 owner 访问观测

当前 runtime 会记录关键跨 owner 访问路径，例如：

- `environment`
- `all_inventory`
- `present`
- `call_other`
- `move_object`
- `destruct`

access trace 会把跨 owner 操作分类为 snapshot、message 或 reject 风格。这一层当前更偏观测和迁移辅助，不应理解成已经完成所有跨 owner 写入隔离。

直接效果：下游可以先看到哪些旧 LPC 逻辑仍然依赖全局对象互访，再逐步迁移到快照读取或消息提交模型。

## 改造效果

### 工程效果

- 主线程边界更清楚：对象表和核心 VM 状态仍归主线程管理。
- 后台任务边界更清楚：worker 只处理固定、可序列化、确定性的任务。
- owner 迁移路径更清楚：owner id、epoch、mailbox、trace 和 allowlist 已经具备。
- 风险可观测：跨 owner 访问、任务派发、上下文清理、canary 和 rejected task 都有计数或 trace。
- 下游集成更稳定：Gateway session 和 README/发布规范让引擎仓库更适合作为公开依赖。

### 性能方向效果

多核化当前最直接的收益是让部分计算型任务从主事件循环中剥离出来，降低主线程被 CPU 计算阻塞的概率。适合迁移的任务包括：

- 基于快照的摘要和校验。
- 角色状态评分。
- 战斗数值计算。
- 未来可白名单化的 owner domain 任务。

需要注意的是，当前仓库没有宣称完整生产压测数据，也没有把任意 LPC 对象操作搬到后台线程。当前成果更准确地说是“多核化运行时地基已经落地，并通过测试覆盖关键安全边界”。

### 可维护性效果

- 多核相关代码集中在 `context`、`worker`、`owner` 和 core efun 封装中。
- 关键行为有 `src/tests/test_lpc.cc` 覆盖。
- README 已明确项目范围，降低下游误用风险。
- owner task allowlist 让新增后台 LPC 能力必须显式注册，而不是默认开放。

## 已验证内容

当前测试重点覆盖：

- VMContext 主线程和 worker 线程绑定。
- 非主线程 object store 同步拒绝。
- VMExecutionScope、execution frame/call origin/inherit offset/stack temporary depth setter、VMCurrentInteractiveScope、command_giver 保存栈、error context 栈、eval error flags 和 VMOwnerScope 的保存恢复。
- owner id、epoch、guard、mailbox、schedule、purge。
- owner thread opt-in、上下文绑定、对象表隔离和状态清理。
- 主线程 owner queue 的 owner scope 绑定和 stale owner epoch 丢弃。
- 普通 LPC 任务默认拒绝。
- restricted canary 和 registered owner LPC task。
- 未注册 owner LPC task 拒绝。
- VM worker 的同步、异步、批量、timeout、TTL 和结果轮询。
- Gateway session 创建、销毁、exec logon 后 session 绑定。

推荐验证命令：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
cd testsuite && ../build/bin/driver etc/config.test -ftest
```

## 当前边界

- 不支持任意 LPC 在后台线程自由执行。
- gateway/player input、callout、heartbeat、async/db/file completion、DNS callback、socket read/write/close callback 已进入主线程 owner queue，但尚未变成后台 owner executor 并行执行。
- apply/direct/function pointer 高频入口已通过 VMContext API 设置 `current_object`、`current_prog`、`previous_ob`、`caller_type`、`call_origin`、inherit offset 和 stack temporary depth；interactive/gateway 高频入口已通过 VMContext API 设置 `current_interactive`，`command_giver` 保存栈、`current_error_context` 和 eval error flags 会同步 VMContext，`this_player()` 读取 VMContext execution 快照；但 eval stack 和对象存储还没有完全 owner-local 化。
- `socket_release` callback 仍保持同步路径，因为 efun 返回值依赖 callback 是否立即完成 release/acquire 交接。
- 不应把 owner thread 理解为传统对象系统的并发写入口。
- 跨 owner access trace 当前主要用于观测、分类和迁移辅助。
- worker 任务必须是固定任务类型，并使用可序列化输入。
- owner thread 是 opt-in，最大线程数为 `4`。
- 生产性能收益需要结合具体 mudlib、任务粒度和主线程负载继续压测。

## 面向下游的建议

下游项目如果要利用这次改造，建议按以下顺序推进：

1. 先把纯计算逻辑整理成基于快照的输入输出。
2. 用 `snapshot_digest`、`actor_score`、`combat_damage` 这类固定 worker task 验证任务切分收益。
3. 给关键服务对象设置 owner id，并观察 access trace。
4. 把跨 owner 直接调用逐步改成 snapshot 或 message 风格。
5. 对确实安全的 LPC domain task 走显式注册和 canary 验证。
6. 最后再做项目侧压测，比较主线程延迟、命令响应和 CPU 利用率。

## 对外表述口径

建议对外这样描述：

FluffOS_XK 已经完成第一阶段多核化运行时基础改造。它通过线程本地 VMContext、受控 VM worker、owner mailbox 和 owner-bound execution，把传统 LPC driver 从单一全局执行模型推进到可逐步 actor 化的架构。当前重点是安全边界和可验证迁移路径，而不是开放不受限制的后台 LPC 执行。
