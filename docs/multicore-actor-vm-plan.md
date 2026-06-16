# FluffOS_XK 最终多核化一镜到底执行方案

## 最终结论

FluffOS_XK 的最终多核化路线采用 owner/actor 分片 VM，而不是给旧对象系统到处加锁。

目标是：

- 同一 owner 内保持 LPC 串行语义。
- 不同 owner 可以并行执行。
- 跨 owner 禁止直接写对象。
- 跨 owner 只允许 message、snapshot、future。
- XiaKeXing `cloud` 运行树作为真实业务验收场景。

## 现状基线

当前已经具备：

- `VMContext` 线程本地化。
- `VMWorkerRuntime` 受控后台任务。
- owner id、owner epoch、owner mailbox、trace。
- 主线程 owner queue，已接管 gateway/player input、到期 callout、heartbeat、async/db/file completion、DNS callback、socket read/write/close callback 的 owner-bound 分发。
- `current_object`/`current_prog`/`previous_ob`/`caller_type` execution frame setter，`call_origin` 和 inherit offset setter，`command_giver` 的 VMContext setter/保存栈同步，`current_interactive` 的 VMContext setter/scope，以及 `current_error_context` 和 eval error flags 的 VMContext 同步，已用于 apply/direct/function pointer、interactive/gateway 高频入口和 `this_player()` 读取路径。
- owner thread opt-in。
- registered owner LPC task allowlist。
- Gateway session 集成。
- 真实业务素材：`.internal/test-sources/XiaKeXing`。
- 压测工具：`.internal/test-tools/loadtest`。

当前尚未完成：

- object store 仍是全局模型。
- heartbeat/callout 已先进入主线程 owner queue，但尚未 owner shard 并行执行。
- interactive/gateway input 已先进入主线程 owner queue，且 `current_object`、`current_prog`、`previous_ob`、`caller_type`、`call_origin`、inherit offset、`current_interactive`、`command_giver`、`current_error_context`、eval error flags 高频入口已收敛到 VMContext API；eval stack 和 object store 仍未完全 owner-local 化。
- `call_other` 仍可形成跨 owner 同步调用。
- array/mapping/object ref 跨线程内存模型还未封口。
- async/db/file completion、DNS callback、socket read/write/close callback 已先进入主线程 owner queue；`socket_release` callback 因同步返回语义仍保留原路径。

## 阶段 0：固定迁移边界

目的：避免边改边漂。

执行：

- 保留当前 `VM worker`、`owner mailbox`、`owner thread` 作为基础。
- 新增运行模式配置：`multicore mode : off`、`multicore mode : audit`、`multicore mode : enforced`。
- 默认先使用 `audit`，不直接强制旧 mudlib。
- `XiaKeXing cloud` 运行树作为真实场景，不进入 git 提交。

涉及位置：

- `src/base/internal/rc.cc`
- `src/include/runtime_config.h`
- `src/vm/internal/owner.cc`

验收信号：

- driver 可读取 multicore mode。
- off 模式保持旧行为。
- audit 模式开始记录跨 owner 风险。

## 阶段 1：owner 模型正式化

目的：让 owner 从 trace 标签变成调度归属。

执行：

- 每个 `object_t` 必须有 owner。
- clone、load、exec、move、destruct 保留或更新 owner。
- 无 owner 对象归入 `legacy/main`。
- `vm_owner_guard` 升级为正式约束。
- owner epoch 作为对象生命周期版本。

默认规则：

- 玩家/session owner：`session:<id>`。
- 房间 owner：`room:<path or region>`。
- NPC/物品 owner：继承容器 owner，或归属系统 owner。
- daemon/service owner：`service:<name>`。
- 无法判断：`legacy/main`。

涉及位置：

- `src/vm/internal/owner.cc`
- `src/vm/owner.h`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/simulate.cc`
- `src/packages/core/vm_owner.cc`

验收信号：

- 新建、clone、移动、销毁对象都有 owner/epoch。
- XiaKeXing 启动后核心对象不再大面积无 owner。

## 阶段 2：引入 ObjectHandle

目的：切断跨 owner 裸指针访问。

执行：

- 新增 `ObjectHandle`。
- `ObjectHandle` 包含 object id、owner id、epoch、object path。
- 全局查找优先返回 handle。
- owner-local 执行时才能解引用 handle。
- 跨 owner 只能携带 handle，不能长期持有 `object_t*`。
- destruct 后 epoch 变化，旧 handle 失效。

建议新增：

- `src/vm/object_handle.h`
- `src/vm/internal/object_store.h`
- `src/vm/internal/object_store.cc`

涉及位置：

- `src/vm/internal/simulate.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/apply.cc`

验收信号：

- 跨 owner 访问能检测 stale handle。
- destruct 后旧引用不能跨线程继续使用。

## 阶段 3：owner shard object store

目的：把对象表从全局模型拆成 owner 分片模型。

执行：

- 引入 `VMObjectShard`。
- 每个 shard 维护 owner id、local objects、destruct queue、heartbeat queue、callout queue、pending messages。
- 主线程保留 global index，不直接拥有所有执行状态。
- owner executor 只操作当前 owner shard。

涉及位置：

- `src/vm/internal/object_store.cc`
- `src/vm/internal/context.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/vm.cc`

验收信号：

- 同一 owner 的对象在同一 shard。
- 不同 owner 的对象可被不同 executor 处理。
- 非 owner 线程不能直接同步 object store。

## 阶段 4：owner executor 替代实验 owner thread

目的：把 owner mailbox 升级成正式 LPC 调度器。

执行：

- 新增 `OwnerExecutor`。
- 线程池从 runnable owner 队列取任务。
- 同一 owner 只能被一个 executor claim。
- 一个 owner 执行固定 budget 后释放。
- 支持 owner 在任务间迁移到不同线程。
- 任务类型统一覆盖 command、heartbeat、callout、apply、message、async/db/file completion、gateway input、DNS callback、socket read/write/close callback、maintenance。
- 当前过渡层先使用主线程 owner queue 固定这些任务的 owner FIFO、轮转和 stale epoch 语义。

涉及位置：

- `src/vm/internal/owner.cc`
- `src/vm/owner.h`
- `src/backend.cc`

验收信号：

- 两个不同 owner 可同时执行。
- 同一 owner 永不并发。
- owner 卡住不会拖死全部 owner。

## 阶段 5：command / interactive / gateway 输入 owner 化

目的：玩家命令不再全部挤在主线程。

执行：

- interactive 绑定 session owner。
- 网络层只接收、解析、投递。
- 命令执行先进入主线程 session owner queue。
- `this_player()`、`current_interactive` 进入 owner-local execution state。
- gateway create、destroy、send、inject 都投递到 owner executor。
- session 对象迁移时更新 handle，不移动裸指针。

涉及位置：

- `src/comm.cc`
- `src/interactive.h`
- `src/user.cc`
- `src/packages/gateway/gateway.cc`
- `src/packages/gateway/gateway_session.cc`
- `src/vm/internal/context.cc`

验收信号：

- 最终验收：多个 XiaKeXing 玩家命令可按 session owner 并行。
- 过渡验收：多个 XiaKeXing 玩家命令可经 session owner queue 串行分发并保持 gateway 行为。
- 单个玩家命令仍串行。
- gateway session 生命周期不依赖主线程直接执行 LPC。

## 阶段 6：heartbeat / callout owner-local

目的：让游戏世界 tick 并行。

执行：

- `set_heart_beat` 注册到对象 owner shard。
- `call_out` 注册到当前 owner 或目标 owner。
- 过渡层先由 backend 推进时间，到期任务投递到主线程 owner queue。
- 最终层由 owner executor 执行到期 heartbeat/callout。
- cross-owner callout 改成 message/future。

涉及位置：

- `src/packages/core/heartbeat.cc`
- `src/packages/core/call_out.cc`
- `src/backend.cc`
- `src/vm/internal/simulate.cc`

验收信号：

- 不同 owner 的 heartbeat 可并行。
- 过渡验收：到期 heartbeat/callout 已按 owner queue 分发，并在 owner epoch 变化后丢弃 stale task。
- 大房间或高频 NPC 不阻塞所有玩家。

## 阶段 7：cross-owner call_other 改造

目的：封住最大并发风险。

执行：

- owner-local `call_other` 保持同步。
- cross-owner `call_other` 在 audit 模式记录。
- cross-owner `call_other` 在 enforced 模式拒绝。
- 新增替代 API：`owner_send(owner, message)`、`owner_call_async(object, method, args...)`、`owner_future_poll(id)`、`owner_snapshot(object)`、`owner_publish_snapshot(mapping data)`。

涉及位置：

- `src/packages/core/efuns_main.cc`
- `src/vm/internal/apply.cc`
- `src/vm/internal/simulate.cc`
- `src/packages/core/core.spec`

验收信号：

- XiaKeXing 中跨 owner 同步调用可被 audit 定位。
- enforced 下跨 owner 同步写对象失败。
- message/future 可替代核心交互路径。

## 阶段 8：冻结值与消息协议

目的：禁止跨 owner 共享 mutable value。

执行：

- array/mapping/class 默认 owner-local mutable。
- 跨 owner payload 必须 frozen 或 deep copy。
- object 不能作为 message payload 直接传递，只能传 handle。
- program bytecode 可 immutable 共享。
- string refcount 改 atomic 或 shard-local。
- object release 走 owner-local deferred release。

涉及位置：

- `src/vm/internal/base/array.cc`
- `src/vm/internal/base/mapping.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/base/program.cc`
- `src/vm/internal/base/function.cc`
- `src/vm/internal/base/svalue.cc`
- `src/vm/internal/stralloc.cc`

验收信号：

- mapping/array 跨 owner 后不能被双方同时改。
- message payload 不含裸 `object_t*`。
- future 返回值符合 frozen/deep copy 规则。

## 阶段 9：async/db/file/network 回调 owner 化

目的：外部 I/O 完成后回到正确 owner。

执行：

- async 回调记录发起 owner。
- db/file/socket/external 事件投递到 owner queue。
- owner 已销毁或 epoch 不匹配时丢弃或 dead-letter。
- callback 不直接进入主线程执行 LPC。

涉及位置：

- `src/packages/async/`
- `src/packages/db/`
- `src/packages/external/`
- `src/packages/sockets/`
- `src/packages/core/file.cc`

验收信号：

- I/O 回调不会跨 owner 修改对象。
- XiaKeXing 登录、存档、网关事件仍能正常闭环。

## 阶段 10：VM worker 并入 owner/future 体系

目的：让现有 worker 不是孤立实验能力。

执行：

- compute worker 只跑 pure/frozen CPU task。
- owner executor 跑 owner-local LPC。
- 两者共享 future/message。
- compute 结果投递回发起 owner。
- compute worker 永远不能拿 mutable object。

涉及位置：

- `src/vm/internal/worker.cc`
- `src/vm/internal/owner.cc`
- `src/packages/core/vm_worker.cc`
- `src/packages/core/vm_owner.cc`

验收信号：

- `snapshot_digest`、`actor_score`、`combat_damage` 结果回到 owner queue。
- worker 不直接触碰 object store。

## 阶段 11：XiaKeXing 真实运行树迁移

目的：让引擎改造绑定真实业务，而不是只在 toy tests 里成立。

现有素材：

- 源码：`.internal/test-sources/XiaKeXing`
- 分支：`cloud`
- 提交：`f80968b0868059d97e02da4062c3a233f1225bd8`
- 压测工具：`.internal/test-tools/loadtest/xkx_websocket_loadtest.py`

执行顺序：

1. 用新 driver 替换 `.internal/test-sources/XiaKeXing/driver/bin/driver`。
2. 启动 XiaKeXing server 和 gateway。
3. 在 `multicore mode : off` 下确认兼容。
4. 切到 `audit`，收集无 owner 对象、cross-owner `call_other`、mutable payload 跨 owner、stale handle、owner queue 延迟。
5. 根据 audit 结果给 XiaKeXing server 层补 owner 归属规则。
6. 先迁移 daemon/service，再迁移 player/session，再迁移 room/NPC/item。
7. 最后切 `enforced` 验证真实运行路径。

XiaKeXing 迁移优先级：

- `server/kernel/login/*`
- `server/daemons/services/system/command_dispatch_d.c`
- `server/daemons/services/*`
- `server/kernel/framework/xk_protocol_core.c`
- `server/world/*`
- `server/config/content/*`

验收信号：

- 多用户 WebSocket 登录稳定。
- 玩家命令进入 session owner。
- 房间/NPC heartbeat 不阻塞所有用户。
- 跨 owner 调用能被 message/future 替代。
- enforced 模式下核心登录、移动、查看、基础战斗可跑。

## 阶段 12：清理旧全局执行假设

目的：完成真正多核 VM 收口。

执行：

- 把 `current_object`、`command_giver`、`current_interactive`、`previous_ob`、`current_prog`、`caller_type` 纳入 `VMContext` 或 owner shard。
- 把 eval stack、error context、object list、destruct list、heartbeat list、callout list、apply return 临时值纳入 `VMContext` 或 owner shard。
- process-global 只保留 immutable config、logger、metrics、program immutable cache、string intern table。

验收信号：

- 主线程不再是唯一 LPC 执行点。
- owner executor 中 `this_player()`、`previous_object()`、`current_object` 语义稳定。
- 新代码不再依赖隐式全局执行状态。

## 最终落地顺序

实际执行顺序：

1. 加 `multicore mode`。
2. owner 正式化。
3. ObjectHandle。
4. owner shard。
5. 主线程 owner queue 接管 input/callout/heartbeat。
6. OwnerExecutor。
7. interactive/gateway owner-local 化。
8. heartbeat/callout owner-local。
9. cross-owner call audit。
10. message/snapshot/future。
11. frozen payload。
12. async/db/file/network owner 化。
13. VM worker 并入 future。
14. XiaKeXing audit 迁移。
15. XiaKeXing enforced 运行。
16. 清理旧全局状态。

## 关键原则

- 先 audit，再 enforced。
- 先 handle，再 shard。
- 先 message/future，再禁止 cross-owner sync call。
- 先 owner-local 串行，再 cross-owner 并行。
- 不允许 worker 直接碰 mutable object。
- 不允许靠 mutex 把旧 VM 硬改成并发 VM。

## 最终完成标准

可以宣称多核化真正完成的标准：

- 不同 owner 的 LPC 能同时跑在不同 CPU 核。
- 同一 owner 内命令、heartbeat、callout 永不并发。
- 跨 owner 写对象被 runtime 阻止。
- 跨 owner 只能通过 message、snapshot、future。
- XiaKeXing `cloud` 运行树能在 enforced 模式下完成登录、移动、查看、基础战斗、网关压测。
- 一个 owner 卡住不会拖死全部玩家。
- destruct 后对象不会被其他线程通过旧指针访问。
- 主线程 CPU 不再随所有 LPC 计算线性增长。
