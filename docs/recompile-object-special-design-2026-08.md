# recompile_object() 热重载专项设计方案（DRAFT，待审计）

> 状态：**DRAFT v0.1 —— 供外部审计；审计通过前不实施**
> 生成日期：2026-08-15
> 前置：FluffOS_XK 上游同步（2026-08 批次）已全部落地（26 commits 已推送）；本方案为
> 批次遗留项 E3 的专项设计前置文档，按 `docs/upstream-sync-optimization-plan-2026-08.md`
> §6.1 条款要求产出
> 执行纪律：本方案任何实施动作（含代码修改）须在审计通过并获用户明确授权后进行

---

## 0. 结论摘要

1. **E3 值得做**：在线热更新（改代码不重启、状态保留）是长期运行 MUD 的运维刚需；上游 PR #1237 已把单线程 VM 下的边界打磨成熟（5 轮 commit）。
2. **不能照搬**：上游在单线程 VM 上实现；本地是 owner/service 多核 VM，program 热替换同时触碰执行栈帧、function pointer 代际、owner shard program pin、跨 owner 引用四类并发面。必须按本地多核语义重新设计后移植。
3. **实施建议**：本方案审计通过后，作为**独立新会话**实施（预计 3-5 天含验证），不混入其它工作。
4. **T3（lpcshell）/ E4（read_source_line）不做**：依赖本地不存在的新诊断渲染器基建（P3 判定不适用），性价比低，保持 deferred。

---

## 1. 上游素材清单（PR #1237，已水合可读）

| commit | 内容 | 关键文件 |
|---|---|---|
| `34d2b299` | recompile_object() 主体：in-place program 更新、状态保留 | function.cc/h（prog_generation 快照）、object.cc/h（program 交换）、efuns_main.cc、core.spec、debugmalloc.h、checkmemory.cc、sprintf.cc |
| `d865b23c` | 支持 master/simul_efun 目标；review 修复 | simulate.cc、simul_efun.cc |
| `af504254` | void mid-update replace_program；覆盖 virtuals | object.cc、disassembler.cc |
| `01ca7f55` | 钉住 shadow/catch_tell/add_action/heart_beat 生存性 | 测试 + 相关实现 |
| `74a65adc` | simul_efun/__INIT 边界修复；callback 覆盖面 | simul_efun.cc、simulate.cc、测试 |

上游核心机制（function.h）：
- `prog_generation`：object 的 program 代际计数，`recompile_object()` 交换 program 时 +1
- FP_LOCAL funptr 在创建/bind 时快照 owner 的 `prog_generation`；调用路径比对代际，不匹配即报错（旧 funp 指向旧 program 的索引失效保护）
- 变量存储布局保持不变（同文件重编译），状态（variables 块）整体保留；变量增删需逐项迁移

## 2. 本地差异与风险面（专项设计必须覆盖）

| # | 风险面 | 本地现状 | 设计必须回答的问题 |
|---|---|---|---|
| R1 | **执行中栈帧** | 控制栈帧持有 `current_prog`/`fr.table_index`（旧 program 索引）；eval 循环在 recompile 进行中不会主动打断 | 热重载仅允许在无 LPC 执行点（backend 空闲/命令边界）触发？还是支持执行中替换？上游语义是什么（建议：仅空闲点，先做保守版） |
| R2 | **FP_LOCAL 代际** | 本地 function.cc 有 FP_LOCAL 分支（S3 刚改过），无 prog_generation 概念 | 移植上游快照+比对机制；本地 funp 生命周期与 owner 引用管理叠加，需审计释放路径 |
| R3 | **owner shard program pin** | 本地 `OwnerProgramPin`（owner.cc）pin 住 program 防跨 owner 释放 | 热重载换 program 时 pin 的是新 program 还是旧？旧 program 的 pin 引用何时释放？（建议：重载后旧 program 进入 deferred release，由 owner executor cleanup 释放） |
| R4 | **跨 owner 引用** | ObjectHandle 携带 program 相关状态？对象跨 owner 迁移时 program 指针共享 | 热重载期间其他 owner 线程能否观察到半替换状态？需要 owner 级互斥或 epoch 检查 |
| R5 | **simul_efun dispatch** | 本地 simul_efun.cc 有 dispatch table | master/simul_efun 自身热重载时 table 重建的原子性；`::` 调用链 |
| R6 | **replace_program 交互** | 本地 replace_program.cc 存在；`replaced_program` 字段 | mid-update replace_program（上游 af504254 已修）本地等价处理 |
| R7 | **shadow/add_action/heart_beat/catch_tell 回调** | 回调注册持有对象引用 + 函数索引 | 上游 01ca7f55 钉住的生存性测试本地需等价覆盖 |
| R8 | **失败原子性** | error() 展开机制（C++ 异常） | 变量迁移中途 error：新 program 已装但变量半迁移——回滚策略（恢复旧 program？标记对象损坏？）上游语义 |
| R9 | **__INIT/继承链** | 本地 create/__INIT 调用链 | 重载后是否重跑 __INIT？继承链上的 program 版本一致性 |

## 3. 专项设计文档必须产出的内容（实施前审计项）

按方案 §6.1 要求，以下每项须形成独立小节并获批：

1. **调用链清单**：`recompile_object()` → program 交换 → 代际递增 → 变量迁移 → pin 释放 的完整 C++ 调用链（含 owner 上下文标注）
2. **失败原子性方案**：迁移中途 error 的回滚/标记策略；旧 program 释放的时机与所有权
3. **owner 并发审计**：R3/R4 的互斥或 epoch 方案；`OwnerProgramPin` 与热重载的交互时序图
4. **测试矩阵**（至少）：
   - 基本：同文件重编译（函数体修改、变量值保留、变量增删、函数增删）
   - 引用：FP_LOCAL funp 重载前创建 → 重载后调用（期望：代际不匹配报错）
   - 回调：shadow/catch_tell/add_action/heart_beat 注册后重载 → 回调仍指向有效对象
   - 特殊目标：master 自身重载、simul_efun 重载、virtual object、replace_program 中重载
   - owner：重载发生在 owner executor 上下文 vs 主线程；跨 owner 对象持有目标引用
   - 失败注入：变量迁移中途 error（用巨型变量/故意坏类型）
   - 回归：`recompile_object` 不触发时全量现有测试不变
5. **范围裁剪建议**（供审计决策）：
   - v1 只支持"空闲点重载 + 同文件变量布局不变 + 无 shadow 对象"；其余能力（执行中替换、master/simul_efun、shadow 目标）v2 再开
   - 或 v1 即对齐上游全部能力（风险更高，验证周期更长）

## 4. 实施计划（审计通过后）

| 阶段 | 内容 | 产出 |
|---|---|---|
| P0 | 移植上游 function.h/cc 的 prog_generation 机制 + object.h/cc program 交换核心 | 编译通过 + 上游单测等价移植 |
| P1 | 变量迁移 + 失败原子性（R8） | 迁移器 + 回滚策略测试 |
| P2 | owner 并发收口（R3/R4）：pin 时序 + epoch 检查 | owner 合同测试 |
| P3 | 特殊目标（master/simul/virtual/replace_program，R5/R6） | 对应测试 |
| P4 | 回调生存性（R7）+ 上游 5 commit 全量边界测试 | 全量矩阵 |
| P5 | 验证：ASan/TSan、回归、owner 压测 | 证据文档 |

每阶段独立 commit + 验证；与方案 v2.4 相同的门禁纪律（针对性测试 → 全量回归 → sanitizer）。

## 5. 明确不做（保持 deferred）

- **T3 lpcshell**：依赖本地不存在的 scratchpad/结构化诊断基建，无独立载体
- **E4 read_source_line 优化**：与 T3 同源（P3 判定不适用）
- 上游编译器 flex 重构 / transport 抽象 / ffi / WASM：与本地多核改造冲突大，维持原方案"不做"清单

## 6. 待审计决策点

1. E3 范围：保守 v1（空闲点+同布局+无 shadow）还是对齐上游全能力？
2. R1 执行中替换：上游是否支持？若支持，本地先禁止（error 拒绝）还是实现？
3. R8 失败原子性：回滚旧 program vs 标记对象损坏（kill），审计倾向哪种？
4. 实施节奏：审计通过后独立新会话连续执行，还是分阶段（P0-P2 一批、P3-P5 一批）？
