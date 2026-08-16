# recompile_object()（E3 v1）

## 概要

```c
int recompile_object(object blueprint);
```

在**不 destruct 对象**的前提下，把 blueprint 及其全部现存 clone 的程序原子切换到
新编译的同布局实现。对象身份、变量值、交互状态、heart beat/call_out 等对象级
注册全部保留。默认**关闭**（`enable recompile object : 0`）。

## 前置

- 配置文件：`enable recompile object : 1`
- master 授权：实现 `int valid_recompile_object(object caller, object target);`
  （缺失/返回 0/抛错均 fail-closed）
- 读取权限：与普通加载一致（`check_valid_path` 路径链）

## v1 支持

- 同一 blueprint program 的函数实现热更新（增删改函数、改实现）
- 变量/inherit **布局完全一致**时的原子家族切换（blueprint + 全部现存 clones）
- 返回被切换对象数（≥1）

## v1 明确不支持

- 变量增删/重排/改类型、class 成员 schema 变化、inherit 布局变化（稳定报
  `layout mismatch`）
- 运行 `create()`/`__INIT`/initializer（现存变量原样保留）
- master/simul_efun/virtual object/shadow 链/pending `replace_program()`
  （稳定报 `target is unsupported`）
- 目标 program 正在执行（稳定报 `target program is executing`）
- 旧函数指针（FP_LOCAL/FP_FUNCTIONAL）自动重绑——调用报稳定
  `stale function pointer`，需重新创建
- 跨进程/多 program 事务原子性——多文件依赖按 parent-first 独立批次重编译

## 错误类别（稳定前缀）

| 前缀 | 场景 |
|---|---|
| `recompile_object requires the main thread` | owner worker 调用 |
| `recompile_object is disabled` | 默认关闭 |
| `recompile_object requires master authorization` | master 拒绝 |
| `recompile_object requires a blueprint` | clone/destructed/非法参数 |
| `recompile_object target is unsupported: <reason>` | master/simul/virtual/shadow/replace |
| `recompile_object target program is executing` | 活动帧 |
| `recompile_object owner quiescence timed out` | owner 活跃工作未归零 |
| `recompile_object compile failed` | 源码读取/编译失败 |
| `recompile_object layout mismatch: <field>` | 布局不一致 |
| `recompile_object transaction already active` | 嵌套调用（含 master hook 内） |

## 运维

- 无自动回滚：一次成功热重载后，业务错误需从已知良好源码再次同布局重编译
  或按常规流程重启
- 建议先编译验证再上线（`lpcc --batch` 可批量预检）；热重载前确认无
  活跃长任务（等待或超时后原子失败）
- 冻结期间新 owner 提交被稳定拒绝（admission_rejected 计数可观测）；
  排队任务在 reopen 后按原 FIFO 继续

## 实现要点（v0.4）

- owner 全局静默：OPEN → CLOSING（拒绝新提交）→ FROZEN（活跃 owner 工作归零）
  → 交换 → OPEN；全部在现有 runtime mutex 下，无第二把锁
- commit 段无分配、无 LPC、无 error：所有可失败工作（编译/布局/apply 表
  预热/快照）在交换前完成
- `prog_generation` 代际：旧 funptr 快照创建时代际，交换后稳定报 stale；
  旧 program 由 ref/func_ref 自然收敛释放
- apply lookup table 在冻结期显式构建，reopen 后无懒构建竞态
