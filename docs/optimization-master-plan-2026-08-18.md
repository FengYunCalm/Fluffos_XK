# FluffOS_XK 深度优化大方案 v0.3（2026-08-18）

> 状态：**DRAFT v0.3**。A-S0 证据闭合和基线复验通过后，才允许进入实现阶段。
> 计划基线：本地 `main` 为 `2785c8a6165eab7d32842306468cd0b48eab17aa`；开工前必须记录实际 HEAD，基线变化时重做受影响的 hunk 对照。
> 上游输入：`/tmp/pr1247.diff` 的 SHA-256 为 `79d4648dec2b4b83173d2d2ee9336469e4d94ad5829b138b11a109ccaad2d2d9`，`git apply --numstat` 显示 47 个 `src/` 路径和 19 个 `testsuite/` 路径。A-S0 必须补齐可复现的 PR/base/head 来源，不能把临时文件路径当作长期证据。
> 证据归属：A-S0 完成前，把 #1247 的完整矩阵、命令和结论写入 `docs/upstream-sync-evidence-2026-08.md`；本文只保留执行契约和已确认的最低工作集。

---

## 0. 目标、顺序与授权边界

按依赖顺序完成三个工作流：

1. **A：上游 #1247 安全性与正确性同步**，先关闭已知内存安全风险。
2. **B：对象变量布局解耦与可回滚迁移**，在当前 recompile 事务上扩展，不另建热重载框架。
3. **C：编译期 monotonic arena**，以本地真实编译 A/B 数据决定是否保留。

| 阶段 | 内容 | 风险 | 估算 | 阶段产物 |
|---|---|---:|---:|---|
| **A-S0** | #1247 全量 hunk/test 归档和基线复验 | 中 | 1-2 天 | 可复现证据矩阵、最终任务数 |
| **A-S1** | 矩阵中全部安全/UB 项 | 高 | A-S0 后估算 | 独立安全提交与定向回归 |
| **A-S2** | 矩阵中其余正确性项 | 中 | A-S0 后估算 | 完整同步结论 |
| **B-S1** | `ObjectVariableBlock` 存储边界 | 高 | 2-3 天 | 对象变量独立 payload |
| **B-S2** | 独立布局模块、稳定描述器与结构化差异分类 | 高 | 2-3 天 | 纯 `recompile_layout`模块和迁移资格判断 |
| **B-S3** | per-kind 生命周期与变量迁移事务 | 高 | 4-6 天 | 变量增删/重排热重载 |
| **C-S1** | arena 核心、lexer、全部调用点原子迁移 | 高 | 5-7 天 | 可编译、无旧 API 的实现提交 |
| **C-S2** | 本地性能与内存验收 | 中 | 1-2 天 | before/after 原始数据和结论 |

授权约束：

- 严格执行 `A-S0 -> A-S1 -> A-S2 -> B-S1 -> B-S2 -> B-S3 -> C-S1 -> C-S2`。
- 每阶段必须独立编译、通过该阶段门禁并可独立回滚；不得用后续阶段修复当前阶段的编译或测试失败。
- A-S0 未闭合前，A-S1/A-S2 的任务数和总工期只是未知量，不得据此宣布 #1247 同步完成。
- B-S2 只产出分类结果，调用方继续拒绝所有布局差异；B-S3 接入迁移后才放行明确可迁移的差异。
- C-S1 是一个原子实现阶段，不保留不可验证的半兼容 scratch API。

---

## 1. 工作流 A：上游 #1247 安全性与正确性同步

### A.1 已确认输入

- 上游 PR 描述称包含 61 项修复；该数量在 A-S0 中只作为待核对元数据，不作为 hunk 完整性判据。
- 精确补丁包含 **47 个源码路径和 19 个测试路径**。
- 19 个测试路径由 2 个 clone fixture 和 17 个 runnable 组成：compiler 2、crasher 6、efuns 8、operators 1。
- 本地已有部分等价修复和回归测试。`已覆盖`、`等价保护`必须同时给出源码与测试证据，不能只凭补丁无法应用判定。

### A.2 A-S0：按本地文件分组的全量 hunk 矩阵

`docs/upstream-sync-evidence-2026-08.md` 中新增一个 #1247 章节，以**本地目标文件分组、每个上游 hunk 单独一行**记录。一个文件包含多个独立 hunk 时必须拆行；不得用“单文件一行”或跨模块兜底项合并无关问题。

每行字段固定为：

| 字段 | 契约 |
|---|---|
| `hunk_id` | 稳定编号；可从 upstream commit/path/hunk 序号生成 |
| 上游来源 | PR、base/head commit、上游文件和 hunk 上下文 |
| 缺陷与风险 | 触发条件、内存/UB/正确性后果、严重度 |
| 本地落点 | 本地文件、符号和适用配置 |
| 状态 | `未移植` / `已覆盖` / `等价保护` / `不适用` |
| 证据 | 本地代码行、测试、配置或不适用理由 |
| owner | 负责的本地模块，如 VM/base、net、compiler、DB |
| 阶段 | `A-S1` 或 `A-S2`；非实现项写 `-` |
| 回归测试 | 上游测试路径、本地等价测试或新增测试 |
| 目标提交 | 一个可独立回滚的提交标识；实施前允许写计划 ID |

**代码级溯源标记约定**（每个矩阵行必须对应代码中的标记，否则不闭合）：

- 每个移植点在修复代码处落 `// #1247 <hunk_id>: <缺陷>` 注释（与现有 `E3 P2`、`v0.4 §7`、`Upstream #1344` 惯例一致）。
- 每个等价保护点在已有代码处补落 `// #1247-equivalent <上游 ref>` 注释（sys.cc/comm.cc/reclaim.cc/object.cc 等已确认点必须补标）。
- A-S1/A-S2 退出门禁增加 grep 可验证的标记覆盖率检查：对照 evidence 矩阵逐行 grep `#1247 <hunk_id>`，无标记即不闭合。
- 理由：本次审计已证明关键词 grep 查覆盖不可靠（sys.cc/comm.cc 等价物误报），无标记则每月同步审计必须重做全量人工 diff 分析。

A-S0 执行顺序：

1. 固定实际本地 HEAD、PR base/head、补丁 SHA-256 和获取命令。
2. 用结构化 diff 解析列出全部源码 hunk和 19 个测试路径，禁止手工从文件列表推算修复数。
3. 逐 hunk 定位本地符号并赋予唯一状态；同一上游修复跨多个文件时用同一 issue ID 关联，但每个 hunk 仍保留独立行。
4. 对 `已覆盖`、`等价保护`运行对应回归；没有行为证据时降为 `未移植`。
5. 对 `不适用`记录具体编译配置、已删除调用链或替代实现，禁止只写“本项目不用”。
6. 按 owner 和阶段生成 A-S1/A-S2 实施队列及估算。

A-S0 退出条件：

- 47 个源码路径中的每个 hunk 都在矩阵中出现且没有 `待确认`状态。
- 19 个测试路径全部归类为移植、已有等价覆盖或有证据的不适用。
- 矩阵能由固定补丁重新生成 hunk 集合，并有检查脚本证明不存在漏行和重复认领。
- 下列已确认问题全部有独立行；A-S0 新发现的问题按相同规则追加。
- `lpc_tests 424/424`、driver GTest 和已有 sanitizer 基线重新通过。

### A.3 已确认的最低工作集

该表不是 #1247 总台账，只是 A-S0 不得遗漏的最低集合。完整状态以 evidence 矩阵为准。

| ID | 本地落点 | 当前事实 | 状态 | owner | 阶段 | 回归测试 | 目标提交 |
|---|---|---|---|---|---|---|---|
| K1 | `src/packages/contrib/contrib.cc:f_replaceable` | 空 ignore 数组时 `ignore=nullptr` 后仍写 `[0]/[1]` | 未移植 | contrib | A-S1 | `crasher/replaceable_empty.lpc` | `A-S1-contrib-replaceable` |
| K2 | `src/packages/db/db.cc:MySQL_fetch` | BINARY/BLOB 按 `field->max_length` 读取当前行，未使用实际 row length | 未移植 | DB | A-S1 | MySQL 短 BLOB 定向测试；无可用 DB fixture 时新增可单测的长度转换 helper | `A-S1-db-row-length` |
| K3 | `src/packages/async/async.cc:getdir` | 按 `sizeof(dirent *)` 扩容后复制 `sizeof(*de)` | 未移植 | async | A-S1 | ASan getdir 多条目测试 | `A-S1-async-getdir` |
| K4 | `src/net/telnet.cc` ZMP | `argc-1`数组与写入索引不一致；上游 hunk 约位于补丁 712-735 | 未移植 | net | A-S1 | ZMP 空/单/多参数测试 | `A-S1-net-zmp` |
| K5 | `src/net/telnet.cc` LINEMODE | 读取 `buf[1]`前只检查 `size==0`；上游 hunk 位于补丁 360-381 | 未移植 | net | A-S1 | LINEMODE 0/1/2 字节输入测试 | `A-S1-net-linemode` |
| K6 | `src/vm/internal/base/object.cc` | 对象/索引边界缺陷待按 hunk 固定具体符号 | 待 A-S0 定位 | VM/base | A-S1 | 上游对应 crasher | `A-S1-object-bounds` |
| K7 | `src/vm/internal/base/array.cc` | 分配失败/长度运算路径待按 hunk 拆分 | 待 A-S0 定位 | VM/base | A-S1 | `efuns/allocate.lpc` | `A-S1-array-bounds` |
| K8 | `src/packages/core/sprintf.cc` | 宽度/列处理的整数与输出边界修复 | 待 A-S0 定位 | core | A-S1 | 两个 sprintf 测试路径 | `A-S1-sprintf-bounds` |
| K9 | `src/packages/ops/ops.cc` | float-to-int UB 边界 | 待 A-S0 定位 | ops | A-S1 | 新增 NaN/Inf/极值测试 | `A-S1-ops-float` |
| K10 | `src/packages/contrib/contrib.cc:repeat_string` | 乘法溢出和错误路径 | 待 A-S0 定位 | contrib | A-S1 | 新增长度极值测试 | `A-S1-contrib-repeat` |
| K11 | `src/comm.cc` input callback | `#` apply 的 VM 栈保护已存在；sentence/carryover 释放是否等价仍需逐 hunk 证明 | 待 A-S0 定性 | comm | A-S1 | input_to 清理测试 | `A-S1-comm-input` |
| K12 | `src/packages/pcre/pcre.cc:pcre_get_replace` | 已有非重叠 segment 构建、长度上限和嵌套 capture 回归 | 等价保护 | PCRE | - | `efuns/pcre_replace.lpc` + 本地 `pcre.c` | - |
| K13 | `src/packages/core/sys.cc:sys_reload_tls` | 已覆盖 INT_MIN、负数、边界及最大值 | 已覆盖 | core | - | 本地 `sys_reload_tls.c` | - |

A-S0 必须继续覆盖 transport、stralloc、strutils、compiler、parser、compress、external、sockets、mudlib_stats、matrix、checkmemory、dwlib 等补丁路径；这些模块不能被 K1-K13 代替。

### A.4 A-S1/A-S2 实施规则

**A-S1：安全、越界、UAF、泄漏、UB。**

- A-S0 标为高/中安全风险的 hunk 全部进入 A-S1，不再使用固定“9 项”数量。
- 按 subsystem 或单一缺陷提交；跨十余模块的兜底提交不允许进入评审。
- 每个提交先落回归测试，再移植最小修复；平台/可选 package 无法在默认配置执行时，提供可单测 helper 或对应配置构建证据。
- 每个提交运行定向测试、GTest、`lpc_tests`、ASan/UBSan；A-S1 尾部统一运行 TSan。

**A-S2：其余正确性与资源清理。**

- 只接收 A-S0 明确分配的 hunk，不在阶段中临时扩大为上游全量同步。
- 行为变化必须记录兼容性；单纯类型加宽、错误路径清理也需要边界测试。
- A-S2 完成后重新生成矩阵摘要，状态只能是有证据的闭合状态。

A 工作流最终门禁：

- evidence 中源码 hunk 与测试路径集合闭合，无未知、无重复 owner、无无主提交。
- 相关上游测试或本地等价测试通过。
- `lpc_tests 424/424`，driver GTest 零失败。
- ASan、UBSan、TSan 零新增报告；基线已有报告必须单独列出，不能伪装为本阶段通过。

---

## 2. 工作流 B：对象变量布局解耦与可回滚迁移

### B.1 当前边界

- `object_t` 仍以内联尾数组 `svalue_t variables[1]`保存变量，`get_empty_object()`按变量数扩大对象 allocation。
- `dealloc_object()`和内存统计依赖 `ob->prog->num_variables_total`；program 和变量块在事务中不同步时会按错误长度释放。
- `replace_program()`会搬移 slot、调整统计并切换 program，必须与 recompile 共用变量块原语。
- 当前 `recompile_layouts_match()`在事务开始前拒绝全部布局差异。
- 当前 `RecompilePrepared`已经提供 program、generation、flags、simul dispatch 和引用的 no-fail swap/rollback；B 只扩展该事务。

### B.2 B-S1：嵌入 handle、独立 payload

`ObjectVariableBlock` handle **嵌入 `object_t`**，只有 payload 使用 `TAG_OBJ_VARS`独立分配：

```cpp
struct ObjectVariableBlock {
  svalue_t *data;       // max(count, 1) 个 slot，唯一 payload allocation
  uint32_t count;       // 释放、mark、统计的唯一长度来源
  uint64_t layout_id;   // 规范化布局摘要；生命周期边界做一致性断言
};

struct object_t {
  // ...
  ObjectVariableBlock variables;
};
```

因此每个对象固定为两次 allocation：一次 `sizeof(object_t)`，一次变量 payload。handle 不允许单独 allocation，也不允许由 program 变量数推导释放长度。

`layout_id`的唯一生产者是 `src/vm/internal/base/program.{h,cc}`中的中立纯函数：

```cpp
uint64_t program_layout_digest(const program_t *) noexcept;
```

B-S1 先把当前严格布局规则收进该函数；B-S2 在同一提交内把函数和规范化描述器一起升级，使所有生产者使用同一种算法。一个 driver process 内不得同时存在两种 digest 算法。`layout_id`只用于生命周期断言和快速排除：不相等可以证明 block/program 不一致；相等不能替代 B-S2 的完整结构比较，迁移放行不得依赖 64 位 digest 无碰撞。

base 层 API 只负责 program 布局指纹和变量存储原语，不认识 recompile 事务：

```cpp
void obj_vars_init(ObjectVariableBlock *, const program_t *);
void obj_vars_destroy(ObjectVariableBlock *) noexcept;
void obj_vars_clear(ObjectVariableBlock *) noexcept;
void obj_vars_move(ObjectVariableBlock *dst_empty, ObjectVariableBlock *src) noexcept;
void obj_vars_swap(ObjectVariableBlock *, ObjectVariableBlock *) noexcept;  // 仅 replace_program 槽位搬移用（B-S3 明确）
svalue_t *obj_vars_data(ObjectVariableBlock *) noexcept;
void obj_vars_mark(const ObjectVariableBlock *);
size_t obj_vars_accounted_bytes(const ObjectVariableBlock *) noexcept;
```

职责约束：

- `get_empty_object()`改为接收 `program_t *`，内部通过 `obj_vars_init()`取得 count 和 `program_layout_digest()`；load_object 和 clone_object 两个调用点传入实际 program。
- `dealloc_object()`只调用 `obj_vars_destroy()`，不从当前 program 推导长度。
- `replace_program()`为目标 program 初始化一个新 block，按现有 offset 规则搬值，再 swap 并销毁旧 block；不允许只改 `layout_id/count`或直接 `FREE()` payload。
- recompile prepare 通过同一个 `obj_vars_init(new_prog)`创建 staged block；attach 只移动已经带正确 `layout_id`的完整 handle。
- object 创建、replace_program 和 recompile attach 之外不得直接写 `layout_id`；算法升级必须与 B-S2 描述器变更原子落地。
- checkmemory、debugmalloc mark、`tot_alloc_object_size`和 package stats 使用 block 的 `count`。
- 所有 `ob->variables`裸指针算术迁移为 `ob->variables.data`或内联 accessor；不提供隐式指针转换掩盖遗漏调用点。

B-S1 门禁：

- 全仓不存在把 embedded handle 当裸指针使用的调用点，也不存在绕过 `program_layout_digest()`直接生成或改写 `layout_id`的生产路径。
- object 创建、replace_program 和 recompile staged block 对同一 program 产生相同 `layout_id`；digest 不同的 block 不能 attach。
- 普通对象创建/销毁、clone、destruct、replace_program、save/restore、GC/checkmemory 行为通过。
- Debug/ASan 无 orphan、double free、错误长度清理。
- 对象创建吞吐相对同工具链基线回退不超过 5%；常驻内存增量与“一份 handle + 一份 payload”模型一致。

### B.3 B-S2：独立描述器、稳定身份和结构化差异

纯布局职责放入 `src/vm/internal/recompile_layout.{h,cc}`：

- `describe_recompile_layout(program_t *)`构建规范化描述器。
- `classify_recompile_layout(old, new)`返回结构化 diff。
- `build_variable_matches(old, new)`构建迁移表。
- 该模块只读 `program_t`，不读写 live `object_t`、VM context、simul 表或 transaction state，能够脱离 driver 生命周期做单元测试。

`src/vm/internal/recompile.{h,cc}`只保留 staging、target snapshot、`RecompilePrepared`、per-kind policy、迁移执行和 commit/rollback。B-S2 开始时先机械地把当前 descriptor/comparator 搬入 `recompile_layout`并锁定等价测试；此后 class schema、diff 和 match 修改只发生在纯布局模块，事务文件只更新调用接口。`base/object.*`不新增“按 inherit 路径查变量”的 recompile 专用 resolver。

描述器要求：

```text
RecompileLayout
  variables[] = {
    slot,
    inherit_path,
    name_text,
    effective_decl_type,
    class_schema_digest
  }
  inherits[] = {
    slot,
    inherit_path,
    filename_text,
    type_mod,
    nested_layout_digest
  }
  classes[] = {
    stable_id = {defining_inherit_path, class_name_text},
    members[],
    schema_digest
  }
```

实现规则：

- `walk_layout()`沿当前 DFS/slot 顺序维护 `inherit_path`，直接把定义者路径写入变量描述；不得回头调用 `find_global_variable()`按名字首命中。
- `RecompileLayoutInherit::type_mod`必须从 `inherit_t::type_mod`填充、逐项比较，并纳入包含该 inherit 边的 digest。
- inherited 变量的 `effective_decl_type`必须包含沿路径应用的 `DECL_MODIFY(type_mod, type)`结果。
- program-local class index 只用于定位 schema；跨 program 比较使用稳定 class ID 和递归 schema digest。
- 为覆盖 `mixed`中保留的 class 值，保守比较 old/new program 及 inherit graph 的完整 class 定义集合，而不只比较具名 class 变量。
- 变量稳定身份是 `{inherit_path, name_text}`。身份重复、路径无法规范化或 schema 无法解析时 fail-closed。

差异结果使用结构体或 bitmask，不使用只能表示一种变化的 enum：

```cpp
struct RecompileLayoutDiff {
  std::vector<VariableMatch> matches;
  std::vector<VariableIdentity> added;
  std::vector<VariableIdentity> removed;
  RecompileDiffFlags flags;       // 可同时包含多种变化
  std::vector<std::string> reject_reasons;
  bool migratable() const noexcept;
};
```

放行规则：

- 可迁移：变量新增、删除、重排；变量改名按“旧变量删除 + 新变量新增”处理，不保留旧值。
- 必须拒绝：matched 变量有效类型变化、inherit graph/edge `type_mod`变化、class schema 变化、重复稳定身份、无法证明兼容的布局变化。
- `recompile_layouts_match()`保持纯比较/分类，不发 warning、不决定用户可见策略。
- B-S2 期间 `efuns_main.cc`仍拒绝所有非 exact match；B-S3 接入事务后才按 `diff.migratable()`放行。

B-S2 门禁至少覆盖：

- 同名 private 变量位于不同 inherit 路径时能正确区分。
- 仅父 inherit 边 `type_mod`变化时必须判不兼容，且 nested digest 改变。
- class index 数值相同但成员 schema 不同必须拒绝。
- 同时发生新增、删除和类型变化时，结果保留全部 flags，任一拒绝原因都能阻止放行。
- exact match 与当前严格比较结果一致；fuzz descriptor 输入不能越界或产生不稳定 digest。
- 对 testsuite 编译得到的全部 program 记录 `(program_layout_digest, canonical exact-layout serialization)`：同一 serialization 必须只有一个 digest，同一 digest 必须只有一个 serialization；任何漂移或碰撞都使门禁失败，不设静默白名单。属性测试同时断言 `digest(a) == digest(b)`与 descriptor exact-match 等价。
- `recompile_layout`单元测试不启动 owner thread、不构造 live object；纯分类测试失败不需要经过 recompile transaction。

### B.4 B-S3：per-kind policy 与迁移事务

生命周期只在 `recompile.cc`的单一入口执行。`efuns_main.cc`保持薄壳：编译 staging program、取得结构化 diff、调用 recompile policy；不得复制 target-kind 条件链。

```cpp
enum class RecompileInitPolicy {
  Never,
  OnMigratableLayoutChange,
  Always,
};

enum class RecompileMigrationPolicy {
  None,
  OnMigratableLayoutChange,
  Always,
};

enum class RecompileStateOrder {
  InitThenMigrate,
  MigrateThenInit,
};

enum class RecompileCreatePolicy {
  Never,
  AfterStateReady,
};

struct RecompileLifecycle {
  RecompileInitPolicy init;
  RecompileMigrationPolicy migrate;
  RecompileStateOrder state_order;
  RecompileCreatePolicy create;
};
```

固定 policy：

| Target kind | `__INIT` | 变量迁移 | 状态顺序 | `create()` | 兼容性契约 |
|---|---|---|---|---|---|
| `BlueprintFamily` | 仅可迁移布局变化时 | 仅可迁移布局变化时 | `InitThenMigrate` | 从不 | exact layout 保持本地 v1 的 no-init/no-create；布局变化时 initializer 只保留新增变量，matched 变量恢复旧值 |
| `Master` | 总是 | 总是 | `MigrateThenInit` | state ready 后 | `__INIT`读取已恢复的旧状态，其写入保留并传给 create |
| `SimulEfun` | 总是 | 总是 | `MigrateThenInit` | state ready 后 | simul staging 完成后恢复旧状态，再运行 `__INIT/create` |

该 policy 显式决定 exact layout 是否运行 `__INIT`以及 init/migrate 的相对顺序，不能由“变量数量是否变化”或散落分支隐式决定。BlueprintFamily 的新 block 先运行 initializer，再由旧值覆盖 matched 槽，只让新增变量保留 initializer；Master/SimulEfun 先把旧值复制到独立新 block，再运行 `__INIT`，因此 `__INIT`看到旧状态且写入不会被迁移覆盖，保持当前特殊对象 reload 的可见语义。两种顺序都不修改旧 block，失败时可以完整回滚。若要采用上游对普通 blueprint 每次运行 `__INIT`的行为，必须作为单独兼容性决策修改表格和测试，不得混入实现细节。

每个 target 的 migration 作为 `RecompilePrepared`成员持有：

```text
PreparedVariableMigration
  old_block       // 从 object 临时 detach，完整且从不逐槽修改
  new_block       // 按 policy 在其上执行 init/migrate
  matches[]       // 由 old/new RecompileLayout 构建
  diff
```

所有权状态只有三种：

```text
准备前/完成后：Object owns attached payload
临时发布期间：Object owns new payload; RecompilePrepared owns old payload
回滚后：      Object owns old payload; RecompilePrepared owns/discards new payload
```

`RecompilePrepared`的析构、`commit_finish()`和 `rollback()`是 detached payload 的唯一释放者。任何路径都不得同时让 object 和 prepared 认为自己拥有同一 payload。

事务顺序：

1. admission 关闭并完成 quiescence；固定 target snapshot、program refs、generation、old/new derived flags 和旧变量 block。
2. 在 fallible prepare 段构建 layout diff、migration matches、新变量 block、apply cache 和 simul staging；不修改 live object。BlueprintFamily exact layout 不创建 migration；Master/SimulEfun 按 `Always`创建。
3. `commit_swap() noexcept`通过 `obj_vars_move()`临时发布新 program 和新 block，并把旧 block 的 payload 所有权移入 `PreparedVariableMigration`；两个 move 之间不开放 admission，也不调用任何可失败代码。
4. `copy_matches()`对每个 match 执行 `assign_svalue(&new[dst], &old[src])`，增加旧值引用并保持旧槽不变；该 helper 不得执行 mudlib callback，也不得移动或清空旧槽。
5. 单一 `prepare_target_state()`按 `state_order`执行：BlueprintFamily 为 `call___INIT()`后 `copy_matches()`，此时 copy 会释放 matched 槽的 initializer/`__INIT`结果；Master/SimulEfun 为 `copy_matches()`后 `call___INIT()`，使 init 读取旧状态并保留写入。任一 error 或 target self-destruct 进入统一失败路径。
6. `Master`/`SimulEfun`通过 `base/object.{h,cc}`中与现有 `call_create()`相邻的新原语 `call_create_only()`运行 `APPLY_CREATE`。现有 `call_create()`改为组合 `call___INIT()`和 `call_create_only()`；recompile 不自行实现 apply 入口变体，也不能调用会再次执行 `__INIT`的组合入口。
7. 成功时 `commit_finish() noexcept`释放旧 block/program 和旧 simul 表；失败时 `rollback() noexcept`把旧 program、generation、old derived flags、simul 表和旧 block 原样换回，再销毁新 block。

失败与副作用契约：

- 回滚恢复 driver 持有的 program、变量值、generation、flags 和 dispatch 状态。
- `__INIT`、`create()`对其他对象、call_out、文件、网络或全局 daemon 产生的外部副作用不可回滚；命令失败信息必须明确这一边界。
- target 在 `__INIT/create`中 destruct 时，snapshot ref 保持 object 内存和两个 block 可清理；事务返回失败，不得重新开放一个半提交对象。
- migration 的引用复制如果违反 noexcept 前提，必须在 prepare/fallible guard 内完成；no-fail 段只允许指针、计数和已预留引用的交换。

B-S3 门禁：

- BlueprintFamily 布局变化时，新增变量获得新 program 的 initializer 值，matched 变量恢复旧值；删除变量在成功后释放，重排按稳定身份保值，改名不保值。
- Master/SimulEfun 的 exact 和布局变化路径都验证：`__INIT`能读取迁移后的旧状态，`__INIT`对 matched 变量的写入在 create 中可见且成功后保留。
- 同名不同 inherit 路径不串值；class schema、`type_mod`和类型变化全部拒绝。
- exact layout 按 policy 表执行，BlueprintFamily 不新增 `__INIT/create`副作用。
- `__INIT`失败、create 失败、self-destruct、第二个 target 失败、simul staging 失败均验证 object/program/block/refcount 回滚。
- `replace_program()`、save/restore、clone/destruct、master/simul reload 回归通过。
- ASan/UBSan/TSan、debugmalloc/checkmemory 零新增报告。
- 同规模 exact-layout recompile 相对 B-S1 基线回退不超过 5%；布局迁移峰值 RSS 与“每 target 同时持有 old+new payload”模型一致，完成后回落。

---

## 3. 工作流 C：编译期 monotonic arena

### C.1 当前边界和收益口径

- 当前 scratchpad 使用 4KB 静态块，小 allocation bump，大 allocation 或溢出 allocation 单独链接并在 `scratch_destroy()`释放。
- `scratchpad.h`导出 `scr_last`、`scr_tail`、`scratch_end`，lexer 直接读写游标；只替换函数签名不能封闭 arena 边界。
- `scratch_free()`有尾 allocation 回退、大 allocation 立即释放、内部非尾 allocation 标记三种行为；改成 no-op 会改变峰值内存，必须通过原子调用点迁移和 RSS 门禁承担该变化。
- 性能承诺限定为：**scratch arena warmup 后零新增 chunk malloc**。program、mem_block、诊断和最终 bytecode 等持久 allocation 不在“零分配”承诺内。

### C.2 C-S1：核心和全部调用点原子迁移

arena 核心使用独立 `src/compiler/internal/compile_arena.{h,cc}`作为 chunk pool 生命周期的唯一 owner：

- 进程级 pool：1MB 静态 base chunk，最多保留 8 个 1MB standard chunk；超过保留上限的 standard chunk和所有 oversize exact-fit chunk在 compile scope 结束时释放。
- compile 级 scope：**不用 RAII 作用域析构语义**——本仓库 error() 是 longjmp（machine.h:38 `[[noreturn]]`；interpret.cc:4339 注释确认），跨过 compile_file 栈帧时 C++ 析构不运行。改为**显式 begin/end**：`compile_arena_begin()` 在 compile_file() 入口调用，`compile_arena_end()` 从成功路径（compiler.cc:2503 现有 scratch_destroy 处）与错误清理路径（compiler.cc:2612 现有 scratch_destroy 处）**两处显式调用**，保留现有双清理点结构；普通 parse error 走 clean_parser() 返回；不引入只拥有 arena、却无法代表编译器全局状态的半套 `CompileSession`。
- allocation：按 `max_align_t`对齐的 monotonic bump；allocation 不跨 chunk。
- deallocation：arena allocator 的 individual deallocate 明确为 no-op。旧 `scratch_free()`三分语义不保留；所有依赖 tail rewind 或立即 free 的调用点必须在同一阶段改写，峰值影响由 C-S2 验收。
- 容器：提供 `ArenaString`、`ArenaVector<T>`和 token materialization API。任何跨 compile 存活的数据必须在边界复制到自有 storage。
- lexer：用 string builder API 替换直接游标操作；同一提交删除 `scr_last`、`scr_tail`、`scratch_end`导出。
- parser/compiler：迁移 grammar source、generated parser、trees、宏参数、类型名和其他全部 scratch 调用点；生成文件必须由对应源重新生成并通过一致性检查。
- observability：记录 cycle bytes、peak cycle bytes、chunk mallocs、reset count、retained chunks、retained heap bytes，并接入 `mud_status()`。

C-S1 是一个实现提交序列中的原子合入单元：内部可拆小提交开发，但授权分支上只有“旧 scratchpad 完整可用”或“新 arena 全部调用点完成”两个可编译状态，不接受删除 API 后等待 C-S2 修调用点。

C-S1 门禁：

- `src/compiler/`中 `scr_last|scr_tail|scratch_end|scratch_alloc|scratch_realloc|scratch_free`零生产调用；测试工具中的故障注入接口使用新命名。
- GTest 覆盖 alignment、exact fit、spill、oversize、retained ceiling、bulk reset、错误 unwind 和统计。**错误 unwind 测试必须验证：模拟编译错误（error() longjmp 路径，经错误清理路径显式调用 end）后 arena cycle bytes 归零**、下一次 compile 可正常复用 retained chunks；普通 parse error（clean_parser() 路径）同样经显式 end 归零。
- lexer/parser randomized `lpc_tests`至少连续 3 轮通过。
- Debug ASan/UBSan 构建无 UAF、double free、orphan chunk；生成 parser 与 grammar source 一致。

### C.3 C-S2：本地 A/B 与内存验收

基线和候选必须使用相同 compiler、CMake options、build type、CPU affinity、输入 corpus、预热轮次和测量轮次。WSL2 构建前执行 `df -h /`，同一时间只保留一个活动构建，固定 `cmake --build ... -j4`或 `-j8`，不得全并行。

基准分两层：

1. `bench_scratchpad`：tokens、string accumulation、macro arguments、compile mix；用于解释 allocation 热点，不单独决定上线。
2. `bench_compile`：通过真实 `compile_file()`反复编译固定代表性 LPC corpus，报告 throughput、median、p95、p99、chunk mallocs、retained bytes 和 peak RSS。

每组至少 5 次独立进程，保留原始 CSV/JSON、commit、工具链、机器负载和汇总脚本。before 数据记录后可删除旧 build 目录，再构建候选，避免 WSL2 磁盘占用叠加。

通过条件：

- warmup 后 `chunk_mallocs`增量为 0；forced-small-chunk 模式允许 overflow，但每次 reset 后无残留增长。
- 真实 compile throughput 相对基线提升至少 10%。
- median、p95、p99 任一不得回退超过 5%。
- scratch 路径 malloc 次数下降至少 50%；不把 compiler 其他 allocation 计入该分母。
- steady-state retained heap 不超过 8 个 standard chunk预算；peak RSS 不超过基线 110%。
- last-10% / first-10% 不超过 1.10，只作为生命周期退化门禁，不作为优化收益证明。

任一硬门禁失败时回滚 C-S1，保留 benchmark 和失败原因；不得只调低阈值宣布成功。

---

## 4. 统一门禁、提交和回滚

| 阶段 | 必须通过的证据 |
|---|---|
| A-S0 | 47 个源码路径的全量 hunk 集合闭合；19 个测试路径闭合；基线 green；evidence 落库 |
| A-S1 | 每提交定向测试 + GTest + 424/424 + ASan/UBSan；阶段末 TSan |
| A-S2 | 全矩阵状态闭合 + GTest + 424/424 + ASan/UBSan/TSan |
| B-S1 | 变量块生命周期/统计/replace_program 测试 + 性能/RSS 基线 |
| B-S2 | identity/type_mod/class schema/diff bitmask + digest/descriptor 等价性；调用方仍拒绝布局差异 |
| B-S3 | per-kind init/migrate 顺序、迁移、失败回滚、master/simul、ASan/UBSan/TSan |
| C-S1 | RAII 覆盖 parse error/C++异常 + arena GTest + 3 轮 randomized 424/424 + ASan/UBSan + 全旧符号 grep 零命中 |
| C-S2 | 同工具链本地 A/B 全部硬门禁通过，原始数据写入 evidence |

提交原则：

- A：按 evidence 行或同一 subsystem 的单一缺陷提交，测试与修复同提交。
- B：`object vars storage`、`recompile_layout descriptor/diff`、`migration lifecycle`三个可回滚边界；B-S2 的机械抽取先锁定等价行为，且不提前放行。
- C：开发提交可细分，最终合入必须保持原子可编译边界；benchmark 工具与生产 arena 分提交便于复核。
- 不使用 `git reset --hard`或覆盖工作区并行修改；每次回滚只反转本阶段拥有的文件和提交。

停止条件：

- A-S0 无法固定上游 provenance、存在无法归属 hunk 或基线不绿：停止 A 实施。
- B 的稳定身份、class schema、`type_mod`、所有权状态或 no-fail rollback 任一无法证明：保持严格 layout mismatch，停止 B-S3。
- C 无法原子迁移全部旧调用点、warmup 后仍持续 chunk malloc、真实 throughput 未达标或 peak RSS 超限：回滚 C-S1。

---

## 5. 完成定义

只有以下条件同时成立，才能宣布整项优化完成：

- #1247 的固定补丁、源码 hunk 和测试路径有可复现的闭合矩阵，所有实现行都有 owner、测试和提交。
- 对象变量 storage 的长度、布局、统计和释放不再依赖可能已切换的 `ob->prog`；`program_layout_digest()`是 `layout_id`唯一生产者，布局迁移按稳定身份复制并可恢复整个旧 block。
- 纯 `recompile_layout`模块独立完成 descriptor、class schema、diff 和 matches；事务模块只消费结果。
- per-kind lifecycle policy 是唯一行为入口，普通 blueprint、Master、SimulEfun 的 init/migrate 顺序和 `create`语义均有回归测试，纯 create apply 由 base/object 的 `call_create_only()`提供。
- compiler arena 不导出内部游标，旧 scratch API 无生产调用；`CompileArenaScope`在 parse error、`error()`的 C++异常和正常返回路径都恰好执行一次 bulk reset。
- GTest、`lpc_tests 424/424`和对应 sanitizer 门禁通过；性能结论来自同工具链、本地 before/after 原始数据。
