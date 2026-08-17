# `recompile_object()` v2 设计（L8，文档产出）

> 状态：**DRAFT v0.2** —— 设计文档，实施不并入本批（走单项授权）
> 前置：E3 v1 已落地（`docs/recompile-object-special-design-2026-08.md`）；
> L1-L7 验证矩阵全绿（见 `docs/recompile-followup-plan-2026-08.md` §5）

## 0. 结论与执行决策

- v2 能力：**master / simul_efun 热重载**、**`__INIT`/`create()` 执行**、
  **失败回滚**（回滚到旧 program）。
- **拆两期实施**（风险表既定备选，P6 定案）：
  - **Phase 1**：master/simul_efun 重载（无 `__INIT`/`create` 执行）——
    扩展点最小，复用 v1 事务管线；master 缓存态失效是本期核心。
  - **Phase 2**：`__INIT`/`create()` 执行 + 失败回滚——commit 段拆分
    （create 不能在 no-fail 段内执行）是本期核心。
- 两期独立授权、独立提交；Phase 1 不依赖 Phase 2 的任何机制。

## 1. 审计：v1 现状与扩展点确认

### 1.1 v1 已实现的能力边界（磁盘实证）

- 事务管线：`src/vm/internal/recompile.{h,cc}` —— prepare（快照 +
  staging）→ quiesce（`vm_owner_recompile_quiesce_begin`，admission
  关闭 + owner 工作排空）→ commit（no-fail 段，swap + pin 释放 +
  free_object）。快照走 `obj_list` 遍历（recompile.cc:196），按
  blueprint 族匹配。
- 拒绝点：`efuns_main.cc:3405-3411` —— `ob == master_ob` /
  `ob == simul_efun_ob` 特判 error（"target is unsupported"）。
- 授权：`APPLY_VALID_RECOMPILE_OBJECT`（master apply，fail-closed）。
- 周期：`CONFIG_INT(__RECOMPILE_OBJECT_QUIESCE_TIMEOUT_MS__)`（CFG_INT 71）。

### 1.2 扩展点逐项确认

| 扩展点 | v1 现状 | v2 动作 |
|---|---|---|
| 快照覆盖 master/simul_efun | master/simul_efun 是普通 object，在 obj_list 中；v1 快照按 blueprint 族匹配，目标传入即覆盖（recompile.cc:175-208，无 member 校验概念） | **无需新遍历、无新校验**（方案已确认）；拒绝机制即 efuns_main.cc:3405-3411 特判，移除即放行 |
| v1 拒绝特判 | efuns_main.cc:3405-3411 | Phase 1 移除 master 特判；simul_efun 特判保留到 Phase 1 内同步处理（同机制，无额外依赖） |
| apply_cache 失效 | `apply_cache_invalidate_program(prog)` 已存在（apply_cache.cc:255）：epoch bump + shared 单条目清空；**v1 commit 从不显式调用**（唯一调用点在 `deallocate_program`——旧 prog refcount 归零时间接触发） | **v2 swap/回滚段显式调用**（noexcept、纯 epoch bump + 指针清空，无分配，no-fail 安全）——显式失效使 §2.3 回滚代价"新旧两次 epoch bump"成立 |
| master applies 表 | apply_lookup_table 是 **per-program** 构建（apply_cache.cc:250 附近，profile 计数为证）——新 program 自带新表 | **无需全局表重建**；旧 program 的表随旧 prog 释放。需验证点：`APPLY_*` 枚举解析（`find_apply` 类路径）对 master 重载后的对象仍按新 prog 表解析 |
| simul_efun dispatch table | `simul_names`（simul_entry[]）+ `simuls`（function_lookup_info_t[]），simul_efun.cc:36 附近为 `num_simul_efun` 计数；`get_simul_efuns`（:101-139）RESIZE/DCALLOC 建表 | **需重建，且必须两段化**：现有 `get_simul_efuns`/`init_simul_efun` 都不可复用（static、就地改活表、load_object）——Phase 1 显式交付物：simul_efun.cc 新导出 API `build_simul_efuns(program_t*)`（可失败上下文构建新数组）。**冻结/prepare 段（可失败）**：构建新数组；**no-fail swap 段**：仅指针换入 + ident 字段写（`ihe->dn.simul_num`/`IHE_SIMUL`/`sem_value` 纯字段写，无分配）——no-fail 安全成立（先例：`prepare_apply_lookup_table` 同样在冻结期建表，efuns_main.cc:3443） |

### 1.3 新发现的交互面（v2 设计必须处理）

1. **destruct 替换路径（既有非事务性重载）**：simulate.cc:1258 不是
   valid_destruct 拒绝——destruct master/simul_efun 时**重新 load_object
   新副本并 set_master/set_simul_efun**（:1263-1283，含 error handler 与
   名字保存），即一条**已存在的非事务性 master/simul_efun 重载路径**
   （经 set_simul_efun → get_simul_efuns 在普通可失败上下文重建 dispatch
   表——佐证发现一的两段化放置）。**与 v2 对照**：destruct 路径 = 全量
   重载 + create 生效、破坏性无回滚；v2 = swap-only 事务 + 失败回滚。
   destruct 与事务同在主线程串行（quiesce 关闭 admission）——**无新
   竞争面**（记录为验证点而非机制改动）。
2. **事务内 master apply**：授权步 `safe_apply_master_ob(APPLY_VALID_RECOMPILE_OBJECT)`
   在 swap 前执行（旧 program）——swap 后事务不再依赖 master 状态
   （commit 是纯内存操作）——**swap 点之后到事务结束之间无 master apply**
   ——需在 Phase 1 测试中显式验证（"重载后立刻 recompile_object 同一
   master"：第二次事务的授权 apply 必须命中新 program）。
3. **master 重载的 self-reload 语义**：v1 的 executing guard（目标 program
   正在执行的帧拒绝）——master 重载自己时，事务自身帧就在 master
   program 上——**v1 guard 会拒绝**（与 blueprint 族 self-reload 同理，
   recompile_object.c self_reload 已测该语义）——**v2 保持拒绝**：master
   必须由第三方对象重载（如 admin 对象），与 v1 蓝图的 family-member
   限制一致。
4. **simul_efun 重载的 executing guard**：simul_efun 函数执行中（调用栈
   含 simul_efun 帧）重载自身——v1 guard 检查目标 program 帧——simul_efun
   帧在 interpret 栈上——**guard 复用**（与 blueprint 一致）。记录为
   Phase 1 测试项。

## 2. v2 合同

### 2.1 master / simul_efun 热重载（Phase 1）

- `recompile_object(master_ob)` / `recompile_object(simul_efun_ob)` 合法；
  返回快照族计数（master 自身 + 无克隆 → 1；simul_efun 同理）。
- swap 后：master applies 走新 program 的 apply_lookup_table；
  simul_efun dispatch 表已重建（名称 → 新 function_t）。
- 失败语义与 v1 一致：编译失败 / 授权失败 / quiesce 超时 → 事务中止，
  旧 program 保持。
- **限制**：`__INIT`/`create()` 不执行（与 v1 蓝图一致——Phase 2 扩展）；
  调用方须是第三方对象（self-reload 被 executing guard 拒绝）。
- **缓存一致性保证**：swap 后到事务结束前，主线程无任何 master apply /
  simul_efun 调用（事务代码路径保证，见 §1.3.2）。

### 2.2 `__INIT` / `create()` 执行（Phase 2）

- swap 后、pin 释放前，对新 program 依次执行 `__INIT`（编译期初始化
  段）与 `create()`（无参调用，与 v1 蓝图成员 create 语义一致——v1
  蓝图测试已覆盖成员 create 不执行，v2 是对 master/simul_efun 执行）。
- **顺序**：`__INIT` 先于 `create()`；两者都在新 program 生效后执行。
- **执行上下文**：主线程、事务事务内（admission 仍关闭——quiesce 状态
  保持到 create 完成）。
- **禁止**：create 内不能调用 `recompile_object`（嵌套事务——guard
  `g_recompile_transaction_active` 已存在，efuns_main.cc:3363）。

### 2.3 失败回滚（Phase 2）

- create 抛错（或 `__INIT` 失败）→ **回滚到旧 program**：旧 prog 重新
  swap 回目标对象；新 prog 释放；master applies / simul_efun dispatch
  表恢复到旧 program 状态。
- **回滚代价**：apply_cache epoch 再 bump 一次（新旧两次失效）；
  快照族对象变量保持（swap 不丢变量——v1 语义）。
- **create 部分副作用**：create 内已产生的非对象副作用（全局变量、
  call_out、文件写）**不回滚**——文档化限制（与 LPC 无事务语义一致）。
- **执行 guard 与回滚交互**：create 抛错时若栈上有旧 program 帧
  （recompile 调用方的帧在旧 master 上？——master 由第三方重载，调用方
  帧在第三方 program 上——**旧 master 帧不存在**——simul_efun 重载时
  调用方帧若在 simul_efun 上则 executing guard 已拒绝——**回滚路径无
  旧帧存活**——记录为验证点）。

### 2.4 commit 段拆分（Phase 2 核心机制）

v1 commit 是单一 no-fail 段（recompile.cc:213 起，swap + pin + free）。
v2 拆为：

1. **swap 段（no-fail）**：新 prog 换入所有目标 + simul_efun dispatch
   指针换入（数组已在冻结段构建）+ apply_cache 显式失效 bump（均无
   分配、无 LPC 执行——no-fail 安全）。
2. **create 段（可失败）**：`__INIT` + `create()` 执行。失败 → 回滚
   （反向 swap）。
3. **收尾段（no-fail）**：pin 释放 + 快照 ref 释放 + 统计。

create 段与收尾段之间的状态：目标对象持新 prog（若 create 失败则已
回滚）；quiesce 状态保持到收尾段结束。

## 3. 阶段拆分

### Phase 1（master/simul_efun 重载，无 create）

- 改动面：efuns_main.cc 特判移除（2 行）+ simul_efun.cc 新导出 API
  `build_simul_efuns(program_t*)`（冻结段构建）
  + swap 段指针换入 + apply_cache 显式失效 + 测试。
- 风险：最小——复用 v1 事务管线全部机制；缓存失效是唯一新机制（且
  apply_cache_invalidate_program 已存在）。

### Phase 2（`__INIT`/create + 回滚）

- 改动面：commit 段拆分（recompile.cc 重构）+ create 执行 + 回滚路径
  + 测试。
- 风险：create 执行期对象状态（变量/引用）与 v1 的 swap-only 语义
  差异；回滚路径的 pin/ref 账目。

## 4. 门禁

| 阶段 | 门禁 |
|---|---|
| Phase 1 | lpc_tests 424/424（build-sync + ASan）；ftest 全量；recompile 合同扩展（master/simul_efun 重载 + 缓存一致性 + 二次重载新 program 生效）；TSan 全量 424/424 零警告 |
| Phase 2 | Phase 1 全部门禁 + create 成功路径（`__INIT`/create 执行序断言）+ 失败回滚路径（create 抛错 → 旧 program 保持 + 变量不丢）+ ASan 零报错 |

## 5. 测试矩阵（规划）

| 用例 | 阶段 | 断言 |
|---|---|---|
| master 重载成功 | P1 | 返回 1；master applies 走新 program（新函数可调） |
| simul_efun 重载成功 | P1 | dispatch 表重建；新旧函数名解析 |
| master 重载后立即二次重载 | P1 | 授权 apply 命中新 program（§1.3.2 验证点） |
| master/simul_efun self-reload | P1 | executing guard 拒绝（与 v1 family self-reload 一致） |
| destruct master/simul_efun 触发替换路径（既有行为不变） | P1 | 替换路径语义保持（simulate.cc:1258 起） |
| 编译失败 → 旧 program 保持 | P1 | v1 语义回归 |
| create 执行序（__INIT → create） | P2 | 执行序断言（探针计数） |
| create 抛错 → 回滚 | P2 | 旧 program 生效、变量保持、epoch 双 bump 可观测 |
| create 内 recompile_object | P2 | 嵌套事务拒绝（g_recompile_transaction_active） |
| 热重载压测扩展（master 为目标） | P2 | 压测契约 recompile_stress 扩展 master 轮次 |

## 6. 风险与备选

| 风险 | 影响 | 备选 |
|---|---|---|
| simul_efun dispatch 重建遗漏名称绑定 | P1 失败 | 重建后全函数遍历断言（num_simul_efun 计数不变） |
| create 执行期全局态副作用 | P2 语义争议 | 文档化限制（§2.3）；回滚仅对象级 |
| create 期间 call_out/心跳交互 | P2 时序 | create 在 quiesce 保持期执行（admission 关闭），无新并发 |
| 回滚 pin/ref 账目错误 | P2 泄漏 | ASan 定向 + 泄漏复现对比（L1 既定流程） |
