# FluffOS_XK 上游同步与优化执行方案（2026-08，修订版）

> 状态：**DRAFT v2.4 - 仅供审计；用户批准本版后，仍需按门禁逐阶段授权**
> 修订日期：2026-08-15（v2.4 四审修订同日）
> 本地核验基线：`FluffOS_XK` `80b0f329`（`main`，领先 `origin/main` 1 个提交）
> 上游离线参考：`/tmp/fluffos-upstream` `6cf257c`（2026-08-12，单提交 shallow clone）
> 证据边界：本版未联网刷新上游；离线浅克隆只能用于当前树结构核对，不能证明历史提交内容。
> 授权边界：批准本方案不等于授权联网、修改代码、提交、推送、发布或部署；这些动作分别按阶段确认。

---

## 0.0 v2.2 修订说明（二次审计修订，2026-08-15）

本版在 v2.1 基础上修正性能证据链和上游对象完整性：

1. **逐项性能归因**：不再用阶段 0 的原始 `SYNC_BASE_SHA` 对比包含多个阶段改动的 after。#1342、#1344、#1343 分别建立紧邻的 before/after commit 对。
2. **benchmark harness 前置**：目标微基准脚本、目标和分析器必须先形成纯测试 harness commit，并在对应 before/after 中保持字节一致；不能随实现 commit 才首次出现。
3. **owner 命令修正**：当前 `owner-scheduler-capacity.sh` 实际读取 `BUILD_DIR`、`REPORT_DIR` 环境变量，不使用尚未实现的 `--build-dir/--report-dir` 参数。
4. **依赖判定修正**：提交祖先关系只证明时间线，不证明移植依赖。G1 必须结合精确 patch、重叠 hunk、结构前置条件和本地试验决定 DAG。
5. **partial clone 收口**：G0 必须验证 promisor/filter 配置，水合所有目标 patch、上游测试和必要依赖 blob，并在禁止 lazy fetch 时复现关键命令；G0 后不把持续联网作为隐含前提。
6. **S16 证据降级**：当前只确认本地 4.2.1 和离线上游快照 4.5.8；#1260 与 CVE-2025-1866 的精确修复映射仍待 G0/G1 和官方 advisory 核对。

---

## 0.1 v2.3 修订说明（本地三审优化，2026-08-15）

本版基于对 v2.2 的复核，修正与补充如下：

1. **manifest 边界澄清**：§5.5B 的“目标源码”明确为 benchmark target 的私有源文件，**不含被优化的生产文件**；生产文件由 I 范围单独核验，避免与 §5.5D 的 `diff --exit-code` harness 两侧一致合同冲突。
2. **I 范围核验**：§5.5D 新增实现范围检查——`git diff H..I --name-only` 只应包含该候选预声明的生产文件清单；清单外文件出现即停止归因。
3. **水合清单模板**：§2.2 新增水合记录格式（候选、patch blob SHA、上游测试、头文件、文档路径、验证命令），G0 证据文档按模板填写，减少人工判断漂移。
4. **回滚流程**：§1.5 新增——每项逻辑 commit 用 `git revert` 回滚并复跑该项针对性测试；多项回滚按提交逆序；相邻性能 commit 按 I → H → F 逆序，保证中间状态可构建；回滚本身需完整证据记录。
5. **S7/S8 配对**：当时将 S8 视为 S7 的配套回归；该未证实绑定已由 v2.4 撤销。
6. **owner 回归阈值引用**：当时直接复用通用 5%/10% 阈值；v2.4 已改为 owner 专用比较器和指标方向合同。

---

## 0.2 v2.4 修订说明（四审修订，2026-08-15）

本版修复 v2.3 审计发现的六项门禁缺口：

1. **上游来源钉死**：已有 `upstream` remote 不再无条件复用；其 URL 必须与用户批准值完全一致，否则 G0 停止。
2. **离线验证修正**：水合模板中的 `GIT_NO_LAZY_FETCH=1` 分别作用于 `show` 和 `diff`，禁止第二条命令隐式联网补对象。
3. **S7/S8 解耦**：两者只保留“可能属于同一问题族”的待证假设；S8 不复现不能单独推出 S7 不适用。
4. **I 范围硬门禁**：新增随 H 固化的机器可读 implementation manifest，实际文件集合必须与其完全一致，注释不再代替检查。
5. **owner 比较闭环**：新增 owner 专用分析器和指标方向合同；正式回退判定改为 1 次 warm-up 加 7 个有效样本，必要时升级为 15 个有效样本。
6. **#1343 成功标准**：固定主指标、输出字节合同和最小收益阈值，避免“测了但无法决定”。

---

## 0. 结论与目标

### 0.1 一句话目标

在不破坏 FluffOS_XK owner/service 多核语义和用户现有工作树的前提下，建立可复现的上游差异证据，按依赖顺序移植已确认适用的安全修复与性能优化，并用针对性、消毒器、LPC、并发和性能证据证明结果。

### 0.2 当前结论

1. 不能直接进入代码移植。现有上游副本缺少目标提交及父提交，原方案的补丁提取方式不可复现。
2. S1-S17 是**待核对候选集**，不是“已确认全部缺失”的实施清单。只有状态为 `missing` 或 `partial` 的候选才进入移植阶段。
3. 性能项暂按 `#1342 -> #1344` 排列，但这只是待验证假设；G1 根据精确 patch 和本地语义试验确定最终 DAG。`#1343` 先只评估独立诊断渲染优化。
4. 循环引用工具、fuzz harness、热重载和工具类 efun 都是可选增强，不随 P0 自动获批。
5. `recompile_object()` 默认延期，必须完成专项设计审计并再次获得用户授权后才能实施。

### 0.3 范围

**默认范围：**

- 建立可追溯的 upstream remote、不可变上游基线和逐项证据表。
- 核对 S1-S17 安全/正确性候选；移植确认缺失且适用于本地结构的修复。
- 按 G1 证据化 DAG 评估和移植 #1342、#1344；仅在本地针对性基准成立时接受。
- 评估 #1343 中可独立移植的 `read_source_line()` 优化。
- 建立普通、ASan+UBSan、必要时 TSan、隔离 LPC testsuite、fuzz 和性能验证矩阵。

**默认不做：**

- 整体同步上游 master、merge/rebase 上游历史。
- flex 编译器重构、transport 抽象、FFI/jsbridge/WASM 等大范围架构迁移。
- 未经专项批准的 `recompile_object()`、lpcshell、scratchpad 所有权重构。
- 改变 owner/service 边界、协议、工作负载、到达形态或超时以制造性能收益。
- 发布、部署、打 tag、force push 或清理用户现有改动。

---

## 1. 执行原则与状态模型

### 1.1 工作树与授权纪律

1. 执行前记录当前分支、HEAD、`git status --short --branch` 和计划文件 SHA-256。
2. 当前工作树不要求“干净”；不得删除、暂存、提交或覆盖用户已有改动。
3. 代码实施必须基于用户确认的 `SYNC_BASE_SHA` 创建隔离 worktree，建议分支名为 `codex/upstream-sync-2026-08`。
4. 添加 remote、fetch、创建分支/worktree、修改代码、提交和推送分别属于有副作用动作，执行前按用户授权边界确认。
5. 每个逻辑修复形成可独立构建、可独立验证、可独立回滚的 commit；不强制把一个上游 umbrella commit 或一行状态表机械压成单一 commit。
6. 未获得明确提交/推送授权时，只保留工作树改动和验证证据，不自行提交或推送。

### 1.2 证据等级

| 等级 | 定义 | 可支持的结论 |
|---|---|---|
| A | 精确上游 commit+parent、源码语义对照、可复现的适用性证据齐全；实施后还需通过该项完整验证 | 可判定 `included/missing/partial/not-applicable`；只有实施验证完成后才能标记 `accepted` |
| B | 当前树特征匹配或单一测试通过，但缺少精确历史/完整验证 | 仅作初筛，不能宣称完成 |
| C | PR 描述、commit message、二手资料或未复现 benchmark | 仅作线索，不能作为实施或验收依据 |

### 1.3 候选状态

每个候选只能使用以下状态：

- `unknown`：精确上游变更或本地等价性尚未核对。
- `included`：本地已有语义等价实现，并有 A 级证据。
- `missing`：本地缺失且确认适用。
- `partial`：本地只覆盖部分语义，需列明缺口。
- `not-applicable`：上游修复依赖本地不存在的路径或问题，并有解释和测试证据。
- `blocked`：依赖、设计或验证未满足，禁止继续依赖项。
- `deferred`：经用户明确决定延期，不计入当前里程碑完成。
- `accepted`：移植完成且全部必需门禁通过。

### 1.4 失败与停止条件

- 不使用“30 分钟内无法定位就 revert 并继续”作为安全策略。
- 任一 P0 项失败时，先保存最小复现、日志和当前差异，状态改为 `blocked`。
- 依赖被阻断后，所有下游项同步阻断；不得绕过检查或弱化验收。
- 只有无依赖的候选可继续核对。跳过适用的 P0 安全项必须由用户明确接受风险。
- 回滚只针对本任务自己的已提交逻辑变更；不得触碰用户或并行任务改动。

### 1.5 回滚流程

- 每项逻辑 commit 独立回滚：`git revert <commit>`，随后复跑该项针对性测试和对应 sanitizer 门禁；revert 与原始 commit 一样需要完整证据记录。
- 多项回滚按提交逆序执行；相邻性能 commit（F/H/I）回滚时按 I → H → F 逆序，保证每个中间状态仍可构建。
- 回滚只针对本任务自己的已提交逻辑变更，不得触碰用户或并行任务改动（与 §1.4 一致）。
- 回滚后对应候选状态在证据文档中更新为 `deferred`/`blocked`，不静默消失。

---

## 2. 阶段 0：建立可复现基线

### 2.1 前置记录

在任何有副作用操作前，只读记录：

```bash
git status --short --branch
git rev-parse HEAD
git remote -v
sha256sum docs/upstream-sync-optimization-plan-2026-08.md
```

上述记录同时用于核对文首基线元数据（含“领先 origin/main”的领先关系）；如与实际不符，以本记录为准并更新文档。

用户确认基线后，设置任务专用变量并创建隔离 worktree：

```bash
SYNC_BASE_SHA=<用户确认的本地提交>
git worktree add -b codex/upstream-sync-2026-08 \
  ../xkx-upstream-sync-work "$SYNC_BASE_SHA"
```

（`../xkx-upstream-sync-work` 在仓库外，命名与 §5.5 的 `../xkx-bench-<candidate>-before/after` detached worktree 明确区分。）

若目标分支或目录已存在，停止并核对所有权，不删除、不复用未知 worktree。

### 2.2 上游历史获取

联网和修改仓库 remote 配置获得授权后执行：

```bash
SYNC_UPSTREAM_URL="https://github.com/fluffos/fluffos.git"  # 用户批准的来源
if git remote get-url upstream >/dev/null 2>&1; then
  test "$(git remote get-url upstream)" = "$SYNC_UPSTREAM_URL" || {
    echo "upstream URL differs from the user-approved source" >&2
    exit 1
  }
else
  git remote add upstream "$SYNC_UPSTREAM_URL"
fi

# 获取可遍历的 master 历史；不能只保留 depth=1 的 tip。
git fetch upstream master:refs/remotes/upstream/master \
  --no-tags --filter=blob:none

# 在现有非 partial clone 仓库中显式登记 promisor/filter；不能假设
# 单次 fetch 已自动持久化 lazy-fetch 配置。
git config remote.upstream.promisor true
git config remote.upstream.partialclonefilter blob:none

SYNC_UPSTREAM_SHA=$(git rev-parse refs/remotes/upstream/master)
git show -s --format=fuller "$SYNC_UPSTREAM_SHA"
```

说明：

- 本地与上游无共同祖先不妨碍查看或 cherry-pick 精确 commit；它只意味着不能把常规 merge/rebase 当作同步策略。
- `SYNC_UPSTREAM_URL` 是本阶段批准记录的一部分；如需使用 SSH URL 或镜像，先由用户批准新值，不能把“remote 已存在”当作来源可信证据。
- `/tmp/fluffos-upstream` 是临时浅克隆，不作为执行证据源。
- 如目标 commit 或 parent 缺失，继续获取相应历史；在 `git cat-file` 验证通过前不得生成补丁。
- 目标 commit 不在 master 可达历史时，按 PR ref 获取并记录来源，例如 `git fetch upstream refs/pull/<PR>/head:refs/remotes/upstream/pr/<PR> --filter=blob:none`。
- `--filter=blob:none` 允许先获取 commit/tree，再按需获取 blob，但 G0 必须显式验证 promisor 配置，不能只根据命令参数推断仓库状态。
- 网络授权期内必须水合每个候选的 parent/head patch blob、关联上游测试、必要头文件和文档证据。新增候选或路径时更新水合清单并重新通过 G0。
- G0 通过后，已批准批次的关键 `show/diff/checkout` 必须能在 `GIT_NO_LAZY_FETCH=1` 下执行；后续执行不依赖持续联网。发现漏水合对象时停止并重新申请最小范围联网授权。

水合记录按以下格式写入 `docs/upstream-sync-evidence-2026-08.md`（每个候选一条，G0 验收时逐条核对）：

```text
Candidate: <S/P/E/T 编号>
Commit: <sha>   Parent: <sha>
Patch objects: <parent-sha>:<path> -> <blob-oid|absent>
               <commit-sha>:<path> -> <blob-oid|absent>
               （每个 patch 路径均记录前后两侧；新增/删除用 absent）
Upstream tests: <sha>:<path> xN（GIT_NO_LAZY_FETCH=1 下 cat-file -e 验证）
Headers/docs: <sha>:<path> xN
Verify show: GIT_NO_LAZY_FETCH=1 git show <sha> --stat
Verify diff: GIT_NO_LAZY_FETCH=1 git diff <sha>^ <sha> -- <paths>
```

新增候选或新增依赖路径时，按同一格式补充条目并重新通过 G0。

### 2.3 精确补丁提取协议

每个 commit 必须先通过：

```bash
SYNC_ITEM_SHA=<目标上游提交>
git cat-file -e "${SYNC_ITEM_SHA}^{commit}"
git cat-file -e "${SYNC_ITEM_SHA}^1^{commit}"
git show --format=fuller --stat "$SYNC_ITEM_SHA"
git diff "${SYNC_ITEM_SHA}^1" "$SYNC_ITEM_SHA" -- <目标路径...>
```

禁止使用以下命令提取单项修复：

```bash
git diff upstream/master -- <file>
```

该命令只能辅助查看“本地当前树 vs 上游最终树”的总体差异，会混入无关改动。

PR 含多个 commit 时，记录 `base_sha`、`head_sha`、merge commit（如有）和实际依赖；不能仅以 PR 号代替补丁范围。

水合后对每个候选重跑关键命令并禁止 lazy fetch：

```bash
GIT_NO_LAZY_FETCH=1 \
  git show --format=fuller --stat "$SYNC_ITEM_SHA"
GIT_NO_LAZY_FETCH=1 \
  git diff "${SYNC_ITEM_SHA}^1" "$SYNC_ITEM_SHA" -- <目标路径...>
```

关联上游测试和文档路径也必须用 `git cat-file -e <sha>:<path>` 在同一模式下验证，路径清单写入证据文档。

### 2.4 基线交付物与门禁 G0

新增 `docs/upstream-sync-evidence-2026-08.md`，至少记录：

- 本地 base SHA、上游 master SHA、获取时间、remote URL。
- 每个候选的精确 commit、parent、PR、文件清单和依赖。
- 当前工作树所有权说明。
- 初筛状态及证据等级。

**G0 通过条件：**

- [ ] 上游 master 不是单提交 shallow 边界。
- [ ] `upstream` 实际 URL 与本阶段用户批准的 `SYNC_UPSTREAM_URL` 完全一致，并已写入证据文档。
- [ ] 所有拟实施 commit 及 parent 可读取。
- [ ] 记录 #1342/#1344 精确 commit、parent 和祖先关系；祖先关系只作历史事实，不直接生成依赖边。
- [ ] `remote.upstream.promisor`、`remote.upstream.partialclonefilter` 与实际 fetch 模式一致。
- [ ] 已批准批次的 patch、上游测试和必要依赖 blob 完成水合，关键命令在 `GIT_NO_LAZY_FETCH=1` 下复现。
- [ ] 证据文档可从记录的 SHA 复现。
- [ ] 隔离 worktree 未包含或覆盖用户未知改动。
- [ ] 用户审阅证据表并授权进入候选核对。

---

## 3. 阶段 1：安全/正确性候选核对

### 3.1 核对流程

每个候选按相同顺序处理：

1. 读取精确上游 patch、关联测试、commit/PR 说明和依赖。
2. 定位本地对应路径；如果结构不同，追踪真实调用链而非只搜关键字。
3. 构造或移植最小回归测试；能复现时先证明本地基线失败。
4. 判定 `included/missing/partial/not-applicable`，记录语义依据。
5. 只有 `missing/partial` 进入阶段 2；umbrella commit 必须拆成可独立判断的子项。
6. 依赖边必须由 patch 重叠、结构/API 前置条件或可复现的编译/行为试验证明；提交时间和祖先关系本身不能建立依赖。

### 3.2 候选清单

下表中的 commit/PR 是原调研线索，在 G0 前均视为 C 级，不代表内容已经确认。

| # | 上游线索 | 候选问题 | 本地重点路径 | 初始状态 |
|---|---|---|---|---|
| S1 | `98f09f3d` | `f_present()` 调用 `id()` 时对象析构 | `packages/core/efuns_main.cc`、`object_present` | B：疑似已含，待精确等价核对 |
| S2 | `ec9b6a4a` | string/object 拼接 UAF 或栈损坏 | `vm/internal/base/interpret.cc` | `unknown` |
| S3 | `aec12ca7` / #1298 | 默认参数 helper/直接调用填充 | `vm/internal/apply.cc` | `unknown` |
| S4 | `2d317e45` | inline 默认参数填充栈损坏 | `vm/internal/apply.cc` | `unknown` |
| S5 | `d9171788` | restore、FFI、master、refloop、socket/parser、math/matrix 等 umbrella 修复 | 按上游 patch 拆分 | `unknown` |
| S6 | `4d5345f5` | preprocessor 递归与 DB 锁对称 | `tools/preprocessor.hpp`、`packages/db/db.cc` | `unknown` |
| S7 | `948b49ed` | object refcount over-decrement | `vm/internal/base/object.cc`、`array.cc` | `unknown` |
| S8 | `b0d3d297` / #1330 | remove_interactive/net_dead teardown 回归 | `testsuite/`、network teardown | `unknown` |
| S9 | `f3e5bfa7` | 宏展开/lexer C 栈递归 | `tools/preprocessor.hpp`、`compiler/internal/lex.cc` | B：旧结构疑似未含 |
| S10 | `8b0aee8a` | #if、parser、TLS、dead-code、aggregate umbrella 修复 | 按上游 patch 拆分 | `unknown` |
| S11 | `d0549220` / `bf73c66e` | 未初始化 float 与 typed lvalue | `svalue.h`、`interpret.cc` | `unknown` |
| S12 | `dca0eae0` / #1302 | 位运算残留 undefined subtype | `packages/ops/ops.cc` | `unknown` |
| S13 | `b1fb96f3` | AFL++ 发现的 compile/restore umbrella 修复 | compiler/restore 路径 | `unknown` |
| S14 | `0f91897c` / #1294 | disassembler/lpcc 缺陷 | `disassembler.cc`、`main_lpcc.cc` | `unknown` |
| S15 | `06d23cfb` / #1293 | 无 return 的行号归属 | `compiler/internal/compiler.cc` | `unknown` |
| S16 | #1260 / 安全公告待确认 | libwebsockets 版本与 CVE 适用性 | `src/thirdparty/libwebsockets/` | B：本地版本 4.2.1（已由 `CMakeLists.txt` 的 `CPACK_PACKAGE_VERSION` 核实），CVE-2025-1866 适用性待核对 |
| S17 | `3ec802f6` | null `backbone_domain` 崩溃 | `packages/core/` | `unknown` |

> 注：S7 与 S8 目前只视为可能同属一个 refcount/teardown 问题族的待证假设。G1 必须分别读取两项精确 patch、关联测试和调用链后，再决定是否建立“修复/配套回归”关系。S8 不复现不能单独推出 S7 为 `not-applicable`；只有精确历史和语义证据证明直接配对时，G2 才成对验收。

### 3.3 核对验收 G1

- [ ] S1-S17 全部达到 A 级判定，umbrella 项已拆出子项。
- [ ] 每项有上游精确 patch、调用链说明、本地判定和测试策略。
- [ ] `missing/partial` 项已有依赖 DAG 和风险分级；每条依赖边均附 patch/结构/试验证据。
- [ ] S7/S8 已分别判定；如建立配对关系，证据中明确主修复、配套测试和非复现时不得反推不适用的边界。
- [ ] 工作量根据确认后的实际文件和测试重新估算。
- [ ] 用户审阅实施清单，决定当前批次；未获批项保持 `deferred`。

---

## 4. 阶段 2：安全/正确性移植

### 4.1 单项实施协议

1. 在当前项变更前运行针对性基线测试，保存命令、退出码和日志摘要。
2. 优先移植上游回归测试；本地方言或架构不同时，记录适配理由，不能删弱断言。
3. 按本地 owner/VMContext 模式实现语义等价修复，不机械复制最终 master 文件。
4. 运行该项针对性测试，再运行本节要求的矩阵。
5. 审阅 task-owned diff、`git diff --check` 和生成文件；无关改动不得混入。
6. 门禁通过并获得提交授权后，形成一个可独立验证的逻辑 commit。

### 4.2 构建与消毒器基线

```bash
# 普通 Release 构建
cmake -S . -B build-sync-release \
  -DCMAKE_BUILD_TYPE=Release -DMARCH_NATIVE=OFF
cmake --build build-sync-release \
  --target driver lpcc lpc_tests ofile_tests -j2

# ASan + UBSan；不能使用不存在的 USE_SANITIZERS
cmake -S . -B build-sync-asan-ubsan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_ASAN=ON -DENABLE_UBSAN=ON \
  -DENABLE_LTO=OFF -DMARCH_NATIVE=OFF
cmake --build build-sync-asan-ubsan \
  --target driver lpcc lpc_tests ofile_tests -j2
```

如变更触及 owner 跨线程状态、对象生命周期、refcount、future、gateway callback 或共享缓存，另跑独立 TSan 构建：

```bash
cmake -S . -B build-sync-tsan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_TSAN=ON -DENABLE_LTO=OFF -DMARCH_NATIVE=OFF
cmake --build build-sync-tsan \
  --target driver lpc_tests ofile_tests -j2

ctest --test-dir build-sync-tsan --output-on-failure
tools/testsuite/run-isolated.sh \
  --driver build-sync-tsan/bin/driver --mode audit
```

### 4.3 测试矩阵

```bash
ctest --test-dir build-sync-release --output-on-failure
ctest --test-dir build-sync-asan-ubsan --output-on-failure

# 使用隔离 runner；禁止直接以固定 0.0.0.0:4000-4003 作为门禁。
tools/testsuite/run-isolated.sh \
  --driver build-sync-release/bin/driver --mode audit
tools/testsuite/run-isolated.sh \
  --driver build-sync-asan-ubsan/bin/driver --mode audit
```

测试数量通过 `ctest --test-dir <build> -N` 动态记录，不在方案中硬编码“当前 424 用例”。

按改动类型追加：

| 改动类型 | 必需追加验证 |
|---|---|
| object/svalue/refcount/apply | 对应最小复现；ASan+UBSan；owner 合同 GTest；必要时 TSan |
| compiler/lexer/restore | crasher 回归；诊断输出钉死；对应 fuzz corpus smoke |
| net/socket/TLS/libwebsockets | teardown 回归；gateway fuzz；协议/完整 wire smoke |
| owner/VMContext 热路径 | owner executor 合同、队列/future/FIFO 清理字段、TSan |
| 依赖升级 | 版本证据、上游 release/security advisory、构建许可与裁剪差异 |

### 4.4 阶段验收 G2

- [ ] 当前获批的所有 `missing/partial` 项均为 `accepted`，或经用户明确转为 `deferred`。
- [ ] 每项针对性测试先后证据完整；不存在只靠全量测试掩盖未复现问题的情况。
- [ ] Release、ASan+UBSan、隔离 LPC testsuite 通过。
- [ ] 需要 TSan/fuzz/协议验证的项通过相应门禁。
- [ ] 无 sanitizer 报告、资源泄漏、残留进程或任务队列未清理。

---

## 5. 阶段 3：性能优化

### 5.1 候选顺序与依赖判定

```text
#1342 去 per-svalue 堆分配
  ..> #1344 ASCII 字符串缓存/快路径（待 G1 证明依赖）

#1343a read_source_line() 独立优化
  -> #1343b scratchpad 所有权重构（默认 deferred）
     -> lpcshell（默认 deferred）
```

`#1342 -> #1344` 目前只是优先核对顺序，不是已确认依赖。G0 记录两项精确 commit/parent 和祖先关系；G1 只有满足以下至少一项时才能建立依赖边：

1. #1344 的 patch preimage、数据布局或调用 API 明确依赖 #1342 引入/删除的结构。
2. 两项存在重叠 hunk，且先移植 #1344 会产生无法语义等价解决的冲突。
3. 同一最小本地试验在未含 #1342 时编译或行为失败，在含 #1342 后通过，并能排除其他改动影响。

如果以上条件均不成立，两项按独立候选处理；可以保持风险优先顺序，但不得把时间线写成技术依赖。

### 5.2 P1：#1342 去 per-svalue 堆分配

**核对范围：**以精确 patch 为准，重点包括 `svalue.h`、`interpret.cc`、`array.cc`、`efuns_main.cc`、`simulate.cc`、`ops.cc` 及所有上游实际触及文件。

**本地风险：**

- owner/VMContext 栈状态和 `vm_set_*_fast` 包装。
- F_REF/lvalue、string-char lvalue 和跨线程对象句柄语义。
- 上游 45 文件变更可能含依赖性清理，必须区分必需变更与无关重构。

**验收：**

- 增加或移植能直接观测目标堆分配消除的测试/benchmark；当前 `lpc_vm_bench` 的 profile 计数不能单独证明该优化。
- 通过 G2 全部正确性门禁。
- 通过 §5.5 性能协议和 owner/object-store 不劣化门禁。

### 5.3 P2：#1344 ASCII 字符串 O(1) 快路径

**核对范围：**

- `EGCIterator` 的 ASCII fast path。
- `stralloc` tri-state ASCII tag、布局 `static_assert` 和所有初始化/复制/释放路径。
- concat 传播、CRLF 例外、`extend_string()` tag 失效。
- `sizeof`、index、range 的缓存读取与边界。
- 本地 stralloc accounting、UTF-8/GBK/source_encoding 语义。

**正确性用例至少覆盖：**

- 空串、短串、72KB ASCII 串。
- `\r\n` 拼接边界和其他 ASCII 拼接。
- UTF-8 中文、GBK 高字节串、无效/边界编码输入。
- append 后 `sizeof`、index、正反向 range。
- tag 未知、命中 ASCII、确认非 ASCII 三种状态。

**性能证据：**新增目标微基准，直接测 `sizeof/index/range/append+sizeof`；不能以现有综合 `lpc_vm_bench` 替代。

### 5.4 P3：#1343 编译诊断优化

分成两个决策单元：

1. `read_source_line()` 缓冲读取：在输出字节完全一致且独立 patch 可提取时，可进入当前批次。
2. scratchpad arena 所有权：默认 `deferred`。它与结构化诊断、compile lifetime 和 lpcshell 消费者耦合，需单独设计审计。

验收至少包括 deep macro/nested include 诊断全文字节对比、编译器单测、ASan+UBSan 和重复编译性能。性能主指标固定为同一输入 corpus 的 `compile_diagnostic_ns_per_case`（越低越好）：7 个有效样本的中位数至少改善 10%，且每个输入的 stdout/stderr、退出码和诊断顺序逐字节一致。中位数改善在 5%-10% 或 p95 回退超过 5% 时改跑 15 个有效样本；15 样本后仍未达到 10% 改善则不得接受 #1343 性能结论。

### 5.5 性能测量协议

性能主证据与 owner 回归证据分开管理。每个性能项都必须拥有自己的相邻 before/after commit 对，不能用阶段 0 的原始 `SYNC_BASE_SHA` 对比包含安全修复和多个性能项的最终结果。

**A. 性能阶段前置与 commit 拓扑**

G2 完成后先得到干净、已验收的 `PERF_STAGE_BASE_SHA`。如果安全修复仍是未提交工作树改动，则停止在 M3；未获得 commit 授权前不能进入正式 G3。

每个性能项先提交功能回归测试（如需新增），再提交只含 benchmark 的 harness commit，最后提交生产实现：

```text
PERF_STAGE_BASE_SHA
  -> F1342（#1342 功能回归测试；如需新增）
     -> H1342（#1342 harness；PERF_1342_BEFORE_SHA）
        -> I1342...（连续且只实现 #1342；PERF_1342_AFTER_SHA）
           -> F1344（#1344 功能回归测试；如需新增）
              -> H1344（#1344 harness；PERF_1344_BEFORE_SHA）
                 -> I1344...（连续且只实现 #1344；PERF_1344_AFTER_SHA）
```

该拓扑只表示建议执行顺序。若 G1 证明 #1342/#1344 独立，可以调整先后或在独立分支试验，但每项仍须从用户批准的干净父提交建立相邻 `F? -> H -> I` 范围；所有接受项最终进入同一集成线并在组合 tip 重跑正确性与非目标回归。#1343 同样使用独立 `F1343? -> H1343 -> I1343`，不与 #1342/#1344 合并归因。

规则：

1. `F` 只能新增或强化候选功能回归测试及其测试注册，不得改变运行时生产语义；基线预期失败的断言必须有精确失败证据，纯等价性/不回归测试则须在 before 上通过。
2. `H` 只能修改 benchmark 工具、专用 benchmark target、分析器、候选 rules/manifest 和必要的 CMake benchmark 注册，不得改变运行时生产语义。
3. `H` 必须先在 before 源码上构建并产生有效样本，之后才允许编写 `I`。
4. `I` 可以是一个或多个连续 commit，但 `H..I` 范围只能包含该候选生产实现，不得混入其他优化、功能测试或 harness 变更。开始 `I` 后如发现测试缺口，停止该项并从补齐后的新 `F/H` 对重新建立 before。
5. before/after 的 harness manifest、文件清单、文件模式和逐文件 SHA-256 必须一致；manifest 必须覆盖该 `H` 引入或修改的全部文件。
6. 未提交状态可运行诊断 benchmark，但不能通过 G3；正式报告中的 `tested_sha` 必须唯一对应实际源码。

**B. Harness 文件与输出合同**

每个候选的 `H` 必须形成该候选可独立复现的完整 harness；共享文件可沿用前项中已提交且未改变的版本。至少包括：

- `tools/upstream-sync-bench.sh`：真实解析 `--candidate`、`--build-dir`、`--report-dir`、`--sample-kind warmup|measurement`；未知参数、缺失参数、非法枚举值或已存在的非空报告目录均退出非零，禁止覆盖既有样本。
- 候选专用微基准 target：#1342 直接观测目标堆分配，#1344 直接测 `sizeof/index/range/append+sizeof`，#1343 直接测固定输入集的重复编译与诊断渲染；不得只包装现有 `lpc_vm_bench`。
- `tools/analyze-upstream-sync-bench.py`：读取同一候选的 before/after 原始 JSON，核对调用方传入的预期 before/after SHA 与 harness 聚合哈希，计算有效样本中位数、p95、回退阈值和最终判定；拒绝覆盖已有比较报告。
- `tools/upstream-sync-bench-<candidate>.rules.json`：在编写 I 前固定主/次指标、方向、样本数、接受/复测/阻断阈值和输出等价合同；分析器拒绝缺字段或与 candidate 不匹配的规则。
- `tools/upstream-sync-impl-<candidate>.manifest`：按字节序排序且无重复的 repo-relative I 范围预期精确文件集合；只列生产源码、生产构建元数据及该实现确需的非测试文件，不列功能测试或 harness 文件。实际集合必须与其完全相等，不是允许子集；重命名按旧、新两个路径记录。
- `tools/upstream-sync-bench-<candidate>.manifest`：按字节序排序且无重复的 repo-relative **harness** 路径清单，包含脚本、分析器、candidate rules、implementation manifest、**benchmark target 的私有源文件**（即 harness 自身引入的微基准源码，不含被优化的生产文件）、CMake 注册和 manifest 自身；每行一个已跟踪普通文件，不允许空行、绝对路径、`..` 路径段或以 `-` 开头的路径。implementation manifest 本身属于 H 元数据并纳入哈希，但它所列出的生产文件不得写入 harness manifest。
- 每个 H 还必须把共享的 `tools/analyze-owner-scheduler-capacity.py`、`tools/upstream-sync-owner-metrics.json`、现有 owner 采集/证据校验脚本、schema、三个 benchmark 私有源及其 CMake 注册纳入 harness manifest；只有 §4.3 判定需要 owner 回归的候选才执行 §5.5E。指标规则逐项声明 JSON metric path、`higher_is_better`/`lower_is_better`/`must_equal_zero`/`must_balance` 方向及是否为硬门禁。

Harness 不得通过修改候选生产文件加入仅供测量的计数逻辑；如需插桩，使用 benchmark target 私有包装、链接器/分配器统计或只对 benchmark target 生效且 before/after 完全相同的机制。

每个 run JSON 至少记录：schema、candidate、tested SHA、harness 文件哈希、rules 哈希、build config hash、编译器、平台、`sample_kind`、目标原始指标和 `lpc_vm_bench` 综合指标。分析器必须拒绝 mixed candidate、mixed config、mixed harness/rules、mixed compiler/platform、重复报告、非预期 tested SHA 或每侧少于规则要求的 `measurement`；比较报告使用独立 schema，并保留所消费原始报告的 SHA-256。

**C. 采样与环境规则**

1. before/after 必须在同一机器、同一编译器、相同 CMake 配置和相同工作负载下运行；配置哈希与 harness 文件哈希必须一致。
2. 每个目标 benchmark 至少保留 7 个有效样本，另跑 1 个 warm-up；比较有效样本的中位数和 p95。p95 仅作尾部噪声信号，主要回退判定使用中位数。
3. #1342 的目标操作在 before 必须能观测到待消除分配，after 的对应 per-svalue 目标分配计数必须为 0；before 已为 0 时回到 G1 重判，不能制造性能结论。
4. #1344 的 ASCII 大串 `sizeof` 必须显示与长度无关的量级，并至少较相邻 baseline 提升 10 倍；否则不能宣称 O(1) 优化有效。
5. #1343 使用 §5.4 的固定 corpus、逐字节输出合同和至少 10% 中位数改善标准。
6. 非目标关键指标中位数回退超过 5% 时重跑 15 个有效样本调查；确认回退超过 10% 时阻断；确认在 5%-10% 时必须记录为 warning 并由用户决定是否接受。
7. 不修改系统 governor、CPU affinity 或机器配置来美化数据；如确需控制环境，单独获得授权并同时重跑 before/after。

**D. 单项 before/after 执行模板**

以下模板对 #1342、#1344、#1343 分别执行。`PERF_ITEM_BEFORE_SHA` 必须是该项 harness commit，`PERF_ITEM_AFTER_SHA` 必须是仅包含该候选连续实现范围的 tip。

```bash
set -euo pipefail

PERF_ITEM=1342  # 分别替换为 1342、1344、1343
PERF_ITEM_BEFORE_SHA=<该项 harness commit>
PERF_ITEM_AFTER_SHA=<该项 implementation range tip>
PERF_PHASE=initial
PERF_EFFECTIVE_RUNS=7
PERF_WORKTREE_PARENT=$(dirname "$(pwd)")
PERF_BEFORE_DIR="${PERF_WORKTREE_PARENT}/xkx-bench-${PERF_ITEM}-before"
PERF_AFTER_DIR="${PERF_WORKTREE_PARENT}/xkx-bench-${PERF_ITEM}-after"

git worktree add --detach "$PERF_BEFORE_DIR" "$PERF_ITEM_BEFORE_SHA"
git worktree add --detach "$PERF_AFTER_DIR" "$PERF_ITEM_AFTER_SHA"

# 从 before commit 读取受版本控制的 harness manifest；先验证清单合同和覆盖性。
PERF_MANIFEST="tools/upstream-sync-bench-${PERF_ITEM}.manifest"
PERF_RULES="tools/upstream-sync-bench-${PERF_ITEM}.rules.json"
PERF_IMPL_MANIFEST="tools/upstream-sync-impl-${PERF_ITEM}.manifest"
mapfile -t PERF_HARNESS_PATHS < <(
  git show "${PERF_ITEM_BEFORE_SHA}:${PERF_MANIFEST}"
)

if [ "${#PERF_HARNESS_PATHS[@]}" -eq 0 ] || \
   ! diff -u \
     <(printf '%s\n' "${PERF_HARNESS_PATHS[@]}") \
     <(printf '%s\n' "${PERF_HARNESS_PATHS[@]}" | LC_ALL=C sort -u); then
  echo "invalid or unsorted harness manifest" >&2
  exit 1
fi

for PERF_REQUIRED_PATH in \
  tools/upstream-sync-bench.sh \
  tools/analyze-upstream-sync-bench.py \
  tools/analyze-owner-scheduler-capacity.py \
  tools/upstream-sync-owner-metrics.json \
  tools/owner-scheduler-capacity.sh \
  tools/docs/derive-cleanup.py \
  tools/docs/check-evidence.py \
  docs/evidence/manifest.schema.json \
  src/tests/owner_runtime_bench.cc \
  src/tests/lpc_vm_bench.cc \
  src/tests/object_store_bench.cc \
  src/tests/CMakeLists.txt \
  "$PERF_RULES" \
  "$PERF_IMPL_MANIFEST" \
  "$PERF_MANIFEST"; do
  if ! printf '%s\n' "${PERF_HARNESS_PATHS[@]}" | \
       grep -Fqx -- "$PERF_REQUIRED_PATH"; then
    echo "manifest misses required path: $PERF_REQUIRED_PATH" >&2
    exit 1
  fi
done

# implementation manifest 在 H 中固化；I 的实际文件集合必须与它完全一致。
mapfile -t PERF_ALLOWED_I_PATHS < <(
  git show "${PERF_ITEM_BEFORE_SHA}:${PERF_IMPL_MANIFEST}"
)
if [ "${#PERF_ALLOWED_I_PATHS[@]}" -eq 0 ] || \
   ! diff -u \
     <(printf '%s\n' "${PERF_ALLOWED_I_PATHS[@]}") \
     <(printf '%s\n' "${PERF_ALLOWED_I_PATHS[@]}" | LC_ALL=C sort -u); then
  echo "invalid or unsorted implementation manifest" >&2
  exit 1
fi
for PERF_ALLOWED_I_PATH in "${PERF_ALLOWED_I_PATHS[@]}"; do
  case "$PERF_ALLOWED_I_PATH" in
    ""|/*|-*|..|../*|*/..|*/../*)
      echo "invalid implementation path: $PERF_ALLOWED_I_PATH" >&2
      exit 1
      ;;
    tools/upstream-sync-*|src/tests/*|testsuite/*)
      echo "test or harness path is forbidden in implementation manifest: $PERF_ALLOWED_I_PATH" >&2
      exit 1
      ;;
  esac
done

for PERF_HARNESS_PATH in "${PERF_HARNESS_PATHS[@]}"; do
  case "$PERF_HARNESS_PATH" in
    ""|/*|-*|..|../*|*/..|*/../*)
      echo "invalid harness path: $PERF_HARNESS_PATH" >&2
      exit 1
      ;;
  esac
  git cat-file -e "${PERF_ITEM_BEFORE_SHA}:${PERF_HARNESS_PATH}"
  git cat-file -e "${PERF_ITEM_AFTER_SHA}:${PERF_HARNESS_PATH}"
  case "$(git ls-tree "$PERF_ITEM_BEFORE_SHA" -- "$PERF_HARNESS_PATH" | awk '{print $1}')" in
    100644|100755) ;;
    *) echo "harness path is not a regular file: $PERF_HARNESS_PATH" >&2; exit 1 ;;
  esac
done

# H 只能是单父 commit；H 自身修改的每个文件都必须被 manifest 覆盖。
test "$(git rev-list --parents -n 1 "$PERF_ITEM_BEFORE_SHA" | wc -w)" -eq 2
mapfile -t PERF_H_COMMIT_PATHS < <(
  git diff --no-renames --name-only \
    "${PERF_ITEM_BEFORE_SHA}^" "$PERF_ITEM_BEFORE_SHA" | \
    LC_ALL=C sort -u
)
if [ -n "$(comm -23 \
  <(printf '%s\n' "${PERF_H_COMMIT_PATHS[@]}") \
  <(printf '%s\n' "${PERF_HARNESS_PATHS[@]}"))" ]; then
  echo "harness commit contains files absent from manifest" >&2
  exit 1
fi

git diff --exit-code "$PERF_ITEM_BEFORE_SHA" "$PERF_ITEM_AFTER_SHA" \
  -- "${PERF_HARNESS_PATHS[@]}"

# 同时独立比较两侧 blob 的逐文件 SHA-256；harness 每次 run 按同一清单
# 重算并写入 JSON，分析器再与这些预检值交叉核对。
PERF_BEFORE_HARNESS_SHA256=$(
  for PERF_HARNESS_PATH in "${PERF_HARNESS_PATHS[@]}"; do
    printf '%s  %s\n' \
      "$(git show "${PERF_ITEM_BEFORE_SHA}:${PERF_HARNESS_PATH}" | sha256sum | cut -d' ' -f1)" \
      "$PERF_HARNESS_PATH"
  done
)
PERF_AFTER_HARNESS_SHA256=$(
  for PERF_HARNESS_PATH in "${PERF_HARNESS_PATHS[@]}"; do
    printf '%s  %s\n' \
      "$(git show "${PERF_ITEM_AFTER_SHA}:${PERF_HARNESS_PATH}" | sha256sum | cut -d' ' -f1)" \
      "$PERF_HARNESS_PATH"
  done
)
test "$PERF_BEFORE_HARNESS_SHA256" = "$PERF_AFTER_HARNESS_SHA256"
PERF_HARNESS_DIGEST=$(
  printf '%s\n' "$PERF_BEFORE_HARNESS_SHA256" | sha256sum | cut -d' ' -f1
)

mapfile -t PERF_ACTUAL_I_PATHS < <(
  git diff --no-renames --name-only \
    "$PERF_ITEM_BEFORE_SHA" "$PERF_ITEM_AFTER_SHA" | LC_ALL=C sort -u
)
if ! diff -u \
  <(printf '%s\n' "${PERF_ALLOWED_I_PATHS[@]}") \
  <(printf '%s\n' "${PERF_ACTUAL_I_PATHS[@]}"); then
  echo "implementation range differs from the frozen manifest" >&2
  exit 1
fi
git diff --check "$PERF_ITEM_BEFORE_SHA" "$PERF_ITEM_AFTER_SHA"

for PERF_SIDE in before after; do
  if [ "$PERF_SIDE" = before ]; then
    PERF_RUN_DIR="$PERF_BEFORE_DIR"
  else
    PERF_RUN_DIR="$PERF_AFTER_DIR"
  fi

  (
    cd "$PERF_RUN_DIR" || exit 1
    cmake -S . -B build-sync-bench \
      -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON -DMARCH_NATIVE=OFF
    for PERF_RUN in $(seq 0 "$PERF_EFFECTIVE_RUNS"); do
      if [ "$PERF_RUN" -eq 0 ]; then
        PERF_SAMPLE_KIND=warmup
      else
        PERF_SAMPLE_KIND=measurement
      fi
      tools/upstream-sync-bench.sh \
        --candidate "$PERF_ITEM" \
        --build-dir build-sync-bench \
        --report-dir "build/reports/upstream-sync/${PERF_SIDE}/${PERF_PHASE}/run-${PERF_RUN}" \
        --sample-kind "$PERF_SAMPLE_KIND"
    done
  )
done

"$PERF_AFTER_DIR/tools/analyze-upstream-sync-bench.py" \
  --candidate "$PERF_ITEM" \
  --before "$PERF_BEFORE_DIR/build/reports/upstream-sync/before/${PERF_PHASE}" \
  --after "$PERF_AFTER_DIR/build/reports/upstream-sync/after/${PERF_PHASE}" \
  --rules "$PERF_AFTER_DIR/$PERF_RULES" \
  --expected-before-sha "$PERF_ITEM_BEFORE_SHA" \
  --expected-after-sha "$PERF_ITEM_AFTER_SHA" \
  --expected-harness-sha256 "$PERF_HARNESS_DIGEST" \
  --expected-effective-runs "$PERF_EFFECTIVE_RUNS" \
  --output "$PERF_AFTER_DIR/build/reports/upstream-sync/comparison-${PERF_PHASE}.json"
```

初检报告要求复测时，不覆盖已有数据：保留 worktree 和构建，将 `PERF_PHASE=investigation`、`PERF_EFFECTIVE_RUNS=15`，仅重新执行采样循环和分析器命令。分析器必须把初检与调查报告分别归档；G3 只接受规则文件定义的最终状态。

创建和移除这些 worktree 都需要相应授权；如路径已存在，停止核对所有权，不自动删除。

**E. owner 回归不劣化门禁（非性能主证据）**

涉及 owner/VMContext/对象生命周期/调度路径时，对同一 before/after commit 对各跑 1 个 warm-up + 7 个有效样本。当前采集脚本只读取环境变量，不能使用尚未实现的 CLI 参数；它只负责生成和校验单次 evidence envelope，跨样本比较由 H 中新增的 owner 分析器负责：

以下模板承接 §5.5D 已设置的 `PERF_ITEM_BEFORE_SHA`、`PERF_ITEM_AFTER_SHA`、`PERF_BEFORE_DIR` 和 `PERF_AFTER_DIR`：

```bash
set -euo pipefail

OWNER_PHASE=initial
OWNER_EFFECTIVE_RUNS=7
for PERF_SIDE in before after; do
  if [ "$PERF_SIDE" = before ]; then
    PERF_RUN_DIR="$PERF_BEFORE_DIR"
  else
    PERF_RUN_DIR="$PERF_AFTER_DIR"
  fi

  (
    cd "$PERF_RUN_DIR" || exit 1
    for OWNER_RUN in $(seq 0 "$OWNER_EFFECTIVE_RUNS"); do
      OWNER_REPORT_DIR="$PWD/build/reports/upstream-sync/${PERF_SIDE}/owner/${OWNER_PHASE}/run-${OWNER_RUN}"
      test ! -e "$OWNER_REPORT_DIR" || {
        echo "owner report directory already exists: $OWNER_REPORT_DIR" >&2
        exit 1
      }
      BUILD_DIR=build-sync-bench \
      REPORT_DIR="$OWNER_REPORT_DIR" \
        tools/owner-scheduler-capacity.sh
    done
  )
done

"$PERF_AFTER_DIR/tools/analyze-owner-scheduler-capacity.py" \
  --before "$PERF_BEFORE_DIR/build/reports/upstream-sync/before/owner/${OWNER_PHASE}" \
  --after "$PERF_AFTER_DIR/build/reports/upstream-sync/after/owner/${OWNER_PHASE}" \
  --rules "$PERF_AFTER_DIR/tools/upstream-sync-owner-metrics.json" \
  --expected-before-sha "$PERF_ITEM_BEFORE_SHA" \
  --expected-after-sha "$PERF_ITEM_AFTER_SHA" \
  --expected-effective-runs "$OWNER_EFFECTIVE_RUNS" \
  --output "$PERF_AFTER_DIR/build/reports/upstream-sync/owner-${OWNER_PHASE}-comparison.json"
```

`run-0` 仅 warm-up，`run-1..7` 为有效样本。分析器必须验证每份 envelope/raw digest、tested SHA、workload schema、build config、编译器和平台一致；缺报告、重复 run、未知方向或必需指标缺失均阻断。owner 队列、future backlog、claim/release、global fallback、FIFO 和 cleanup 字段按 rules 文件执行 `must_equal_zero`/`must_balance` 硬门禁，不得用吞吐提升抵消。

性能指标按 rules 文件声明的方向比较有效样本中位数。初检回退超过 5% 时，不覆盖原报告：设置 `OWNER_PHASE=investigation`、`OWNER_EFFECTIVE_RUNS=15` 后完整重跑上述采集与分析。15 样本确认回退超过 10% 时阻断；确认在 5%-10% 时状态为 `warning_requires_user_decision`，未经用户明确接受不能通过 G3。

### 5.6 阶段验收 G3

- [ ] 实际执行顺序符合 G1 证据化 DAG；未把祖先关系直接当作依赖。
- [ ] 每个性能项都有独立、相邻的 `F? -> H -> I` 范围；harness/rules 哈希一致，I 实际文件集合与冻结的 implementation manifest 完全一致。
- [ ] 目标微基准直接证明该单项优化，综合 benchmark 无确认的重大回退。
- [ ] G2 正确性矩阵全部重跑通过。
- [ ] 如使用独立试验分支，所有接受项已进入同一 `PERF_INTEGRATION_SHA`，组合 tip 的正确性、非目标综合 benchmark 和适用的 owner 回归全部通过。
- [ ] 每项 before/after 原始 JSON、比较报告、原始报告哈希和配置哈希归档。
- [ ] 需要 owner 回归的项完成环境变量形式的 1 warm-up + 7 有效样本及专用比较报告；触发调查时完成独立 15 样本报告，并通过硬正确性与用户决策门禁。
- [ ] 所有性能结论只描述实际测得指标，不复述未经本地复现的上游数字。

---

## 6. 阶段 4：可选增强（默认不执行）

以下各项必须在 G2/G3 后单独选择；批准 P0 不自动批准本节。

| 项 | 正确边界 | 默认状态 | 额外门禁 |
|---|---|---|---|
| E1a | contrib：`has_cycle()`、`find_cycles()`、`break_cycles()` | `deferred` | contrib spec、循环图/DAG/closure/mapping 测试 |
| E1b | develop：`find_orphaned_cycles()`，仅 `DEBUGMALLOC && DEBUGMALLOC_EXTENSIONS` | `deferred` | debugmalloc 专用构建、检测/回收/幂等测试 |
| E2 | `fuzz_compile`、`fuzz_restore` harness 与 corpus | `deferred` | Clang/libFuzzer 配置、bounded smoke、crash artifact 规则 |
| E3 | `recompile_object()` 与 master applies | **`blocked`，待专项设计** | 见 §6.1 |
| E4 | `read_source_line()` 优化（若未在 P3 完成） | `deferred` | 诊断字节一致和编译性能 |
| T1 | contrib：`get_os_env()`/`set_os_env()` + allowlist | `deferred` | 权限、空值、不可写变量、配置测试 |
| T2 | core：`set_clean_up()` | `deferred` | object 生命周期和调度测试 |
| T3 | lpcshell | `blocked`，依赖 scratchpad/结构化诊断 | 独立产品范围和交互测试 |
| T4 | `lpcc --batch` / `--ast` | `deferred` | CLI 兼容与输出合同 |
| T5 | 上游 testsuite 候选同步 | 持续核对，不是独立功能 | 逐修复随项移植，禁止无选择批量覆盖 |

### 6.1 E3 热重载专项前置条件

`recompile_object()` 至少涉及以下兼容边界，不能只核对 `replace_program.cc`：

- `object_t` 变量存储布局和 `prog_generation`。
- local/functional function pointer 对旧 program 的引用及代际失效。
- simul_efun dispatch table 重建。
- master/simul_efun 自身热重载、inherit 链和 `replace_program()` 冲突。
- 正在执行、clone、shadow、destruct、owner shard/program pin 的并发与生命周期。
- 状态迁移、变量增删、异常回滚和旧 program 释放。

只有专项设计文档、调用链清单、失败原子性方案、owner 并发审计和完整测试矩阵获用户批准后，E3 才能从 `blocked` 转为实施项。

---

## 7. 统一验证与证据格式

### 7.1 每项证据记录

`docs/upstream-sync-evidence-2026-08.md` 中每项使用固定字段：

| 字段 | 内容 |
|---|---|
| Candidate | S/P/E/T 编号和一句话问题 |
| Upstream range | commit、parent、PR、依赖 |
| Local base | 测试前本地 SHA |
| Applicability | 状态、调用链和理由 |
| Test first | 测试路径、baseline 结果 |
| Patch | task-owned 文件、实现差异 |
| Verification | 命令、退出码、报告路径、sanitizer 状态 |
| Performance | before/after SHA、implementation manifest、harness/rules/config 哈希、统计与 owner 比较报告，仅性能项 |
| Decision | accepted/blocked/deferred 和批准记录 |

### 7.2 必须保留的原始证据

- 上游 patch/stat 和本地对照摘要。
- targeted test、CTest、隔离 LPC testsuite 的日志与退出码。
- sanitizer/fuzz 原始错误或无错误结论。
- benchmark 与 owner 回归的原始 JSON、汇总、比较报告、commit/config/harness/rules hash。
- `git diff --check`、task-owned diff 和最终状态。

构建目录和临时日志默认不提交；需要进入仓库的证据必须先做敏感信息检查并获得文档范围授权。

### 7.3 不得宣称的结论

- 只通过 C++ GTest，不得写“LPC 全量通过”。
- 只看到特征代码，不得写“已完整包含上游修复”。
- 只跑一次 benchmark，不得写“性能稳定提升”。
- sanitizer 开关未在 cache/编译命令中确认，不得写“ASan/UBSan 通过”。
- owner 合同和清理字段未验证，不得写“多核无回归”。

---

## 8. 里程碑、授权门禁与交付物

| 里程碑 | 内容 | 交付物 | 进入下一阶段的授权 |
|---|---|---|---|
| M0 | 用户审阅本修订版 | 方案内容 hash、范围确认 | 授权联网/remote/worktree 后进入阶段 0 |
| M1 | G0 可复现基线 | upstream SHA、精确历史、证据文档 | 授权候选核对 |
| M2 | G1 候选核对 | S1-S17 A 级状态、实施 DAG、重估工期 | 用户选择当前实施批次 |
| M3 | G2 安全修复与性能基线固化 | 逻辑 commits、测试与 sanitizer 证据、干净且已验收的安全阶段 tip SHA；未获提交授权时只能保留工作树证据并停在 M3 | 用户确认 `PERF_STAGE_BASE_SHA`，并单独授权性能 harness/实现 commits 与 benchmark worktree |
| M4 | G3 性能优化 | 每个获批候选独立的 `F? -> H -> I` 范围、implementation/harness manifests、rules 文件、原始 JSON、逐项及适用的 owner 比较报告、最终 `PERF_INTEGRATION_SHA` | 用户决定可选增强 |
| M5 | 可选增强 | 仅单独批准的 E/T 项 | 每项单独授权 |
| M6 | 收尾 | 全量重验、证据审计、剩余风险 | 单独授权收尾文档 commit 与 push；不含发布部署 |

原方案的 `1~1.5 周` 估算作废。新的实施工期只能在 M2 得到精确缺失项、文件范围、依赖和测试成本后给出；M0-M1 的证据准备预计约 0.5-1 个工作日，但不是交付承诺。

---

## 9. 风险登记

| 风险 | 等级 | 控制措施 | 停止条件 |
|---|---|---|---|
| 用上游最终文件差异代替精确 patch | 阻断 | commit+parent 验证、精确 range | 任一目标 parent 缺失 |
| owner/VMContext 与上游单线程结构冲突 | 高 | 调用链审计、owner 合同、TSan、清理字段 | owner/FIFO/future 硬门禁失败 |
| svalue/refcount/lvalue 组合引入 UAF 或栈损坏 | 高 | 最小复现、ASan+UBSan、分阶段依赖 | sanitizer 或回归失败 |
| 编译器结构差异导致错误机械移植 | 高 | 语义移植、诊断钉死、fuzz | 无法证明等价语义 |
| libwebsockets 升级改变 gateway 行为 | 高 | CVE 适用性、版本/裁剪审计、fuzz/wire | 协议或 teardown 回归 |
| benchmark 噪声造成虚假收益 | 中 | 同配置、候选 rules、7/15 样本中位数/p95、回退阈值 | 配置/rules hash 不一致或结果处于未决区间 |
| I 范围混入其他改动导致错误归因 | 高 | H 中冻结 implementation manifest、禁用 rename 折叠后精确集合比较 | 实际路径集合与 manifest 不一致 |
| 用户/并行工作树被混入 | 高 | 隔离 worktree、task-owned diff | 发现未知重叠改动 |
| 可选增强借 P0 授权扩大范围 | 高 | E/T 默认 deferred、E3/T3 blocked | 缺少单项授权 |

---

## 10. 当前状态表

| Gate | 状态 | 说明 |
|---|---|---|
| 方案审计 | 已完成 | v1 → v2 → v2.1 → v2.2 → v2.3 → v2.4（四审：来源/离线门禁、S7/S8 解耦、I 范围硬校验、owner 比较器、#1343 阈值） |
| M0 修订版确认 | 待用户确认 | 本文件为 DRAFT v2.4 |
| G0 可复现基线 | 未开始 | 当前只有 `6cf257c` shallow 离线参考 |
| G1 候选核对 | 未开始 | S1-S17 不能整体宣称缺失 |
| G2 安全移植 | 未授权 | 等待 G1 和批次选择 |
| G3 性能优化 | 未授权 | `#1342 -> #1344` 仅为待 G1 证据确认的顺序假设；#1343 独立评估 |
| 可选增强 | 未授权 | E/T 默认 deferred；E3/T3 blocked |
| commit/push | 未授权 | 与代码修改授权分离 |
| 发布/部署 | 不在范围 | 本方案不执行 |

---

## 11. 待用户决策

1. 是否批准本 DRAFT v2.4 作为后续执行依据？
2. 批准后，是否授权阶段 0 的联网 fetch、upstream remote 配置和隔离 worktree 创建？
3. M2 完成后分别选择安全项实施批次和性能候选范围；任何性能实施仍须先完成 M3 的干净安全阶段 SHA 固化。
4. 可选增强在 M4 后逐项决定；`recompile_object()` 和 lpcshell 不接受批量授权。
5. commit、push、发布和部署继续分别授权。
