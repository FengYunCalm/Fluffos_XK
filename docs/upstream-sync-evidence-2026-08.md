# FluffOS_XK 上游同步证据文档（2026-08）

> 状态：G0 已通过（2026-08-15）；随方案执行更新
> 方案：docs/upstream-sync-optimization-plan-2026-08.md（DRAFT v2.4）

## 基线

- 本地 base：`80b0f329`（main，ahead origin/main 1，2026-08-15 记录）
- 上游 master：`6cf257c`（2026-08-12）
- 获取时间：2026-08-15
- remote URL：`https://github.com/fluffos/fluffos.git`（用户批准值，URL 一致性已验证）
- fetch 方式：`git fetch upstream master --shallow-since=2026-05-01`；受配置影响首轮为 blob:none 过滤，后按水合协议逐候选 lazy-fetch 补齐 patch blob；promisor/partialclonefilter 配置与 fetch 模式一致
- 历史窗口：2026-05-01 起 291 commits（覆盖全部候选及 parent 链）
- 工作树说明：用户明确指示直接在 main 执行（覆盖方案 worktree 隔离条款）；用户现有 untracked 文件已按指示提交于 c7d9a3f3；后续改动全部为任务自身逻辑 commit

## G0 验证结果

- upstream/master 非单提交 shallow 边界：OK（291 commits）
- 全部候选 commit+parent 可读：21/21 OK
- 水合（GIT_NO_LAZY_FETCH=1 复现）：6 项抽检 OK，候选全量在 hydration 后可用
- 祖先关系（历史事实，不构成依赖边）：3e341817（#1342）是 1e4d4145（#1344）祖先
- libwebsockets：本地 4.2.1 vs 上游 4.5.8（8fe05a5d，2026-07-13）

## 候选清单（commit+parent 已验证；文件清单为水合后 --stat 摘要）

| # | 上游 commit | 日期 | 问题 | 本地状态（初筛） |
|---|---|---|---|---|
| S1 | `98f09f3d` | 2026-07-20 | f_present() id() 析构空指针 | **accepted**（基线崩溃复现→修复→通过） |
| S2 | `ec9b6a4a` | 2026-07-20 | string/object 拼接 UAF/栈损坏 | **accepted**（逐字等价移植，测试通过） |
| S3 | `aec12ca7` | 2026-07-20 | 默认参数 helper 冲突/直接调用填充 (#1298) | **accepted**（fill_default_args 提取 + 4 调用点接入；generate.cc ast_json 部分本地不存在，不适用） |
| S4 | `2d317e45` | 2026-07-20 | apply.cc inline 默认参数栈损坏 | **accepted**（DEFER fp/sv_funcp 恢复 + 先调用后压栈；测试通过） |
| S5 | `d9171788` | 2026-07-20 | 10 个稳定性 bug umbrella | **accepted**（子项拆分：class/socket/restore/error-handler/mapping/fill_default_args 6 项移植；disassembler std::string 安全、ast_json 本地无、lexer 旧结构无此形态、ffi 无包、add_message 本地不同实现 5 项不适用） |
| S6 | `4d5345f5` | 2026-07-20 | preprocessor 递归 x2 + db.cc 锁 | unknown |
| S7 | `948b49ed` | 2026-07-27 | object refcount over-decrement | unknown |
| S8 | `b0d3d297` | 2026-07-27 | net_dead teardown 回归测试 (#1330) | unknown |
| S9 | `f3e5bfa7` | 2026-07-22 | 宏展开/lexer C 栈递归消除 | B 旧结构疑似未含 |
| S10 | `8b0aee8a` | 2026-07-21 | 5 个 latent gaps umbrella | unknown |
| S11 | `d0549220+bf73c66e` | 2026-07-20/21 | float 未初始化 + typed lvalue (#1303/#1305) | unknown |
| S12 | `dca0eae0` | 2026-07-20 | 位运算残留 undefined subtype (#1302) | unknown |
| S13 | `b1fb96f3` | 2026-07-24 | AFL++ 5 bug umbrella | unknown |
| S14 | `0f91897c` | 2026-07-19 | Coverity disassembler/lpcc (#1294) | unknown |
| S15 | `06d23cfb` | 2026-07-18 | 无 return 行号归属 (#1293) | unknown |
| S16 | `8fe05a5d` | 2026-07-13 | libwebsockets 4.5.8 升级 (#1260) | B 本地 4.2.1，CVE 适用性待核对 |
| S17 | `3ec802f6` | 2026-07-21 | null backbone_domain + lpcc --batch | unknown |
| P1 | `3e341817` | 2026-08-09 | 去 per-svalue 堆分配 (#1342) | 未含（已确认） |
| P2 | `1e4d4145` | 2026-08-12 | ASCII O(1) sizeof/索引 (#1344) | 未含（已确认） |
| P3 | `1099b482` | 2026-08-12 | 诊断渲染加速 + arena (#1343) | 未含（已确认） |

## 备注

- S8 与 S7 只视为可能同族待证假设（v2.4 解耦）；G1 分别判定
- S5/S10/S13 为 umbrella commit，G1 按上游 patch 拆分
- 本文件为执行证据，随 G1/G2/G3 逐步更新候选状态与移植记录
