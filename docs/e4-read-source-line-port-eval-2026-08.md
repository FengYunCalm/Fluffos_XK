# E4 `read_source_line()` 移植评估（L9，评估产出）

> 状态：**DRAFT v0.1** —— 评估文档，实施需单独授权
> 前置：上游对照为 fluffos/fluffos master（2026-08 快照，/tmp 克隆，
> 非 vendor 绑定）；验收门基线见 `docs/upstream-sync-optimization-plan-2026-08.md` §6.1

## 1. 结论摘要

- **`read_source_line()` 不是孤立优化，是上游诊断渲染栈的一部分**。
  本地 src 树零匹配该函数（compiler.cc 无 snippet / emit_snippet /
  report_compile_diagnostic / expansions / fgetc 任何等价物）——移植
  必须连同其调用面（snippet 渲染 + macro 展开级联）一起评估。
- **上游实现形态**（compiler.cc:177，已磁盘实证）：8K 栈缓冲 +
  memchr 分行扫描；512 字节行截断；相对 mudlib 路径解析（`/` 前缀剥
  离）；`fopen` 失败静默返回空串。注释记录优化动机：旧逐字节 fgetc
  读法在 LPC testsuite 全量跑中产生 4540 万次 fgetc（占全运行 12%），
  仅服务 153 次诊断渲染。
- **依赖方向**：read_source_line → 诊断渲染栈（report_compile_diagnostic
  的 snippet/expansion 段）→ 结构化诊断记录（lpcshell 消费）→
  scratchpad arena 基建（上游 #1343）。E4 与 T3（lpcshell 前置）共享
  同一依赖链——**E4 应作为诊断栈移植的一部分立项，不单独立项**。

## 2. 本地现状与差异清单（磁盘实证）

| 维度 | 本地（FluffOS_XK） | 上游（fluffos） | 差异 |
|---|---|---|---|
| read_source_line | 零匹配 | compiler.cc:177（memchr 优化版） | 缺失 |
| 诊断渲染 | 无 snippet/emit_snippet/expansion 级联 | report_compile_diagnostic（clang 形状：snippet + caret + macro 级联 note） | 缺失整个渲染栈 |
| 诊断记录 | prepare_logs（compiler.cc:2802，error_file/line/what 传统格式） | 结构化 Diagnostic 对象（message/snippet/ranges/fixits/expansions） | 记录模型不同 |
| scratchpad | 传统编译器内部 scratchpad（scratchpad.h，语法分析缓冲） | #1343 scratchpad arena（编译周期外生命周期，lpcshell 消费） | arena 基建缺失 |
| 性能基准 | 无 compile_diagnostic_ns_per_case 指标 | 有（profile 工具 + 7 样本验收） | 基准缺失 |
| 错误输出格式 | 传统格式（error_file/line/what） | clang 形状（path:line:col: error/warning + snippet + caret） | 格式不同 |

## 3. 移植范围与依赖

```
T3 lpcshell 前置基建（P8 立项）
 └─ scratchpad arena（诊断生命周期管理）
     └─ 结构化诊断记录（Diagnostic 对象 + 存储）
         └─ 诊断渲染栈（E4 范围）
             ├─ report_compile_diagnostic（yyerror/yywarn 接入）
             ├─ emit_snippet + read_source_line（memchr 版直接带入）
             └─ macro 展开级联（lpc_lex_expansion_chain 等价物）
```

- **read_source_line 本身可直接移植**（~50 行、无外部依赖、仅 libc）——
  但**零调用点**（本地无渲染栈）——单独移植无意义。
- **E4 合理边界**：渲染栈整体移植 + read_source_line（优化形态直接
  带入，**无需先写 fgetc 慢版再优化**——上游已证明慢版是反例）。
- **输出格式兼容风险**：clang 形状输出改变 XK 现有错误格式——mudlib
  工具/日志解析依赖旧格式的需兼容层或分阶段切换。

## 4. 性能基准计划（验收门调整建议）

- 上游验收门（optimization-plan §6.1）：输出逐字节一致 +
  `compile_diagnostic_ns_per_case` 中位数 ≥10% 改善（7 样本；5%-10%
  或 p95 回退 >5% 扩 15 样本）。
- **本地现状**：无该指标、无 profile 工具——**验收门不可直接套用**。
- 建议：① 移植时同步移植上游 profile 工具（诊断路径计时）建立基线；
  ② 因新代码直接写优化形态，性能验收改为**诊断渲染路径总耗时对比**
  （移植前后全量 testsuite 编译耗时，7 样本中位数）；③ "输出逐字节
  一致"改为"与上游实现同输入同输出一致"（golden 样本对比，20 组
  诊断场景），并单列 XK 输出格式切换兼容项。

## 5. 风险与备选

| 风险 | 影响 | 备选 |
|---|---|---|
| 渲染栈移植面大（非单函数） | 周期超预期 | 分两步：先渲染栈+read_source_line（E4），arena/结构化存储随 T3 基建 |
| 错误输出格式变化破坏 mudlib 工具 | 兼容性回归 | 配置开关双格式；默认旧格式，新格式 opt-in |
| 无本地基准可对比 | 验收门失真 | 移植 profile 工具建基线（§4 建议） |
| read_source_line 单独移植零调用点 | 无意义交付 | 不单独立项（§1 结论） |

## 6. 结论

E4 实施**不单独立项**：read_source_line 随诊断渲染栈整体移植（P8 的
T3 基建之后或并行），验收门按 §4 调整；本评估文档即交付物，实施授权
待 P8 立项文档与用户确认后单独申请。
