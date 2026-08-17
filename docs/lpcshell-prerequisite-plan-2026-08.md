# lpcshell 前置基建立项（L10，立项产出）

> 状态：**DRAFT v0.1** —— 立项文档；基建实施需单独授权
> 前置：上游对照 fluffos/fluffos master（2026-08 快照）；E4 评估
> `docs/e4-read-source-line-port-eval-2026-08.md`；optimization-plan
> T3 状态（`blocked`，依赖 scratchpad/结构化诊断，原 :785）

## 0. 结论摘要

- **立项成立**：lpcshell（上游 `main_lpcshell.cc`，REPL 交互模型）依赖
  三项本地不存在的基建：ScratchArena（跨编译周期生命周期）、结构化
  诊断记录（`compiler_diags`）、诊断渲染栈（E4 范围）。三者与 lpcshell
  在上游 #1343 中耦合（main_lpcshell.cc:153-167：Session 持有 arena、
  编译后渲染 compiler_diags）。
- **与 E4 共享依赖**：read_source_line 属诊断渲染栈（E4 评估 §1 结论：
  E4 应作为诊断栈移植的一部分立项）。本立项与 E4 合并为**一个诊断
  基建序列**，分四阶段推进（§3），每阶段独立授权。
- **范围纪律**：本批仅立项文档；不实施任何基建代码（optimization-plan
  T3 维持 blocked 直至用户授权）。

## 1. 设计范围

### 1.1 ScratchArena（基建 1）

- 上游形态（base/internal/scratchpad.h:116/149，磁盘实证）：
  `ScratchArena`（chunk 分配器，编译周期外可存活）+ `ScratchArenaBinding`
  （作用域绑定，析构释放 chunk）。
- 本地现状：`src/compiler/internal/scratchpad.h` 是传统编译器内部
  scratchpad（语法分析缓冲，编译周期内），**不是 arena**——语义不同、
  生命周期不同，不能复用。
- 设计要点：arena 所有权单元（lpcshell Session 持有 vs 编译器持有）；
  `compiler_diags` 全局（compiler.h:421 `g_compile.diags`）的 arena 备份
  语义（Diagnostic 记录内字符串指针的生命周期）；绑定嵌套规则
  （Binding 可重入/顺序释放）。

### 1.2 结构化诊断记录（基建 2）

- 上游形态：`Diagnostic` 对象（message / snippet / ranges / fixits /
  expansions，compiler.cc 渲染段为证）+ `compiler_diags`（vector，
  编译期累积、编译后供渲染/lpcshell 消费，compiler.h:441 有 arena
  记录释放路径）。
- 本地现状：`prepare_logs`（compiler.cc:2802）传统 error_file/line/what
  记录——**无对象模型**。
- 设计要点：yyerror/yywarn 接入点改造（调用面全量清单）；Diagnostic
  字段定义（与上游逐字段对齐，保证 E4 渲染栈可移植）；`__INIT`/
  create 期诊断与普通编译诊断的存储隔离。

### 1.3 诊断渲染栈（基建 3 = E4 范围）

- 见 `docs/e4-read-source-line-port-eval-2026-08.md` §3：渲染栈整体移植
  （emit_snippet + read_source_line memchr 版 + macro 展开级联）。
- 输出格式兼容：clang 形状 vs XK 传统格式——配置开关双格式（E4 §5）。

### 1.4 lpcshell REPL 交互合同（基建 4）

- 上游形态（main_lpcshell.cc）：Session/Eval 模型——arena 跨 Eval
  调用存活、每次 Eval 前 reset（:154-167）；编译错误渲染为结构化诊断；
  `compiler_diags` 在 Eval 结束后仍可渲染（arena 生命周期保证）。
- 设计要点：REPL 合同（输入提示符/多行续入/错误恢复/`#` 调试命令）；
  Eval 边界（arena reset 时机）；与 driver 进程模型的关系（独立
  二进制 vs driver 内嵌——上游是独立二进制 main_lpcshell）。

## 2. 阶段拆分与门禁

| 阶段 | 内容 | 依赖 | 门禁 |
|---|---|---|---|
| T3.1 | ScratchArena + Binding | 无 | gtest 单测（分配/释放/嵌套/生命周期）；ASan 零报错 |
| T3.2 | 结构化诊断记录 + yyerror/yywarn 接入 | T3.1 | 全量 lpc_tests 424/424（诊断路径无回归）；诊断对象字段 golden 对比 |
| T3.3 | 渲染栈移植（= E4） | T3.2 | E4 验收门（§4 调整版）：golden 输出一致 + 渲染耗时基线 |
| T3.4 | lpcshell REPL（独立二进制） | T3.3 | REPL 交互合同测试（输入/错误恢复/诊断渲染）；ASan + TSan |

每阶段独立原子提交、证据落盘 docs/evidence/；阶段间用户确认。

## 3. 风险与备选

| 风险 | 影响 | 备选 |
|---|---|---|
| 诊断路径接入破坏既有错误输出 | mudlib 工具回归 | 双格式开关（E4 §5）；T3.2 门禁含全量 ftest 错误输出 diff |
| arena 生命周期与 compiler_diags 指针悬挂 | 内存安全 | T3.1 单测覆盖 + ASan；Binding 顺序纪律（上游声明序模式） |
| lpcshell 产品范围膨胀 | 周期超预期 | 合同最小化：仅编译+诊断渲染，不做求值补全等增强 |
| E4 渲染栈依赖上游大改 | 移植面失控 | 逐函数移植 + golden 对比；超出本立项范围部分单列 |

## 4. 交付物

- 本立项文档（L10 commit 10）
- T3.1-T3.4 各阶段实施授权单独申请（本批不实施）
