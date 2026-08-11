# Owner Scheduler 容量验证矩阵报告（T14）

> 生成日期：2026-08-09（Asia/Shanghai）
> 证据类型：`current`（当前 checkout 直接产生）
> 原始数据：`build/reports/capacity/*_capacity.json`（`fluffos.evidence.manifest.v1` 信封，含 commit/compiler/platform/时间/命令/cleanup）
> 验证命令：`tools/docs/check-evidence.py` 对三份报告全部通过

## 1. 验证范围与配置

| 项 | 值 |
| --- | --- |
| commit | 见各报告 `commit_sha` 字段（本次执行 `7256cdcd` 之后的 bench 构建） |
| 平台 | WSL2 Linux x86_64，`nproc` 核 |
| 编译器 | 见各报告 `compiler.version` |
| workload | `owner-scheduler-capacity-v1`：owner runtime bench 内置 1/2/4 worker 矩阵、LPC VM bench、object store bench |
| 复用脚本 | `tools/owner-scheduler-capacity.sh` |

## 2. Owner 矩阵结果（workers × owner 分布）

### 2.1 同 owner 串行语义

| workers | throughput/s | runtime_max_parallel_owners | claim_conflicts |
| --- | ---: | ---: | ---: |
| 1 | 133 | 1 | 0 |
| 2 | 134 | 1 | 0 |
| 4 | 133 | 1 | 0 |

**结论（A 级，当前 checkout）**：同一 owner 的任务在任何 worker 数下都保持串行，`runtime_max_parallel_owners_seen=1`、`claim_conflicts=0`。与合同 `same-owner 无并发执行` 一致。

### 2.2 不同 owner 并行可观测

| workers | throughput/s | runtime_max_parallel_owners | claim_conflicts |
| --- | ---: | ---: | ---: |
| 1 | 175 | 1 | 0 |
| 2 | 302 | 2 | 0 |
| 4 | 536 | 4 | 0 |

**结论（A 级）**：不同 owner 在 2/4 worker 下出现可测并行（1.7x / 3.1x），`max_parallel_owners` 与 worker 数一致，无 same-owner claim conflict。

### 2.3 service shard（多 owner 服务分片）

| workers | throughput/s | runtime_max_parallel_owners | claim_conflicts |
| --- | ---: | ---: | ---: |
| 1 | 174 | 4 | 0 |
| 2 | 299 | 4 | 0 |
| 4 | 534 | 4 | 0 |

**结论（A 级）**：service shard 内多 owner 可跨 worker 并行；1 worker 下 `max_parallel_owners=4` 表示分片内 4 个 owner 均可调度，但物理并行受 worker 数约束（1 worker 时串行执行，吞吐与 1w 档一致）。

### 2.4 队列与终结状态

- `same_owner_initial_queue_depth=32`、`same_owner_throughput_per_sec≈1200`（无 worker 竞争路径）。
- bench 结束后的 executor queue 与 future pending backlog 为 0（stress 脚本 required-zero 断言通过：`normal_path_main_fallback_count=0`、`executor_context_cleanup_leaks=0`、`executor_same_owner_claim_conflicts=0`、`object_resolve_global_fallback_count=0`）。

## 3. Object store 规模基线（32 对象 smoke）

| 指标 | 值 |
| --- | --- |
| resolve p50 / p95 / p99 | 1133 / 1344 / 1856 ns |
| owner_id_lookup p95 | 1064 ns |
| owner_path_lookup p95 | 1504 ns |
| clone p95 | 136663 ns |
| destruct p95 | 55329 ns |
| object_resolve_global_fallback_count | 0 |

**边界**：这是 32 对象诊断规模，**不能**外推 1K/10K/100K 对象；1K/10K/100K 阶梯测量（T11 关联项）属后续容量工作，当前未执行（标记 `unknown`）。

## 4. 结论与限制

1. 当前边界（4 worker、4096 mailbox、32 task budget）在本次 workload 下行为可预测：同 owner 串行、不同 owner 并行、无 claim conflict、无 global fallback、shutdown 后 queue/claim 归零。
2. **未覆盖**（`external-required` / `unknown`）：真实玩家行为、慢 peer、1K+ 对象、4096 session、owner 数 256+、跨机器与 300-player Pair。这些不能由本报告宣称通过。
3. 本报告为 `current` 证据，与 2026-06 历史压测报告明确分离；`production_gate_ready` 判定仍按 `docs/multicore-production-gate.md` 的证据新鲜度规则执行。
