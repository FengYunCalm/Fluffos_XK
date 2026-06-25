# FluffOS_XK 多核化生产验收门禁

## 当前结论

当前 driver 侧多核化执行面已经进入 production gate 前夜：owner-local lifecycle、OwnerExecutor callback task boundary、heartbeat、callout、async/file/db、DNS、socket read/write/close callback 和 gateway command execute 都已经具备 owner executor 路径，并保留 `off` 或 owner executor 不可用时的 main fallback。

这不等于生产完成。10 用户 30 分钟 `audit` 压测已经满足当前压力验收口径；生产 ready 仍取决于真实 mudlib final audit、cross-owner hotspot 清零和直接 cross-owner 可变写清零证据，因此机器可读合同必须继续报告 `production_gate_ready=0`。

## 机器可读状态

`vm_owner_runtime_status()` 与 `vm_owner_thread_status()` 内的 `gateway_owner_task_contract` / `owner_executor_boundary_contract` 必须保持以下状态，直到真实 mudlib production gate 全部通过：

| 字段 | 当前值 | 含义 |
| --- | --- | --- |
| `mudlib_audit_required` | `1` | 真实 mudlib audit 是 production gate 的硬前置 |
| `mudlib_cross_owner_hotspots_ready` | `0` | cross-owner 热点尚未完成迁移验收 |
| `mudlib_cross_owner_hotspots_blocker` | `real_mudlib_audit_not_complete` | 仍缺真实 mudlib audit 证据 |
| `production_gate_ready` | `0` | 不能声明生产可用 |
| `production_gate_blocker` | `real_mudlib_final_audit_not_complete` | 压力口径已收口，仍缺最终非压测 audit 证据 |
| `production_gate_required_users` | `1,3,10` | 当前验收覆盖的并发用户档位 |
| `production_gate_required_durations` | `smoke,30m` | 当前验收覆盖的时长档位 |
| `production_gate_pressure_evidence_ready` | `1` | 10 用户 30 分钟 audit 证据已满足当前压力口径 |
| `production_gate_pressure_evidence` | `xkx_audit_10_users_30m_2026_06_25_zero_timeouts_zero_gateway_errors` | 当前压力验收证据标识 |
| `production_gate_required_modes` | `off,audit,enforced` | 必须覆盖的 driver 多核模式 |
| `production_gate_required_scenarios` | `login,create,move,chat,inventory,shop,quest,combat,skills,mail,reconnect,gateway_callback,socket_callback,heartbeat,callout` | 必须覆盖的真实 mudlib 场景 |
| `production_gate_evidence_schema` | `multicore_production_gate_evidence_v1` | 生产验收证据 schema |
| `production_gate_short_smoke_sufficient` | `0` | 单用户短 smoke 永远不能单独置 ready |
| `production_gate_minimum_ready_evidence` | `accepted_30m_pressure_scope_with_zero_final_audit_blockers` | 最小 ready 证据模型 |
| `production_gate_unclassified_hotspots_required_zero` | `1` | 未分类 cross-owner hotspot 必须为 0 |
| `production_gate_direct_cross_owner_writes_required_zero` | `1` | 直接 cross-owner 可变写必须为 0 |
| `production_gate_context_leaks_required_zero` | `1` | VMContext/eval/context leak 必须为 0 |
| `production_gate_future_backlog_required_zero` | `1` | future backlog 不允许持续增长 |
| `production_gate_same_owner_claim_conflict_required_zero` | `1` | same-owner claim conflict 必须为 0 |
| `production_gate_gateway_error_delta_required_zero` | `1` | gateway rejected/dropped/queue-full/write-error 增量必须为 0 |
| `production_gate_socket_release_policy` | `main_required_until_owner_safe_handshake` | `socket_release` 保持 main-required，直到 release/acquire handshake 被证明 owner-safe |
| `production_gate_socket_release_handshake_ready` | `0` | handshake 尚未完成，不得误判为 production complete |
| `production_gate_report_schema` | `xkx_gateway_loadtest_report_v1` | loadtest JSON 报告 schema |
| `production_gate_report_required_fields` | `schema,run_id,mode,users_requested,duration_seconds,scenario,commands_ok,timeouts,gateway_metrics_delta,production_gate_observations` | 每个归档 JSON 必须包含的字段 |

这些字段只表达生产验收状态，不改变 gateway、heartbeat、callout 或 socket callback 的执行路径。

## 当前 smoke 证据

2026-06-24 本地真实 mudlib gateway smoke 已覆盖 `enforced` 模式下的单用户 WebSocket 登录和基础命令闭环。覆盖动作包括：新角色创建、查看环境、背包、技能、状态、移动、地图和聊天。

2026-06-25 10 用户 `audit` 模式 30 分钟短压已通过，使用 `--command-timeout 5`，`commands_ok=32539`、`timeouts=0`、`gateway_metrics_delta` 全 0。这个结果说明 5 秒预算可以稳定覆盖当前 audit 长压，不应再把 2 秒默认值当成后续矩阵的基线。

观察结果：

- 客户端能完成登录并进入场景。
- 基础玩家命令有响应。
- smoke 期间未观察到新增 driver fatal error 或新增 enforced cross-owner 阻断错误。
- gateway command 已走 `gateway_command_execute` owner executor 合同；网络 reply、prompt、telnet 和 cleanup 仍按合同保留 main-required 边界。

单用户 smoke 只能证明最小路径没有立即回归；当前压力验收以 10 用户 30 分钟 `audit` 结果为准，不再要求追加更长时长或更高并发压测档位。

## Loadtest 入口

仓库内自包含入口为 `tools/loadtest/xkx_gateway_loadtest.py`。最小 smoke 运行形式：

```bash
python3 tools/loadtest/xkx_gateway_loadtest.py --host <gateway-host> --port <gateway-port> --path <ws-path> --mode audit --users 1 --scenario smoke --fail-on-error
```

复核压力证据时显式设置 `--mode`、`--users`、`--duration`、`--ramp-up`、`--scenario`、`--metrics-url` 和 `--report-json`。`--mode` 只记录本次报告对应的 driver 模式，不负责启动或切换 driver；调用方必须先用匹配的 `off`、`audit` 或 `enforced` 配置启动真实链路。当前 loadtest 默认 `--command-timeout` 已提高到 5 秒，30 分钟复核仍建议显式传参记录本次预算。

该脚本输出的 JSON 顶层 schema 为 `xkx_gateway_loadtest_report_v1`，并包含 `production_gate_observations.schema=multicore_production_gate_evidence_v1`。没有 `--metrics-url` 或指标缺失时，`production_gate_observations.metrics_available` 与 `gateway_error_delta_zero` 都必须为 `false`，该 run 只能作为功能 smoke，不能作为 production gate 证据。报告中的 `production_gate_observations.production_matrix_complete` 在单次入口内固定为 `false`；最终 ready 只能由当前接受的 30 分钟压力证据和 final audit 零 blocker 共同决定。

当前入口已通过 1 用户 `smoke` 场景，覆盖登录/建角和 `look`、`i`、`skills`、`score`、`map` 命令闭环；该结果只证明入口可用和最小路径未立即回归，不替代 production matrix。

## 当前阻塞项

本轮只读 final audit 快照仍发现真实 mudlib 中存在未完成分类的入口，包括 generic callback dispatch、network packet wrapper、room/message wrapper 以及仍携带 object 引用的协议/广播路径。这些路径必须逐项证明为 same-owner、安全 snapshot、owner message 或 owner future 后，才能把生产 gate 置 ready。

1. 真实 mudlib final audit 尚未输出完整清单：`call_other`、`present`、move/destruct、parser、mutable payload、socket/gateway callback 都需要按热点归类。
2. 未分类 cross-owner hotspot 尚未以仓内最终报告证明为 0。
3. 直接 cross-owner mutable write 尚未以仓内最终报告证明为 0。
4. 高频同步返回路径尚未逐项证明已经迁成 snapshot、owner message 或 owner future。
5. `socket_release` 仍是 main-required 例外，除非先设计并验证 release/acquire 替代 handshake，否则不得迁入 owner executor。

## 验收矩阵

当前压力验收口径固定为 smoke 与 10 用户 30 分钟 `audit` 复核，不再追加更长时长或更高并发压力档位。final audit 是非压测门禁，负责证明 cross-owner hotspot 与 mutable write 已清零。

| 项目 | 用户数 | 时长 | 必须覆盖 |
| --- | --- | --- | --- |
| smoke 入口 | 1、3 | smoke | 登录、建角、基础命令、gateway callback 基线 |
| accepted pressure evidence | 10 | 30m | audit 模式、owner executor、gateway metrics、timeout/fatal/panic 为 0 |
| final audit | 不适用 | 非压测 | cross-owner hotspot 分类、mutable write 清零、snapshot/message/future 迁移证明 |

通过标准：

- 命令成功率满足 production SLA，且 timeout、断线、panic、fatal error 为 0。
- owner executor trace 中同 owner 串行、不同 owner 可并行，没有 same-owner claim conflict。
- `thread_eval_stack_leak_detected`、VMContext leak、object store sync rejection 都为 0。
- future pending 不持续增长，stale/destructed/owner epoch mismatch 都明确 drop 或 fail。
- gateway metrics 没有 rejected、dropped、queue full 或 write error 增量。
- audit trace 中没有未分类 cross-owner write；enforced 模式没有静默同步 cross-owner fallback。

## 失败处理

- accepted pressure evidence 失效或新增同类路径改动后，禁止把 `production_gate_ready` 改为 `1`，必须重新运行对应 smoke 或 30 分钟复核。
- 若 final audit 发现 mudlib 同步 cross-owner 调用，先迁 mudlib/API 模型，再重跑定向 smoke 或 audit 复核。
- 若失败来自 gateway 协议解析或大 payload，先修协议/客户端解析，再重跑相关 smoke。
- 若失败来自 owner executor context cleanup、future backlog 或 stale drop，先补 driver 合同测试，再重跑 C++、LPC 和真实 mudlib 定向验收。

## 下一步

1. 完成真实 mudlib final audit 报告，输出按调用类型、owner、对象路径和频率聚合的 cross-owner hotspot 清单。
2. 证明未分类 cross-owner hotspot 为 0，直接 cross-owner mutable write 为 0。
3. 将仍需同步返回的高频路径迁移为 snapshot、owner message 或 owner future，并在报告中逐项列明。
4. 复核 owner executor context cleanup、future backlog、stale/drop 和 gateway error delta 证据。
5. final audit 零 blocker 后，才能把 `mudlib_cross_owner_hotspots_ready` 和 `production_gate_ready` 改为 `1`。
