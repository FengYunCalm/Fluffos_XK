# FluffOS_XK 多核化生产验收门禁

## 当前结论

当前 driver 侧多核化执行面已经进入 production gate 前夜：owner-local lifecycle、OwnerExecutor callback task boundary、heartbeat、callout、async/file/db、DNS、socket read/write/close callback 和 gateway command execute 都已经具备 owner executor 路径，并保留 `off` 或 owner executor 不可用时的 main fallback。

这不等于生产完成。真实 mudlib 的 cross-owner hotspot audit、长时间压测和多用户压测仍未完成，因此机器可读合同必须继续报告 `production_gate_ready=0`。

## 机器可读状态

`vm_owner_runtime_status()` 与 `vm_owner_thread_status()` 内的 `gateway_owner_task_contract` / `owner_executor_boundary_contract` 必须保持以下状态，直到真实 mudlib production gate 全部通过：

| 字段 | 当前值 | 含义 |
| --- | --- | --- |
| `mudlib_audit_required` | `1` | 真实 mudlib audit 是 production gate 的硬前置 |
| `mudlib_cross_owner_hotspots_ready` | `0` | cross-owner 热点尚未完成迁移验收 |
| `mudlib_cross_owner_hotspots_blocker` | `real_mudlib_audit_not_complete` | 仍缺真实 mudlib audit 证据 |
| `production_gate_ready` | `0` | 不能声明生产可用 |
| `production_gate_blocker` | `real_mudlib_pressure_not_verified` | 仍缺长压和高并发证据 |
| `production_gate_required_users` | `1,3,10,50,100` | 必须覆盖的并发用户档位 |
| `production_gate_required_durations` | `smoke,30m,2h,overnight` | 必须覆盖的时长档位 |
| `production_gate_required_modes` | `off,audit,enforced` | 必须覆盖的 driver 多核模式 |
| `production_gate_required_scenarios` | `login,create,move,chat,inventory,shop,quest,combat,skills,mail,reconnect,gateway_callback,socket_callback,heartbeat,callout` | 必须覆盖的真实 mudlib 场景 |
| `production_gate_evidence_schema` | `multicore_production_gate_evidence_v1` | 生产验收证据 schema |
| `production_gate_short_smoke_sufficient` | `0` | 单用户短 smoke 永远不能单独置 ready |
| `production_gate_minimum_ready_evidence` | `all_required_modes_users_durations_scenarios_with_zero_blockers` | 最小 ready 证据模型 |
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

该 smoke 只能证明最小路径没有立即回归，不能替代 3/10/50/100 用户并发，也不能替代 30 分钟、2 小时和隔夜压测。

## Loadtest 入口

仓库内自包含入口为 `tools/loadtest/xkx_gateway_loadtest.py`。最小 smoke 运行形式：

```bash
python3 tools/loadtest/xkx_gateway_loadtest.py --host <gateway-host> --port <gateway-port> --path <ws-path> --mode audit --users 1 --scenario smoke --fail-on-error
```

扩大压测时显式设置 `--mode`、`--users`、`--duration`、`--ramp-up`、`--scenario`、`--metrics-url` 和 `--report-json`。`--mode` 只记录本次报告对应的 driver 模式，不负责启动或切换 driver；调用方必须先用匹配的 `off`、`audit` 或 `enforced` 配置启动真实链路。当前 loadtest 默认 `--command-timeout` 已提高到 5 秒，但长压仍建议显式传参记录本次预算。

该脚本输出的 JSON 顶层 schema 为 `xkx_gateway_loadtest_report_v1`，并包含 `production_gate_observations.schema=multicore_production_gate_evidence_v1`。没有 `--metrics-url` 或指标缺失时，`production_gate_observations.metrics_available` 与 `gateway_error_delta_zero` 都必须为 `false`，该 run 只能作为功能 smoke，不能作为 production gate 证据。报告中的 `production_gate_observations.production_matrix_complete` 在单次入口内固定为 `false`，最终只能由完整 production matrix 汇总器在所有模式、用户数、时长和场景都满足后置为 complete。

当前入口已通过 1 用户 `smoke` 场景，覆盖登录/建角和 `look`、`i`、`skills`、`score`、`map` 命令闭环；该结果只证明入口可用和最小路径未立即回归，不替代 production matrix。

## 当前阻塞项

1. 仓库内已新增 `tools/loadtest/xkx_gateway_loadtest.py` 作为自包含 gateway WebSocket smoke/loadtest 入口；该入口已解除对本地未提交客户端模块的隐式依赖，并已通过 1 用户 smoke，但尚未跑完 production matrix。
2. smoke 中出现客户端侧大 payload JSON 解析 warning，涉及批量/系统/地图/动作类消息；虽然本次命令响应可用、driver 日志未新增错误，但这仍是 gateway production gate blocker。
3. 真实 mudlib cross-owner hotspot audit 尚未输出完整清单：`call_other`、`present`、move/destruct、parser、mutable payload、socket/gateway callback 都需要按热点归类。
4. 高频同步返回路径尚未逐项证明已经迁成 snapshot、owner message 或 owner future。
5. `socket_release` 仍是 main-required 例外，除非先设计并验证 release/acquire 替代 handshake，否则不得迁入 owner executor。

## 验收矩阵

每个模式都必须先通过 smoke，再进入更长压测。

| 模式 | 用户数 | 时长 | 必须覆盖 |
| --- | --- | --- | --- |
| `off` | 1、3 | smoke、30m | 旧路径兼容、登录、移动、聊天、断线重连 |
| `audit` | 1、3、10 | smoke、30m、2h | cross-owner trace、owner queue、future、object lifecycle、gateway/socket callback |
| `enforced` | 1、3、10、50、100 | smoke、30m、2h、overnight | 登录、移动、聊天、战斗、物品、任务、存档、断线重连、gateway、socket |

通过标准：

- 命令成功率满足 production SLA，且 timeout、断线、panic、fatal error 为 0。
- owner executor trace 中同 owner 串行、不同 owner 可并行，没有 same-owner claim conflict。
- `thread_eval_stack_leak_detected`、VMContext leak、object store sync rejection 都为 0。
- future pending 不持续增长，stale/destructed/owner epoch mismatch 都明确 drop 或 fail。
- gateway metrics 没有 rejected、dropped、queue full 或 write error 增量。
- audit trace 中没有未分类 cross-owner write；enforced 模式没有静默同步 cross-owner fallback。

## 失败处理

- 任一档位失败，禁止把 `production_gate_ready` 改为 `1`。
- 若失败来自 mudlib 同步 cross-owner 调用，先迁 mudlib/API 模型，再重跑对应档位。
- 若失败来自 gateway 协议解析或大 payload，先修协议/客户端解析，再重跑 smoke 和并发档位。
- 若失败来自 owner executor context cleanup、future backlog 或 stale drop，先补 driver 合同测试，再重跑 C++、LPC 和真实 mudlib 验收。

## 下一步

1. 使用 `tools/loadtest/xkx_gateway_loadtest.py` 先复跑 1 用户 smoke，再扩展到 3/10/50/100 用户矩阵。
2. 修复或隔离大 payload JSON 解析 warning，并把 BACH/SYST/MAPS/ACT 类消息纳入 smoke 断言。
3. 在 `audit` 下收集真实 cross-owner hotspot 报告，输出按调用类型、owner、对象路径和频率聚合的清单。
4. 将高频同步返回路径迁移为 snapshot、owner message 或 owner future。
5. 逐级运行 `off`、`audit`、`enforced` 的 1/3/10/50/100 用户压测和 smoke/30m/2h/overnight 时长档位。
6. 全部通过后，才能把 `mudlib_cross_owner_hotspots_ready` 和 `production_gate_ready` 改为 `1`。
