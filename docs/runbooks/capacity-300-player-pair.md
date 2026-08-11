# T16：真实容量与 300-player Pair 验收（external-required）

> 状态：**external-required，未执行**。本页是准备件，不是完成证据。

## 为什么不能在本仓库内完成

300-player Pair 需要用户授权的外部环境：真实 XiaKeXing/mudlib checkout、可控
gateway 端点、指标 endpoint、独立端口/账号以及至少 900 秒的长时运行窗口。
`docs/codebase-audit-and-execution-plan-2026-08-09.md` 第 13 节明确将该项列为
`external-required`；在条件未满足前写“已支持 300 players”属于虚假证据。

## 准备件清单（本分支已交付）

| 准备件 | 位置 | 状态 |
| --- | --- | --- |
| loadtest 入口 | `tools/loadtest/xkx_gateway_loadtest.py` | 已有，支持 `--users/--duration/--ramp-up/--scenario/--command-timeout/--metrics-url/--report-json/--fail-on-error` |
| 证据 schema | `docs/evidence/manifest.schema.json` | 已交付（T03），报告必须携带 commit/config/workload/时间/cleanup |
| 证据校验 | `tools/docs/check-evidence.py` | 已交付（T03） |
| 模式与配置匹配 | driver `off/audit/enforced` 配置模板 | 由运行方按版本化 mudlib commit 提供 |

## 运行模板（外部环境就绪后执行）

```bash
python3 tools/loadtest/xkx_gateway_loadtest.py \
  --host <gateway-host> --port <gateway-port> --path <ws-path> \
  --mode audit --users 300 --duration 900 --ramp-up <seconds> \
  --scenario <versioned-scenario> --command-timeout 5 \
  --metrics-url <metrics-url> --report-json <report.json> --fail-on-error
```

- 对 `single_thread` 与 `owner_thread_full` 各跑至少 300 players、至少 900 秒。
- 重复一次以排除偶然性；保存原始日志、JSON、配置、commit、平台与 cleanup manifest。
- 报告必须通过 `tools/docs/check-evidence.py` 校验，且 `evidence_kind=current`。

## 验收门禁（Gate E，引用方案 §11）

命令成功率、timeout/fatal/panic、gateway error delta、same-owner claim conflict、
VMContext leak、future backlog、direct cross-owner write 与未分类 hotspot 必须
满足发布前批准的 SLO；不满足时只能报告具体上限，不能写“支持 300 players”。

## 回退

运行期间以 `off` 模式或旧二进制做流量切换回退；任何异常先停止压力并保留现场，
不删除日志或强行清理证据。
