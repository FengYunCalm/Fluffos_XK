#!/usr/bin/env python3
"""Create a concise Markdown report from official-vs-XK benchmark JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def latency(report: dict[str, Any], key: str) -> float:
    return float(report.get("summary", {}).get("latency_ms", {}).get(key, 0.0))


def commands_per_second(report: dict[str, Any]) -> float:
    return float(report.get("summary", {}).get("commands_per_second", 0.0))


def ratio(value: float, base: float) -> str:
    if base <= 0:
        return "n/a"
    return f"{value / base:.2f}x"


def render(data: dict[str, Any]) -> str:
    targets = data.get("targets", [])
    official = next((item for item in targets if item.get("target") == "official_master"), None)
    official_cps = commands_per_second(official or {})
    official_p99 = latency(official or {}, "p99")
    lines = [
        "# FluffOS_XK vs Official FluffOS High-Load Report",
        "",
        "## Summary",
        "",
        f"- Schema: `{data.get('schema', '')}`",
        f"- CPU: `{data.get('host', {}).get('cpu_model', '')}`",
        f"- Logical CPUs: `{data.get('host', {}).get('logical_cpus', '')}`",
        "- This report compares only portable telnet/LPC workload results.",
        "- XiaKeXing owner/gateway production mode is a separate A/B result and must not be merged into this official fair comparison.",
        "",
        "## Results",
        "",
        "| Target | Ref | Commit | CPS | CPS ratio vs official | p50 ms | p95 ms | p99 ms | p99 ratio vs official | failures | driver status |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in targets:
        summary = item.get("summary", {})
        lat = summary.get("latency_ms", {})
        lines.append(
            "| {target} | `{ref}` | `{commit}` | {cps:.2f} | {cps_ratio} | {p50:.2f} | {p95:.2f} | {p99:.2f} | {p99_ratio} | {failures} | {status} |".format(
                target=item.get("target", ""),
                ref=item.get("requested_ref", ""),
                commit=(item.get("commit", "") or "")[:12],
                cps=commands_per_second(item),
                cps_ratio=ratio(commands_per_second(item), official_cps),
                p50=float(lat.get("p50", 0.0)),
                p95=float(lat.get("p95", 0.0)),
                p99=float(lat.get("p99", 0.0)),
                p99_ratio=ratio(latency(item, "p99"), official_p99),
                failures=summary.get("failures", 0),
                status=item.get("driver_exit_status", ""),
            )
        )
    lines += [
        "",
        "## Evidence",
        "",
    ]
    for item in targets:
        lines.append(f"- `{item.get('target')}` raw JSON: `{item.get('loadtest_report')}`")
        lines.append(f"- `{item.get('target')}` driver log: `{item.get('driver_log')}`")
        lines.append(f"- `{item.get('target')}` driver sha256: `{item.get('driver_checksum', '')}`")
    lines += [
        "",
        "## Required Interpretation",
        "",
        "- If XK common p99 is more than 10% above official, treat it as a common-path regression.",
        "- If XK production differs little from XK common, do not blame the gateway package without profiling proof.",
        "- Do not claim multicore speedup from this report alone; XiaKeXing single-vs-owner A/B is required.",
        "",
        "## 中文摘要",
        "",
        "- 本报告只比较官方 FluffOS 与 FluffOS_XK 在可移植 telnet/LPC 工作负载下的表现。",
        "- 如果 XK common 的 p99 比官方高超过 10%，应判定为 common path 退化。",
        "- XiaKeXing owner/gateway 生产模式需要另用 single-vs-owner A/B 报告证明，不能混在这里下结论。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze official-vs-XK benchmark JSON")
    parser.add_argument("input_json", type=Path)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.input_json.read_text(encoding="utf-8"))
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(render(data), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
