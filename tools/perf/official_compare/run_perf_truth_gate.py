#!/usr/bin/env python3
"""Run and evaluate the FluffOS_XK performance truth gate."""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "fluffos_perf_truth_gate_v1"
HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run_official_vs_xk.py"
ANALYZER = HERE / "analyze_official_vs_xk.py"
DEFAULT_BENCH_DIR = Path("/home/mechrevo/projects/_bench/fluffos-official-vs-xk")


@dataclass(frozen=True)
class MatrixConfig:
    users: int
    duration: float
    ramp_up: float
    clone_threshold: float
    call_other_threshold: float
    cps_min_ratio: float
    p99_max_ratio: float


MATRIX: dict[str, MatrixConfig] = {
    "smoke": MatrixConfig(20, 60.0, 10.0, 3.0, 1.25, 0.50, 5.0),
    "stage": MatrixConfig(100, 300.0, 60.0, 3.0, 1.25, 0.50, 5.0),
    "final": MatrixConfig(300, 900.0, 60.0, 1.5, 1.10, 0.80, 1.5),
}


def run_cmd(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, timeout=timeout)


def latest_stable_release() -> tuple[str, str]:
    try:
        result = subprocess.run(
            [
                "gh",
                "release",
                "view",
                "--repo",
                "fluffos/fluffos",
                "--json",
                "tagName,publishedAt",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=True,
        )
        data = json.loads(result.stdout)
        return str(data.get("tagName", "")), ""
    except Exception as exc:  # noqa: BLE001 - diagnostics are part of the report.
        return "", f"{type(exc).__name__}: {exc}"


def median_metric(summary: dict[str, Any], driver: str, metric: str) -> float | None:
    runs = summary.get("drivers", {}).get(driver, {}).get("runs", [])
    values: list[float] = []
    for run in runs:
        entry = run.get("metrics", {}).get(metric)
        if isinstance(entry, dict) and "per_ns" in entry:
            values.append(float(entry["per_ns"]))
    if not values:
        return None
    return float(statistics.median(values))


def target(data: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((item for item in data.get("targets", []) if item.get("target") == name), None)


def load_summary(item: dict[str, Any] | None) -> dict[str, Any]:
    if not item:
        return {}
    summary = item.get("summary", {})
    return summary if isinstance(summary, dict) else {}


def load_errors(item: dict[str, Any] | None) -> int:
    summary = load_summary(item)
    return int(summary.get("failures", 0) or 0) + int(summary.get("timeouts", 0) or 0) + int(
        summary.get("disconnected", 0) or 0
    )


def commands_per_second(item: dict[str, Any] | None) -> float:
    return float(load_summary(item).get("commands_per_second", 0.0) or 0.0)


def p99_ms(item: dict[str, Any] | None) -> float:
    return float(load_summary(item).get("latency_ms", {}).get("p99", 0.0) or 0.0)


def add_ratio_check(
    checks: list[dict[str, Any]],
    name: str,
    actual: float | None,
    baseline: float | None,
    threshold: float,
    lower_is_better: bool,
) -> None:
    if actual is None or baseline is None or baseline <= 0:
        checks.append(
            {
                "name": name,
                "status": "blocker",
                "reason": "missing baseline or actual metric",
                "actual": actual,
                "baseline": baseline,
            }
        )
        return
    ratio = actual / baseline
    passed = ratio <= threshold if lower_is_better else ratio >= threshold
    checks.append(
        {
            "name": name,
            "status": "pass" if passed else "fail",
            "actual": actual,
            "baseline": baseline,
            "ratio": ratio,
            "threshold": threshold,
            "direction": "lower_is_better" if lower_is_better else "higher_is_better",
        }
    )


def evaluate_gate(
    matrix: str,
    runner_data: dict[str, Any] | None,
    microbench_data: dict[str, Any] | None,
    runner_exit_status: int,
    runner_blocker: str = "",
) -> dict[str, Any]:
    config = MATRIX[matrix]
    checks: list[dict[str, Any]] = []

    if runner_data is None:
        checks.append({"name": "official_vs_xk_runner", "status": "blocker", "reason": runner_blocker})
    else:
        official = target(runner_data, "official_master")
        xk_common = target(runner_data, "xk_common_gateway_off")
        if official is None or xk_common is None:
            checks.append(
                {
                    "name": "portable_highload_targets",
                    "status": "blocker",
                    "reason": "missing official_master or xk_common_gateway_off target",
                }
            )
        else:
            errors = load_errors(xk_common)
            checks.append(
                {
                    "name": "xk_common_highload_errors",
                    "status": "pass" if errors == 0 else "fail",
                    "actual": errors,
                    "threshold": 0,
                    "direction": "must_equal_zero",
                }
            )
            add_ratio_check(
                checks,
                "xk_common_cps_vs_official",
                commands_per_second(xk_common),
                commands_per_second(official),
                config.cps_min_ratio,
                lower_is_better=False,
            )
            add_ratio_check(
                checks,
                "xk_common_p99_vs_official",
                p99_ms(xk_common),
                p99_ms(official),
                config.p99_max_ratio,
                lower_is_better=True,
            )
        if runner_exit_status != 0:
            checks.append(
                {
                    "name": "runner_exit_status",
                    "status": "fail",
                    "actual": runner_exit_status,
                    "threshold": 0,
                    "reason": "runner returned non-zero; raw JSON is still evaluated when available",
                }
            )

    if microbench_data is None:
        checks.append(
            {
                "name": "portable_microbench_summary",
                "status": "blocker",
                "reason": "portable-bench-summary.json not found or unreadable",
            }
        )
    else:
        add_ratio_check(
            checks,
            "clone_destruct",
            median_metric(microbench_data, "xk_common_gateway_off", "clone_destruct"),
            median_metric(microbench_data, "official_master_common", "clone_destruct"),
            config.clone_threshold,
            lower_is_better=True,
        )
        add_ratio_check(
            checks,
            "call_other_self",
            median_metric(microbench_data, "xk_common_gateway_off", "call_other_self"),
            median_metric(microbench_data, "official_master_common", "call_other_self"),
            config.call_other_threshold,
            lower_is_better=True,
        )

    blockers = [item for item in checks if item.get("status") == "blocker"]
    failures = [item for item in checks if item.get("status") == "fail"]
    status = "blocker" if blockers else "fail" if failures else "pass"
    regressions = sorted(
        failures + blockers,
        key=lambda item: float(item.get("ratio", item.get("actual", 0.0)) or 0.0),
        reverse=True,
    )[:5]
    improvements = [
        item
        for item in checks
        if item.get("status") == "pass"
        and isinstance(item.get("ratio"), (int, float))
        and (
            (item.get("direction") == "lower_is_better" and float(item["ratio"]) < 1.0)
            or (item.get("direction") == "higher_is_better" and float(item["ratio"]) > 1.0)
        )
    ][:5]
    return {
        "status": status,
        "blocker_reason": "; ".join(str(item.get("reason", item.get("name", ""))) for item in blockers),
        "top_regressions": regressions,
        "top_improvements": improvements,
        "checks": checks,
    }


def load_json(path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as exc:  # noqa: BLE001 - surfaced in gate_result.
        return None, f"{type(exc).__name__}: {exc}"


def append_gate_markdown(path: Path, gate: dict[str, Any]) -> None:
    lines = [
        "",
        "## Performance Truth Gate",
        "",
        f"- Status: `{gate.get('status')}`",
        f"- Blocker reason: `{gate.get('blocker_reason', '')}`",
        "",
        "| Check | Status | Actual | Baseline | Ratio | Threshold |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for item in gate.get("checks", []):
        lines.append(
            "| {name} | {status} | {actual} | {baseline} | {ratio} | {threshold} |".format(
                name=item.get("name", ""),
                status=item.get("status", ""),
                actual=item.get("actual", ""),
                baseline=item.get("baseline", ""),
                ratio=f"{float(item['ratio']):.3f}" if isinstance(item.get("ratio"), (int, float)) else "",
                threshold=item.get("threshold", ""),
            )
        )
    lines += [
        "",
        "## 性能门禁结论",
        "",
        "- `pass` 才允许进入正式性能宣传口径。",
        "- `fail` 表示已有数据证明未达红线，需要继续优化 common path 或真实 workload。",
        "- `blocker` 表示缺少必要原始数据，不能下性能结论。",
        "",
    ]
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run FluffOS_XK performance truth gate")
    parser.add_argument("--matrix", choices=sorted(MATRIX), default="smoke")
    parser.add_argument("--bench-dir", type=Path, default=DEFAULT_BENCH_DIR)
    parser.add_argument("--xk-source", type=Path, default=Path("/home/mechrevo/projects/fluffos-src"))
    parser.add_argument("--official-master-ref", default="master")
    parser.add_argument("--official-stable-ref", default="auto")
    parser.add_argument("--skip-stable", action="store_true")
    parser.add_argument("--official-master-source", type=Path, default=Path(""))
    parser.add_argument("--official-master-build", type=Path, default=Path(""))
    parser.add_argument("--official-stable-source", type=Path, default=Path(""))
    parser.add_argument("--official-stable-build", type=Path, default=Path(""))
    parser.add_argument("--xk-common-build", type=Path, default=Path(""))
    parser.add_argument("--xk-production-build", type=Path, default=Path(""))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--scenario", choices=("mixed", "readonly", "clone", "dispatch"), default="mixed")
    parser.add_argument("--think-min", type=float, default=0.02)
    parser.add_argument("--think-max", type=float, default=0.12)
    parser.add_argument("--command-timeout", type=float, default=3.0)
    parser.add_argument("--driver-startup-wait", type=float, default=3.0)
    parser.add_argument("--base-port", type=int, default=4210)
    parser.add_argument("--runner-json", type=Path, default=Path(""))
    parser.add_argument("--report-json", type=Path, default=Path(""))
    parser.add_argument("--report-md", type=Path, default=Path(""))
    parser.add_argument("--microbench-summary", type=Path, default=Path(""))
    parser.add_argument("--evaluate-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = MATRIX[args.matrix]
    args.bench_dir.mkdir(parents=True, exist_ok=True)
    runner_json = args.runner_json or (args.bench_dir / f"perf-truth-{args.matrix}-runner.json")
    report_json = args.report_json or (args.bench_dir / f"perf-truth-{args.matrix}-gate.json")
    report_md = args.report_md or (args.bench_dir / f"perf-truth-{args.matrix}.md")
    microbench_summary = args.microbench_summary or (args.bench_dir / "portable-bench-summary.json")

    stable_ref = "" if args.skip_stable else args.official_stable_ref
    stable_resolution_error = ""
    if stable_ref == "auto":
        stable_ref, stable_resolution_error = latest_stable_release()

    runner_cmd = [
        sys.executable,
        str(RUNNER),
        "--bench-dir",
        str(args.bench_dir),
        "--xk-source",
        str(args.xk_source),
        "--official-master-ref",
        args.official_master_ref,
        "--users",
        str(config.users),
        "--duration",
        str(config.duration),
        "--ramp-up",
        str(config.ramp_up),
        "--scenario",
        args.scenario,
        "--think-min",
        str(args.think_min),
        "--think-max",
        str(args.think_max),
        "--command-timeout",
        str(args.command_timeout),
        "--driver-startup-wait",
        str(args.driver_startup_wait),
        "--base-port",
        str(args.base_port),
        "--report-json",
        str(runner_json),
        "--sync-start",
    ]
    optional_paths = (
        ("--official-master-source", args.official_master_source),
        ("--official-master-build", args.official_master_build),
        ("--official-stable-source", args.official_stable_source),
        ("--official-stable-build", args.official_stable_build),
        ("--xk-common-build", args.xk_common_build),
        ("--xk-production-build", args.xk_production_build),
    )
    for flag, path in optional_paths:
        if str(path) not in ("", "."):
            runner_cmd += [flag, str(path)]
    if stable_ref:
        runner_cmd += ["--official-stable-ref", stable_ref]
    if args.skip_build:
        runner_cmd.append("--skip-build")

    started_at = int(time.time())
    if args.evaluate_only:
        print(f"[perf_truth_gate] evaluate-only runner_json={runner_json}", flush=True)
        runner_result = subprocess.CompletedProcess(runner_cmd, 0)
    else:
        print(
            f"[perf_truth_gate] matrix={args.matrix} users={config.users} "
            f"duration={config.duration}s ramp={config.ramp_up}s",
            flush=True,
        )
        runner_result = run_cmd(runner_cmd)

    runner_data, runner_error = load_json(runner_json)
    microbench_data, microbench_error = load_json(microbench_summary)
    gate = evaluate_gate(
        args.matrix,
        runner_data,
        microbench_data,
        runner_result.returncode,
        runner_error or stable_resolution_error,
    )

    if runner_data is not None:
        subprocess.run(
            [sys.executable, str(ANALYZER), str(runner_json), "--output-md", str(report_md)],
            text=True,
            check=False,
        )
        append_gate_markdown(report_md, gate)

    report = {
        "schema": SCHEMA,
        "created_at": started_at,
        "matrix": args.matrix,
        "matrix_config": config.__dict__,
        "runner_json": str(runner_json),
        "runner_exit_status": runner_result.returncode,
        "runner_markdown": str(report_md) if report_md.exists() else "",
        "microbench_summary": str(microbench_summary),
        "microbench_error": microbench_error,
        "official_stable_ref": stable_ref,
        "official_stable_resolution_error": stable_resolution_error,
        "gate_result": gate,
    }
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if gate["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
