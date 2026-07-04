#!/usr/bin/env python3
"""Run portable LPC microbenchmarks on official FluffOS and FluffOS_XK."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "fluffos_portable_bench_v1"
DEFAULT_BENCH_DIR = Path("/home/mechrevo/projects/_bench/fluffos-official-vs-xk")
MUDLIB_TEMPLATE = Path(__file__).resolve().parent / "portable_mudlib"

PORTABLE_PERF_SOURCE = r'''
int sink;
string sink_s;
mapping sink_m;

void emit(string name, int iterations, int total_ns) {
  int per_ns;
  if (iterations > 0) {
    per_ns = total_ns / iterations;
  } else {
    per_ns = total_ns;
  }
  write("BENCH|" + name + "|" + iterations + "|" + total_ns + "|" + per_ns + "\n");
}

void bench(string name, int iterations, function fn) {
  int before;
  int after;
  set_eval_limit(0x7fffffff);
  reset_eval_cost();
  before = perf_counter_ns();
  evaluate(fn);
  after = perf_counter_ns();
  emit(name, iterations, after - before);
}

int leaf(int x) {
  return x + 1;
}

void run_apply_loop(int n) {
  int i;
  for (i = 0; i < n; i++) {
    sink = leaf(i);
  }
}

void run_call_other_loop(int n) {
  int i;
  object ob;
  ob = this_object();
  for (i = 0; i < n; i++) {
    sink = call_other(ob, "leaf", i);
  }
}

void run_mapping_loop(int n) {
  int i;
  mapping m;
  m = ([ ]);
  for (i = 0; i < n; i++) {
    m[i % 4096] = i + 1;
    sink = m[i % 4096];
  }
  sink_m = m;
}

void run_string_loop(int n) {
  int i;
  string s;
  s = "";
  for (i = 0; i < n; i++) {
    s = "abc" + "def" + "ghi";
    sink = strlen(s);
  }
  sink_s = s;
}

void run_array_loop(int n) {
  int i;
  mixed *a;
  a = ({ });
  for (i = 0; i < n; i++) {
    a += ({ i, i + 1, i + 2 });
    sink = sizeof(a);
    if (sizeof(a) > 300) {
      a = ({ });
    }
  }
}

void run_clone_loop(int n) {
  int i;
  object ob;
  for (i = 0; i < n; i++) {
    ob = new("/std/bench_clone");
    if (!ob) {
      error("clone failed\n");
    }
    destruct(ob);
  }
}

void do_tests() {
  int n_apply;
  int n_map;
  int n_clone;

  n_apply = 200000;
  n_map = 50000;
  n_clone = 2000;

  run_apply_loop(1000);
  run_call_other_loop(1000);
  run_mapping_loop(1000);
  run_string_loop(1000);
  run_array_loop(1000);
  run_clone_loop(100);

  bench("apply_direct", n_apply, (: run_apply_loop, n_apply :));
  bench("call_other_self", n_apply, (: run_call_other_loop, n_apply :));
  bench("mapping_set_get", n_map, (: run_mapping_loop, n_map :));
  bench("string_concat_strlen", n_apply, (: run_string_loop, n_apply :));
  bench("array_append_size", n_map, (: run_array_loop, n_map :));
  bench("clone_destruct", n_clone, (: run_clone_loop, n_clone :));
}
'''


@dataclass(frozen=True)
class Target:
    name: str
    source: Path
    build: Path
    config_overrides: tuple[str, ...] = ()


def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=True,
    )
    return result.stdout


def optional_path(path: Path) -> Path | None:
    return None if str(path) in ("", ".") else path


def git_commit(source: Path) -> str:
    try:
        return run_cmd(["git", "rev-parse", "HEAD"], source, timeout=20).strip()
    except Exception:
        return ""


def driver_path(build: Path) -> Path:
    for candidate in (build / "bin" / "driver", build / "src" / "driver", build / "driver"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"driver not found under {build}")


def prepare_testsuite(run_dir: Path, config_overrides: tuple[str, ...]) -> Path:
    if not MUDLIB_TEMPLATE.exists():
        raise FileNotFoundError(f"portable mudlib template not found: {MUDLIB_TEMPLATE}")
    mudlib = run_dir / "mudlib"
    if mudlib.exists():
        shutil.rmtree(mudlib)
    shutil.copytree(MUDLIB_TEMPLATE, mudlib, ignore=shutil.ignore_patterns("log", "*.o", "*.db"))
    for dirname in ("log", "data"):
        (mudlib / dirname).mkdir(exist_ok=True)
    bench_dir = mudlib / "single" / "tests" / "bench"
    bench_dir.mkdir(parents=True, exist_ok=True)
    (bench_dir / "portable_perf.c").write_text(PORTABLE_PERF_SOURCE, encoding="utf-8")
    config_template = (mudlib / "etc" / "config.template").read_text(encoding="utf-8")
    config = config_template.replace("@PORT@", "0")
    if config_overrides:
        for override in config_overrides:
            key = override.split(":", 1)[0].strip()
            pattern = re.compile(rf"^{re.escape(key)}\s*:.*$", re.MULTILINE)
            if pattern.search(config):
                config = pattern.sub(override, config)
            else:
                config = config.rstrip() + "\n" + override + "\n"
    (mudlib / "etc" / "config").write_text(config, encoding="utf-8")
    return mudlib


def parse_bench_log(text: str) -> dict[str, dict[str, int]]:
    metrics: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        if "BENCH|" not in line:
            continue
        payload = line[line.index("BENCH|") :]
        parts = payload.split("|")
        if len(parts) != 5:
            continue
        _, name, iterations, total_ns, per_ns = parts
        metrics[name] = {
            "iterations": int(iterations),
            "total_ns": int(total_ns),
            "per_ns": int(per_ns),
        }
    return metrics


def run_target_once(args: argparse.Namespace, target: Target, run_index: int) -> dict[str, Any]:
    run_dir = args.bench_dir / "microbench-runs" / f"{target.name}-{run_index}-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    mudlib = prepare_testsuite(run_dir, target.config_overrides)
    driver = driver_path(target.build)
    log_path = run_dir / "driver.log"
    started = time.perf_counter()
    status = 0
    try:
        output = run_cmd(
            [str(driver), "etc/config", "-ftest:single/tests/bench/portable_perf"],
            cwd=mudlib,
            timeout=args.timeout,
        )
    except subprocess.CalledProcessError as exc:
        status = exc.returncode
        output = exc.output
    elapsed = time.perf_counter() - started
    log_path.write_text(output, encoding="utf-8", errors="replace")
    metrics = parse_bench_log(output)
    return {
        "run": run_index,
        "elapsed_s": elapsed,
        "exit_status": status,
        "metrics": metrics,
        "log": str(log_path),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run portable FluffOS LPC microbenchmarks")
    parser.add_argument("--bench-dir", type=Path, default=DEFAULT_BENCH_DIR)
    parser.add_argument("--official-master-source", type=Path, default=DEFAULT_BENCH_DIR / "official-master-src")
    parser.add_argument(
        "--official-master-build",
        type=Path,
        default=DEFAULT_BENCH_DIR / "official-master-src" / "build-release",
    )
    parser.add_argument("--xk-source", type=Path, default=Path("/home/mechrevo/projects/fluffos-src"))
    parser.add_argument("--xk-common-build", type=Path, default=DEFAULT_BENCH_DIR / "xk-common-build")
    parser.add_argument("--xk-production-build", type=Path, default=Path("/home/mechrevo/projects/fluffos-src/build"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--target-order", choices=("interleaved", "grouped"), default="interleaved")
    parser.add_argument("--skip-production", action="store_true")
    parser.add_argument("--report-json", type=Path, default=Path(""))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.bench_dir.mkdir(parents=True, exist_ok=True)
    targets = [
        Target("official_master_common", args.official_master_source, args.official_master_build),
        Target("xk_common_gateway_off", args.xk_source, args.xk_common_build, ("multicore mode : off",)),
    ]
    if not args.skip_production:
        targets.append(Target("xk_production_current", args.xk_source, args.xk_production_build, ("multicore mode : audit",)))
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "created_at": int(time.time()),
        "runs_per_driver": args.runs,
        "target_order": args.target_order,
        "drivers": {},
    }
    failed = False
    for target in targets:
        report["drivers"][target.name] = {
            "source": str(target.source),
            "build": str(target.build),
            "commit": git_commit(target.source),
            "config_overrides": list(target.config_overrides),
            "runs": [],
        }
    if args.target_order == "grouped":
        schedule = [(target, index) for target in targets for index in range(1, args.runs + 1)]
    else:
        schedule = [(target, index) for index in range(1, args.runs + 1) for target in targets]
    for target in targets:
        print(f"[portable_microbench] target={target.name} runs={args.runs}", flush=True)
    for target, index in schedule:
        item = run_target_once(args, target, index)
        if item["exit_status"] != 0 or not item["metrics"]:
            failed = True
        report["drivers"][target.name]["runs"].append(item)
        print(
            f"[portable_microbench] target={target.name} run={index} "
            f"status={item['exit_status']} metrics={len(item['metrics'])}",
            flush=True,
        )
    output = optional_path(args.report_json) or (args.bench_dir / "portable-bench-summary.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
