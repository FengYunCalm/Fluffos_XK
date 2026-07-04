#!/usr/bin/env python3
"""Build and run official FluffOS versus FluffOS_XK portable benchmarks."""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "fluffos_official_vs_xk_runner_v1"
DEFAULT_OFFICIAL_REPO = "https://github.com/fluffos/fluffos.git"
HERE = Path(__file__).resolve().parent
LOADTEST = HERE / "portable_fluffos_loadtest.py"
MUDLIB_TEMPLATE = HERE / "portable_mudlib"


@dataclass
class Target:
    name: str
    source: Path
    build: Path
    cmake_args: list[str]
    ref: str = ""
    config_overrides: list[str] | None = None


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


def child_usage_snapshot() -> dict[str, float]:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "user_cpu_seconds": usage.ru_utime,
        "system_cpu_seconds": usage.ru_stime,
        "max_rss_kb": float(usage.ru_maxrss),
    }


def child_usage_delta(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    return {
        "user_cpu_seconds": max(0.0, after["user_cpu_seconds"] - before["user_cpu_seconds"]),
        "system_cpu_seconds": max(0.0, after["system_cpu_seconds"] - before["system_cpu_seconds"]),
        "max_rss_kb": after["max_rss_kb"],
    }


def process_snapshot(pid: int) -> dict[str, Any]:
    status_path = Path(f"/proc/{pid}/status")
    stat_path = Path(f"/proc/{pid}/stat")
    snapshot: dict[str, Any] = {"pid": pid, "available": False}
    try:
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(("VmRSS:", "VmHWM:", "Threads:")):
                key, value = line.split(":", 1)
                snapshot[key.lower()] = value.strip()
        stat = stat_path.read_text(encoding="utf-8", errors="replace").split()
        ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        snapshot["user_cpu_seconds"] = int(stat[13]) / ticks
        snapshot["system_cpu_seconds"] = int(stat[14]) / ticks
        snapshot["available"] = True
    except Exception as exc:  # noqa: BLE001 - best-effort diagnostics only.
        snapshot["error"] = f"{type(exc).__name__}: {exc}"
    return snapshot


def log_tail(path: Path, lines: int = 80) -> list[str]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return content[-lines:]
    except Exception as exc:  # noqa: BLE001 - preserve report generation.
        return [f"failed to read log tail: {type(exc).__name__}: {exc}"]


def run_cmd_to_file(cmd: list[str], output: Path, timeout: int | None = None) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        result = subprocess.run(
            cmd,
            stdout=handle,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=True,
        )
    return result.stderr.decode("utf-8", errors="replace")


def sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit(source: Path) -> str:
    try:
        return run_cmd(["git", "rev-parse", "HEAD"], source).strip()
    except Exception:
        return ""


def compiler_info() -> dict[str, str]:
    info: dict[str, str] = {}
    for key, command in (
        ("cc", ["cc", "--version"]),
        ("cxx", ["c++", "--version"]),
        ("cmake", ["cmake", "--version"]),
    ):
        try:
            first_line = run_cmd(command, timeout=10).splitlines()[0]
        except Exception:
            first_line = ""
        info[key] = first_line
    return info


def host_info() -> dict[str, Any]:
    cpu_model = ""
    logical_cpus = os.cpu_count() or 0
    mem_total_kb = 0
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
                break
    except Exception:
        pass
    return {
        "cpu_model": cpu_model,
        "logical_cpus": logical_cpus,
        "mem_total_kb": mem_total_kb,
    }


def checkout_ref(source: Path, ref: str) -> None:
    if not ref or not (source / ".git").exists():
        return
    try:
        run_cmd(["git", "fetch", "--tags", "--prune", "origin", ref], source, timeout=300)
    except Exception:
        run_cmd(["git", "fetch", "--tags", "--prune", "origin"], source, timeout=300)
    run_cmd(["git", "checkout", "--detach", ref], source, timeout=120)
    run_cmd(["git", "submodule", "update", "--init", "--recursive"], source, timeout=900)


def ensure_official_source(args: argparse.Namespace, bench_dir: Path, ref: str, name: str) -> Path:
    source = bench_dir / "sources" / name
    if source.exists():
        if (source / ".git").exists():
            checkout_ref(source, ref)
            return source
        if (source / "CMakeLists.txt").exists():
            return source
        shutil.rmtree(source)
    source.parent.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    clone_commands = [
        ["git", "clone", "--recursive", DEFAULT_OFFICIAL_REPO, str(source)],
        ["gh", "repo", "clone", "fluffos/fluffos", str(source), "--", "--recursive"],
    ]
    for command in clone_commands:
        if source.exists():
            shutil.rmtree(source)
        try:
            run_cmd(command, timeout=900)
            checkout_ref(source, ref)
            return source
        except subprocess.CalledProcessError as exc:
            failures.append(f"{' '.join(command)}: {exc.output.strip()[-500:]}")
        except Exception as exc:  # noqa: BLE001 - preserve download diagnostics.
            failures.append(f"{' '.join(command)}: {type(exc).__name__}: {exc}")

    tarball = bench_dir / f"{name}.tar.gz"
    archive_ref = ref or "master"
    tarball_commands = [
        {
            "label": "curl tarball",
            "cmd": [
                "curl",
                "-L",
                "--retry",
                "3",
                "--connect-timeout",
                "30",
                "--max-time",
                "900",
                "-o",
                str(tarball),
                f"https://github.com/fluffos/fluffos/archive/{archive_ref}.tar.gz",
            ],
            "to_file": False,
        },
        {
            "label": "gh api tarball",
            "cmd": ["gh", "api", f"repos/fluffos/fluffos/tarball/{archive_ref}"],
            "to_file": True,
        },
    ]
    for command in tarball_commands:
        extract_dir = bench_dir / "sources" / f"{name}-extract"
        if source.exists():
            shutil.rmtree(source)
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        try:
            if command["to_file"]:
                run_cmd_to_file(command["cmd"], tarball, timeout=900)
            else:
                run_cmd(command["cmd"], timeout=900)
            extract_dir.mkdir(parents=True, exist_ok=True)
            run_cmd(["tar", "-xzf", str(tarball), "-C", str(extract_dir), "--strip-components=1"], timeout=300)
            extract_dir.rename(source)
            return source
        except subprocess.CalledProcessError as exc:
            output = exc.output if isinstance(exc.output, str) else str(exc.output)
            failures.append(f"{command['label']} {' '.join(command['cmd'])}: {output.strip()[-500:]}")
        except Exception as exc:  # noqa: BLE001 - preserve download diagnostics.
            failures.append(f"{command['label']} {' '.join(command['cmd'])}: {type(exc).__name__}: {exc}")
    raise RuntimeError("failed to fetch official FluffOS source:\n" + "\n".join(failures))


def configure_and_build(target: Target, skip_build: bool) -> None:
    if skip_build:
        return
    target.build.mkdir(parents=True, exist_ok=True)
    cmake = [
        "cmake",
        "-S",
        str(target.source),
        "-B",
        str(target.build),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON",
    ] + target.cmake_args
    run_cmd(cmake, timeout=900)
    run_cmd(["cmake", "--build", str(target.build), "--target", "driver", "lpcc", "-j2"], timeout=1800)


def prepare_mudlib(run_dir: Path, port: int, config_overrides: list[str] | None = None) -> Path:
    mudlib = run_dir / "mudlib"
    if mudlib.exists():
        shutil.rmtree(mudlib)
    shutil.copytree(MUDLIB_TEMPLATE, mudlib)
    config_template = (mudlib / "etc" / "config.template").read_text(encoding="utf-8")
    config = config_template.replace("@PORT@", str(port))
    if config_overrides:
        config += "\n" + "\n".join(config_overrides) + "\n"
    (mudlib / "etc" / "config").write_text(config, encoding="utf-8")
    for dirname in ("log", "data"):
        (mudlib / dirname).mkdir(exist_ok=True)
    return mudlib


def driver_path(build: Path) -> Path:
    for candidate in (build / "bin" / "driver", build / "src" / "driver", build / "driver"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"driver not found under {build}")


def lpcc_path(build: Path) -> Path:
    for candidate in (build / "bin" / "lpcc", build / "src" / "lpcc", build / "lpcc"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"lpcc not found under {build}")


def run_target(args: argparse.Namespace, target: Target, port: int) -> dict[str, Any]:
    target_started = time.time()
    run_dir = args.bench_dir / "runs" / f"{target.name}-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    mudlib = prepare_mudlib(run_dir, port, target.config_overrides)
    driver = driver_path(target.build)
    lpcc = lpcc_path(target.build)
    log_path = run_dir / "driver.log"
    with log_path.open("w", encoding="utf-8") as log:
        print(f"[official_compare] starting driver target={target.name} port={port} log={log_path}", flush=True)
        proc = subprocess.Popen(
            [str(driver), "etc/config"],
            cwd=str(mudlib),
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )
    time.sleep(args.driver_startup_wait)
    driver_started = time.time()
    driver_start_snapshot = process_snapshot(proc.pid)
    report_json = run_dir / "loadtest.json"
    command = [
        str(LOADTEST),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--users",
        str(args.users),
        "--duration",
        str(args.duration),
        "--ramp-up",
        str(args.ramp_up),
        "--scenario",
        args.scenario,
        "--think-min",
        str(args.think_min),
        "--think-max",
        str(args.think_max),
        "--command-timeout",
        str(args.command_timeout),
        "--report-json",
        str(report_json),
        "--driver-name",
        target.name,
        "--driver-commit",
        git_commit(target.source),
        "--driver-checksum",
        sha256(driver),
        "--build-config",
        "Release+LTO " + " ".join(target.cmake_args),
        "--fail-on-error",
    ]
    if args.sync_start:
        command.append("--sync-start")
    loadtest_status = 0
    loadtest_started = time.time()
    usage_before = child_usage_snapshot()
    print(
        f"[official_compare] running loadtest target={target.name} users={args.users} "
        f"duration={args.duration}s ramp={args.ramp_up}s",
        flush=True,
    )
    try:
        run_cmd(command, timeout=int(args.duration + args.ramp_up + 120))
    except subprocess.CalledProcessError as exc:
        loadtest_status = exc.returncode
    finally:
        usage_after = child_usage_snapshot()
        loadtest_ended = time.time()
        driver_end_snapshot = process_snapshot(proc.pid)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=10)
    target_ended = time.time()
    report = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
    print(
        f"[official_compare] finished target={target.name} loadtest_status={loadtest_status} "
        f"driver_status={proc.returncode} elapsed={target_ended - target_started:.1f}s",
        flush=True,
    )
    return {
        "target": target.name,
        "requested_ref": target.ref,
        "source": str(target.source),
        "commit": git_commit(target.source),
        "cmake_args": target.cmake_args,
        "runtime_config_overrides": target.config_overrides or [],
        "build_type": "Release",
        "lto": True,
        "driver": str(driver),
        "driver_checksum": sha256(driver),
        "lpcc_checksum": sha256(lpcc),
        "compiler": compiler_info(),
        "driver_exit_status": proc.returncode,
        "loadtest_exit_status": loadtest_status,
        "timing": {
            "target_started_at": target_started,
            "driver_started_at": driver_started,
            "loadtest_started_at": loadtest_started,
            "loadtest_ended_at": loadtest_ended,
            "target_ended_at": target_ended,
            "target_elapsed_seconds": target_ended - target_started,
            "loadtest_elapsed_seconds": loadtest_ended - loadtest_started,
        },
        "load_generator_resource": child_usage_delta(usage_before, usage_after),
        "driver_process_start_snapshot": driver_start_snapshot,
        "driver_process_end_snapshot": driver_end_snapshot,
        "driver_log": str(log_path),
        "driver_log_tail": log_tail(log_path),
        "loadtest_report": str(report_json),
        "summary": report,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run official FluffOS vs FluffOS_XK portable load tests")
    parser.add_argument("--bench-dir", type=Path, default=Path("/home/mechrevo/projects/_bench/fluffos-official-vs-xk"))
    parser.add_argument("--xk-source", type=Path, default=Path("/home/mechrevo/projects/fluffos-src"))
    parser.add_argument("--official-master-source", type=Path, default=Path(""))
    parser.add_argument("--official-master-build", type=Path, default=Path(""))
    parser.add_argument("--official-stable-source", type=Path, default=Path(""))
    parser.add_argument("--official-stable-build", type=Path, default=Path(""))
    parser.add_argument("--xk-common-build", type=Path, default=Path(""))
    parser.add_argument("--xk-production-build", type=Path, default=Path(""))
    parser.add_argument("--official-master-ref", default="master")
    parser.add_argument("--official-stable-ref", default="")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--duration", type=float, default=300.0)
    parser.add_argument("--ramp-up", type=float, default=60.0)
    parser.add_argument("--scenario", choices=("mixed", "readonly", "clone", "dispatch"), default="mixed")
    parser.add_argument("--sync-start", action="store_true")
    parser.add_argument("--think-min", type=float, default=0.02)
    parser.add_argument("--think-max", type=float, default=0.12)
    parser.add_argument("--command-timeout", type=float, default=3.0)
    parser.add_argument("--driver-startup-wait", type=float, default=3.0)
    parser.add_argument("--base-port", type=int, default=4210)
    parser.add_argument("--report-json", type=Path, default=Path(""))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.bench_dir.mkdir(parents=True, exist_ok=True)
    official_master_source = optional_path(args.official_master_source) or ensure_official_source(
        args, args.bench_dir, args.official_master_ref, "official-master"
    )
    xk_common_build = optional_path(args.xk_common_build) or (args.bench_dir / "build" / "xk-common-gateway-off")
    xk_production_build = optional_path(args.xk_production_build) or (args.bench_dir / "build" / "xk-production")
    targets = [
        Target(
            name="official_master",
            source=official_master_source,
            build=optional_path(args.official_master_build) or (args.bench_dir / "build" / "official-master"),
            cmake_args=[],
            ref=args.official_master_ref,
        ),
        Target(
            name="xk_common_gateway_off",
            source=args.xk_source,
            build=xk_common_build,
            cmake_args=["-DPACKAGE_GATEWAY=OFF"],
            config_overrides=["multicore mode : off"],
        ),
        Target(
            name="xk_production",
            source=args.xk_source,
            build=xk_production_build,
            cmake_args=[],
            config_overrides=["multicore mode : audit"],
        ),
    ]
    if args.official_stable_ref:
        official_stable_source = optional_path(args.official_stable_source) or ensure_official_source(
            args, args.bench_dir, args.official_stable_ref, "official-stable"
        )
        targets.insert(
            1,
            Target(
                name="official_stable",
                source=official_stable_source,
                build=optional_path(args.official_stable_build) or (args.bench_dir / "build" / "official-stable"),
                cmake_args=[],
                ref=args.official_stable_ref,
            ),
        )
    for target in targets:
        print(f"[official_compare] configure/build target={target.name} skip_build={args.skip_build}", flush=True)
        configure_and_build(target, args.skip_build)
    results = []
    for index, target in enumerate(targets):
        print(f"[official_compare] target {index + 1}/{len(targets)}: {target.name}", flush=True)
        results.append(run_target(args, target, args.base_port + index))
    report = {
        "schema": REPORT_SCHEMA,
        "created_at": int(time.time()),
        "host": host_info(),
        "targets": results,
    }
    output = args.report_json or (args.bench_dir / "official-vs-xk-loadtest.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if any(item["loadtest_exit_status"] != 0 for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
