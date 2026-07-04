#!/usr/bin/env python3
"""Portable telnet load test for official FluffOS and FluffOS_XK.

The workload targets the portable mudlib in this directory and intentionally
uses only common telnet/LPC behavior. It does not depend on XK owner/gateway
APIs, so its output can be used for fair official-vs-XK comparisons.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "portable_fluffos_loadtest_v1"
SCENARIOS = {
    "mixed": ("apply", "call_other", "mapping", "string", "array", "clone"),
    "readonly": ("apply", "call_other", "mapping", "string"),
    "clone": ("clone",),
    "dispatch": ("apply", "call_other"),
}


@dataclass
class PlayerResult:
    index: int
    connected: bool = False
    commands_sent: int = 0
    commands_ok: int = 0
    failures: int = 0
    timeouts: int = 0
    disconnected: bool = False
    latencies_ms: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * pct)))
    return ordered[index]


async def read_until(reader: asyncio.StreamReader, needle: bytes, timeout: float) -> bytes:
    data = bytearray()
    deadline = time.perf_counter() + timeout
    while needle not in data:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {needle!r}")
        chunk = await asyncio.wait_for(reader.read(4096), remaining)
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
        if len(data) > 1_000_000:
            raise RuntimeError("response exceeded 1MB")
    return bytes(data)


async def player_task(args: argparse.Namespace, index: int, start_gate: asyncio.Event) -> PlayerResult:
    result = PlayerResult(index=index)
    try:
        if args.ramp_up > 0:
            await asyncio.sleep(args.ramp_up * index / max(1, args.users - 1))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(args.host, args.port), args.connect_timeout
        )
        result.connected = True
        await read_until(reader, b"PORTABLE_READY", args.login_timeout)
        writer.write(f"benchuser{index}\n".encode("ascii"))
        await writer.drain()
        await read_until(reader, b"> ", args.login_timeout)
        if args.sync_start:
            await start_gate.wait()

        commands = SCENARIOS[args.scenario]
        end_at = time.perf_counter() + args.duration
        while time.perf_counter() < end_at:
            kind = random.choice(commands)
            token = f"u{index}-{result.commands_sent}-{time.monotonic_ns()}"
            command = f"bench {token} {kind}\n"
            started = time.perf_counter()
            writer.write(command.encode("ascii"))
            await writer.drain()
            result.commands_sent += 1
            try:
                await read_until(reader, f"OK {token}".encode("ascii"), args.command_timeout)
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                result.latencies_ms.append(elapsed_ms)
                result.commands_ok += 1
            except TimeoutError as exc:
                result.timeouts += 1
                result.failures += 1
                result.errors.append(str(exc))
                if args.fail_on_error:
                    break
            except Exception as exc:  # noqa: BLE001 - preserve loadtest diagnostics.
                result.failures += 1
                result.errors.append(type(exc).__name__ + ": " + str(exc))
                break
            if args.think_max > 0:
                await asyncio.sleep(random.uniform(args.think_min, args.think_max))

        writer.write(b"quit\n")
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001 - load tests need per-player evidence.
        result.failures += 1
        result.errors.append(type(exc).__name__ + ": " + str(exc))
        if result.connected:
            result.disconnected = True
    return result


def summarize(args: argparse.Namespace, started: float, ended: float, results: list[PlayerResult]) -> dict[str, Any]:
    latencies = [latency for result in results for latency in result.latencies_ms]
    commands_sent = sum(result.commands_sent for result in results)
    commands_ok = sum(result.commands_ok for result in results)
    failures = sum(result.failures for result in results)
    timeouts = sum(result.timeouts for result in results)
    disconnected = sum(1 for result in results if result.disconnected)
    elapsed = max(ended - started, 0.001)
    return {
        "schema": REPORT_SCHEMA,
        "run_id": args.run_id,
        "driver_name": args.driver_name,
        "driver_commit": args.driver_commit,
        "driver_checksum": args.driver_checksum,
        "build_config": args.build_config,
        "host": args.host,
        "port": args.port,
        "users_requested": args.users,
        "users_connected": sum(1 for result in results if result.connected),
        "duration_seconds": args.duration,
        "elapsed_seconds": elapsed,
        "ramp_up_seconds": args.ramp_up,
        "scenario": args.scenario,
        "sync_start": args.sync_start,
        "think_min": args.think_min,
        "think_max": args.think_max,
        "commands_sent": commands_sent,
        "commands_ok": commands_ok,
        "commands_per_second": commands_ok / elapsed,
        "failures": failures,
        "timeouts": timeouts,
        "disconnected": disconnected,
        "latency_ms": {
            "count": len(latencies),
            "avg": statistics.fmean(latencies) if latencies else 0.0,
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
            "max": max(latencies) if latencies else 0.0,
        },
        "sample_errors": [
            {"player": result.index, "errors": result.errors[:3]}
            for result in results
            if result.errors
        ][: args.sample_errors],
    }


async def run(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    start_gate = asyncio.Event()
    tasks = [asyncio.create_task(player_task(args, index, start_gate)) for index in range(args.users)]
    if args.sync_start:
        await asyncio.sleep(args.ramp_up + args.post_login_settle)
        start_gate.set()
    else:
        start_gate.set()
    results = await asyncio.gather(*tasks)
    ended = time.perf_counter()
    report = summarize(args, started, ended, results)
    if args.report_json:
        path = Path(args.report_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if args.fail_on_error and report["failures"] else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Portable FluffOS telnet load tester")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4200)
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--duration", type=float, default=300.0)
    parser.add_argument("--ramp-up", type=float, default=60.0)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="mixed")
    parser.add_argument("--sync-start", action="store_true")
    parser.add_argument("--think-min", type=float, default=0.02)
    parser.add_argument("--think-max", type=float, default=0.12)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--login-timeout", type=float, default=5.0)
    parser.add_argument("--command-timeout", type=float, default=3.0)
    parser.add_argument("--post-login-settle", type=float, default=1.0)
    parser.add_argument("--report-json", default="")
    parser.add_argument("--run-id", default=f"portable-{int(time.time())}-{os.getpid()}")
    parser.add_argument("--driver-name", default="unknown")
    parser.add_argument("--driver-commit", default="")
    parser.add_argument("--driver-checksum", default="")
    parser.add_argument("--build-config", default="")
    parser.add_argument("--sample-errors", type=int, default=12)
    parser.add_argument("--fail-on-error", action="store_true")
    return parser.parse_args()


def main() -> int:
    return asyncio.run(run(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
