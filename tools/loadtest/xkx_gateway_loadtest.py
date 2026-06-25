#!/usr/bin/env python3
"""Self-contained WebSocket smoke/load test for an XK-style gateway.

The script intentionally uses only the Python standard library so production
multicore gate runs do not depend on local ai-player checkout state.
"""

from __future__ import annotations

import argparse
import base64
from collections import defaultdict
import hashlib
import json
import os
import random
import socket
import ssl
import statistics
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


ZH_DIGITS = "零一二三四五六七八九"
XK_PREFIXES = ("\x1b[XK", "\x1bXK")
SCENARIOS = {
    "smoke": ["look", "i", "skills", "score", "map"],
    "readonly": ["look", "i", "skills", "hp", "score", "map"],
    "movement": ["look", "go east", "look", "go west", "look"],
    "room-chat": ["say {token}"],
    "mixed": [
        "look",
        "i",
        "skills",
        "learn list dummy",
        "ask guard about 方向",
        "map",
        "score",
    ],
}

BAD_LOGIN_TOKENS = ("密码错误", "限制登录", "登录失败", "拒绝", "failed")
NAME_PROMPTS = ("角色名", '"stage":"name"', "请输入你的角色名字")
GENDER_PROMPTS = ("性别", '"stage":"gender"')
WORLD_READY_PACKET_TYPES = {"TITL", "EXIT", "NPCS", "ITEM", "MAPS", "STAT", "SKLS", "IVTY"}
NON_CONTENT_PACKET_TYPES = {"PING", "PONG", "ACKN", "REDY", "HPBR", "MPBR", "PRMT"}


class WebSocketError(RuntimeError):
    pass


@dataclass
class PlayerResult:
    index: int
    account: str
    connected: bool = False
    logged_in: bool = False
    created_role: bool = False
    commands_sent: int = 0
    commands_ok: int = 0
    command_failures: int = 0
    timeouts: int = 0
    disconnected: bool = False
    latencies_ms: List[float] = field(default_factory=list)
    command_latencies_ms: Dict[str, List[float]] = field(default_factory=dict)
    command_timeouts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class WebSocketClient:
    def __init__(self, host: str, port: int, path: str, use_tls: bool, timeout: float):
        self.host = host
        self.port = port
        self.path = path if path.startswith("/") else f"/{path}"
        self.use_tls = use_tls
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            context = ssl.create_default_context()
            raw = context.wrap_socket(raw, server_hostname=self.host)
        raw.settimeout(self.timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        raw.sendall(request.encode("ascii"))
        response = self._read_http_response(raw)
        self._validate_handshake(response, key)
        self.sock = raw

    @staticmethod
    def _read_http_response(sock: socket.socket) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 65536:
                raise WebSocketError("websocket handshake response is too large")
        return bytes(data)

    @staticmethod
    def _validate_handshake(response: bytes, key: str) -> None:
        header = response.decode("iso-8859-1", "replace")
        status = header.split("\r\n", 1)[0]
        if " 101 " not in f" {status} ":
            raise WebSocketError(f"websocket upgrade failed: {status}")
        expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        if expected.lower() not in header.lower():
            raise WebSocketError("websocket accept key mismatch")

    def close(self) -> None:
        if not self.sock:
            return
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        finally:
            self.sock = None

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if not self.sock:
            raise WebSocketError("websocket is not connected")
        first = 0x80 | (opcode & 0x0F)
        mask_bit = 0x80
        length = len(payload)
        if length <= 125:
            header = struct.pack("!BB", first, mask_bit | length)
        elif length <= 0xFFFF:
            header = struct.pack("!BBH", first, mask_bit | 126, length)
        else:
            header = struct.pack("!BBQ", first, mask_bit | 127, length)
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def recv_text(self, timeout: float) -> str:
        if not self.sock:
            raise WebSocketError("websocket is not connected")
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            while True:
                opcode, payload = self._recv_frame()
                if opcode == 0x1:
                    return payload.decode("utf-8", "replace")
                if opcode == 0x2:
                    return payload.decode("utf-8", "replace")
                if opcode == 0x8:
                    raise WebSocketError("websocket closed by peer")
                if opcode == 0x9:
                    self._send_frame(0xA, payload)
                    continue
                if opcode == 0xA:
                    continue
        finally:
            self.sock.settimeout(old_timeout)

    def _recv_frame(self) -> tuple[int, bytes]:
        first_two = self._read_exact(2)
        first, second = first_two[0], first_two[1]
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else b""
        payload = self._read_exact(length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        return opcode, payload

    def _read_exact(self, size: int) -> bytes:
        if not self.sock:
            raise WebSocketError("websocket is not connected")
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise WebSocketError("websocket closed while reading")
            data.extend(chunk)
        return bytes(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="XK gateway WebSocket smoke/load test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--path", default="/ws")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--users", type=int, default=1)
    parser.add_argument("--duration", type=float, default=0.0)
    parser.add_argument("--ramp-up", type=float, default=0.0)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="smoke")
    parser.add_argument("--mode", choices=("off", "audit", "enforced"), default="audit")
    parser.add_argument("--commands", default="", help="semicolon-separated command override")
    parser.add_argument("--account-prefix", default="loadtest")
    parser.add_argument("--password", default="test1234")
    parser.add_argument("--gender", default="男")
    parser.add_argument("--run-id", type=int, default=int(time.time()) % 1000)
    parser.add_argument("--connect-timeout", type=float, default=8.0)
    parser.add_argument("--login-timeout", type=float, default=5.0)
    parser.add_argument("--command-timeout", type=float, default=2.0)
    parser.add_argument("--idle-gap", type=float, default=0.15)
    parser.add_argument("--think-min", type=float, default=0.1)
    parser.add_argument("--think-max", type=float, default=0.5)
    parser.add_argument("--metrics-url", default="")
    parser.add_argument("--metrics-cooldown", type=float, default=0.5)
    parser.add_argument("--report-json", default="")
    parser.add_argument("--sample-errors", type=int, default=12)
    parser.add_argument("--fail-on-error", action="store_true")
    return parser.parse_args()

def command_plan(args: argparse.Namespace) -> List[str]:
    if args.commands.strip():
        commands = [item.strip() for item in args.commands.split(";") if item.strip()]
        return commands or ["look"]
    return list(SCENARIOS[args.scenario])


def role_name(index: int, run_id: int) -> str:
    value = (run_id * 1000 + index) % 100000
    return "压" + "".join(ZH_DIGITS[int(ch)] for ch in f"{value:05d}")


def flatten_json(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from flatten_json(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_json(item)
    elif value is not None:
        yield str(value)


def find_next_packet_prefix(text: str, start: int = 0) -> tuple[int, str]:
    matches = [(text.find(prefix, start), prefix) for prefix in XK_PREFIXES]
    matches = [(index, prefix) for index, prefix in matches if index >= 0]
    if not matches:
        return -1, ""
    return min(matches, key=lambda item: item[0])


def parse_xk_packets(frame: str) -> List[tuple[str, Any]]:
    packets: List[tuple[str, Any]] = []
    decoder = json.JSONDecoder()
    cursor = 0
    while cursor < len(frame):
        prefix_index, prefix = find_next_packet_prefix(frame, cursor)
        if prefix_index < 0:
            break
        type_start = prefix_index + len(prefix)
        packet_type = frame[type_start : type_start + 4]
        if len(packet_type) < 4:
            break
        payload_start = type_start + 4
        while payload_start < len(frame) and frame[payload_start].isspace():
            payload_start += 1
        try:
            payload, payload_end = decoder.raw_decode(frame[payload_start:])
            cursor = payload_start + payload_end
        except json.JSONDecodeError:
            next_prefix, _ = find_next_packet_prefix(frame, payload_start)
            if next_prefix < 0:
                payload = frame[payload_start:].strip()
                cursor = len(frame)
            else:
                payload = frame[payload_start:next_prefix].strip()
                cursor = next_prefix
        if packet_type == "BACH" and isinstance(payload, dict):
            messages = payload.get("messages")
            if isinstance(messages, list):
                for item in messages:
                    if not isinstance(item, dict):
                        continue
                    nested_type = item.get("type") or item.get("code")
                    if not isinstance(nested_type, str):
                        continue
                    nested_payload = item.get("payload")
                    if nested_payload is None:
                        nested_payload = item.get("data", item)
                    packets.append((nested_type[:4], nested_payload))
                continue
        packets.append((packet_type, payload))
    return packets


def message_packets(messages: Iterable[str]) -> List[tuple[str, Any]]:
    packets: List[tuple[str, Any]] = []
    for message in messages:
        packets.extend(parse_xk_packets(message))
    return packets


def frame_to_text(frame: str) -> str:
    packets = parse_xk_packets(frame)
    if packets:
        rendered = []
        for packet_type, payload in packets:
            rendered.append(packet_type)
            rendered.extend(flatten_json(payload))
        return "\n".join(rendered)
    try:
        decoded = json.loads(frame)
    except json.JSONDecodeError:
        return frame
    return "\n".join(flatten_json(decoded))


def message_blob(messages: Iterable[str]) -> str:
    return "\n".join(frame_to_text(message) for message in messages)


def compact(text: str, limit: int = 180) -> str:
    return " ".join(text.split())[:limit]


def has_any(text: str, tokens: Iterable[str]) -> bool:
    return any(token and token in text for token in tokens)


def has_world_ready(messages: Iterable[str]) -> bool:
    return any(packet_type in WORLD_READY_PACKET_TYPES for packet_type, _ in message_packets(messages))


def has_content_response(messages: Iterable[str]) -> bool:
    packets = message_packets(messages)
    if any(packet_type not in NON_CONTENT_PACKET_TYPES for packet_type, _ in packets):
        return True
    stripped = compact(message_blob(messages))
    return bool(stripped and stripped not in {">", "> >"})


def collect_messages(client: WebSocketClient, timeout: float, idle_gap: float) -> List[str]:
    deadline = time.monotonic() + timeout
    last_message_at: Optional[float] = None
    messages: List[str] = []
    while time.monotonic() < deadline:
        remaining = max(0.01, min(0.25, deadline - time.monotonic()))
        try:
            messages.append(client.recv_text(remaining))
            last_message_at = time.monotonic()
        except socket.timeout:
            if messages and last_message_at and time.monotonic() - last_message_at >= idle_gap:
                break
        except TimeoutError:
            if messages and last_message_at and time.monotonic() - last_message_at >= idle_gap:
                break
    return messages


def login_player(client: WebSocketClient, args: argparse.Namespace, result: PlayerResult) -> bool:
    client.connect()
    result.connected = True
    collect_messages(client, min(1.0, args.login_timeout), args.idle_gap)
    client.send_text(f"{result.account}:{args.password}\n")
    messages = collect_messages(client, args.login_timeout, args.idle_gap)
    blob = message_blob(messages)
    if has_any(blob, BAD_LOGIN_TOKENS):
        result.errors.append("login_rejected:" + compact(blob))
        return False
    if has_world_ready(messages):
        result.logged_in = True
        return True
    if has_any(blob, NAME_PROMPTS):
        result.created_role = True
        client.send_text(role_name(result.index, args.run_id) + "\n")
        messages.extend(collect_messages(client, args.login_timeout, args.idle_gap))
        blob = message_blob(messages)
        if has_world_ready(messages):
            result.logged_in = True
            return True

    if has_any(blob, GENDER_PROMPTS):
        client.send_text(args.gender + "\n")
        messages.extend(collect_messages(client, args.login_timeout, args.idle_gap))
        blob = message_blob(messages)
        if has_world_ready(messages):
            result.logged_in = True
            return True

    if has_any(blob, BAD_LOGIN_TOKENS):
        result.errors.append("login_or_create_rejected:" + compact(blob))
        return False

    client.send_text("look\n")
    probe_messages = collect_messages(client, args.login_timeout, args.idle_gap)
    if has_world_ready(probe_messages) or has_content_response(probe_messages):
        result.logged_in = True
        return True

    if not messages and not probe_messages:
        result.errors.append("login_timeout")
        return False
    result.errors.append("login_state_unconfirmed:" + compact(message_blob(messages + probe_messages)))
    return False


def run_command(client: WebSocketClient, command: str, args: argparse.Namespace, result: PlayerResult) -> None:
    command_key = command
    expects_token = "{token}" in command
    token = f"LT-{result.index:04d}-{result.commands_sent + 1:04d}"
    command = command.replace("{token}", token)
    started = time.perf_counter()
    result.commands_sent += 1
    client.send_text(command + "\n")
    messages = collect_messages(client, args.command_timeout, args.idle_gap)
    elapsed = (time.perf_counter() - started) * 1000.0
    blob = message_blob(messages)
    if has_content_response(messages) and (not expects_token or token in blob):
        result.commands_ok += 1
        result.latencies_ms.append(elapsed)
        result.command_latencies_ms.setdefault(command_key, []).append(elapsed)
        return
    result.timeouts += 1
    result.command_failures += 1
    result.command_timeouts[command_key] = result.command_timeouts.get(command_key, 0) + 1
    result.errors.append("timeout:" + command)


def run_player(index: int, args: argparse.Namespace, commands: List[str]) -> PlayerResult:
    account = f"{args.account_prefix}_{args.run_id:03d}_{index:04d}"
    result = PlayerResult(index=index, account=account)
    client = WebSocketClient(args.host, args.port, args.path, args.tls, args.connect_timeout)
    try:
        if not login_player(client, args, result):
            return result
        if args.duration <= 0:
            for command in commands:
                run_command(client, command, args, result)
            return result

        deadline = time.monotonic() + args.duration
        command_index = random.randint(0, len(commands) - 1) if commands else 0
        while time.monotonic() < deadline:
            command = commands[command_index % len(commands)]
            command_index += 1
            run_command(client, command, args, result)
            sleep_for = random.uniform(args.think_min, max(args.think_min, args.think_max))
            time.sleep(min(sleep_for, max(0.0, deadline - time.monotonic())))
    except Exception as exc:  # noqa: BLE001 - per-player errors belong in the report.
        result.errors.append(f"exception:{type(exc).__name__}:{exc}")
        if result.connected:
            result.disconnected = True
    finally:
        client.close()
    return result


def fetch_metrics(metrics_url: str) -> Dict[str, float]:
    if not metrics_url:
        return {}
    try:
        with urllib.request.urlopen(metrics_url, timeout=3.0) as response:
            text = response.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return {"_metrics_error": str(exc)}
    return parse_prometheus_metrics(text)


def parse_prometheus_metrics(text: str) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or " " not in line:
            continue
        name, value = line.rsplit(" ", 1)
        try:
            metrics[name] = float(value)
        except ValueError:
            continue
    return metrics


def metric_delta(before: Dict[str, float], after: Dict[str, float], name: str) -> Optional[float]:
    if name not in before or name not in after:
        return None
    return after[name] - before[name]


def percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * pct))
    return ordered[index]


def latency_summary(values: List[float]) -> Dict[str, Optional[float]]:
    return {
        "count": len(values),
        "min": min(values) if values else None,
        "avg": statistics.fmean(values) if values else None,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values) if values else None,
    }


def summarize(
    args: argparse.Namespace,
    results: List[PlayerResult],
    started: float,
    ended: float,
    metrics_before: Dict[str, float],
    metrics_after: Dict[str, float],
) -> Dict[str, Any]:
    latencies = [value for result in results for value in result.latencies_ms]
    command_latencies: Dict[str, List[float]] = defaultdict(list)
    command_timeouts: Dict[str, int] = defaultdict(int)
    errors = []
    for result in results:
        for command, values in result.command_latencies_ms.items():
            command_latencies[command].extend(values)
        for command, count in result.command_timeouts.items():
            command_timeouts[command] += count
        for err in result.errors:
            errors.append({"account": result.account, "error": err})
    elapsed = max(0.001, ended - started)
    commands_sent = sum(result.commands_sent for result in results)
    commands_ok = sum(item.commands_ok for item in results)
    command_failures = sum(item.command_failures for item in results)
    timeouts = sum(item.timeouts for item in results)
    disconnected = sum(1 for item in results if item.disconnected)
    logged_in = sum(1 for item in results if item.logged_in)
    metrics_error = metrics_after.get("_metrics_error") or metrics_before.get("_metrics_error")
    gateway_metrics_delta = {
        "connections_rejected_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_connections_rejected_total"
        ),
        "messages_dropped_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_websocket_messages_dropped_total"
        ),
        "messages_collapsed_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_websocket_messages_collapsed_total"
        ),
        "late_frames_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_websocket_late_frames_total"
        ),
        "closed_session_writes_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_websocket_closed_session_writes_total"
        ),
        "queue_full_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_websocket_queue_full_total"
        ),
        "write_errors_total": metric_delta(
            metrics_before, metrics_after, "xkx_gateway_websocket_write_errors_total"
        ),
    }
    metrics_available = (
        bool(args.metrics_url)
        and metrics_error is None
        and all(value is not None for value in gateway_metrics_delta.values())
    )
    production_error_metric_keys = (
        "connections_rejected_total",
        "messages_dropped_total",
        "queue_full_total",
        "write_errors_total",
    )
    gateway_error_delta_zero = metrics_available and all(
        gateway_metrics_delta.get(name) == 0 for name in production_error_metric_keys
    )
    short_smoke = args.users == 1 and args.scenario == "smoke" and args.duration <= 0
    return {
        "schema": "xkx_gateway_loadtest_report_v1",
        "run_id": args.run_id,
        "mode": args.mode,
        "host": args.host,
        "port": args.port,
        "path": args.path,
        "scenario": args.scenario,
        "duration_seconds": elapsed,
        "duration_requested_seconds": args.duration,
        "users_requested": args.users,
        "users_started": len(results),
        "connected": sum(1 for item in results if item.connected),
        "logged_in": logged_in,
        "created_roles": sum(1 for item in results if item.created_role),
        "disconnected": disconnected,
        "commands_sent": commands_sent,
        "commands_ok": commands_ok,
        "command_failures": command_failures,
        "timeouts": timeouts,
        "commands_per_second": commands_sent / elapsed,
        "latency_ms": latency_summary(latencies),
        "command_latency_ms": {
            command: latency_summary(values)
            for command, values in sorted(command_latencies.items())
        },
        "command_timeouts_by_command": {
            command: count for command, count in sorted(command_timeouts.items())
        },
        "gateway_metrics_delta": gateway_metrics_delta,
        "production_gate_observations": {
            "schema": "multicore_production_gate_evidence_v1",
            "short_smoke_sufficient": False,
            "short_smoke_run": short_smoke,
            "all_users_logged_in": logged_in == args.users,
            "command_failures_zero": command_failures == 0,
            "timeouts_zero": timeouts == 0,
            "disconnects_zero": disconnected == 0,
            "gateway_error_delta_zero": gateway_error_delta_zero,
            "metrics_available": metrics_available,
            "production_matrix_complete": False,
        },
        "metrics_error": metrics_error,
        "sample_errors": errors[: max(0, args.sample_errors)],
        "elapsed_seconds": elapsed,
    }


def should_fail(summary: Dict[str, Any]) -> bool:
    metric_delta_summary = summary["gateway_metrics_delta"]
    return bool(
        summary["logged_in"] < summary["users_requested"]
        or summary["command_failures"] > 0
        or summary["disconnected"] > 0
        or (metric_delta_summary.get("connections_rejected_total") or 0) > 0
        or (metric_delta_summary.get("messages_dropped_total") or 0) > 0
        or (metric_delta_summary.get("queue_full_total") or 0) > 0
        or (metric_delta_summary.get("write_errors_total") or 0) > 0
    )


def main() -> int:
    args = parse_args()
    commands = command_plan(args)
    if args.users < 1:
        raise SystemExit("--users must be >= 1")
    if args.duration < 0:
        raise SystemExit("--duration must be >= 0")

    metrics_before = fetch_metrics(args.metrics_url)
    started = time.perf_counter()
    results: List[PlayerResult] = []
    print_lock = threading.Lock()

    def ramp_delay(index: int) -> float:
        if args.users <= 1 or args.ramp_up <= 0:
            return 0.0
        return args.ramp_up * (index - 1) / max(1, args.users - 1)

    def worker(index: int) -> PlayerResult:
        delay = ramp_delay(index)
        if delay > 0:
            time.sleep(delay)
        result = run_player(index, args, commands)
        with print_lock:
            print(
                f"[player {index:04d}] login={result.logged_in} "
                f"ok={result.commands_ok}/{result.commands_sent} "
                f"timeouts={result.timeouts} errors={len(result.errors)}",
                flush=True,
            )
        return result

    with ThreadPoolExecutor(max_workers=args.users) as executor:
        futures = [executor.submit(worker, index) for index in range(1, args.users + 1)]
        for future in as_completed(futures):
            results.append(future.result())

    ended = time.perf_counter()
    if args.metrics_cooldown > 0:
        time.sleep(args.metrics_cooldown)
    metrics_after = fetch_metrics(args.metrics_url)
    results.sort(key=lambda item: item.index)
    summary = summarize(args, results, started, ended, metrics_before, metrics_after)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))

    if args.report_json:
        with open(args.report_json, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")

    return 1 if args.fail_on_error and should_fail(summary) else 0


if __name__ == "__main__":
    raise SystemExit(main())
