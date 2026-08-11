#!/usr/bin/env python3
"""Run one command with timeout semantics on platforms without GNU timeout."""

import os
import signal
import subprocess
import sys


TIMEOUT_EXIT_CODE = 124
TERMINATE_GRACE_SECONDS = 5.0


def signal_process_tree(process: subprocess.Popen, sig: int) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        elif sig == signal.SIGKILL:
            process.kill()
        else:
            process.terminate()
    except ProcessLookupError:
        pass


def stop_process_tree(process: subprocess.Popen, sig: int = signal.SIGTERM) -> None:
    signal_process_tree(process, sig)
    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        signal_process_tree(process, signal.SIGKILL)
        process.wait()


def normalize_returncode(returncode: int) -> int:
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(f"usage: {argv[0]} SECONDS [--] COMMAND [ARG ...]", file=sys.stderr)
        return 2

    try:
        timeout_seconds = float(argv[1])
    except ValueError:
        print(f"error: invalid timeout: {argv[1]}", file=sys.stderr)
        return 2
    if timeout_seconds <= 0:
        print("error: timeout must be greater than zero", file=sys.stderr)
        return 2

    command = argv[2:]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("error: command is required", file=sys.stderr)
        return 2

    popen_kwargs = {}
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True
    elif os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except FileNotFoundError:
        print(f"error: command not found: {command[0]}", file=sys.stderr)
        return 127
    except PermissionError:
        print(f"error: command is not executable: {command[0]}", file=sys.stderr)
        return 126

    def forward_signal(signum: int, _frame) -> None:
        stop_process_tree(process, signum)
        raise SystemExit(128 + signum)

    forwarded_signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        forwarded_signals.append(signal.SIGHUP)
    for forwarded_signal in forwarded_signals:
        signal.signal(forwarded_signal, forward_signal)

    try:
        return normalize_returncode(process.wait(timeout=timeout_seconds))
    except subprocess.TimeoutExpired:
        stop_process_tree(process)
        return TIMEOUT_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main(sys.argv))
