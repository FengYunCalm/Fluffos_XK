# FluffOS_XK Engine Overview

FluffOS_XK is a production-oriented FluffOS maintenance fork for modern
LPC/MUD projects. It is meant to be consumed as an engine repository: game
mudlibs, world data, accounts, deployment secrets, and operational policy stay
in downstream game repositories.

## Positioning

FluffOS_XK keeps the classic FluffOS driver model and focuses on practical
runtime engineering:

- predictable CMake builds on current Linux, WSL, and Windows/MSYS2 toolchains;
- gateway/session behavior needed by WebSocket-facing clients;
- owner/service multicore execution for production mudlib migration;
- source hygiene and documentation that make the fork easy to audit.

The upstream FluffOS project remains the canonical base. FluffOS_XK is a
downstream-friendly engine line for projects that need a stable integration
target and a production multicore baseline.

## Production Multicore Baseline

The current multicore model is controlled, explicit, and compatibility-minded.
It does not make arbitrary legacy LPC run freely on background threads.

The sealed production path covers:

- owner-local object lifecycle;
- OwnerExecutor callback tasks;
- heartbeat and callout execution;
- async/file/db, DNS, and socket callbacks;
- gateway command execution;
- target-owner messages;
- `socket_release` owner-safe release/acquire handshake.

Executor entry requires an explicit owner-safe path: same-owner execution,
allowlist coverage, driver callback task, frozen payload, ObjectHandle route,
owner future, or service shard domain.

## Integration Model

Downstream projects should use FluffOS_XK as the engine layer and keep gameplay
state elsewhere.

Recommended integration model:

1. Pin a FluffOS_XK commit or release tag.
2. Build `driver`, `lpcc`, and `lpc_tests`.
3. Run engine tests.
4. Copy built binaries into the downstream runtime tree.
5. Run downstream smoke and audit checks against login, gateway commands,
   movement, persistence, reconnect, heartbeat, callout, and callback paths.

This keeps engine upgrades reviewable and prevents game-specific runtime assets
from being mixed into the engine repository.

## Safety Boundaries

FluffOS_XK is intentionally conservative:

- ordinary legacy LPC background execution remains default-closed;
- mutable cross-owner state must use snapshot, message, future, commit, or
  shard-domain contracts;
- main-thread work is limited to IO adapters, cleanup adapters, explicit
  fallback, and documented compatibility surfaces;
- production status is represented by machine-readable runtime contracts rather
  than informal claims.

These boundaries are part of the production design, not deferred work.

## When To Use It

Use FluffOS_XK when you need:

- a modern FluffOS-compatible LPC runtime;
- a source-level engine baseline that can be audited and rebuilt;
- a safe migration path from single-threaded global mudlib services toward
  owner/service execution;
- a driver suitable for gateway-backed web or mobile clients;
- clear separation between engine code and private game operations.

Do not use this repository as a place to store a complete mudlib, accounts,
private deployment scripts, or project-specific secrets.

## Key References

- [README](../README.md)
- [Multicore Runtime v2](./multicore-runtime-v2.md)
- [Multicore Production Gate](./multicore-production-gate.md)
- [Owner Multicore API](./owner-multicore-api.md)
- [Production Baseline Release Note](./releases/multicore-production-baseline-2026-06-27.md)
