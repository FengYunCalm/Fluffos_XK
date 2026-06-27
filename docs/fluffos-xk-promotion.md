# FluffOS_XK: A Production-Ready Multicore LPC/MUD Engine

FluffOS_XK is a production-oriented FluffOS engine fork for modern LPC/MUD
projects. It keeps the classic FluffOS driver model, while adding a sealed
owner/service multicore runtime baseline, gateway-ready execution paths, and a
clean separation between engine code and game mudlib code.

It is built for teams that want to keep the LPC ecosystem, keep compatibility
with proven MUD architecture, and still move real game workloads toward safer
parallel execution.

## The Problem It Solves

Classic LPC/MUD drivers are stable and expressive, but real production games
often hit the same engineering limits:

- too much mutable state is concentrated on one global execution path;
- player commands, heartbeat, callout, socket, and async callbacks are hard to
  reason about once concurrency is introduced;
- game repositories often mix driver binaries, mudlib content, deployment
  details, and operational state;
- "just run LPC on another thread" is unsafe without ownership, payload, and
  cleanup contracts.

FluffOS_XK addresses these problems without throwing away the FluffOS model.

## What Makes FluffOS_XK Different

### Production Multicore Baseline

FluffOS_XK provides a controlled owner/service executor runtime. The production
path covers:

- owner-local object lifecycle;
- OwnerExecutor callback tasks;
- heartbeat and callout execution;
- async/file/db, DNS, and socket callbacks;
- gateway command execution;
- target-owner messages;
- `socket_release` owner-safe release/acquire handshake.

This is not a lab-only experiment or an unrestricted background LPC switch. It
is a production contract for owner-safe execution.

### Safety First

Ordinary legacy LPC remains default-closed for arbitrary background execution.
Executor entry requires a real safety boundary:

- same-owner execution;
- explicit allowlist coverage;
- driver callback contract;
- frozen or deep-copied payload;
- ObjectHandle routing;
- owner future or service shard domain.

That means existing mudlibs can migrate deliberately instead of being forced
into unsafe global parallelism.

### Designed For Real Game Repositories

FluffOS_XK is an engine repository. It does not try to become your game server
repository.

Downstream projects keep their own:

- mudlib and world content;
- accounts and player data;
- deployment scripts and secrets;
- cloud operations reports;
- product-specific gateway policy.

The engine stays rebuildable, auditable, and easy to upgrade.

## Why It Matters For MUD Projects

FluffOS_XK gives classic LPC projects a practical path forward:

- keep proven LPC gameplay code;
- use modern gateway clients, including WebSocket-facing clients;
- move hot mutable state toward owner/service shards;
- classify stale owner, destructed object, epoch mismatch, payload, and cleanup
  failures instead of hiding them;
- preserve compatibility while adding measurable runtime boundaries.

The result is a driver that can support larger, more service-oriented MUD
systems without pretending that concurrency is free.

## Best Fit

FluffOS_XK is a good fit when a project needs:

- a FluffOS-compatible LPC runtime that can be rebuilt from source;
- a production multicore baseline with explicit safety contracts;
- clean separation between engine work and gameplay work;
- gateway/session integration for web or mobile clients;
- a maintenance fork that is public, reviewable, and downstream-friendly.

It is not intended for projects that want to bundle a complete mudlib inside the
engine repository, bypass ownership contracts, or execute arbitrary legacy LPC
on background threads without a defined owner boundary.

## Integration Path

A downstream project can adopt FluffOS_XK incrementally:

1. Pin a known FluffOS_XK commit or release tag.
2. Build `driver`, `lpcc`, and `lpc_tests`.
3. Run engine tests.
4. Copy the built binaries into the downstream runtime tree.
5. Run game-level smoke tests for login, gateway, commands, movement,
   persistence, heartbeat, callout, and reconnect behavior.
6. Migrate cross-owner game logic through snapshots, messages, futures, commit
   proposals, or service shard domains.

## Current Status

The current FluffOS_XK production baseline is complete and documented. The
multicore model is sealed around owner/service execution, not arbitrary LPC
parallelism.

Primary technical references:

- [Multicore Runtime v2](./multicore-runtime-v2.md)
- [Multicore Production Gate](./multicore-production-gate.md)
- [Owner Multicore API](./owner-multicore-api.md)
- [Production Baseline Release Note](./releases/multicore-production-baseline-2026-06-27.md)
- [Engine Overview](./fluffos-xk-overview.md)

## One-Sentence Pitch

FluffOS_XK brings a production-ready owner/service multicore runtime to the
classic FluffOS LPC driver, giving real MUD projects a safe path from
single-threaded global state toward auditable parallel execution.
