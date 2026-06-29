# FluffOS_XK Multicore Runtime

This page is the stable entry point for FluffOS_XK multicore runtime documentation.
The historical v1 runtime note has been archived at
[`docs/archive/multicore/multicore-runtime-v1-2026-06.md`](archive/multicore/multicore-runtime-v1-2026-06.md).

## Current Status

FluffOS_XK multicore runtime work is production-baseline complete for the current
owner/service executor model. The current contract is not arbitrary background
execution for every legacy LPC method. Ordinary legacy LPC remains default-closed;
only explicit allowlist paths, same-owner execution, driver callback tasks,
frozen payloads, ObjectHandle routing, and owner/service shard contracts may enter
the owner executor.

The current production facts are recorded in these documents:

- [`multicore-runtime-v2.md`](multicore-runtime-v2.md): owner runtime v2 and production-perfect contract.
- [`multicore-production-gate.md`](multicore-production-gate.md): production gate fields, evidence model, and accepted pressure scope.
- [`owner-multicore-api.md`](owner-multicore-api.md): owner/snapshot API guide for downstream mudlibs.
- [`releases/multicore-production-baseline-2026-06-27.md`](releases/multicore-production-baseline-2026-06-27.md): dual-repository production baseline and driver checksum.

## Historical Plans

Older multicore plans and v1 notes are retained for audit history under
[`docs/archive/multicore/`](archive/multicore/README.md). They are not current execution
plans and must not be used to infer unfinished production work.
