# FluffOS_XK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMake](https://img.shields.io/badge/build-CMake-blue.svg)](CMakeLists.txt)
[![LPC Runtime](https://img.shields.io/badge/runtime-LPC%20%2F%20MUD-informational.svg)](https://www.fluffos.info)

English | [简体中文](README_CN.md)

FluffOS_XK is a public maintenance fork of [FluffOS](https://github.com/fluffos/fluffos) for modern LPC/MUD
runtime projects. It keeps the classic FluffOS driver model while improving build reliability, gateway integration,
runtime ownership hygiene, and downstream engine maintenance.

This fork is intended for projects that need a practical, source-level FluffOS base rather than a separate game server
or a rewrite of the LPC ecosystem.

## Highlights

- **Downstream-friendly engine fork**: keeps engine work separate from game mudlibs, so projects can consume driver
  updates without mixing gameplay content into the engine repository.
- **Owner-runtime groundwork**: includes runtime ownership and VM worker infrastructure work used by downstream
  actor-style service migration, while keeping unsafe arbitrary off-main LPC execution out of scope.
- **Gateway-oriented runtime path**: maintains gateway/session integration needed by modern WebSocket clients and
  service-managed deployments.
- **Reliable Linux and Windows builds**: improves CMake and Windows/MSYS2 install behavior, including safer binary
  replacement during `cmake --install`.
- **Compiler and dependency hygiene**: applies targeted warning cleanup in core modules and controls noisy third-party
  warnings in vendored dependencies.
- **Open-source housekeeping**: provides clear license files, contribution guidance, security policy, changelog, and
  a narrow fork scope for easier external review.

## Why This Fork Exists

The upstream FluffOS project remains the canonical source for the driver. FluffOS_XK exists to keep a production-facing
maintenance line for projects that need:

- predictable builds on current Linux and Windows toolchains;
- a stable place for owner-runtime and VM worker experiments that are validated by downstream usage;
- gateway integration work for web and mobile clients;
- a public repository that can be audited, cloned, and integrated without private project artifacts.

## Runtime Focus

FluffOS_XK focuses on engine-level foundations, not gameplay rules.

- **Owner-bound execution**: ownership checks and runtime contracts support gradual migration from global mutable
  services toward safer owner/actor-style execution boundaries.
- **VM worker infrastructure**: worker/context cleanup lays the groundwork for controlled off-main execution paths.
- **Gateway sessions**: gateway session lifecycle and logon behavior are kept testable for WebSocket-facing clients.
- **Operational separation**: game repositories can pin or rebuild this driver without inheriting engine development
  branches, private docs, or deployment data.

## Multicore Runtime Status

### Owner/Actor Shard VM (✅ Production Ready)

FluffOS_XK now supports **owner-based object isolation** for true multicore execution. Each player becomes an independent 
"owner" with their own object shard, enabling parallel execution without synchronization overhead.

**Key Features:**
- **Owner-based isolation**: Every object has an owner ID (`"player/<account>"` or `"legacy/main"`)
- **Enforced mode**: Complete cross-owner access blocking with safe read-only API
- **Zero-copy snapshots**: Query object structure without cross-owner calls
- **Multicore execution**: Independent owners run in parallel on separate CPU cores

**Validated in Production:**
- ✅ 10 concurrent users × 300 seconds stress test: 100% success rate
- ✅ Zero cross-owner errors in enforced mode
- ✅ Stable performance: 3.08 cmd/s, 202ms avg latency

**Safe Cross-Owner Access API:**
```lpc
// Get object snapshot without cross-owner call
mapping snapshot = owner_query_object_snapshot(target);
if (mapp(snapshot)) {
    // Cross-owner - use snapshot data
    if (snapshot["living"]) { ... }
} else {
    // Same owner - direct access
    if (living(target)) { ... }
}
```

**Configuration:**
```c
// In driver config
multicore mode : 0    // Disabled
multicore mode : 1    // Owner-based (default)
multicore mode : 2    // Enforced isolation (recommended for production)
```

See [`docs/owner-multicore-api.md`](docs/owner-multicore-api.md) for complete API documentation and migration guide.

### Worker Infrastructure

The driver includes thread-local VMContext binding, owner-aware worker runtime, owner mailboxes, and task tracing 
infrastructure for controlled off-main execution.

See `docs/multicore-runtime.md` for worker infrastructure details.

## Get The Code

```bash
git clone https://github.com/FengYunCalm/Fluffos_XK.git
cd Fluffos_XK
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
```

For install-oriented environments:

```bash
cmake --build build --target install
```

Windows/MSYS2 users should prefer the CMake install path instead of manually copying generated binaries.

## For Downstream MUD Projects

Use this repository as an engine source tree or as the source for rebuilt `driver` and `lpcc` binaries. Keep your mudlib,
world content, service configuration, accounts, and deployment data in your own project repository.

Recommended downstream flow:

1. Rebuild `driver` and `lpcc` from a known FluffOS_XK commit.
2. Run upstream engine tests such as `lpc_tests`.
3. Copy the resulting binaries into the downstream runtime tree.
4. Run project-level smoke tests against login, gateway, commands, content loading, and persistence.

## Project Scope

In scope:

- build reliability and CMake/install fixes;
- runtime ownership, VM worker, and gateway integration maintenance;
- focused compiler warning cleanup;
- source hygiene that makes the fork easier to audit and consume.

Out of scope:

- bundling a complete game mudlib;
- replacing upstream FluffOS as the canonical project;
- opening arbitrary LPC execution on background threads without explicit ownership contracts;
- adding private deployment scripts, secrets, account data, or game-specific content.

## Documentation

- Official FluffOS docs: https://www.fluffos.info
- Multicore runtime status: `docs/multicore-runtime.md`
- Local docs entry: `docs/index.md`
- Fork changelog: `CHANGELOG.md`
- Release notes and workflow notes: `RELEASE.md`

## Contributing

Focused contributions are welcome. Good candidates include build fixes, warning cleanup, test coverage, documentation,
and narrowly scoped runtime maintenance that fits this fork's role. See `CONTRIBUTING.md` before opening a pull request.

Security issues should be reported responsibly. See `SECURITY.md`.

## License & Attribution

- MIT License: see `LICENSE`.
- Historical LPmud/MudOS notices still apply to legacy components: see `Copyright`.
- Third-party licenses: see `NOTICE` and `src/thirdparty/*`.

## Upstream

- Upstream project: https://github.com/fluffos/fluffos
- Official docs: https://www.fluffos.info
