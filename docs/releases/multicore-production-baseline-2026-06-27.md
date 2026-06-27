# FluffOS_XK Multicore Production Baseline - 2026-06-27

## Baseline

- Engine repository: `FengYunCalm/Fluffos_XK`
- Engine branch: `master`
- Engine runtime commit: `4e4811c13eb448a6f1e4ac3d1fcc030e8c22d57d`
- Release tag: `multicore-production-2026-06-27`
- Release tag target: `de550ad90afe74f0a2752804760b790d4e4e9170`
- Paired XiaKeXing main commit: `5b5e433e0ad02c0432246f7a4369694669f1aef0`
- Paired XiaKeXing cloud commit: `87007f089a3d431a1dfd12af54e94fa6b62cc5c7`
- Paired XiaKeXing main tag target: `5041b078e2e08ae2c58bdfd694ac43312bbd2603`

## Driver Runtime

- `driver` SHA-256: `dcad2c53119c8c10add78afdd323f680473bbde5a2363c22d3c70cf47a82269e`
- `lpcc` SHA-256: `304a096d529f47f2f2ec9f1e47b4276834f77fe8ffcc35a7ff61e3ae1858d39f`
- The paired XiaKeXing runtime tree uses driver binaries produced from this engine baseline.

## Runtime Contract

This baseline follows the production-perfect contract recorded in
`docs/multicore-runtime-v2.md`.

- Owner task domains are explicitly registered and aligned with the mudlib runtime.
- Target-owner messages use executor-safe ObjectHandle routing.
- Normal production paths keep `normal_path_main_fallback_count=0`.
- Hot-path service-owner single points are represented by keyed service shards.
- Ordinary legacy LPC background execution remains default-closed.
- Main-thread work is limited to IO adapters, cleanup adapters, explicit fallback,
  and documented compatibility surfaces.

## Verification Entry Points

Engine verification entry points for this baseline:

- `git diff --check`
- `cmake --build build --target lpc_tests -j2`
- `build/src/tests/lpc_tests`
- `cmake --build build --target driver -j2`
- `cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract`

Paired XiaKeXing verification entry points:

- `tools/public-beta-smoke-ubuntu.sh --cloud --skip-contracts`
- `tools/cloud-health-check-ubuntu.sh --ssh --smoke --json docs/reports/cloud-health-2026-06-27.json`
- `python -m unittest tools.ai-player.tests.test_cloud_deploy_contract`
- `python -m unittest tools.ai-player.tests.test_cloud_health_check_contract`

## Acceptance

This tag marks the engine side of the dual-repository multicore production
baseline. The paired XiaKeXing tags record the source and cloud runtime commits
that were deployed and smoke-verified against this driver runtime.
