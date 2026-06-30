# LPC Modern Runtime

FluffOS_XK keeps LPC as the primary mudlib language. The modern runtime adds
opt-in contracts on top of legacy LPC instead of changing old mudlibs by
default.

## Opt-In Profiles

Modern behavior is enabled by pragmas:

```c
#pragma modern_lpc
#pragma strict_owner
```

`modern_lpc` enables modern diagnostics and owner-safe APIs. `strict_owner`
enables stronger owner audit rules for new code: cross-owner mutable writes,
bare object payloads, unfrozen callback payloads, and direct hot-path
`save_object` calls are reported by the compiler audit path.

Legacy LPC remains compatible and default-closed for arbitrary background
execution.

## Owner-Safe APIs

The stable LPC-facing APIs are:

- `freeze(value)`: validate and deep-copy frozen-safe values.
- `snapshot(value)`: create frozen snapshots or ObjectHandle-backed object
  snapshots.
- `owner_async(target, mapping payload)`: submit owner-safe async work and return
  a future mapping.
- `owner_await(int future_id)`: poll owner future state until coroutine runtime
  support is enabled.
- `owner_commit(mapping proposal)`: enter the owner/service commit boundary.
- `owner_snapshot_persist(object target, mapping options)`: serialize a
  same-owner object snapshot without direct hot-path file writes.

Failures return machine-readable fields: `success`, `ok`, `code`, `error`,
`reason`, `api`, and `trace_id` when available.

## Value Objects And ObjectHandle

Frozen mapping/array snapshots are reported as
`value_object_model=frozen_snapshot_value_object_v1`. They are payload values,
not live LPC objects, and do not join the traditional destruct chain.

Live object references use `ObjectHandle` capability metadata:

- owner id
- owner epoch
- object id
- object path
- permission intent
- snapshot version

Same-owner handle resolve uses the owner-local object store fast path. The
runtime contract requires `object_store_global_fallback_on_owner_fast_path=0`.

## Encoding Boundaries

The VM keeps internal canonical strings as UTF-8. Other encodings are supported
at boundaries:

- session encoding: `set_encoding("GBK")`, `query_encoding()`
- data encoding: `string_encode`, `string_decode`, `buffer_transcode`
- source encoding: `#pragma source_encoding("GBK")`
- gateway/session payloads: converted to UTF-8 before VM execution and converted
  back according to the session encoding on output

Supported names depend on ICU. GBK, GB2312, Big5, and UTF-8 are covered by the
modern runtime tests.

## Static Audit

Use `lpcc` to audit modern LPC migration work:

```bash
build/bin/lpcc --owner-audit --format=json etc/config.test path/to/file.c
```

The JSON report uses `schema=lpcc_owner_audit_v1` and includes profile pragmas,
source encoding, transcode status, invalid sequence count, rule code, severity,
line number, and suggestion.

## Runtime Diagnostics

The runtime exposes hot-path counters through `lpc_vm_profile_v1` and
`lpc_vm_bench_v1`:

- opcode dispatch
- efun dispatch
- call_other dispatch
- function pointer dispatch
- parser/add_action lookup
- mapping lookup/insert
- string push
- apply dispatch cache hit/miss/invalidation

Run:

```bash
cmake --build build --target lpc_vm_bench object_store_bench owner_runtime_bench -j2
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
```

The integrated smoke gate is:

```bash
tools/lpc-modern-runtime-stress.sh smoke
```

It validates owner runtime contracts, LPC modern profile tests, benchmark JSON
schemas, owner-local object resolve, dispatch profiling counters, and the LPC
`owner_executor_contract`.
