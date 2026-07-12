# LPC Modern Runtime / LPC 现代运行时

## Purpose / 目标

FluffOS_XK keeps LPC as the primary mudlib language. The modern runtime adds
opt-in contracts above legacy LPC: stricter owner audits, owner-safe payload
APIs, source/session encoding boundaries, VM hot-path diagnostics, and
benchmark/stress entry points. Legacy LPC remains compatible by default.

FluffOS_XK 继续把 LPC 作为 mudlib 主语言。现代运行时是在 legacy LPC 之上增加按需启用的合同：
更严格的 owner 审计、owner-safe payload API、源码/会话编码边界、VM 热路径诊断以及
benchmark/stress 入口。旧 LPC 默认保持兼容。

## Opt-In Profiles / 按需启用的 Profile

Modern behavior is enabled by pragmas:

```c
#pragma modern_lpc
#pragma strict_owner
```

`modern_lpc` enables modern diagnostics and owner-safe APIs. `strict_owner`
enables stronger audit rules for new code: cross-owner mutable writes, bare
object payloads, unfrozen callback payloads, and direct hot-path `save_object`
calls are reported by the compiler audit path.

现代行为通过 pragma 启用：

```c
#pragma modern_lpc
#pragma strict_owner
```

`modern_lpc` 启用现代诊断和 owner-safe API。`strict_owner` 为新代码启用更严格的审计规则：
cross-owner mutable write、裸 object payload、未冻结 callback payload 和热路径直接
`save_object` 会被编译器审计路径报告。

Ordinary legacy LPC remains default-closed for arbitrary background execution.
That is a compatibility and safety boundary, not an unfinished feature.

普通 legacy LPC 仍默认不开放任意后台执行。这是兼容性和安全边界，不是未完成项。

## Owner-Safe APIs / Owner-Safe API

Stable LPC-facing APIs:

| API | Contract |
|---|---|
| `freeze(value)` | Validate and deep-copy values that can cross owner boundaries. |
| `snapshot(value)` | Create frozen value snapshots or ObjectHandle-backed object snapshots. |
| `owner_async(target, mapping payload)` | Submit owner-safe work and return a future mapping. |
| `owner_await(int future_id)` | Poll owner future state; coroutine suspension is not enabled for legacy LPC. |
| `owner_commit(mapping proposal)` | Enter the owner/service commit boundary. |
| `owner_snapshot_persist(object target, mapping options)` | Serialize a same-owner object snapshot without direct hot-path file writes. |

面向 LPC 的稳定 API：

| API | 合同 |
|---|---|
| `freeze(value)` | 校验并深拷贝可跨 owner 边界传递的值。 |
| `snapshot(value)` | 生成 frozen value snapshot 或带 ObjectHandle 的 object snapshot。 |
| `owner_async(target, mapping payload)` | 投递 owner-safe 工作并返回 future mapping。 |
| `owner_await(int future_id)` | 查询 owner future 状态；legacy LPC 默认不启用 coroutine suspension。 |
| `owner_commit(mapping proposal)` | 进入 owner/service commit 边界。 |
| `owner_snapshot_persist(object target, mapping options)` | 序列化 same-owner object snapshot，避免热路径直接文件写入。 |

Failures return machine-readable fields such as `success`, `ok`, `code`,
`error`, `reason`, `api`, and `trace_id` when available.

失败结果会返回机器可判定字段，例如 `success`、`ok`、`code`、`error`、`reason`、`api`
以及可用时的 `trace_id`。

## Minimal Example / 最小示例

```c
#pragma modern_lpc
#pragma strict_owner

mapping submit_reward_commit(string player_id, mapping reward) {
    mapping frozen = freeze(([
        "player_id": player_id,
        "reward": reward,
    ]));

    if (!frozen["ok"]) {
        return frozen;
    }

    return owner_async("service/reward/" + player_id, ([
        "type": "owner_task_reward",
        "payload_key": "reward/commit/v1",
        "payload": frozen["value"],
    ]));
}
```

This example freezes mutable data before it crosses an owner boundary and routes
the work through a keyed service shard.

这个示例在数据跨 owner 边界之前先冻结可变数据，然后通过 keyed service shard 路由任务。

## Value Objects And ObjectHandle / Value Object 与 ObjectHandle

Frozen mapping/array snapshots use
`value_object_model=frozen_snapshot_value_object_v1`. They are payload values,
not live LPC objects, and do not join the traditional destruct chain.

Live object references use ObjectHandle capability metadata:

- owner id;
- owner epoch;
- object id;
- object path;
- permission intent;
- snapshot version.

Same-owner handle resolve uses the owner-local object store fast path. The
runtime contract requires `object_store_global_fallback_on_owner_fast_path=0`.

Frozen mapping/array snapshot 使用
`value_object_model=frozen_snapshot_value_object_v1`。它们是 payload value，不是
live LPC object，也不进入传统 destruct 链。

live object 引用使用 ObjectHandle capability 元数据：

- owner id；
- owner epoch；
- object id；
- object path；
- permission intent；
- snapshot version。

same-owner handle resolve 走 owner-local object store fast path。运行时合同要求
`object_store_global_fallback_on_owner_fast_path=0`。

## Encoding Boundaries / 编码边界

The VM keeps canonical strings as UTF-8. Other encodings are supported at
explicit boundaries:

- source encoding: `#pragma source_encoding("GBK")`;
- session encoding: `set_encoding("GBK")`, `query_encoding()`;
- data encoding: `string_encode`, `string_decode`, `buffer_transcode`;
- gateway/session payloads: convert to UTF-8 before VM execution and convert
  back according to session encoding on output.

Supported names depend on ICU. GBK, GB2312, Big5, and UTF-8 are covered by the
modern runtime tests.

VM 内部规范字符串保持 UTF-8。其他编码通过明确边界支持：

- 源码编码：`#pragma source_encoding("GBK")`；
- 会话编码：`set_encoding("GBK")`、`query_encoding()`；
- 数据编码：`string_encode`、`string_decode`、`buffer_transcode`；
- gateway/session payload：进入 VM 前转为 UTF-8，输出时按 session encoding 转回。

可用编码名称取决于 ICU。GBK、GB2312、Big5 和 UTF-8 已由现代运行时测试覆盖。

## Static Audit / 静态审计

Audit modern LPC migration work with `lpcc`:

```bash
build/bin/lpcc --owner-audit --format=json etc/config.test path/to/file.c
```

The JSON report uses `schema=lpcc_owner_audit_v1` and includes profile pragmas,
source encoding, transcode status, invalid sequence count, rule code, severity,
line number, and suggestion.

使用 `lpcc` 审计现代 LPC 迁移：

```bash
build/bin/lpcc --owner-audit --format=json etc/config.test path/to/file.c
```

JSON 报告使用 `schema=lpcc_owner_audit_v1`，包含 profile pragma、source encoding、
transcode status、invalid sequence count、rule code、severity、line number 和 suggestion。

## Diagnostics / 诊断

The runtime exposes hot-path counters through `lpc_vm_profile_v1` and
`lpc_vm_bench_v1`:

`lpc_vm_profile` recording is disabled by default and is explicitly enabled
only for the current VM thread by diagnostics. Owner audit/enforcement remains
active independently of this profiler gate.

- opcode dispatch;
- efun dispatch;
- `call_other` dispatch;
- function pointer dispatch;
- parser/add_action lookup;
- mapping lookup/insert;
- string push;
- apply dispatch cache hit/miss/invalidation.

运行时通过 `lpc_vm_profile_v1` 和 `lpc_vm_bench_v1` 暴露热路径计数：

`lpc_vm_profile` 默认不持续记录，仅由诊断流程对当前 VM 线程显式开启；owner
audit/enforcement 与该 profiler 开关相互独立，保持生效。

- opcode dispatch；
- efun dispatch；
- `call_other` dispatch；
- function pointer dispatch；
- parser/add_action lookup；
- mapping lookup/insert；
- string push；
- apply dispatch cache hit/miss/invalidation。

Run benchmark reports:

```bash
cmake --build build --target lpc_vm_bench object_store_bench owner_runtime_bench -j2
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
```

运行 benchmark 报告：

```bash
cmake --build build --target lpc_vm_bench object_store_bench owner_runtime_bench -j2
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
```

Integrated smoke gate:

```bash
tools/lpc-modern-runtime-stress.sh smoke
```

集成 smoke 门禁：

```bash
tools/lpc-modern-runtime-stress.sh smoke
```
