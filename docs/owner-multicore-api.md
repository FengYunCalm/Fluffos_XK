# Owner/Actor Shard VM Multicore API Guide

## Overview

FluffOS_XK supports owner-based object boundaries for controlled multicore migration. Each player-owned object can be assigned to an independent owner shard, while legacy system objects remain under the default owner. The current model does not make arbitrary LPC execution freely parallel; it provides guarded owner queues, deterministic worker tasks, and explicit snapshot/message contracts.

## Core Concepts

### Owner ID
- Every object has an associated owner ID
- Default owner: `"legacy/main"` (for system objects, daemons, rooms)
- Player owner: `"player/<account>"` (e.g., `"player/alice"`)
- Objects created by players automatically inherit player's owner ID

### Cross-Owner Access Rules
- **Same owner**: Direct access allowed (fast path)
- **Default owner target**: Always accessible from any owner
- **Cross-owner synchronous calls/writes**: Blocked in enforced mode unless they use an explicit owner contract
- **Cross-owner structure inspection**: Use `owner_query_object_snapshot()` for data that can be read without executing target LPC code

### Multicore Modes
```c
// In driver config
multicore mode : 0    // Disabled
multicore mode : 1    // Owner-based (default)
multicore mode : 2    // Enforced isolation
```

## Modern Owner-Safe LPC APIs

LPC Modern Runtime adds opt-in APIs for mudlibs that want explicit owner
boundaries without replacing LPC. Use them with `#pragma modern_lpc`; use
`#pragma strict_owner` when new code should fail audit for unsafe owner
patterns.

### `freeze(value)`

Validates and deep-copies values that are safe to pass through owner messages,
callbacks, futures, and service shard tasks. Frozen payloads may contain
numbers, reals, strings, arrays, and mappings. Live mutable objects and VM-bound
values are rejected.

Successful results include:

- `success=1`
- `ok=1`
- `api="freeze"`
- `value`: the validated deep-copy payload
- `value_object_profile_ready=1`
- `value_object_model="frozen_snapshot_value_object_v1"`
- `cross_owner_payload_safe=1`

### `snapshot(value)`

Creates a frozen value snapshot for mappings and arrays, or an ObjectHandle
capability snapshot for live objects. Value snapshots are payload values, not
live LPC objects, and do not join the traditional destruct chain.

Object snapshots include owner id, epoch, object id, object path, permission
intent, and snapshot version so stale/destructed/epoch mismatch cases can be
classified before execution.

### `owner_async(target, mapping payload)`

Submits owner-safe work to an owner executor and returns a future-oriented
mapping. `target` may be an owner id string or an object. Object targets require
ObjectHandle routing and a `payload["method"]` entry. Payloads must be frozen or
freeze-compatible.

Typical failure mappings include:

- `success=0`
- `ok=0`
- `code`
- `error`
- `reason`
- `api="owner_async"`
- `trace_id` when a trace was created

### `owner_await(int future_id)`

Returns the current future state through the owner future contract. It is a
modern-profile API boundary; coroutine suspension is not enabled for legacy LPC
by default.

### `owner_commit(mapping proposal)`

Submits a proposal to the owner/service commit boundary. Use it for cross-owner
writes that should not mutate another owner directly. Proposals should include a
stable key, target owner or service shard, domain, frozen payload, and idempotent
commit identity.

### `owner_snapshot_persist(object target, mapping options)`

Serializes a same-owner object snapshot for persistence. The owner/service
executor owns consistency; the main/file side remains an adapter for I/O. In
strict owner migrations, direct hot-path `save_object` calls should be audited
and replaced with snapshot persistence where appropriate.

### Minimal Modern Example

```lpc
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

## Cross-Owner Snapshot API

Get read-only structural information about cross-owner objects.

#### C++ API
```cpp
#include "vm/owner.h"

mapping *vm_owner_query_object_snapshot(object_t *target, const char *requesting_owner_id);
```

**Returns:**
- `nullptr` - Same owner or default owner target (direct access safe)
- `mapping *` - Cross-owner object snapshot with keys:
  - `"object_name"` (string): Object file path
  - `"owner_id"` (string): Target's owner ID
  - `"living"` (int): Whether object is living (1/0)
  - `"has_is_character"` (int): Has is_character() method
  - `"has_is_npc"` (int): Has is_npc() method
  - `"has_is_player"` (int): Has is_player() method

#### LPC API
```lpc
mapping owner_query_object_snapshot(object target);
```

**Usage Example:**
```lpc
object find_living_in_room(object env, string name) {
    object *obs = all_inventory(env);
    
    foreach(object ob in obs) {
        mapping snapshot = owner_query_object_snapshot(ob);
        
        if (mapp(snapshot)) {
            // Cross-owner object - use snapshot
            if (!snapshot["living"] && !snapshot["has_is_character"])
                continue;
                
            // Try to get name with error catching
            catch {
                string ob_name = ob->query_name();
                if (ob_name == name)
                    return ob;
            };
        } else {
            // Same owner - direct access
            if (!living(ob))
                continue;
                
            if (ob->query_name() == name)
                return ob;
        }
    }
    
    return 0;
}
```

### 2. Error Suppression Pattern

For cross-owner queries that may fail, use LPC `catch` to suppress errors:

```lpc
// Check if NPC should be visible
int should_include_npc(object npc) {
    if (!objectp(npc))
        return 0;
    
    // Use catch for cross-owner queries
    catch {
        if (npc->query_temp("is_dying"))
            return 0;
            
        int hp = npc->query("combat/hp");
        int max_hp = npc->query("combat/max_hp");
        if (intp(max_hp) && max_hp > 0 && intp(hp) && hp <= 0)
            return 0;
    };
    
    return 1;
}
```

## Best Practices

### 1. Check Snapshot First
Always check if snapshot API returns mapping before attempting cross-owner access:

```lpc
mapping snapshot = owner_query_object_snapshot(target);
if (mapp(snapshot)) {
    // Cross-owner - use snapshot + catch
} else {
    // Same owner - direct access
}
```

### 2. Handle Type Variations
Cross-owner queries may return different types than expected:

```lpc
catch {
    mixed id = ob->query_id();  // May return string or array
    if (stringp(id) && id == name)
        return ob;
};
```

### 3. Minimize Cross-Owner Calls
- Cache snapshot data when possible
- Use structural information (living flag, method existence) before querying
- Batch queries when feasible

### 4. Error Recovery
Always provide fallback behavior when cross-owner queries fail:

```lpc
string get_display_name(object ob) {
    mapping snapshot = owner_query_object_snapshot(ob);
    if (mapp(snapshot)) {
        string name;
        catch {
            name = ob->query_name();
        };
        return stringp(name) ? name : snapshot["object_name"];
    }
    return ob->query_name();
}
```

## Common Patterns

### Pattern 1: Room Visibility Check
```lpc
private int is_visible_character(object ob) {
    mapping snapshot = owner_query_object_snapshot(ob);
    if (mapp(snapshot)) {
        return snapshot["living"] 
            || snapshot["has_is_character"]
            || snapshot["has_is_npc"]
            || snapshot["has_is_player"];
    }
    
    return living(ob)
        || (function_exists("is_character", ob) && ob->is_character())
        || (function_exists("is_npc", ob) && ob->is_npc())
        || (function_exists("is_player", ob) && ob->is_player());
}
```

### Pattern 2: Safe Property Query
```lpc
private mixed safe_query(object ob, string property, mixed default_value) {
    mapping snapshot = owner_query_object_snapshot(ob);
    if (mapp(snapshot)) {
        mixed result;
        catch {
            result = ob->query(property);
        };
        return result ? result : default_value;
    }
    return ob->query(property);
}
```

### Pattern 3: Filter Cross-Owner List
```lpc
object *filter_living_objects(object *obs) {
    object *result = ({});
    
    foreach(object ob in obs) {
        mapping snapshot = owner_query_object_snapshot(ob);
        if (mapp(snapshot)) {
            if (snapshot["living"])
                result += ({ ob });
        } else {
            if (living(ob))
                result += ({ ob });
        }
    }
    
    return result;
}
```

## Performance Considerations

### Snapshot API Cost
- **Fast path**: Same owner check is O(1) pointer comparison
- **Cross-owner**: Creates a small mapping with identity and type flags
- **Recommended**: Cache snapshot results when querying multiple properties

### Error Catching Cost
- LPC `catch` has minimal overhead
- Use for bounded operations only
- Avoid in tight loops with thousands of iterations

### Optimization Tips
```lpc
// Good: Check snapshot once
mapping snapshot = owner_query_object_snapshot(ob);
if (mapp(snapshot) && snapshot["living"]) {
    catch {
        string name = ob->query_name();
        string id = ob->query_id();
        // ... use cached snapshot and queried values
    };
}

// Bad: Multiple snapshot checks
if (mapp(owner_query_object_snapshot(ob))) {
    // ...
}
if (mapp(owner_query_object_snapshot(ob))) {  // Duplicate check
    // ...
}
```

## Migration Guide

### Before (Direct Access)
```lpc
object find_player(string name) {
    object *players = users();
    foreach(object p in players) {
        if (p->query_name() == name)
            return p;
    }
    return 0;
}
```

### After (Snapshot + Catch)
```lpc
object find_player(string name) {
    object *players = users();
    foreach(object p in players) {
        mapping snapshot = owner_query_object_snapshot(p);
        if (mapp(snapshot)) {
            string p_name;
            catch { p_name = p->query_name(); };
            if (p_name == name)
                return p;
        } else {
            if (p->query_name() == name)
                return p;
        }
    }
    return 0;
}
```

## Debugging

### Check Owner ID
```lpc
string debug_owner(object ob) {
    mapping snapshot = owner_query_object_snapshot(ob);
    if (mapp(snapshot))
        return snapshot["owner_id"];
    return "same_owner_or_default";
}
```

## Testing

### Unit Test Template
```lpc
void test_cross_owner_access() {
    object player1 = new("/std/player");
    object player2 = new("/std/player");
    
    // Same owner access
    mapping snapshot = owner_query_object_snapshot(player1);
    assert(!mapp(snapshot), "Same owner should return 0");
    
    // Cross-owner access
    // (Requires multicore mode 2)
    mapping p2_snapshot = owner_query_object_snapshot(player2);
    assert(mapp(p2_snapshot), "Cross-owner should return mapping");
    assert(p2_snapshot["owner_id"], "Should have owner_id");
}
```

## See Also

- [Multicore Runtime v4](multicore-runtime-v4.md)
- [Owner Implementation](https://github.com/FengYunCalm/Fluffos_XK/blob/master/src/vm/internal/owner.cc)
- [API Reference](https://github.com/FengYunCalm/Fluffos_XK/blob/master/src/vm/owner.h)
