#include "base/std.h"

#include "vm/internal/base/apply_cache.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>

#include "base/internal/tracing.h"
#include "vm/owner.h"
#include "vm/internal/base/program.h"
#include "vm/internal/lpc_vm_profile.h"

static inline void fill_lookup_table(program_t *prog);

namespace {
struct ApplyDispatchDirectCacheEntry {
  program_t *prog{nullptr};
  intptr_t key{0};
  lookup_entry_s entry{nullptr};
};

std::atomic<uint64_t> apply_dispatch_cache_epoch{1};
FLUFFOS_VM_THREAD_LOCAL std::array<ApplyDispatchDirectCacheEntry, 4> apply_dispatch_direct_cache{};
FLUFFOS_VM_THREAD_LOCAL uint64_t apply_dispatch_direct_cache_epoch_seen{0};
FLUFFOS_VM_THREAD_LOCAL size_t apply_dispatch_direct_cache_next_slot{0};
#if !FLUFFOS_OWNER_THREAD_VM
program_t *apply_shared_single_cache_prog{nullptr};
intptr_t apply_shared_single_cache_key{0};
lookup_entry_s apply_shared_single_cache_entry{nullptr};
#endif

uint64_t current_apply_dispatch_cache_epoch() {
  return apply_dispatch_cache_epoch.load(std::memory_order_acquire);
}

void ensure_apply_dispatch_cache_epoch_current(bool profile_enabled) {
  auto epoch = current_apply_dispatch_cache_epoch();
  if (apply_dispatch_direct_cache_epoch_seen == epoch) {
    return;
  }
  for (auto &entry : apply_dispatch_direct_cache) {
    entry = ApplyDispatchDirectCacheEntry{};
  }
  apply_dispatch_direct_cache_next_slot = 0;
  if (profile_enabled && apply_dispatch_direct_cache_epoch_seen != 0) {
    lpc_vm_profile_record_apply_dispatch_cache_epoch_invalidation();
  }
  apply_dispatch_direct_cache_epoch_seen = epoch;
}

lookup_entry_s apply_dispatch_direct_cache_lookup(program_t *prog, intptr_t key, bool profile_enabled, bool *hit) {
  ensure_apply_dispatch_cache_epoch_current(profile_enabled);
  for (const auto &entry : apply_dispatch_direct_cache) {
    if (entry.prog == prog && entry.key == key && entry.entry.funp != nullptr) {
      if (profile_enabled) {
        lpc_vm_profile_record_apply_dispatch_cache_lookup(true);
      }
      *hit = true;
      return entry.entry;
    }
  }
  if (profile_enabled) {
    lpc_vm_profile_record_apply_dispatch_cache_lookup(false);
  }
  *hit = false;
  return lookup_entry_s{nullptr};
}

void apply_dispatch_direct_cache_store(program_t *prog, intptr_t key, lookup_entry_s entry, bool profile_enabled) {
  if (!entry.funp) {
    return;
  }
  ensure_apply_dispatch_cache_epoch_current(profile_enabled);
  auto slot = apply_dispatch_direct_cache_next_slot++ % apply_dispatch_direct_cache.size();
  apply_dispatch_direct_cache[slot] = ApplyDispatchDirectCacheEntry{prog, key, entry};
}
}  // namespace

lookup_entry_s apply_cache_lookup(const char *funcname, program_t *prog) {
  ScopedTracer _tracer("Apply Cache Lookup", EventCategory::APPLY_CACHE, [=] {
    return json{"name", funcname};
  });

  // All function names are shared string.
  const bool profile_enabled = lpc_vm_profile_recording_enabled();
#if FLUFFOS_OWNER_THREAD_VM
  const bool direct_cache_enabled = vm_multicore_audit_enabled_fast();
#else
  constexpr bool direct_cache_enabled = false;
#endif
  auto key = (intptr_t)(findstring(funcname));
  if (key == 0) {
    if (profile_enabled) {
      lpc_vm_profile_record_apply_cache_lookup(false);
    }
    return lookup_entry_s{nullptr};
  }

  if (prog->apply_lookup_table == nullptr) {
    fill_lookup_table(prog);
  }

  apply_cache_lookups++;

  if (direct_cache_enabled) {
    bool direct_hit = false;
    auto direct = apply_dispatch_direct_cache_lookup(prog, key, profile_enabled, &direct_hit);
    if (direct_hit) {
      apply_cache_hits++;
      if (profile_enabled) {
        lpc_vm_profile_record_apply_cache_lookup(true);
      }
      return direct;
    }
  }

  auto pos = prog->apply_lookup_table->find(key);
  if (pos != prog->apply_lookup_table->end()) {
    apply_cache_hits++;
    if (profile_enabled) {
      lpc_vm_profile_record_apply_cache_lookup(true);
    }
    if (direct_cache_enabled) {
      apply_dispatch_direct_cache_store(prog, key, pos->second, profile_enabled);
    }
    return pos->second;
  } else {
    if (profile_enabled) {
      lpc_vm_profile_record_apply_cache_lookup(false);
    }
    return lookup_entry_s{nullptr};
  }
}

lookup_entry_s apply_cache_lookup_shared(const char *funcname, program_t *prog) {
#if FLUFFOS_OWNER_THREAD_VM
  ScopedTracer _tracer("Apply Cache Shared Lookup", EventCategory::APPLY_CACHE, [=] {
    return json{"name", funcname};
  });
#endif

  const bool profile_enabled = lpc_vm_profile_recording_enabled();
#if FLUFFOS_OWNER_THREAD_VM
  const bool direct_cache_enabled = vm_multicore_audit_enabled_fast();
#else
  constexpr bool direct_cache_enabled = false;
#endif
  auto key = reinterpret_cast<intptr_t>(funcname);
  if (key == 0) {
    if (profile_enabled) {
      lpc_vm_profile_record_apply_cache_lookup(false);
    }
    return lookup_entry_s{nullptr};
  }

#if !FLUFFOS_OWNER_THREAD_VM
  if (apply_shared_single_cache_prog == prog && apply_shared_single_cache_key == key &&
      apply_shared_single_cache_entry.funp != nullptr) {
    apply_cache_lookups++;
    apply_cache_hits++;
    return apply_shared_single_cache_entry;
  }
#endif

  if (prog->apply_lookup_table == nullptr) {
    fill_lookup_table(prog);
  }

  apply_cache_lookups++;

  if (direct_cache_enabled) {
    bool direct_hit = false;
    auto direct = apply_dispatch_direct_cache_lookup(prog, key, profile_enabled, &direct_hit);
    if (direct_hit) {
      apply_cache_hits++;
      if (profile_enabled) {
        lpc_vm_profile_record_apply_cache_lookup(true);
      }
      return direct;
    }
  }

  auto pos = prog->apply_lookup_table->find(key);
  if (pos != prog->apply_lookup_table->end()) {
    apply_cache_hits++;
#if !FLUFFOS_OWNER_THREAD_VM
    apply_shared_single_cache_prog = prog;
    apply_shared_single_cache_key = key;
    apply_shared_single_cache_entry = pos->second;
#endif
    if (profile_enabled) {
      lpc_vm_profile_record_apply_cache_lookup(true);
    }
    if (direct_cache_enabled) {
      apply_dispatch_direct_cache_store(prog, key, pos->second, profile_enabled);
    }
    return pos->second;
  }
  if (profile_enabled) {
    lpc_vm_profile_record_apply_cache_lookup(false);
  }
  return lookup_entry_s{nullptr};
}

static inline void fill_lookup_table_recurse(
    std::unique_ptr<program_t::apply_lookup_table_type> &table, program_t *prog, uint16_t fio,
    uint16_t vio) {
  // add all defined functions
  for (int i = 0; i < prog->num_functions_defined; i++) {
    auto idx = i + prog->last_inherited;
    if (prog->function_flags[idx] & (FUNC_UNDEFINED | FUNC_PROTOTYPE)) {
      continue;
    }

    auto key = (intptr_t)(prog->function_table[i].funcname);
    if (table->find(key) == table->end()) {
      lookup_entry_s entry = {nullptr};
      entry.progp = prog;
      entry.funp = &(prog->function_table[i]);
      entry.runtime_index = fio + idx;
      entry.function_index_offset = fio;
      entry.variable_index_offset = vio;
      table->insert({key, entry});
    }
  }

  // add inherited functions (must go backwards)
  int i = prog->num_inherited;
  while (i--) {
    auto inherit = prog->inherit[i];
    fill_lookup_table_recurse(table, inherit.prog, fio + inherit.function_index_offset,
                              vio + inherit.variable_index_offset);
  }
}

static inline void fill_lookup_table(program_t *prog) {
  const bool profile_enabled = lpc_vm_profile_recording_enabled();
  auto start = profile_enabled ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
  prog->apply_lookup_table = std::make_unique<program_t::apply_lookup_table_type>();
  fill_lookup_table_recurse(prog->apply_lookup_table, prog, 0, 0);

  apply_cache_items += prog->apply_lookup_table->size();
  if (profile_enabled) {
    auto elapsed_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
            .count();
    lpc_vm_profile_record_apply_cache_table_build(prog->apply_lookup_table->size(),
                                                  static_cast<uint64_t>(elapsed_ns));
  }
}

void apply_cache_invalidate_program(program_t * /*prog*/) {
#if !FLUFFOS_OWNER_THREAD_VM
  apply_shared_single_cache_prog = nullptr;
  apply_shared_single_cache_key = 0;
  apply_shared_single_cache_entry = lookup_entry_s{nullptr};
#endif
  apply_dispatch_cache_epoch.fetch_add(1, std::memory_order_acq_rel);
}
