#include "base/std.h"

#include "vm/internal/base/apply_cache.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>

#include "base/internal/tracing.h"
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
thread_local std::array<ApplyDispatchDirectCacheEntry, 4> apply_dispatch_direct_cache{};
thread_local uint64_t apply_dispatch_direct_cache_epoch_seen{0};
thread_local size_t apply_dispatch_direct_cache_next_slot{0};

uint64_t current_apply_dispatch_cache_epoch() {
  return apply_dispatch_cache_epoch.load(std::memory_order_acquire);
}

void ensure_apply_dispatch_cache_epoch_current() {
  auto epoch = current_apply_dispatch_cache_epoch();
  if (apply_dispatch_direct_cache_epoch_seen == epoch) {
    return;
  }
  for (auto &entry : apply_dispatch_direct_cache) {
    entry = ApplyDispatchDirectCacheEntry{};
  }
  apply_dispatch_direct_cache_next_slot = 0;
  if (apply_dispatch_direct_cache_epoch_seen != 0) {
    lpc_vm_profile_record_apply_dispatch_cache_epoch_invalidation();
  }
  apply_dispatch_direct_cache_epoch_seen = epoch;
}

lookup_entry_s apply_dispatch_direct_cache_lookup(program_t *prog, intptr_t key, bool *hit) {
  ensure_apply_dispatch_cache_epoch_current();
  for (const auto &entry : apply_dispatch_direct_cache) {
    if (entry.prog == prog && entry.key == key && entry.entry.funp != nullptr) {
      lpc_vm_profile_record_apply_dispatch_cache_lookup(true);
      *hit = true;
      return entry.entry;
    }
  }
  lpc_vm_profile_record_apply_dispatch_cache_lookup(false);
  *hit = false;
  return lookup_entry_s{nullptr};
}

void apply_dispatch_direct_cache_store(program_t *prog, intptr_t key, lookup_entry_s entry) {
  if (!entry.funp) {
    return;
  }
  ensure_apply_dispatch_cache_epoch_current();
  auto slot = apply_dispatch_direct_cache_next_slot++ % apply_dispatch_direct_cache.size();
  apply_dispatch_direct_cache[slot] = ApplyDispatchDirectCacheEntry{prog, key, entry};
}
}  // namespace

lookup_entry_s apply_cache_lookup(const char *funcname, program_t *prog) {
  ScopedTracer _tracer("Apply Cache Lookup", EventCategory::APPLY_CACHE, [=] {
    return json{"name", funcname};
  });

  // All function names are shared string.
  auto key = (intptr_t)(findstring(funcname));
  if (key == 0) {
    lpc_vm_profile_record_apply_cache_lookup(false);
    return lookup_entry_s{nullptr};
  }

  if (prog->apply_lookup_table == nullptr) {
    fill_lookup_table(prog);
  }

  apply_cache_lookups++;

  bool direct_hit = false;
  auto direct = apply_dispatch_direct_cache_lookup(prog, key, &direct_hit);
  if (direct_hit) {
    apply_cache_hits++;
    lpc_vm_profile_record_apply_cache_lookup(true);
    return direct;
  }

  auto pos = prog->apply_lookup_table->find(key);
  if (pos != prog->apply_lookup_table->end()) {
    apply_cache_hits++;
    lpc_vm_profile_record_apply_cache_lookup(true);
    apply_dispatch_direct_cache_store(prog, key, pos->second);
    return pos->second;
  } else {
    lpc_vm_profile_record_apply_cache_lookup(false);
    return lookup_entry_s{nullptr};
  }
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
  auto start = std::chrono::steady_clock::now();
  prog->apply_lookup_table = std::make_unique<program_t::apply_lookup_table_type>();
  fill_lookup_table_recurse(prog->apply_lookup_table, prog, 0, 0);

  apply_cache_items += prog->apply_lookup_table->size();
  auto elapsed_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
          .count();
  lpc_vm_profile_record_apply_cache_table_build(prog->apply_lookup_table->size(),
                                                static_cast<uint64_t>(elapsed_ns));
}

void apply_cache_invalidate_program(program_t * /*prog*/) {
  apply_dispatch_cache_epoch.fetch_add(1, std::memory_order_acq_rel);
}
