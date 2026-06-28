#include "vm/internal/lpc_vm_profile.h"

#include <atomic>

namespace {
struct LpcVmProfileState {
  std::atomic<uint64_t> apply_cache_lookup_count{0};
  std::atomic<uint64_t> apply_cache_hit_count{0};
  std::atomic<uint64_t> apply_cache_miss_count{0};
  std::atomic<uint64_t> apply_cache_table_build_count{0};
  std::atomic<uint64_t> apply_cache_table_item_count{0};
  std::atomic<uint64_t> apply_cache_table_build_ns{0};
  std::atomic<uint64_t> apply_dispatch_cache_lookup_count{0};
  std::atomic<uint64_t> apply_dispatch_cache_hit_count{0};
  std::atomic<uint64_t> apply_dispatch_cache_epoch_invalidation_count{0};
};

LpcVmProfileState &state() {
  static LpcVmProfileState profile;
  return profile;
}

uint64_t load_relaxed(const std::atomic<uint64_t> &value) {
  return value.load(std::memory_order_relaxed);
}
}  // namespace

void lpc_vm_profile_reset() {
  auto &profile = state();
  profile.apply_cache_lookup_count.store(0, std::memory_order_relaxed);
  profile.apply_cache_hit_count.store(0, std::memory_order_relaxed);
  profile.apply_cache_miss_count.store(0, std::memory_order_relaxed);
  profile.apply_cache_table_build_count.store(0, std::memory_order_relaxed);
  profile.apply_cache_table_item_count.store(0, std::memory_order_relaxed);
  profile.apply_cache_table_build_ns.store(0, std::memory_order_relaxed);
  profile.apply_dispatch_cache_lookup_count.store(0, std::memory_order_relaxed);
  profile.apply_dispatch_cache_hit_count.store(0, std::memory_order_relaxed);
  profile.apply_dispatch_cache_epoch_invalidation_count.store(0, std::memory_order_relaxed);
}

void lpc_vm_profile_record_apply_cache_lookup(bool hit) {
  auto &profile = state();
  profile.apply_cache_lookup_count.fetch_add(1, std::memory_order_relaxed);
  if (hit) {
    profile.apply_cache_hit_count.fetch_add(1, std::memory_order_relaxed);
  } else {
    profile.apply_cache_miss_count.fetch_add(1, std::memory_order_relaxed);
  }
}

void lpc_vm_profile_record_apply_cache_table_build(std::size_t items, uint64_t elapsed_ns) {
  auto &profile = state();
  profile.apply_cache_table_build_count.fetch_add(1, std::memory_order_relaxed);
  profile.apply_cache_table_item_count.fetch_add(static_cast<uint64_t>(items), std::memory_order_relaxed);
  profile.apply_cache_table_build_ns.fetch_add(elapsed_ns, std::memory_order_relaxed);
}

void lpc_vm_profile_record_apply_dispatch_cache_lookup(bool hit) {
  auto &profile = state();
  profile.apply_dispatch_cache_lookup_count.fetch_add(1, std::memory_order_relaxed);
  if (hit) {
    profile.apply_dispatch_cache_hit_count.fetch_add(1, std::memory_order_relaxed);
  }
}

void lpc_vm_profile_record_apply_dispatch_cache_epoch_invalidation() {
  state().apply_dispatch_cache_epoch_invalidation_count.fetch_add(1, std::memory_order_relaxed);
}

LpcVmProfileSnapshot lpc_vm_profile_snapshot() {
  auto &profile = state();
  LpcVmProfileSnapshot snapshot;
  snapshot.apply_cache_lookup_count = load_relaxed(profile.apply_cache_lookup_count);
  snapshot.apply_cache_hit_count = load_relaxed(profile.apply_cache_hit_count);
  snapshot.apply_cache_miss_count = load_relaxed(profile.apply_cache_miss_count);
  snapshot.apply_cache_table_build_count = load_relaxed(profile.apply_cache_table_build_count);
  snapshot.apply_cache_table_item_count = load_relaxed(profile.apply_cache_table_item_count);
  snapshot.apply_cache_table_build_ns = load_relaxed(profile.apply_cache_table_build_ns);
  snapshot.apply_dispatch_cache_lookup_count = load_relaxed(profile.apply_dispatch_cache_lookup_count);
  snapshot.apply_dispatch_cache_hit_count = load_relaxed(profile.apply_dispatch_cache_hit_count);
  snapshot.apply_dispatch_cache_epoch_invalidation_count =
      load_relaxed(profile.apply_dispatch_cache_epoch_invalidation_count);
  return snapshot;
}
