#include "vm/internal/lpc_vm_profile.h"

#include "base/internal/vm_thread_local.h"
#include "vm/owner.h"

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
  std::atomic<uint64_t> opcode_dispatch_count{0};
  std::atomic<uint64_t> efun_dispatch_count{0};
  std::atomic<uint64_t> efun_dispatch_ns{0};
  std::atomic<uint64_t> call_other_dispatch_count{0};
  std::atomic<uint64_t> function_pointer_dispatch_count{0};
  std::atomic<uint64_t> function_pointer_efun_dispatch_count{0};
  std::atomic<uint64_t> parser_action_lookup_count{0};
  std::atomic<uint64_t> parser_action_match_count{0};
  std::atomic<uint64_t> mapping_lookup_count{0};
  std::atomic<uint64_t> mapping_insert_lookup_count{0};
  std::atomic<uint64_t> string_push_count{0};
};

FLUFFOS_VM_THREAD_LOCAL uint64_t opcode_dispatch_batch = 0;

LpcVmProfileState &state() {
  static LpcVmProfileState profile;
  return profile;
}

uint64_t load_relaxed(const std::atomic<uint64_t> &value) {
  return value.load(std::memory_order_relaxed);
}

void reset_counter(std::atomic<uint64_t> &value) { value.store(0, std::memory_order_relaxed); }

void add_counter(std::atomic<uint64_t> &value, uint64_t delta = 1) {
  value.fetch_add(delta, std::memory_order_relaxed);
}

}  // namespace

bool lpc_vm_profile_recording_enabled() {
  return vm_multicore_audit_enabled();
}

void lpc_vm_profile_reset() {
  lpc_vm_profile_flush_opcode_dispatch();
  opcode_dispatch_batch = 0;
  auto &profile = state();
  reset_counter(profile.apply_cache_lookup_count);
  reset_counter(profile.apply_cache_hit_count);
  reset_counter(profile.apply_cache_miss_count);
  reset_counter(profile.apply_cache_table_build_count);
  reset_counter(profile.apply_cache_table_item_count);
  reset_counter(profile.apply_cache_table_build_ns);
  reset_counter(profile.apply_dispatch_cache_lookup_count);
  reset_counter(profile.apply_dispatch_cache_hit_count);
  reset_counter(profile.apply_dispatch_cache_epoch_invalidation_count);
  reset_counter(profile.opcode_dispatch_count);
  reset_counter(profile.efun_dispatch_count);
  reset_counter(profile.efun_dispatch_ns);
  reset_counter(profile.call_other_dispatch_count);
  reset_counter(profile.function_pointer_dispatch_count);
  reset_counter(profile.function_pointer_efun_dispatch_count);
  reset_counter(profile.parser_action_lookup_count);
  reset_counter(profile.parser_action_match_count);
  reset_counter(profile.mapping_lookup_count);
  reset_counter(profile.mapping_insert_lookup_count);
  reset_counter(profile.string_push_count);
}

void lpc_vm_profile_record_apply_cache_lookup(bool hit) {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  auto &profile = state();
  add_counter(profile.apply_cache_lookup_count);
  if (hit) {
    add_counter(profile.apply_cache_hit_count);
  } else {
    add_counter(profile.apply_cache_miss_count);
  }
}

void lpc_vm_profile_record_apply_cache_table_build(std::size_t items, uint64_t elapsed_ns) {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  auto &profile = state();
  add_counter(profile.apply_cache_table_build_count);
  add_counter(profile.apply_cache_table_item_count, static_cast<uint64_t>(items));
  add_counter(profile.apply_cache_table_build_ns, elapsed_ns);
}

void lpc_vm_profile_record_apply_dispatch_cache_lookup(bool hit) {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  auto &profile = state();
  add_counter(profile.apply_dispatch_cache_lookup_count);
  if (hit) {
    add_counter(profile.apply_dispatch_cache_hit_count);
  }
}

void lpc_vm_profile_record_apply_dispatch_cache_epoch_invalidation() {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  add_counter(state().apply_dispatch_cache_epoch_invalidation_count);
}

void lpc_vm_profile_record_opcode_dispatch() {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  opcode_dispatch_batch++;
  if (opcode_dispatch_batch >= 1024) {
    lpc_vm_profile_flush_opcode_dispatch();
  }
}

void lpc_vm_profile_flush_opcode_dispatch() {
  if (opcode_dispatch_batch == 0) {
    return;
  }
  add_counter(state().opcode_dispatch_count, opcode_dispatch_batch);
  opcode_dispatch_batch = 0;
}

void lpc_vm_profile_record_efun_dispatch(uint64_t elapsed_ns) {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  auto &profile = state();
  add_counter(profile.efun_dispatch_count);
  add_counter(profile.efun_dispatch_ns, elapsed_ns);
}

void lpc_vm_profile_record_call_other_dispatch() {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  add_counter(state().call_other_dispatch_count);
}

void lpc_vm_profile_record_function_pointer_dispatch(bool efun_pointer) {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  auto &profile = state();
  add_counter(profile.function_pointer_dispatch_count);
  if (efun_pointer) {
    add_counter(profile.function_pointer_efun_dispatch_count);
  }
}

void lpc_vm_profile_record_parser_action_lookup(bool matched) {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  auto &profile = state();
  add_counter(profile.parser_action_lookup_count);
  if (matched) {
    add_counter(profile.parser_action_match_count);
  }
}

void lpc_vm_profile_record_mapping_lookup() {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  add_counter(state().mapping_lookup_count);
}

void lpc_vm_profile_record_mapping_insert_lookup() {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  add_counter(state().mapping_insert_lookup_count);
}

void lpc_vm_profile_record_string_push() {
  if (!lpc_vm_profile_recording_enabled()) {
    return;
  }
  add_counter(state().string_push_count);
}

LpcVmProfileSnapshot lpc_vm_profile_snapshot() {
  lpc_vm_profile_flush_opcode_dispatch();
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
  snapshot.opcode_dispatch_count = load_relaxed(profile.opcode_dispatch_count);
  snapshot.efun_dispatch_count = load_relaxed(profile.efun_dispatch_count);
  snapshot.efun_dispatch_ns = load_relaxed(profile.efun_dispatch_ns);
  snapshot.call_other_dispatch_count = load_relaxed(profile.call_other_dispatch_count);
  snapshot.function_pointer_dispatch_count = load_relaxed(profile.function_pointer_dispatch_count);
  snapshot.function_pointer_efun_dispatch_count = load_relaxed(profile.function_pointer_efun_dispatch_count);
  snapshot.parser_action_lookup_count = load_relaxed(profile.parser_action_lookup_count);
  snapshot.parser_action_match_count = load_relaxed(profile.parser_action_match_count);
  snapshot.mapping_lookup_count = load_relaxed(profile.mapping_lookup_count);
  snapshot.mapping_insert_lookup_count = load_relaxed(profile.mapping_insert_lookup_count);
  snapshot.string_push_count = load_relaxed(profile.string_push_count);
  return snapshot;
}
