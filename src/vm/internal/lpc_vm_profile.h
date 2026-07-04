#ifndef LPC_VM_PROFILE_H_
#define LPC_VM_PROFILE_H_

#include <cstddef>
#include <cstdint>

inline constexpr const char *kLpcVmProfileSchemaV1 = "lpc_vm_profile_v1";
inline constexpr const char *kLpcVmBenchSchemaV1 = "lpc_vm_bench_v1";

struct LpcVmProfileSnapshot {
  uint64_t apply_cache_lookup_count{0};
  uint64_t apply_cache_hit_count{0};
  uint64_t apply_cache_miss_count{0};
  uint64_t apply_cache_table_build_count{0};
  uint64_t apply_cache_table_item_count{0};
  uint64_t apply_cache_table_build_ns{0};
  uint64_t apply_dispatch_cache_lookup_count{0};
  uint64_t apply_dispatch_cache_hit_count{0};
  uint64_t apply_dispatch_cache_epoch_invalidation_count{0};
  uint64_t opcode_dispatch_count{0};
  uint64_t efun_dispatch_count{0};
  uint64_t efun_dispatch_ns{0};
  uint64_t call_other_dispatch_count{0};
  uint64_t function_pointer_dispatch_count{0};
  uint64_t function_pointer_efun_dispatch_count{0};
  uint64_t parser_action_lookup_count{0};
  uint64_t parser_action_match_count{0};
  uint64_t mapping_lookup_count{0};
  uint64_t mapping_insert_lookup_count{0};
  uint64_t string_push_count{0};
};

void lpc_vm_profile_reset();
bool lpc_vm_profile_recording_enabled();
void lpc_vm_profile_record_apply_cache_lookup(bool hit);
void lpc_vm_profile_record_apply_cache_table_build(std::size_t items, uint64_t elapsed_ns);
void lpc_vm_profile_record_apply_dispatch_cache_lookup(bool hit);
void lpc_vm_profile_record_apply_dispatch_cache_epoch_invalidation();
void lpc_vm_profile_record_opcode_dispatch();
void lpc_vm_profile_flush_opcode_dispatch();
void lpc_vm_profile_record_efun_dispatch(uint64_t elapsed_ns);
void lpc_vm_profile_record_call_other_dispatch();
void lpc_vm_profile_record_function_pointer_dispatch(bool efun_pointer);
void lpc_vm_profile_record_parser_action_lookup(bool matched);
void lpc_vm_profile_record_mapping_lookup();
void lpc_vm_profile_record_mapping_insert_lookup();
void lpc_vm_profile_record_string_push();
LpcVmProfileSnapshot lpc_vm_profile_snapshot();

#endif /* LPC_VM_PROFILE_H_ */
