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
};

void lpc_vm_profile_reset();
void lpc_vm_profile_record_apply_cache_lookup(bool hit);
void lpc_vm_profile_record_apply_cache_table_build(std::size_t items, uint64_t elapsed_ns);
LpcVmProfileSnapshot lpc_vm_profile_snapshot();

#endif /* LPC_VM_PROFILE_H_ */
