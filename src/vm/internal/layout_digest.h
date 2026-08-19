#ifndef FLUFFOS_SRC_VM_INTERNAL_LAYOUT_DIGEST_H_
#define FLUFFOS_SRC_VM_INTERNAL_LAYOUT_DIGEST_H_

// #1247 B-S2: the SINGLE digest implementation for layout fingerprints.
// program_layout_digest() (base/program.cc, hot path) and
// canonical_layout_serialization() (recompile_layout.cc, descriptor side)
// both build their byte streams from these primitives, so one process can
// never hold two digest algorithms. Pure functions, no driver state.

#include <cstddef>
#include <cstdint>
#include <string>

namespace layout_digest {

constexpr uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

inline uint64_t fnv_mix(uint64_t h, const char *p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    h ^= static_cast<unsigned char>(p[i]);
    h *= kFnvPrime;
  }
  return h;
}

inline void fnv_mix_int(uint64_t *h, int v) {
  *h = fnv_mix(*h, reinterpret_cast<const char *>(&v), sizeof(v));
}

// Canonical record builders -- the byte format both sides must agree on.
// Order: inherit records (DFS), variable records (slot order), class
// records (sorted by {path, name}).
inline std::string inherit_record(const std::string &inherit_path, const std::string &filename,
                                  int type_mod, uint64_t nested_digest) {
  return "inh:" + inherit_path + ":" + filename + ":" + std::to_string(type_mod) + ":" +
         std::to_string(nested_digest) + ";";
}

inline std::string variable_record(const std::string &inherit_path, const std::string &name,
                                   int effective_decl_type, uint64_t class_schema_digest) {
  return "var:" + inherit_path + ":" + name + ":" + std::to_string(effective_decl_type) + ":" +
         std::to_string(class_schema_digest) + ";";
}

inline std::string class_record(const std::string &defining_path, const std::string &class_name,
                                const std::string &members_serialized) {
  return "class:" + defining_path + ":" + class_name + ":" + members_serialized + ";";
}

}  // namespace layout_digest

#endif /* FLUFFOS_SRC_VM_INTERNAL_LAYOUT_DIGEST_H_ */
