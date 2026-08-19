#ifndef FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_LAYOUT_H_
#define FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_LAYOUT_H_

// #1247 B-S2: pure layout description/classification module. Reads
// program_t only -- no live objects, no VM context, no simul tables, no
// transaction state -- so it can be unit-tested outside the driver
// lifecycle. recompile.cc (the transaction module) consumes only the
// results (RecompileLayout / RecompileLayoutDiff / matches); all class
// schema, type_mod and identity rules live here.

#include <cstdint>
#include <string>
#include <vector>

struct program_t;

// One variable in the layout, in actual variable-block (DFS/slot) order.
struct RecompileLayoutVariable {
  int slot{0};
  std::string inherit_path;        // defining program's path from the root
  std::string name_text;           // variable name
  int effective_decl_type{0};      // DECL_MODIFY applied along the path
  uint64_t class_schema_digest{0}; // 0 = not a class-typed variable
};

// One inherit edge of the layout, in DFS order (children before the edge
// that contains them is recorded parent-side; see describe_recompile_layout).
struct RecompileLayoutInherit {
  int slot{0};                   // variable-block slot where this subtree starts
  std::string inherit_path;      // path of the inherited program
  std::string filename_text;     // the edge's program filename
  int type_mod{0};               // inherit_t::type_mod of the edge
  uint64_t nested_layout_digest{0};  // recursive digest of the nested layout
};

struct RecompileLayoutClassMember {
  std::string name;
  int type{0};
};

struct RecompileLayoutClass {
  std::string defining_inherit_path;  // program path that defines the class
  std::string class_name;
  std::vector<RecompileLayoutClassMember> members;
  uint64_t schema_digest{0};
};

struct RecompileLayout {
  int num_variables_total{0};
  std::vector<RecompileLayoutVariable> variables;
  std::vector<RecompileLayoutInherit> inherits;
  // Complete class definition set of the program AND its inherit graph
  // (conservative: covers class values retained in mixed variables).
  std::vector<RecompileLayoutClass> classes;
};

// Stable variable identity: {inherit_path, name_text}. Same name on
// different inherit paths are distinct variables.
struct VariableIdentity {
  std::string inherit_path;
  std::string name_text;
  bool operator==(const VariableIdentity &o) const {
    return inherit_path == o.inherit_path && name_text == o.name_text;
  }
  bool operator<(const VariableIdentity &o) const {
    if (inherit_path != o.inherit_path) return inherit_path < o.inherit_path;
    return name_text < o.name_text;
  }
};

struct VariableMatch {
  VariableIdentity identity;
  int old_slot{0};
  int new_slot{0};
};

// Bitmask, not an enum: a diff can combine several change kinds and every
// reject reason must block migration independently.
enum RecompileDiffFlags : uint32_t {
  kRecompileDiffNone = 0,
  kAddedVariable = 1u << 0,
  kRemovedVariable = 1u << 1,
  kReordered = 1u << 2,
  kTypeChanged = 1u << 3,        // matched variable effective type changed
  kInheritChanged = 1u << 4,     // inherit graph / edge type_mod changed
  kClassSchemaChanged = 1u << 5, // class schema changed anywhere
  kDuplicateIdentity = 1u << 6,  // repeated stable identity within one layout
  kUnresolvable = 1u << 7,       // path/schema could not be normalized
};

struct RecompileLayoutDiff {
  std::vector<VariableMatch> matches;
  std::vector<VariableIdentity> added;
  std::vector<VariableIdentity> removed;
  uint32_t flags{kRecompileDiffNone};
  std::vector<std::string> reject_reasons;
  bool migratable() const noexcept { return reject_reasons.empty(); }
};

// Build the full descriptor (variables in block order with inherit paths
// and effective types, inherit edges with type_mod and nested digests, the
// complete class definition set). Pure: no warnings, no policy.
RecompileLayout describe_recompile_layout(program_t *prog);

// Classify old vs new: build matches by stable identity, lists of added /
// removed identities, and reject reasons. Pure comparison/classification:
// never warns and never decides user-visible policy.
RecompileLayoutDiff classify_recompile_layout(const RecompileLayout &old_l,
                                              const RecompileLayout &new_l);

// Strict field-by-field comparison (exact layout only). True when
// identical; otherwise false and first_diff names the first mismatch.
bool recompile_layouts_match(const RecompileLayout &a, const RecompileLayout &b,
                             std::string *first_diff);

// Canonical byte serialization of an exact layout. Deterministic; used to
// prove digest/deserialization equivalence and to seed the layout digest.
std::string canonical_layout_serialization(const RecompileLayout &layout);

// FNV-1a 64 over canonical bytes (the same mixing program_layout_digest
// uses). Exported so the equivalence test can compare both sides.
uint64_t layout_serialization_digest(const std::string &bytes);

#endif /* FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_LAYOUT_H_ */
