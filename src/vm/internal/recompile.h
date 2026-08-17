#ifndef FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_H_
#define FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_H_

// E3 recompile_object() transaction subsystem (v0.4 §8/§9). Owned by
// src/vm/internal/recompile.cc; simulate.h keeps only forward declarations
// so the transaction has a single home and simulate.cc stops growing.

#include <cstdint>
#include <string>
#include <vector>

#include "vm/internal/base/program.h"  // free_prog, program_t

struct object_t;

struct RecompileLayoutVariable {
  int slot{0};
  std::string name;
  int full_decl_type{0};
};

struct RecompileLayoutInherit {
  int slot{0};
  std::string filename;
  int type_mod{0};
  std::string nested_digest;  // recursive digest of the inherited layout
};

struct RecompileLayout {
  int num_variables_total{0};
  std::vector<RecompileLayoutVariable> variables;
  std::vector<RecompileLayoutInherit> inherits;
};

// RAII owner of a freshly compiled (staging) program: never published to any
// live object until commit. free_prog() on destruction.
struct StagedProgram {
  program_t *prog{nullptr};
  StagedProgram() = default;
  explicit StagedProgram(program_t *p) : prog(p) {}
  ~StagedProgram() {
    if (prog) free_prog(&prog);
  }
  StagedProgram(const StagedProgram &) = delete;
  StagedProgram &operator=(const StagedProgram &) = delete;
  StagedProgram(StagedProgram &&other) noexcept : prog(other.prog) { other.prog = nullptr; }
  StagedProgram &operator=(StagedProgram &&other) noexcept {
    if (this != &other) {
      if (prog) free_prog(&prog);
      prog = other.prog;
      other.prog = nullptr;
    }
    return *this;
  }
};

struct RecompileTarget {
  object_t *ob{nullptr};
  uint32_t precomputed_flags{0};
};

// Fully prepared transaction: staging program, validated layouts, frozen
// target set (each target holds an add_ref). commit() performs the no-fail
// swap AND releases every resource the transaction owns; the destructor is a
// pure failure-path cleanup. New callers must never hand-release targets or
// the old-program pin outside this type.
struct RecompilePrepared {
  StagedProgram staged;
  program_t *old_prog{nullptr};
  RecompileLayout old_layout;
  RecompileLayout new_layout;
  std::vector<RecompileTarget> targets;

  RecompilePrepared() = default;
  ~RecompilePrepared();
  RecompilePrepared(const RecompilePrepared &) = delete;
  RecompilePrepared &operator=(const RecompilePrepared &) = delete;

  // The no-fail commit: reserve new-program refs, swap program/generation/
  // flags on every target, release the N old-program references, then drop
  // the snapshot add_refs. Must only be called with the owner runtime FROZEN
  // and after every allocatable step succeeded (v0.4 §9.2).
  void commit() noexcept;
};

// Compile the blueprint's source file into a staging program, WITHOUT
// touching the live object. Fails with a stable error on read/compile
// failure. Inherits not already loaded are a prepare error (v1 never loads
// inherits inside the transaction).
StagedProgram compile_program_for_recompile(object_t *blueprint);

// Build a structured layout descriptor from a program (variables in actual
// variable-block order, inherits depth-first).
RecompileLayout describe_recompile_layout(program_t *prog);

// Compare two layouts field by field. Returns true when identical; otherwise
// false and first_diff names the first mismatching field.
bool recompile_layouts_match(const RecompileLayout &a, const RecompileLayout &b,
                             std::string *first_diff);

// Snapshot every live object still sharing blueprint->prog (the blueprint
// itself and its clones), checking: not the current VM program, not on the
// main control stack, no shadowing/shadowed chain, no pending
// replace_program(). Any violation is a stable error before anything is
// touched. The frozen set takes add_ref on every target.
void snapshot_recompile_targets(object_t *blueprint, RecompilePrepared *prepared);

#endif /* FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_H_ */
