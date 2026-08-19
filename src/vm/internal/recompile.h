#ifndef FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_H_
#define FLUFFOS_SRC_VM_INTERNAL_RECOMPILE_H_

// E3 recompile_object() transaction subsystem (v0.4 §8/§9). Owned by
// src/vm/internal/recompile.cc; simulate.h keeps only forward declarations
// so the transaction has a single home and simulate.cc stops growing.

#include <cstdint>
#include <string>
#include <vector>

#include <memory>  // std::unique_ptr
#include "vm/internal/base/program.h"  // free_prog, program_t
#include "vm/internal/recompile_layout.h"  // RecompileLayout, RecompileLayoutDiff
#include "vm/internal/simul_efun.h"     // simul_efun_prepared_t

struct object_t;
// Defined in recompile.cc: keeps ObjectVariableBlock (object.h) out of the
// public header's include graph.
struct PreparedVariableMigration;

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
  uint64_t old_generation{0};  // pre-swap prog_generation, restored by rollback()
};

// What kind of object family this transaction reloads. Decided once by the
// caller (f_recompile_object) at prepare time; every Phase 2 extension
// (create-phase execution, simul_efun dispatch rebuild) derives from it so
// the transaction keeps a single discriminant instead of accumulating
// booleans.
enum class RecompileTargetKind {
  BlueprintFamily,  // ordinary blueprint + clones: no create phase (v1)
  Master,           // master_ob: create phase runs inside the transaction
  SimulEfun         // simul_efun_ob: create phase + dispatch rebuild
};

// #1247 B-S3: per-kind lifecycle policy -- the single behavioral entry for
// __INIT / variable migration ordering / create. Exact-layout and
// layout-change behavior are decided HERE, never by scattered branches.
//
// | Target kind    | __INIT            | migrate           | order            | create          |
// | BlueprintFamily| OnMigratableChange| OnMigratableChange| InitThenMigrate  | Never           |
// | Master         | Always            | Always            | MigrateThenInit  | AfterStateReady |
// | SimulEfun      | Always            | Always            | MigrateThenInit  | AfterStateReady |
enum class RecompileInitPolicy {
  Never,
  OnMigratableLayoutChange,
  Always,
};

enum class RecompileMigrationPolicy {
  None,
  OnMigratableLayoutChange,
  Always,
};

enum class RecompileStateOrder {
  InitThenMigrate,
  MigrateThenInit,
};

enum class RecompileCreatePolicy {
  Never,
  AfterStateReady,
};

struct RecompileLifecycle {
  RecompileInitPolicy init;
  RecompileMigrationPolicy migrate;
  RecompileStateOrder state_order;
  RecompileCreatePolicy create;
};

// Fixed policy table (see the table above).
RecompileLifecycle recompile_lifecycle_for(RecompileTargetKind kind);

// Fully prepared transaction: staging program, validated layouts, frozen
// target set (each target holds an add_ref). The commit is split into three
// segments (v2 Phase 2): commit_swap() is the no-fail swap (program +
// apply-cache epoch + simul_efun activation) while admission stays closed;
// the caller then runs __INIT/create for special targets in an error
// context; commit_finish() releases the old resources after success,
// rollback() restores the old program and dispatch tables after a failed
// create. The destructor is a pure failure-path cleanup. New callers must
// never hand-release targets or the old-program pin outside this type.
struct RecompilePrepared {
  StagedProgram staged;
  program_t *old_prog{nullptr};
  RecompileLayout old_layout;
  RecompileLayout new_layout;
  // #1247 B-S3: the admission-time classification (single source of truth
  // for matches/added/removed; prepare_variable_migrations reuses it
  // instead of re-classifying).
  RecompileLayoutDiff admission_diff;
  std::vector<RecompileTarget> targets;
  RecompileTargetKind kind{RecompileTargetKind::BlueprintFamily};

  // #1247 B-S3: per-target prepared migrations (parallel to targets, empty
  // for exact-layout transactions and for kinds whose policy never
  // migrates). Built in the fallible frozen segment, published inside
  // commit_swap()'s no-fail segment, applied by prepare_target_state().
  std::vector<std::unique_ptr<PreparedVariableMigration>> migrations;

  // simul_efun dispatch rebuild (v2): prepared in the allocatable frozen
  // segment when kind == SimulEfun, activated inside commit_swap()'s no-fail
  // segment (old tables handed over alive), finished/rolled back after the
  // create phase, discarded by the destructor on failure paths.
  simul_efun_prepared_t simuls;

  RecompilePrepared();
  ~RecompilePrepared();
  RecompilePrepared(const RecompilePrepared &) = delete;
  RecompilePrepared &operator=(const RecompilePrepared &) = delete;

  // Segment 1 (no-fail): reserve new-program refs (commit pin + one per
  // target), swap program/generation/derived-flags on every target, bump
  // the apply-cache epoch, activate the simul_efun rebuild (old dispatch
  // tables handed to simuls, kept alive). Must only be called with the
  // owner runtime FROZEN and after every allocatable step succeeded.
  void commit_swap() noexcept;

  // Segment 2 (fail-able, special targets only): run __INIT/create on every
  // target while admission stays closed. BlueprintFamily is a no-op (v1
  // semantics: ordinary blueprints and clones have no create phase) so any
  // caller can invoke this uniformly. Errors from __INIT, create(), or the
  // interpreter propagate as C++ exceptions (plain apply() does not
  // swallow them; only safe_apply does) to the caller's error context, and
  // a destructed target is a stable error too -- both must end in rollback().
  void run_create();

  // Segment 2 wrapper owning the error-context dance: save_context around
  // run_create(); on a C++ error it restores the interpreter stack
  // (restore_context -> pop_context, in that order), rolls the transaction
  // back (noexcept, safe after restore per the safe_apply convention) and
  // returns false. The caller then raises a fresh stable error. This is the
  // ONLY supported way to run the create phase outside the package layer.
  bool run_create_guarded();

  // Segment 3 (no-fail, after a successful create phase): release the old
  // simul_efun tables, the N old-program references, the commit pin, the
  // old-program transaction pin, and the snapshot add_refs.
  void commit_finish() noexcept;

  // Failure path after commit_swap(): reverse the swap (targets point back
  // at old_prog, generation and derived flags restored), restore the old
  // simul_efun dispatch tables, bump the apply-cache epoch for the staged
  // program, release the staged program's commit pin + N target
  // reservations, then finalize like commit_finish(). noexcept: runs inside
  // the no-fail segment (the create phase is the only fail-able part).
  void rollback() noexcept;

 private:
  // Shared tail of commit_finish()/rollback(): drop the transaction pin on
  // old_prog (the N object references stay or are already gone depending on
  // the caller's segment) and release the snapshot add_refs. The ref
  // accounting around this tail is the most fragile part of the
  // transaction; it lives here so both success and failure paths cannot
  // drift apart. tag distinguishes the two call sites in free_object().
  void release_pin_and_snapshot_refs(const char *tag) noexcept;
};

// Compile the blueprint's source file into a staging program, WITHOUT
// touching the live object. Fails with a stable error on read/compile
// failure. Inherits not already loaded are a prepare error (v1 never loads
// inherits inside the transaction).
StagedProgram compile_program_for_recompile(object_t *blueprint);

// Wire the transaction's entry segment exactly like f_recompile_object:
// pin the old program (ref++ transaction pin), decide the kind, run the
// simul_efun dispatch preparation when kind == SimulEfun, pre-build the
// staged program's apply lookup table while still frozen (v0.4 §9.3), and
// freeze the target set. The staging program must already be assigned to
// prepared->staged. Callers must not hand-roll this wiring (pin accounting
// and per-kind preparation live here only).
void start_recompile_transaction(object_t *ob, RecompileTargetKind kind,
                                 RecompilePrepared *prepared);

// #1247 B-S3: build the per-target PreparedVariableMigration blocks in the
// fallible frozen segment, per the kind's lifecycle policy (allocation
// allowed). Must be called after start_recompile_transaction() and before
// commit_swap(). No-op when the policy never migrates.
void prepare_variable_migrations(RecompilePrepared *prepared);

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
