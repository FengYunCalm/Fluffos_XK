// E3 recompile_object() transaction subsystem (v0.4 §8/§9).
//
// Owned by this translation unit; simulate.cc / efuns_main.cc consume the
// API in recompile.h. Resource ownership for a prepared transaction lives
// entirely inside RecompilePrepared: commit() swaps and releases, the
// destructor cleans up a failed preparation. Callers must not hand-release
// targets or pins.

#include "vm/internal/recompile.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>   // for O_RDONLY, open
#include <unistd.h>  // for close
#include <string>
#include <vector>

#include "base/package_api.h"
#include "vm/internal/base/apply_cache.h"
#include "vm/internal/base/interpret.h"
#include "vm/internal/base/object.h"
#include "vm/internal/base/program.h"
#include "vm/internal/simulate.h"  // obj_list, destruct_object, error machinery
#include "packages/core/replace_program.h"

// ---------------------------------------------------------------------------
// Staging compile (v0.4 §8.1)
// ---------------------------------------------------------------------------

StagedProgram compile_program_for_recompile(object_t *blueprint) {
  if (!blueprint || (blueprint->flags & O_DESTRUCTED) || !blueprint->prog) {
    error("recompile_object: invalid blueprint\n");
  }
  std::string load_name = blueprint->obname ? blueprint->obname : "";
  if (load_name.empty()) {
    error("recompile_object: blueprint has no source path\n");
  }
  std::string source_path = load_name;
  if (source_path.size() >= 2 && source_path.compare(source_path.size() - 2, 2, ".c") == 0) {
    source_path.resize(source_path.size() - 2);
  }

  char real_name[PATH_MAX];
  char obname[PATH_MAX];
  (void)strcpy(real_name, source_path.c_str());
  (void)strcat(real_name, ".c");
  (void)strcpy(obname, source_path.c_str());
  (void)strcat(obname, ".c");

  int f = open(real_name, O_RDONLY);
  // #1247-equivalent SIMULATE-1 (upstream DEFER close in recompile_object):
  // both error paths and the success path below close(f) explicitly.
  if (f == -1) {
    debug_perror("recompile_object compile", real_name);
    error("recompile_object: cannot read '/%s'\n", real_name);
  }
  if (!legal_path(real_name)) {
    close(f);
    error("recompile_object: illegal path '/%s'\n", real_name);
  }

  error_context_t econ{};
  save_context(&econ);
  program_t *prog = nullptr;
  try {
    auto stream = std::make_unique<FileLexStream>(f);
    prog = compile_file(std::move(stream), obname);
  } catch (const char *) {
    close(f);
    restore_context(&econ);
    pop_context(&econ);
    error("recompile_object: compile failed\n");
  } catch (...) {
    close(f);
    restore_context(&econ);
    pop_context(&econ);
    error("recompile_object: compile failed\n");
  }
  pop_context(&econ);
  close(f);

  if (!prog) {
    error("recompile_object: compile failed\n");
  }
  return StagedProgram(prog);
}

// ---------------------------------------------------------------------------
// Layout descriptor (v0.4 §8.2)
// ---------------------------------------------------------------------------

namespace {
void walk_layout(program_t *prog, int *next_slot, RecompileLayout *out, std::string *digest) {
  for (int i = 0; i < prog->num_inherited; i++) {
    inherit_t &inh = prog->inherit[i];
    std::string nested_digest;
    if (inh.prog) {
      walk_layout(inh.prog, next_slot, out, &nested_digest);
    }
    RecompileLayoutInherit entry;
    entry.slot = *next_slot;
    entry.filename = inh.prog && inh.prog->filename ? inh.prog->filename : "";
    entry.nested_digest = std::move(nested_digest);
    out->inherits.push_back(std::move(entry));
    if (digest) {
      digest->append(entry.filename);
      digest->append("|");
    }
  }
  for (int i = 0; i < prog->num_variables_defined; i++) {
    const char *name = prog->variable_table ? prog->variable_table[i] : "";
    int type = prog->variable_types ? prog->variable_types[i] : 0;
    RecompileLayoutVariable v;
    v.slot = (*next_slot)++;
    v.name = name ? name : "";
    v.full_decl_type = type;
    out->variables.push_back(std::move(v));
    if (digest) {
      digest->append(v.name);
      digest->append(":");
      digest->append(std::to_string(type));
      digest->append("|");
    }
  }
}
}  // namespace

RecompileLayout describe_recompile_layout(program_t *prog) {
  RecompileLayout out;
  int slot = 0;
  std::string digest;
  walk_layout(prog, &slot, &out, &digest);
  out.num_variables_total = slot;
  return out;
}

bool recompile_layouts_match(const RecompileLayout &a, const RecompileLayout &b,
                             std::string *first_diff) {
  if (a.num_variables_total != b.num_variables_total) {
    if (first_diff) *first_diff = "num_variables_total";
    return false;
  }
  if (a.variables.size() != b.variables.size()) {
    if (first_diff) *first_diff = "variables.size";
    return false;
  }
  for (size_t i = 0; i < a.variables.size(); i++) {
    const auto &va = a.variables[i];
    const auto &vb = b.variables[i];
    if (va.slot != vb.slot || va.name != vb.name || va.full_decl_type != vb.full_decl_type) {
      if (first_diff) {
        *first_diff = "variable[" + std::to_string(i) + "] " + va.name + " != " + vb.name;
      }
      return false;
    }
  }
  if (a.inherits.size() != b.inherits.size()) {
    if (first_diff) *first_diff = "inherits.size";
    return false;
  }
  for (size_t i = 0; i < a.inherits.size(); i++) {
    const auto &ia = a.inherits[i];
    const auto &ib = b.inherits[i];
    if (ia.slot != ib.slot || ia.filename != ib.filename || ia.nested_digest != ib.nested_digest) {
      if (first_diff) {
        *first_diff = "inherit[" + std::to_string(i) + "] " + ia.filename + " != " + ib.filename;
      }
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Frozen target snapshot (v0.4 §8.3)
// ---------------------------------------------------------------------------

void snapshot_recompile_targets(object_t *blueprint, RecompilePrepared *prepared) {
  if (!blueprint || (blueprint->flags & O_DESTRUCTED) || !blueprint->prog) {
    error("recompile_object: invalid blueprint\n");
  }
  program_t *old_prog = blueprint->prog;

  // The top-level frame's csp->prog holds the CALLER's program (captured at
  // push_control_stack() time), so walking frames alone misses the target
  // program executing at the top level -- e.g. a member of the blueprint
  // family calling recompile_object() on itself. Check the VM's current
  // program explicitly, then walk the remaining frames for nested frames.
  if (current_prog == old_prog) {
    error("recompile_object target program is executing\n");
  }
  for (control_stack_t *frame = csp; frame && frame >= control_stack; frame--) {
    if (frame->prog == old_prog) {
      error("recompile_object target program is executing\n");
    }
  }

  int found = 0;
  for (object_t *ob = obj_list; ob; ob = ob->next_all) {
    if (ob->prog != old_prog) continue;
    if (ob->flags & O_DESTRUCTED) continue;
    if (ob->shadowing || ob->shadowed) {
      error("recompile_object target is shadowing or shadowed\n");
    }
    if (replace_program_pending(ob)) {
      error("recompile_object target has a pending replace_program()\n");
    }
    RecompileTarget t;
    t.ob = ob;
    add_ref(ob, "recompile_prepared");
    uint32_t derived = 0;
    if (function_exists(APPLY_CLEAN_UP, ob, 1)) {
      derived |= O_WILL_CLEAN_UP;
    }
    t.precomputed_flags = derived;
    prepared->targets.push_back(std::move(t));
    found++;
  }
  if (found == 0) {
    error("recompile_object: blueprint not found in object list\n");
  }
}

// ---------------------------------------------------------------------------
// No-fail commit + full resource release (v0.4 §9.1/§9.2)
// ---------------------------------------------------------------------------

RecompilePrepared::~RecompilePrepared() {
  // Failure-path cleanup only: after commit_finish()/rollback(), targets
  // have been cleared and the old-program pin released, so this is a no-op
  // there. The staged program's initial ref is released here too (rollback()
  // already released the commit pin + N reservations).
  for (auto &t : targets) {
    if (t.ob) free_object(&t.ob, "recompile_prepared");
  }
  if (old_prog) free_prog(&old_prog);
  if (kind == RecompileTargetKind::SimulEfun) {
    simul_efuns_discard(&simuls);
  }
}

void RecompilePrepared::commit_swap() noexcept {
  program_t *new_prog = staged.prog;
  // A transaction without a staged program is a caller bug: commit_swap()
  // must never silently skip the swap (commit_finish() would then release
  // N old_prog references while the targets still point at old_prog, orphaning
  // live objects). assert, not error(): this is a noexcept segment.
  assert(new_prog != nullptr);
  new_prog->ref++;  // commit pin

  constexpr uint32_t kProgramDerivedFlags = O_WILL_CLEAN_UP;
  // v0.4 §9.1: every target now holds a reference to new_prog (objects free
  // their program reference on dealloc). Accounted before any swap.
  for (auto &t : targets) {
    if (t.ob) new_prog->ref++;
  }
  for (auto &t : targets) {
    if (!t.ob) continue;
    t.old_generation = t.ob->prog_generation;  // rollback() restores this
    t.ob->prog = new_prog;
    t.ob->prog_generation++;
    t.ob->flags = (t.ob->flags & ~kProgramDerivedFlags) | t.precomputed_flags;
  }

  // v2 design Phase 1: the apply lookup cache is keyed per program; every
  // target shared old_prog, so one explicit invalidation covers them all.
  // (v1 only invalidated indirectly, via deallocate_program -- this is the
  // contract-level invalidation. Pure epoch bump, no allocation.)
  apply_cache_invalidate_program(old_prog);

  // v2 design Phase 1: simul_efun dispatch activation (no-fail: ident field
  // writes + pointer swap + free() only). Cumulative-table semantics keep
  // every already-compiled caller's sindex valid; dropped names stay in the
  // table, inactive. The OLD live tables are handed to simuls alive (not
  // freed): the create phase may still need to roll them back.
  if (kind == RecompileTargetKind::SimulEfun) {
    simul_efuns_activate(&simuls);
  }
}

void RecompilePrepared::run_create() {
  // BlueprintFamily has no create phase (v1 semantics: ordinary blueprints
  // and clones keep their old behavior). The kind discriminant lives inside
  // the transaction so no caller can silently skip the create segment for
  // a new kind -- a new kind must decide here explicitly.
  if (kind == RecompileTargetKind::BlueprintFamily) {
    return;
  }
  // v2 Phase 2: __INIT + create() on the special targets while admission
  // stays closed. Any error -- from __INIT, create(), or the interpreter --
  // propagates as a C++ exception (plain apply() does not swallow errors)
  // and must end in rollback() at the caller; a target that destructs
  // itself during create is a stable error too.
  for (auto &t : targets) {
    if (!t.ob) continue;
    call_create(t.ob, 0);
    if (t.ob->flags & O_DESTRUCTED) {
      error("recompile_object: target destructed during create()\n");
    }
  }
}

bool RecompilePrepared::run_create_guarded() {
  error_context_t econ{};
  save_context(&econ);
  try {
    run_create();
  } catch (const char *) {
    restore_context(&econ);
    pop_context(&econ);
    // rollback() is noexcept (free()/field writes only) and does not
    // depend on interpreter state -- safe after restore, per the
    // safe_apply convention.
    rollback();
    return false;
  }
  pop_context(&econ);
  return true;
}

void start_recompile_transaction(object_t *ob, RecompileTargetKind kind,
                                 RecompilePrepared *prepared) {
  prepared->kind = kind;
  prepared->old_prog = ob->prog;
  prepared->old_prog->ref++;  // transaction pin
  if (kind == RecompileTargetKind::SimulEfun) {
    // simul_efun dispatch rebuild -- frozen-segment preparation. Shadow
    // arrays and identifier-hash pre-inserts happen here (allocation
    // allowed); the no-fail activation runs inside commit_swap().
    simul_efuns_prepare(prepared->staged.prog, &prepared->simuls);
  }
  // Apply lookup table must be fully built while still frozen (v0.4
  // §9.3): the commit segments are no-fail and must not allocate, and the
  // no-fail swap relies on the staged program's table being ready.
  // (Allocation allowed here, in the frozen-segment preparation.)
  prepare_apply_lookup_table(prepared->staged.prog);
  snapshot_recompile_targets(ob, prepared);
}

void RecompilePrepared::commit_finish() noexcept {
  // Create phase succeeded: the old simul_efun dispatch tables (handed over
  // alive by activate so a failed create could restore them) are the loser
  // -- free them.
  if (kind == RecompileTargetKind::SimulEfun) {
    simul_efuns_finish(&simuls);
  }

  // Release the N old-program references held by the targets. The
  // transaction pin keeps old_prog alive until this loop.
  for (size_t i = 0; i < targets.size(); i++) {
    program_t *old_ref = old_prog;
    free_prog(&old_ref);
  }

  // Drop the commit pin; the targets now hold the new program's refs.
  program_t *staged_pin = staged.prog;
  free_prog(&staged_pin);

  // Release the transaction pin on old_prog: the N object references are
  // already gone above; this final free_prog may deallocate old_prog unless
  // a funptr/inheritor still pins it via func_ref. (No allocation, no error
  // -- still within the no-fail segment.)
  release_pin_and_snapshot_refs("recompile_commit");
}

void RecompilePrepared::release_pin_and_snapshot_refs(const char *tag) noexcept {
  program_t *pin = old_prog;
  old_prog = nullptr;
  free_prog(&pin);

  // Release the snapshot add_refs (objects are live and keep their
  // identity; the refs were for snapshot stability only).
  for (auto &t : targets) {
    if (t.ob) {
      object_t *snap = t.ob;
      t.ob = nullptr;
      free_object(&snap, tag);
    }
  }
}


void RecompilePrepared::rollback() noexcept {
  program_t *new_prog = staged.prog;
  // Reverse swap: targets point back at old_prog (their references never
  // left it -- the swap only redirected the pointer). Generation and
  // derived flags are restored so the object is exactly in its pre-swap
  // state; funptrs bound during the create phase carry the swap-era
  // generation and stay rejected, like any reload.
  constexpr uint32_t kProgramDerivedFlags = O_WILL_CLEAN_UP;
  for (auto &t : targets) {
    if (!t.ob) continue;
    t.ob->prog = old_prog;
    t.ob->prog_generation = t.old_generation;
    t.ob->flags = (t.ob->flags & ~kProgramDerivedFlags) | t.precomputed_flags;
  }

  // Restore the old simul_efun dispatch tables: ident fields mirrored
  // back, pointers swapped back in, new tables freed.
  if (kind == RecompileTargetKind::SimulEfun) {
    simul_efuns_rollback(&simuls);
  }

  // Cache epoch bump: the staged program's apply table must never be used
  // again; the old program's table rebuilds on the next lookup.
  apply_cache_invalidate_program(new_prog);

  // Release the new program: the commit pin (1) plus the per-target
  // reservations (N). staged.prog's own initial ref is released by the
  // destructor, which then deallocates it.
  for (size_t i = 0; i <= targets.size(); i++) {
    program_t *p = new_prog;
    free_prog(&p);
  }

  // Same finalization as commit_finish(): drop the transaction pin on
  // old_prog (the N object references stay -- the objects point at it
  // again) and release the snapshot add_refs.
  release_pin_and_snapshot_refs("recompile_rollback");
}
