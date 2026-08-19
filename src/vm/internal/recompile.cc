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
#include "vm/internal/source_spelling.h"
#include "packages/core/replace_program.h"

// #1247 B-S3: per-target prepared variable migration. Ownership states are
// exactly three: (1) before publish and after finalize the OBJECT owns the
// attached payload; (2) during publish the object owns new_block's payload
// while this struct owns old_block's (detached); (3) after rollback the
// object owns old_block's payload again and this struct owns/discards
// new_block's. The destructor, commit_finish() and rollback() are the only
// releasers of detached payloads -- no path may leave both object and
// migration believing they own the same payload.
struct PreparedVariableMigration {
  ObjectVariableBlock old_block;  // detached old payload during publish
  ObjectVariableBlock new_block;  // staged payload (init/migrate applied)
  std::vector<VariableMatch> matches;
  RecompileLayoutDiff diff;
};

// #1247 B-S3: internal migration helpers (defined below; forward-declared
// so the transaction destructor/commit/rollback, which appear earlier in
// this file, can call them).
namespace {
// #1247 B-S3: copy every matched old slot into the object's ATTACHED new
// block (the migration's own new_block was moved into the object during
// commit_swap publish and is empty here). Reference copy, old slots
// untouched. noexcept: assign_svalue only bumps refcounts.
void copy_matches(PreparedVariableMigration *m, svalue_t *attached_new_data) noexcept;
void release_migration_payload(PreparedVariableMigration *m) noexcept;
}  // namespace

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
  // #1247 .lpc: derive the source extension from the compiled program's own
  // filename (prog->filename carries the extension the loader chose, e.g.
  // "/foo.lpc" for a .lpc source), instead of assuming ".c" -- otherwise
  // hot-reload of a .lpc-sourced blueprint would always fail to open.
  const char *compile_name = blueprint->prog->filename ? blueprint->prog->filename : "";
  size_t clen = strlen(compile_name);
  const char *requested_ext = nullptr;
  if (clen > 4 && strcmp(compile_name + clen - 4, ".lpc") == 0) {
    requested_ext = ".lpc";
  } else if (clen > 2 && compile_name[clen - 1] == 'c' && compile_name[clen - 2] == '.') {
    requested_ext = ".c";
  }
  // #1247 .lpc: source spelling resolved by the shared owner
  // (vm/internal/source_spelling.cc). Unlike load_object (explicit request
  // is exact), recompile always allows the .lpc -> .c fallback: a deleted
  // .lpc source must degrade to the .c twin, and recompile cannot know the
  // original request was explicit -- the loader may already have fallen
  // back, so prog->filename is authoritative only as a preference.
  const char *src_ext;
  char real_name[PATH_MAX];
  char obname[PATH_MAX];
  resolve_source_spelling(source_path.c_str(), requested_ext, true, &src_ext,
                          real_name, sizeof real_name);
  (void)strcpy(obname, source_path.c_str());
  (void)strcat(obname, src_ext);

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

RecompilePrepared::RecompilePrepared() = default;

RecompilePrepared::~RecompilePrepared() {
  // Failure-path cleanup only: after commit_finish()/rollback(), targets
  // have been cleared and the old-program pin released, so this is a no-op
  // there. The staged program's initial ref is released here too (rollback()
  // already released the commit pin + N reservations).
  for (auto &t : targets) {
    if (t.ob) free_object(&t.ob, "recompile_prepared");
  }
  // #1247 B-S3: a prepare-time failure (before commit_swap) leaves the
  // migration blocks holding their fresh payloads; release them.
  for (auto &m : migrations) {
    release_migration_payload(m.get());
  }
  migrations.clear();
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
    // #1247 B-S3: publish the prepared migration for this target: detach
    // the old payload into the migration (object temporarily owns the new
    // payload), then attach the new payload. Two moves, no allocation, no
    // fail-able code between them.
    if (migrations.size() == targets.size()) {
      size_t idx = static_cast<size_t>(&t - targets.data());
      obj_vars_move(&migrations[idx]->old_block, &t.ob->variables);
      obj_vars_move(&t.ob->variables, &migrations[idx]->new_block);
    }
    // #1247 B-S1: exact-layout transactions only (B-S3 adds migration), so
    // the attached variable block must still match the new program's
    // layout. DEBUG assertion: any future layout-changing commit must
    // migrate the block before this point, never swap prog first.
    assert(t.ob->variables.layout_id == program_layout_digest(new_prog));
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
  // #1247 B-S3: segment 2a -- prepare target state per the kind's policy:
  // __INIT and migration copy run in the policy's order (BlueprintFamily
  // InitThenMigrate, Master/SimulEfun MigrateThenInit). Any __INIT error
  // propagates as a C++ exception and must end in rollback().
  RecompileLifecycle lifecycle = recompile_lifecycle_for(kind);
  bool has_migration = migrations.size() == targets.size();
  for (size_t i = 0; i < targets.size(); i++) {
    auto &t = targets[i];
    if (!t.ob) continue;
    // #1247 B-S3: keep call_create()'s reset scheduling on the special
    // targets (call_create runs set_nextreset before __INIT; the split
    // __INIT/create path must not silently drop it).
    if (kind != RecompileTargetKind::BlueprintFamily) {
      set_nextreset(t.ob);
    }
    PreparedVariableMigration *m = has_migration ? migrations[i].get() : nullptr;
    bool run_init = false;
    switch (lifecycle.init) {
      case RecompileInitPolicy::Always:
        run_init = true;
        break;
      case RecompileInitPolicy::OnMigratableLayoutChange:
        run_init = m != nullptr;
        break;
      case RecompileInitPolicy::Never:
        run_init = false;
        break;
    }
    if (lifecycle.state_order == RecompileStateOrder::InitThenMigrate) {
      if (run_init) call___INIT(t.ob);
      if (m) copy_matches(m, obj_vars_data(&t.ob->variables));
    } else {
      if (m) copy_matches(m, obj_vars_data(&t.ob->variables));
      if (run_init) call___INIT(t.ob);
    }
  }

  // BlueprintFamily has no create phase (v1 semantics: ordinary blueprints
  // and clones keep their old behavior). The kind discriminant lives inside
  // the transaction so no caller can silently skip the create segment for
  // a new kind -- a new kind must decide here explicitly.
  if (kind == RecompileTargetKind::BlueprintFamily) {
    return;
  }
  // v2 Phase 2: create() on the special targets while admission stays
  // closed. __INIT already ran in the state-preparation step above, so the
  // create-only primitive is used -- never the __INIT+create combination.
  // Any error -- from create(), or the interpreter -- propagates as a C++
  // exception and must end in rollback(); a target that destructs itself
  // during create is a stable error too.
  for (auto &t : targets) {
    if (!t.ob) continue;
    call_create_only(t.ob, 0);
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

// #1247 B-S3: fixed per-kind lifecycle policy (the table in recompile.h).
RecompileLifecycle recompile_lifecycle_for(RecompileTargetKind kind) {
  switch (kind) {
    case RecompileTargetKind::BlueprintFamily:
      return {RecompileInitPolicy::OnMigratableLayoutChange,
              RecompileMigrationPolicy::OnMigratableLayoutChange,
              RecompileStateOrder::InitThenMigrate, RecompileCreatePolicy::Never};
    case RecompileTargetKind::Master:
    case RecompileTargetKind::SimulEfun:
      return {RecompileInitPolicy::Always, RecompileMigrationPolicy::Always,
              RecompileStateOrder::MigrateThenInit, RecompileCreatePolicy::AfterStateReady};
  }
  return {RecompileInitPolicy::Never, RecompileMigrationPolicy::None,
          RecompileStateOrder::MigrateThenInit, RecompileCreatePolicy::Never};
}

// #1247 B-S3: build the per-target PreparedVariableMigration blocks in the
// fallible frozen segment (allocation allowed). The policy decides whether
// a migration exists at all; an exact layout never creates one for
// BlueprintFamily but ALWAYS does for Master/SimulEfun (their __INIT must
// read the old state, so the new block must carry the old values before
// __INIT runs).
void prepare_variable_migrations(RecompilePrepared *prepared) {
  if (!prepared->migrations.empty()) return;  // already prepared
  RecompileLifecycle lifecycle = recompile_lifecycle_for(prepared->kind);
  if (lifecycle.migrate == RecompileMigrationPolicy::None) return;

  // Reuse the admission-time classification (single source of truth).
  // Defensive fallback: direct-driver paths (tests) that never ran the
  // admission gate get a fresh classification -- for an exact layout this
  // still yields the full identity matches the Always-migrate kinds need.
  RecompileLayoutDiff diff = prepared->admission_diff;
  if (diff.matches.empty() && diff.added.empty() && diff.removed.empty()) {
    diff = classify_recompile_layout(prepared->old_layout, prepared->new_layout);
    prepared->admission_diff = diff;
  }
  bool layout_changed =
      !prepared->old_layout.variables.empty() || !prepared->new_layout.variables.empty()
          ? !recompile_layouts_match(prepared->old_layout, prepared->new_layout, nullptr)
          : false;
  // No-op layouts (identical, no structural change) still migrate for
  // Always kinds so __INIT sees old values on an exact reload.
  if (lifecycle.migrate == RecompileMigrationPolicy::OnMigratableLayoutChange && !layout_changed) {
    return;
  }
  // Fail-closed: a diff that is not migratable must have been rejected by
  // the caller before reaching this point.
  if (!diff.migratable()) {
    error("recompile_object: layout diff is not migratable\n");
  }
  for (auto &t : prepared->targets) {
    auto m = std::make_unique<PreparedVariableMigration>();
    m->diff = diff;
    m->matches = diff.matches;
    obj_vars_init(&m->new_block, prepared->staged.prog);
    prepared->migrations.push_back(std::move(m));
    (void)t;
  }
}

namespace {
// #1247 B-S3: copy every matched old slot into the object's attached new
// block (reference copy, old slots untouched). noexcept: assign_svalue
// only bumps refcounts.
void copy_matches(PreparedVariableMigration *m, svalue_t *attached_new_data) noexcept {
  for (const auto &match : m->matches) {
    assign_svalue(&attached_new_data[match.new_slot], &m->old_block.data[match.old_slot]);
  }
}

// #1247 B-S3: release a detached migration payload's svalue contents and
// the payload allocation. Safe on empty blocks (post-publish new_block,
// post-rollback old_block).
void release_migration_payload(PreparedVariableMigration *m) noexcept {
  if (m->old_block.data) {
    for (uint32_t i = 0; i < m->old_block.count; i++) {
      free_svalue(&m->old_block.data[i], "recompile_migration");
    }
    obj_vars_destroy(&m->old_block);
  }
  if (m->new_block.data) {
    for (uint32_t i = 0; i < m->new_block.count; i++) {
      free_svalue(&m->new_block.data[i], "recompile_migration");
    }
    obj_vars_destroy(&m->new_block);
  }
}
}  // namespace

void RecompilePrepared::commit_finish() noexcept {
  // Create phase succeeded: the old simul_efun dispatch tables (handed over
  // alive by activate so a failed create could restore them) are the loser
  // -- free them.
  if (kind == RecompileTargetKind::SimulEfun) {
    simul_efuns_finish(&simuls);
  }

  // #1247 B-S3: release the detached old migration payloads (their values
  // were reference-copied into the new blocks during state preparation;
  // the new payloads are attached to the objects and empty here).
  for (auto &m : migrations) {
    release_migration_payload(m.get());
  }
  migrations.clear();

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

  // #1247 B-S3: reverse the migration publish: detach the new payload from
  // the object back into the migration (owned by us again) and re-attach
  // the old payload. Then release both payloads' contents -- the new one
  // may carry __INIT/migration writes that must be discarded, the old one
  // is empty (it was moved back out).
  if (migrations.size() == targets.size()) {
    for (size_t i = 0; i < targets.size(); i++) {
      auto &t = targets[i];
      if (!t.ob) continue;
      auto &m = migrations[i];
      obj_vars_move(&m->new_block, &t.ob->variables);
      obj_vars_move(&t.ob->variables, &m->old_block);
    }
    for (auto &m : migrations) {
      release_migration_payload(m.get());
    }
    migrations.clear();
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
