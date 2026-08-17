#include "base/std.h"

#include "vm/internal/simul_efun.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include "vm/internal/apply.h"
#include "vm/internal/base/machine.h"
#include "vm/internal/simulate.h"
#include "compiler/internal/lex.h"  // for ident_hash_elem_t etc, fix me!

/*
 * This file rewritten by Beek because it was inefficient and slow.  We
 * now keep track of two mappings:
 *     name -> index       and     index -> function
 *
 * index->function is used at runtime since it's very fast.  name->index
 * is used at compile time.  It's sorted so we can search it in O(log n)
 * as opposed to a linear search on the function table.  Note that we
 * can't sort the function table b/c then indices wouldn't be preserved
 * across updates.
 *
 * note, the name list holds names for past and present simul_efuns and
 * is now sorted for finding entries faster etc.  The identifier hash
 * table is used at compile time.
 */

simul_entry *simul_names = nullptr;
function_lookup_info_t *simuls = nullptr;
int num_simul_efun = 0;
object_t *simul_efun_ob;

static void find_or_add_simul_efun(function_t * /*funp*/, int /*runtime_index*/);
static void remove_simuls(void);

// Sorted-name insertion shared by the online builder (find_or_add_simul_efun)
// and the two-phase recompile path (simul_efuns_prepare): binary-search the
// sorted name list (identity order), update an existing same-name entry, or
// insert a new one.
//
// Key discipline: names/idents are position-keyed (the sorted table used for
// binary search), funcs is DISPATCH-INDEX-keyed (simuls[sindex] at runtime)
// and is NEVER shifted -- a new entry always lands at funcs[count], with the
// dispatch index being the cumulative count. Only names/idents shift on a
// middle insert.
//
// Returns the new entry's sorted position (>= 0) on insert, or -1 - index on
// a same-name update, where index is the entry's stable dispatch index.
static int add_simul_entry(simul_entry *names, function_lookup_info_t *funcs, void **idents,
                           int count, function_t *funp, int runtime_index) {
  int first = 0;
  int last = count - 1;
  while (first <= last) {
    int j = ((first + last) >> 1);
    if (funp->funcname < names[j].name) {
      last = j - 1;
    } else if (funp->funcname > names[j].name) {
      first = j + 1;
    } else {
      funcs[names[j].index].index = runtime_index;
      funcs[names[j].index].func = funp;
      return -1 - names[j].index;
    }
  }
  for (int i = count - 1; i > last; i--) {
    names[i + 1] = names[i];
    if (idents) {
      idents[i + 1] = idents[i];
    }
  }
  funcs[count].index = runtime_index;
  funcs[count].func = funp;
  names[first].name = funp->funcname;
  names[first].index = count;
  return first;
}

#ifdef DEBUGMALLOC_EXTENSIONS
void mark_simuls() {
  int i;

  for (i = 0; i < num_simul_efun; i++) {
    EXTRA_REF(BLOCK(simul_names[i].name))++;
  }
}
#endif

/*
 * If there is a simul_efun file, then take care of it and extract all
 * information we need.
 */
void init_simul_efun(const char *file) {
  char buf[512];
  object_t *new_ob;

  if (!file || !file[0]) {
    debug_message("No simul_efun\n");
    return;
  }
  if (!filename_to_obname(file, buf, sizeof(buf) - 2)) {
    error("Illegal simul_efun file name '%s'\n", file);
  }

  const size_t file_length = strlen(file);
  if (file_length < 2 || file[file_length - 2] != '.' || file[file_length - 1] != 'c') {
    strcat(buf, ".c");
  }

  new_ob = load_object(buf, 1);
  if (new_ob == nullptr) {
    debug_message("The simul_efun file %s was not loaded.\n", buf);
    exit(-1);
  }
  set_simul_efun(new_ob);
}

// Ident-hash activation primitives shared by every table rebuild path
// (online builder, prepare/activate, rollback, and the test restore
// helpers). The inactivate guard (simul_num != -1) makes the mirror exact
// by construction: only an entry that was activated may be deactivated, so
// a name dropped by an earlier reload (inert orphan, simul_num -1) is never
// touched on either side.
static void inactivate_ident(ident_hash_elem_t *ihe) {
  if (ihe->dn.simul_num != -1) {
    ihe->sem_value--;
  }
  ihe->dn.simul_num = -1;
  ihe->token &= ~IHE_SIMUL;
  ihe->token |= IHE_ORPHAN;
}

static void activate_ident(ident_hash_elem_t *ihe, int sim_idx) {
  ihe->token |= IHE_SIMUL;
  ihe->token &= ~IHE_ORPHAN;
  ihe->sem_value++;
  ihe->dn.simul_num = sim_idx;
}

static void remove_simuls() {
  int i;
  ident_hash_elem_t *ihe;
  /* inactivate all old simul_efuns */
  for (i = 0; i < num_simul_efun; i++) {
    simuls[i].index = 0;
    simuls[i].func = nullptr;
  }
  for (i = 0; i < num_simul_efun; i++) {
    if ((ihe = lookup_ident(simul_names[i].name))) {
      inactivate_ident(ihe);
    }
  }
}

static void get_simul_efuns(program_t *prog) {
  int i;
  int num_new = prog->num_functions_defined + prog->last_inherited;

  if (num_simul_efun) {
    remove_simuls();
    if (!num_new) {
      FREE(simul_names);
      FREE(simuls);
      num_simul_efun = 0;
    } else {
      /* will be resized later */
      simul_names =
          RESIZE(simul_names, num_simul_efun + num_new, simul_entry, TAG_SIMULS, "get_simul_efuns");
      simuls = RESIZE(simuls, num_simul_efun + num_new, function_lookup_info_t, TAG_SIMULS,
                      "get_simul_efuns: 2");
    }
  } else {
    if (num_new) {
      simul_names = reinterpret_cast<simul_entry *>(
          DCALLOC(num_new, sizeof(simul_entry), TAG_SIMULS, "get_simul_efuns"));
      simuls = reinterpret_cast<function_lookup_info_t *>(
          DCALLOC(num_new, sizeof(function_lookup_info_t), TAG_SIMULS, "get_simul_efuns: 2"));
    }
  }
  for (i = 0; i < num_new; i++) {
    if (prog->function_flags[i] & (FUNC_NO_CODE | DECL_PROTECTED | DECL_PRIVATE | DECL_HIDDEN)) {
      continue;
    }

    find_or_add_simul_efun(find_func_entry(prog, i), i);
  }

  if (num_simul_efun) {
    /* shrink to fit */
    simul_names = RESIZE(simul_names, num_simul_efun, simul_entry, TAG_SIMULS, "get_simul_efuns");
    simuls = RESIZE(simuls, num_simul_efun, function_lookup_info_t, TAG_SIMULS, "get_simul_efuns");
  }
}

/*
 * Define a new simul_efun (online builder, live tables)
 */
static void find_or_add_simul_efun(function_t *funp, int runtime_index) {
  int r = add_simul_entry(simul_names, simuls, nullptr, num_simul_efun, funp, runtime_index);
  int sim_idx;
  if (r < 0) {
    sim_idx = -1 - r;  // same-name entry updated; its dispatch index survives
  } else {
    sim_idx = num_simul_efun;  // fresh entry: dispatch index = cumulative count
    ref_string(funp->funcname);
  }
  ident_hash_elem_t *ihe = find_or_add_perm_ident(funp->funcname);
  activate_ident(ihe, sim_idx);
  if (r >= 0) {
    num_simul_efun++;
  }
}

void simul_efuns_prepare(program_t *prog, simul_efun_prepared_t *out) {
  *out = {};
  int num_new = prog->num_functions_defined + prog->last_inherited;
  if (!num_new && !num_simul_efun) {
    return;
  }

  // Cumulative-table semantics (same as the online get_simul_efuns): the
  // dispatch index of a name is assigned once and never recycled, so every
  // already-compiled caller's hardcoded F_SIMUL_EFUN sindex stays valid
  // across reloads. The shadow table starts as a clone of the live table
  // with all func slots cleared (a name the new program no longer provides
  // stays in the table, inactive, instead of shifting indices); then the
  // new program's functions update their same-name entries in place (same
  // dispatch index) or insert fresh ones at their sorted name position
  // (dispatch index = cumulative count; the sorted table shifts, the
  // dispatch-keyed funcs array never does).
  int capacity = num_simul_efun + num_new;
  simul_entry *names = reinterpret_cast<simul_entry *>(
      DCALLOC(capacity, sizeof(simul_entry), TAG_SIMULS, "simul_efuns_prepare"));
  function_lookup_info_t *funcs = reinterpret_cast<function_lookup_info_t *>(
      DCALLOC(capacity, sizeof(function_lookup_info_t), TAG_SIMULS, "simul_efuns_prepare: 2"));
  void **idents = reinterpret_cast<void **>(
      DCALLOC(capacity, sizeof(void *), TAG_SIMULS, "simul_efuns_prepare: 3"));

  int count = 0;
  for (int i = 0; i < num_simul_efun; i++) {
    names[count] = simul_names[i];  // name + stable dispatch index survive
    funcs[count].func = nullptr;    // inactive until the new program provides it
    funcs[count].index = 0;
    // Resolve every ident slot here in the allocatable segment. Old names
    // are resident with sem_value >= 1 (nothing decremented yet), so this
    // is a pure lookup that cannot fail; a re-added name (dropped by an
    // earlier build) is re-resolved to its existing perm-ident. Do NOT
    // resolve via lookup_ident in activate(): step 1's decrement leaves
    // sem_value == 0, and lookup_ident returns NULL for such entries.
    idents[count] = find_or_add_perm_ident(simul_names[i].name);
    count++;
  }

  for (int i = 0; i < num_new; i++) {
    if (prog->function_flags[i] & (FUNC_NO_CODE | DECL_PROTECTED | DECL_PRIVATE | DECL_HIDDEN)) {
      continue;
    }
    function_t *funp = find_func_entry(prog, i);
    int pos = add_simul_entry(names, funcs, idents, count, funp, i);
    if (pos < 0) {
      continue;  // same-name entry updated in place; ident already resident
    }
    // Pre-insert the identifier-hash entry now (allocation allowed here);
    // activation only writes fields on the stable element. The ident slot
    // is POSITION-keyed (idents[i] aligns with names[i]): the fresh entry
    // sits at sorted position pos while its dispatch index is count. A name
    // later abandoned by a failed transaction stays an inert perm-ident
    // (token 0, simul_num -1) for the driver lifetime -- harmless, and the
    // normal loader's ident semantics are identical.
    idents[pos] = find_or_add_perm_ident(funp->funcname);
    ref_string(funp->funcname);
    count++;
  }

  if (count) {
    names = RESIZE(names, count, simul_entry, TAG_SIMULS, "simul_efuns_prepare");
    funcs = RESIZE(funcs, count, function_lookup_info_t, TAG_SIMULS, "simul_efuns_prepare");
    idents = static_cast<void **>(
        RESIZE(idents, count, void *, TAG_SIMULS, "simul_efuns_prepare"));
  } else {
    FREE(names);
    FREE(funcs);
    FREE(idents);
    return;
  }
  out->names = names;
  out->funcs = funcs;
  out->idents = idents;
  out->count = count;
}

void simul_efuns_activate(simul_efun_prepared_t *p) noexcept {
  // 1. Inactivate the old identifiers first (pure field writes, same as
  //    remove_simuls): clear IHE_SIMUL, mark orphan, drop simul_num/sem.
  //    Order matters: a name present in both tables nets sem_value 0 here
  //    and +1 in step 3 (mirror of the normal path's remove-then-insert).
  for (int i = 0; i < num_simul_efun; i++) {
    ident_hash_elem_t *ihe = lookup_ident(simul_names[i].name);
    if (ihe) {
      inactivate_ident(ihe);
    }
  }

  // 2. Swap in the shadow arrays. The OLD live tables stay alive: they are
  //    handed to the prepared structure so the transaction's create phase
  //    can roll back (swap them back) or finalize (free them here in
  //    finish()). free() only -- no allocation.
  p->old_names = simul_names;
  p->old_funcs = simuls;
  p->old_count = num_simul_efun;
  simul_names = static_cast<simul_entry *>(p->names);
  simuls = static_cast<function_lookup_info_t *>(p->funcs);
  num_simul_efun = p->count;

  // 3. Activate the entries the new program provides (dispatch-keyed func
  //    non-null), pure field writes mirroring the online builder. The loop
  //    iterates POSITION-keyed (names/idents) while funcs is DISPATCH-keyed:
  //    position != dispatch index in general (sorted name table vs
  //    cumulative index assignment), so every func access goes through
  //    simul_names[i].index. Entries with func null are dropped names: they
  //    stay inactive, and callers holding their old sindex get the stable
  //    "no longer a simul_efun" error instead of an out-of-bounds read.
  //    Every ident slot [0, count) was pre-resolved by prepare() -- there
  //    is deliberately no lookup_ident fallback here, because step 1's
  //    decrement leaves sem_value == 0 and lookup_ident returns NULL for
  //    such entries (assert guards regressions).
  for (int i = 0; i < num_simul_efun; i++) {
    int sim_idx = simul_names[i].index;
    if (!simuls[sim_idx].func) {
      continue;
    }
    ident_hash_elem_t *ihe = static_cast<ident_hash_elem_t *>(p->idents[i]);
    assert(ihe != nullptr);
    activate_ident(ihe, sim_idx);
  }

  // Ownership moved into the live tables; the old tables are held by
  // p->old_* until finish()/rollback() decides their fate.
  p->names = nullptr;
  p->funcs = nullptr;
  p->idents = nullptr;
  p->count = 0;
  p->state = simul_efun_prepared_t::State::Activated;
}

void simul_efuns_finish(simul_efun_prepared_t *p) noexcept {
  // Create phase succeeded: the OLD tables are the loser, free them.
  if (p->state != simul_efun_prepared_t::State::Activated) {
    return;
  }
  if (p->old_names) {
    FREE(p->old_names);
  }
  if (p->old_funcs) {
    FREE(p->old_funcs);
  }
  p->old_names = nullptr;
  p->old_funcs = nullptr;
  p->old_count = 0;
  p->state = simul_efun_prepared_t::State::Finalized;
}

void simul_efuns_rollback(simul_efun_prepared_t *p) noexcept {
  if (p->state != simul_efun_prepared_t::State::Activated) {
    return;
  }
  // 1. Deactivate every entry the new (currently live) table activated:
  //    mirror of activate step 3, reversed. These entries have sem_value 1
  //    (step 3 incremented them), so lookup_ident() still hits, but guard
  //    with find_or_add_perm_ident anyway (dropped entries with func null
  //    were never activated and may sit at sem_value 0).
  for (int i = 0; i < num_simul_efun; i++) {
    int sim_idx = simul_names[i].index;
    if (!simuls[sim_idx].func) {
      continue;
    }
    ident_hash_elem_t *ihe = lookup_ident(simul_names[i].name);
    if (!ihe) {
      ihe = find_or_add_perm_ident(simul_names[i].name);
    }
    if (ihe) {
      inactivate_ident(ihe);
    }
  }
  // 2. Restore the old table's entries (mirror of activate step 1,
  //    reversed). Ident lookup MUST NOT use lookup_ident() here: after
  //    step 1 the shared names have sem_value 0 (the CHECK_ELEM trap). The
  //    perm-ident elements survive; find_or_add_perm_ident resolves them
  //    with zero allocation. Mirror of activate step 3: only entries with a
  //    live func slot are activated -- dropped names (func null) stay
  //    inert orphans, exactly the state the previous transaction left them
  //    in.
  simul_entry *old = static_cast<simul_entry *>(p->old_names);
  function_lookup_info_t *old_funcs = static_cast<function_lookup_info_t *>(p->old_funcs);
  for (int i = 0; i < p->old_count; i++) {
    if (!old_funcs[old[i].index].func) {
      continue;
    }
    ident_hash_elem_t *ihe = find_or_add_perm_ident(old[i].name);
    if (ihe) {
      activate_ident(ihe, old[i].index);
    }
  }
  // 3. Free the new tables, swap the old ones back. free() only -- still
  //    within the no-fail segment.
  if (num_simul_efun) {
    FREE(simul_names);
    FREE(simuls);
  }
  simul_names = static_cast<simul_entry *>(p->old_names);
  simuls = static_cast<function_lookup_info_t *>(p->old_funcs);
  num_simul_efun = p->old_count;
  p->old_names = nullptr;
  p->old_funcs = nullptr;
  p->old_count = 0;
  p->state = simul_efun_prepared_t::State::Finalized;
}

void simul_efuns_discard(simul_efun_prepared_t *p) noexcept {
  // Prepared: release the shadow arrays (nothing is live yet).
  // Activated (defensive -- the transaction always calls finish()/rollback()
  // before destruction): the new tables are live and must stay; release the
  // held old tables only.
  // Finalized: no-op.
  if (p->state == simul_efun_prepared_t::State::Prepared) {
    if (p->names) {
      FREE(p->names);
    }
    if (p->funcs) {
      FREE(p->funcs);
    }
    if (p->idents) {
      FREE(p->idents);
    }
  } else if (p->state == simul_efun_prepared_t::State::Activated) {
    if (p->old_names) {
      FREE(p->old_names);
    }
    if (p->old_funcs) {
      FREE(p->old_funcs);
    }
  }
  *p = {};
}

void set_simul_efun(object_t *ob) {
  get_simul_efuns(ob->prog);

  simul_efun_ob = ob;
  add_ref(simul_efun_ob, "set_simul_efun");
}

void call_simul_efun(unsigned short index, int num_arg) {
  extern object_t *simul_efun_ob;

  if (current_object->flags & O_DESTRUCTED) { /* No external calls allowed */
    pop_n_elems(num_arg);
    push_undefined();
    return;
  }

  if (simuls[index].func) {
    /* Don't need to use apply() since we have the pointer directly;
     * this saves function lookup.
     */
    call_direct(simul_efun_ob, simuls[index].index, ORIGIN_SIMUL_EFUN, num_arg);
  } else {
    error("Function is no longer a simul_efun.\n");
  }
}
