#ifndef SIMUL_EFUN_H
#define SIMUL_EFUN_H

/*
 * simul_efun.c
 */

extern struct object_t *simul_efun_ob;
extern struct function_lookup_info_t *simuls;

// Live dispatch tables (extern for tests; owned by simul_efun.cc).
// names is the sorted position-keyed table (binary search), funcs is the
// DISPATCH-INDEX-keyed table (simuls[sindex] at runtime); a name's stable
// dispatch index is simul_names[position].index and is never recycled.
struct simul_entry {
  const char *name;
  short index;
};
extern simul_entry *simul_names;
extern int num_simul_efun;

void init_simul_efun(const char *);
void set_simul_efun(struct object_t *);

#ifdef DEBUGMALLOC_EXTENSIONS
void mark_simuls(void);
#endif

void call_simul_efun(unsigned short, int);

/*
 * Two-phase simul_efun dispatch rebuild for the recompile_object()
 * transaction (v2 design Phase 1): simul_efuns_prepare() runs in the
 * allocatable frozen segment -- it builds shadow dispatch arrays from a
 * staging program and pre-inserts identifier-hash entries (allocation
 * allowed); simul_efuns_activate() runs inside the no-fail commit segment
 * -- pure ident field writes plus pointer swap, no allocation, no error.
 * simul_efuns_discard() releases a prepared-but-uncommitted build and is a
 * no-op after activation (ownership moved into the live tables).
 *
 * KEY DISCIPLINE (position key vs dispatch index key):
 * - names/idents are POSITION-keyed: simul_names is the sorted name table
 *   for binary search, and idents[i] aligns with names[i].
 * - funcs is DISPATCH-INDEX-keyed: runtime dispatch reads simuls[sindex],
 *   and funcs is never shifted -- a fresh entry always lands at
 *   funcs[count], its dispatch index being the cumulative count.
 * - position != dispatch index in general (the sorted table permutes the
 *   declaration order); every func access must go through
 *   simul_names[position].index.
 * Cumulative-table invariants: a name's dispatch index is assigned once and
 * never recycled (already-compiled callers embed it in F_SIMUL_EFUN); a
 * dropped name stays in the table with func null, inactive. prepare()
 * pre-resolves EVERY ident slot (old names, re-added names and fresh names
 * alike) while sem_value is still >= 1; activate() must not fall back to
 * lookup_ident -- after its own step 1 decrement, sem_value is 0 and
 * lookup_ident returns NULL for such entries.
 *
 * Pointer members are void* so this header stays free of compiler-internal
 * types; the owning translation unit casts.
 */
struct simul_efun_prepared_t {
  void *names{nullptr};   // simul_entry* shadow array
  void *funcs{nullptr};   // function_lookup_info_t* shadow array
  void **idents{nullptr}; // ident_hash_elem_t* per entry, pre-inserted
  int count{0};
  bool active{false};
};

void simul_efuns_prepare(struct program_t *prog, simul_efun_prepared_t *out);
void simul_efuns_activate(simul_efun_prepared_t *p) noexcept;
void simul_efuns_discard(simul_efun_prepared_t *p) noexcept;

#endif
