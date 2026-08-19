#ifndef SIMUL_EFUN_H
#define SIMUL_EFUN_H

/*
 * simul_efun.c
 */

extern struct object_t *simul_efun_ob;
extern struct function_lookup_info_t *simuls;

// Live dispatch tables (extern for tests; owned by simul_efun.cc).
// names is the position-keyed table ordered by INTERNED STRING POINTER
// (add_simul_entry compares const char* addresses, NOT strcmp -- the order
// is allocator-layout dependent, NOT lexicographic; same-name strings are
// interned so the == branch is correct). funcs is the DISPATCH-INDEX-keyed
// table (simuls[sindex] at runtime); a name's stable dispatch index is
// simul_names[position].index and is never recycled. Consumers must NOT
// rely on the position ordering (position may coincide with dispatch
// index); runtime dispatch goes through the dispatch index only.
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
 * Three-phase simul_efun dispatch rebuild for the recompile_object()
 * transaction (v2 design): simul_efuns_prepare() runs in the allocatable
 * frozen segment -- it builds shadow dispatch arrays from a staging program
 * and pre-inserts identifier-hash entries (allocation allowed);
 * simul_efuns_activate() runs inside the no-fail swap segment -- pure ident
 * field writes plus pointer swap, no allocation, no error, and it hands the
 * OLD live tables to the prepared structure alive (not freed) so a failed
 * create phase can roll back; simul_efuns_finish() frees the loser tables
 * after the create phase succeeded, simul_efuns_rollback() restores the old
 * tables (ident fields mirrored back, pointers swapped, new tables freed)
 * after it failed. simul_efuns_discard() releases a prepared-but-uncommitted
 * build (and, defensively, tables left activated without a terminal call).
 *
 * STATE protocol: Prepared -> Activated -> Finalized. activate() must only
 * be called once; finish()/rollback() only from Activated; discard() is
 * safe in every state (no-op when nothing is owned).
 *
 * KEY DISCIPLINE (position key vs dispatch index key):
 * - names/idents are POSITION-keyed: simul_names is ordered by interned
 *   string POINTER (add_simul_entry: const char* < / >, NOT strcmp --
 *   allocator-layout dependent, NOT lexicographic), and idents[i] aligns
 *   with names[i]. The binary search in add_simul_entry is self-consistent
 *   (same comparator), but the relative order is NOT a contract.
 * - funcs is DISPATCH-INDEX-keyed: runtime dispatch reads simuls[sindex],
 *   and funcs is never shifted -- a fresh entry always lands at
 *   funcs[count], its dispatch index being the cumulative count.
 * - position may coincide with dispatch index (no ordering contract);
 *   every func access must go through simul_names[position].index.
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
  enum class State { Prepared, Activated, Finalized };

  void *names{nullptr};    // simul_entry* shadow array (live after activate)
  void *funcs{nullptr};    // function_lookup_info_t* shadow array
  void **idents{nullptr};  // ident_hash_elem_t* per entry, pre-inserted
  int count{0};
  // After activate(), the OLD live tables (handed over alive so a failed
  // create can restore them). finish() frees them; rollback() swaps them
  // back into the live table and frees the new ones.
  void *old_names{nullptr};  // simul_entry* previous live table
  void *old_funcs{nullptr};  // function_lookup_info_t* previous live table
  int old_count{0};
  State state{State::Prepared};
};

void simul_efuns_prepare(struct program_t *prog, simul_efun_prepared_t *out);
void simul_efuns_activate(simul_efun_prepared_t *p) noexcept;
void simul_efuns_finish(simul_efun_prepared_t *p) noexcept;
void simul_efuns_rollback(simul_efun_prepared_t *p) noexcept;
void simul_efuns_discard(simul_efun_prepared_t *p) noexcept;

#endif
