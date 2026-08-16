#ifndef SIMULATE_H
#define SIMULATE_H

#include <string>
#include <vector>

#include "vm/internal/base/machine.h"

#include <csignal>
#include <cstddef>
#include <cstdint>

#define V_SHORT 1
#define V_NOSPACE 2
#define V_FUNCTION 4

/*
 * simulate.c
 */
struct object_t;

constexpr size_t VM_OBJECT_LIFECYCLE_PERF_STAGE_COUNT = 17;

struct VMObjectLifecyclePerfSnapshot {
  uint64_t counts[VM_OBJECT_LIFECYCLE_PERF_STAGE_COUNT]{};
  uint64_t total_ns[VM_OBJECT_LIFECYCLE_PERF_STAGE_COUNT]{};
};

extern object_t *obj_list;
extern object_t *obj_list_destruct;
extern uint64_t tot_alloc_sentence;
extern volatile std::sig_atomic_t MudOS_is_being_shut_down;
extern volatile std::sig_atomic_t MudOS_shutdown_exit_code;
#ifdef DEBUG
extern object_t *obj_list_dangling;
#endif

[[noreturn]] void fatal(const char *, ...);
#ifndef NO_LIGHT
void add_light(object_t *, int);
#endif
void free_sentence(sentence_t *);

sentence_t *alloc_sentence(void);
int input_to(svalue_t *, int, int, svalue_t *);
int get_char(svalue_t *, int, int, svalue_t *);

char *check_name(char *);
int filename_to_obname(const char *, char *, int);
object_t *load_object(const char *, int);
object_t *clone_object(const char *, int);
object_t *environment(svalue_t *);
object_t *first_inventory(svalue_t *);
object_t *object_present(svalue_t *, object_t *);
object_t *find_object(const char *);
object_t *find_object2(const char *);
void move_object(object_t *, object_t *);
void destruct_object(object_t *);
void destruct2(object_t *);
void vm_object_lifecycle_perf_set_enabled(bool enabled);
void vm_object_lifecycle_perf_reset();
VMObjectLifecyclePerfSnapshot vm_object_lifecycle_perf_snapshot();
const char *vm_object_lifecycle_perf_stage_name(size_t index);

void print_svalue(svalue_t *);
void do_write(svalue_t *);
void do_message(svalue_t *, svalue_t *, array_t *, array_t *, int);
void say(svalue_t *, array_t *);
void tell_room(object_t *, svalue_t *, array_t *);
void shout_string(const char *);

[[noreturn]] void error_needs_free(char *);
[[noreturn]] void throw_error(void);
[[noreturn]] void error_handler(char *);

void startshutdownMudOS(int);
void shutdownMudOS(int);
void slow_shut_down(int);

#ifdef DEBUGMALLOC_EXTENSIONS
void mark_free_sentences(void);
#endif

void tell_npc(object_t *, const char *);
void tell_object(object_t *, const char *, int);

// ---------------------------------------------------------------------------
// E3 recompile_object() internal API (v0.4 §8). Not registered as an efun
// until P5; these are the building blocks P0-P4 consume.
// ---------------------------------------------------------------------------

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

// E3 P4: target snapshot and no-fail commit (v0.4 §8.3/§9).
struct RecompileTarget {
  object_t *ob{nullptr};
  uint32_t precomputed_flags{0};
};

// Fully prepared transaction: staging program, validated layouts, frozen
// target set (each target holds an add_ref). Destroying it (any failure
// path before commit) releases the staging program and the target refs and
// leaves every live object untouched.
struct RecompilePrepared {
  StagedProgram staged;
  program_t *old_prog{nullptr};
  RecompileLayout old_layout;
  RecompileLayout new_layout;
  std::vector<RecompileTarget> targets;

  RecompilePrepared() = default;
  ~RecompilePrepared() {
    for (auto &t : targets) {
      if (t.ob) free_object(&t.ob, "recompile_prepared");
    }
    if (old_prog) free_prog(&old_prog);
  }
  RecompilePrepared(const RecompilePrepared &) = delete;
  RecompilePrepared &operator=(const RecompilePrepared &) = delete;
};

// Snapshot every live object still sharing blueprint->prog (the blueprint
// itself and its clones), checking: not on the main control stack, no
// shadowing/shadowed chain, no pending replace_program(). Any violation is
// a stable error before anything is touched. The frozen set takes add_ref
// on every target.
void snapshot_recompile_targets(object_t *blueprint, RecompilePrepared *prepared);

// The no-fail commit: swap program/generation/flags on every target, then
// release the N old-program references. Must only be called with the owner
// runtime FROZEN and after every allocatable step succeeded (v0.4 §9.2).
void commit_recompile_targets_noexcept(RecompilePrepared *prepared) noexcept;

#endif
