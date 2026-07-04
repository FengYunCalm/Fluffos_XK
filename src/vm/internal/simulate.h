#ifndef SIMULATE_H
#define SIMULATE_H

#include "vm/internal/base/machine.h"

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
extern int MudOS_is_being_shut_down;
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

#endif
