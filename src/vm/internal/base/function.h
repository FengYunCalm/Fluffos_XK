#ifndef FUNCTION_H
#define FUNCTION_H

/* It is usually better to include "lpc_incl.h" instead of including this
   directly */

/* FP_LOCAL */
typedef struct {
  short index;
  /* E3 P2: the program this index belongs to at creation/bind time. It is
   * also the func_ref accounting object: dealloc_funp() decrements THIS
   * program's func_ref, never the owner's current program (which can be
   * hot-replaced). NULL for non-FP_LOCAL uses of the union slot. */
  struct program_t *prog;
} local_ptr_t;

/* FP_SIMUL */
typedef local_ptr_t simul_ptr_t;

/* FP_EFUN */
typedef local_ptr_t efun_ptr_t;

/* FP_FUNCTIONAL */
struct functional_t {
  /* these two must come first */
  unsigned char num_arg;
  unsigned char num_local;
  short fio;
  struct program_t *prog;
  int offset;
  short vio;
  // char lpccode[80];
};

/* common header */
struct funptr_hdr_t {
  uint32_t ref;
  short type; /* FP_* is used */
#ifdef DEBUGMALLOC_EXTENSIONS
  int extra_ref;
#endif
  struct object_t *owner;
  struct array_t *args;
  /* E3 P2: owner->prog_generation at creation/bind time. FP_LOCAL and
   * FP_FUNCTIONAL call paths compare generations and report a stable
   * stale-function-pointer error after recompile_object() swaps programs;
   * a fresh funptr snapshots the new generation. */
  uint64_t owner_gen;
};

struct funptr_t {
  funptr_hdr_t hdr;
  union {
    efun_ptr_t efun;
    local_ptr_t local;
    simul_ptr_t simul;
    functional_t functional;
  } f;
};

union string_or_func {
  funptr_t *f;
  const char *s;
};

void dealloc_funp(funptr_t *);
void push_refed_funp(funptr_t *);
void push_funp(funptr_t *);
void free_funp(funptr_t *);
int merge_arg_lists(int, struct array_t *, int);
funptr_t *make_efun_funp(int, struct svalue_t *);
funptr_t *make_lfun_funp(int, struct svalue_t *);
funptr_t *make_simul_funp(int, struct svalue_t *);
funptr_t *make_functional_funp(short, short, short, struct svalue_t *, int);

#endif
