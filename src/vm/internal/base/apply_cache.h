#ifndef LPC_APPLY_CACHE_H_
#define LPC_APPLY_CACHE_H_

#include "vm/internal/base/program.h"

lookup_entry_s apply_cache_lookup(const char *funcname, struct program_t *prog);
lookup_entry_s apply_cache_lookup_shared(const char *funcname, struct program_t *prog);
void apply_cache_invalidate_program(struct program_t *prog);

// E3 P3/P5: explicitly build (or confirm) a program's apply lookup table.
// Used by recompile_object() while the owner runtime is FROZEN so that no
// owner thread can race the first lazy build of a freshly published program
// (v0.4 §9.3). Failure (allocation/exception) propagates to the caller
// BEFORE any live object is touched.
void prepare_apply_lookup_table(struct program_t *prog);

#endif /* LPC_APPLY_CACHE_H_ */
