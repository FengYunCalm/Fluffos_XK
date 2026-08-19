// #1247 C-S1: scratchpad compatibility layer over compile_arena.
//
// The old scratchpad (static 4KB block + malloc'd overflow blocks with
// tail-rewind frees) is replaced by the compile-scope monotonic arena.
// These functions keep the historical names so the grammar/lexer call
// sites compile unchanged during the migration; individual deallocation
// is a no-op (the whole scope is reclaimed by compile_arena::end()).
// scr_last/scr_tail/scratch_end are GONE -- direct cursor manipulation
// was the reason the old boundary could not be closed.

#include "base/std.h"

#include "scratchpad.h"

#include <cstddef>
#include <cstring>

#include "compiler.h"
#include "compile_arena.h"

char *scratch_copy(const char *str) {
  size_t len = strlen(str);
  char *res = compile_arena::alloc_string(len);
  if (len) memcpy(res, str, len);
  return res;
}

char *scratch_alloc(int size) {
  if (size < 0) {
    fatal("invalid scratchpad allocation size");
  }
  return compile_arena::alloc_string(static_cast<size_t>(size));
}

void scratch_free(char *) {
  // no-op: the whole compile scope is reclaimed by compile_arena::end().
}

char *scratch_join(char *s1, char *s2) {
  size_t l1 = strlen(s1);
  size_t l2 = strlen(s2);
  char *res = compile_arena::alloc_string(l1 + l2);
  if (l1) memcpy(res, s1, l1);
  if (l2) memcpy(res + l1, s2, l2);
  return res;
}

char *scratch_realloc(char *ptr, int size) {
  if (size < 0) {
    fatal("invalid scratchpad allocation size");
  }
  size_t len = strlen(ptr);
  char *res = compile_arena::alloc_string(static_cast<size_t>(size));
  // Copy the NUL terminator too: grammar.y's function_name shift idiom
  // (grammar.y:3579-3586) relies on the old NUL being moved along with
  // the payload, so the result must be NUL-terminated at [len].
  memcpy(res, ptr, len + 1);
  return res;
}

