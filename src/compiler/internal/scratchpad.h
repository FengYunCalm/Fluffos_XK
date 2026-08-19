#ifndef _SCRATCHPAD_H
#define _SCRATCHPAD_H

/* #1247 C-S1: compatibility header for the compile-scope arena migration.
 *
 * The historical scratch_* entry points are implemented on top of
 * compile_arena (monotonic bump, no individual deallocation). The old
 * exported cursors (scr_last / scr_tail / scratch_end) and the
 * scratch_free_last() macro are REMOVED -- direct cursor manipulation is
 * gone; lexer string building uses the arena API instead.
 */

/*
 *  scratchpad.c
 */
char *scratch_copy(const char *);
char *scratch_alloc(int);
void scratch_free(char *);
char *scratch_join(char *, char *);
char *scratch_realloc(char *, int);

#endif
