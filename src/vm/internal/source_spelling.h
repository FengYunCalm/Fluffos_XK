#ifndef SOURCE_SPELLING_H
#define SOURCE_SPELLING_H

#include <cstddef>

/*
 * Source-file extension spelling resolution (#1247 TESTS, single owner).
 *
 * Three callers share this rule: load_object (simulate.cc), the recompiler
 * (compile_program_for_recompile, recompile.cc) and replace_program
 * (replace_program.cc). Before this module the rule was inlined in four
 * C++ places -- the three callers plus filename_to_obname's own
 * strip-normalization loop -- with slightly different probe semantics (stat
 * vs access); testsuite/command/tests.c carries an LPC-layer copy that is
 * intentionally kept independent. This module owns the idempotent
 * strip (source_spelling_strip_len), the probe-and-fallback rule
 * (resolve_source_spelling) and the in-memory match (source_name_matches);
 * the callers keep their explicit-extension detection (load_object on the
 * raw pname, recompile on prog->filename).
 *
 * Semantics parameterized (callers differ):
 *  - requested_ext != nullptr: the caller knows the extension already, in
 *    dotted form (".lpc"/".c" -- an explicit request in load_object, or the
 *    compiled program's own filename in recompile_object). No probing
 *    unless allow_fallback.
 *  - allow_fallback: when the chosen .lpc source is missing, fall back to
 *    ".c" (probed with stat + S_ISDIR). load_object enables this only for
 *    extension-less names; recompile_object always enables it because a
 *    deleted .lpc source must degrade to the .c twin. Note the asymmetry:
 *    recompile_object previously probed with access(R_OK), which also
 *    accepts directories; stat + S_ISDIR rejects them (slightly stricter,
 *    by design). Also note load_object with an explicit ".lpc" never falls
 *    back while recompile always does for the same object -- recompile
 *    cannot know the request was explicit, a known trade-off.
 *
 * out_real_name receives path + selected ext truncated to out_size (always
 * NUL-terminated when out_size > 0).
 */
void resolve_source_spelling(const char *path, const char *requested_ext,
                             bool allow_fallback, const char **out_ext,
                             char *out_real_name, size_t out_size);

/*
 * In-memory match used by replace_program: does a user-supplied path (any
 * spelling, "/" prefix optional) name the same source as a compiled
 * program's filename (which carries the loader-chosen extension)? Both
 * sides are stripped of a .lpc/.c suffix and compared.
 */
bool source_name_matches(const char *user_path, const char *prog_filename);

/*
 * Idempotent strip of a trailing .lpc/.c suffix ("foo.lpc.lpc" -> "foo",
 * "foo.lpc.c" -> "foo"), returning the stripped length. Shared by
 * filename_to_obname's normalization and source_name_matches, so the loader
 * and replace_program resolve the same string identically. Note the
 * idempotence: single-pass stripping would leave "foo.lpc" for
 * "foo.lpc.c" and diverge from the loader.
 */
size_t source_spelling_strip_len(const char *s, size_t len);

#endif  // SOURCE_SPELLING_H
