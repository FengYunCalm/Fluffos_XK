#include "vm/internal/source_spelling.h"

#include <climits>  // PATH_MAX
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

size_t source_spelling_strip_len(const char *s, size_t len) {
  // Idempotent: strip ".lpc"/".c" repeatedly, so "foo.lpc.lpc" -> "foo"
  // and "foo.lpc.c" -> "foo", matching the loader's normalization.
  for (;;) {
    if (len > 4 && s[len - 1] == 'c' && s[len - 2] == 'p' && s[len - 3] == 'l' &&
        s[len - 4] == '.') {
      len -= 4;
    } else if (len > 2 && s[len - 1] == 'c' && s[len - 2] == '.') {
      len -= 2;
    } else {
      break;
    }
  }
  return len;
}

void resolve_source_spelling(const char *path, const char *requested_ext,
                             bool allow_fallback, const char **out_ext,
                             char *out_real_name, size_t out_size) {
  struct stat c_st;
  const char *ext = requested_ext != nullptr ? requested_ext : ".lpc";

  // Probe fallback: the .lpc source is missing (or is a directory) and the
  // caller permits degrading to the .c twin.
  if (allow_fallback && strcmp(ext, ".lpc") == 0) {
    char probe[PATH_MAX];
    (void)snprintf(probe, sizeof(probe), "%s%s", path, ext);
    if (stat(probe, &c_st) == -1 || S_ISDIR(c_st.st_mode)) {
      ext = ".c";
    }
  }

  *out_ext = ext;
  if (out_size > 0) {
    (void)snprintf(out_real_name, out_size, "%s%s", path, ext);
  }
}

bool source_name_matches(const char *user_path, const char *prog_filename) {
  const char *u = user_path;
  const char *p = prog_filename;
  if (*u == '/') {
    u++;
  }
  if (*p == '/') {
    p++;
  }
  // Idempotent strip on both sides (same normalization as the loader), so
  // replace_program("/foo") / "/foo.lpc" / "/foo.c" all match a compiled
  // foo.lpc or foo.c inherited program. When a program inherits both foo.c
  // and foo.lpc, the inherit order wins (first match) -- an accepted
  // divergence from the loader's .lpc-first preference.
  size_t ulen = source_spelling_strip_len(u, strlen(u));
  size_t plen = source_spelling_strip_len(p, strlen(p));
  return ulen == plen && strncmp(u, p, ulen) == 0;
}
