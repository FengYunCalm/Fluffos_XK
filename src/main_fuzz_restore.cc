// AFL++ deferred-fork-server harness for restore_variable()/save_variable().
//
// Boots the VM once (master + simul_efun, same as lpcc), then calls
// __AFL_INIT() so AFL forks a fresh child per test case AFTER that expensive
// one-time setup. Each child splits the input on a "\n#==#\n" delimiter into
// a SEQUENCE of save-strings and runs restore_variable() on each in the SAME
// process.
//
// R2 hardening (2026-08): input open/read failures are now visible and fail
// the process; success/diagnostic counts self-validate the harness (both
// zero after non-empty input means restore_variable() was never actually
// exercised -> non-zero exit).

#include "base/std.h"

#include "mainlib.h"
#include "vm/vm.h"
#include "vm/internal/base/scoped_current_object_as_master.h"
#include "vm/internal/simulate.h"
#include "vm/internal/base/interpret.h"
#include "vm/internal/base/machine.h"
#include "vm/internal/base/object.h"
#include "vm/internal/base/svalue.h"

#include <cstdio>
#include <string>
#include <vector>

char *save_variable(svalue_t *var);  // packages/core/save.cc

#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <unistd.h>
#endif

namespace {

// Reads the whole file. Returns false when the file cannot be opened or a
// read error occurs (caller fails closed); an empty-but-open file returns
// true with an empty vector.
bool read_file(const char* path, std::vector<char>* out) {
  out->clear();
  FILE* f = fopen(path, "rb");
  if (!f) {
    return false;
  }
  char buf[65536];
  size_t n;
  bool read_ok = true;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    out->insert(out->end(), buf, buf + n);
  }
  if (ferror(f)) {
    read_ok = false;
  }
  fclose(f);
  return read_ok;
}

constexpr std::string_view kDelim = "\n#==#\n";
constexpr size_t kMaxChunks = 32;

// Per-process counters: both must be non-zero after any non-empty input, or
// the harness did not exercise restore_variable() and must fail closed.
int g_restore_success = 0;
int g_restore_diagnostic = 0;

void run_chunk(std::string chunk) {
  error_context_t econ{};
  save_context(&econ);
  try {
    svalue_t v;
    v.type = T_NUMBER;
    restore_variable(&v, chunk.data());

    char* s2 = save_variable(&v);
    svalue_t v2;
    v2.type = T_NUMBER;
    restore_variable(&v2, s2);
    FREE_MSTR(s2);
    free_svalue(&v2, "fuzz_restore: v2");
    free_svalue(&v, "fuzz_restore: v");
    g_restore_success++;
  } catch (const char*) {
    g_restore_diagnostic++;
    restore_context(&econ);
  } catch (...) {
    g_restore_diagnostic++;
    restore_context(&econ);
  }
  pop_context(&econ);
}

// Split on the delimiter and feed each piece to restore_variable() in
// sequence, in this same process -- see the file header for why a sequence
// (not a single call) is what this harness needs to find.
void run_sequence(const std::vector<char>& raw) {
  std::string_view all(raw.data(), raw.size());
  size_t pos = 0, chunks = 0;
  while (chunks < kMaxChunks) {
    size_t next = all.find(kDelim, pos);
    std::string_view piece =
        (next == std::string_view::npos) ? all.substr(pos) : all.substr(pos, next - pos);
    // restore_variable() takes a plain NUL-terminated char*; embedded NULs
    // truncate the save string exactly like a real one read from a file
    // would if it somehow contained one (LPC strings can't, a fuzzed byte
    // can).
    run_chunk(std::string(piece));
    chunks++;
    if (next == std::string_view::npos) break;
    pos = next + kDelim.size();
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: fuzz_restore <config> <input_file>\n");
    return 1;
  }

  auto config = get_argument(0, argc, argv);
  init_main(config);
  vm_start();
    ScopedCurrentObjectAsMaster master_scope;


#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  std::vector<char> input;
  if (!read_file(argv[2], &input)) {
    fprintf(stderr, "fuzz_restore: cannot open/read input %s\n", argv[2]);
    return 1;
  }
  if (input.empty()) {
    fprintf(stderr, "fuzz_restore: input is empty; nothing to restore\n");
    return 1;
  }

  run_sequence(input);

  if (g_restore_success == 0 && g_restore_diagnostic == 0) {
    fprintf(stderr,
            "fuzz_restore: harness self-check failed: restore_variable never exercised "
            "(success=%d diagnostic=%d)\n",
            g_restore_success, g_restore_diagnostic);
    return 1;
  }

  fprintf(stderr, "fuzz_restore: success=%d diagnostic=%d\n", g_restore_success,
          g_restore_diagnostic);
  return 0;
}
