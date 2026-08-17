// AFL++ deferred-fork-server harness for the LPC compiler front-end (lexer
// + preprocessor + parser + codegen).
//
// Boots the VM once (master + simul_efun, same as lpcc), then calls
// __AFL_INIT() so AFL forks a fresh child per test case AFTER that expensive
// one-time setup. Each child splits the input on a "\n#==#\n" delimiter into a
// SEQUENCE of LPC source texts and compiles each in turn via load_object()
// -- the same in-memory "restart pattern" lpcshell uses -- in the SAME
// process, not just one compile per exec.
//
// A sequence (not a single compile) matters here for the same reason it
// mattered for the restore_variable() harness: state left over from one
// compile (shared strings, identifier tables, object table entries) is part
// of what a later compile sees, so single-compile fuzzing could never find
// the cross-compile interaction bugs this harness exists for.
//
// R2 hardening (2026-08): scratch files are written into the mudlib-internal
// directory <mudlib>/data/fuzz_compile/ (the original "/fuzz_compile#N.c"
// host path is not writable by unprivileged users AND is not resolvable by
// the LPC loader, so the compiler was never actually exercised; failures
// were silently swallowed). Every fopen/fwrite/fclose result is checked and
// turns into a harness failure; success/diagnostic counts self-validate the
// harness (both zero means the compiler was never actually exercised ->
// non-zero exit).

#include "base/std.h"

#include "mainlib.h"
#include "vm/vm.h"
#include "vm/internal/base/scoped_current_object_as_master.h"
#include "vm/internal/simulate.h"
#include "vm/internal/base/interpret.h"
#include "vm/internal/base/object.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <sys/stat.h>  // for mkdir
#include <unistd.h>    // for rmdir

#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <unistd.h>
#endif

namespace {

std::vector<char> read_file(const char* path) {
  std::vector<char> data;
  FILE* f = fopen(path, "rb");
  if (!f) return data;
  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    data.insert(data.end(), buf, buf + n);
  }
  fclose(f);
  return data;
}

constexpr std::string_view kDelim = "\n#==#\n";
constexpr size_t kMaxChunks = 8;  // compiles are heavier than restores

// Per-process counters: both must be non-zero after any real input, or the
// harness did not exercise the compiler and must fail closed.
int g_compile_success = 0;
int g_compile_diagnostic = 0;

// Fixed mudlib-internal scratch directory (host side + LPC side). The
// compiler only resolves paths inside the mudlib, so scratch files cannot
// live in /tmp; /data/fuzz_compile/ is inside the mudlib and conventionally
// writable. (v0.4 R2.)
constexpr const char* kScratchMudPath = "/data/fuzz_compile";
std::string g_scratch_host_dir;
std::string g_scratch_mud_dir;

// One compile, in its own caught error context. A successfully-compiled
// object is destructed immediately (see file header). Returns false on
// scratch I/O failure (never swallowed).
bool compile_one(int index, const std::string& src) {
  std::string host_path =
      g_scratch_host_dir + "/chunk_" + std::to_string(index) + ".c";
  std::string mud_path =
      g_scratch_mud_dir + "/chunk_" + std::to_string(index) + ".c";

  FILE* f = fopen(host_path.c_str(), "wb");
  if (!f) {
    fprintf(stderr, "fuzz_compile: cannot create scratch file %s\n", host_path.c_str());
    return false;
  }
  bool io_ok = fwrite(src.data(), 1, src.size(), f) == src.size();
  if (fclose(f) != 0) {
    io_ok = false;
  }
  if (!io_ok) {
    fprintf(stderr, "fuzz_compile: scratch write failed for %s\n", host_path.c_str());
    return false;
  }

  error_context_t econ{};
  save_context(&econ);
  try {
    object_t* ob = load_object(mud_path.c_str(), /*callcreate=*/0);
    if (ob && !(ob->flags & O_DESTRUCTED)) {
      g_compile_success++;
      destruct_object(ob);
    } else {
      g_compile_diagnostic++;
      fprintf(stderr, "fuzz_compile: load_object returned %s for %s\n",
              ob ? "destructed/null-prog object" : "null", mud_path.c_str());
    }
  } catch (const char* e) {
    g_compile_diagnostic++;
    fprintf(stderr, "fuzz_compile: compile error: %s\n", e);
    restore_context(&econ);
  } catch (...) {
    g_compile_diagnostic++;
    restore_context(&econ);
  }
  pop_context(&econ);

  if (unlink(host_path.c_str()) != 0) {
    fprintf(stderr, "fuzz_compile: scratch unlink failed for %s\n", host_path.c_str());
    return false;
  }
  return true;
}

// Split on the delimiter and compile each piece in sequence. Returns false
// on scratch I/O failure (caller fails closed).
bool run_sequence(const std::vector<char>& raw) {
  std::string_view all(raw.data(), raw.size());
  size_t pos = 0, chunks = 0;
  while (chunks < kMaxChunks) {
    size_t next = all.find(kDelim, pos);
    std::string_view piece =
        (next == std::string_view::npos) ? all.substr(pos) : all.substr(pos, next - pos);
    if (!compile_one(static_cast<int>(chunks), std::string(piece))) {
      return false;
    }
    chunks++;
    if (next == std::string_view::npos) break;
    pos = next + kDelim.size();
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: fuzz_compile <config> <input_file>\n");
    return 1;
  }

  auto config = get_argument(0, argc, argv);
  init_main(config);
  vm_start();
    ScopedCurrentObjectAsMaster master_scope;


#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  std::vector<char> input = read_file(argv[2]);
  if (input.empty()) {
    // Distinguish "could not open" from "opened but empty": both must fail
    // closed, but the message tells them apart.
    FILE* probe = fopen(argv[2], "rb");
    if (!probe) {
      fprintf(stderr, "fuzz_compile: cannot open input %s\n", argv[2]);
      return 1;
    }
    fclose(probe);
    fprintf(stderr, "fuzz_compile: input is empty; nothing to compile\n");
    return 1;
  }

  // Fixed mudlib-internal scratch directory: the compiler resolves LPC
  // paths inside the mudlib only, so /tmp scratch never compiles. Create
  // <mudlib>/data/fuzz_compile/ (host side) and load via the mudlib path.
  const char* mudlib = CONFIG_STR(__MUD_LIB_DIR__);
  g_scratch_host_dir = std::string(mudlib ? mudlib : ".") + "/data/fuzz_compile";
  g_scratch_mud_dir = kScratchMudPath;
  if (mkdir(g_scratch_host_dir.c_str(), 0700) != 0) {
    if (errno != EEXIST) {
      fprintf(stderr, "fuzz_compile: cannot create scratch dir %s\n",
              g_scratch_host_dir.c_str());
      return 1;
    }
  }

  bool ok = run_sequence(input);

  // RAII-style cleanup on every path that got past mkdir.
  if (rmdir(g_scratch_host_dir.c_str()) != 0 && errno != ENOENT && errno != ENOTEMPTY) {
    fprintf(stderr, "fuzz_compile: scratch dir cleanup failed\n");
    ok = false;
  }

  if (!ok) {
    return 1;
  }
  if (g_compile_success == 0 && g_compile_diagnostic == 0) {
    fprintf(stderr,
            "fuzz_compile: harness self-check failed: compiler never exercised "
            "(success=%d diagnostic=%d)\n",
            g_compile_success, g_compile_diagnostic);
    return 1;
  }

  fprintf(stderr, "fuzz_compile: success=%d diagnostic=%d\n", g_compile_success,
          g_compile_diagnostic);
  return 0;
}
