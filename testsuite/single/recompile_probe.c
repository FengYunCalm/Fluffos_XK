// E3 v2 Phase 2 probe object: file-level initialization (packaged by the
// compiler into the implicit #global_init# function, which call_create()
// runs before create()) sets probe_order to 1; create() promotes it to 2.
// A successful call_create() must leave probe_order == 2 (init strictly
// before create). Loaded by the gtest recompile transaction tests as a
// scratch target; never part of the ftest suite.
int probe_order;

int probe_mark() {
  probe_order = 1;
  return 1;
}

// Function-call initializer: not a compile-time constant, so the compiler
// emits real init code (TREE_INIT -> #global_init#).
int probe_dummy = probe_mark();

void create() {
  if (probe_order == 1) {
    probe_order = 2;
  }
}
