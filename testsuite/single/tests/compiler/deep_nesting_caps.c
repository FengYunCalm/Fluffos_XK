// Regression for compiler-front-end depth caps (upstream 4d5345f5), ported
// to the local preprocessor structure.
//
// The local #if/#elif evaluator (cond_get_exp in tools/preprocessor.hpp) is
// recursive-descent with no depth bound; a pathological `#if ((((...))))`
// overflowed the C stack. A cap (kMaxIfExprDepth=500) now fails the compile
// cleanly. NOTE: the local preprocessor's error path is yyerrorp() -> exit(1)
// (fatal), so the over-cap case is pinned at the process level (exit 1, not
// SIGSEGV) rather than as a catchable error; only the under-cap case is
// asserted here.

private string build_if_parens(int n) {
  string s = "#if ";
  int i;
  for (i = 0; i < n; i++) {
    s += "(";
  }
  s += "1";
  for (i = 0; i < n; i++) {
    s += ")";
  }
  s += "\n#endif\nint gate() { return 1; }\n";
  return s;
}

void do_tests() {
  // Deep nesting below the cap compiles and evaluates fine.
  rm("/gen_deep_if_ok.c");
  write_file("/gen_deep_if_ok.c", build_if_parens(400));
  object ok = load_object("/gen_deep_if_ok");
  ASSERT(objectp(ok));
  ASSERT_EQ(1, ok->gate());
  destruct(ok);
  rm("/gen_deep_if_ok.c");
}
