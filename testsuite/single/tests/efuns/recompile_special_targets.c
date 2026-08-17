// E3 recompile_object() v2 Phase 1 contract: master and simul_efun reloads.
//
// Master (rejection path under ftest): recompile_object(master()) must fail
// with the executing guard -- the ftest driver chain runs inside the
// master's main loop, so a master frame is always on the stack and the
// guard correctly refuses the reload (a program executing on the stack
// cannot be swapped). This also proves the v1 special-case rejection is
// gone: the error is the guard's "target program is executing", not the old
// "target is unsupported: master". A successful master reload requires a
// window with no master frame on the stack (master idle, no apply in
// flight); ftest's synchronous model never exposes such a window, so the
// success path is covered by the shared commit pipeline below (simul_efun)
// plus the master-specific snapshot/swap steps that are identical for any
// object in the program family.
//
// Simul_efun (success path): recompile_object(simul_efun_ob) must succeed
// (count 1: the simul_efun object alone shares its program). This object is
// itself an already-compiled caller of sefuns (base64encode below compiles
// to F_SIMUL_EFUN with a hardcoded sindex), so calling a sefun before AND
// after the reload proves cumulative-table semantics: dispatch indices are
// assigned once and never recycled (a name the new program no longer
// provides stays in the table, inactive), so already-compiled callers'
// indices stay valid while the new program's function pointers are wired
// into the same slots.
//
// Full contract runs with etc/config.recompile (enable recompile object : 1);
// under etc/config.test (default off) it verifies the disabled error only.

int total;

void do_tests_p6() {
  object sefun = find_object("/single/simul_efun");
  ASSERT(sefun);
  total++;

  // Baseline sefun resolution through the live dispatch table.
  ASSERT_EQ("dGVzdA==", base64encode("test"));
  total++;

  // 1. Master reload: must hit the executing guard (master main loop is on
  //    the stack), and the error must NOT be the v1 unsupported-target
  //    message -- the special case is removed and master goes through the
  //    regular snapshot checks.
  mixed err = catch(recompile_object(master()));
  ASSERT2(stringp(err) && strsrch(err, "target program is executing") != -1,
          "master reload must hit the executing guard");
  ASSERT2(strsrch(err, "unsupported") == -1, "v1 special-case rejection must be gone");
  total++;

  // 2. Simul_efun reload: count 1, then the rebuilt dispatch table must
  //    still resolve inherited sefuns.
  int n = recompile_object(sefun);
  ASSERT_EQ(1, n);
  total++;
  ASSERT_EQ("dGVzdA==", base64encode("test"));
  total++;

  // 3. Second simul_efun reload: the dispatch rebuild is repeatable and the
  //    new program's functions resolve again (cumulative table keeps
  //    growing consistently).
  n = recompile_object(sefun);
  ASSERT_EQ(1, n);
  total++;
  ASSERT_EQ("dGVzdA==", base64encode("test"));
  total++;

  // 4. Transaction machinery unaffected by the special reloads: a plain
  //    blueprint reload still works end to end.
  object blueprint = load_object("/clone/recompile_blueprint");
  ASSERT(blueprint);
  ASSERT_EQ(1, recompile_object(blueprint));
  total++;

  write(sprintf("recompile_special_targets: %d special reload checks ok\n", total));
}

void do_tests() {
  if (!get_config(326)) {
    // Stable rejection only under the default config.
    mixed err = catch(recompile_object(this_object()));
    ASSERT2(stringp(err), "expected disabled");
    return;
  }
  do_tests_p6();
}
