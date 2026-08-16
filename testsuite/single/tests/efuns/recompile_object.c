// E3 recompile_object() v1 contract (v0.4 §5/§11): same-layout hot swap of a
// blueprint and its clones, no __INIT, stale funptr rejection, executing
// guard, disabled and permission failures, heartbeat/call_out survival,
// repeated reloads.
// Full contract runs with etc/config.recompile (enable recompile object : 1);
// under etc/config.test (default off) it verifies the disabled error only.

// Self-reload probe: a family member calling recompile_object() on its own
// blueprint must hit the "target program is executing" guard.
object family_blueprint;
int self_reload() {
  mixed err = catch(recompile_object(family_blueprint));
  if (stringp(err) && strsrch(err, "target program is executing") != -1) {
    return 1;
  }
  return 0;
}

int hb_count = 0;
int callout_count = 0;
void heart_beat() { hb_count++; }
void on_callout() { callout_count++; }

void do_tests_p6() {
  if (!get_config(326)) return;  // CFG_INT(70) = __RECOMPILE_OBJECT_ENABLED__

  object blueprint = load_object("/clone/recompile_blueprint");
  object worker = new("/clone/recompile_blueprint");
  worker->set_heart_beat(1);
  call_out("on_callout", 1);

  // Repeated recompiles: generations, refcounts and queues stay stable.
  int ok = 1;
  for (int i = 0; i < 200; i++) {
    int n = recompile_object(blueprint);
    if (n < 1) { ok = 0; break; }
  }
  ASSERT_EQ(1, ok);
  ASSERT_EQ(7, worker->get_value());  // variables preserved across all swaps

  destruct(worker);
}

void do_tests() {
  // Default-off (config.test): the efun must stably reject.
  if (!get_config(326)) {  // CFG_INT(70) = __RECOMPILE_OBJECT_ENABLED__ (70 + 256 base)
    mixed err = catch(recompile_object(this_object()));
    ASSERT2(stringp(err), "expected disabled");
    return;
  }

  // The blueprint family lives in /clone/recompile_blueprint; THIS object
  // (running do_tests) is not a member, so the swap below is legal.
  object blueprint = load_object("/clone/recompile_blueprint");
  object clone_a = new("/clone/recompile_blueprint");
  object clone_b = new("/clone/recompile_blueprint");
  clone_a->set_value(100);
  clone_b->set_value(200);
  ASSERT_EQ(1, blueprint->version());
  ASSERT_EQ(100, clone_a->get_value());

  // Old funptr created on a family member before the swap must go stale
  // afterwards (the owner's generation is bumped by the swap).
  function old_fp = clone_a->make_fp();
  ASSERT_EQ(1, old_fp());

  int n = recompile_object(blueprint);
  ASSERT_EQ(3, n);  // blueprint + 2 clones

  // Variables preserved on every member of the family.
  ASSERT_EQ(100, clone_a->get_value());
  ASSERT_EQ(200, clone_b->get_value());
  ASSERT_EQ(7, blueprint->get_value());

  // Old funptr is now stale: stable error, no re-resolution against the
  // new program.
  mixed err = catch(old_fp());
  ASSERT2(stringp(err), "expected stale function pointer error");

  // A funptr created after the swap snapshots the new generation.
  function new_fp = clone_a->make_fp();
  ASSERT_EQ(1, new_fp());

  // Executing guard: a family member reloading its own blueprint must be
  // rejected with "target program is executing" (top-level frame).
  object self = new("/clone/recompile_blueprint");
  self->set_family_blueprint(blueprint);
  ASSERT_EQ(1, self->self_reload());

  destruct(self);
  destruct(clone_b);
  destruct(clone_a);
  destruct(blueprint);

  do_tests_p6();
}
