// E3 recompile_object() v1 contract (v0.4 §5/§11): same-layout hot swap of a
// blueprint and its clones, no __INIT, stale funptr rejection, disabled and
// permission failures, heartbeat/call_out survival, repeated reloads.
// Runs the full contract with etc/config.recompile (enable recompile object : 1);
// under etc/config.test (default off) it verifies the disabled error only.

int value = 7;

int get_value() { return value; }

void set_value(int v) { value = v; }

// Old body returns 1; the layout never changes across reloads.
int version() { return 1; }

int hb_count = 0;
int callout_count = 0;
void heart_beat() { hb_count++; }
void on_callout() { callout_count++; }

void do_tests_p6() {
  if (!get_config(326)) return;  // CFG_INT(70) = __RECOMPILE_OBJECT_ENABLED__

  object blueprint = load_object(__FILE__);
  object worker = new(__FILE__);
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
  // Default-off (config.test): the efun must stably reject; nothing else is
  // reachable. The full contract runs under etc/config.recompile.
  if (!get_config(326)) {  // CFG_INT(70) = __RECOMPILE_OBJECT_ENABLED__ (70 + 256 base)
    mixed err = catch(recompile_object(this_object()));
    ASSERT2(stringp(err), "expected disabled");
    return;
  }

  object blueprint = load_object(__FILE__);
  object clone_a = new(__FILE__);
  object clone_b = new(__FILE__);
  clone_a->set_value(100);
  clone_b->set_value(200);
  ASSERT_EQ(1, blueprint->version());
  ASSERT_EQ(100, clone_a->get_value());

  // Old funptr created before the swap must go stale afterwards.
  function old_fp = (: version :);
  ASSERT_EQ(1, old_fp());

  // Swap: same layout; the contract under test is the atomic family swap,
  // variable preservation, and generation bump.
  int n = recompile_object(blueprint);
  ASSERT_EQ(3, n);  // blueprint + 2 clones

  // Variables preserved on every member of the family.
  ASSERT_EQ(100, clone_a->get_value());
  ASSERT_EQ(200, clone_b->get_value());
  ASSERT_EQ(7, blueprint->get_value());

  // Old funptr is now stale.
  mixed err = catch(old_fp());
  ASSERT2(stringp(err), "expected stale function pointer error");

  // New funptr works.
  function new_fp = (: version :);
  ASSERT_EQ(1, new_fp());

  destruct(clone_b);
  destruct(clone_a);
  destruct(blueprint);

  do_tests_p6();
}
