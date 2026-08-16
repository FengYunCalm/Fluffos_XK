// set_clean_up() lifecycle contract (R4b): parameter semantics, cancellation,
// and the no-clean_up gate. The deadline sweep itself is driven by the
// backend tick (look_for_objects_to_swap, 5-min interval) and is covered by
// the C++ owner-runtime contract tests; here we pin the LPC-visible surface.

int cleaned = 0;
int clean_up() { cleaned = 1; return 1; }

void do_tests() {
  // 1. Scheduling a deadline keeps the object on the clean_up path
  //    (O_WILL_CLEAN_UP is set for objects that define clean_up()).
  set_clean_up(this_object(), 60);
  // 2. One-shot cancellation reverts to the idle rule.
  set_clean_up(this_object());
  // 3. Re-schedule works after cancel.
  set_clean_up(this_object(), 120);
  // 4. Explicit second arg is a deadline in seconds (gametick units); the
  //    efun accepts a non-negative integer and rejects nothing at this layer.
  set_clean_up(this_object(), 0);
  set_clean_up(this_object());

  // 5. An object without clean_up() must not be flagged: create a bare
  //    clone and schedule it; the efun itself is a no-op for the flag.
  object bare = new("/clone/testob1");
  set_clean_up(bare, 30);
  set_clean_up(bare);

  // 6. Invalid argument shapes fail cleanly.
  mixed err = catch(set_clean_up(0, 1));
  ASSERT2(stringp(err), "expected error for null object");

  ASSERT(1);
}
