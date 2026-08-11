void do_tests_real() {
  // boundary: below 1 must be rejected before any index arithmetic
  ASSERT_NE(0, catch(sys_reload_tls(-MAX_INT - 1))); /* INT_MIN */
  ASSERT_NE(0, catch(sys_reload_tls(-1)));
  ASSERT_NE(0, catch(sys_reload_tls(0)));

  // non tls port
  ASSERT_NE(0, catch(sys_reload_tls(1)));

  // no support for websocket
  ASSERT_NE(0, catch(sys_reload_tls(2)));

  // valid tls
  ASSERT_EQ(0, sys_reload_tls(4));

  // boundary: beyond element count must be rejected (index 5 == external_port[5], OOB)
  ASSERT_NE(0, catch(sys_reload_tls(5)));
  ASSERT_NE(0, catch(sys_reload_tls(6)));
  ASSERT_NE(0, catch(sys_reload_tls(MAX_INT)));
}
void after_boot() {
  mixed err;
  write("boot finished, doing test.\n");

  err = catch(do_tests_real());

  if (err) {
    debug_message(err);
    shutdown(-1);
  }

  write("sys_reload_tls: succeed.\n");
}
void do_tests() {
  write("waiting for boot...\n");

  call_out("after_boot", 0);
}
