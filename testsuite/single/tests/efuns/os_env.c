// get_os_env()/set_os_env() contract (R3): allow-list enforcement,
// read/write round-trip, absence -> 0, and (by code review) main-thread-only.
void do_tests() {
  // allow-list 内可读（config.test: PATH:HOME）
  string p = get_os_env("PATH");
  ASSERT(stringp(p));

  // writable 列表内写读回（config.test: FLUFFOS_XK_TEST_ENV）
  set_os_env("FLUFFOS_XK_TEST_ENV", "hello");
  ASSERT_EQ("hello", get_os_env("FLUFFOS_XK_TEST_ENV"));
  // 覆盖写
  set_os_env("FLUFFOS_XK_TEST_ENV", "world");
  ASSERT_EQ("world", get_os_env("FLUFFOS_XK_TEST_ENV"));

  // 未设置的（白名单内）变量 -> 0（上游语义：const0u）
  set_os_env("FLUFFOS_XK_TEST_ENV");  // unset
  ASSERT_EQ(0, get_os_env("FLUFFOS_XK_TEST_ENV"));

  // 白名单外拒绝
  mixed err = catch(get_os_env("SECRET_VAR"));
  ASSERT2(stringp(err), "expected readable-list rejection");
  err = catch(set_os_env("SECRET_VAR", "x"));
  ASSERT2(stringp(err), "expected writable-list rejection");
}
