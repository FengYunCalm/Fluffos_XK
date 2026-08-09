void do_tests() {
#ifndef __PACKAGE_CONTRIB__
  write("PACKAGE_CONTRIB not enabled, test did not run.\n");
#else
  mixed result = pluralize("a of b");

  ASSERT(stringp(result));
  ASSERT_EQ("cups of tea", pluralize("a cup of tea"));
#endif
}
