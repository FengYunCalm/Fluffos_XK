string *parse_command_id_list() {
  return ({ "bag" });
}

void create() {
  parse_init();

  if (clonep()) {
    move_object(__FILE__);
  }
}

string can_debug_obj() {
  return repeat_string("x", 4096);
}

int direct_debug_obj() {
  return 1;
}

int do_debug_obj() {
  return 0;
}

void do_tests() {
#ifndef __PACKAGE_PARSER__
  write("no package parser, skipped.\n");
#else
  clone_object(__FILE__);
  parse_add_rule("debug", "OBJ");

  ASSERT_EQ(0, parse_sentence("debug bag", 1, all_inventory()));
#endif
}
