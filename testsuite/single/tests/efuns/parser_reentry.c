string* parse_command_id_list() {
  return ({ "bag" });
}

nosave int nested_parse_rejected = 0;
nosave int nested_rules_rejected = 0;
nosave int do_callback_parse_result = 0;

void create() {
  parse_init();

  if (clonep()) {
    move_object(__FILE__);
  }
}

int can_inner_obj() {
  return 1;
}

int direct_inner_obj() {
  return 1;
}

int do_inner_obj() {
  return 1;
}

int can_outer_obj() {
  mixed err = catch(parse_sentence("inner bag", 0, all_inventory()));
  nested_parse_rejected = stringp(err) && strsrch(err, "recursively") >= 0;
  mixed rules_err = catch(parse_my_rules(this_object(), "inner bag", 0));
  nested_rules_rejected = stringp(rules_err) && strsrch(rules_err, "recursively") >= 0;
  return 1;
}

int direct_outer_obj() {
  return 1;
}

int do_outer_obj() {
  return 1;
}

int can_follow_obj() {
  return 1;
}

int direct_follow_obj() {
  return 1;
}

int do_follow_obj() {
  do_callback_parse_result = parse_sentence("inner bag", 0, all_inventory());
  return 1;
}

void do_tests() {
#ifndef __PACKAGE_PARSER__
  write("no package parser, skipped.\n");
  return;
#else
  clone_object(__FILE__);
  parse_add_rule("inner", "OBJ");
  parse_add_rule("outer", "OBJ");
  parse_add_rule("follow", "OBJ");

  ASSERT_EQ(1, parse_sentence("outer bag", 0, all_inventory()));
  ASSERT_EQ(1, nested_parse_rejected);
  ASSERT_EQ(1, nested_rules_rejected);

  ASSERT_EQ(1, parse_sentence("follow bag", 0, all_inventory()));
  ASSERT_EQ(1, do_callback_parse_result);
#endif
}
