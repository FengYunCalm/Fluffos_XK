string* parse_command_id_list() {
  return ({ "bag" });
}

void create() {
  parse_init();
}

int can_look_wrd_obj() {
  return 1;
}

int direct_look_wrd_obj() {
  return 1;
}

int do_look_wrd_obj() {
  return 1;
}

int parse_targets(object* targets) {
  parse_add_rule("look", "WRD OBJ");
  return parse_sentence("look in bag", 2, targets);
}
