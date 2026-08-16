// E3 recompile_object() blueprint fixture: a prototype object whose program
// is hot-swapped. The test object (running do_tests) is deliberately NOT a
// member of this family, so the swap does not trip the executing guard.
object family_blueprint;

int value = 7;

int get_value() { return value; }

void set_value(int v) { value = v; }

int version() { return 1; }

// A funptr whose owner is a member of this family: its generation snapshot
// goes stale when the family program is swapped.
function make_fp() { return (: version :); }

// Self-reload probe: a family member calling recompile_object() on its own
// blueprint must hit the "target program is executing" guard (top-level
// frame). Returns 1 when the guard fires with the expected message.
void set_family_blueprint(object ob) { family_blueprint = ob; }

int self_reload() {
  mixed err = catch(recompile_object(family_blueprint));
  if (stringp(err) && strsrch(err, "target program is executing") != -1) {
    return 1;
  }
  return 0;
}
