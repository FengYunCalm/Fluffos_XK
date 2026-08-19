// #1247 B-S1 replace_program fixture: inherits rp_a, adds one variable.
inherit "/single/tests/efuns/rp_a";
int m;
void set_m(int v) { m = v; }
int get_m() { return m; }
