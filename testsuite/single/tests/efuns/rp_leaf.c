// #1247 B-S1 replace_program fixture: inherits rp_mid, adds one variable.
inherit "/single/tests/efuns/rp_mid";
int l;
void set_l(int v) { l = v; }
int get_l() { return l; }
