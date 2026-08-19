void do_tests() {
  // #1247 DISASM-1: the short-offset walk must stop before the
  // sizeof(LPC_INT)-wide table tail; disassembling any program exercises it.
  // dump_prog writes the listing to /PROG_DUMP (no string return).
  dump_prog(this_object());
  string s = read_file("/PROG_DUMP");
  ASSERT(s && strlen(s) > 0);
}
