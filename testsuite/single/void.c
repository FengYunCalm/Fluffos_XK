int called = 0;

void virtual_start() {
  called = 1;
}

int get_called() {
  return called;
}

void dummy()
{
}

mixed call_target(object target)
{
  return call_other(target, "dummy");
}
