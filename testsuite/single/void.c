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

mapping owner_lpc_probe()
{
  return ([
    "off_main_thread": !vm_context_is_main_thread(),
    "main_thread": vm_context_is_main_thread(),
  ]);
}

int owner_lpc_canary()
{
  return !vm_context_is_main_thread();
}

int owner_task_readonly()
{
  return !vm_context_is_main_thread();
}
