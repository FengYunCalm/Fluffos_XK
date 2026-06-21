#include <globals.h>

void logon() {
  write("Normal login path reached.\n");
}

void gateway_logon(mixed data) {
  vm_set_owner_id(this_object(), "owner/test/gateway/login");
  object user = new("/clone/gateway_exec_user");
  vm_set_owner_id(user, "owner/test/gateway/exec-user");
  exec(user, this_object());
  user->finish_gateway_logon(data);
  destruct(this_object());
}
