#include <globals.h>

private mapping last_gateway_login = ([]);
private mixed last_gateway_payload = 0;
private mapping last_gateway_receive_context = ([]);
private string last_disconnect_code = 0;
private string last_disconnect_text = 0;

void logon() {
  write("Normal login path reached.\n");
}

void gateway_logon(mixed data) {
  last_gateway_login = mapp(data) ? data : (["raw": data]);
}

mapping query_gateway_login() { return last_gateway_login; }

mixed query_last_gateway_payload() { return last_gateway_payload; }

mapping query_last_gateway_receive_context() { return last_gateway_receive_context; }

string query_last_disconnect_code() { return last_disconnect_code; }

string query_last_disconnect_text() { return last_disconnect_text; }

void gateway_receive(mixed data) {
  last_gateway_payload = data;
  last_gateway_receive_context = ([
    "owner_id": vm_owner_id(this_object()),
    "owner_epoch": vm_owner_epoch(this_object()),
    "this_player": this_player() ? file_name(this_player()) : "",
  ]);
}

void gateway_disconnected(string reason_code, string reason_text) {
  last_disconnect_code = reason_code;
  last_disconnect_text = reason_text;
}

void net_dead() {
  if (!last_disconnect_code) {
    last_disconnect_code = "net_dead";
  }
}
