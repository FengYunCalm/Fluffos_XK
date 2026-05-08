#include <globals.h>

private mapping last_gateway_login = ([]);
private mixed last_gateway_payload = 0;
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

string query_last_disconnect_code() { return last_disconnect_code; }

string query_last_disconnect_text() { return last_disconnect_text; }

void gateway_receive(mixed data) {
  last_gateway_payload = data;
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
