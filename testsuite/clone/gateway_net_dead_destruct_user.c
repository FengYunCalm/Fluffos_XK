#include <globals.h>

private string last_disconnect_code = 0;
private string last_disconnect_text = 0;
private int saved_before_destruct = 0;

void gateway_logon(mixed data) {
}

void gateway_disconnected(string reason_code, string reason_text) {
  last_disconnect_code = reason_code;
  last_disconnect_text = reason_text;
}

string query_last_disconnect_code() { return last_disconnect_code; }

string query_last_disconnect_text() { return last_disconnect_text; }

int query_saved_before_destruct() { return saved_before_destruct; }

void net_dead() {
  saved_before_destruct = 1;
  save_object("/data/gateway_net_dead_destruct_user");
  destruct(this_object());
}
