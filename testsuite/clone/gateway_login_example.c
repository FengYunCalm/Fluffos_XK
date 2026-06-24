#include <globals.h>

private mapping last_gateway_login = ([]);
private mixed last_gateway_payload = 0;
private mapping last_gateway_receive_context = ([]);
private string last_disconnect_code = 0;
private string last_disconnect_text = 0;
private string last_input_to_line = 0;
private string last_input_to_token = 0;
private string last_get_char_value = 0;
private string last_get_char_token = 0;
private string last_process_input_command = 0;
private int last_process_input_off_main = 0;

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

void gateway_input_to_callback(string line, string token) {
  last_input_to_line = line;
  last_input_to_token = token;
}

int enable_gateway_input_to() {
  return input_to("gateway_input_to_callback", 3, "carry-token");
}

string query_last_input_to_line() { return last_input_to_line; }

string query_last_input_to_token() { return last_input_to_token; }

void gateway_get_char_callback(string value, string token) {
  last_get_char_value = value;
  last_get_char_token = token;
}

int enable_gateway_get_char() {
  return get_char("gateway_get_char_callback", 3, "char-token");
}

int enable_gateway_ed() {
#ifdef __OLD_ED__
  ed("/ed_test");
  return 1;
#else
  return 0;
#endif
}

mixed process_input(string command) {
  last_process_input_command = command;
  last_process_input_off_main = !vm_context_is_main_thread();
  return 0;
}

void reset_gateway_command_probe() {
  last_process_input_command = 0;
  last_process_input_off_main = 0;
}

string query_last_process_input_command() { return last_process_input_command; }

int query_last_process_input_off_main() { return last_process_input_off_main; }

string query_last_get_char_value() { return last_get_char_value; }

string query_last_get_char_token() { return last_get_char_token; }

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
