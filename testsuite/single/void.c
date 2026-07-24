int called = 0;
int heartbeat_called = 0;
int callout_called = 0;
int callout_off_main = 0;
int async_callback_called = 0;
int async_callback_off_main = 0;
string async_callback_value = 0;
int dns_callback_called = 0;
int dns_callback_off_main = 0;
int dns_callback_key = 0;
int socket_callback_called = 0;
int socket_callback_off_main = 0;
int socket_callback_fd = 0;

void virtual_start() {
  called = 1;
}

int get_called() {
   return called;
}

void heart_beat() {
  heartbeat_called++;
}

int get_heartbeat_called() {
  return heartbeat_called;
}

void reset_heartbeat_called() {
  heartbeat_called = 0;
  set_heart_beat(0);
}

void start_heartbeat() {
  set_heart_beat(1);
}

void stop_heartbeat() {
  set_heart_beat(0);
}

int start_callout_probe() {
  return call_out("callout_probe", 0);
}

int start_walltime_callout_probe() {
  return call_out_walltime("callout_probe", 3600);
}

int start_gateway_walltime_callout_probe() {
  return call_out_walltime_gateway("callout_probe", 3600);
}

int start_background_walltime_callout_probe() {
  return call_out_walltime_background("callout_probe", 3600);
}

void callout_probe() {
  callout_called++;
  callout_off_main = !vm_context_is_main_thread();
}

int get_callout_called() {
  return callout_called;
}

int get_callout_off_main() {
  return callout_off_main;
}

void reset_callout_probe() {
  callout_called = 0;
  callout_off_main = 0;
}

void async_callback_probe(string value) {
  async_callback_called++;
  async_callback_off_main = !vm_context_is_main_thread();
  async_callback_value = value;
}

int get_async_callback_called() { return async_callback_called; }
int get_async_callback_off_main() { return async_callback_off_main; }
string get_async_callback_value() { return async_callback_value; }

void reset_async_callback_probe() {
  async_callback_called = 0;
  async_callback_off_main = 0;
  async_callback_value = 0;
}

void dns_callback_probe(mixed name, mixed address, int key) {
  dns_callback_called++;
  dns_callback_off_main = !vm_context_is_main_thread();
  dns_callback_key = key;
}

int get_dns_callback_called() { return dns_callback_called; }
int get_dns_callback_off_main() { return dns_callback_off_main; }
int get_dns_callback_key() { return dns_callback_key; }

void reset_dns_callback_probe() {
  dns_callback_called = 0;
  dns_callback_off_main = 0;
  dns_callback_key = 0;
}

void socket_callback_probe(int fd) {
  socket_callback_called++;
  socket_callback_off_main = !vm_context_is_main_thread();
  socket_callback_fd = fd;
}

int get_socket_callback_called() { return socket_callback_called; }
int get_socket_callback_off_main() { return socket_callback_off_main; }
int get_socket_callback_fd() { return socket_callback_fd; }

void reset_socket_callback_probe() {
  socket_callback_called = 0;
  socket_callback_off_main = 0;
  socket_callback_fd = 0;
}

void dummy()
{
}

mixed call_target(object target)
{
  return call_other(target, "dummy");
}

mapping call_owner_async_echo(object target)
{
  return owner_call_async(target, "owner_async_echo", ([
    "payload_key": "cross-owner/echo/v1",
    "value": 41,
  ]));
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

int owner_task_player() { return !vm_context_is_main_thread(); }
int owner_task_room() { return !vm_context_is_main_thread(); }
int owner_task_session() { return !vm_context_is_main_thread(); }
int owner_task_item() { return !vm_context_is_main_thread(); }
int owner_task_economy() { return !vm_context_is_main_thread(); }
int owner_task_combat() { return !vm_context_is_main_thread(); }
int owner_task_mail() { return !vm_context_is_main_thread(); }
int owner_task_reward() { return !vm_context_is_main_thread(); }
int owner_task_world() { return !vm_context_is_main_thread(); }
int owner_task_persistence() { return !vm_context_is_main_thread(); }
int owner_task_team() { return !vm_context_is_main_thread(); }
int owner_task_guild() { return !vm_context_is_main_thread(); }
int owner_task_sect() { return !vm_context_is_main_thread(); }
int owner_task_quest() { return !vm_context_is_main_thread(); }
int owner_task_rank() { return !vm_context_is_main_thread(); }
int owner_task_crafting() { return !vm_context_is_main_thread(); }
int owner_task_life_skill() { return !vm_context_is_main_thread(); }
