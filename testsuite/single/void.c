int called = 0;
int heartbeat_called = 0;

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
