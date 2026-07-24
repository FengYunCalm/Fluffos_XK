// Gateway Package - 基础会话/interactive 集成骨架

int gateway_listen(int, int default:0);
mapping gateway_status();
int gateway_command_pending();
int gateway_main_queue_pending();
int gateway_buffered_input_pending();
mixed gateway_config(string, mixed default:0);
int gateway_send(mixed, mixed default:0);
void gateway_set_heartbeat(int, int default:0);
void gateway_check_timeout();
int gateway_ping_master(int default:0);
object gateway_create_session(string, mixed, void | string, void | int, void | int);
int gateway_destroy_session(string);
object *gateway_sessions();
mapping gateway_session_info(object);
int gateway_session_send(object, mixed, mixed default:0);
int gateway_session_reserve(object);
int gateway_session_fill(object, int, string);
int gateway_session_fill_preencoded_chat_batch(object, int, string *, int, int, int, string);
int gateway_session_release(object, int);
int gateway_session_watch_future(object, int, int, int);
int gateway_session_watch_future_output(object, int, int, int);
int gateway_future_watch(object, int, int, int);
int gateway_inject_input(object, string);
int is_gateway_user(object);
int gateway_probe_suppress_once(object);
