// Gateway Package - 基础会话/interactive 集成骨架

int gateway_listen(int, int default:0);
mapping gateway_status();
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
int gateway_inject_input(object, string);
int is_gateway_user(object);
