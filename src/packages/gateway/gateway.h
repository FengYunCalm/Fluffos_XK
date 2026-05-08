#ifndef PACKAGES_GATEWAY_H
#define PACKAGES_GATEWAY_H

#include "base/package_api.h"

#include <event2/listener.h>

extern int g_gateway_debug;
extern size_t g_gateway_max_packet_size;
extern int g_gateway_max_masters;
extern int g_gateway_max_sessions;
extern int g_gateway_heartbeat_interval;
extern int g_gateway_heartbeat_timeout;

struct GatewayMaster {
  int fd{-1};
  bufferevent *bev{nullptr};
  std::string ip;
  bool closing{false};
  time_t connected_at{0};
  time_t last_active{0};
  uint64_t messages_received{0};
  uint64_t messages_sent{0};
  std::string read_buffer;

  ~GatewayMaster();
};

struct GatewaySession {
  std::string session_id;
  std::string real_ip;
  int real_port{0};
  int master_fd{-1};
  time_t connected_at{0};
  time_t last_active{0};
  object_t *user_ob{nullptr};
  int64_t user_ob_load_time{0};
};

void init_gateway(void);
void cleanup_gateway(void);

int gateway_listen_internal(int port, int bind_all);
mapping_t *gateway_status_internal();
int gateway_get_session_count();
int gateway_send_raw_to_fd(int fd, const char *data, size_t len);
int gateway_svalue_to_json_string(const svalue_t *sv, std::string *out);
int gateway_ping_master_internal(int fd);
void gateway_check_heartbeat_timeouts();
bool gateway_has_master(int fd);

GatewaySession *gateway_find_session(const char *session_id);
GatewaySession *gateway_find_session_by_object(object_t *ob);
int gateway_bind_session_object(const char *session_id, object_t *ob, const char *ip,
                                int port, int master_fd);
void gateway_unbind_session_object(object_t *ob);
void gateway_cleanup_master_sessions(int master_fd);
object_t *gateway_create_session_internal(const char *session_id, svalue_t *data_val,
                                          const char *ip, int port, int master_fd);
int gateway_destroy_session_internal(const char *session_id, const char *reason_code,
                                     const char *reason_text);
int gateway_inject_input_internal(object_t *user, const char *input);
int gateway_send_to_session(const char *session_id, const char *data, size_t len);
void gateway_check_session_timeouts();
void cleanup_gateway_sessions();

void gateway_session_exec_update(object_t *new_ob, object_t *old_ob);
void gateway_handle_remove_interactive(interactive_t *ip);
bool gateway_is_session(object_t *ob);

#endif /* PACKAGES_GATEWAY_H */
