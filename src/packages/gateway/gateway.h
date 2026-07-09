#ifndef PACKAGES_GATEWAY_H
#define PACKAGES_GATEWAY_H

#include "base/package_api.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <string>

#include <event2/listener.h>

extern int g_gateway_debug;
extern size_t g_gateway_max_packet_size;
extern int g_gateway_max_masters;
extern int g_gateway_max_sessions;
extern int g_gateway_heartbeat_interval;
extern int g_gateway_heartbeat_timeout;

struct GatewayRuntimeCounters {
  std::atomic<uint64_t> data_frames_received{0};
  std::atomic<uint64_t> data_frames_applied{0};
  std::atomic<uint64_t> data_frames_rejected{0};
  std::atomic<uint64_t> receive_tasks_enqueued{0};
  std::atomic<uint64_t> receive_tasks_dispatched{0};
  std::atomic<uint64_t> receive_tasks_rejected{0};
  std::atomic<uint64_t> command_callbacks{0};
  std::atomic<uint64_t> command_tasks_enqueued{0};
  std::atomic<uint64_t> command_tasks_rejected{0};
  std::atomic<uint64_t> command_tasks_rejected_pending{0};
  std::atomic<uint64_t> command_tasks_finished{0};
  std::atomic<uint64_t> command_tasks_stale{0};
  std::atomic<uint64_t> command_tasks_cleared{0};
  std::atomic<uint64_t> reply_tasks_enqueued{0};
  std::atomic<uint64_t> reply_tasks_inline_fallbacks{0};
  std::atomic<uint64_t> reply_reschedule_cmd_in_buf{0};
  std::atomic<uint64_t> output_fifo_enqueued{0};
  std::atomic<uint64_t> output_fifo_flushed{0};
  std::atomic<uint64_t> output_fifo_rejected{0};
  std::atomic<uint64_t> raw_writes_sent{0};
  std::atomic<uint64_t> raw_writes_failed{0};
  std::atomic<uint64_t> main_drain_runs{0};
  std::atomic<uint64_t> main_drain_tasks_total{0};
  std::atomic<uint64_t> main_drain_tasks_max{0};
  std::atomic<uint64_t> main_drain_budget_hits{0};
  std::atomic<uint64_t> main_drain_deferred_scheduled{0};
  std::atomic<uint64_t> main_drain_deferred_coalesced{0};
  std::atomic<uint64_t> main_drain_deferred_executed{0};
  std::atomic<uint64_t> receive_inline_drain_calls{0};
  std::atomic<uint64_t> receive_deferred_drain_requests{0};
  std::atomic<uint64_t> receive_main_queue_depth_total{0};
  std::atomic<uint64_t> receive_main_queue_depth_max{0};
  std::atomic<uint64_t> receive_main_queue_depth_samples{0};
  std::atomic<uint64_t> main_drain_deferred_wait_ns_total{0};
  std::atomic<uint64_t> main_drain_deferred_wait_ns_max{0};
  std::atomic<uint64_t> main_drain_deferred_wait_samples{0};
  std::atomic<uint64_t> receive_decode_ns_total{0};
  std::atomic<uint64_t> receive_decode_ns_max{0};
  std::atomic<uint64_t> receive_decode_samples{0};
  std::atomic<uint64_t> receive_payload_copy_ns_total{0};
  std::atomic<uint64_t> receive_payload_copy_ns_max{0};
  std::atomic<uint64_t> receive_payload_copy_samples{0};
  std::atomic<uint64_t> receive_enqueue_to_dispatch_ns_total{0};
  std::atomic<uint64_t> receive_enqueue_to_dispatch_ns_max{0};
  std::atomic<uint64_t> receive_enqueue_to_dispatch_samples{0};
  std::atomic<uint64_t> receive_apply_ns_total{0};
  std::atomic<uint64_t> receive_apply_ns_max{0};
  std::atomic<uint64_t> receive_apply_samples{0};
  std::atomic<uint64_t> command_enqueue_to_dispatch_ns_total{0};
  std::atomic<uint64_t> command_enqueue_to_dispatch_ns_max{0};
  std::atomic<uint64_t> command_enqueue_to_dispatch_samples{0};
  std::atomic<uint64_t> command_execute_ns_total{0};
  std::atomic<uint64_t> command_execute_ns_max{0};
  std::atomic<uint64_t> command_execute_samples{0};
  std::atomic<uint64_t> reply_enqueue_to_dispatch_ns_total{0};
  std::atomic<uint64_t> reply_enqueue_to_dispatch_ns_max{0};
  std::atomic<uint64_t> reply_enqueue_to_dispatch_samples{0};
  std::atomic<uint64_t> reply_execute_ns_total{0};
  std::atomic<uint64_t> reply_execute_ns_max{0};
  std::atomic<uint64_t> reply_execute_samples{0};
  std::atomic<uint64_t> output_enqueue_to_dispatch_ns_total{0};
  std::atomic<uint64_t> output_enqueue_to_dispatch_ns_max{0};
  std::atomic<uint64_t> output_enqueue_to_dispatch_samples{0};
  std::atomic<uint64_t> output_execute_ns_total{0};
  std::atomic<uint64_t> output_execute_ns_max{0};
  std::atomic<uint64_t> output_execute_samples{0};
};

extern GatewayRuntimeCounters g_gateway_runtime_counters;

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
  std::string user_ob_name;
  int64_t user_ob_load_time{0};
  std::atomic<bool> command_task_pending{false};
  std::deque<std::string> output_fifo;
  uint64_t output_fifo_enqueued{0};
  uint64_t output_fifo_flushed{0};
  uint64_t output_fifo_rejected{0};
  size_t output_fifo_max_depth{4096};
};

void init_gateway(void);
void cleanup_gateway(void);

int gateway_listen_internal(int port, int bind_all);
mapping_t *gateway_status_internal();
int gateway_get_session_count();
long gateway_session_fifo_depth_total();
long gateway_session_command_pending_count();
uint64_t gateway_session_fifo_enqueued_total();
uint64_t gateway_session_fifo_flushed_total();
uint64_t gateway_session_fifo_rejected_total();
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
uint64_t gateway_enqueue_pending_command_internal(object_t *user);
int gateway_process_pending_command_internal(object_t *user);
int gateway_send_to_session(const char *session_id, const char *data, size_t len);
void gateway_check_session_timeouts();
void cleanup_gateway_sessions();

void gateway_session_exec_update(object_t *new_ob, object_t *old_ob);
void gateway_handle_remove_interactive(interactive_t *ip);
bool gateway_is_session(object_t *ob);

#endif /* PACKAGES_GATEWAY_H */
