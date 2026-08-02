#ifndef PACKAGES_GATEWAY_H
#define PACKAGES_GATEWAY_H

#include "base/package_api.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <event2/listener.h>

struct evbuffer;
struct TickEvent;

using GatewayOutputWriter = int (*)(int fd, const char *data, size_t len);

enum GatewayReadPauseReason : uint8_t {
  GATEWAY_READ_PAUSE_BUFFERED_BACKLOG = 1u << 0,
  GATEWAY_READ_PAUSE_MAIN_QUEUE = 1u << 1,
};

extern int g_gateway_debug;
extern size_t g_gateway_max_packet_size;
extern int g_gateway_max_masters;
extern int g_gateway_max_sessions;
extern int g_gateway_heartbeat_interval;
extern int g_gateway_heartbeat_timeout;
extern int g_gateway_reconnect_grace;

struct GatewayRuntimeCounters {
  std::atomic<uint64_t> data_frames_received{0};
  std::atomic<uint64_t> data_frames_applied{0};
  std::atomic<uint64_t> data_frames_rejected{0};
  std::atomic<uint64_t> ingress_sequence_duplicates{0};
  std::atomic<uint64_t> ingress_sequence_gaps{0};
  std::atomic<uint64_t> ingress_sequence_stream_mismatches{0};
  std::atomic<uint64_t> ingress_sequence_stream_resets{0};
  std::atomic<uint64_t> ingress_ack_frames_sent{0};
  std::atomic<uint64_t> ingress_ack_frames_failed{0};
  std::atomic<uint64_t> stale_master_frames_rejected{0};
  std::atomic<uint64_t> sessions_detached{0};
  std::atomic<uint64_t> session_rebind_attempts{0};
  std::atomic<uint64_t> session_rebind_completed{0};
  std::atomic<uint64_t> session_rebind_rejected{0};
  std::atomic<uint64_t> session_reconnect_expired{0};
  std::atomic<uint64_t> receive_tasks_enqueued{0};
  std::atomic<uint64_t> receive_tasks_dispatched{0};
  std::atomic<uint64_t> receive_tasks_rejected{0};
  std::atomic<uint64_t> read_dispatch_runs{0};
  std::atomic<uint64_t> read_dispatch_frames_total{0};
  std::atomic<uint64_t> read_dispatch_frames_max{0};
  std::atomic<uint64_t> read_dispatch_budget_hits{0};
  std::atomic<uint64_t> read_dispatch_deferred_scheduled{0};
  std::atomic<uint64_t> read_dispatch_deferred_coalesced{0};
  std::atomic<uint64_t> read_dispatch_deferred_executed{0};
  std::atomic<uint64_t> read_dispatch_input_paused{0};
  std::atomic<uint64_t> read_dispatch_input_resumed{0};
  std::atomic<uint64_t> main_queue_read_admission_limited{0};
  std::atomic<uint64_t> main_queue_read_pressure_events{0};
  std::atomic<uint64_t> main_queue_read_paused{0};
  std::atomic<uint64_t> main_queue_read_resumed{0};
  std::atomic<uint64_t> read_dispatch_buffer_compactions{0};
  std::atomic<uint64_t> read_dispatch_buffer_compacted_bytes{0};
  std::atomic<uint64_t> read_dispatch_front_shift_bytes_avoided{0};
  std::atomic<uint64_t> read_dispatch_buffer_peak_bytes{0};
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
  std::atomic<uint64_t> output_fifo_reserved{0};
  std::atomic<uint64_t> output_fifo_filled{0};
  std::atomic<uint64_t> output_fifo_released{0};
  std::atomic<uint64_t> output_fifo_reservation_misses{0};
  std::atomic<uint64_t> output_fifo_writer_failures{0};
  // A ready wire became invalid after max_packet_size was reduced. Unlike a
  // transient writer failure, this entry can never become writable again and
  // must fail closed so it cannot block later FIFO entries forever.
  std::atomic<uint64_t> output_fifo_oversize_dropped{0};
  std::atomic<uint64_t> output_fifo_destroyed_ready{0};
  std::atomic<uint64_t> output_fifo_destroyed_pending{0};
  // A later reservation was filled but could not write because an earlier
  // reservation remains unresolved.  These are aggregate-only FIFO evidence.
  std::atomic<uint64_t> output_fifo_head_blocked_fills{0};
  std::atomic<uint64_t> output_fifo_head_blocked_predecessors_total{0};
  std::atomic<uint64_t> output_fifo_head_blocked_predecessors_max{0};
  std::atomic<uint64_t> output_reserve_ns_total{0};
  std::atomic<uint64_t> output_reserve_ns_max{0};
  std::atomic<uint64_t> output_reserve_samples{0};
  std::atomic<uint64_t> future_watches_registered{0};
  std::atomic<uint64_t> future_watches_rejected{0};
  std::atomic<uint64_t> future_watches_completed{0};
  std::atomic<uint64_t> future_watches_failed{0};
  std::atomic<uint64_t> future_watches_timed_out{0};
  std::atomic<uint64_t> future_watches_cancelled{0};
  std::atomic<uint64_t> future_watch_callbacks{0};
  std::atomic<uint64_t> future_watch_callback_failures{0};
  std::atomic<uint64_t> future_watch_poll_runs{0};
  std::atomic<uint64_t> future_watch_poll_items{0};
  std::atomic<uint64_t> future_watch_poll_budget_hits{0};
  std::atomic<uint64_t> future_watch_completion_notifications{0};
  std::atomic<uint64_t> future_watch_completion_wakeups{0};
  std::atomic<uint64_t> future_watch_timer_wakeups{0};
  std::atomic<uint64_t> future_watch_register_ns_total{0};
  std::atomic<uint64_t> future_watch_register_ns_max{0};
  std::atomic<uint64_t> future_watch_register_samples{0};
  std::atomic<uint64_t> future_watch_terminal_lag_ns_total{0};
  std::atomic<uint64_t> future_watch_terminal_lag_ns_max{0};
  std::atomic<uint64_t> future_watch_terminal_lag_samples{0};
  std::atomic<uint64_t> future_watch_take_ns_total{0};
  std::atomic<uint64_t> future_watch_take_ns_max{0};
  std::atomic<uint64_t> future_watch_take_samples{0};
  std::atomic<uint64_t> future_watch_callback_ns_total{0};
  std::atomic<uint64_t> future_watch_callback_ns_max{0};
  std::atomic<uint64_t> future_watch_callback_samples{0};
  std::atomic<uint64_t> future_watch_end_to_end_ns_total{0};
  std::atomic<uint64_t> future_watch_end_to_end_ns_max{0};
  std::atomic<uint64_t> future_watch_end_to_end_samples{0};
  std::atomic<uint64_t> future_watch_main_completion_thread_cpu_ns_total{0};
  std::atomic<uint64_t> future_watch_main_completion_thread_cpu_unavailable{0};
  std::atomic<uint64_t> generic_future_watches_registered{0};
  std::atomic<uint64_t> generic_future_watches_rejected{0};
  std::atomic<uint64_t> generic_future_watches_completed{0};
  std::atomic<uint64_t> generic_future_watches_failed{0};
  std::atomic<uint64_t> generic_future_watches_timed_out{0};
  std::atomic<uint64_t> generic_future_watches_cancelled{0};
  std::atomic<uint64_t> generic_future_watch_callbacks{0};
  std::atomic<uint64_t> generic_future_watch_callback_failures{0};
  std::atomic<uint64_t> raw_writes_sent{0};
  std::atomic<uint64_t> raw_writes_failed{0};
  std::atomic<uint64_t> master_tcp_nodelay_enabled{0};
  std::atomic<uint64_t> master_tcp_nodelay_failed{0};
  std::atomic<uint64_t> main_drain_runs{0};
  std::atomic<uint64_t> main_drain_tasks_total{0};
  std::atomic<uint64_t> main_drain_tasks_max{0};
  std::atomic<uint64_t> main_drain_budget_hits{0};
  std::atomic<uint64_t> main_drain_deferred_scheduled{0};
  std::atomic<uint64_t> main_drain_deferred_coalesced{0};
  std::atomic<uint64_t> main_drain_deferred_executed{0};
  std::atomic<uint64_t> main_drain_deferred_backlog_boosted{0};
  std::atomic<uint64_t> main_drain_deferred_tasks_total{0};
  std::atomic<uint64_t> main_drain_deferred_tasks_max{0};
  std::atomic<uint64_t> main_drain_deferred_wall_ns_total{0};
  std::atomic<uint64_t> main_drain_deferred_wall_ns_max{0};
  std::atomic<uint64_t> main_drain_deferred_wall_samples{0};
  std::atomic<uint64_t> main_drain_deferred_wall_budget_yields{0};
  std::atomic<uint64_t> main_drain_deferred_task_budget_yields{0};
  std::atomic<uint64_t> main_drain_deferred_remaining_total{0};
  std::atomic<uint64_t> main_drain_deferred_remaining_max{0};
  std::atomic<uint64_t> main_drain_deferred_remaining_samples{0};
  std::atomic<uint64_t> main_drain_deferred_main_task_wall_ns_max{0};
  std::atomic<uint64_t> main_drain_deferred_main_tasks_exceeding_wall_budget{0};
  std::atomic<uint64_t> read_batch_drain_runs{0};
  std::atomic<uint64_t> read_batch_drain_tasks_total{0};
  std::atomic<uint64_t> read_batch_drain_tasks_max{0};
  std::atomic<uint64_t> read_batch_drain_backlog_rescheduled{0};
  std::atomic<uint64_t> read_batch_drain_wall_ns_total{0};
  std::atomic<uint64_t> read_batch_drain_wall_ns_max{0};
  std::atomic<uint64_t> read_batch_drain_wall_samples{0};
  std::atomic<uint64_t> read_batch_drain_wall_budget_yields{0};
  std::atomic<uint64_t> read_batch_drain_task_budget_yields{0};
  std::atomic<uint64_t> read_batch_drain_remaining_total{0};
  std::atomic<uint64_t> read_batch_drain_remaining_max{0};
  std::atomic<uint64_t> read_batch_drain_remaining_samples{0};
  std::atomic<uint64_t> read_batch_drain_main_task_wall_ns_max{0};
  std::atomic<uint64_t> read_batch_drain_main_tasks_exceeding_wall_budget{0};
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
  std::atomic<uint64_t> receive_apply_thread_cpu_ns_total{0};
  std::atomic<uint64_t> receive_apply_thread_cpu_ns_max{0};
  std::atomic<uint64_t> receive_apply_thread_cpu_samples{0};
  std::atomic<uint64_t> receive_apply_thread_cpu_unavailable{0};
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
  std::atomic<uint64_t> message_event_template_cache_hits{0};
  std::atomic<uint64_t> message_event_template_cache_misses{0};
  std::atomic<uint64_t> message_event_template_cache_evictions{0};
  std::atomic<uint64_t> message_event_template_cache_bypasses{0};
  std::atomic<uint64_t> room_output_projection_snapshot_ns_total{0};
  std::atomic<uint64_t> room_output_projection_snapshot_ns_max{0};
  std::atomic<uint64_t> room_output_projection_snapshot_samples{0};
  std::atomic<uint64_t> room_output_projection_submit_watch_ns_total{0};
  std::atomic<uint64_t> room_output_projection_submit_watch_ns_max{0};
  std::atomic<uint64_t> room_output_projection_submit_watch_samples{0};
  std::atomic<uint64_t> room_output_projection_worker_ns_total{0};
  std::atomic<uint64_t> room_output_projection_worker_ns_max{0};
  std::atomic<uint64_t> room_output_projection_worker_samples{0};
  std::atomic<uint64_t> room_output_projection_worker_thread_cpu_ns_total{0};
  std::atomic<uint64_t> room_output_projection_worker_thread_cpu_ns_max{0};
  std::atomic<uint64_t> room_output_projection_worker_thread_cpu_samples{0};
  std::atomic<uint64_t> room_output_projection_worker_thread_cpu_unavailable{0};
  std::atomic<uint64_t> room_output_projection_inline_thread_cpu_ns_total{0};
  std::atomic<uint64_t> room_output_projection_inline_thread_cpu_ns_max{0};
  std::atomic<uint64_t> room_output_projection_inline_thread_cpu_samples{0};
  std::atomic<uint64_t> room_output_projection_inline_thread_cpu_unavailable{0};
  std::atomic<uint64_t> room_output_projection_publish_ns_total{0};
  std::atomic<uint64_t> room_output_projection_publish_ns_max{0};
  std::atomic<uint64_t> room_output_projection_publish_samples{0};
  std::atomic<uint64_t> room_output_projection_submitted{0};
  std::atomic<uint64_t> room_output_projection_completed{0};
  std::atomic<uint64_t> room_output_projection_released{0};
  std::atomic<uint64_t> room_output_projection_inline_fallbacks{0};
  std::atomic<uint64_t> room_output_projection_failed{0};
  std::atomic<uint64_t> room_output_projection_forced_cleanup{0};
  std::atomic<uint64_t> room_output_projection_retry_enqueued{0};
  std::atomic<uint64_t> room_output_projection_retry_attempted{0};
  std::atomic<uint64_t> room_output_projection_retry_exhausted{0};
  std::atomic<uint64_t> room_output_projection_retry_budget_hits{0};
  std::atomic<uint64_t> room_output_projection_retry_wall_budget_hits{0};
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
  size_t read_buffer_offset{0};
  bool read_dispatch_scheduled{false};
  TickEvent *read_dispatch_event{nullptr};
  bool read_dispatch_pending{false};
  bool read_dispatch_input_paused{false};
  uint8_t read_dispatch_pause_reasons{0};
  bool ingress_ack_pending{false};
  uint64_t ingress_ack_sequence{0};

  ~GatewayMaster();
};

struct GatewayMessageEventTemplate {
  std::string encoded;
  std::string stable_members;
  std::string reliability_json;
  std::string priority_json;
  std::string collapse_key_json;
  std::string outer_escaped_stable_members;
  std::string outer_escaped_reliability_json;
  std::string outer_escaped_priority_json;
  std::string outer_escaped_collapse_key_json;
  LPC_INT ttl_ms{0};
  bool has_id{false};
  bool has_scope{false};
  bool has_causation_id{false};
  bool has_correlation_id{false};
};

struct GatewayPreencodedMessageEventWave {
  std::string scope_type;
  std::string outer_escaped_scope_type_json;
  GatewayMessageEventTemplate message_template;
  uint64_t wave_id{0};
  LPC_INT sent_at{0};
};

enum class GatewayMessageEventReservationOrigin : uint8_t {
  kUnspecified = 0,
  kReused,
  kCreated,
};

struct GatewayPendingMessageEvent {
  std::shared_ptr<const GatewayPreencodedMessageEventWave> wave;
  LPC_INT message_seq{0};
  LPC_INT server_seq{0};
  LPC_INT epoch{0};
  GatewayMessageEventReservationOrigin reservation_origin{
      GatewayMessageEventReservationOrigin::kUnspecified};
};

struct GatewayPendingMessageEventBatch {
  std::vector<GatewayPendingMessageEvent> events;
  LPC_INT slot_server_seq{0};
  LPC_INT slot_sent_at{0};
  uint64_t projection_generation{0};
  bool projection_sealed{false};
};

struct GatewayOutputEntry {
  uint64_t reservation_id{0};
  bool ready{true};
  // Complete southbound JSON consumed by the Go Gateway, never an inner XK frame.
  std::string wire_bytes;
  std::unique_ptr<GatewayPendingMessageEventBatch> pending_message_batch;
};

struct GatewaySession {
  std::string session_id;
  std::string real_ip;
  int real_port{0};
  int master_fd{-1};
  time_t detached_at{0};
  time_t connected_at{0};
  time_t last_active{0};
  object_t *user_ob{nullptr};
  std::string user_ob_name;
  int64_t user_ob_load_time{0};
  std::atomic<bool> command_input_pending{false};
  std::atomic<bool> command_task_pending{false};
  bool probe_suppressed_once{false};
  std::deque<GatewayOutputEntry> output_fifo;
  uint64_t output_fifo_enqueued{0};
  uint64_t output_fifo_flushed{0};
  uint64_t output_fifo_rejected{0};
  size_t output_fifo_max_depth{4096};
};

struct GatewaySessionBatchReservationResult {
  std::vector<uint64_t> reservation_ids;
  std::vector<bool> reused;
  uint64_t wave_id{0};
};

struct GatewayPendingMessageEventBatchFillResult {
  std::vector<bool> filled;
  std::vector<LPC_INT> event_counts;
  std::vector<LPC_INT> slot_server_seqs;
};

// Object-free immutable input shared by inline and owner projection. Dynamic
// session metadata lives in the separate columns structure below.
struct GatewayPendingMessageEventProjectionSnapshot {
  std::vector<std::shared_ptr<const GatewayPreencodedMessageEventWave>>
      wave_table;
  std::vector<size_t> event_wave_indices;
  uint64_t generation{0};
};

struct GatewayPendingMessageEventProjectionColumns {
  std::string session_id;
  std::string scope_id;
  std::vector<LPC_INT> message_seqs;
  std::vector<LPC_INT> server_seqs;
  std::vector<LPC_INT> message_epochs;
  LPC_INT slot_server_seq{0};
  LPC_INT slot_epoch{0};
  LPC_INT slot_sent_at{0};
};

struct GatewayPendingMessageEventBatchOwnerSubmitResult {
  std::vector<bool> submitted;
  std::vector<bool> filled_inline;
  std::vector<LPC_INT> event_counts;
  std::vector<LPC_INT> slot_server_seqs;
  std::vector<uint64_t> future_ids;
};

void init_gateway(void);
void cleanup_gateway(void);

int gateway_listen_internal(int port, int bind_all);
mapping_t *gateway_status_internal();
int gateway_get_session_count();
long gateway_session_fifo_depth_total();
long gateway_session_fifo_pending_reservations_total();
long gateway_session_command_input_pending_count();
long gateway_session_command_task_pending_count();
long gateway_session_command_pending_count();
long gateway_read_dispatch_pending_count();
long gateway_buffered_input_pending_count();
long gateway_command_pressure_count();
long gateway_main_queue_pending_count();
uint64_t gateway_session_fifo_enqueued_total();
uint64_t gateway_session_fifo_flushed_total();
uint64_t gateway_session_fifo_rejected_total();
int gateway_flush_session_output_fifo_with_writer(GatewaySession *sess, GatewayOutputWriter writer);
int gateway_flush_session_output_fifo(GatewaySession *sess);
int gateway_enqueue_session_protocol_output(GatewaySession *sess, const char *data,
                                            size_t len);
uint64_t gateway_reserve_session_output(GatewaySession *sess);
bool gateway_session_pending_reservation_has_ready_successor(
    const GatewaySession *sess, uint64_t reservation_id);
bool gateway_reserve_session_outputs(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &existing_reservation_ids,
    GatewaySessionBatchReservationResult *result);
bool gateway_append_preencoded_message_event_wave(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<LPC_INT> &slot_server_seqs,
    const std::vector<LPC_INT> &message_server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &message_seqs, const std::string &stable_json,
    const std::string &scope_type, LPC_INT sent_at, size_t batch_limit);
bool gateway_reserve_and_append_preencoded_message_event_wave(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &existing_reservation_ids,
    LPC_INT first_server_seq,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &message_seqs, const std::string &stable_json,
    const std::string &scope_type, LPC_INT sent_at, size_t batch_limit,
    GatewaySessionBatchReservationResult *result);
bool gateway_rollback_preencoded_message_event_wave_with_writer(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<bool> &reused, uint64_t wave_id,
    GatewayOutputWriter writer);
size_t gateway_pending_message_event_count(const GatewaySession *sess,
                                           uint64_t reservation_id);
int gateway_fill_pending_message_event_batch_with_writer(
    GatewaySession *sess, uint64_t reservation_id, const std::string &scope_id,
    LPC_INT slot_epoch, GatewayOutputWriter writer);
bool gateway_fill_pending_message_event_batches_with_writer(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<std::string> &scope_ids,
    const std::vector<LPC_INT> &slot_epochs, GatewayOutputWriter writer,
    GatewayPendingMessageEventBatchFillResult *result);
bool gateway_snapshot_pending_message_event_batch(
    const GatewaySession *sess, uint64_t reservation_id,
    const std::string &scope_id, LPC_INT slot_epoch,
    GatewayPendingMessageEventProjectionSnapshot *snapshot,
    GatewayPendingMessageEventProjectionColumns *columns);
bool gateway_encode_pending_message_event_projection(
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns,
    std::string *wire_bytes);
bool gateway_submit_pending_message_event_batches_for_objects(
    const std::vector<object_t *> &targets,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<std::string> &scope_ids,
    const std::vector<LPC_INT> &slot_epochs, int timeout_ms,
    GatewayPendingMessageEventBatchOwnerSubmitResult *result);
int gateway_fill_pending_message_event_batch_for_object(
    object_t *ob, uint64_t reservation_id, const char *scope_id,
    size_t scope_id_len, LPC_INT slot_epoch);
int gateway_fill_session_protocol_output_with_writer(
    GatewaySession *sess, uint64_t reservation_id, const char *data, size_t len,
    GatewayOutputWriter writer);
int gateway_release_session_output_with_writer(GatewaySession *sess, uint64_t reservation_id,
                                               GatewayOutputWriter writer);
int gateway_release_session_output(GatewaySession *sess, uint64_t reservation_id);
uint64_t gateway_reserve_session_output_for_object(object_t *ob);
int gateway_fill_session_output_for_object(object_t *ob, uint64_t reservation_id, const char *data, size_t len);
int gateway_release_session_output_for_object(object_t *ob, uint64_t reservation_id);
int gateway_session_pending_reservation_has_ready_successor_for_object(
    object_t *ob, uint64_t reservation_id);
int gateway_watch_session_future_for_object(object_t *ob, uint64_t reservation_id,
                                            uint64_t future_id, int timeout_ms);
int gateway_watch_session_future_output_for_object(object_t *ob, uint64_t reservation_id,
                                                   uint64_t future_id, int timeout_ms);
int gateway_watch_future_for_object(object_t *ob, uint64_t context_id,
                                    uint64_t future_id, int timeout_ms);
int gateway_process_session_future_watches_at(uint64_t now_ms);
int gateway_process_future_watches_at(uint64_t now_ms);
long gateway_session_future_watch_count();
long gateway_room_output_projection_pending_count();
long gateway_room_output_projection_wave_count();
long gateway_room_output_projection_reservation_count();
long gateway_room_output_projection_retry_count();
long gateway_future_watch_count();
mapping_t *gateway_owner_output_quiesce(const char *reason);
int gateway_send_raw_to_fd(int fd, const char *data, size_t len);
int gateway_svalue_to_json_string(const svalue_t *sv, std::string *out);
int gateway_ping_master_internal(int fd);
void gateway_check_heartbeat_timeouts();
bool gateway_has_master(int fd);

// C++ regression hooks; not part of the LPC/runtime API.
bool gateway_dispatch_message_for_test(int fd, const char *payload);
int gateway_dispatch_buffered_frames_for_test(GatewayMaster *master, int budget);
void gateway_set_read_dispatch_pending_for_test(GatewayMaster *master, bool pending);
void gateway_service_admitted_receive_tasks_for_test();
bool gateway_master_has_buffered_input_for_test(const GatewayMaster *master);
GatewayMaster *gateway_register_master_for_test(int fd, bufferevent *bev);
void gateway_remove_master_for_test(int fd);
void gateway_reset_ingress_sequence_for_test();
int gateway_append_framed_output_for_test(evbuffer *output, const char *data,
                                          size_t len);
std::string gateway_encode_output_envelope_for_test(const std::string &session_id,
                                                    const char *data, size_t len);
int gateway_enqueue_session_wire_json_for_test(GatewaySession *sess,
                                               const std::string &wire_json);
int gateway_enqueue_session_payload_json_for_test(
    GatewaySession *sess, const std::string &payload_json);
bool gateway_fill_projected_wires_for_test(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<std::string> &wire_json,
    GatewayOutputWriter writer);
void gateway_reset_projected_wire_full_validation_count_for_test();
uint64_t gateway_projected_wire_full_validation_count_for_test();
bool gateway_drop_room_output_wave_for_test(uint64_t reservation_id);
std::string gateway_encode_preencoded_chat_batch_for_test(
    const std::vector<std::string> &stable_children_json, LPC_INT message_epoch,
    LPC_INT first_server_seq, LPC_INT sent_at, const std::string &outer_dynamic_json);
std::string gateway_encode_preencoded_message_event_batch_for_test(
    const std::vector<std::string> &stable_children_json,
    const std::vector<std::string> &scope_types, const std::string &scope_id,
    const std::vector<LPC_INT> &message_seqs,
    const std::vector<LPC_INT> &server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &sent_ats, LPC_INT slot_server_seq,
    LPC_INT slot_epoch, LPC_INT slot_sent_at);
void gateway_clear_message_event_template_cache_for_test();

GatewaySession *gateway_find_session(const char *session_id);
GatewaySession *gateway_find_session_by_object(object_t *ob);
int gateway_bind_session_object(const char *session_id, object_t *ob, const char *ip,
                                int port, int master_fd);
object_t *gateway_rebind_session_internal(const char *session_id, const char *ip,
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
int gateway_probe_suppress_once_for_object(object_t *ob);
bool gateway_probe_suppressed_for_object(object_t *ob);
void gateway_probe_finish_suppressed_command_for_object(object_t *ob);

#endif /* PACKAGES_GATEWAY_H */
