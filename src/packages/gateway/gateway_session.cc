#include "base/package_api.h"

#include "gateway.h"

#include "base/internal/external_port.h"
#include "comm.h"
#include "packages/core/dns.h"
#include "user.h"
#include "vm/context.h"
#include "vm/owner.h"

#include <event2/event.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

uint64_t gateway_enqueue_pending_command_internal(object_t *user);

namespace {
std::unordered_map<std::string, std::unique_ptr<GatewaySession>> g_gateway_sessions;
std::unordered_map<object_t *, GatewaySession *> g_gateway_obj_to_session;
constexpr const char *kGatewayCommandExecutorActivationBlocker =
    "interactive_command_requires_main_thread_io_adapter";
constexpr int kGatewayCommandMainDrainBudget = 16;

uint64_t gateway_session_now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

void gateway_session_record_max(std::atomic<uint64_t> &counter, uint64_t value) {
  auto current = counter.load(std::memory_order_relaxed);
  while (value > current && !counter.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
  }
}

void gateway_session_record_latency(std::atomic<uint64_t> &total, std::atomic<uint64_t> &max,
                                    std::atomic<uint64_t> &samples, uint64_t elapsed_ns) {
  total.fetch_add(elapsed_ns, std::memory_order_relaxed);
  samples.fetch_add(1, std::memory_order_relaxed);
  gateway_session_record_max(max, elapsed_ns);
}

class GatewayControlledLpcScope {
 public:
  GatewayControlledLpcScope() : previous_(vm_context().owner.controlled_lpc_active) {
    vm_context().owner.controlled_lpc_active = true;
  }
  ~GatewayControlledLpcScope() { vm_context().owner.controlled_lpc_active = previous_; }

 private:
  bool previous_;
};

bool gateway_object_valid(object_t *ob) {
  return ob && !(ob->flags & O_DESTRUCTED) && ob->obname && ob->obname[0] != '\0';
}

void gateway_debugf(const char *fmt, ...) {
  va_list args;
  char buffer[1024];

  if (!g_gateway_debug) {
    return;
  }
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  debug_message("%s", buffer);
}

std::string gateway_pending_command_snapshot(interactive_t *user) {
  if (!user || !(user->iflags & CMD_IN_BUF) || user->text_end < user->text_start) {
    return {};
  }

  if (user->iflags & SINGLE_CHAR) {
    if (user->text_start >= user->text_end) {
      return {};
    }
    auto c = user->text[user->text_start];
    if (c == 8 || c == 127) {
      return {};
    }
    return std::string(1, c);
  }

  auto end = user->text_start;
  while (end < user->text_end && user->text[end] != '\n' && user->text[end] != '\r') {
    end++;
  }
  return std::string(user->text + user->text_start, user->text + end);
}

bool gateway_executor_session_current(object_t *user, interactive_t *ip) {
  return ip && ::gateway_is_session(user) && user->interactive == ip && ip->ob == user &&
         !(user->flags & O_DESTRUCTED);
}

object_t *resolve_active_session_owner(const char *session_id, object_t *fallback = nullptr);

svalue_t gateway_command_task_payload(interactive_t *user, bool snapshot_ready, size_t snapshot_bytes) {
  svalue_t payload{};
  auto pending_bytes = user && user->text_end >= user->text_start ? user->text_end - user->text_start : 0;
#if defined(F_INPUT_TO) || defined(F_GET_CHAR)
  auto input_callback_active = user && user->input_to ? 1 : 0;
  auto input_callback_carryover_count = user ? user->num_carry : 0;
#else
  auto input_callback_active = 0;
  auto input_callback_carryover_count = 0;
#endif

  payload.type = T_MAPPING;
  payload.u.map = allocate_mapping(96);
  add_mapping_string(payload.u.map, "payload_model", "gateway_command_buffer_metadata_v1");
  add_mapping_string(payload.u.map, "payload_policy", "no_raw_command_text_in_trace");
  add_mapping_string(payload.u.map, "input_source", "interactive_text_buffer");
  add_mapping_string(payload.u.map, "vm_internal_string_encoding", "utf-8");
  add_mapping_pair(payload.u.map, "session_encoding_contract_ready", 1);
  add_mapping_pair(payload.u.map, "gateway_encoding_boundary_ready", 1);
  add_mapping_string(payload.u.map, "gateway_command_encoding_model",
                     "session_encoding_to_vm_utf8_before_owner_executor");
  add_mapping_string(payload.u.map, "gateway_command_payload_encoding", "utf-8");
  add_mapping_string(payload.u.map, "command_text_snapshot_policy", "owner_private_redacted_from_trace");
  add_mapping_pair(payload.u.map, "command_text_snapshot_ready", snapshot_ready ? 1 : 0);
  add_mapping_pair(payload.u.map, "command_text_snapshot_bytes", static_cast<long>(snapshot_bytes));
  add_mapping_pair(payload.u.map, "command_text_snapshot_redacted", snapshot_ready ? 1 : 0);
  add_mapping_string(payload.u.map, "input_callback_state_policy", "redacted_input_to_get_char_state_v1");
  add_mapping_pair(payload.u.map, "input_callback_state_snapshot_ready", 1);
  add_mapping_pair(payload.u.map, "input_callback_state_redacted", 1);
  add_mapping_string(payload.u.map, "input_callback_frame_model", "owner_command_frame_input_callback_detach_v1");
  add_mapping_pair(payload.u.map, "input_callback_frame_detach_ready", 1);
  add_mapping_pair(payload.u.map, "input_callback_frame_executor_ready", 1);
  add_mapping_string(payload.u.map, "input_callback_apply_frame_model", "owner_command_frame_input_callback_apply");
  add_mapping_string(payload.u.map, "input_callback_apply_frame_task_type", "interactive_input_callback");
  add_mapping_pair(payload.u.map, "input_callback_apply_frame_ready", 1);
  add_mapping_pair(payload.u.map, "input_callback_apply_frame_executor_ready", 1);
  add_mapping_string(payload.u.map, "input_callback_mode_delta_model",
                     "owner_command_frame_input_callback_mode_delta");
  add_mapping_pair(payload.u.map, "input_callback_mode_delta_ready", 1);
  add_mapping_pair(payload.u.map, "input_callback_mode_delta_executor_ready", 1);
  add_mapping_pair(payload.u.map, "input_callback_active", input_callback_active);
  add_mapping_pair(payload.u.map, "input_callback_single_char", user && (user->iflags & SINGLE_CHAR) ? 1 : 0);
  add_mapping_pair(payload.u.map, "input_callback_noescape", user && (user->iflags & NOESC) ? 1 : 0);
  add_mapping_pair(payload.u.map, "input_callback_noecho", user && (user->iflags & NOECHO) ? 1 : 0);
  add_mapping_pair(payload.u.map, "input_callback_carryover_count", input_callback_carryover_count);
  add_mapping_pair(payload.u.map, "input_callback_function_redacted", input_callback_active);
  add_mapping_pair(payload.u.map, "input_callback_object_redacted", input_callback_active);
  add_mapping_string(payload.u.map, "process_input_add_action_parser_state_policy",
                     "redacted_process_input_add_action_parser_state_v1");
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_state_snapshot_ready", 1);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_state_redacted", 1);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_has_process_input",
                   user && (user->iflags & HAS_PROCESS_INPUT) ? 1 : 0);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_safe_parse_fallback", 1);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_requires_command_giver", 1);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_command_giver_redacted", 1);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_command_text_redacted", snapshot_ready ? 1 : 0);
  add_mapping_string(payload.u.map, "process_input_apply_frame_model", "owner_command_frame_process_input_apply");
  add_mapping_string(payload.u.map, "process_input_apply_frame_task_type", "interactive_command_parser");
  add_mapping_pair(payload.u.map, "process_input_apply_frame_ready", 1);
  add_mapping_pair(payload.u.map, "process_input_apply_frame_executor_ready", 1);
  add_mapping_string(payload.u.map, "process_input_add_action_parser_frame_model",
                     "owner_command_parser_context_v1");
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_frame_ready", 1);
  add_mapping_pair(payload.u.map, "process_input_add_action_parser_frame_executor_ready", 1);
  add_mapping_string(payload.u.map, "process_input_add_action_parser_blocker", "");
  add_mapping_string(payload.u.map, "interactive_mode_flags_state_policy", "redacted_interactive_mode_flags_v1");
  add_mapping_pair(payload.u.map, "interactive_mode_flags_state_snapshot_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_flags_state_redacted", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_noecho", user && (user->iflags & NOECHO) ? 1 : 0);
  add_mapping_string(payload.u.map, "interactive_mode_localecho_restore_model",
                     "owner_command_frame_localecho_restore");
  add_mapping_string(payload.u.map, "interactive_mode_localecho_restore_task_type", "interactive_mode_flags");
  add_mapping_string(payload.u.map, "interactive_mode_localecho_restore_boundary",
                     "main_reply_queue_after_command_consume");
  add_mapping_pair(payload.u.map, "interactive_mode_localecho_restore_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_localecho_restore_executor_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_localecho_restore_required", user && (user->iflags & NOECHO) ? 1 : 0);
  add_mapping_string(payload.u.map, "interactive_mode_terminal_mode_delta_boundary",
                     "main_mode_delta_queue_after_command_consume");
  add_mapping_pair(payload.u.map, "interactive_mode_terminal_mode_delta_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_terminal_linemode_restore_required",
                   input_callback_active && user && (user->iflags & SINGLE_CHAR) ? 1 : 0);
  add_mapping_pair(payload.u.map, "interactive_mode_terminal_charmode_restore_required",
                   user && (user->iflags & WAS_SINGLE_CHAR) ? 1 : 0);
  add_mapping_pair(payload.u.map, "interactive_mode_noescape", user && (user->iflags & NOESC) ? 1 : 0);
  add_mapping_pair(payload.u.map, "interactive_mode_single_char", user && (user->iflags & SINGLE_CHAR) ? 1 : 0);
  add_mapping_pair(payload.u.map, "interactive_mode_was_single_char", user && (user->iflags & WAS_SINGLE_CHAR) ? 1 : 0);
  add_mapping_pair(payload.u.map, "interactive_mode_using_mxp", user && (user->iflags & USING_MXP) ? 1 : 0);
  add_mapping_string(payload.u.map, "interactive_mode_mxp_tag_filter_model", "owner_command_frame_mxp_tag_filter");
  add_mapping_string(payload.u.map, "interactive_mode_mxp_tag_filter_task_type", "interactive_mode_flags");
  add_mapping_pair(payload.u.map, "interactive_mode_mxp_tag_filter_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_mxp_tag_filter_executor_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_mxp_tag_filter_required",
                   user && (user->iflags & USING_MXP) ? 1 : 0);
  add_mapping_string(payload.u.map, "interactive_mode_ed_command_model", "owner_command_frame_ed_command");
  add_mapping_string(payload.u.map, "interactive_mode_ed_command_task_type", "interactive_mode_flags");
  add_mapping_pair(payload.u.map, "interactive_mode_ed_command_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_ed_command_executor_ready", 1);
  add_mapping_pair(payload.u.map, "interactive_mode_ed_command_required", user && user->ed_buffer ? 1 : 0);
  add_mapping_pair(payload.u.map, "interactive_mode_ed_buffer_active", user && user->ed_buffer ? 1 : 0);
  add_mapping_string(payload.u.map, "prompt_telnet_reschedule_state_policy",
                     "redacted_prompt_telnet_reschedule_io_v1");
  add_mapping_pair(payload.u.map, "prompt_telnet_reschedule_state_snapshot_ready", 1);
  add_mapping_pair(payload.u.map, "prompt_telnet_reschedule_state_redacted", 1);
  add_mapping_string(payload.u.map, "prompt_telnet_reschedule_boundary", "main_reply_queue_after_owner_command");
  add_mapping_pair(payload.u.map, "prompt_telnet_reschedule_reply_queue_ready", 1);
  add_mapping_pair(payload.u.map, "prompt_telnet_reschedule_blocks_activation", 0);
  add_mapping_pair(payload.u.map, "prompt_has_write_prompt", user && (user->iflags & HAS_WRITE_PROMPT) ? 1 : 0);
  add_mapping_pair(payload.u.map, "prompt_text_redacted", user && user->prompt ? 1 : 0);
  add_mapping_pair(payload.u.map, "prompt_write_prompt_apply_required",
                   user && (user->iflags & HAS_WRITE_PROMPT) && !user->ed_buffer ? 1 : 0);
  add_mapping_string(payload.u.map, "prompt_write_prompt_apply_frame_model",
                     "owner_command_frame_write_prompt_apply");
  add_mapping_string(payload.u.map, "prompt_write_prompt_apply_frame_task_type", "command_reply");
  add_mapping_pair(payload.u.map, "prompt_write_prompt_apply_frame_ready", 1);
  add_mapping_pair(payload.u.map, "prompt_write_prompt_apply_frame_executor_ready", 0);
  add_mapping_pair(payload.u.map, "telnet_handle_active", user && user->telnet ? 1 : 0);
  add_mapping_pair(payload.u.map, "telnet_using_telnet", user && (user->iflags & USING_TELNET) ? 1 : 0);
  add_mapping_pair(payload.u.map, "telnet_suppress_ga", user && (user->iflags & SUPPRESS_GA) ? 1 : 0);
  add_mapping_pair(payload.u.map, "telnet_ga_required",
                   user && user->telnet && (user->iflags & USING_TELNET) && !(user->iflags & SUPPRESS_GA) ? 1 : 0);
  add_mapping_pair(payload.u.map, "reschedule_cmd_in_buf", user && (user->iflags & CMD_IN_BUF) ? 1 : 0);
  add_mapping_string(payload.u.map, "command_executor_blocker", kGatewayCommandExecutorActivationBlocker);
  add_mapping_string(payload.u.map, "command_consume_model", "owner_owned_snapshot_main_thread_consume");
  add_mapping_pair(payload.u.map, "command_consume_snapshot_ready", snapshot_ready ? 1 : 0);
  add_mapping_pair(payload.u.map, "command_consume_executor_ready", 0);
  add_mapping_string(payload.u.map, "command_consume_blocker",
                     snapshot_ready ? kGatewayCommandExecutorActivationBlocker : "interactive_command_buffer_not_snapshotted");
  add_mapping_string(payload.u.map, "execution_frame_restore_policy", "main_thread_vmcontext_scope");
  add_mapping_pair(payload.u.map, "execution_frame_restore_ready", 1);
  add_mapping_string(payload.u.map, "execution_frame_restore_blocker", "");
  add_mapping_string(payload.u.map, "session_id", user && user->gateway_session_id ? user->gateway_session_id : "");
  add_mapping_pair(payload.u.map, "pending_bytes", pending_bytes);
  add_mapping_pair(payload.u.map, "text_start", user ? user->text_start : 0);
  add_mapping_pair(payload.u.map, "text_end", user ? user->text_end : 0);
  add_mapping_pair(payload.u.map, "cmd_in_buf", user && (user->iflags & CMD_IN_BUF) ? 1 : 0);
  add_mapping_pair(payload.u.map, "gateway_session", user && (user->iflags & GATEWAY_SESSION) ? 1 : 0);
  return payload;
}

void cleanup_temp_gateway_interactive(object_t *owner) {
  auto *ip = owner ? owner->interactive : nullptr;
  if (!ip) {
    return;
  }

  if (ip->ev_command) {
    evtimer_del(ip->ev_command);
    event_free(ip->ev_command);
    ip->ev_command = nullptr;
  }
  if (ip->gateway_session_id) {
    FREE_MSTR(ip->gateway_session_id);
    ip->gateway_session_id = nullptr;
  }
  if (ip->gateway_real_ip) {
    FREE_MSTR(ip->gateway_real_ip);
    ip->gateway_real_ip = nullptr;
  }

  user_del(ip);
  FREE(ip);
  owner->interactive = nullptr;
}

void gateway_command_callback(evutil_socket_t /*fd*/, short /*what*/, void *arg) {
  auto *user = reinterpret_cast<interactive_t *>(arg);
  if (!user) {
    return;
  }
  g_gateway_runtime_counters.command_callbacks.fetch_add(1, std::memory_order_relaxed);

  if (g_gateway_debug && user->gateway_session_id) {
    debug_message("[gateway] command_callback begin sid=%s\n", user->gateway_session_id);
  }

  if (user->ob && !(user->ob->flags & O_DESTRUCTED)) {
    auto task_id = gateway_enqueue_pending_command_internal(user->ob);
    if (task_id != 0) {
      auto drained = vm_owner_drain_main_tasks(kGatewayCommandMainDrainBudget);
      g_gateway_runtime_counters.main_drain_runs.fetch_add(1, std::memory_order_relaxed);
      g_gateway_runtime_counters.main_drain_tasks_total.fetch_add(static_cast<uint64_t>(drained),
                                                                  std::memory_order_relaxed);
      gateway_session_record_max(g_gateway_runtime_counters.main_drain_tasks_max, static_cast<uint64_t>(drained));
      if (drained >= kGatewayCommandMainDrainBudget) {
        g_gateway_runtime_counters.main_drain_budget_hits.fetch_add(1, std::memory_order_relaxed);
      }
    }
  } else {
    set_eval(max_eval_cost);
    process_user_command(user);
    vm_context_set_current_interactive(vm_context(), nullptr);
  }
}

bool gateway_mark_command_task_pending(GatewaySession *sess) {
  if (!sess) {
    return false;
  }
  bool expected = false;
  return sess->command_task_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                           std::memory_order_acquire);
}

void gateway_clear_command_task_pending(const std::string &session_id) {
  auto *sess = gateway_find_session(session_id.c_str());
  if (!sess) {
    return;
  }
  if (sess->command_task_pending.exchange(false, std::memory_order_acq_rel)) {
    g_gateway_runtime_counters.command_tasks_cleared.fetch_add(1, std::memory_order_relaxed);
  }
}

void gateway_finish_command_task(const std::string &session_id, object_t *fallback) {
  auto *sess = gateway_find_session(session_id.c_str());
  if (!sess) {
    return;
  }

  if (sess->command_task_pending.exchange(false, std::memory_order_acq_rel)) {
    g_gateway_runtime_counters.command_tasks_cleared.fetch_add(1, std::memory_order_relaxed);
  }
  g_gateway_runtime_counters.command_tasks_finished.fetch_add(1, std::memory_order_relaxed);
  auto *active_user = resolve_active_session_owner(session_id.c_str(), fallback);
  auto *active_ip = active_user ? active_user->interactive : nullptr;
  if (!gateway_executor_session_current(active_user, active_ip)) {
    return;
  }
  /*
   * Do not enqueue the next buffered command here. process_user_command_text()
   * queues command reply side effects, and that path reschedules the command
   * event if CMD_IN_BUF is still set. Keeping the next command behind a fresh
   * event preserves the driver command fairness rule and prevents one gateway
   * drain from chasing a large buffered burst on the main thread.
   */
  (void)active_ip;
}

object_t *resolve_active_session_owner(const char *session_id, object_t *fallback) {
  auto *sess = gateway_find_session(session_id);
  if (sess && gateway_object_valid(sess->user_ob) && sess->user_ob->interactive &&
      sess->user_ob->interactive->ob == sess->user_ob) {
    return sess->user_ob;
  }
  if (gateway_object_valid(fallback) && fallback->interactive &&
      fallback->interactive->ob == fallback) {
    return fallback;
  }
  return nullptr;
}
}  // namespace

int gateway_get_session_count() { return static_cast<int>(g_gateway_sessions.size()); }

GatewaySession *gateway_find_session(const char *session_id) {
  if (!session_id || session_id[0] == '\0') {
    return nullptr;
  }
  auto it = g_gateway_sessions.find(session_id);
  return it == g_gateway_sessions.end() ? nullptr : it->second.get();
}

GatewaySession *gateway_find_session_by_object(object_t *ob) {
  if (!gateway_object_valid(ob)) {
    return nullptr;
  }
  auto it = g_gateway_obj_to_session.find(ob);
  if (it == g_gateway_obj_to_session.end()) {
    return nullptr;
  }

  auto *sess = it->second;
  if (!sess || !gateway_object_valid(sess->user_ob) || sess->user_ob != ob ||
      sess->user_ob_load_time != ob->load_time) {
    g_gateway_obj_to_session.erase(it);
    return nullptr;
  }
  return sess;
}

long gateway_session_fifo_depth_total() {
  long depth = 0;
  for (const auto &entry : g_gateway_sessions) {
    depth += static_cast<long>(entry.second->output_fifo.size());
  }
  return depth;
}

long gateway_session_command_pending_count() {
  long total = 0;
  for (const auto &entry : g_gateway_sessions) {
    if (entry.second->command_task_pending.load(std::memory_order_acquire)) {
      total++;
    }
  }
  return total;
}

uint64_t gateway_session_fifo_enqueued_total() {
  uint64_t total = 0;
  for (const auto &entry : g_gateway_sessions) {
    total += entry.second->output_fifo_enqueued;
  }
  return total;
}

uint64_t gateway_session_fifo_flushed_total() {
  uint64_t total = 0;
  for (const auto &entry : g_gateway_sessions) {
    total += entry.second->output_fifo_flushed;
  }
  return total;
}

uint64_t gateway_session_fifo_rejected_total() {
  uint64_t total = 0;
  for (const auto &entry : g_gateway_sessions) {
    total += entry.second->output_fifo_rejected;
  }
  return total;
}

int gateway_flush_session_output_fifo(GatewaySession *sess) {
  int flushed = 0;
  if (!sess || sess->master_fd < 0) {
    return 0;
  }
  while (!sess->output_fifo.empty()) {
    const auto &encoded = sess->output_fifo.front();
    if (!gateway_send_raw_to_fd(sess->master_fd, encoded.c_str(), encoded.size())) {
      break;
    }
    sess->output_fifo.pop_front();
    sess->output_fifo_flushed++;
    g_gateway_runtime_counters.output_fifo_flushed.fetch_add(1, std::memory_order_relaxed);
    flushed = 1;
  }
  return flushed;
}

int gateway_enqueue_session_output(GatewaySession *sess, std::string encoded) {
  if (!sess || sess->master_fd < 0 || encoded.empty()) {
    return 0;
  }
  if (sess->output_fifo.size() >= sess->output_fifo_max_depth) {
    sess->output_fifo_rejected++;
    g_gateway_runtime_counters.output_fifo_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  sess->output_fifo.push_back(std::move(encoded));
  sess->output_fifo_enqueued++;
  g_gateway_runtime_counters.output_fifo_enqueued.fetch_add(1, std::memory_order_relaxed);
  sess->last_active = get_current_time();
  gateway_flush_session_output_fifo(sess);
  return 1;
}

int gateway_bind_session_object(const char *session_id, object_t *ob, const char *ip, int port,
                                int master_fd) {
  GatewaySession *sess;

  if (!gateway_object_valid(ob) || !session_id || session_id[0] == '\0') {
    return 0;
  }

  sess = gateway_find_session(session_id);
  if (!sess) {
    if (g_gateway_max_sessions > 0 && gateway_get_session_count() >= g_gateway_max_sessions) {
      return 0;
    }
    auto created = std::make_unique<GatewaySession>();
    created->session_id = session_id;
    created->connected_at = get_current_time();
    created->last_active = created->connected_at;
    sess = created.get();
    g_gateway_sessions[session_id] = std::move(created);
  }

  sess->real_ip = ip ? ip : "";
  sess->real_port = port;
  sess->master_fd = master_fd;
  sess->user_ob = ob;
  sess->user_ob_load_time = ob->load_time;
  sess->last_active = get_current_time();
  g_gateway_obj_to_session[ob] = sess;
  return 1;
}

void gateway_unbind_session_object(object_t *ob) {
  auto *sess = gateway_find_session_by_object(ob);
  if (!sess) {
    return;
  }
  std::string session_id = sess->session_id;
  g_gateway_obj_to_session.erase(ob);
  g_gateway_sessions.erase(session_id);
}

void gateway_cleanup_master_sessions(int master_fd) {
  std::vector<std::string> to_remove;

  for (const auto &entry : g_gateway_sessions) {
    if (entry.second && entry.second->master_fd == master_fd) {
      to_remove.push_back(entry.first);
    }
  }

  for (const auto &session_id : to_remove) {
    gateway_destroy_session_internal(session_id.c_str(), "gateway_lost", "gateway lost");
  }
}

bool gateway_is_session(object_t *ob) {
  return ob && ob->interactive && (ob->interactive->iflags & GATEWAY_SESSION);
}

uint64_t gateway_enqueue_pending_command_internal(object_t *user) {
  if (!gateway_is_session(user) || !user->interactive || !user->obname || (user->flags & O_DESTRUCTED)) {
    g_gateway_runtime_counters.command_tasks_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  auto *sess = gateway_find_session_by_object(user);
  if (!gateway_mark_command_task_pending(sess)) {
    g_gateway_runtime_counters.command_tasks_rejected.fetch_add(1, std::memory_order_relaxed);
    g_gateway_runtime_counters.command_tasks_rejected_pending.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  auto *ip = user->interactive;
  auto command_snapshot = gateway_pending_command_snapshot(ip);
  std::string session_id = ip->gateway_session_id ? ip->gateway_session_id : "";
  auto snapshot_ready = (ip->iflags & CMD_IN_BUF) != 0;
  auto payload = gateway_command_task_payload(ip, snapshot_ready, command_snapshot.size());
  /*
   * process_user_command_snapshot() still consumes interactive_t, command_giver
   * and global VM parser state. Keep this path on the main thread until command
   * execution is fully detached from interactive/session objects.
   */
  auto main_task_policy = VM_OWNER_MAIN_TASK_IO_ADAPTER;
  auto enqueued_at = gateway_session_now_ns();
  auto task_id = vm_owner_enqueue_main_task_with_payload(
      user, "gateway_command_execute", "process_user_command", "gateway_command_input", &payload, [user, session_id, command_snapshot, enqueued_at] {
        gateway_session_record_latency(g_gateway_runtime_counters.command_enqueue_to_dispatch_ns_total,
                                       g_gateway_runtime_counters.command_enqueue_to_dispatch_ns_max,
                                       g_gateway_runtime_counters.command_enqueue_to_dispatch_samples,
                                       gateway_session_now_ns() - enqueued_at);
        auto *active_user = resolve_active_session_owner(session_id.c_str(), user);
        auto *active_ip = active_user ? active_user->interactive : nullptr;
        if (!gateway_executor_session_current(active_user, active_ip)) {
          vm_owner_record_task_trace(user ? vm_owner_id(user) : vm_owner_default_id(), "gateway_command_execute",
                                     "process_user_command", user ? vm_owner_epoch(user) : 0, "session_stale");
          g_gateway_runtime_counters.command_tasks_stale.fetch_add(1, std::memory_order_relaxed);
          gateway_clear_command_task_pending(session_id);
          vm_context_set_current_interactive(vm_context(), nullptr);
          return;
        }
        set_eval(max_eval_cost);
        auto execute_started_at = gateway_session_now_ns();
        process_user_command_snapshot(active_ip, command_snapshot.c_str(), command_snapshot.size());
        gateway_session_record_latency(g_gateway_runtime_counters.command_execute_ns_total,
                                       g_gateway_runtime_counters.command_execute_ns_max,
                                       g_gateway_runtime_counters.command_execute_samples,
                                       gateway_session_now_ns() - execute_started_at);
        gateway_finish_command_task(session_id, active_user);
        vm_context_set_current_interactive(vm_context(), nullptr);
      }, [session_id] { gateway_clear_command_task_pending(session_id); },
      "gateway_command_execution_frame_v1", "owner_scope_current_interactive_command_giver",
      "owner_owned_snapshot_main_thread_consume", kGatewayCommandExecutorActivationBlocker, true, true,
      "main_thread_vmcontext_scope", "",
      snapshot_ready ? command_snapshot.c_str() : nullptr, command_snapshot.size(),
      main_task_policy);
  if (task_id == 0) {
    g_gateway_runtime_counters.command_tasks_rejected.fetch_add(1, std::memory_order_relaxed);
    gateway_clear_command_task_pending(session_id);
  } else {
    g_gateway_runtime_counters.command_tasks_enqueued.fetch_add(1, std::memory_order_relaxed);
  }
  free_svalue(&payload, "gateway_command_task_payload");
  return task_id;
}

int gateway_process_pending_command_internal(object_t *user) {
  if (!gateway_is_session(user) || !user->interactive) {
    return 0;
  }
  gateway_command_callback(0, 0, user->interactive);
  auto drained = vm_owner_drain_main_tasks(kGatewayCommandMainDrainBudget);
  g_gateway_runtime_counters.main_drain_runs.fetch_add(1, std::memory_order_relaxed);
  g_gateway_runtime_counters.main_drain_tasks_total.fetch_add(static_cast<uint64_t>(drained),
                                                              std::memory_order_relaxed);
  gateway_session_record_max(g_gateway_runtime_counters.main_drain_tasks_max, static_cast<uint64_t>(drained));
  if (drained >= kGatewayCommandMainDrainBudget) {
    g_gateway_runtime_counters.main_drain_budget_hits.fetch_add(1, std::memory_order_relaxed);
  }
  return 1;
}

void gateway_session_exec_update(object_t *new_ob, object_t *old_ob) {
  auto *sess = gateway_find_session_by_object(old_ob);

  if (!sess || !new_ob || !old_ob || !new_ob->interactive) {
    return;
  }
  new_ob->interactive->ob = new_ob;
  g_gateway_obj_to_session.erase(old_ob);
  g_gateway_obj_to_session[new_ob] = sess;
  sess->user_ob = new_ob;
  sess->user_ob_load_time = new_ob->load_time;
}

void gateway_handle_remove_interactive(interactive_t *ip) {
  if (!ip || !(ip->iflags & GATEWAY_SESSION)) {
    return;
  }
  gateway_unbind_session_object(ip->ob);
}

int gateway_send_to_session(const char *session_id, const char *data, size_t len) {
  auto *sess = gateway_find_session(session_id);
  nlohmann::json payload;
  std::string encoded;

  if (!sess || sess->master_fd < 0 || !data) {
    return 0;
  }

  payload["type"] = "output";
  payload["cid"] = sess->session_id;
  payload["data"] = std::string(data, len);
  encoded = payload.dump();
  if (g_gateway_debug) {
    debug_message("[gateway] output sid=%s len=%zu\n", session_id, len);
  }
  return gateway_enqueue_session_output(sess, std::move(encoded));
}

object_t *gateway_create_session_internal(const char *session_id, svalue_t *data_val,
                                          const char *ip, int port, int master_fd) {
  object_t *ob;
  svalue_t *ret;
  interactive_t *user;
  int has_gateway_logon;

  if (!session_id || session_id[0] == '\0' || gateway_find_session(session_id) || !g_event_base ||
      (g_gateway_max_sessions > 0 && gateway_get_session_count() >= g_gateway_max_sessions)) {
    return nullptr;
  }

  if (g_gateway_debug) {
    debug_message("[gateway] create_session sid=%s ip=%s port=%d master_fd=%d\n",
                  session_id, ip ? ip : "", port, master_fd);
  }

  save_command_giver(master_ob);
  master_ob->flags |= O_ONCE_INTERACTIVE;

  user = user_add();
  if (!user) {
    master_ob->flags &= ~O_ONCE_INTERACTIVE;
    restore_command_giver();
    return nullptr;
  }
  user->connection_type = PORT_TYPE_GATEWAY;
  user->ob = master_ob;
  user->last_time = get_current_time();
  user->fd = -1;
  user->local_port = 0;
  user->external_port = -1;
  user->iflags |= GATEWAY_SESSION;
  user->gateway_session_id = string_copy(session_id, "gateway_session_id");
  user->gateway_real_ip = string_copy(ip ? ip : "", "gateway_real_ip");
  user->gateway_real_port = port;
  user->gateway_master_fd = master_fd;
  user->ev_command = evtimer_new(g_event_base, gateway_command_callback, user);
  if (!user->ev_command) {
    cleanup_temp_gateway_interactive(master_ob);
    master_ob->flags &= ~O_ONCE_INTERACTIVE;
    restore_command_giver();
    return nullptr;
  }

  master_ob->interactive = user;
  set_eval(max_eval_cost);
  ret = safe_apply_master_ob(APPLY_CONNECT, 0);
  restore_command_giver();
  if (!ret || ret == (svalue_t *)-1 || ret->type != T_OBJECT) {
    cleanup_temp_gateway_interactive(master_ob);
    master_ob->flags &= ~O_ONCE_INTERACTIVE;
    return nullptr;
  }

  ob = ret->u.ob;
  ob->interactive = master_ob->interactive;
  ob->interactive->ob = ob;
  ob->interactive->iflags |= (HAS_WRITE_PROMPT | HAS_PROCESS_INPUT);
  ob->flags |= O_ONCE_INTERACTIVE;
  master_ob->flags &= ~O_ONCE_INTERACTIVE;
  master_ob->interactive = nullptr;
  add_ref(ob, "gateway_create_session");

  query_name_by_addr(ob);
  save_command_giver(ob);
  set_prompt("> ");
  restore_command_giver();

  if (!gateway_bind_session_object(session_id, ob, ip, port, master_fd)) {
    if (ob->interactive) {
      remove_interactive(ob, 1);
    } else {
      free_object(&ob, "gateway_create_session_failed_bind");
    }
    return nullptr;
  }

  has_gateway_logon = function_exists("gateway_logon", ob, 0) ? 1 : 0;
  save_command_giver(ob);
  {
    VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob), vm_owner_epoch(ob));
    VMCurrentInteractiveScope interactive_scope(vm_context(), ob);
    vm_owner_record_task_trace(vm_owner_id(ob), "gateway", has_gateway_logon ? "gateway_logon" : "logon",
                               vm_owner_epoch(ob), "dispatched");
    if (has_gateway_logon) {
      if (data_val) {
        push_svalue(data_val);
        ret = safe_apply("gateway_logon", ob, 1, ORIGIN_DRIVER);
      } else {
        ret = safe_apply("gateway_logon", ob, 0, ORIGIN_DRIVER);
      }
    } else {
      ret = safe_apply("logon", ob, 0, ORIGIN_DRIVER);
    }
  }
  restore_command_giver();

  if (!ret) {
    auto *active_ob = resolve_active_session_owner(session_id, ob);
    if (active_ob && active_ob->interactive) {
      remove_interactive(active_ob, 0);
    } else {
      gateway_unbind_session_object(ob);
      free_object(&ob, "gateway_create_session_failed_logon");
    }
    return nullptr;
  }

  return resolve_active_session_owner(session_id, ob);
}

int gateway_destroy_session_internal(const char *session_id, const char *reason_code,
                                     const char *reason_text) {
  auto *sess = gateway_find_session(session_id);
  auto *ob = sess ? sess->user_ob : nullptr;
  const char *reason_code_str = reason_code && reason_code[0] ? reason_code : "client_disconnected";
  const char *reason_text_str = reason_text && reason_text[0] ? reason_text : reason_code_str;

  if (!sess) {
    return 0;
  }
  if (gateway_object_valid(ob) && ob->interactive) {
    save_command_giver(ob);
    {
      VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob), vm_owner_epoch(ob));
      VMCurrentInteractiveScope interactive_scope(vm_context(), ob);
      vm_owner_record_task_trace(vm_owner_id(ob), "gateway", "gateway_disconnected", vm_owner_epoch(ob),
                                 "dispatched");
      set_eval(max_eval_cost);
      copy_and_push_string(reason_code_str);
      copy_and_push_string(reason_text_str);
      safe_apply("gateway_disconnected", ob, 2, ORIGIN_DRIVER);
    }
    restore_command_giver();

    if ((sess = gateway_find_session(session_id))) {
      sess->master_fd = -1;
    }
    ob = resolve_active_session_owner(session_id, ob);
    if (!ob || !ob->interactive) {
      if (sess && gateway_object_valid(sess->user_ob)) {
        gateway_unbind_session_object(sess->user_ob);
      } else {
        g_gateway_sessions.erase(session_id);
      }
      return 1;
    }
    remove_interactive(ob, 0);
    return 1;
  }
  if (gateway_object_valid(ob)) {
    gateway_unbind_session_object(ob);
  } else {
    g_gateway_sessions.erase(session_id);
  }
  return 1;
}

int gateway_inject_input_internal(object_t *user, const char *input) {
  interactive_t *ip;
  size_t input_len;

  if (!gateway_is_session(user) || !input) {
    return 0;
  }
  ip = user->interactive;
  input_len = strlen(input);
  while (input_len > 0 && (input[input_len - 1] == '\n' || input[input_len - 1] == '\r')) {
    input_len--;
  }
  if (input_len == 0 || ip->text_end + static_cast<int>(input_len) + 2 >= MAX_TEXT) {
    return 0;
  }

  memcpy(ip->text + ip->text_end, input, input_len);
  ip->text_end += static_cast<int>(input_len);
  ip->text[ip->text_end++] = '\n';
  ip->text[ip->text_end] = '\0';

  if (cmd_in_buf(ip)) {
    ip->iflags |= CMD_IN_BUF;
    if (ip->ev_command) {
      timeval zero = {0, 0};
      evtimer_del(ip->ev_command);
      evtimer_add(ip->ev_command, &zero);
    }
  }

  if (auto *sess = gateway_find_session_by_object(user)) {
    sess->last_active = get_current_time();
    if (g_gateway_debug) {
      debug_message("[gateway] inject_input sid=%s text=%s\n", sess->session_id.c_str(), input);
    }
  }

  return 1;
}

void gateway_check_session_timeouts() {
  std::vector<std::string> to_remove;

  for (const auto &entry : g_gateway_sessions) {
    auto *sess = entry.second.get();
    if (!sess) {
      to_remove.push_back(entry.first);
      continue;
    }
    if (!gateway_has_master(sess->master_fd)) {
      to_remove.push_back(entry.first);
      continue;
    }
    if (!gateway_object_valid(sess->user_ob) || !sess->user_ob->interactive) {
      to_remove.push_back(entry.first);
    }
  }

  for (const auto &session_id : to_remove) {
    gateway_destroy_session_internal(session_id.c_str(), "session_timeout", "session cleanup");
  }
}

void cleanup_gateway_sessions() {
  std::vector<std::string> session_ids;

  session_ids.reserve(g_gateway_sessions.size());
  for (const auto &entry : g_gateway_sessions) {
    session_ids.push_back(entry.first);
  }

  for (const auto &session_id : session_ids) {
    gateway_destroy_session_internal(session_id.c_str(), "gateway_cleanup", "gateway cleanup");
  }

  g_gateway_sessions.clear();
  g_gateway_obj_to_session.clear();
}

void f_gateway_session_send() {
  int num_args = st_num_arg;
  object_t *ob = num_args >= 1 ? (sp - num_args + 1)->u.ob : nullptr;
  svalue_t *data_sv = num_args >= 2 ? (sp - num_args + 2) : nullptr;
  GatewaySession *sess = gateway_find_session_by_object(ob);
  nlohmann::json payload;
  std::string payload_json;
  std::string encoded;
  int result = 0;

  if (!sess || !data_sv || !gateway_svalue_to_json_string(data_sv, &payload_json)) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  try {
    payload = nlohmann::json::parse(payload_json);
  } catch (...) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  if (payload.is_object()) {
    payload["cid"] = sess->session_id;
  } else {
    payload = nlohmann::json{
        {"type", "output"},
        {"cid", sess->session_id},
        {"data", payload},
    };
  }

  encoded = payload.dump();
  result = gateway_enqueue_session_output(sess, std::move(encoded));

  pop_n_elems(num_args);
  push_number(result);
}

void f_gateway_create_session() {
  int num_args = st_num_arg;
  svalue_t *args = sp - num_args + 1;
  const char *session_id = args[0].u.string;
  svalue_t *data = num_args >= 2 ? &args[1] : nullptr;
  const char *ip = (num_args >= 3 && args[2].type == T_STRING) ? args[2].u.string : "";
  int port = (num_args >= 4 && args[3].type == T_NUMBER) ? args[3].u.number : 0;
  int master_fd = (num_args >= 5 && args[4].type == T_NUMBER) ? args[4].u.number : -1;
  object_t *ob;

  ob = gateway_create_session_internal(session_id, data, ip, port, master_fd);
  pop_n_elems(num_args);
  if (ob) {
    put_unrefed_object(ob, "f_gateway_create_session");
  } else {
    put_number(0);
  }
}

void f_gateway_destroy_session() {
  const char *session_id = sp->u.string;
  pop_stack();
  put_number(gateway_destroy_session_internal(session_id, "efun_destroy", "efun"));
}

void f_gateway_sessions() {
  array_t *arr;
  int index = 0;

  arr = allocate_array(gateway_get_session_count());
  for (const auto &entry : g_gateway_sessions) {
    if (gateway_object_valid(entry.second->user_ob)) {
      arr->item[index].type = T_OBJECT;
      arr->item[index].u.ob = entry.second->user_ob;
      add_ref(entry.second->user_ob, "gateway_sessions");
      index++;
    }
  }
  arr->size = index;
  push_refed_array(arr);
}

void f_gateway_session_info() {
  auto *ob = sp->u.ob;
  auto *sess = gateway_find_session_by_object(ob);
  mapping_t *map;

  pop_stack();
  if (!sess) {
    put_number(0);
    return;
  }

  map = allocate_mapping(16);
  add_mapping_string(map, "session_id", sess->session_id.c_str());
  add_mapping_string(map, "ip", sess->real_ip.c_str());
  add_mapping_pair(map, "port", sess->real_port);
  add_mapping_pair(map, "master_fd", sess->master_fd);
  add_mapping_pair(map, "connected_at", sess->connected_at);
  add_mapping_pair(map, "last_active", sess->last_active);
  add_mapping_string(map, "object_name", sess->user_ob->obname);
  add_mapping_string(map, "owner_id", vm_owner_id(sess->user_ob));
  add_mapping_pair(map, "owner_epoch", static_cast<long>(vm_owner_epoch(sess->user_ob)));
  add_mapping_pair(map, "session_fifo_contract_ready", 1);
  add_mapping_pair(map, "session_fifo_depth", static_cast<long>(sess->output_fifo.size()));
  add_mapping_pair(map, "session_fifo_max_depth", static_cast<long>(sess->output_fifo_max_depth));
  add_mapping_pair(map, "session_fifo_enqueued", static_cast<long>(sess->output_fifo_enqueued));
  add_mapping_pair(map, "session_fifo_flushed", static_cast<long>(sess->output_fifo_flushed));
  add_mapping_pair(map, "session_fifo_rejected", static_cast<long>(sess->output_fifo_rejected));
  add_mapping_string(map, "gateway_io_boundary", "main_thread_io_adapter");
  push_refed_mapping(map);
}

void f_gateway_inject_input() {
  const char *input = sp->u.string;
  auto *ob = (sp - 1)->u.ob;

  pop_2_elems();
  put_number(gateway_inject_input_internal(ob, input));
}
