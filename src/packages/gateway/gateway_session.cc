#include "base/package_api.h"

#include "gateway.h"

#include "backend.h"
#include "base/internal/external_port.h"
#include "base/internal/port.h"
#include "comm.h"
#include "packages/core/dns.h"
#include "user.h"
#include "vm/context.h"
#include "vm/internal/otable.h"
#include "vm/owner.h"

#include <event2/event.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <charconv>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

uint64_t gateway_enqueue_pending_command_internal(object_t *user);

namespace {
std::unordered_map<std::string, std::unique_ptr<GatewaySession>> g_gateway_sessions;
std::unordered_map<object_t *, GatewaySession *> g_gateway_obj_to_session;
std::atomic<uint64_t> g_gateway_next_output_reservation_id{1};
std::atomic<long> g_gateway_command_input_pending_sessions{0};
std::atomic<long> g_gateway_command_task_pending_sessions{0};
struct GatewaySessionFutureWatch {
  std::string session_id;
  std::string user_ob_name;
  int64_t user_ob_load_time{0};
  uint64_t reservation_id{0};
  uint64_t future_id{0};
  uint64_t deadline_ms{0};
  uint64_t registered_at_ns{0};
  bool encoded_output{false};
};
struct GatewayFutureWatch {
  std::string target_ob_name;
  int64_t target_ob_load_time{0};
  uint64_t context_id{0};
  uint64_t future_id{0};
  uint64_t deadline_ms{0};
  uint64_t registered_at_ns{0};
};
std::unordered_map<uint64_t, GatewaySessionFutureWatch> g_gateway_session_future_watches;
std::unordered_map<uint64_t, uint64_t> g_gateway_future_to_reservation;
std::list<uint64_t> g_gateway_future_watch_queue;
std::unordered_map<uint64_t, std::list<uint64_t>::iterator> g_gateway_future_watch_queue_positions;
std::unordered_map<uint64_t, GatewayFutureWatch> g_gateway_future_watches;
std::list<uint64_t> g_gateway_generic_future_watch_queue;
event *g_gateway_future_watch_timer = nullptr;
event *g_gateway_future_watch_completion_event = nullptr;
constexpr const char *kGatewayCommandExecutorActivationBlocker =
    "interactive_command_requires_main_thread_io_adapter";
constexpr int kGatewayCommandMainDrainBudget = 16;
constexpr size_t kGatewayMaxFutureWatches = 65536;
constexpr int kGatewayFutureWatchPollIntervalMs = 1;
constexpr size_t kGatewayFutureWatchPollBudget = 64;

uint64_t gateway_session_now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

uint64_t gateway_session_now_ms() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
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

void gateway_record_future_completion_thread_cpu(int64_t started_ns) {
  auto finished_ns = get_current_thread_cpu_time_ns();
  if (started_ns < 0 || finished_ns < started_ns) {
    g_gateway_runtime_counters.future_watch_main_completion_thread_cpu_unavailable.fetch_add(
        1, std::memory_order_relaxed);
    return;
  }
  g_gateway_runtime_counters.future_watch_main_completion_thread_cpu_ns_total.fetch_add(
      static_cast<uint64_t>(finished_ns - started_ns), std::memory_order_relaxed);
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

bool gateway_append_json_string(const char *value, size_t length, std::string *out) {
  constexpr char kHexDigits[] = "0123456789abcdef";
  size_t index = 0;

  if (!out || (!value && length != 0)) {
    return false;
  }
  out->push_back('"');
  while (index < length) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (byte >= 0x80) {
      size_t continuation_count = 0;
      uint32_t codepoint = 0;
      uint32_t minimum_codepoint = 0;
      if (byte >= 0xc2 && byte <= 0xdf) {
        continuation_count = 1;
        codepoint = byte & 0x1f;
        minimum_codepoint = 0x80;
      } else if (byte >= 0xe0 && byte <= 0xef) {
        continuation_count = 2;
        codepoint = byte & 0x0f;
        minimum_codepoint = 0x800;
      } else if (byte >= 0xf0 && byte <= 0xf4) {
        continuation_count = 3;
        codepoint = byte & 0x07;
        minimum_codepoint = 0x10000;
      } else {
        return false;
      }
      if (continuation_count >= length - index) {
        return false;
      }
      for (size_t offset = 1; offset <= continuation_count; ++offset) {
        const auto continuation = static_cast<unsigned char>(value[index + offset]);
        if ((continuation & 0xc0) != 0x80) {
          return false;
        }
        codepoint = (codepoint << 6) | (continuation & 0x3f);
      }
      if (codepoint < minimum_codepoint || codepoint > 0x10ffff ||
          (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
        return false;
      }
      out->append(value + index, continuation_count + 1);
      index += continuation_count + 1;
      continue;
    }

    switch (byte) {
      case '\\':
        out->append("\\\\");
        break;
      case '"':
        out->append("\\\"");
        break;
      case '\b':
        out->append("\\b");
        break;
      case '\f':
        out->append("\\f");
        break;
      case '\n':
        out->append("\\n");
        break;
      case '\r':
        out->append("\\r");
        break;
      case '\t':
        out->append("\\t");
        break;
      default:
        if (byte <= 0x1f) {
          out->append("\\u00");
          out->push_back(kHexDigits[byte >> 4]);
          out->push_back(kHexDigits[byte & 0x0f]);
        } else {
          out->push_back(static_cast<char>(byte));
        }
        break;
    }
    ++index;
  }
  out->push_back('"');
  return true;
}

std::string gateway_encode_output_envelope_slow(const std::string &session_id, const char *data,
                                                size_t len) {
  nlohmann::json payload{
      {"type", "output"},
      {"cid", session_id},
      {"data", std::string(data, len)},
  };
  return payload.dump();
}

std::string gateway_encode_output_envelope(const std::string &session_id,
                                           const char *data, size_t len) {
  std::string encoded;

  encoded.reserve(session_id.size() + len + 36);
  encoded.append("{\"cid\":");
  if (!gateway_append_json_string(session_id.data(), session_id.size(), &encoded)) {
    return gateway_encode_output_envelope_slow(session_id, data, len);
  }
  encoded.append(",\"data\":");
  if (!gateway_append_json_string(data, len, &encoded)) {
    return gateway_encode_output_envelope_slow(session_id, data, len);
  }
  encoded.append(",\"type\":\"output\"}");
  return encoded;
}

bool gateway_json_object_members(std::string_view encoded, std::string_view *members) {
  if (!members || encoded.size() < 2 || encoded.front() != '{' || encoded.back() != '}') {
    return false;
  }
  *members = encoded.substr(1, encoded.size() - 2);
  return true;
}

bool gateway_append_lpc_int(LPC_INT value, std::string *out) {
  char buffer[std::numeric_limits<LPC_INT>::digits10 + 4];
  auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
  if (!out || result.ec != std::errc{}) {
    return false;
  }
  out->append(buffer, static_cast<size_t>(result.ptr - buffer));
  return true;
}

bool gateway_build_preencoded_chat_batch_frame(
    const std::vector<std::string_view> &stable_children_json, LPC_INT message_epoch,
    LPC_INT first_server_seq, LPC_INT sent_at, std::string_view outer_dynamic_json,
    std::string *frame) {
  constexpr std::string_view kFramePrefix = "\x1bXKBACH{\"messages\":[";
  constexpr std::string_view kChildPrefix = "{\"type\":\"CHAT\",\"payload\":{";
  constexpr std::string_view kChildMetaPrefix =
      "\"meta\":{\"stream\":\"message\",\"server_seq\":";
  constexpr std::string_view kSentAtPrefix =
      ",\"sent_at\":";
  constexpr std::string_view kEpochPrefix =
      ",\"priority\":\"normal\",\"epoch\":";
  constexpr std::string_view kChildSuffix =
      ",\"reliability\":\"important\"}}}";
  std::string_view outer_members;
  const auto child_overhead = kChildPrefix.size() + kChildMetaPrefix.size() +
                              kSentAtPrefix.size() + kEpochPrefix.size() +
                              kChildSuffix.size() + 72;
  const auto maximum_size = frame ? frame->max_size() : 0;
  size_t estimated_size;

  if (!frame || stable_children_json.empty() || message_epoch < 0 || first_server_seq <= 0 ||
      sent_at <= 0 || !gateway_json_object_members(outer_dynamic_json, &outer_members) ||
      stable_children_json.size() > static_cast<size_t>(std::numeric_limits<LPC_INT>::max()) ||
      first_server_seq > std::numeric_limits<LPC_INT>::max() -
                             static_cast<LPC_INT>(stable_children_json.size() - 1)) {
    return false;
  }

  if (outer_members.size() > maximum_size - kFramePrefix.size() - 4) {
    return false;
  }
  estimated_size = kFramePrefix.size() + outer_members.size() + 4;
  for (const auto stable_json : stable_children_json) {
    std::string_view stable_members;
    if (!gateway_json_object_members(stable_json, &stable_members) ||
        stable_json.size() > maximum_size - estimated_size ||
        child_overhead > maximum_size - estimated_size - stable_json.size()) {
      return false;
    }
    estimated_size += stable_json.size() + child_overhead;
  }

  frame->clear();
  frame->reserve(estimated_size);
  frame->append(kFramePrefix);
  for (size_t index = 0; index < stable_children_json.size(); ++index) {
    std::string_view stable_members;
    gateway_json_object_members(stable_children_json[index], &stable_members);
    if (index > 0) {
      frame->push_back(',');
    }
    frame->append(kChildPrefix);
    if (!stable_members.empty()) {
      frame->append(stable_members);
      frame->push_back(',');
    }
    frame->append(kChildMetaPrefix);
    if (!gateway_append_lpc_int(first_server_seq + static_cast<LPC_INT>(index), frame)) {
      frame->clear();
      return false;
    }
    frame->append(kSentAtPrefix);
    if (!gateway_append_lpc_int(sent_at, frame)) {
      frame->clear();
      return false;
    }
    frame->append(kEpochPrefix);
    if (!gateway_append_lpc_int(message_epoch, frame)) {
      frame->clear();
      return false;
    }
    frame->append(kChildSuffix);
  }
  frame->push_back(']');
  if (!outer_members.empty()) {
    frame->push_back(',');
    frame->append(outer_members);
  }
  frame->append("}\x1b\n");
  return true;
}

object_t *gateway_resolve_session_object(GatewaySession *sess) {
  if (!sess || sess->user_ob_name.empty()) {
    return nullptr;
  }

  auto *current = ObjectTable::instance().find(sess->user_ob_name);
  if (!gateway_object_valid(current) || current != sess->user_ob ||
      current->load_time != sess->user_ob_load_time) {
    sess->user_ob = nullptr;
    return nullptr;
  }
  return current;
}

bool gateway_session_has_pending_reservation(GatewaySession *sess, uint64_t reservation_id) {
  if (!sess || reservation_id == 0) {
    return false;
  }
  for (const auto &entry : sess->output_fifo) {
    if (entry.reservation_id == reservation_id && !entry.ready) {
      return true;
    }
  }
  return false;
}

std::string gateway_future_mapping_state(mapping_t *future) {
  auto *state = future ? find_string_in_mapping(future, "state") : nullptr;
  return state && state->type == T_STRING && state->u.string ? state->u.string : "unknown";
}

void gateway_stop_future_watch_timer() {
  vm_owner_set_future_terminal_notifier(nullptr);
  if (g_gateway_future_watch_timer) {
    evtimer_del(g_gateway_future_watch_timer);
  }
}

bool gateway_has_future_watches() {
  return !g_gateway_session_future_watches.empty() || !g_gateway_future_watches.empty();
}

void gateway_future_watch_timer_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*ctx*/);
void gateway_future_watch_completion_event_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*ctx*/);

void gateway_owner_future_terminal_notified() {
  if (!g_gateway_future_watch_completion_event) {
    return;
  }
  g_gateway_runtime_counters.future_watch_completion_notifications.fetch_add(1,
                                                                              std::memory_order_relaxed);
  event_active(g_gateway_future_watch_completion_event, EV_TIMEOUT, 0);
}

bool gateway_enable_future_watch_completion_event() {
  if (!g_event_base) {
    return false;
  }
  if (!g_gateway_future_watch_completion_event) {
    g_gateway_future_watch_completion_event =
        event_new(g_event_base, -1, EV_PERSIST, gateway_future_watch_completion_event_cb, nullptr);
    if (!g_gateway_future_watch_completion_event ||
        event_add(g_gateway_future_watch_completion_event, nullptr) != 0) {
      if (g_gateway_future_watch_completion_event) {
        event_free(g_gateway_future_watch_completion_event);
        g_gateway_future_watch_completion_event = nullptr;
      }
      return false;
    }
  }
  vm_owner_set_future_terminal_notifier(gateway_owner_future_terminal_notified);
  return true;
}

void gateway_schedule_future_watch_timer() {
  if (!g_event_base || !gateway_has_future_watches()) {
    return;
  }
  if (!g_gateway_future_watch_timer) {
    g_gateway_future_watch_timer = evtimer_new(g_event_base, gateway_future_watch_timer_cb, nullptr);
  }
  if (!g_gateway_future_watch_timer || event_pending(g_gateway_future_watch_timer, EV_TIMEOUT, nullptr)) {
    return;
  }
  timeval delay{0, kGatewayFutureWatchPollIntervalMs * 1000};
  evtimer_add(g_gateway_future_watch_timer, &delay);
}

void gateway_future_watch_timer_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*ctx*/) {
  g_gateway_runtime_counters.future_watch_timer_wakeups.fetch_add(1, std::memory_order_relaxed);
  gateway_process_session_future_watches_at(gateway_session_now_ms());
  gateway_process_future_watches_at(gateway_session_now_ms());
  gateway_schedule_future_watch_timer();
}

void gateway_future_watch_completion_event_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*ctx*/) {
  g_gateway_runtime_counters.future_watch_completion_wakeups.fetch_add(1, std::memory_order_relaxed);
  gateway_process_session_future_watches_at(gateway_session_now_ms());
  gateway_process_future_watches_at(gateway_session_now_ms());
  gateway_schedule_future_watch_timer();
}

void gateway_cleanup_future_watch_timer() {
  vm_owner_set_future_terminal_notifier(nullptr);
  if (g_gateway_future_watch_completion_event) {
    event_del(g_gateway_future_watch_completion_event);
    event_free(g_gateway_future_watch_completion_event);
    g_gateway_future_watch_completion_event = nullptr;
  }
  if (!g_gateway_future_watch_timer) {
    return;
  }
  evtimer_del(g_gateway_future_watch_timer);
  event_free(g_gateway_future_watch_timer);
  g_gateway_future_watch_timer = nullptr;
}

void gateway_consume_cancelled_future(uint64_t future_id, const char *reason) {
  auto *cancelled = vm_owner_future_cancel(future_id, reason);
  free_mapping(cancelled);
  auto *consumed = vm_owner_future_take(future_id);
  free_mapping(consumed);
}

void gateway_cancel_session_future_watches(const std::string &session_id, GatewaySession *sess,
                                           const char *reason, bool release_reservations) {
  std::vector<GatewaySessionFutureWatch> cancelled;
  for (auto it = g_gateway_session_future_watches.begin();
       it != g_gateway_session_future_watches.end();) {
    if (it->second.session_id != session_id) {
      ++it;
      continue;
    }
    cancelled.push_back(it->second);
    g_gateway_future_to_reservation.erase(it->second.future_id);
    auto queue_it = g_gateway_future_watch_queue_positions.find(it->second.reservation_id);
    if (queue_it != g_gateway_future_watch_queue_positions.end()) {
      g_gateway_future_watch_queue.erase(queue_it->second);
      g_gateway_future_watch_queue_positions.erase(queue_it);
    }
    it = g_gateway_session_future_watches.erase(it);
  }

  for (const auto &watch : cancelled) {
    gateway_consume_cancelled_future(watch.future_id, reason);
    if (release_reservations && sess) {
      gateway_release_session_output(sess, watch.reservation_id);
    }
    g_gateway_runtime_counters.future_watches_cancelled.fetch_add(1, std::memory_order_relaxed);
  }
  if (g_gateway_session_future_watches.empty()) {
    g_gateway_future_watch_queue.clear();
    g_gateway_future_watch_queue_positions.clear();
    gateway_stop_future_watch_timer();
  }
}

bool gateway_dispatch_future_watch_callback(object_t *ob, uint64_t reservation_id,
                                            mapping_t *future) {
  if (!gateway_object_valid(ob) || !future ||
      !function_exists("gateway_owner_future_completed", ob, 0)) {
    return false;
  }

  bool callback_ok = false;
  save_command_giver(ob);
  {
    VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob), vm_owner_epoch(ob));
    VMCurrentInteractiveScope interactive_scope(vm_context(), ob);
    GatewayControlledLpcScope controlled_scope;
    set_eval(max_eval_cost);
    push_number(static_cast<LPC_INT>(reservation_id));
    push_mapping(future);
    auto *ret = safe_apply("gateway_owner_future_completed", ob, 2, ORIGIN_DRIVER);
    callback_ok = ret && ret->type == T_NUMBER && ret->u.number != 0;
  }
  restore_command_giver();
  return callback_ok;
}

bool gateway_dispatch_future_output_notification(object_t *ob, uint64_t reservation_id,
                                                 const char *state) {
  if (!gateway_object_valid(ob)) {
    return false;
  }
  if (!function_exists("gateway_owner_future_output_completed", ob, 0)) {
    return true;
  }

  bool callback_ok = false;
  save_command_giver(ob);
  {
    VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob), vm_owner_epoch(ob));
    VMCurrentInteractiveScope interactive_scope(vm_context(), ob);
    GatewayControlledLpcScope controlled_scope;
    set_eval(max_eval_cost);
    push_number(static_cast<LPC_INT>(reservation_id));
    copy_and_push_string(state && state[0] ? state : "released");
    auto *ret = safe_apply("gateway_owner_future_output_completed", ob, 2,
                           ORIGIN_DRIVER);
    callback_ok = ret && ret->type == T_NUMBER && ret->u.number != 0;
  }
  restore_command_giver();
  return callback_ok;
}

object_t *gateway_resolve_future_watch_object(const GatewayFutureWatch &watch) {
  if (watch.target_ob_name.empty()) {
    return nullptr;
  }
  auto *ob = ObjectTable::instance().find(watch.target_ob_name);
  if (!gateway_object_valid(ob) || ob->load_time != watch.target_ob_load_time) {
    return nullptr;
  }
  return ob;
}

bool gateway_dispatch_generic_future_watch_callback(object_t *ob, uint64_t context_id,
                                                    mapping_t *future) {
  if (!gateway_object_valid(ob) || !future ||
      !function_exists("owner_future_watch_completed", ob, 0)) {
    return false;
  }

  bool callback_ok = false;
  {
    VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob), vm_owner_epoch(ob));
    GatewayControlledLpcScope controlled_scope;
    set_eval(max_eval_cost);
    push_number(static_cast<LPC_INT>(context_id));
    push_mapping(future);
    auto *ret = safe_apply("owner_future_watch_completed", ob, 2, ORIGIN_DRIVER);
    callback_ok = ret && ret->type == T_NUMBER && ret->u.number != 0;
  }
  return callback_ok;
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
  if (!sess->command_task_pending.compare_exchange_strong(
          expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
    return false;
  }
  g_gateway_command_task_pending_sessions.fetch_add(1, std::memory_order_release);
  return true;
}

void gateway_decrement_pending_counter(std::atomic<long> &counter) {
  auto pending = counter.load(std::memory_order_acquire);
  while (pending > 0 &&
         !counter.compare_exchange_weak(
             pending, pending - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
  }
}

bool gateway_mark_command_input_pending(GatewaySession *sess) {
  if (!sess) {
    return false;
  }
  bool expected = false;
  if (!sess->command_input_pending.compare_exchange_strong(
          expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
    return false;
  }
  g_gateway_command_input_pending_sessions.fetch_add(1, std::memory_order_release);
  return true;
}

void gateway_release_command_input_pending(GatewaySession *sess) {
  if (!sess || !sess->command_input_pending.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  gateway_decrement_pending_counter(g_gateway_command_input_pending_sessions);
}

void gateway_release_command_task_pending(GatewaySession *sess) {
  if (!sess || !sess->command_task_pending.exchange(false, std::memory_order_acq_rel)) {
    return;
  }

  gateway_decrement_pending_counter(g_gateway_command_task_pending_sessions);
  g_gateway_runtime_counters.command_tasks_cleared.fetch_add(1, std::memory_order_relaxed);
}

void gateway_clear_command_task_pending(const std::string &session_id) {
  auto *sess = gateway_find_session(session_id.c_str());
  if (!sess) {
    return;
  }
  gateway_release_command_task_pending(sess);
}

void gateway_finish_command_task(const std::string &session_id, object_t *fallback) {
  auto *sess = gateway_find_session(session_id.c_str());
  if (!sess) {
    return;
  }

  gateway_release_command_task_pending(sess);
  g_gateway_runtime_counters.command_tasks_finished.fetch_add(1, std::memory_order_relaxed);
  auto *active_user = resolve_active_session_owner(session_id.c_str(), fallback);
  auto *active_ip = active_user ? active_user->interactive : nullptr;
  if (!gateway_executor_session_current(active_user, active_ip)) {
    return;
  }
  if (active_ip->iflags & CMD_IN_BUF) {
    gateway_mark_command_input_pending(sess);
  } else {
    gateway_release_command_input_pending(sess);
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
  auto *session_ob = gateway_resolve_session_object(sess);
  if (session_ob && session_ob->interactive && session_ob->interactive->ob == session_ob) {
    return session_ob;
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
  if (!sess || gateway_resolve_session_object(sess) != ob) {
    g_gateway_obj_to_session.erase(it);
    return nullptr;
  }
  return sess;
}

int gateway_watch_session_future_for_object_internal(object_t *ob, uint64_t reservation_id,
                                                     uint64_t future_id, int timeout_ms,
                                                     bool encoded_output) {
  auto register_started_ns = gateway_session_now_ns();
  if (!vm_context_is_main_thread() || reservation_id == 0 || future_id == 0 || timeout_ms <= 0 ||
      g_gateway_session_future_watches.size() >= kGatewayMaxFutureWatches) {
    g_gateway_runtime_counters.future_watches_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  auto *sess = gateway_find_session_by_object(ob);
  if (!sess || !gateway_session_has_pending_reservation(sess, reservation_id) ||
      g_gateway_session_future_watches.find(reservation_id) !=
          g_gateway_session_future_watches.end() ||
      g_gateway_future_to_reservation.find(future_id) != g_gateway_future_to_reservation.end() ||
      g_gateway_future_watches.find(future_id) != g_gateway_future_watches.end()) {
    g_gateway_runtime_counters.future_watches_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  if (vm_owner_future_state(future_id) == VM_OWNER_FUTURE_UNKNOWN ||
      !vm_owner_future_targets_object(future_id, ob)) {
    g_gateway_runtime_counters.future_watches_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  auto now_ms = gateway_session_now_ms();
  auto completion_event_ready = gateway_enable_future_watch_completion_event();
  auto timeout = static_cast<uint64_t>(timeout_ms);
  auto deadline_ms = timeout > std::numeric_limits<uint64_t>::max() - now_ms
                         ? std::numeric_limits<uint64_t>::max()
                         : now_ms + timeout;
  GatewaySessionFutureWatch watch;
  watch.session_id = sess->session_id;
  watch.user_ob_name = sess->user_ob_name;
  watch.user_ob_load_time = sess->user_ob_load_time;
  watch.reservation_id = reservation_id;
  watch.future_id = future_id;
  watch.deadline_ms = deadline_ms;
  watch.registered_at_ns = register_started_ns;
  watch.encoded_output = encoded_output;
  g_gateway_session_future_watches.emplace(reservation_id, std::move(watch));
  g_gateway_future_to_reservation.emplace(future_id, reservation_id);
  g_gateway_future_watch_queue.push_back(reservation_id);
  g_gateway_future_watch_queue_positions.emplace(
      reservation_id, std::prev(g_gateway_future_watch_queue.end()));
  g_gateway_runtime_counters.future_watches_registered.fetch_add(1, std::memory_order_relaxed);
  if (completion_event_ready && vm_owner_future_state(future_id) != VM_OWNER_FUTURE_PENDING) {
    gateway_owner_future_terminal_notified();
  }
  gateway_schedule_future_watch_timer();
  gateway_session_record_latency(g_gateway_runtime_counters.future_watch_register_ns_total,
                                 g_gateway_runtime_counters.future_watch_register_ns_max,
                                 g_gateway_runtime_counters.future_watch_register_samples,
                                 gateway_session_now_ns() - register_started_ns);
  return 1;
}

int gateway_watch_session_future_for_object(object_t *ob, uint64_t reservation_id,
                                            uint64_t future_id, int timeout_ms) {
  return gateway_watch_session_future_for_object_internal(ob, reservation_id, future_id,
                                                          timeout_ms, false);
}

int gateway_watch_session_future_output_for_object(object_t *ob, uint64_t reservation_id,
                                                   uint64_t future_id, int timeout_ms) {
  return gateway_watch_session_future_for_object_internal(ob, reservation_id, future_id,
                                                          timeout_ms, true);
}

int gateway_process_session_future_watches_at(uint64_t now_ms) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }

  g_gateway_runtime_counters.future_watch_poll_runs.fetch_add(1, std::memory_order_relaxed);
  auto queued_at_start = g_gateway_future_watch_queue.size();
  auto poll_count = std::min(queued_at_start, kGatewayFutureWatchPollBudget);
  if (queued_at_start > kGatewayFutureWatchPollBudget) {
    g_gateway_runtime_counters.future_watch_poll_budget_hits.fetch_add(1, std::memory_order_relaxed);
  }
  int processed = 0;
  for (size_t index = 0; index < poll_count; index++) {
    auto reservation_id = g_gateway_future_watch_queue.front();
    g_gateway_future_watch_queue.pop_front();
    g_gateway_future_watch_queue_positions.erase(reservation_id);
    auto watch_it = g_gateway_session_future_watches.find(reservation_id);
    if (watch_it == g_gateway_session_future_watches.end()) {
      continue;
    }
    g_gateway_runtime_counters.future_watch_poll_items.fetch_add(1, std::memory_order_relaxed);
    auto watch = watch_it->second;
    auto completion_cpu_started_ns = get_current_thread_cpu_time_ns();
    auto *sess = gateway_find_session(watch.session_id.c_str());
    auto *ob = gateway_resolve_session_object(sess);
    auto session_current = sess && ob && sess->user_ob_name == watch.user_ob_name &&
                           sess->user_ob_load_time == watch.user_ob_load_time;
    if (!session_current) {
      g_gateway_future_to_reservation.erase(watch.future_id);
      g_gateway_session_future_watches.erase(watch_it);
      gateway_consume_cancelled_future(watch.future_id, "gateway session stale");
      if (sess) {
        gateway_release_session_output(sess, watch.reservation_id);
      }
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(1, std::memory_order_relaxed);
      gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
      processed++;
      continue;
    }

    auto future_state = vm_owner_future_state(watch.future_id);
    if (future_state == VM_OWNER_FUTURE_PENDING && now_ms < watch.deadline_ms) {
      g_gateway_future_watch_queue.push_back(reservation_id);
      g_gateway_future_watch_queue_positions.emplace(
          reservation_id, std::prev(g_gateway_future_watch_queue.end()));
      continue;
    }

    mapping_t *future = nullptr;
    VMOwnerFutureStringTakeResult output_future;
    uint64_t terminal_at_ns = 0;
    uint64_t take_started_ns = 0;
    uint64_t take_finished_ns = 0;
    if (future_state == VM_OWNER_FUTURE_PENDING) {
      auto *timed_out = vm_owner_future_timeout(watch.future_id, "gateway owner future timed out");
      free_mapping(timed_out);
      take_started_ns = gateway_session_now_ns();
      if (watch.encoded_output) {
        output_future = vm_owner_future_take_string(watch.future_id);
        terminal_at_ns = output_future.terminal_at_ns;
      } else {
        future = vm_owner_future_take(watch.future_id, &terminal_at_ns);
      }
      take_finished_ns = gateway_session_now_ns();
      g_gateway_runtime_counters.future_watches_timed_out.fetch_add(1, std::memory_order_relaxed);
    } else if (future_state == VM_OWNER_FUTURE_COMPLETED ||
               future_state == VM_OWNER_FUTURE_FAILED) {
      take_started_ns = gateway_session_now_ns();
      if (watch.encoded_output) {
        output_future = vm_owner_future_take_string(watch.future_id);
        terminal_at_ns = output_future.terminal_at_ns;
      } else {
        future = vm_owner_future_take(watch.future_id, &terminal_at_ns);
      }
      take_finished_ns = gateway_session_now_ns();
    } else {
      if (watch.encoded_output) {
        output_future = vm_owner_future_take_string(watch.future_id);
      } else {
        future = vm_owner_future_poll(watch.future_id);
      }
    }
    if (take_finished_ns >= take_started_ns && take_started_ns > 0) {
      gateway_session_record_latency(g_gateway_runtime_counters.future_watch_take_ns_total,
                                     g_gateway_runtime_counters.future_watch_take_ns_max,
                                     g_gateway_runtime_counters.future_watch_take_samples,
                                     take_finished_ns - take_started_ns);
    }
    if (terminal_at_ns > 0 && take_started_ns >= terminal_at_ns) {
      gateway_session_record_latency(g_gateway_runtime_counters.future_watch_terminal_lag_ns_total,
                                     g_gateway_runtime_counters.future_watch_terminal_lag_ns_max,
                                     g_gateway_runtime_counters.future_watch_terminal_lag_samples,
                                     take_started_ns - terminal_at_ns);
    }
    std::string state;
    if (watch.encoded_output) {
      if (output_future.state == VM_OWNER_FUTURE_COMPLETED && output_future.string_result) {
        state = "completed";
      } else if (output_future.state == VM_OWNER_FUTURE_PENDING) {
        state = "pending";
      } else if (output_future.state == VM_OWNER_FUTURE_UNKNOWN) {
        state = "unknown";
      } else {
        state = "failed";
      }
    } else {
      state = gateway_future_mapping_state(future);
    }

    g_gateway_future_to_reservation.erase(watch.future_id);
    g_gateway_session_future_watches.erase(watch_it);
    processed++;
    if (state == "completed") {
      g_gateway_runtime_counters.future_watches_completed.fetch_add(1, std::memory_order_relaxed);
    } else {
      g_gateway_runtime_counters.future_watches_failed.fetch_add(1, std::memory_order_relaxed);
    }

    g_gateway_runtime_counters.future_watch_callbacks.fetch_add(1, std::memory_order_relaxed);
    auto callback_started_ns = gateway_session_now_ns();
    bool callback_ok = false;
    if (watch.encoded_output) {
      if (state == "completed") {
        callback_ok = gateway_fill_session_output_for_object(
            ob, watch.reservation_id, output_future.value.data(), output_future.value.size()) != 0;
      } else {
        callback_ok = gateway_release_session_output_for_object(ob, watch.reservation_id) != 0;
      }
      auto *output_state = state == "completed" && callback_ok ? "completed" : "released";
      callback_ok = gateway_dispatch_future_output_notification(
                        ob, watch.reservation_id, output_state) &&
                    callback_ok;
    } else {
      callback_ok = gateway_dispatch_future_watch_callback(ob, watch.reservation_id, future);
    }
    auto callback_finished_ns = gateway_session_now_ns();
    gateway_session_record_latency(g_gateway_runtime_counters.future_watch_callback_ns_total,
                                   g_gateway_runtime_counters.future_watch_callback_ns_max,
                                   g_gateway_runtime_counters.future_watch_callback_samples,
                                   callback_finished_ns - callback_started_ns);
    if (watch.registered_at_ns > 0 && callback_finished_ns >= watch.registered_at_ns) {
      gateway_session_record_latency(g_gateway_runtime_counters.future_watch_end_to_end_ns_total,
                                     g_gateway_runtime_counters.future_watch_end_to_end_ns_max,
                                     g_gateway_runtime_counters.future_watch_end_to_end_samples,
                                     callback_finished_ns - watch.registered_at_ns);
    }
    if (future) {
      free_mapping(future);
    }

    sess = gateway_find_session(watch.session_id.c_str());
    ob = gateway_resolve_session_object(sess);
    session_current = sess && ob && sess->user_ob_name == watch.user_ob_name &&
                      sess->user_ob_load_time == watch.user_ob_load_time;
    if (!callback_ok) {
      g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(1, std::memory_order_relaxed);
    }
    if (session_current && gateway_session_has_pending_reservation(sess, watch.reservation_id)) {
      gateway_release_session_output(sess, watch.reservation_id);
    }
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
  }

  if (g_gateway_session_future_watches.empty()) {
    g_gateway_future_watch_queue.clear();
    g_gateway_future_watch_queue_positions.clear();
    if (!gateway_has_future_watches()) {
      gateway_stop_future_watch_timer();
    }
  }
  return processed;
}

long gateway_session_future_watch_count() {
  return static_cast<long>(g_gateway_session_future_watches.size());
}

int gateway_watch_future_for_object(object_t *ob, uint64_t context_id,
                                    uint64_t future_id, int timeout_ms) {
  if (!vm_context_is_main_thread() || !gateway_object_valid(ob) || context_id == 0 ||
      future_id == 0 || timeout_ms <= 0 ||
      g_gateway_session_future_watches.size() + g_gateway_future_watches.size() >=
          kGatewayMaxFutureWatches ||
      g_gateway_future_watches.find(future_id) != g_gateway_future_watches.end() ||
      g_gateway_future_to_reservation.find(future_id) != g_gateway_future_to_reservation.end() ||
      !function_exists("owner_future_watch_completed", ob, 0)) {
    g_gateway_runtime_counters.generic_future_watches_rejected.fetch_add(1,
                                                                         std::memory_order_relaxed);
    return 0;
  }
  if (vm_owner_future_state(future_id) == VM_OWNER_FUTURE_UNKNOWN ||
      !vm_owner_future_targets_object(future_id, ob)) {
    g_gateway_runtime_counters.generic_future_watches_rejected.fetch_add(1,
                                                                         std::memory_order_relaxed);
    return 0;
  }

  auto now_ms = gateway_session_now_ms();
  auto timeout = static_cast<uint64_t>(timeout_ms);
  auto deadline_ms = timeout > std::numeric_limits<uint64_t>::max() - now_ms
                         ? std::numeric_limits<uint64_t>::max()
                         : now_ms + timeout;
  GatewayFutureWatch watch;
  watch.target_ob_name = ob->obname;
  watch.target_ob_load_time = ob->load_time;
  watch.context_id = context_id;
  watch.future_id = future_id;
  watch.deadline_ms = deadline_ms;
  watch.registered_at_ns = gateway_session_now_ns();
  g_gateway_future_watches.emplace(future_id, std::move(watch));
  g_gateway_generic_future_watch_queue.push_back(future_id);
  g_gateway_runtime_counters.generic_future_watches_registered.fetch_add(
      1, std::memory_order_relaxed);

  auto completion_event_ready = gateway_enable_future_watch_completion_event();
  if (completion_event_ready && vm_owner_future_state(future_id) != VM_OWNER_FUTURE_PENDING) {
    gateway_owner_future_terminal_notified();
  }
  gateway_schedule_future_watch_timer();
  return 1;
}

int gateway_process_future_watches_at(uint64_t now_ms) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }

  auto queued_at_start = g_gateway_generic_future_watch_queue.size();
  auto poll_count = std::min(queued_at_start, kGatewayFutureWatchPollBudget);
  int processed = 0;
  for (size_t index = 0; index < poll_count; index++) {
    auto future_id = g_gateway_generic_future_watch_queue.front();
    g_gateway_generic_future_watch_queue.pop_front();
    auto watch_it = g_gateway_future_watches.find(future_id);
    if (watch_it == g_gateway_future_watches.end()) {
      continue;
    }
    auto watch = watch_it->second;
    auto completion_cpu_started_ns = get_current_thread_cpu_time_ns();
    auto *ob = gateway_resolve_future_watch_object(watch);
    if (!ob) {
      g_gateway_future_watches.erase(watch_it);
      gateway_consume_cancelled_future(future_id, "gateway future watch target stale");
      g_gateway_runtime_counters.generic_future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
      gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
      processed++;
      continue;
    }

    auto future_state = vm_owner_future_state(future_id);
    if (future_state == VM_OWNER_FUTURE_PENDING && now_ms < watch.deadline_ms) {
      g_gateway_generic_future_watch_queue.push_back(future_id);
      continue;
    }

    mapping_t *future = nullptr;
    if (future_state == VM_OWNER_FUTURE_PENDING) {
      auto *timed_out = vm_owner_future_timeout(future_id, "gateway future watch timed out");
      free_mapping(timed_out);
      future = vm_owner_future_take(future_id);
      g_gateway_runtime_counters.generic_future_watches_timed_out.fetch_add(
          1, std::memory_order_relaxed);
    } else if (future_state == VM_OWNER_FUTURE_COMPLETED ||
               future_state == VM_OWNER_FUTURE_FAILED) {
      future = vm_owner_future_take(future_id);
    } else {
      future = vm_owner_future_poll(future_id);
    }

    g_gateway_future_watches.erase(watch_it);
    processed++;
    auto state = gateway_future_mapping_state(future);
    if (state == "completed") {
      g_gateway_runtime_counters.generic_future_watches_completed.fetch_add(
          1, std::memory_order_relaxed);
    } else {
      g_gateway_runtime_counters.generic_future_watches_failed.fetch_add(
          1, std::memory_order_relaxed);
    }
    g_gateway_runtime_counters.generic_future_watch_callbacks.fetch_add(
        1, std::memory_order_relaxed);
    if (!gateway_dispatch_generic_future_watch_callback(ob, watch.context_id, future)) {
      g_gateway_runtime_counters.generic_future_watch_callback_failures.fetch_add(
          1, std::memory_order_relaxed);
    }
    free_mapping(future);
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
  }

  if (g_gateway_future_watches.empty()) {
    g_gateway_generic_future_watch_queue.clear();
    if (!gateway_has_future_watches()) {
      gateway_stop_future_watch_timer();
    }
  }
  return processed;
}

long gateway_future_watch_count() {
  return static_cast<long>(g_gateway_future_watches.size());
}

long gateway_session_fifo_depth_total() {
  long depth = 0;
  for (const auto &entry : g_gateway_sessions) {
    depth += static_cast<long>(entry.second->output_fifo.size());
  }
  return depth;
}

long gateway_session_fifo_pending_reservations_total() {
  long pending = 0;
  for (const auto &session_entry : g_gateway_sessions) {
    for (const auto &output_entry : session_entry.second->output_fifo) {
      if (!output_entry.ready) {
        pending++;
      }
    }
  }
  return pending;
}

long gateway_session_command_input_pending_count() {
  return g_gateway_command_input_pending_sessions.load(std::memory_order_acquire);
}

long gateway_session_command_task_pending_count() {
  return g_gateway_command_task_pending_sessions.load(std::memory_order_acquire);
}

long gateway_session_command_pending_count() {
  return gateway_session_command_input_pending_count() +
         gateway_session_command_task_pending_count();
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

int gateway_flush_session_output_fifo_with_writer(GatewaySession *sess, GatewayOutputWriter writer) {
  int flushed = 0;
  if (!sess || sess->master_fd < 0 || !writer) {
    return 0;
  }
  while (!sess->output_fifo.empty()) {
    const auto &entry = sess->output_fifo.front();
    if (!entry.ready) {
      break;
    }
    if (!writer(sess->master_fd, entry.encoded.c_str(), entry.encoded.size())) {
      break;
    }
    sess->output_fifo.pop_front();
    sess->output_fifo_flushed++;
    g_gateway_runtime_counters.output_fifo_flushed.fetch_add(1, std::memory_order_relaxed);
    flushed = 1;
  }
  return flushed;
}

int gateway_flush_session_output_fifo(GatewaySession *sess) {
  return gateway_flush_session_output_fifo_with_writer(sess, gateway_send_raw_to_fd);
}

int gateway_enqueue_session_output(GatewaySession *sess, std::string encoded) {
  if (!sess || encoded.empty()) {
    return 0;
  }
  if (sess->output_fifo.size() >= sess->output_fifo_max_depth) {
    sess->output_fifo_rejected++;
    g_gateway_runtime_counters.output_fifo_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  GatewayOutputEntry entry;
  entry.encoded = std::move(encoded);
  sess->output_fifo.push_back(std::move(entry));
  sess->output_fifo_enqueued++;
  g_gateway_runtime_counters.output_fifo_enqueued.fetch_add(1, std::memory_order_relaxed);
  sess->last_active = get_current_time();
  gateway_flush_session_output_fifo(sess);
  return 1;
}

uint64_t gateway_reserve_session_output(GatewaySession *sess) {
  auto reserve_started_ns = gateway_session_now_ns();
  if (!sess) {
    return 0;
  }
  if (sess->output_fifo.size() >= sess->output_fifo_max_depth) {
    sess->output_fifo_rejected++;
    g_gateway_runtime_counters.output_fifo_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  auto reservation_id = g_gateway_next_output_reservation_id.fetch_add(1, std::memory_order_relaxed);
  if (reservation_id == 0 ||
      reservation_id > static_cast<uint64_t>(std::numeric_limits<LPC_INT>::max())) {
    sess->output_fifo_rejected++;
    g_gateway_runtime_counters.output_fifo_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  GatewayOutputEntry entry;
  entry.reservation_id = reservation_id;
  entry.ready = false;
  sess->output_fifo.push_back(std::move(entry));
  sess->output_fifo_enqueued++;
  g_gateway_runtime_counters.output_fifo_enqueued.fetch_add(1, std::memory_order_relaxed);
  g_gateway_runtime_counters.output_fifo_reserved.fetch_add(1, std::memory_order_relaxed);
  sess->last_active = get_current_time();
  gateway_session_record_latency(g_gateway_runtime_counters.output_reserve_ns_total,
                                 g_gateway_runtime_counters.output_reserve_ns_max,
                                 g_gateway_runtime_counters.output_reserve_samples,
                                 gateway_session_now_ns() - reserve_started_ns);
  return reservation_id;
}

int gateway_fill_session_output_with_writer(GatewaySession *sess, uint64_t reservation_id,
                                            std::string encoded, GatewayOutputWriter writer) {
  if (!sess || reservation_id == 0 || encoded.empty() || !writer) {
    return 0;
  }
  for (auto it = sess->output_fifo.begin(); it != sess->output_fifo.end(); ++it) {
    auto &entry = *it;
    if (entry.reservation_id != reservation_id || entry.ready) {
      continue;
    }
    entry.encoded = std::move(encoded);
    entry.ready = true;
    g_gateway_runtime_counters.output_fifo_filled.fetch_add(1, std::memory_order_relaxed);
    if (it != sess->output_fifo.begin() && !sess->output_fifo.front().ready) {
      auto preceding_count = static_cast<uint64_t>(std::distance(sess->output_fifo.begin(), it));
      auto &counters = g_gateway_runtime_counters;
      counters.output_fifo_head_blocked_fills.fetch_add(1, std::memory_order_relaxed);
      counters.output_fifo_head_blocked_predecessors_total.fetch_add(preceding_count,
                                                                       std::memory_order_relaxed);
      auto observed = counters.output_fifo_head_blocked_predecessors_max.load(std::memory_order_relaxed);
      while (observed < preceding_count &&
             !counters.output_fifo_head_blocked_predecessors_max.compare_exchange_weak(
                 observed, preceding_count, std::memory_order_relaxed, std::memory_order_relaxed)) {
      }
    }
    sess->last_active = get_current_time();
    gateway_flush_session_output_fifo_with_writer(sess, writer);
    return 1;
  }
  g_gateway_runtime_counters.output_fifo_reservation_misses.fetch_add(1, std::memory_order_relaxed);
  return 0;
}

int gateway_fill_session_output(GatewaySession *sess, uint64_t reservation_id, std::string encoded) {
  return gateway_fill_session_output_with_writer(sess, reservation_id, std::move(encoded),
                                                 gateway_send_raw_to_fd);
}

int gateway_release_session_output_with_writer(GatewaySession *sess, uint64_t reservation_id,
                                               GatewayOutputWriter writer) {
  if (!sess || reservation_id == 0 || !writer) {
    return 0;
  }
  for (auto it = sess->output_fifo.begin(); it != sess->output_fifo.end(); ++it) {
    if (it->reservation_id != reservation_id || it->ready) {
      continue;
    }
    sess->output_fifo.erase(it);
    g_gateway_runtime_counters.output_fifo_released.fetch_add(1, std::memory_order_relaxed);
    gateway_flush_session_output_fifo_with_writer(sess, writer);
    return 1;
  }
  g_gateway_runtime_counters.output_fifo_reservation_misses.fetch_add(1, std::memory_order_relaxed);
  return 0;
}

int gateway_release_session_output(GatewaySession *sess, uint64_t reservation_id) {
  return gateway_release_session_output_with_writer(sess, reservation_id, gateway_send_raw_to_fd);
}

uint64_t gateway_reserve_session_output_for_object(object_t *ob) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }
  return gateway_reserve_session_output(gateway_find_session_by_object(ob));
}

int gateway_fill_session_output_for_object(object_t *ob, uint64_t reservation_id, const char *data, size_t len) {
  if (!vm_context_is_main_thread() || !data) {
    return 0;
  }
  auto *sess = gateway_find_session_by_object(ob);
  if (!sess) {
    return 0;
  }

  if (!gateway_fill_session_output(
          sess, reservation_id,
          gateway_encode_output_envelope(sess->session_id, data, len))) {
    return 0;
  }
  return 1;
}

int gateway_release_session_output_for_object(object_t *ob, uint64_t reservation_id) {
  if (!vm_context_is_main_thread()) {
    return 0;
  }
  auto *sess = gateway_find_session_by_object(ob);
  if (!sess || !gateway_release_session_output(sess, reservation_id)) {
    return 0;
  }
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
  sess->detached_at = 0;
  sess->user_ob = ob;
  sess->user_ob_name = ob->obname ? ob->obname : "";
  sess->user_ob_load_time = ob->load_time;
  sess->last_active = get_current_time();
  g_gateway_obj_to_session[ob] = sess;
  return 1;
}

object_t *gateway_rebind_session_internal(const char *session_id, const char *ip,
                                          int port, int master_fd) {
  g_gateway_runtime_counters.session_rebind_attempts.fetch_add(1, std::memory_order_relaxed);
  auto *sess = gateway_find_session(session_id);
  auto *ob = gateway_resolve_session_object(sess);
  if (!sess || !gateway_object_valid(ob) || !ob->interactive ||
      !(ob->interactive->iflags & GATEWAY_SESSION) || master_fd < 0) {
    g_gateway_runtime_counters.session_rebind_rejected.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }

  auto *user = ob->interactive;
  sess->real_ip = ip ? ip : "";
  sess->real_port = port;
  sess->master_fd = master_fd;
  sess->detached_at = 0;
  sess->last_active = get_current_time();
  user->gateway_master_fd = master_fd;
  user->gateway_real_port = port;
  user->last_time = sess->last_active;
  if (user->gateway_real_ip) {
    FREE_MSTR(user->gateway_real_ip);
  }
  user->gateway_real_ip = string_copy(ip ? ip : "", "gateway_real_ip");
  gateway_flush_session_output_fifo(sess);
  g_gateway_runtime_counters.session_rebind_completed.fetch_add(1, std::memory_order_relaxed);
  return ob;
}

void gateway_unbind_session_object(object_t *ob) {
  auto *sess = gateway_find_session_by_object(ob);
  if (!sess) {
    return;
  }
  std::string session_id = sess->session_id;
  gateway_cancel_session_future_watches(session_id, sess, "gateway session unbound", false);
  gateway_release_command_input_pending(sess);
  gateway_release_command_task_pending(sess);
  g_gateway_obj_to_session.erase(ob);
  g_gateway_sessions.erase(session_id);
}

void gateway_cleanup_master_sessions(int master_fd) {
  for (const auto &entry : g_gateway_sessions) {
    auto *sess = entry.second.get();
    if (!sess || sess->master_fd != master_fd) {
      continue;
    }
    sess->master_fd = -1;
    sess->detached_at = get_current_time();
    if (auto *ob = gateway_resolve_session_object(sess); gateway_object_valid(ob) && ob->interactive) {
      ob->interactive->gateway_master_fd = -1;
    }
    g_gateway_runtime_counters.sessions_detached.fetch_add(1, std::memory_order_relaxed);
  }
}

bool gateway_is_session(object_t *ob) {
  return ob && ob->interactive && (ob->interactive->iflags & GATEWAY_SESSION);
}

int gateway_probe_suppress_once_for_object(object_t *ob) {
  auto *sess = gateway_find_session_by_object(ob);
  if (!sess) {
    return 0;
  }
  sess->probe_suppressed_once = true;
  return 1;
}

bool gateway_probe_suppressed_for_object(object_t *ob) {
  auto *sess = gateway_find_session_by_object(ob);
  return sess && sess->probe_suppressed_once;
}

void gateway_probe_finish_suppressed_command_for_object(object_t *ob) {
  auto *sess = gateway_find_session_by_object(ob);
  if (sess) {
    sess->probe_suppressed_once = false;
  }
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
  gateway_cancel_session_future_watches(sess->session_id, sess, "gateway session exec", true);
  new_ob->interactive->ob = new_ob;
  g_gateway_obj_to_session.erase(old_ob);
  g_gateway_obj_to_session[new_ob] = sess;
  sess->user_ob = new_ob;
  sess->user_ob_name = new_ob->obname ? new_ob->obname : "";
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
  std::string encoded;

  if (!sess || !data) {
    return 0;
  }

  encoded = gateway_encode_output_envelope(sess->session_id, data, len);
  if (g_gateway_debug) {
    debug_message("[gateway] output sid=%s len=%zu\n", session_id, len);
  }
  return gateway_enqueue_session_output(sess, std::move(encoded));
}

std::string gateway_encode_output_envelope_for_test(const std::string &session_id,
                                                    const char *data, size_t len) {
  return gateway_encode_output_envelope(session_id, data, len);
}

std::string gateway_encode_preencoded_chat_batch_for_test(
    const std::vector<std::string> &stable_children_json, LPC_INT message_epoch,
    LPC_INT first_server_seq, LPC_INT sent_at, const std::string &outer_dynamic_json) {
  std::vector<std::string_view> views;
  std::string frame;

  views.reserve(stable_children_json.size());
  for (const auto &stable_json : stable_children_json) {
    views.emplace_back(stable_json);
  }
  if (!gateway_build_preencoded_chat_batch_frame(
          views, message_epoch, first_server_seq, sent_at, outer_dynamic_json, &frame)) {
    return "";
  }
  return frame;
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
  auto *ob = gateway_resolve_session_object(sess);
  const char *reason_code_str = reason_code && reason_code[0] ? reason_code : "client_disconnected";
  const char *reason_text_str = reason_text && reason_text[0] ? reason_text : reason_code_str;

  if (!sess) {
    return 0;
  }
  gateway_cancel_session_future_watches(session_id, sess, "gateway session destroyed", false);
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
      auto *session_ob = gateway_resolve_session_object(sess);
      if (session_ob) {
        gateway_unbind_session_object(session_ob);
      } else {
        gateway_release_command_input_pending(sess);
        gateway_release_command_task_pending(sess);
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
    gateway_release_command_input_pending(sess);
    gateway_release_command_task_pending(sess);
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
    if (ip->iflags & CMD_IN_BUF) {
      gateway_mark_command_input_pending(sess);
    }
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
    auto *session_ob = gateway_resolve_session_object(sess);
    if (!session_ob || !session_ob->interactive) {
      to_remove.push_back(entry.first);
      continue;
    }
    if (sess->master_fd >= 0 && gateway_has_master(sess->master_fd)) {
      continue;
    }
    if (sess->master_fd >= 0) {
      sess->master_fd = -1;
      sess->detached_at = get_current_time();
      session_ob->interactive->gateway_master_fd = -1;
      g_gateway_runtime_counters.sessions_detached.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    if (sess->detached_at <= 0) {
      sess->detached_at = get_current_time();
      continue;
    }
    if (g_gateway_reconnect_grace > 0 &&
        (get_current_time() - sess->detached_at) <= g_gateway_reconnect_grace) {
      continue;
    }
    g_gateway_runtime_counters.session_reconnect_expired.fetch_add(1, std::memory_order_relaxed);
    to_remove.push_back(entry.first);
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
  g_gateway_command_input_pending_sessions.store(0, std::memory_order_release);
  g_gateway_command_task_pending_sessions.store(0, std::memory_order_release);
  for (const auto &entry : g_gateway_future_watches) {
    gateway_consume_cancelled_future(entry.first, "gateway cleanup");
    g_gateway_runtime_counters.generic_future_watches_cancelled.fetch_add(
        1, std::memory_order_relaxed);
  }
  g_gateway_future_watches.clear();
  g_gateway_generic_future_watch_queue.clear();
  gateway_cleanup_future_watch_timer();
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

void f_gateway_probe_suppress_once() {
  auto *ob = sp->u.ob;
  if (sp->type != T_OBJECT || !ob || (ob->flags & O_DESTRUCTED)) {
    if (sp->type == T_OBJECT) {
      free_object(&sp->u.ob, "f_gateway_probe_suppress_once");
    } else {
      pop_stack();
    }
    put_number(0);
    return;
  }
  free_object(&sp->u.ob, "f_gateway_probe_suppress_once");
  put_number(gateway_probe_suppress_once_for_object(ob));
}

void f_gateway_session_reserve() {
  auto *ob = sp->u.ob;
  auto reservation_id = gateway_reserve_session_output_for_object(ob);
  pop_stack();
  push_number(static_cast<LPC_INT>(reservation_id));
}

void f_gateway_session_fill() {
  auto *data = sp;
  auto reservation_id = static_cast<uint64_t>((sp - 1)->u.number);
  auto *ob = (sp - 2)->u.ob;
  auto result = gateway_fill_session_output_for_object(ob, reservation_id, data->u.string, SVALUE_STRLEN(data));
  pop_n_elems(3);
  push_number(result);
}

void f_gateway_session_fill_preencoded_chat_batch() {
  const auto *outer_dynamic_json = sp->u.string;
  const auto outer_dynamic_json_len = SVALUE_STRLEN(sp);
  const auto sent_at = (sp - 1)->u.number;
  const auto first_server_seq = (sp - 2)->u.number;
  const auto message_epoch = (sp - 3)->u.number;
  auto *stable_children = (sp - 4)->u.arr;
  const auto reservation_id = static_cast<uint64_t>((sp - 5)->u.number);
  auto *ob = (sp - 6)->u.ob;
  std::vector<std::string_view> stable_children_json;
  std::string frame;
  int result = 0;

  if (stable_children && stable_children->size > 0 && outer_dynamic_json &&
      vm_context_is_main_thread()) {
    stable_children_json.reserve(static_cast<size_t>(stable_children->size));
    for (int index = 0; index < stable_children->size; ++index) {
      const auto *child = &stable_children->item[index];
      if (child->type != T_STRING || !child->u.string) {
        stable_children_json.clear();
        break;
      }
      stable_children_json.emplace_back(child->u.string, SVALUE_STRLEN(child));
    }
    if (!stable_children_json.empty() &&
        gateway_build_preencoded_chat_batch_frame(
            stable_children_json, message_epoch, first_server_seq, sent_at,
            std::string_view(outer_dynamic_json, outer_dynamic_json_len), &frame)) {
      result = gateway_fill_session_output_for_object(
          ob, reservation_id, frame.data(), frame.size());
    }
  }

  pop_n_elems(7);
  push_number(result);
}

void f_gateway_session_release() {
  auto reservation_id = static_cast<uint64_t>(sp->u.number);
  auto *ob = (sp - 1)->u.ob;
  auto result = gateway_release_session_output_for_object(ob, reservation_id);
  pop_2_elems();
  push_number(result);
}

void f_gateway_session_watch_future() {
  auto timeout_ms = static_cast<int>(sp->u.number);
  auto future_id = static_cast<uint64_t>((sp - 1)->u.number);
  auto reservation_id = static_cast<uint64_t>((sp - 2)->u.number);
  auto *ob = (sp - 3)->u.ob;
  auto result = gateway_watch_session_future_for_object(ob, reservation_id, future_id, timeout_ms);
  pop_n_elems(4);
  push_number(result);
}

void f_gateway_session_watch_future_output() {
  auto timeout_ms = static_cast<int>(sp->u.number);
  auto future_id = static_cast<uint64_t>((sp - 1)->u.number);
  auto reservation_id = static_cast<uint64_t>((sp - 2)->u.number);
  auto *ob = (sp - 3)->u.ob;
  auto result = gateway_watch_session_future_output_for_object(
      ob, reservation_id, future_id, timeout_ms);
  pop_n_elems(4);
  push_number(result);
}

void f_gateway_future_watch() {
  auto timeout_ms = static_cast<int>(sp->u.number);
  auto future_id = static_cast<uint64_t>((sp - 1)->u.number);
  auto context_id = static_cast<uint64_t>((sp - 2)->u.number);
  auto *ob = (sp - 3)->u.ob;
  auto result = gateway_watch_future_for_object(ob, context_id, future_id, timeout_ms);
  pop_n_elems(4);
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
    auto *session_ob = gateway_resolve_session_object(entry.second.get());
    if (session_ob) {
      arr->item[index].type = T_OBJECT;
      arr->item[index].u.ob = session_ob;
      add_ref(session_ob, "gateway_sessions");
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
  auto *session_ob = gateway_resolve_session_object(sess);
  add_mapping_string(map, "object_name", session_ob ? session_ob->obname : "");
  add_mapping_string(map, "owner_id", session_ob ? vm_owner_id(session_ob) : "");
  add_mapping_pair(map, "owner_epoch", session_ob ? static_cast<long>(vm_owner_epoch(session_ob)) : 0);
  add_mapping_pair(map, "session_fifo_contract_ready", 1);
  add_mapping_pair(map, "session_fifo_depth", static_cast<long>(sess->output_fifo.size()));
  long pending_reservations = 0;
  for (const auto &entry : sess->output_fifo) {
    if (!entry.ready) {
      pending_reservations++;
    }
  }
  add_mapping_pair(map, "session_fifo_pending_reservations", pending_reservations);
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
