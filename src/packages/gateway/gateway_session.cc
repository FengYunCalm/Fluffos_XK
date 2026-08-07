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

#include <algorithm>
#include <chrono>
#include <charconv>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

uint64_t gateway_enqueue_pending_command_internal(object_t *user);

bool gateway_session_id_is_valid(const char *data, size_t len) {
  if (!data || len == 0 || len > kGatewayMaxSessionIdBytes) {
    return false;
  }
  for (size_t index = 0; index < len; ++index) {
    const auto byte = static_cast<unsigned char>(data[index]);
    if (byte < 0x21 || byte > 0x7e) {
      return false;
    }
  }
  return true;
}

namespace {
bool gateway_session_id_c_string_is_valid(const char *session_id) {
  if (!session_id) {
    return false;
  }
  size_t len = 0;
  while (len <= kGatewayMaxSessionIdBytes && session_id[len] != '\0') {
    ++len;
  }
  return gateway_session_id_is_valid(session_id, len);
}

std::unordered_map<std::string, std::unique_ptr<GatewaySession>> g_gateway_sessions;
std::unordered_map<object_t *, GatewaySession *> g_gateway_obj_to_session;
std::unordered_map<int, size_t> g_gateway_master_output_fifo_wire_bytes;
size_t g_gateway_detached_output_fifo_wire_bytes = 0;
std::atomic<uint64_t> g_gateway_next_output_reservation_id{1};
std::atomic<uint64_t> g_gateway_next_message_event_wave_id{1};
std::atomic<uint64_t> g_gateway_projected_wire_full_validation_count{0};
std::atomic<long> g_gateway_command_input_pending_sessions{0};
std::atomic<long> g_gateway_command_task_pending_sessions{0};
enum class GatewayFutureOutputKind : uint8_t {
  kMapping = 0,
  kProtocolPayload,
  kValidatedWire,
};
struct GatewaySessionFutureWatch {
  std::string session_id;
  std::string user_ob_name;
  std::string owner_id;
  int64_t user_ob_load_time{0};
  uint64_t owner_epoch{0};
  uint64_t reservation_id{0};
  uint64_t future_id{0};
  uint64_t deadline_ms{0};
  uint64_t registered_at_ns{0};
  LPC_INT event_count{0};
  LPC_INT slot_server_seq{0};
  uint64_t projection_generation{0};
  uint64_t room_output_wave_id{0};
  size_t room_output_wave_index{0};
  GatewayFutureOutputKind output_kind{GatewayFutureOutputKind::kMapping};
};
struct GatewayPendingMessageEventProjectionWork {
  GatewayPendingMessageEventProjectionSnapshot snapshot;
  GatewayPendingMessageEventProjectionColumns columns;
  std::string prevalidated_wire_bytes;
};
using GatewayRoomOutputRetrySchedule = std::multimap<uint64_t, uint64_t>;
struct GatewayRoomOutputWaveItem {
  GatewaySessionFutureWatch watch;
  std::shared_ptr<const GatewayPendingMessageEventProjectionWork> work;
  bool terminal{false};
  bool completed{false};
  bool inline_fallback{false};
  bool reservation_closed{false};
  bool notification_finalized{false};
  std::string wire_bytes;
};
struct GatewayRoomOutputWave {
  uint64_t wave_id{0};
  std::vector<GatewayRoomOutputWaveItem> items;
  uint64_t retry_started_at_ms{0};
  uint64_t retry_due_at_ms{0};
  uint32_t retry_attempts{0};
  std::optional<GatewayRoomOutputRetrySchedule::iterator> retry_schedule;
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
std::unordered_map<uint64_t, GatewayRoomOutputWave> g_gateway_room_output_waves;
GatewayRoomOutputRetrySchedule g_gateway_room_output_retry_schedule;
uint64_t g_gateway_next_room_output_wave_id = 1;
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
constexpr size_t kGatewayRoomOutputRetryBudget = 16;
constexpr uint64_t kGatewayRoomOutputRetryWallBudgetNs = 500000;
constexpr uint64_t kGatewayRoomOutputRetryBaseDelayMs = 2;
constexpr uint64_t kGatewayRoomOutputRetryMaxDelayMs = 128;
constexpr uint64_t kGatewayRoomOutputRetryMaxHoldMs = 2000;
constexpr uint32_t kGatewayRoomOutputRetryMaxAttempts = 12;
constexpr size_t kGatewayMessageEventTemplateCacheMaxEntries = 256;
constexpr size_t kGatewayMessageEventTemplateCacheMaxBytes = 4 * 1024 * 1024;
constexpr size_t kGatewayMessageEventTemplateCacheMaxItemBytes = 64 * 1024;
constexpr LPC_INT kGatewayOwnerRoomOutputMaxEvents = 128;

std::unordered_multimap<size_t, GatewayMessageEventTemplate>
    g_gateway_message_event_template_cache;
size_t g_gateway_message_event_template_cache_bytes = 0;

class GatewayWireOutput;
bool gateway_dispatch_future_output_notification(
    object_t *ob, uint64_t reservation_id, const char *state,
    LPC_INT event_count, LPC_INT slot_server_seq);
void gateway_finalize_cancelled_session_future_watch(
    const GatewaySessionFutureWatch &watch, const char *reason,
    bool release_non_mapping_reservation);
bool gateway_pending_message_event_projection_matches(
    const GatewaySession *sess, uint64_t reservation_id, uint64_t generation,
    bool require_sealed);
bool gateway_stage_session_wire_output(GatewaySession *sess,
                                       uint64_t reservation_id,
                                       GatewayWireOutput wire_output);
std::optional<GatewaySessionFutureWatch>
gateway_detach_session_future_watch(uint64_t reservation_id);
size_t gateway_abort_room_output_wave(uint64_t wave_id, const char *reason,
                                      const std::string *skip_release_session);
void gateway_cancel_room_output_wave_session_items(
    const std::string &session_id, GatewaySession *sess, const char *reason,
    bool release_reservations);
int gateway_process_room_output_wave_watch(
    const GatewaySessionFutureWatch &watch, uint64_t now_ms);
bool gateway_room_output_wave_all_terminal(
    const GatewayRoomOutputWave &wave);
bool gateway_publish_room_output_wave(uint64_t wave_id);
void gateway_process_room_output_publish_retries(uint64_t now_ms);

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

void gateway_session_record_thread_cpu(
    std::atomic<uint64_t> &total, std::atomic<uint64_t> &max,
    std::atomic<uint64_t> &samples, std::atomic<uint64_t> &unavailable,
    int64_t started_ns) {
  const auto finished_ns = get_current_thread_cpu_time_ns();
  if (started_ns < 0 || finished_ns < started_ns) {
    unavailable.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  gateway_session_record_latency(
      total, max, samples, static_cast<uint64_t>(finished_ns - started_ns));
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

bool gateway_escape_json_string_content(std::string_view value,
                                        std::string *escaped) {
  if (!escaped) {
    return false;
  }
  std::string quoted;
  try {
    quoted.reserve(value.size() + 2);
    if (!gateway_append_json_string(value.data(), value.size(), &quoted) ||
        quoted.size() < 2) {
      return false;
    }
    escaped->assign(quoted.data() + 1, quoted.size() - 2);
  } catch (const std::exception &) {
    escaped->clear();
    return false;
  }
  return true;
}

bool gateway_encode_inner_json_string_for_outer(std::string_view value,
                                                std::string *escaped) {
  if (!escaped) {
    return false;
  }
  std::string inner_json;
  try {
    inner_json.reserve(value.size() + 2);
    if (!gateway_append_json_string(value.data(), value.size(), &inner_json)) {
      return false;
    }
  } catch (const std::exception &) {
    return false;
  }
  return gateway_escape_json_string_content(inner_json, escaped);
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

class GatewayWireOutput {
 public:
  GatewayWireOutput(GatewayWireOutput &&) noexcept = default;
  GatewayWireOutput &operator=(GatewayWireOutput &&) noexcept = default;
  GatewayWireOutput(const GatewayWireOutput &) = delete;
  GatewayWireOutput &operator=(const GatewayWireOutput &) = delete;

  bool empty() const { return wire_bytes_.empty(); }
  size_t size() const { return wire_bytes_.size(); }
  bool bound_to(const GatewaySession *sess) const {
    return sess && !session_id_.empty() && session_id_ == sess->session_id;
  }
  std::string release() && { return std::move(wire_bytes_); }

 private:
  GatewayWireOutput(std::string session_id, std::string wire_bytes)
      : session_id_(std::move(session_id)), wire_bytes_(std::move(wire_bytes)) {}

  std::string session_id_;
  std::string wire_bytes_;

  friend class GatewayWireOutputFactory;
};

size_t gateway_session_output_fifo_wire_limit(const GatewaySession *sess) {
  return sess && sess->output_fifo_max_wire_bytes > 0
      ? sess->output_fifo_max_wire_bytes
      : gateway_write_buffer_limit();
}

int gateway_output_fifo_aggregate_bucket_key(int master_fd) {
  return master_fd < 0 ? -1 : master_fd;
}

size_t gateway_output_fifo_aggregate_bucket_bytes(int master_fd) {
  const auto bucket_key =
      gateway_output_fifo_aggregate_bucket_key(master_fd);
  if (bucket_key < 0) {
    return g_gateway_detached_output_fifo_wire_bytes;
  }
  auto it = g_gateway_master_output_fifo_wire_bytes.find(bucket_key);
  return it == g_gateway_master_output_fifo_wire_bytes.end() ? 0 : it->second;
}

bool gateway_output_fifo_aggregate_bucket_can_add(int master_fd,
                                                  size_t wire_bytes) {
  const auto current = gateway_output_fifo_aggregate_bucket_bytes(master_fd);
  const auto limit = gateway_write_buffer_limit();
  return current <= limit && wire_bytes <= limit - current;
}

void gateway_output_fifo_aggregate_bucket_add(int master_fd,
                                              size_t wire_bytes) {
  if (wire_bytes == 0) {
    return;
  }
  const auto bucket_key =
      gateway_output_fifo_aggregate_bucket_key(master_fd);
  auto *current = &g_gateway_detached_output_fifo_wire_bytes;
  if (bucket_key >= 0) {
    current = &g_gateway_master_output_fifo_wire_bytes[bucket_key];
  }
  *current = wire_bytes > std::numeric_limits<size_t>::max() - *current
                 ? std::numeric_limits<size_t>::max()
                 : *current + wire_bytes;
}

void gateway_output_fifo_aggregate_bucket_remove(int master_fd,
                                                 size_t wire_bytes) {
  if (wire_bytes == 0) {
    return;
  }
  const auto bucket_key =
      gateway_output_fifo_aggregate_bucket_key(master_fd);
  if (bucket_key < 0) {
    g_gateway_detached_output_fifo_wire_bytes =
        wire_bytes >= g_gateway_detached_output_fifo_wire_bytes
            ? 0
            : g_gateway_detached_output_fifo_wire_bytes - wire_bytes;
    return;
  }
  auto it = g_gateway_master_output_fifo_wire_bytes.find(bucket_key);
  if (it == g_gateway_master_output_fifo_wire_bytes.end()) {
    return;
  }
  if (wire_bytes >= it->second) {
    g_gateway_master_output_fifo_wire_bytes.erase(it);
  } else {
    it->second -= wire_bytes;
  }
}

bool gateway_session_output_fifo_session_can_add_wire_bytes(
    const GatewaySession *sess, size_t wire_bytes) {
  if (!sess) {
    return false;
  }
  const auto limit = gateway_session_output_fifo_wire_limit(sess);
  return sess->output_fifo_wire_bytes <= limit &&
      wire_bytes <= limit - sess->output_fifo_wire_bytes;
}

bool gateway_session_output_fifo_aggregate_can_add_wire_bytes(
    const GatewaySession *sess, size_t wire_bytes) {
  return sess &&
      (!sess->output_fifo_budget_tracked ||
       gateway_output_fifo_aggregate_bucket_can_add(sess->master_fd,
                                                    wire_bytes));
}

void gateway_record_session_output_fifo_wire_rejection(GatewaySession *sess) {
  if (!sess) {
    return;
  }
  sess->output_fifo_rejected++;
  sess->output_fifo_wire_bytes_rejected++;
  g_gateway_runtime_counters.output_fifo_rejected.fetch_add(
      1, std::memory_order_relaxed);
  g_gateway_runtime_counters.output_fifo_wire_bytes_rejected.fetch_add(
      1, std::memory_order_relaxed);
}

void gateway_record_session_output_fifo_aggregate_rejection() {
  g_gateway_runtime_counters.output_fifo_aggregate_wire_bytes_rejected.fetch_add(
      1, std::memory_order_relaxed);
}

void gateway_remove_session_output_fifo_wire_bytes(GatewaySession *sess,
                                                   size_t wire_bytes) {
  if (!sess) {
    return;
  }
  const auto removed = std::min(wire_bytes, sess->output_fifo_wire_bytes);
  gateway_output_fifo_aggregate_bucket_remove(
      sess->output_fifo_budget_tracked ? sess->master_fd : -1,
      sess->output_fifo_budget_tracked ? removed : 0);
  sess->output_fifo_wire_bytes -= removed;
}

void gateway_add_session_output_fifo_wire_bytes(GatewaySession *sess,
                                                size_t wire_bytes) {
  if (!sess || wire_bytes == 0) {
    return;
  }
  gateway_output_fifo_aggregate_bucket_add(
      sess->output_fifo_budget_tracked ? sess->master_fd : -1,
      sess->output_fifo_budget_tracked ? wire_bytes : 0);
  sess->output_fifo_wire_bytes += wire_bytes;
}

void gateway_trim_session_output_fifo_for_bucket(GatewaySession *sess,
                                                 size_t max_wire_bytes) {
  if (!sess || sess->output_fifo_wire_bytes <= max_wire_bytes) {
    return;
  }

  uint64_t dropped_entries = 0;
  uint64_t dropped_wire_bytes = 0;
  // Preserve the oldest send order and every pending reservation barrier.
  auto it = sess->output_fifo.end();
  while (it != sess->output_fifo.begin() &&
         sess->output_fifo_wire_bytes > max_wire_bytes) {
    --it;
    if (!it->ready) {
      continue;
    }
    const auto wire_bytes = it->wire_bytes.size();
    gateway_remove_session_output_fifo_wire_bytes(sess, wire_bytes);
    dropped_wire_bytes += static_cast<uint64_t>(wire_bytes);
    ++dropped_entries;
    it = sess->output_fifo.erase(it);
  }

  if (dropped_entries == 0) {
    return;
  }
  g_gateway_runtime_counters.output_fifo_destroyed_ready.fetch_add(
      dropped_entries, std::memory_order_relaxed);
  g_gateway_runtime_counters.output_fifo_rebucket_wire_bytes_dropped.fetch_add(
      dropped_wire_bytes, std::memory_order_relaxed);
}

size_t gateway_output_fifo_aggregate_bucket_available(int master_fd) {
  const auto current = gateway_output_fifo_aggregate_bucket_bytes(master_fd);
  const auto limit = gateway_write_buffer_limit();
  return current >= limit ? 0 : limit - current;
}

void gateway_track_session_output_fifo_budget(GatewaySession *sess) {
  if (!sess || sess->output_fifo_budget_tracked) {
    return;
  }
  gateway_trim_session_output_fifo_for_bucket(
      sess, gateway_output_fifo_aggregate_bucket_available(sess->master_fd));
  sess->output_fifo_budget_tracked = true;
  gateway_output_fifo_aggregate_bucket_add(sess->master_fd,
                                           sess->output_fifo_wire_bytes);
}

void gateway_move_session_output_fifo_budget(GatewaySession *sess,
                                             int new_master_fd) {
  if (!sess || !sess->output_fifo_budget_tracked ||
      gateway_output_fifo_aggregate_bucket_key(sess->master_fd) ==
          gateway_output_fifo_aggregate_bucket_key(new_master_fd)) {
    return;
  }
  gateway_trim_session_output_fifo_for_bucket(
      sess, gateway_output_fifo_aggregate_bucket_available(new_master_fd));
  gateway_output_fifo_aggregate_bucket_remove(sess->master_fd,
                                              sess->output_fifo_wire_bytes);
  gateway_output_fifo_aggregate_bucket_add(new_master_fd,
                                           sess->output_fifo_wire_bytes);
}

void gateway_untrack_session_output_fifo_budget(GatewaySession *sess) {
  if (!sess || !sess->output_fifo_budget_tracked) {
    return;
  }
  gateway_output_fifo_aggregate_bucket_remove(sess->master_fd,
                                              sess->output_fifo_wire_bytes);
  sess->output_fifo_budget_tracked = false;
}

class GatewayWireOutputFactory {
 public:
  static std::optional<GatewayWireOutput> protocol_output(
      const GatewaySession *sess, std::string_view data) {
    if (!sess || sess->session_id.empty()) {
      return std::nullopt;
    }
    try {
      auto wire_bytes = gateway_encode_output_envelope(
          sess->session_id, data.data(), data.size());
      if (!valid_wire_bytes(wire_bytes)) {
        return std::nullopt;
      }
      return GatewayWireOutput(sess->session_id, std::move(wire_bytes));
    } catch (const std::exception &) {
      return std::nullopt;
    }
  }

  static std::optional<GatewayWireOutput> southbound_json(
      const GatewaySession *sess, const nlohmann::json &payload) {
    if (!sess || sess->session_id.empty() || !payload.is_object() ||
        payload.size() != 3 || payload.value("type", "") != "output" ||
        payload.value("cid", "") != sess->session_id ||
        !payload.contains("data") || !payload["data"].is_string()) {
      return std::nullopt;
    }
    try {
      auto wire_bytes = payload.dump();
      if (!valid_wire_bytes(wire_bytes)) {
        return std::nullopt;
      }
      return GatewayWireOutput(sess->session_id, std::move(wire_bytes));
    } catch (const std::exception &) {
      return std::nullopt;
    }
  }

  static std::optional<GatewayWireOutput> validated_projected_wire(
      const GatewaySession *sess, std::string wire_bytes) {
    if (!sess || sess->session_id.empty() ||
        !valid_wire_bytes(wire_bytes)) {
      return std::nullopt;
    }
    g_gateway_projected_wire_full_validation_count.fetch_add(
        1, std::memory_order_relaxed);
    try {
      const auto payload = nlohmann::json::parse(wire_bytes);
      if (!valid_output_envelope(sess, payload)) {
        return std::nullopt;
      }
    } catch (const std::exception &) {
      return std::nullopt;
    }
    return GatewayWireOutput(sess->session_id, std::move(wire_bytes));
  }

  static std::optional<GatewayWireOutput> locally_encoded_projected_wire(
      const GatewaySession *sess, std::string_view encoded_session_id,
      std::string wire_bytes) {
    if (!sess || sess->session_id.empty() ||
        encoded_session_id != sess->session_id ||
        !valid_wire_bytes(wire_bytes)) {
      return std::nullopt;
    }
    return GatewayWireOutput(sess->session_id, std::move(wire_bytes));
  }

  static std::optional<GatewayWireOutput> session_send(
      const GatewaySession *sess, nlohmann::json payload) {
    if (!sess || sess->session_id.empty()) {
      return std::nullopt;
    }
    if (payload.is_object()) {
      payload["cid"] = sess->session_id;
    } else {
      payload = nlohmann::json{{"type", "output"},
                               {"cid", sess->session_id},
                               {"data", std::move(payload)}};
    }
    try {
      auto wire_bytes = payload.dump();
      if (!valid_wire_bytes(wire_bytes) || !payload.is_object() ||
          payload.value("cid", "") != sess->session_id) {
        return std::nullopt;
      }
      return GatewayWireOutput(sess->session_id, std::move(wire_bytes));
    } catch (const std::exception &) {
      return std::nullopt;
    }
  }

 private:
  static bool valid_wire_bytes(const std::string &wire_bytes) {
    return !wire_bytes.empty() &&
        wire_bytes.size() <= g_gateway_max_packet_size;
  }

  static bool valid_output_envelope(const GatewaySession *sess,
                                    const nlohmann::json &payload) {
    return sess && payload.is_object() && payload.size() == 3 &&
        payload.value("type", "") == "output" &&
        payload.value("cid", "") == sess->session_id &&
        payload.contains("data") && payload["data"].is_string();
  }
};

std::optional<GatewayWireOutput> gateway_prepare_session_send_wire(
    GatewaySession *sess, nlohmann::json payload) {
  return GatewayWireOutputFactory::session_send(sess, std::move(payload));
}

int gateway_enqueue_session_wire_output(GatewaySession *sess,
                                        GatewayWireOutput wire_output);
int gateway_fill_session_wire_output_with_writer(
    GatewaySession *sess, uint64_t reservation_id,
    GatewayWireOutput wire_output, GatewayOutputWriter writer);
bool gateway_stage_session_wire_outputs(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    std::vector<GatewayWireOutput> *wire_outputs);

bool gateway_json_object_members(std::string_view encoded, std::string_view *members) {
  if (!members || encoded.size() < 2 || encoded.front() != '{' || encoded.back() != '}') {
    return false;
  }
  *members = encoded.substr(1, encoded.size() - 2);
  return true;
}

bool gateway_parse_json_object(std::string_view encoded,
                               nlohmann::json *object) {
  if (encoded.empty()) {
    return false;
  }
  auto parsed = nlohmann::json::parse(
      encoded.begin(), encoded.end(), nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object()) {
    return false;
  }
  if (object) {
    *object = std::move(parsed);
  }
  return true;
}

bool gateway_validate_chat_stable_child_json(std::string_view encoded) {
  nlohmann::json payload;
  return gateway_parse_json_object(encoded, &payload) &&
      !payload.contains("meta");
}

bool gateway_validate_chat_outer_dynamic_json(
    std::string_view encoded, std::string_view *members) {
  nlohmann::json payload;
  return gateway_parse_json_object(encoded, &payload) && payload.size() == 1 &&
      payload.contains("meta") && payload["meta"].is_object() &&
      gateway_json_object_members(encoded, members);
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
  std::vector<std::string_view> stable_members_json;
  const auto child_overhead = kChildPrefix.size() + kChildMetaPrefix.size() +
                              kSentAtPrefix.size() + kEpochPrefix.size() +
                              kChildSuffix.size() + 72;
  const auto maximum_size = frame ? frame->max_size() : 0;
  size_t estimated_size;

  if (!frame || stable_children_json.empty() || message_epoch < 0 || first_server_seq <= 0 ||
      sent_at <= 0 ||
      !gateway_validate_chat_outer_dynamic_json(outer_dynamic_json,
                                                &outer_members) ||
      stable_children_json.size() > static_cast<size_t>(std::numeric_limits<LPC_INT>::max()) ||
      first_server_seq > std::numeric_limits<LPC_INT>::max() -
                             static_cast<LPC_INT>(stable_children_json.size() - 1)) {
    return false;
  }

  stable_members_json.reserve(stable_children_json.size());
  if (outer_members.size() > maximum_size - kFramePrefix.size() - 4) {
    return false;
  }
  estimated_size = kFramePrefix.size() + outer_members.size() + 4;
  for (const auto stable_json : stable_children_json) {
    std::string_view stable_members;
    if (!gateway_validate_chat_stable_child_json(stable_json) ||
        !gateway_json_object_members(stable_json, &stable_members) ||
        stable_json.size() > maximum_size - estimated_size ||
        child_overhead > maximum_size - estimated_size - stable_json.size()) {
      return false;
    }
    stable_members_json.push_back(stable_members);
    estimated_size += stable_json.size() + child_overhead;
  }

  frame->clear();
  frame->reserve(estimated_size);
  frame->append(kFramePrefix);
  for (size_t index = 0; index < stable_children_json.size(); ++index) {
    const auto stable_members = stable_members_json[index];
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

bool gateway_parse_and_validate_stable_message_event(
    std::string_view encoded, GatewayMessageEventTemplate *message_template) {
  static const std::unordered_set<std::string> kAllowedKeys{
      "id",             "schema_version", "scope",       "causation_id",
      "correlation_id", "channel",        "intent",      "priority",
      "reliability",    "display_mode",   "ttl_ms",      "collapse_key",
      "text",           "payload",
  };

  if (!message_template || encoded.empty()) {
    return false;
  }
  auto event = nlohmann::json::parse(encoded.begin(), encoded.end(), nullptr, false);
  if (event.is_discarded() || !event.is_object()) {
    return false;
  }
  for (const auto &[key, value] : event.items()) {
    (void)value;
    if (kAllowedKeys.find(key) == kAllowedKeys.end()) {
      return false;
    }
  }
  if (event.size() < 10 || !event.contains("schema_version") ||
      !event["schema_version"].is_number_integer() ||
      event["schema_version"].get<LPC_INT>() != 1 ||
      !event.contains("channel") || !event["channel"].is_string() ||
      event["channel"].get_ref<const std::string &>().empty() ||
      !event.contains("intent") || !event["intent"].is_string() ||
      event["intent"].get_ref<const std::string &>().empty() ||
      !event.contains("priority") || !event["priority"].is_string() ||
      event["priority"].get_ref<const std::string &>().empty() ||
      !event.contains("reliability") || !event["reliability"].is_string() ||
      event["reliability"].get_ref<const std::string &>().empty() ||
      !event.contains("display_mode") || !event["display_mode"].is_string() ||
      event["display_mode"].get_ref<const std::string &>().empty() ||
      !event.contains("ttl_ms") || !event["ttl_ms"].is_number_integer() ||
      event["ttl_ms"].get<LPC_INT>() <= 0 ||
      !event.contains("collapse_key") || !event["collapse_key"].is_string() ||
      !event.contains("text") || !event["text"].is_string() ||
      event["text"].get_ref<const std::string &>().empty() ||
      !event.contains("payload") || !event["payload"].is_object()) {
    return false;
  }
  for (const auto *key : {"id", "causation_id", "correlation_id"}) {
    if (event.contains(key) &&
        (!event[key].is_string() ||
         event[key].get_ref<const std::string &>().empty())) {
      return false;
    }
  }
  if (event.contains("scope") && !event["scope"].is_object()) {
    return false;
  }

  auto canonical = event.dump();
  if (canonical.size() < 2 || canonical.front() != '{' ||
      canonical.back() != '}') {
    return false;
  }
  GatewayMessageEventTemplate parsed;
  parsed.encoded.assign(encoded.data(), encoded.size());
  parsed.stable_members.assign(canonical.data() + 1, canonical.size() - 2);
  parsed.reliability_json = event["reliability"].dump();
  parsed.priority_json = event["priority"].dump();
  if (!event["collapse_key"].get_ref<const std::string &>().empty()) {
    parsed.collapse_key_json = event["collapse_key"].dump();
  }
  if (!gateway_escape_json_string_content(
          parsed.stable_members, &parsed.outer_escaped_stable_members) ||
      !gateway_escape_json_string_content(
          parsed.reliability_json, &parsed.outer_escaped_reliability_json) ||
      !gateway_escape_json_string_content(
          parsed.priority_json, &parsed.outer_escaped_priority_json) ||
      (!parsed.collapse_key_json.empty() &&
       !gateway_escape_json_string_content(
           parsed.collapse_key_json,
           &parsed.outer_escaped_collapse_key_json))) {
    return false;
  }
  parsed.ttl_ms = event["ttl_ms"].get<LPC_INT>();
  parsed.has_id = event.contains("id");
  parsed.has_scope = event.contains("scope");
  parsed.has_causation_id = event.contains("causation_id");
  parsed.has_correlation_id = event.contains("correlation_id");
  *message_template = std::move(parsed);
  return true;
}

size_t gateway_message_event_template_bytes(
    const GatewayMessageEventTemplate &message_template) {
  return sizeof(message_template) + message_template.encoded.size() +
         message_template.stable_members.size() +
         message_template.reliability_json.size() +
         message_template.priority_json.size() +
         message_template.collapse_key_json.size() +
         message_template.outer_escaped_stable_members.size() +
         message_template.outer_escaped_reliability_json.size() +
         message_template.outer_escaped_priority_json.size() +
         message_template.outer_escaped_collapse_key_json.size();
}

const GatewayMessageEventTemplate *gateway_resolve_message_event_template(
    std::string_view encoded, GatewayMessageEventTemplate *uncached) {
  if (!uncached || encoded.empty()) {
    return nullptr;
  }
  if (encoded.size() > kGatewayMessageEventTemplateCacheMaxItemBytes) {
    g_gateway_runtime_counters.message_event_template_cache_bypasses.fetch_add(
        1, std::memory_order_relaxed);
    return gateway_parse_and_validate_stable_message_event(encoded, uncached)
               ? uncached
               : nullptr;
  }

  const auto cache_key = std::hash<std::string_view>{}(encoded);
  const auto cached = g_gateway_message_event_template_cache.equal_range(cache_key);
  for (auto it = cached.first; it != cached.second; ++it) {
    if (it->second.encoded.size() == encoded.size() &&
        std::equal(encoded.begin(), encoded.end(), it->second.encoded.begin())) {
      g_gateway_runtime_counters.message_event_template_cache_hits.fetch_add(
          1, std::memory_order_relaxed);
      return &it->second;
    }
  }

  g_gateway_runtime_counters.message_event_template_cache_misses.fetch_add(
      1, std::memory_order_relaxed);
  if (!gateway_parse_and_validate_stable_message_event(encoded, uncached)) {
    return nullptr;
  }

  const auto entry_bytes = gateway_message_event_template_bytes(*uncached);
  if (g_gateway_message_event_template_cache.size() >=
          kGatewayMessageEventTemplateCacheMaxEntries ||
      entry_bytes > kGatewayMessageEventTemplateCacheMaxBytes -
                        std::min(g_gateway_message_event_template_cache_bytes,
                                 kGatewayMessageEventTemplateCacheMaxBytes)) {
    g_gateway_runtime_counters.message_event_template_cache_evictions.fetch_add(
        g_gateway_message_event_template_cache.size(),
        std::memory_order_relaxed);
    g_gateway_message_event_template_cache.clear();
    g_gateway_message_event_template_cache_bytes = 0;
  }
  auto inserted = g_gateway_message_event_template_cache.emplace(
      cache_key, std::move(*uncached));
  g_gateway_message_event_template_cache_bytes += entry_bytes;
  return &inserted->second;
}

bool gateway_append_message_event_template(
    const GatewayMessageEventTemplate &message_template,
    std::string_view scope_type, std::string_view scope_id,
    LPC_INT message_seq, LPC_INT server_seq, LPC_INT epoch, LPC_INT sent_at,
    std::string *frame) {
  if (!frame || scope_type.empty() || scope_id.empty() || message_seq <= 0 ||
      server_seq <= 0 || epoch < 0 || sent_at <= 0) {
    return false;
  }

  frame->push_back('{');
  frame->append(message_template.stable_members);
  if (!message_template.has_id) {
    frame->append(",\"id\":\"msg_");
    if (!gateway_append_lpc_int(sent_at, frame)) {
      return false;
    }
    frame->push_back('_');
    if (!gateway_append_lpc_int(message_seq, frame)) {
      return false;
    }
    frame->push_back('"');
  }
  frame->append(",\"seq\":");
  if (!gateway_append_lpc_int(message_seq, frame)) {
    return false;
  }
  if (!message_template.has_scope) {
    frame->append(",\"scope\":{\"type\":");
    if (!gateway_append_json_string(scope_type.data(), scope_type.size(), frame)) {
      return false;
    }
    frame->append(",\"id\":");
    if (!gateway_append_json_string(scope_id.data(), scope_id.size(), frame)) {
      return false;
    }
    frame->push_back('}');
  }
  if (!message_template.has_causation_id) {
    frame->append(",\"causation_id\":\"cmd_");
    if (!gateway_append_lpc_int(message_seq, frame)) {
      return false;
    }
    frame->push_back('"');
  }
  if (!message_template.has_correlation_id) {
    frame->append(",\"correlation_id\":\"txn_");
    if (!gateway_append_lpc_int(message_seq, frame)) {
      return false;
    }
    frame->push_back('"');
  }
  frame->append(",\"timestamp\":");
  if (!gateway_append_lpc_int(sent_at, frame)) {
    return false;
  }
  frame->append(",\"meta\":{\"server_seq\":");
  if (!gateway_append_lpc_int(server_seq, frame)) {
    return false;
  }
  frame->append(",\"stream\":\"message\",\"epoch\":");
  if (!gateway_append_lpc_int(epoch, frame)) {
    return false;
  }
  frame->append(",\"reliability\":");
  frame->append(message_template.reliability_json);
  frame->append(",\"priority\":");
  frame->append(message_template.priority_json);
  frame->append(",\"sent_at\":");
  if (!gateway_append_lpc_int(sent_at, frame)) {
    return false;
  }
  if (!message_template.collapse_key_json.empty()) {
    frame->append(",\"collapse_key\":");
    frame->append(message_template.collapse_key_json);
  }
  frame->append(",\"ttl_ms\":");
  if (!gateway_append_lpc_int(message_template.ttl_ms, frame)) {
    return false;
  }
  frame->append("}}");
  return true;
}

bool gateway_build_preencoded_message_event_batch_frame_impl(
    const std::vector<std::string_view> &stable_children_json,
    const std::vector<const GatewayMessageEventTemplate *> *validated_templates,
    const std::vector<std::string_view> &scope_types, std::string_view scope_id,
    const std::vector<LPC_INT> &message_seqs,
    const std::vector<LPC_INT> &server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &sent_ats, LPC_INT slot_server_seq,
    LPC_INT slot_epoch, LPC_INT slot_sent_at, std::string *frame) {
  const auto count = validated_templates
      ? validated_templates->size()
      : stable_children_json.size();

  if (!frame || count == 0 || scope_types.size() != count || scope_id.empty() ||
      (validated_templates && stable_children_json.size() != 0) ||
      message_seqs.size() != count || server_seqs.size() != count ||
      message_epochs.size() != count || sent_ats.size() != count ||
      slot_server_seq <= 0 || slot_epoch < 0 || slot_sent_at <= 0) {
    return false;
  }

  try {
    frame->clear();
    frame->reserve(64 + count * 384);
    if (count == 1) {
      frame->append("\x1bXKMSGE");
    } else {
      frame->append("\x1bXKBACH{\"messages\":[");
    }

    for (size_t index = 0; index < count; ++index) {
      GatewayMessageEventTemplate uncached;
      const auto message_seq = message_seqs[index];
      const auto server_seq = server_seqs[index];
      const auto epoch = message_epochs[index];
      const auto sent_at = sent_ats[index];

      if (scope_types[index].empty() || message_seq <= 0 || server_seq <= 0 ||
          epoch < 0 || sent_at <= 0) {
        return false;
      }
      const auto *message_template = validated_templates
          ? (*validated_templates)[index]
          : gateway_resolve_message_event_template(
                stable_children_json[index], &uncached);
      if (!message_template) {
        frame->clear();
        return false;
      }
      if (count > 1) {
        if (index > 0) {
          frame->push_back(',');
        }
        frame->append("{\"type\":\"MSGE\",\"payload\":");
      }
      if (!gateway_append_message_event_template(
              *message_template, scope_types[index], scope_id, message_seq,
              count == 1 ? slot_server_seq : server_seq, epoch, sent_at,
              frame)) {
        frame->clear();
        return false;
      }
      if (count > 1) {
        frame->push_back('}');
      }
    }

    if (count > 1) {
      frame->append("],\"meta\":{\"server_seq\":");
      if (!gateway_append_lpc_int(slot_server_seq, frame)) {
        frame->clear();
        return false;
      }
      frame->append(",\"stream\":\"system\",\"epoch\":");
      if (!gateway_append_lpc_int(slot_epoch, frame)) {
        frame->clear();
        return false;
      }
      frame->append(",\"reliability\":\"important\",\"priority\":\"normal\","
                    "\"sent_at\":");
      if (!gateway_append_lpc_int(slot_sent_at, frame)) {
        frame->clear();
        return false;
      }
      frame->append("}}");
    }
    frame->append("\x1b\n");
    return true;
  } catch (const std::exception &) {
    frame->clear();
    return false;
  }
}

bool gateway_build_preencoded_message_event_batch_frame(
    const std::vector<std::string_view> &stable_children_json,
    const std::vector<std::string_view> &scope_types, std::string_view scope_id,
    const std::vector<LPC_INT> &message_seqs,
    const std::vector<LPC_INT> &server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &sent_ats, LPC_INT slot_server_seq,
    LPC_INT slot_epoch, LPC_INT slot_sent_at, std::string *frame) {
  return gateway_build_preencoded_message_event_batch_frame_impl(
      stable_children_json, nullptr, scope_types, scope_id, message_seqs,
      server_seqs, message_epochs, sent_ats, slot_server_seq, slot_epoch,
      slot_sent_at, frame);
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

void gateway_discard_session_output_fifo(GatewaySession *sess) {
  if (!sess) {
    return;
  }
  if (sess->output_fifo.empty()) {
    gateway_remove_session_output_fifo_wire_bytes(
        sess, sess->output_fifo_wire_bytes);
    return;
  }
  uint64_t ready = 0;
  uint64_t pending = 0;
  for (const auto &entry : sess->output_fifo) {
    if (entry.ready) {
      ready++;
    } else {
      pending++;
    }
  }
  g_gateway_runtime_counters.output_fifo_destroyed_ready.fetch_add(
      ready, std::memory_order_relaxed);
  g_gateway_runtime_counters.output_fifo_destroyed_pending.fetch_add(
      pending, std::memory_order_relaxed);
  sess->output_fifo.clear();
  gateway_remove_session_output_fifo_wire_bytes(
      sess, sess->output_fifo_wire_bytes);
}

std::string gateway_future_mapping_state(mapping_t *future) {
  auto *state = future ? find_string_in_mapping(future, "state") : nullptr;
  return state && state->type == T_STRING && state->u.string ? state->u.string : "unknown";
}

bool gateway_future_mapping_flag(mapping_t *future, const char *key) {
  auto *value = future && key ? find_string_in_mapping(future, key) : nullptr;
  return value && value->type == T_NUMBER && value->u.number != 0;
}

void gateway_stop_future_watch_timer() {
  vm_owner_set_future_terminal_notifier(nullptr);
  if (g_gateway_future_watch_timer) {
    evtimer_del(g_gateway_future_watch_timer);
  }
}

bool gateway_has_future_watches() {
  return !g_gateway_session_future_watches.empty() ||
      !g_gateway_future_watches.empty() || !g_gateway_room_output_waves.empty();
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
  uint64_t delay_ms = kGatewayFutureWatchPollIntervalMs;
  if (g_gateway_session_future_watches.empty() &&
      g_gateway_future_watches.empty() &&
      !g_gateway_room_output_retry_schedule.empty()) {
    const auto now_ms = gateway_session_now_ms();
    const auto due_at_ms = g_gateway_room_output_retry_schedule.begin()->first;
    delay_ms = due_at_ms > now_ms ? due_at_ms - now_ms : 1;
  }
  timeval delay{static_cast<time_t>(delay_ms / 1000),
                static_cast<decltype(timeval{}.tv_usec)>((delay_ms % 1000) * 1000)};
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
  auto *cancelled = vm_owner_future_cancel_queued_task(future_id, reason);
  free_mapping(cancelled);
  auto *consumed = vm_owner_future_take(future_id);
  free_mapping(consumed);
}

void gateway_cancel_session_future_watches(const std::string &session_id, GatewaySession *sess,
                                           const char *reason, bool release_reservations) {
  gateway_cancel_room_output_wave_session_items(
      session_id, sess, reason, release_reservations);

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
    gateway_finalize_cancelled_session_future_watch(
        watch, reason, release_reservations);
    g_gateway_runtime_counters.future_watches_cancelled.fetch_add(1, std::memory_order_relaxed);
  }
  if (g_gateway_session_future_watches.empty()) {
    g_gateway_future_watch_queue.clear();
    g_gateway_future_watch_queue_positions.clear();
    if (!gateway_has_future_watches()) {
      gateway_stop_future_watch_timer();
    }
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

bool gateway_dispatch_future_watch_cancelled_callback(
    object_t *ob, uint64_t reservation_id, uint64_t future_id,
    const char *reason) {
  if (!gateway_object_valid(ob) ||
      !function_exists("gateway_owner_future_cancelled", ob, 0)) {
    return false;
  }

  bool callback_ok = false;
  save_command_giver(ob);
  {
    VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob),
                             vm_owner_epoch(ob));
    VMCurrentInteractiveScope interactive_scope(vm_context(), ob);
    GatewayControlledLpcScope controlled_scope;
    set_eval(max_eval_cost);
    push_number(static_cast<LPC_INT>(reservation_id));
    push_number(static_cast<LPC_INT>(future_id));
    copy_and_push_string(reason && reason[0] ? reason
                                             : "gateway owner future cancelled");
    auto *ret = safe_apply("gateway_owner_future_cancelled", ob, 3,
                           ORIGIN_DRIVER);
    callback_ok = ret && ret->type == T_NUMBER && ret->u.number != 0;
  }
  restore_command_giver();
  return callback_ok;
}

bool gateway_dispatch_future_output_notification(
    object_t *ob, uint64_t reservation_id, const char *state,
    LPC_INT event_count = 0, LPC_INT slot_server_seq = 0) {
  if (!gateway_object_valid(ob)) {
    return false;
  }
  if (event_count > 0 && event_count <= kGatewayOwnerRoomOutputMaxEvents &&
      slot_server_seq > 0 &&
      function_exists("gateway_owner_room_output_completed", ob, 0)) {
    bool callback_ok = false;
    save_command_giver(ob);
    {
      VMOwnerScope owner_scope(vm_context(), vm_owner_id(ob), vm_owner_epoch(ob));
      VMCurrentInteractiveScope interactive_scope(vm_context(), ob);
      GatewayControlledLpcScope controlled_scope;
      set_eval(max_eval_cost);
      push_number(static_cast<LPC_INT>(reservation_id));
      copy_and_push_string(state && state[0] ? state : "released");
      push_number(event_count);
      push_number(slot_server_seq);
      auto *ret = safe_apply("gateway_owner_room_output_completed", ob, 4,
                             ORIGIN_DRIVER);
      callback_ok = ret && ret->type == T_NUMBER && ret->u.number != 0;
    }
    restore_command_giver();
    return callback_ok;
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

bool gateway_session_pending_reservation_has_ready_successor(
    const GatewaySession *sess, uint64_t reservation_id) {
  if (!sess || reservation_id == 0) {
    return false;
  }
  bool found_pending_reservation = false;
  for (const auto &entry : sess->output_fifo) {
    if (!found_pending_reservation) {
      if (entry.reservation_id != reservation_id) {
        continue;
      }
      if (entry.ready) {
        return false;
      }
      found_pending_reservation = true;
      continue;
    }
    if (entry.ready) {
      return true;
    }
  }
  return false;
}

int gateway_get_session_count() { return static_cast<int>(g_gateway_sessions.size()); }

long gateway_room_output_projection_pending_count() {
  size_t pending = 0;
  for (const auto &[wave_id, wave] : g_gateway_room_output_waves) {
    (void)wave_id;
    for (const auto &item : wave.items) {
      if (item.terminal) {
        continue;
      }
      if (pending == static_cast<size_t>(std::numeric_limits<long>::max())) {
        return std::numeric_limits<long>::max();
      }
      ++pending;
    }
  }
  return static_cast<long>(pending);
}

long gateway_room_output_projection_wave_count() {
  return g_gateway_room_output_waves.size() >
          static_cast<size_t>(std::numeric_limits<long>::max())
      ? std::numeric_limits<long>::max()
      : static_cast<long>(g_gateway_room_output_waves.size());
}

long gateway_room_output_projection_reservation_count() {
  size_t reservations = 0;
  for (const auto &[wave_id, wave] : g_gateway_room_output_waves) {
    (void)wave_id;
    for (const auto &item : wave.items) {
      if (item.reservation_closed) {
        continue;
      }
      if (reservations ==
          static_cast<size_t>(std::numeric_limits<long>::max())) {
        return std::numeric_limits<long>::max();
      }
      ++reservations;
    }
  }
  return static_cast<long>(reservations);
}

long gateway_room_output_projection_retry_count() {
  return g_gateway_room_output_retry_schedule.size() >
          static_cast<size_t>(std::numeric_limits<long>::max())
      ? std::numeric_limits<long>::max()
      : static_cast<long>(g_gateway_room_output_retry_schedule.size());
}

GatewaySession *gateway_find_session(const char *session_id) {
  if (!gateway_session_id_c_string_is_valid(session_id)) {
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

bool gateway_register_session_future_watch_state(
    GatewaySessionFutureWatch watch) {
  const auto reservation_id = watch.reservation_id;
  const auto future_id = watch.future_id;
  bool watch_inserted = false;
  bool future_inserted = false;
  bool queue_inserted = false;
  try {
    watch_inserted =
        g_gateway_session_future_watches
            .emplace(reservation_id, std::move(watch))
            .second;
    if (!watch_inserted) {
      return false;
    }
    future_inserted =
        g_gateway_future_to_reservation.emplace(future_id, reservation_id)
            .second;
    if (!future_inserted) {
      g_gateway_session_future_watches.erase(reservation_id);
      return false;
    }
    g_gateway_future_watch_queue.push_back(reservation_id);
    queue_inserted = true;
    const auto queue_position = std::prev(g_gateway_future_watch_queue.end());
    if (!g_gateway_future_watch_queue_positions
             .emplace(reservation_id, queue_position)
             .second) {
      g_gateway_future_watch_queue.erase(queue_position);
      g_gateway_future_to_reservation.erase(future_id);
      g_gateway_session_future_watches.erase(reservation_id);
      return false;
    }
  } catch (const std::exception &) {
    if (queue_inserted) {
      g_gateway_future_watch_queue.pop_back();
    }
    if (future_inserted) {
      g_gateway_future_to_reservation.erase(future_id);
    }
    if (watch_inserted) {
      g_gateway_session_future_watches.erase(reservation_id);
    }
    return false;
  }
  return true;
}

bool gateway_requeue_session_future_watch(uint64_t reservation_id) {
  try {
    g_gateway_future_watch_queue.push_back(reservation_id);
  } catch (const std::exception &) {
    return false;
  }
  const auto queue_position = std::prev(g_gateway_future_watch_queue.end());
  try {
    if (g_gateway_future_watch_queue_positions
            .emplace(reservation_id, queue_position)
            .second) {
      return true;
    }
  } catch (const std::exception &) {
  }
  g_gateway_future_watch_queue.erase(queue_position);
  return false;
}

bool gateway_register_generic_future_watch_state(GatewayFutureWatch watch) {
  const auto future_id = watch.future_id;
  try {
    if (!g_gateway_future_watches.emplace(future_id, std::move(watch)).second) {
      return false;
    }
    try {
      g_gateway_generic_future_watch_queue.push_back(future_id);
    } catch (const std::exception &) {
      g_gateway_future_watches.erase(future_id);
      return false;
    }
  } catch (const std::exception &) {
    return false;
  }
  return true;
}

bool gateway_requeue_generic_future_watch(uint64_t future_id) {
  try {
    g_gateway_generic_future_watch_queue.push_back(future_id);
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

int gateway_watch_session_future_for_object_internal(
    object_t *ob, uint64_t reservation_id, uint64_t future_id, int timeout_ms,
    GatewayFutureOutputKind output_kind, LPC_INT event_count = 0,
    LPC_INT slot_server_seq = 0, uint64_t projection_generation = 0,
    uint64_t room_output_wave_id = 0, size_t room_output_wave_index = 0) {
  auto register_started_ns = gateway_session_now_ns();
  if (!vm_context_is_main_thread() || reservation_id == 0 || future_id == 0 || timeout_ms <= 0 ||
      g_gateway_session_future_watches.size() >= kGatewayMaxFutureWatches) {
    g_gateway_runtime_counters.future_watches_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  auto *sess = gateway_find_session_by_object(ob);
  if (!sess || !gateway_session_has_pending_reservation(sess, reservation_id) ||
      (output_kind == GatewayFutureOutputKind::kMapping &&
       (!function_exists("gateway_owner_future_completed", ob, 0) ||
        !function_exists("gateway_owner_future_cancelled", ob, 0))) ||
      (output_kind == GatewayFutureOutputKind::kValidatedWire &&
       (event_count <= 0 || event_count > kGatewayOwnerRoomOutputMaxEvents ||
        slot_server_seq <= 0 || room_output_wave_id == 0 ||
        !gateway_pending_message_event_projection_matches(
            sess, reservation_id, projection_generation, true))) ||
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
  auto timeout = static_cast<uint64_t>(timeout_ms);
  auto deadline_ms = timeout > std::numeric_limits<uint64_t>::max() - now_ms
                         ? std::numeric_limits<uint64_t>::max()
                         : now_ms + timeout;
  try {
    GatewaySessionFutureWatch watch;
    watch.session_id = sess->session_id;
    watch.user_ob_name = sess->user_ob_name;
    watch.user_ob_load_time = sess->user_ob_load_time;
    watch.owner_id = vm_owner_id(ob);
    watch.owner_epoch = vm_owner_epoch(ob);
    watch.reservation_id = reservation_id;
    watch.future_id = future_id;
    watch.deadline_ms = deadline_ms;
    watch.registered_at_ns = register_started_ns;
    watch.event_count = event_count;
    watch.slot_server_seq = slot_server_seq;
    watch.projection_generation = projection_generation;
    watch.room_output_wave_id = room_output_wave_id;
    watch.room_output_wave_index = room_output_wave_index;
    watch.output_kind = output_kind;
    if (!gateway_register_session_future_watch_state(std::move(watch))) {
      g_gateway_runtime_counters.future_watches_rejected.fetch_add(
          1, std::memory_order_relaxed);
      return 0;
    }
  } catch (const std::exception &) {
    g_gateway_runtime_counters.future_watches_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return 0;
  }
  g_gateway_runtime_counters.future_watches_registered.fetch_add(1, std::memory_order_relaxed);
  auto completion_event_ready = gateway_enable_future_watch_completion_event();
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
                                                          timeout_ms,
                                                          GatewayFutureOutputKind::kMapping);
}

int gateway_watch_session_future_output_for_object(object_t *ob, uint64_t reservation_id,
                                                   uint64_t future_id, int timeout_ms) {
  return gateway_watch_session_future_for_object_internal(ob, reservation_id, future_id,
                                                          timeout_ms,
                                                          GatewayFutureOutputKind::kProtocolPayload);
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
  for (size_t index = 0;
       index < poll_count && !g_gateway_future_watch_queue.empty(); index++) {
    auto reservation_id = g_gateway_future_watch_queue.front();
    g_gateway_future_watch_queue.pop_front();
    g_gateway_future_watch_queue_positions.erase(reservation_id);
    auto watch_it = g_gateway_session_future_watches.find(reservation_id);
    if (watch_it == g_gateway_session_future_watches.end()) {
      continue;
    }
    g_gateway_runtime_counters.future_watch_poll_items.fetch_add(1, std::memory_order_relaxed);
    auto watch = watch_it->second;
    if (watch.output_kind == GatewayFutureOutputKind::kValidatedWire &&
        watch.room_output_wave_id != 0) {
      processed += gateway_process_room_output_wave_watch(watch, now_ms);
      continue;
    }
    auto completion_cpu_started_ns = get_current_thread_cpu_time_ns();
    auto *sess = gateway_find_session(watch.session_id.c_str());
    auto *ob = gateway_resolve_session_object(sess);
    auto session_current =
        sess && ob && sess->session_id == watch.session_id &&
        sess->user_ob_name == watch.user_ob_name &&
        sess->user_ob_load_time == watch.user_ob_load_time &&
        watch.owner_id == vm_owner_id(ob) &&
        vm_owner_epoch_matches(ob, watch.owner_id.c_str(), watch.owner_epoch);
    if (!session_current) {
      g_gateway_future_to_reservation.erase(watch.future_id);
      g_gateway_session_future_watches.erase(watch_it);
      gateway_consume_cancelled_future(watch.future_id, "gateway session stale");
      gateway_finalize_cancelled_session_future_watch(
          watch, "gateway session stale", true);
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(1, std::memory_order_relaxed);
      gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
      processed++;
      continue;
    }
    const auto reservation_pending =
        gateway_session_has_pending_reservation(sess, watch.reservation_id);
    const auto projection_current =
        watch.output_kind != GatewayFutureOutputKind::kValidatedWire ||
        gateway_pending_message_event_projection_matches(
            sess, watch.reservation_id, watch.projection_generation, true);
    if (!reservation_pending || !projection_current) {
      g_gateway_future_to_reservation.erase(watch.future_id);
      g_gateway_session_future_watches.erase(watch_it);
      gateway_consume_cancelled_future(watch.future_id,
                                       "gateway reservation stale");
      gateway_finalize_cancelled_session_future_watch(
          watch, "gateway reservation stale", reservation_pending);
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
      gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
      processed++;
      continue;
    }

    auto future_state = vm_owner_future_state(watch.future_id);
    if (future_state == VM_OWNER_FUTURE_PENDING && now_ms < watch.deadline_ms) {
      if (!gateway_requeue_session_future_watch(reservation_id)) {
        g_gateway_future_to_reservation.erase(watch.future_id);
        g_gateway_session_future_watches.erase(watch_it);
        gateway_consume_cancelled_future(
            watch.future_id, "gateway future watch requeue failed");
        gateway_finalize_cancelled_session_future_watch(
            watch, "gateway future watch requeue failed", true);
        g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
            1, std::memory_order_relaxed);
        gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
        ++processed;
      }
      continue;
    }

    mapping_t *future = nullptr;
    VMOwnerFutureStringTakeResult output_future;
    uint64_t terminal_at_ns = 0;
    uint64_t take_started_ns = 0;
    uint64_t take_finished_ns = 0;
    if (future_state == VM_OWNER_FUTURE_PENDING) {
      auto *timed_out = vm_owner_future_timeout(watch.future_id, "gateway owner future timed out");
      const auto terminal_changed =
          gateway_future_mapping_flag(timed_out, "terminal_changed");
      free_mapping(timed_out);
      take_started_ns = gateway_session_now_ns();
      if (watch.output_kind != GatewayFutureOutputKind::kMapping) {
        output_future = vm_owner_future_take_string(watch.future_id);
        terminal_at_ns = output_future.terminal_at_ns;
      } else {
        future = vm_owner_future_take(watch.future_id, &terminal_at_ns);
      }
      take_finished_ns = gateway_session_now_ns();
      if (terminal_changed) {
        g_gateway_runtime_counters.future_watches_timed_out.fetch_add(
            1, std::memory_order_relaxed);
      }
    } else if (future_state == VM_OWNER_FUTURE_COMPLETED ||
               future_state == VM_OWNER_FUTURE_FAILED) {
      take_started_ns = gateway_session_now_ns();
      if (watch.output_kind != GatewayFutureOutputKind::kMapping) {
        output_future = vm_owner_future_take_string(watch.future_id);
        terminal_at_ns = output_future.terminal_at_ns;
      } else {
        future = vm_owner_future_take(watch.future_id, &terminal_at_ns);
      }
      take_finished_ns = gateway_session_now_ns();
    } else {
      if (watch.output_kind != GatewayFutureOutputKind::kMapping) {
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
    if (watch.output_kind != GatewayFutureOutputKind::kMapping) {
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
    if (watch.output_kind != GatewayFutureOutputKind::kMapping) {
      const auto publish_started_ns = gateway_session_now_ns();
      bool output_filled = false;
      if (state == "completed") {
        if (watch.output_kind == GatewayFutureOutputKind::kValidatedWire) {
          auto wire_output = GatewayWireOutputFactory::validated_projected_wire(
              sess, std::move(output_future.value));
          output_filled = wire_output &&
              gateway_fill_session_wire_output_with_writer(
                  sess, watch.reservation_id, std::move(*wire_output),
                  gateway_send_raw_to_fd) != 0;
        } else {
          output_filled = gateway_fill_session_output_for_object(
              ob, watch.reservation_id, output_future.value.data(),
              output_future.value.size()) != 0;
        }
        callback_ok = output_filled ||
            gateway_release_session_output_for_object(
                ob, watch.reservation_id) != 0;
      } else {
        callback_ok = gateway_release_session_output_for_object(ob, watch.reservation_id) != 0;
      }
      auto *output_state = output_filled ? "completed" : "released";
      callback_ok = gateway_dispatch_future_output_notification(
                        ob, watch.reservation_id, output_state,
                        watch.event_count, watch.slot_server_seq) &&
                    callback_ok;
      if (watch.output_kind == GatewayFutureOutputKind::kValidatedWire) {
        gateway_session_record_latency(
            g_gateway_runtime_counters.room_output_projection_publish_ns_total,
            g_gateway_runtime_counters.room_output_projection_publish_ns_max,
            g_gateway_runtime_counters.room_output_projection_publish_samples,
            gateway_session_now_ns() - publish_started_ns);
        if (!callback_ok) {
          g_gateway_runtime_counters.room_output_projection_failed.fetch_add(
              1, std::memory_order_relaxed);
        }
      }
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

    if (!callback_ok && watch.output_kind == GatewayFutureOutputKind::kMapping) {
      gateway_finalize_cancelled_session_future_watch(
          watch, "gateway owner future callback failed", true);
    }

    sess = gateway_find_session(watch.session_id.c_str());
    ob = gateway_resolve_session_object(sess);
    session_current =
        sess && ob && sess->session_id == watch.session_id &&
        sess->user_ob_name == watch.user_ob_name &&
        sess->user_ob_load_time == watch.user_ob_load_time &&
        watch.owner_id == vm_owner_id(ob) &&
        vm_owner_epoch_matches(ob, watch.owner_id.c_str(), watch.owner_epoch);
    if (!callback_ok) {
      g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(1, std::memory_order_relaxed);
    }
    if (session_current && gateway_session_has_pending_reservation(sess, watch.reservation_id)) {
      gateway_release_session_output(sess, watch.reservation_id);
    }
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
  }

  gateway_process_room_output_publish_retries(gateway_session_now_ms());

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
  try {
    GatewayFutureWatch watch;
    watch.target_ob_name = ob->obname;
    watch.target_ob_load_time = ob->load_time;
    watch.context_id = context_id;
    watch.future_id = future_id;
    watch.deadline_ms = deadline_ms;
    watch.registered_at_ns = gateway_session_now_ns();
    if (!gateway_register_generic_future_watch_state(std::move(watch))) {
      g_gateway_runtime_counters.generic_future_watches_rejected.fetch_add(
          1, std::memory_order_relaxed);
      return 0;
    }
  } catch (const std::exception &) {
    g_gateway_runtime_counters.generic_future_watches_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return 0;
  }
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
      if (!gateway_requeue_generic_future_watch(future_id)) {
        g_gateway_future_watches.erase(watch_it);
        gateway_consume_cancelled_future(
            future_id, "gateway generic future watch requeue failed");
        g_gateway_runtime_counters.generic_future_watches_cancelled.fetch_add(
            1, std::memory_order_relaxed);
        gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
        ++processed;
      }
      continue;
    }

    mapping_t *future = nullptr;
    if (future_state == VM_OWNER_FUTURE_PENDING) {
      auto *timed_out = vm_owner_future_timeout(future_id, "gateway future watch timed out");
      const auto terminal_changed =
          gateway_future_mapping_flag(timed_out, "terminal_changed");
      free_mapping(timed_out);
      future = vm_owner_future_take(future_id);
      if (terminal_changed) {
        g_gateway_runtime_counters.generic_future_watches_timed_out.fetch_add(
            1, std::memory_order_relaxed);
      }
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

uint64_t gateway_session_fifo_wire_bytes_total() {
  uint64_t total = 0;
  for (const auto &entry : g_gateway_sessions) {
    total += entry.second->output_fifo_wire_bytes;
  }
  return total;
}

uint64_t gateway_session_fifo_wire_bytes_rejected_total() {
  uint64_t total = 0;
  for (const auto &entry : g_gateway_sessions) {
    total += entry.second->output_fifo_wire_bytes_rejected;
  }
  return total;
}

size_t gateway_session_fifo_wire_aggregate_limit() {
  return gateway_write_buffer_limit();
}

size_t gateway_session_fifo_wire_detached_bytes() {
  return g_gateway_detached_output_fifo_wire_bytes;
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
    const auto wire_bytes = entry.wire_bytes.size();
    if (entry.wire_bytes.size() > g_gateway_max_packet_size) {
      gateway_remove_session_output_fifo_wire_bytes(sess, wire_bytes);
      sess->output_fifo.pop_front();
      g_gateway_runtime_counters.output_fifo_oversize_dropped.fetch_add(
          1, std::memory_order_relaxed);
      continue;
    }
    if (!writer(sess->master_fd, entry.wire_bytes.c_str(), entry.wire_bytes.size())) {
      g_gateway_runtime_counters.output_fifo_writer_failures.fetch_add(
          1, std::memory_order_relaxed);
      break;
    }
    gateway_remove_session_output_fifo_wire_bytes(sess, wire_bytes);
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

int gateway_flush_master_output_fifos(int master_fd, size_t budget) {
  if (master_fd < 0 || budget == 0) {
    return 0;
  }
  std::vector<GatewaySession *> sessions;
  sessions.reserve(std::min(budget, g_gateway_sessions.size()));
  for (const auto &entry : g_gateway_sessions) {
    if (entry.second && entry.second->master_fd == master_fd &&
        !entry.second->output_fifo.empty() &&
        entry.second->output_fifo.front().ready) {
      sessions.push_back(entry.second.get());
      if (sessions.size() >= budget) {
        break;
      }
    }
  }
  int flushed = 0;
  for (auto *sess : sessions) {
    flushed += gateway_flush_session_output_fifo(sess);
  }
  return flushed;
}

bool gateway_master_output_pending(int master_fd) {
  if (master_fd < 0) {
    return false;
  }
  for (const auto &entry : g_gateway_sessions) {
    if (entry.second && entry.second->master_fd == master_fd &&
        !entry.second->output_fifo.empty() &&
        entry.second->output_fifo.front().ready) {
      return true;
    }
  }
  return false;
}

namespace {
int gateway_enqueue_session_wire_output(GatewaySession *sess,
                                        GatewayWireOutput wire_output) {
  if (!sess || wire_output.empty() || !wire_output.bound_to(sess)) {
    return 0;
  }
  if (sess->output_fifo.size() >= sess->output_fifo_max_depth) {
    sess->output_fifo_rejected++;
    g_gateway_runtime_counters.output_fifo_rejected.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  const auto wire_bytes = wire_output.size();
  const auto session_capacity =
      gateway_session_output_fifo_session_can_add_wire_bytes(sess, wire_bytes);
  const auto aggregate_capacity =
      gateway_session_output_fifo_aggregate_can_add_wire_bytes(sess,
                                                               wire_bytes);
  if (!session_capacity || !aggregate_capacity) {
    if (!aggregate_capacity) {
      gateway_record_session_output_fifo_aggregate_rejection();
    }
    gateway_record_session_output_fifo_wire_rejection(sess);
    return 0;
  }
  GatewayOutputEntry entry;
  entry.wire_bytes = std::move(wire_output).release();
  sess->output_fifo.push_back(std::move(entry));
  gateway_add_session_output_fifo_wire_bytes(sess, wire_bytes);
  sess->output_fifo_enqueued++;
  g_gateway_runtime_counters.output_fifo_enqueued.fetch_add(1, std::memory_order_relaxed);
  sess->last_active = get_current_time();
  gateway_flush_session_output_fifo(sess);
  return 1;
}
}  // namespace

int gateway_enqueue_session_protocol_output(GatewaySession *sess, const char *data,
                                            size_t len) {
  if (!data) {
    return 0;
  }
  auto wire_output = GatewayWireOutputFactory::protocol_output(
      sess, std::string_view(data, len));
  return wire_output
      ? gateway_enqueue_session_wire_output(sess, std::move(*wire_output))
      : 0;
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

bool gateway_reserve_session_outputs(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &existing_reservation_ids,
    GatewaySessionBatchReservationResult *result) {
  std::unordered_set<GatewaySession *> unique_sessions;
  std::vector<std::pair<GatewaySession *, uint64_t>> created;

  if (!result || sessions.empty() || sessions.size() != existing_reservation_ids.size()) {
    return false;
  }
  result->reservation_ids.clear();
  result->reused.clear();
  result->wave_id = 0;
  result->reservation_ids.reserve(sessions.size());
  result->reused.reserve(sessions.size());
  created.reserve(sessions.size());

  // Validate the complete wave before appending anything. A caller may offer
  // an earlier unresolved reservation, but it is reusable only while it is
  // still the tail; any intervening output forces a new FIFO slot.
  for (size_t index = 0; index < sessions.size(); ++index) {
    auto *sess = sessions[index];
    const auto existing_id = existing_reservation_ids[index];
    if (!sess || !unique_sessions.insert(sess).second) {
      return false;
    }
    const bool can_reuse = existing_id > 0 && !sess->output_fifo.empty() &&
                           sess->output_fifo.back().reservation_id == existing_id &&
                           !sess->output_fifo.back().ready &&
                           (!sess->output_fifo.back().pending_message_batch ||
                            !sess->output_fifo.back()
                                 .pending_message_batch->projection_sealed);
    if (!can_reuse && sess->output_fifo.size() >= sess->output_fifo_max_depth) {
      return false;
    }
  }

  for (size_t index = 0; index < sessions.size(); ++index) {
    auto *sess = sessions[index];
    const auto existing_id = existing_reservation_ids[index];
    const bool can_reuse = existing_id > 0 && !sess->output_fifo.empty() &&
                           sess->output_fifo.back().reservation_id == existing_id &&
                           !sess->output_fifo.back().ready &&
                           (!sess->output_fifo.back().pending_message_batch ||
                            !sess->output_fifo.back()
                                 .pending_message_batch->projection_sealed);
    if (can_reuse) {
      result->reservation_ids.push_back(existing_id);
      result->reused.push_back(true);
      continue;
    }

    const auto reservation_id = gateway_reserve_session_output(sess);
    if (reservation_id == 0) {
      for (auto it = created.rbegin(); it != created.rend(); ++it) {
        gateway_release_session_output_with_writer(
            it->first, it->second,
            [](int, const char *, size_t) -> int { return 0; });
      }
      result->reservation_ids.clear();
      result->reused.clear();
      return false;
    }
    created.emplace_back(sess, reservation_id);
    result->reservation_ids.push_back(reservation_id);
    result->reused.push_back(false);
  }
  return true;
}

namespace {
GatewayOutputEntry *gateway_find_pending_output_entry(GatewaySession *sess,
                                                      uint64_t reservation_id) {
  if (!sess || reservation_id == 0) {
    return nullptr;
  }
  for (auto &entry : sess->output_fifo) {
    if (entry.reservation_id == reservation_id && !entry.ready) {
      return &entry;
    }
  }
  return nullptr;
}

const GatewayOutputEntry *gateway_find_pending_output_entry(
    const GatewaySession *sess, uint64_t reservation_id) {
  if (!sess || reservation_id == 0) {
    return nullptr;
  }
  for (const auto &entry : sess->output_fifo) {
    if (entry.reservation_id == reservation_id && !entry.ready) {
      return &entry;
    }
  }
  return nullptr;
}

bool gateway_pending_message_event_projection_matches(
    const GatewaySession *sess, uint64_t reservation_id, uint64_t generation,
    bool require_sealed) {
  const auto *entry = gateway_find_pending_output_entry(sess, reservation_id);
  const auto *batch = entry && entry->pending_message_batch
      ? entry->pending_message_batch.get()
      : nullptr;
  return generation > 0 && batch && !batch->events.empty() &&
      batch->projection_generation == generation &&
      (!require_sealed || batch->projection_sealed);
}

bool gateway_seal_pending_message_event_projections(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<uint64_t> &generations) {
  const auto count = sessions.size();
  std::vector<GatewayPendingMessageEventBatch *> batches;
  if (count == 0 || reservation_ids.size() != count ||
      generations.size() != count) {
    return false;
  }
  batches.reserve(count);
  for (size_t index = 0; index < count; ++index) {
    auto *entry = gateway_find_pending_output_entry(
        sessions[index], reservation_ids[index]);
    auto *batch = entry && entry->pending_message_batch
        ? entry->pending_message_batch.get()
        : nullptr;
    if (!batch || batch->events.empty() || batch->projection_sealed ||
        generations[index] == 0 ||
        batch->projection_generation != generations[index]) {
      return false;
    }
    batches.push_back(batch);
  }
  for (auto *batch : batches) {
    batch->projection_sealed = true;
  }
  return true;
}
}  // namespace

uint64_t gateway_next_message_event_wave_id() {
  const auto wave_id =
      g_gateway_next_message_event_wave_id.fetch_add(1, std::memory_order_relaxed);
  if (wave_id == 0 ||
      wave_id > static_cast<uint64_t>(std::numeric_limits<LPC_INT>::max())) {
    return 0;
  }
  return wave_id;
}

bool gateway_append_validated_message_event_wave(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<LPC_INT> &slot_server_seqs,
    const std::vector<LPC_INT> &message_server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &message_seqs, const std::string &scope_type,
    LPC_INT sent_at, size_t batch_limit,
    const GatewayMessageEventTemplate &message_template, uint64_t wave_id,
    const std::vector<bool> *reservation_reused, size_t text_length = 0,
    uint64_t appended_at_ns = 0) {
  const auto count = sessions.size();
  std::unordered_set<GatewaySession *> unique_sessions;
  std::vector<GatewayOutputEntry *> entries;
  std::vector<std::unique_ptr<GatewayPendingMessageEventBatch>> new_batches;
  std::vector<uint64_t> next_generations;

  if (count == 0 || reservation_ids.size() != count ||
      slot_server_seqs.size() != count || message_server_seqs.size() != count ||
      message_epochs.size() != count || message_seqs.size() != count ||
      scope_type.empty() || sent_at <= 0 || batch_limit == 0 || wave_id == 0 ||
      (reservation_reused && reservation_reused->size() != count)) {
    return false;
  }

  entries.reserve(count);
  next_generations.reserve(count);
  unique_sessions.reserve(count);
  for (size_t index = 0; index < count; ++index) {
    auto *sess = sessions[index];
    if (!sess || !unique_sessions.insert(sess).second || reservation_ids[index] == 0 ||
        slot_server_seqs[index] <= 0 || message_server_seqs[index] <= 0 ||
        message_epochs[index] < 0 || message_seqs[index] <= 0) {
      return false;
    }
    auto *entry = gateway_find_pending_output_entry(sess, reservation_ids[index]);
    const auto pending_count = entry && entry->pending_message_batch
        ? entry->pending_message_batch->events.size()
        : 0;
    if (!entry || pending_count >= batch_limit ||
        (entry->pending_message_batch &&
         entry->pending_message_batch->projection_sealed)) {
      return false;
    }
    if (entry->pending_message_batch &&
        (entry->pending_message_batch->slot_server_seq <= 0 ||
         entry->pending_message_batch->slot_sent_at <= 0 ||
         entry->pending_message_batch->projection_generation ==
             std::numeric_limits<uint64_t>::max() ||
         text_length > std::numeric_limits<size_t>::max() -
                           entry->pending_message_batch->text_length_total)) {
      return false;
    }
    entries.push_back(entry);
    next_generations.push_back(entry->pending_message_batch
                                   ? entry->pending_message_batch
                                             ->projection_generation +
                                         1
                                   : 1);
  }

  std::shared_ptr<const GatewayPreencodedMessageEventWave> wave;
  try {
    new_batches.resize(count);
    auto mutable_wave = std::make_shared<GatewayPreencodedMessageEventWave>();
    mutable_wave->scope_type = scope_type;
    if (!gateway_encode_inner_json_string_for_outer(
            scope_type, &mutable_wave->outer_escaped_scope_type_json)) {
      return false;
    }
    auto &stored_template = mutable_wave->message_template;
    stored_template.stable_members = message_template.stable_members;
    stored_template.reliability_json = message_template.reliability_json;
    stored_template.priority_json = message_template.priority_json;
    stored_template.collapse_key_json = message_template.collapse_key_json;
    stored_template.outer_escaped_stable_members =
        message_template.outer_escaped_stable_members;
    stored_template.outer_escaped_reliability_json =
        message_template.outer_escaped_reliability_json;
    stored_template.outer_escaped_priority_json =
        message_template.outer_escaped_priority_json;
    stored_template.outer_escaped_collapse_key_json =
        message_template.outer_escaped_collapse_key_json;
    stored_template.ttl_ms = message_template.ttl_ms;
    stored_template.has_id = message_template.has_id;
    stored_template.has_scope = message_template.has_scope;
    stored_template.has_causation_id = message_template.has_causation_id;
    stored_template.has_correlation_id = message_template.has_correlation_id;
    mutable_wave->wave_id = wave_id;
    mutable_wave->sent_at = sent_at;
    wave = std::move(mutable_wave);
    for (size_t index = 0; index < count; ++index) {
      auto *entry = entries[index];
      if (!entry->pending_message_batch) {
        new_batches[index] = std::make_unique<GatewayPendingMessageEventBatch>();
        new_batches[index]->events.reserve(1);
      } else {
        entry->pending_message_batch->events.reserve(
            entry->pending_message_batch->events.size() + 1);
      }
    }
  } catch (const std::bad_alloc &) {
    return false;
  }

  for (size_t index = 0; index < count; ++index) {
    auto *entry = entries[index];
    if (!entry->pending_message_batch) {
      entry->pending_message_batch = std::move(new_batches[index]);
      entry->pending_message_batch->slot_server_seq = slot_server_seqs[index];
      entry->pending_message_batch->slot_sent_at = sent_at;
      entry->pending_message_batch->created_at_ns = appended_at_ns;
    }
    const auto reservation_origin = !reservation_reused
        ? GatewayMessageEventReservationOrigin::kUnspecified
        : (*reservation_reused)[index]
            ? GatewayMessageEventReservationOrigin::kReused
            : GatewayMessageEventReservationOrigin::kCreated;
    entry->pending_message_batch->events.push_back(
        {wave, message_seqs[index], message_server_seqs[index],
         message_epochs[index], text_length, appended_at_ns,
         reservation_origin});
    entry->pending_message_batch->text_length_total += text_length;
    if (appended_at_ns > 0) {
      entry->pending_message_batch->last_append_at_ns = appended_at_ns;
    }
    entry->pending_message_batch->projection_generation =
        next_generations[index];
  }
  return true;
}

bool gateway_append_preencoded_message_event_wave(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<LPC_INT> &slot_server_seqs,
    const std::vector<LPC_INT> &message_server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &message_seqs, const std::string &stable_json,
    const std::string &scope_type, LPC_INT sent_at, size_t batch_limit) {
  GatewayMessageEventTemplate uncached;
  const auto *message_template =
      gateway_resolve_message_event_template(stable_json, &uncached);
  const auto wave_id = gateway_next_message_event_wave_id();
  return message_template && wave_id > 0 &&
      gateway_append_validated_message_event_wave(
          sessions, reservation_ids, slot_server_seqs, message_server_seqs,
          message_epochs, message_seqs, scope_type, sent_at, batch_limit,
          *message_template, wave_id, nullptr);
}

bool gateway_reserve_and_append_preencoded_message_event_wave(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &existing_reservation_ids,
    LPC_INT first_server_seq,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &message_seqs, const std::string &stable_json,
    const std::string &scope_type, LPC_INT sent_at, size_t batch_limit,
    GatewaySessionBatchReservationResult *result) {
  if (!result) {
    return false;
  }
  result->reservation_ids.clear();
  result->reused.clear();
  result->wave_id = 0;

  const auto count = sessions.size();
  const auto max_seq = std::numeric_limits<LPC_INT>::max();
  if (first_server_seq <= 0 || count == 0 ||
      count > static_cast<size_t>((max_seq - first_server_seq + 1) / 2)) {
    return false;
  }

  std::vector<LPC_INT> slot_server_seqs;
  std::vector<LPC_INT> message_server_seqs;
  try {
    slot_server_seqs.reserve(count);
    message_server_seqs.reserve(count);
    for (size_t index = 0; index < count; ++index) {
      const auto slot_server_seq =
          first_server_seq + static_cast<LPC_INT>(index * 2);
      slot_server_seqs.push_back(slot_server_seq);
      message_server_seqs.push_back(slot_server_seq + 1);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }

  GatewayMessageEventTemplate uncached;
  const auto *message_template =
      gateway_resolve_message_event_template(stable_json, &uncached);
  if (!message_template ||
      !gateway_reserve_session_outputs(sessions, existing_reservation_ids,
                                       result)) {
    return false;
  }

  result->wave_id = gateway_next_message_event_wave_id();
  if (result->wave_id > 0 &&
      gateway_append_validated_message_event_wave(
          sessions, result->reservation_ids, slot_server_seqs,
          message_server_seqs, message_epochs, message_seqs, scope_type,
          sent_at, batch_limit, *message_template,
          result->wave_id, &result->reused)) {
    return true;
  }

  for (size_t index = 0; index < sessions.size(); ++index) {
    if (!result->reused[index]) {
      gateway_release_session_output_with_writer(
          sessions[index], result->reservation_ids[index],
          [](int, const char *, size_t) -> int { return 0; });
    }
  }
  result->reservation_ids.clear();
  result->reused.clear();
  result->wave_id = 0;
  return false;
}

bool gateway_reserve_and_append_compact_preencoded_message_event_wave(
    const std::vector<GatewaySession *> &sessions, LPC_INT first_server_seq,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &message_seqs, const std::string &stable_json,
    const std::string &scope_type, LPC_INT sent_at, size_t batch_limit,
    size_t text_length, GatewaySessionCompactMessageEventWaveResult *result) {
  std::unordered_set<GatewaySession *> unique_sessions;
  std::vector<uint64_t> reservation_ids;
  std::vector<bool> reused;
  std::vector<std::pair<GatewaySession *, uint64_t>> created;
  std::vector<LPC_INT> slot_server_seqs;
  std::vector<LPC_INT> message_server_seqs;
  GatewayMessageEventTemplate uncached;
  const auto count = sessions.size();
  const auto max_seq = std::numeric_limits<LPC_INT>::max();

  if (!result) {
    return false;
  }
  *result = GatewaySessionCompactMessageEventWaveResult{};
  if (count == 0 || message_epochs.size() != count ||
      message_seqs.size() != count || stable_json.empty() ||
      scope_type.empty() || sent_at <= 0 || batch_limit == 0 ||
      text_length == 0 || first_server_seq <= 0 ||
      count > static_cast<size_t>((max_seq - first_server_seq + 1) / 2)) {
    return false;
  }
  const auto *message_template =
      gateway_resolve_message_event_template(stable_json, &uncached);
  if (!message_template) {
    return false;
  }

  try {
    unique_sessions.reserve(count);
    reservation_ids.reserve(count);
    reused.reserve(count);
    created.reserve(count);
    slot_server_seqs.reserve(count);
    message_server_seqs.reserve(count);
    result->created_indices.reserve(count);
    result->created_reservation_ids.reserve(count);
    result->created_slot_server_seqs.reserve(count);
    result->full_indices.reserve(count);
    for (size_t index = 0; index < count; ++index) {
      auto *sess = sessions[index];
      if (!sess || !unique_sessions.insert(sess).second ||
          message_epochs[index] < 0 || message_seqs[index] <= 0) {
        return false;
      }
      const auto slot_server_seq =
          first_server_seq + static_cast<LPC_INT>(index * 2);
      slot_server_seqs.push_back(slot_server_seq);
      message_server_seqs.push_back(slot_server_seq + 1);

      auto *tail = sess->output_fifo.empty() ? nullptr : &sess->output_fifo.back();
      auto *batch = tail && !tail->ready && tail->pending_message_batch
          ? tail->pending_message_batch.get()
          : nullptr;
      if (batch && !batch->registered) {
        return false;
      }
      const bool can_reuse = batch && !batch->projection_sealed &&
                             batch->events.size() < batch_limit;
      if (!can_reuse && sess->output_fifo.size() >= sess->output_fifo_max_depth) {
        return false;
      }
      if (can_reuse) {
        reservation_ids.push_back(tail->reservation_id);
        reused.push_back(true);
      } else {
        reservation_ids.push_back(0);
        reused.push_back(false);
      }
    }

    for (size_t index = 0; index < count; ++index) {
      if (reused[index]) {
        continue;
      }
      const auto reservation_id = gateway_reserve_session_output(sessions[index]);
      if (reservation_id == 0) {
        for (auto it = created.rbegin(); it != created.rend(); ++it) {
          gateway_release_session_output_with_writer(
              it->first, it->second,
              [](int, const char *, size_t) -> int { return 0; });
        }
        return false;
      }
      reservation_ids[index] = reservation_id;
      created.emplace_back(sessions[index], reservation_id);
    }
  } catch (const std::bad_alloc &) {
    for (auto it = created.rbegin(); it != created.rend(); ++it) {
      gateway_release_session_output_with_writer(
          it->first, it->second,
          [](int, const char *, size_t) -> int { return 0; });
    }
    return false;
  }

  const auto wave_id = gateway_next_message_event_wave_id();
  const auto appended_at_ns = gateway_session_now_ns();
  if (wave_id == 0 || appended_at_ns == 0 ||
      !gateway_append_validated_message_event_wave(
          sessions, reservation_ids, slot_server_seqs, message_server_seqs,
          message_epochs, message_seqs, scope_type, sent_at, batch_limit,
          *message_template, wave_id, &reused, text_length, appended_at_ns)) {
    for (auto it = created.rbegin(); it != created.rend(); ++it) {
      gateway_release_session_output_with_writer(
          it->first, it->second,
          [](int, const char *, size_t) -> int { return 0; });
    }
    return false;
  }

  try {
    result->wave_id = wave_id;
    for (size_t index = 0; index < count; ++index) {
      const auto *batch = sessions[index]->output_fifo.back().pending_message_batch.get();
      if (reused[index]) {
        result->reused_count++;
      } else {
        result->created_indices.push_back(index);
        result->created_reservation_ids.push_back(reservation_ids[index]);
        result->created_slot_server_seqs.push_back(slot_server_seqs[index]);
      }
      if (batch && batch->events.size() >= batch_limit) {
        result->full_indices.push_back(index);
      }
    }
  } catch (const std::bad_alloc &) {
    gateway_rollback_compact_preencoded_message_event_wave_with_writer(
        sessions, wave_id, [](int, const char *, size_t) -> int { return 0; });
    *result = GatewaySessionCompactMessageEventWaveResult{};
    return false;
  }
  return true;
}

bool gateway_commit_compact_preencoded_message_event_wave(
    const std::vector<GatewaySession *> &sessions, uint64_t wave_id) {
  std::vector<GatewayPendingMessageEventBatch *> created_batches;
  std::unordered_set<GatewaySession *> unique_sessions;
  if (sessions.empty() || wave_id == 0) {
    return false;
  }
  try {
    created_batches.reserve(sessions.size());
    unique_sessions.reserve(sessions.size());
    for (auto *sess : sessions) {
      if (!sess || !unique_sessions.insert(sess).second ||
          sess->output_fifo.empty()) {
        return false;
      }
      auto &entry = sess->output_fifo.back();
      auto *batch = !entry.ready && entry.pending_message_batch
          ? entry.pending_message_batch.get()
          : nullptr;
      if (!batch || batch->events.empty() || !batch->events.back().wave ||
          batch->events.back().wave->wave_id != wave_id) {
        return false;
      }
      const auto origin = batch->events.back().reservation_origin;
      if (origin == GatewayMessageEventReservationOrigin::kCreated) {
        if (batch->registered) {
          return false;
        }
        created_batches.push_back(batch);
      } else if (origin != GatewayMessageEventReservationOrigin::kReused ||
                 !batch->registered) {
        return false;
      }
    }
  } catch (const std::bad_alloc &) {
    return false;
  }
  for (auto *batch : created_batches) {
    batch->registered = true;
  }
  return true;
}

bool gateway_rollback_compact_preencoded_message_event_wave_with_writer(
    const std::vector<GatewaySession *> &sessions, uint64_t wave_id,
    GatewayOutputWriter writer) {
  std::vector<GatewayOutputEntry *> entries;
  std::vector<bool> reused;
  std::unordered_set<GatewaySession *> unique_sessions;
  if (sessions.empty() || wave_id == 0 || !writer) {
    return false;
  }
  try {
    entries.reserve(sessions.size());
    reused.reserve(sessions.size());
    unique_sessions.reserve(sessions.size());
    for (auto *sess : sessions) {
      if (!sess || !unique_sessions.insert(sess).second ||
          sess->output_fifo.empty()) {
        return false;
      }
      auto *entry = &sess->output_fifo.back();
      auto *batch = !entry->ready && entry->pending_message_batch
          ? entry->pending_message_batch.get()
          : nullptr;
      if (!batch || batch->projection_sealed || batch->events.empty() ||
          !batch->events.back().wave ||
          batch->events.back().wave->wave_id != wave_id) {
        return false;
      }
      const auto origin = batch->events.back().reservation_origin;
      if (origin != GatewayMessageEventReservationOrigin::kCreated &&
          origin != GatewayMessageEventReservationOrigin::kReused) {
        return false;
      }
      entries.push_back(entry);
      reused.push_back(origin == GatewayMessageEventReservationOrigin::kReused);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }

  for (size_t index = 0; index < sessions.size(); ++index) {
    auto *batch = entries[index]->pending_message_batch.get();
    if (!reused[index]) {
      if (!gateway_release_session_output_with_writer(
              sessions[index], entries[index]->reservation_id, writer)) {
        return false;
      }
      continue;
    }
    const auto removed_text_length = batch->events.back().text_length;
    batch->events.pop_back();
    batch->text_length_total = removed_text_length <= batch->text_length_total
        ? batch->text_length_total - removed_text_length
        : 0;
    batch->last_append_at_ns = batch->events.empty()
        ? 0
        : batch->events.back().appended_at_ns;
    batch->projection_generation++;
    if (batch->events.empty()) {
      entries[index]->pending_message_batch.reset();
    }
  }
  return true;
}

bool gateway_pending_message_event_batch_status(
    const GatewaySession *sess, uint64_t reservation_id,
    GatewayPendingMessageEventBatchStatus *status) {
  if (!status) {
    return false;
  }
  *status = GatewayPendingMessageEventBatchStatus{};
  const auto *entry = gateway_find_pending_output_entry(sess, reservation_id);
  const auto *batch = entry && entry->pending_message_batch
      ? entry->pending_message_batch.get()
      : nullptr;
  if (!batch || batch->events.empty()) {
    return false;
  }
  status->event_count = batch->events.size();
  status->text_length_total = batch->text_length_total;
  status->created_at_ns = batch->created_at_ns;
  status->last_append_at_ns = batch->last_append_at_ns;
  status->registered = batch->registered;
  return true;
}

bool gateway_rollback_preencoded_message_event_wave_with_writer(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<bool> &reused, uint64_t wave_id,
    GatewayOutputWriter writer) {
  std::unordered_set<GatewaySession *> unique_sessions;
  std::vector<GatewayOutputEntry *> entries;
  const auto count = sessions.size();
  if (count == 0 || reservation_ids.size() != count || reused.size() != count ||
      wave_id == 0 || !writer) {
    return false;
  }
  entries.reserve(count);
  unique_sessions.reserve(count);
  for (size_t index = 0; index < count; ++index) {
    auto *sess = sessions[index];
    if (!sess || !unique_sessions.insert(sess).second) {
      return false;
    }
    auto *entry = gateway_find_pending_output_entry(sess, reservation_ids[index]);
    const auto expected_origin = reused[index]
        ? GatewayMessageEventReservationOrigin::kReused
        : GatewayMessageEventReservationOrigin::kCreated;
    if (!entry || !entry->pending_message_batch ||
        entry->pending_message_batch->projection_sealed ||
        entry->pending_message_batch->events.empty() ||
        !entry->pending_message_batch->events.back().wave ||
        entry->pending_message_batch->events.back().wave->wave_id != wave_id ||
        entry->pending_message_batch->events.back().reservation_origin !=
            expected_origin ||
        (!reused[index] && entry->pending_message_batch->events.size() != 1) ||
        (reused[index] &&
         entry->pending_message_batch->projection_generation ==
             std::numeric_limits<uint64_t>::max())) {
      return false;
    }
    entries.push_back(entry);
  }

  for (size_t index = 0; index < count; ++index) {
    if (!reused[index]) {
      if (!gateway_release_session_output_with_writer(
              sessions[index], reservation_ids[index], writer)) {
        return false;
      }
      continue;
    }
    const auto removed_text_length =
        entries[index]->pending_message_batch->events.back().text_length;
    entries[index]->pending_message_batch->events.pop_back();
    auto *batch = entries[index]->pending_message_batch.get();
    batch->text_length_total = removed_text_length <= batch->text_length_total
        ? batch->text_length_total - removed_text_length
        : 0;
    batch->last_append_at_ns = batch->events.empty()
        ? 0
        : batch->events.back().appended_at_ns;
    entries[index]->pending_message_batch->projection_generation++;
    if (entries[index]->pending_message_batch->events.empty()) {
      entries[index]->pending_message_batch.reset();
    }
  }
  return true;
}

size_t gateway_pending_message_event_count(const GatewaySession *sess,
                                           uint64_t reservation_id) {
  const auto *entry = gateway_find_pending_output_entry(sess, reservation_id);
  return entry && entry->pending_message_batch
      ? entry->pending_message_batch->events.size()
      : 0;
}

bool gateway_snapshot_pending_message_event_batch(
    const GatewaySession *sess, uint64_t reservation_id,
    const std::string &scope_id, LPC_INT slot_epoch,
    GatewayPendingMessageEventProjectionSnapshot *snapshot,
    GatewayPendingMessageEventProjectionColumns *columns) {
  const auto snapshot_started_ns = gateway_session_now_ns();
  const auto *entry = gateway_find_pending_output_entry(sess, reservation_id);
  if (!snapshot || !columns || !sess || sess->session_id.empty() || !entry ||
      !entry->pending_message_batch ||
      entry->pending_message_batch->events.empty() || scope_id.empty() ||
      slot_epoch < 0 ||
      entry->pending_message_batch->projection_generation == 0 ||
      entry->pending_message_batch->slot_server_seq <= 0 ||
      entry->pending_message_batch->slot_sent_at <= 0) {
    return false;
  }

  GatewayPendingMessageEventProjectionSnapshot next_snapshot;
  GatewayPendingMessageEventProjectionColumns next_columns;
  const auto &batch = *entry->pending_message_batch;
  const auto count = batch.events.size();
  std::unordered_map<const GatewayPreencodedMessageEventWave *, size_t>
      wave_indices;
  try {
    next_snapshot.wave_table.reserve(count);
    next_snapshot.event_wave_indices.reserve(count);
    next_columns.message_seqs.reserve(count);
    next_columns.server_seqs.reserve(count);
    next_columns.message_epochs.reserve(count);
    wave_indices.reserve(count);
    for (const auto &event : batch.events) {
      if (!event.wave || event.wave->scope_type.empty() ||
          event.wave->sent_at <= 0 || event.message_seq <= 0 ||
          event.server_seq <= 0 || event.epoch < 0) {
        return false;
      }
      const auto *wave_key = event.wave.get();
      auto [wave_it, inserted] =
          wave_indices.emplace(wave_key, next_snapshot.wave_table.size());
      if (inserted) {
        next_snapshot.wave_table.push_back(event.wave);
      }
      next_snapshot.event_wave_indices.push_back(wave_it->second);
      next_columns.message_seqs.push_back(event.message_seq);
      next_columns.server_seqs.push_back(event.server_seq);
      next_columns.message_epochs.push_back(event.epoch);
    }
    next_columns.session_id = sess->session_id;
    next_columns.scope_id = scope_id;
    next_columns.slot_server_seq = batch.slot_server_seq;
    next_columns.slot_epoch = slot_epoch;
    next_columns.slot_sent_at = batch.slot_sent_at;
    if (batch.text_length_total >
        static_cast<size_t>(std::numeric_limits<LPC_INT>::max())) {
      return false;
    }
    next_snapshot.text_length_total =
        static_cast<LPC_INT>(batch.text_length_total);
    next_snapshot.generation = batch.projection_generation;
  } catch (const std::exception &) {
    return false;
  }

  *snapshot = std::move(next_snapshot);
  *columns = std::move(next_columns);
  gateway_session_record_latency(
      g_gateway_runtime_counters.room_output_projection_snapshot_ns_total,
      g_gateway_runtime_counters.room_output_projection_snapshot_ns_max,
      g_gateway_runtime_counters.room_output_projection_snapshot_samples,
      gateway_session_now_ns() - snapshot_started_ns);
  return true;
}

namespace {
struct GatewayPendingMessageEventProjectionPrepared {
  std::string session_id_json;
  std::string outer_escaped_scope_id_json;
  size_t estimated_wire_size{0};
};

bool gateway_prepare_pending_message_event_projection(
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns,
    GatewayPendingMessageEventProjectionPrepared *prepared) {
  const auto count = snapshot.event_wave_indices.size();
  if (!prepared || count == 0 || snapshot.wave_table.empty() ||
      snapshot.generation == 0 || columns.session_id.empty() ||
      columns.scope_id.empty() || columns.message_seqs.size() != count ||
      columns.server_seqs.size() != count ||
      columns.message_epochs.size() != count ||
      columns.slot_server_seq <= 0 || columns.slot_epoch < 0 ||
      columns.slot_sent_at <= 0) {
    return false;
  }

  GatewayPendingMessageEventProjectionPrepared next;
  try {
    next.session_id_json.reserve(columns.session_id.size() + 2);
    if (!gateway_append_json_string(columns.session_id.data(),
                                    columns.session_id.size(),
                                    &next.session_id_json) ||
        !gateway_encode_inner_json_string_for_outer(
            columns.scope_id, &next.outer_escaped_scope_id_json)) {
      return false;
    }
    // The fixed envelope and batch trailer are smaller than this base. Each
    // event then receives a deliberately conservative 512-byte allowance for
    // literals and all decimal dynamic fields, in addition to the exact
    // escaped stable/scope components below. Therefore an estimate within the
    // configured packet limit proves the final wire also fits without doing
    // the expensive projection on the main thread.
    next.estimated_wire_size = next.session_id_json.size() + 128;
    for (size_t index = 0; index < count; ++index) {
      const auto wave_index = snapshot.event_wave_indices[index];
      if (wave_index >= snapshot.wave_table.size() ||
          !snapshot.wave_table[wave_index] || columns.message_seqs[index] <= 0 ||
          columns.server_seqs[index] <= 0 ||
          columns.message_epochs[index] < 0) {
        return false;
      }
      const auto &wave = *snapshot.wave_table[wave_index];
      const auto &message_template = wave.message_template;
      if (wave.sent_at <= 0 || wave.outer_escaped_scope_type_json.empty() ||
          message_template.outer_escaped_stable_members.empty() ||
          message_template.outer_escaped_reliability_json.empty() ||
          message_template.outer_escaped_priority_json.empty() ||
          (!message_template.collapse_key_json.empty() &&
           message_template.outer_escaped_collapse_key_json.empty())) {
        return false;
      }
      const auto addition =
          message_template.outer_escaped_stable_members.size() +
          message_template.outer_escaped_reliability_json.size() +
          message_template.outer_escaped_priority_json.size() +
          message_template.outer_escaped_collapse_key_json.size() +
          wave.outer_escaped_scope_type_json.size() +
          next.outer_escaped_scope_id_json.size() + 512;
      if (addition > std::numeric_limits<size_t>::max() -
                         next.estimated_wire_size) {
        return false;
      }
      next.estimated_wire_size += addition;
    }
  } catch (const std::exception &) {
    return false;
  }
  *prepared = std::move(next);
  return true;
}

bool gateway_append_outer_escaped_message_event(
    const GatewayPreencodedMessageEventWave &wave,
    std::string_view outer_escaped_scope_id_json, LPC_INT message_seq,
    LPC_INT server_seq, LPC_INT epoch, LPC_INT sent_at, std::string *wire) {
  const auto &message_template = wave.message_template;
  if (!wire || message_template.outer_escaped_stable_members.empty() ||
      wave.outer_escaped_scope_type_json.empty() || message_seq <= 0 ||
      server_seq <= 0 || epoch < 0 || sent_at <= 0) {
    return false;
  }

  wire->push_back('{');
  wire->append(message_template.outer_escaped_stable_members);
  if (!message_template.has_id) {
    wire->append(",\\\"id\\\":\\\"msg_");
    if (!gateway_append_lpc_int(sent_at, wire)) {
      return false;
    }
    wire->push_back('_');
    if (!gateway_append_lpc_int(message_seq, wire)) {
      return false;
    }
    wire->append("\\\"");
  }
  wire->append(",\\\"seq\\\":");
  if (!gateway_append_lpc_int(message_seq, wire)) {
    return false;
  }
  if (!message_template.has_scope) {
    if (outer_escaped_scope_id_json.empty()) {
      return false;
    }
    wire->append(",\\\"scope\\\":{\\\"type\\\":");
    wire->append(wave.outer_escaped_scope_type_json);
    wire->append(",\\\"id\\\":");
    wire->append(outer_escaped_scope_id_json);
    wire->push_back('}');
  }
  if (!message_template.has_causation_id) {
    wire->append(",\\\"causation_id\\\":\\\"cmd_");
    if (!gateway_append_lpc_int(message_seq, wire)) {
      return false;
    }
    wire->append("\\\"");
  }
  if (!message_template.has_correlation_id) {
    wire->append(",\\\"correlation_id\\\":\\\"txn_");
    if (!gateway_append_lpc_int(message_seq, wire)) {
      return false;
    }
    wire->append("\\\"");
  }
  wire->append(",\\\"timestamp\\\":");
  if (!gateway_append_lpc_int(sent_at, wire)) {
    return false;
  }
  wire->append(",\\\"meta\\\":{\\\"server_seq\\\":");
  if (!gateway_append_lpc_int(server_seq, wire)) {
    return false;
  }
  wire->append(",\\\"stream\\\":\\\"message\\\",\\\"epoch\\\":");
  if (!gateway_append_lpc_int(epoch, wire)) {
    return false;
  }
  wire->append(",\\\"reliability\\\":");
  wire->append(message_template.outer_escaped_reliability_json);
  wire->append(",\\\"priority\\\":");
  wire->append(message_template.outer_escaped_priority_json);
  wire->append(",\\\"sent_at\\\":");
  if (!gateway_append_lpc_int(sent_at, wire)) {
    return false;
  }
  if (!message_template.collapse_key_json.empty()) {
    if (message_template.outer_escaped_collapse_key_json.empty()) {
      return false;
    }
    wire->append(",\\\"collapse_key\\\":");
    wire->append(message_template.outer_escaped_collapse_key_json);
  }
  wire->append(",\\\"ttl_ms\\\":");
  if (!gateway_append_lpc_int(message_template.ttl_ms, wire)) {
    return false;
  }
  wire->append("}}");
  return true;
}

bool gateway_encode_pending_message_event_projection_wire(
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns,
    std::string *wire_bytes) {
  const auto count = snapshot.event_wave_indices.size();
  GatewayPendingMessageEventProjectionPrepared prepared;
  if (!wire_bytes || !gateway_prepare_pending_message_event_projection(
                         snapshot, columns, &prepared)) {
    return false;
  }

  try {
    std::string next;
    next.reserve(prepared.estimated_wire_size);
    next.append("{\"cid\":");
    next.append(prepared.session_id_json);
    next.append(",\"data\":\"");
    next.append(count == 1 ? "\\u001bXKMSGE"
                           : "\\u001bXKBACH{\\\"messages\\\":[");
    for (size_t index = 0; index < count; ++index) {
      const auto &wave = *snapshot.wave_table[snapshot.event_wave_indices[index]];
      if (count > 1) {
        if (index > 0) {
          next.push_back(',');
        }
        next.append("{\\\"type\\\":\\\"MSGE\\\",\\\"payload\\\":");
      }
      if (!gateway_append_outer_escaped_message_event(
              wave, prepared.outer_escaped_scope_id_json,
              columns.message_seqs[index],
              count == 1 ? columns.slot_server_seq
                         : columns.server_seqs[index],
              columns.message_epochs[index], wave.sent_at, &next)) {
        return false;
      }
      if (count > 1) {
        next.push_back('}');
      }
    }
    if (count > 1) {
      next.append("],\\\"meta\\\":{\\\"server_seq\\\":");
      if (!gateway_append_lpc_int(columns.slot_server_seq, &next)) {
        return false;
      }
      next.append(",\\\"stream\\\":\\\"system\\\",\\\"epoch\\\":");
      if (!gateway_append_lpc_int(columns.slot_epoch, &next)) {
        return false;
      }
      next.append(
          ",\\\"reliability\\\":\\\"important\\\",\\\"priority\\\":"
          "\\\"normal\\\",\\\"sent_at\\\":");
      if (!gateway_append_lpc_int(columns.slot_sent_at, &next)) {
        return false;
      }
      next.append("}}");
    }
    next.append("\\u001b\\n\",\"type\":\"output\"}");
    *wire_bytes = std::move(next);
  } catch (const std::exception &) {
    wire_bytes->clear();
    return false;
  }
  return !wire_bytes->empty();
}

bool gateway_encode_pending_message_event_projection_inner(
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns,
    std::string *frame) {
  const auto count = snapshot.event_wave_indices.size();
  if (!frame || count == 0 || snapshot.wave_table.empty() ||
      snapshot.generation == 0 ||
      columns.scope_id.empty() || columns.message_seqs.size() != count ||
      columns.server_seqs.size() != count ||
      columns.message_epochs.size() != count ||
      columns.slot_server_seq <= 0 || columns.slot_epoch < 0 ||
      columns.slot_sent_at <= 0) {
    return false;
  }

  std::vector<const GatewayMessageEventTemplate *> templates;
  std::vector<std::string_view> scope_types;
  std::vector<LPC_INT> sent_ats;
  try {
    templates.reserve(count);
    scope_types.reserve(count);
    sent_ats.reserve(count);
    for (const auto wave_index : snapshot.event_wave_indices) {
      if (wave_index >= snapshot.wave_table.size() ||
          !snapshot.wave_table[wave_index]) {
        return false;
      }
      const auto &wave = *snapshot.wave_table[wave_index];
      templates.push_back(&wave.message_template);
      scope_types.emplace_back(wave.scope_type);
      sent_ats.push_back(wave.sent_at);
    }
  } catch (const std::exception &) {
    return false;
  }

  const std::vector<std::string_view> stable_children;
  return gateway_build_preencoded_message_event_batch_frame_impl(
      stable_children, &templates, scope_types, columns.scope_id,
      columns.message_seqs, columns.server_seqs, columns.message_epochs,
      sent_ats, columns.slot_server_seq, columns.slot_epoch,
      columns.slot_sent_at, frame);
}

bool gateway_prevalidate_pending_message_event_projection_work(
    GatewaySession *sess, GatewayPendingMessageEventProjectionWork *work) {
  GatewayPendingMessageEventProjectionPrepared prepared;
  if (!sess || !work ||
      !gateway_prepare_pending_message_event_projection(
          work->snapshot, work->columns, &prepared)) {
    return false;
  }
  if (prepared.estimated_wire_size <= g_gateway_max_packet_size) {
    return true;
  }

  // Near the packet limit, resolve the conservative estimate exactly once.
  // Retain a valid exact wire so neither the worker nor an inline fallback has
  // to repeat this exceptional main-thread projection.
  std::string wire_bytes;
  if (!gateway_encode_pending_message_event_projection_wire(
          work->snapshot, work->columns, &wire_bytes)) {
    return false;
  }
  auto wire_output = GatewayWireOutputFactory::locally_encoded_projected_wire(
      sess, work->columns.session_id, std::move(wire_bytes));
  if (!wire_output) {
    return false;
  }
  work->prevalidated_wire_bytes = std::move(*wire_output).release();
  return true;
}
}  // namespace

bool gateway_encode_pending_message_event_projection(
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns,
    std::string *wire_bytes) {
  return gateway_encode_pending_message_event_projection_wire(snapshot, columns,
                                                              wire_bytes);
}

bool gateway_encode_pending_message_event_projection_inline(
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns,
    std::string *wire_bytes) {
  const auto cpu_started_ns = get_current_thread_cpu_time_ns();
  const auto projected = gateway_encode_pending_message_event_projection(
      snapshot, columns, wire_bytes);
  gateway_session_record_thread_cpu(
      g_gateway_runtime_counters
          .room_output_projection_inline_thread_cpu_ns_total,
      g_gateway_runtime_counters
          .room_output_projection_inline_thread_cpu_ns_max,
      g_gateway_runtime_counters
          .room_output_projection_inline_thread_cpu_samples,
      g_gateway_runtime_counters
          .room_output_projection_inline_thread_cpu_unavailable,
      cpu_started_ns);
  return projected;
}

namespace {
std::optional<GatewayWireOutput>
gateway_encode_pending_message_event_projection_output_inline(
    GatewaySession *sess,
    const GatewayPendingMessageEventProjectionSnapshot &snapshot,
    const GatewayPendingMessageEventProjectionColumns &columns) {
  std::string wire_bytes;
  if (!gateway_encode_pending_message_event_projection_inline(
          snapshot, columns, &wire_bytes)) {
    return std::nullopt;
  }
  return GatewayWireOutputFactory::locally_encoded_projected_wire(
      sess, columns.session_id, std::move(wire_bytes));
}
}  // namespace

bool gateway_build_pending_message_event_batch_frame(
    GatewaySession *sess, uint64_t reservation_id, const std::string &scope_id,
    LPC_INT slot_epoch, std::string *frame, LPC_INT *event_count,
    LPC_INT *slot_server_seq) {
  GatewayPendingMessageEventProjectionSnapshot snapshot;
  GatewayPendingMessageEventProjectionColumns columns;
  if (!frame || !event_count || !slot_server_seq ||
      !gateway_snapshot_pending_message_event_batch(
          sess, reservation_id, scope_id, slot_epoch, &snapshot, &columns)) {
    return false;
  }
  const auto count = snapshot.event_wave_indices.size();
  if (count > static_cast<size_t>(std::numeric_limits<LPC_INT>::max())) {
    return false;
  }
  if (!gateway_encode_pending_message_event_projection_inner(snapshot, columns,
                                                             frame)) {
    return false;
  }
  *event_count = static_cast<LPC_INT>(count);
  *slot_server_seq = columns.slot_server_seq;
  return true;
}

int gateway_fill_pending_message_event_batch_with_writer(
    GatewaySession *sess, uint64_t reservation_id, const std::string &scope_id,
    LPC_INT slot_epoch, GatewayOutputWriter writer) {
  GatewayPendingMessageEventProjectionSnapshot snapshot;
  GatewayPendingMessageEventProjectionColumns columns;
  std::optional<GatewayWireOutput> wire_output;
  try {
    if (!writer || !gateway_snapshot_pending_message_event_batch(
                       sess, reservation_id, scope_id, slot_epoch, &snapshot,
                       &columns)) {
      return 0;
    }
    wire_output = gateway_encode_pending_message_event_projection_output_inline(
        sess, snapshot, columns);
  } catch (const std::exception &) {
    return 0;
  }
  if (!wire_output) {
    return 0;
  }
  const auto already_sealed = gateway_pending_message_event_projection_matches(
      sess, reservation_id, snapshot.generation, true);
  if (already_sealed) {
    const auto watched = g_gateway_session_future_watches.find(reservation_id) !=
        g_gateway_session_future_watches.end();
    const auto owned_by_wave = std::any_of(
        g_gateway_room_output_waves.begin(), g_gateway_room_output_waves.end(),
        [reservation_id](const auto &wave_entry) {
          return std::any_of(
              wave_entry.second.items.begin(), wave_entry.second.items.end(),
              [reservation_id](const GatewayRoomOutputWaveItem &item) {
                return item.watch.reservation_id == reservation_id;
              });
        });
    if (watched || owned_by_wave) {
      return 0;
    }
  } else if (!gateway_seal_pending_message_event_projections(
                 {sess}, {reservation_id}, {snapshot.generation})) {
    return 0;
  }
  return wire_output
      ? gateway_fill_session_wire_output_with_writer(
            sess, reservation_id, std::move(*wire_output), writer)
      : 0;
}

bool gateway_fill_pending_message_event_batches_with_writer(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<std::string> &scope_ids,
    const std::vector<LPC_INT> &slot_epochs, GatewayOutputWriter writer,
    GatewayPendingMessageEventBatchFillResult *result) {
  const auto count = sessions.size();
  std::unordered_set<uint64_t> unique_reservation_ids;
  std::vector<GatewayPendingMessageEventProjectionSnapshot> snapshots;
  std::vector<GatewayPendingMessageEventProjectionColumns> columns;
  std::vector<GatewayWireOutput> wire_outputs;
  std::vector<uint64_t> generations;

  if (!result) {
    return false;
  }
  result->filled.clear();
  result->event_counts.clear();
  result->text_length_totals.clear();
  result->slot_server_seqs.clear();
  if (count == 0 || reservation_ids.size() != count ||
      scope_ids.size() != count || slot_epochs.size() != count || !writer) {
    return false;
  }

  try {
    unique_reservation_ids.reserve(count);
    snapshots.resize(count);
    columns.resize(count);
    wire_outputs.reserve(count);
    generations.reserve(count);
    result->filled.assign(count, false);
    result->event_counts.resize(count);
    result->text_length_totals.resize(count);
    result->slot_server_seqs.resize(count);
    for (size_t index = 0; index < count; ++index) {
      auto *sess = sessions[index];
      std::optional<GatewayWireOutput> wire_output;
      if (!sess || reservation_ids[index] == 0 ||
          !unique_reservation_ids.insert(reservation_ids[index]).second ||
          scope_ids[index].empty() ||
          slot_epochs[index] < 0 ||
          !gateway_snapshot_pending_message_event_batch(
              sess, reservation_ids[index], scope_ids[index], slot_epochs[index],
              &snapshots[index], &columns[index])) {
        result->filled.clear();
        result->event_counts.clear();
        result->text_length_totals.clear();
        result->slot_server_seqs.clear();
        return false;
      }
      result->event_counts[index] = static_cast<LPC_INT>(
          snapshots[index].event_wave_indices.size());
      result->text_length_totals[index] = snapshots[index].text_length_total;
      result->slot_server_seqs[index] = columns[index].slot_server_seq;
      wire_output = gateway_encode_pending_message_event_projection_output_inline(
          sess, snapshots[index], columns[index]);
      if (!wire_output) {
        result->filled.clear();
        result->event_counts.clear();
        result->text_length_totals.clear();
        result->slot_server_seqs.clear();
        return false;
      }
      wire_outputs.push_back(std::move(*wire_output));
      generations.push_back(snapshots[index].generation);
    }
  } catch (const std::exception &) {
    result->filled.clear();
    result->event_counts.clear();
    result->text_length_totals.clear();
    result->slot_server_seqs.clear();
    return false;
  }

  // No recipient may be written until every wire frame is valid and every
  // original FIFO reservation is still pending.
  for (size_t index = 0; index < count; ++index) {
    if (!gateway_session_has_pending_reservation(sessions[index],
                                                 reservation_ids[index])) {
      result->filled.clear();
      result->event_counts.clear();
      result->text_length_totals.clear();
      result->slot_server_seqs.clear();
      return false;
    }
  }
  if (!gateway_seal_pending_message_event_projections(
          sessions, reservation_ids, generations)) {
    result->filled.clear();
    result->event_counts.clear();
    result->text_length_totals.clear();
    result->slot_server_seqs.clear();
    return false;
  }

  if (!gateway_stage_session_wire_outputs(sessions, reservation_ids,
                                          &wire_outputs)) {
    result->filled.clear();
    result->event_counts.clear();
    result->text_length_totals.clear();
    result->slot_server_seqs.clear();
    return false;
  }
  std::fill(result->filled.begin(), result->filled.end(), true);
  for (auto *sess : sessions) {
    gateway_flush_session_output_fifo_with_writer(sess, writer);
  }
  return true;
}

namespace {
std::optional<GatewayWireOutput> gateway_prepare_projection_wire(
    GatewaySession *sess,
    const std::shared_ptr<const GatewayPendingMessageEventProjectionWork> &work) {
  if (!sess || !work) {
    return std::nullopt;
  }
  if (!work->prevalidated_wire_bytes.empty()) {
    return GatewayWireOutputFactory::locally_encoded_projected_wire(
        sess, work->columns.session_id, work->prevalidated_wire_bytes);
  }
  return gateway_encode_pending_message_event_projection_output_inline(
      sess, work->snapshot, work->columns);
}
}  // namespace

bool gateway_submit_pending_message_event_batches_for_objects(
    const std::vector<object_t *> &targets,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<std::string> &scope_ids,
    const std::vector<LPC_INT> &slot_epochs, int timeout_ms,
    GatewayPendingMessageEventBatchOwnerSubmitResult *result) {
  const auto count = targets.size();
  std::vector<GatewaySession *> sessions;
  std::vector<std::shared_ptr<GatewayPendingMessageEventProjectionWork>> works;
  std::vector<std::string> owner_ids;
  std::vector<uint64_t> owner_epochs;
  std::vector<uint64_t> generations;
  std::vector<VMOwnerStringTaskSubmission> submissions;
  std::vector<GatewayWireOutput> inline_wire_outputs;
  std::unordered_set<uint64_t> unique_reservation_ids;

  if (!result) {
    return false;
  }
  *result = {};
  if (!vm_context_is_main_thread() || count == 0 || timeout_ms <= 0 ||
      reservation_ids.size() != count || scope_ids.size() != count ||
      slot_epochs.size() != count) {
    return false;
  }

  try {
    sessions.reserve(count);
    works.reserve(count);
    owner_ids.reserve(count);
    owner_epochs.reserve(count);
    generations.reserve(count);
    submissions.resize(count);
    inline_wire_outputs.reserve(count);
    unique_reservation_ids.reserve(count);
    for (size_t index = 0; index < count; ++index) {
      auto *target = targets[index];
      auto *sess = gateway_find_session_by_object(target);
      auto work = std::make_shared<GatewayPendingMessageEventProjectionWork>();
      if (!gateway_object_valid(target) || !sess ||
          reservation_ids[index] == 0 ||
          !unique_reservation_ids.insert(reservation_ids[index]).second ||
          scope_ids[index].empty() || slot_epochs[index] < 0 ||
          !gateway_snapshot_pending_message_event_batch(
              sess, reservation_ids[index], scope_ids[index],
              slot_epochs[index], &work->snapshot, &work->columns)) {
        return false;
      }
      sessions.push_back(sess);
      works.push_back(std::move(work));
      owner_ids.emplace_back(vm_owner_id(target));
      owner_epochs.push_back(vm_owner_epoch(target));
      generations.push_back(works.back()->snapshot.generation);
    }
    result->submitted.assign(count, false);
    result->filled_inline.assign(count, false);
    result->event_counts.resize(count);
    result->text_length_totals.resize(count);
    result->slot_server_seqs.resize(count);
    result->future_ids.assign(count, 0);
  } catch (const std::exception &) {
    *result = {};
    return false;
  }

  for (size_t index = 0; index < count; ++index) {
    result->event_counts[index] = static_cast<LPC_INT>(
        works[index]->snapshot.event_wave_indices.size());
    result->text_length_totals[index] =
        works[index]->snapshot.text_length_total;
    result->slot_server_seqs[index] =
        works[index]->columns.slot_server_seq;
  }

  // Snapshot every recipient before any owner submit or inline fallback can
  // fill a FIFO slot.
  for (size_t index = 0; index < count; ++index) {
    if (!gateway_prevalidate_pending_message_event_projection_work(
            sessions[index], works[index].get()) ||
        !gateway_session_has_pending_reservation(sessions[index],
                                                 reservation_ids[index]) ||
        owner_ids[index] != vm_owner_id(targets[index]) ||
        !vm_owner_epoch_matches(targets[index], owner_ids[index].c_str(),
                                owner_epochs[index])) {
      *result = {};
      return false;
    }
  }
  if (!gateway_seal_pending_message_event_projections(
          sessions, reservation_ids, generations)) {
    *result = {};
    return false;
  }

  bool owner_batch_ready = true;
  for (size_t index = 0; index < count; ++index) {
    const auto submit_started_ns = gateway_session_now_ns();
    const auto work = works[index];
    submissions[index] = vm_owner_submit_frozen_string_task(
        targets[index], "room_output_projection", "pending-message-event",
        [work](std::string *wire_bytes) {
          const auto worker_started_ns = gateway_session_now_ns();
          const auto worker_cpu_started_ns = get_current_thread_cpu_time_ns();
          const auto projected = wire_bytes &&
              (!work->prevalidated_wire_bytes.empty()
                   ? (*wire_bytes = work->prevalidated_wire_bytes, true)
                   : gateway_encode_pending_message_event_projection(
                         work->snapshot, work->columns, wire_bytes));
          gateway_session_record_thread_cpu(
              g_gateway_runtime_counters
                  .room_output_projection_worker_thread_cpu_ns_total,
              g_gateway_runtime_counters
                  .room_output_projection_worker_thread_cpu_ns_max,
              g_gateway_runtime_counters
                  .room_output_projection_worker_thread_cpu_samples,
              g_gateway_runtime_counters
                  .room_output_projection_worker_thread_cpu_unavailable,
              worker_cpu_started_ns);
          gateway_session_record_latency(
              g_gateway_runtime_counters
                  .room_output_projection_worker_ns_total,
              g_gateway_runtime_counters.room_output_projection_worker_ns_max,
              g_gateway_runtime_counters
                  .room_output_projection_worker_samples,
              gateway_session_now_ns() - worker_started_ns);
          return projected;
        });
    gateway_session_record_latency(
        g_gateway_runtime_counters
            .room_output_projection_submit_watch_ns_total,
        g_gateway_runtime_counters.room_output_projection_submit_watch_ns_max,
        g_gateway_runtime_counters
            .room_output_projection_submit_watch_samples,
        gateway_session_now_ns() - submit_started_ns);
    if (!submissions[index].queued || submissions[index].future_id == 0 ||
        submissions[index].target_owner_epoch != owner_epochs[index]) {
      owner_batch_ready = false;
      break;
    }
  }

  uint64_t room_output_wave_id = 0;
  GatewayRoomOutputWave room_output_wave;
  if (owner_batch_ready) {
    room_output_wave_id = g_gateway_next_room_output_wave_id++;
    if (room_output_wave_id == 0) {
      owner_batch_ready = false;
    } else {
      try {
        room_output_wave.wave_id = room_output_wave_id;
        room_output_wave.items.resize(count);
      } catch (const std::exception &) {
        owner_batch_ready = false;
      }
    }
  }

  size_t registered_count = 0;
  if (owner_batch_ready) {
    for (size_t index = 0; index < count; ++index) {
      if (!gateway_watch_session_future_for_object_internal(
              targets[index], reservation_ids[index],
              submissions[index].future_id, timeout_ms,
              GatewayFutureOutputKind::kValidatedWire,
              result->event_counts[index], result->slot_server_seqs[index],
              generations[index], room_output_wave_id, index)) {
        owner_batch_ready = false;
        break;
      }
      ++registered_count;
      const auto watch_it =
          g_gateway_session_future_watches.find(reservation_ids[index]);
      if (watch_it == g_gateway_session_future_watches.end()) {
        owner_batch_ready = false;
        break;
      }
      room_output_wave.items[index].watch = watch_it->second;
      room_output_wave.items[index].work = works[index];
    }
  }

  if (owner_batch_ready) {
    try {
      owner_batch_ready =
          g_gateway_room_output_waves
              .emplace(room_output_wave_id, std::move(room_output_wave))
              .second;
    } catch (const std::exception &) {
      owner_batch_ready = false;
    }
  }

  if (owner_batch_ready) {
    for (size_t index = 0; index < count; ++index) {
      result->submitted[index] = true;
      result->future_ids[index] = submissions[index].future_id;
    }
    g_gateway_runtime_counters.room_output_projection_submitted.fetch_add(
        count, std::memory_order_relaxed);
    return true;
  }

  for (size_t index = 0; index < registered_count; ++index) {
    auto detached =
        gateway_detach_session_future_watch(reservation_ids[index]);
    if (detached) {
      gateway_consume_cancelled_future(
          detached->future_id, "room output wave watch fallback");
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
    }
  }
  for (size_t index = registered_count; index < submissions.size(); ++index) {
    if (submissions[index].future_id != 0) {
      gateway_consume_cancelled_future(
          submissions[index].future_id, "room output wave submission fallback");
    }
  }
  if (room_output_wave_id != 0) {
    g_gateway_room_output_waves.erase(room_output_wave_id);
  }
  g_gateway_runtime_counters.room_output_projection_inline_fallbacks.fetch_add(
      count, std::memory_order_relaxed);

  bool inline_batch_ready = true;
  for (size_t index = 0; index < count; ++index) {
    if (!gateway_pending_message_event_projection_matches(
            sessions[index], reservation_ids[index], generations[index], true)) {
      inline_batch_ready = false;
      break;
    }
    auto wire_output =
        gateway_prepare_projection_wire(sessions[index], works[index]);
    if (!wire_output) {
      inline_batch_ready = false;
      break;
    }
    inline_wire_outputs.push_back(std::move(*wire_output));
  }
  if (inline_batch_ready) {
    for (size_t index = 0; index < count; ++index) {
      if (!gateway_pending_message_event_projection_matches(
              sessions[index], reservation_ids[index], generations[index],
              true) ||
          !gateway_session_has_pending_reservation(sessions[index],
                                                   reservation_ids[index])) {
        inline_batch_ready = false;
        break;
      }
    }
  }
  if (inline_batch_ready) {
    inline_batch_ready = gateway_stage_session_wire_outputs(
        sessions, reservation_ids, &inline_wire_outputs);
    if (inline_batch_ready) {
      for (size_t index = 0; index < count; ++index) {
        result->filled_inline[index] = true;
      }
    }
  }
  if (inline_batch_ready) {
    for (auto *sess : sessions) {
      gateway_flush_session_output_fifo_with_writer(sess,
                                                    gateway_send_raw_to_fd);
    }
  } else {
    std::fill(result->filled_inline.begin(), result->filled_inline.end(), false);
    g_gateway_runtime_counters.room_output_projection_failed.fetch_add(
        count, std::memory_order_relaxed);
  }
  return true;
}

int gateway_fill_pending_message_event_batch_for_object(
    object_t *ob, uint64_t reservation_id, const char *scope_id,
    size_t scope_id_len, LPC_INT slot_epoch) {
  if (!vm_context_is_main_thread() || !gateway_object_valid(ob) ||
      !scope_id || scope_id_len == 0) {
    return 0;
  }
  auto *sess = gateway_find_session_by_object(ob);
  return gateway_fill_pending_message_event_batch_with_writer(
      sess, reservation_id, std::string(scope_id, scope_id_len), slot_epoch,
      gateway_send_raw_to_fd);
}

namespace {
bool gateway_stage_session_wire_output(GatewaySession *sess,
                                       uint64_t reservation_id,
                                       GatewayWireOutput wire_output) {
  if (!sess || reservation_id == 0 || wire_output.empty() ||
      !wire_output.bound_to(sess)) {
    return false;
  }
  const auto wire_bytes = wire_output.size();
  for (auto it = sess->output_fifo.begin(); it != sess->output_fifo.end(); ++it) {
    auto &entry = *it;
    if (entry.reservation_id != reservation_id || entry.ready) {
      continue;
    }
    const auto session_capacity =
        gateway_session_output_fifo_session_can_add_wire_bytes(sess,
                                                               wire_bytes);
    const auto aggregate_capacity =
        gateway_session_output_fifo_aggregate_can_add_wire_bytes(sess,
                                                                 wire_bytes);
    if (!session_capacity || !aggregate_capacity) {
      if (!aggregate_capacity) {
        gateway_record_session_output_fifo_aggregate_rejection();
      }
      gateway_record_session_output_fifo_wire_rejection(sess);
      return false;
    }
    entry.wire_bytes = std::move(wire_output).release();
    entry.ready = true;
    gateway_add_session_output_fifo_wire_bytes(sess, wire_bytes);
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
    return true;
  }
  g_gateway_runtime_counters.output_fifo_reservation_misses.fetch_add(1, std::memory_order_relaxed);
  return false;
}

bool gateway_stage_session_wire_outputs(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    std::vector<GatewayWireOutput> *wire_outputs) {
  struct PendingStage {
    GatewaySession *session{nullptr};
    GatewayOutputEntry *entry{nullptr};
    uint64_t preceding_count{0};
    size_t wire_bytes{0};
  };
  const auto count = sessions.size();
  std::vector<PendingStage> stages;
  std::unordered_set<uint64_t> unique_reservations;
  std::unordered_map<GatewaySession *, size_t> staged_wire_bytes;
  std::unordered_map<int, size_t> staged_aggregate_wire_bytes;
  if (!wire_outputs || count == 0 || reservation_ids.size() != count ||
      wire_outputs->size() != count) {
    return false;
  }
  try {
    stages.reserve(count);
    unique_reservations.reserve(count);
    staged_wire_bytes.reserve(count);
    staged_aggregate_wire_bytes.reserve(count);
    for (size_t index = 0; index < count; ++index) {
      auto *sess = sessions[index];
      const auto reservation_id = reservation_ids[index];
      if (!sess || reservation_id == 0 || (*wire_outputs)[index].empty() ||
          !(*wire_outputs)[index].bound_to(sess) ||
          !unique_reservations.insert(reservation_id).second) {
        return false;
      }
      auto *entry = gateway_find_pending_output_entry(sess, reservation_id);
      if (!entry) {
        return false;
      }
      const auto wire_bytes = (*wire_outputs)[index].size();
      auto &session_staged_wire_bytes = staged_wire_bytes[sess];
      if (wire_bytes > std::numeric_limits<size_t>::max() -
                           session_staged_wire_bytes) {
        return false;
      }
      session_staged_wire_bytes += wire_bytes;
      if (sess->output_fifo_budget_tracked) {
        auto &aggregate_wire_bytes =
            staged_aggregate_wire_bytes[
                gateway_output_fifo_aggregate_bucket_key(sess->master_fd)];
        if (wire_bytes > std::numeric_limits<size_t>::max() -
                             aggregate_wire_bytes) {
          return false;
        }
        aggregate_wire_bytes += wire_bytes;
      }
      uint64_t preceding_count = 0;
      for (auto it = sess->output_fifo.begin(); it != sess->output_fifo.end();
           ++it) {
        if (&*it == entry) {
          break;
        }
        ++preceding_count;
      }
      stages.push_back({sess, entry, preceding_count, wire_bytes});
    }
  } catch (const std::exception &) {
    return false;
  }

  bool wire_capacity_rejected = false;
  for (const auto &[sess, wire_bytes] : staged_wire_bytes) {
    if (gateway_session_output_fifo_session_can_add_wire_bytes(sess,
                                                               wire_bytes)) {
      continue;
    }
    gateway_record_session_output_fifo_wire_rejection(sess);
    wire_capacity_rejected = true;
  }
  if (wire_capacity_rejected) {
    return false;
  }

  std::unordered_set<int> rejected_aggregate_buckets;
  for (const auto &[master_fd, wire_bytes] : staged_aggregate_wire_bytes) {
    if (!gateway_output_fifo_aggregate_bucket_can_add(master_fd, wire_bytes)) {
      rejected_aggregate_buckets.insert(master_fd);
    }
  }
  if (!rejected_aggregate_buckets.empty()) {
    g_gateway_runtime_counters.output_fifo_aggregate_wire_bytes_rejected.fetch_add(
        rejected_aggregate_buckets.size(), std::memory_order_relaxed);
    for (const auto &[sess, wire_bytes] : staged_wire_bytes) {
      (void)wire_bytes;
      if (sess->output_fifo_budget_tracked &&
          rejected_aggregate_buckets.count(
              gateway_output_fifo_aggregate_bucket_key(sess->master_fd))) {
        gateway_record_session_output_fifo_wire_rejection(sess);
      }
    }
    return false;
  }

  // No operation below this point can reject an item. The complete wave is
  // committed before any writer is invoked.
  for (size_t index = 0; index < count; ++index) {
    auto &stage = stages[index];
    stage.entry->wire_bytes = std::move((*wire_outputs)[index]).release();
    stage.entry->ready = true;
    gateway_add_session_output_fifo_wire_bytes(stage.session,
                                               stage.wire_bytes);
    g_gateway_runtime_counters.output_fifo_filled.fetch_add(
        1, std::memory_order_relaxed);
    if (stage.preceding_count > 0 &&
        !stage.session->output_fifo.front().ready) {
      auto &counters = g_gateway_runtime_counters;
      counters.output_fifo_head_blocked_fills.fetch_add(
          1, std::memory_order_relaxed);
      counters.output_fifo_head_blocked_predecessors_total.fetch_add(
          stage.preceding_count, std::memory_order_relaxed);
      auto observed = counters.output_fifo_head_blocked_predecessors_max.load(
          std::memory_order_relaxed);
      while (observed < stage.preceding_count &&
             !counters.output_fifo_head_blocked_predecessors_max
                  .compare_exchange_weak(observed, stage.preceding_count,
                                         std::memory_order_relaxed,
                                         std::memory_order_relaxed)) {
      }
    }
    stage.session->last_active = get_current_time();
  }
  return true;
}

int gateway_fill_session_wire_output_with_writer(
    GatewaySession *sess, uint64_t reservation_id,
    GatewayWireOutput wire_output, GatewayOutputWriter writer) {
  if (!writer || !gateway_stage_session_wire_output(
                     sess, reservation_id, std::move(wire_output))) {
    return 0;
  }
  gateway_flush_session_output_fifo_with_writer(sess, writer);
  return 1;
}

std::optional<GatewaySessionFutureWatch>
gateway_detach_session_future_watch(uint64_t reservation_id) {
  auto watch_it = g_gateway_session_future_watches.find(reservation_id);
  if (watch_it == g_gateway_session_future_watches.end()) {
    return std::nullopt;
  }
  auto watch = watch_it->second;
  g_gateway_future_to_reservation.erase(watch.future_id);
  auto queue_it = g_gateway_future_watch_queue_positions.find(reservation_id);
  if (queue_it != g_gateway_future_watch_queue_positions.end()) {
    g_gateway_future_watch_queue.erase(queue_it->second);
    g_gateway_future_watch_queue_positions.erase(queue_it);
  }
  g_gateway_session_future_watches.erase(watch_it);
  if (g_gateway_session_future_watches.empty() && !gateway_has_future_watches()) {
    gateway_stop_future_watch_timer();
  }
  return watch;
}

bool gateway_session_future_watch_session_is_current(
    const GatewaySessionFutureWatch &watch, GatewaySession **session,
    object_t **target) {
  auto *sess = gateway_find_session(watch.session_id.c_str());
  auto *ob = gateway_resolve_session_object(sess);
  if (session) {
    *session = sess;
  }
  if (target) {
    *target = ob;
  }
  return sess && ob && sess->session_id == watch.session_id &&
      sess->user_ob_name == watch.user_ob_name &&
      sess->user_ob_load_time == watch.user_ob_load_time;
}

bool gateway_session_future_watch_is_current(
    const GatewaySessionFutureWatch &watch, GatewaySession **session,
    object_t **target) {
  GatewaySession *sess = nullptr;
  object_t *ob = nullptr;
  const auto session_current = gateway_session_future_watch_session_is_current(
      watch, &sess, &ob);
  if (session) {
    *session = sess;
  }
  if (target) {
    *target = ob;
  }
  return session_current && watch.owner_id == vm_owner_id(ob) &&
      vm_owner_epoch_matches(ob, watch.owner_id.c_str(), watch.owner_epoch);
}

GatewaySession *gateway_session_future_watch_cleanup_session(
    const GatewaySessionFutureWatch &watch) {
  auto *sess = gateway_find_session(watch.session_id.c_str());
  if (!sess || sess->user_ob_name != watch.user_ob_name ||
      sess->user_ob_load_time != watch.user_ob_load_time) {
    return nullptr;
  }
  return sess;
}

bool gateway_session_future_watch_cleanup_target(
    const GatewaySessionFutureWatch &watch, GatewaySession **session,
    object_t **target) {
  auto *sess = gateway_session_future_watch_cleanup_session(watch);
  auto *ob = gateway_resolve_session_object(sess);
  if (session) {
    *session = sess;
  }
  if (target) {
    *target = ob;
  }
  return sess && ob;
}

void gateway_finalize_cancelled_session_future_watch(
    const GatewaySessionFutureWatch &watch, const char *reason,
    bool release_non_mapping_reservation) {
  if (watch.output_kind == GatewayFutureOutputKind::kMapping) {
    GatewaySession *callback_session = nullptr;
    object_t *callback_target = nullptr;
    if (gateway_session_future_watch_cleanup_target(
            watch, &callback_session, &callback_target) &&
        !gateway_dispatch_future_watch_cancelled_callback(
            callback_target, watch.reservation_id, watch.future_id, reason)) {
      g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(
          1, std::memory_order_relaxed);
    }

    // The callback may release, destruct, disconnect, or recursively destroy
    // the session. Never reuse callback_session or callback_target here.
    auto *release_session =
        gateway_session_future_watch_cleanup_session(watch);
    if (gateway_session_has_pending_reservation(release_session,
                                                watch.reservation_id)) {
      gateway_release_session_output(release_session, watch.reservation_id);
    }
    return;
  }

  if (release_non_mapping_reservation) {
    auto *release_session =
        gateway_session_future_watch_cleanup_session(watch);
    if (gateway_session_has_pending_reservation(release_session,
                                                watch.reservation_id)) {
      gateway_release_session_output(release_session, watch.reservation_id);
    }
  }

  GatewaySession *notification_session = nullptr;
  object_t *notification_target = nullptr;
  if (gateway_session_future_watch_cleanup_target(
          watch, &notification_session, &notification_target) &&
      !gateway_dispatch_future_output_notification(
          notification_target, watch.reservation_id, "released",
          watch.event_count, watch.slot_server_seq)) {
    g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(
        1, std::memory_order_relaxed);
  }
}

bool gateway_force_remove_session_output(GatewaySession *sess,
                                         uint64_t reservation_id) {
  if (!sess || reservation_id == 0) {
    return false;
  }
  for (auto it = sess->output_fifo.begin(); it != sess->output_fifo.end();
       ++it) {
    if (it->reservation_id != reservation_id) {
      continue;
    }
    if (it->ready) {
      gateway_remove_session_output_fifo_wire_bytes(sess,
                                                    it->wire_bytes.size());
      g_gateway_runtime_counters.output_fifo_destroyed_ready.fetch_add(
          1, std::memory_order_relaxed);
    } else {
      g_gateway_runtime_counters.output_fifo_destroyed_pending.fetch_add(
          1, std::memory_order_relaxed);
    }
    sess->output_fifo.erase(it);
    g_gateway_runtime_counters.room_output_projection_forced_cleanup.fetch_add(
        1, std::memory_order_relaxed);
    return true;
  }
  return false;
}

bool gateway_stage_session_output_release(GatewaySession *sess,
                                          uint64_t reservation_id) {
  if (!sess || reservation_id == 0) {
    return false;
  }
  for (auto it = sess->output_fifo.begin(); it != sess->output_fifo.end();
       ++it) {
    if (it->reservation_id != reservation_id || it->ready) {
      continue;
    }
    sess->output_fifo.erase(it);
    g_gateway_runtime_counters.output_fifo_released.fetch_add(
        1, std::memory_order_relaxed);
    sess->last_active = get_current_time();
    return true;
  }
  return false;
}

bool gateway_notify_room_output_wave_item(GatewayRoomOutputWaveItem *item,
                                          const char *state,
                                          bool require_current) {
  if (!item || item->notification_finalized) {
    return item != nullptr;
  }
  GatewaySession *sess = nullptr;
  object_t *ob = nullptr;
  const auto target_ready = require_current
      ? gateway_session_future_watch_is_current(item->watch, &sess, &ob)
      : gateway_session_future_watch_cleanup_target(item->watch, &sess, &ob);
  if (!target_ready) {
    return false;
  }
  // Mark before entering LPC: the callback may destruct or disconnect its
  // session and re-enter wave cleanup. The watcher remains the sole terminal
  // consumer, and a re-entrant cleanup must not send the notification twice.
  item->notification_finalized = true;
  const auto callback_ok = gateway_dispatch_future_output_notification(
      ob, item->watch.reservation_id, state, item->watch.event_count,
      item->watch.slot_server_seq);
  if (!callback_ok) {
    g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(
        1, std::memory_order_relaxed);
  }
  return callback_ok;
}

bool gateway_release_room_output_wave_item(
    GatewayRoomOutputWaveItem *item, GatewaySession *known_session = nullptr) {
  if (!item) {
    return false;
  }
  item->terminal = true;
  item->completed = false;
  item->inline_fallback = false;
  item->wire_bytes.clear();

  if (!item->reservation_closed) {
    auto *sess = known_session
        ? known_session
        : gateway_session_future_watch_cleanup_session(item->watch);
    if (!sess ||
        !gateway_session_has_pending_reservation(
            sess, item->watch.reservation_id)) {
      item->reservation_closed = true;
    } else {
      item->reservation_closed =
          gateway_release_session_output(
              sess, item->watch.reservation_id) != 0 ||
          gateway_force_remove_session_output(
              sess, item->watch.reservation_id);
    }
  }
  return item->reservation_closed;
}

bool gateway_fail_room_output_wave_item(
    uint64_t wave_id, size_t item_index,
    const GatewaySessionFutureWatch &observed_watch, const char *reason) {
  auto wave_it = g_gateway_room_output_waves.find(wave_id);
  if (wave_it == g_gateway_room_output_waves.end() ||
      item_index >= wave_it->second.items.size()) {
    return false;
  }

  const auto item_watch = wave_it->second.items[item_index].watch;
  auto detached =
      gateway_detach_session_future_watch(observed_watch.reservation_id);
  if (detached) {
    gateway_consume_cancelled_future(
        detached->future_id,
        reason && reason[0] ? reason : "room output wave item failed");
    g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
        1, std::memory_order_relaxed);
  } else if (!wave_it->second.items[item_index].terminal &&
             vm_owner_future_state(item_watch.future_id) !=
                 VM_OWNER_FUTURE_UNKNOWN) {
    gateway_consume_cancelled_future(
        item_watch.future_id,
        reason && reason[0] ? reason : "room output wave item failed");
    g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
        1, std::memory_order_relaxed);
  }

  // Future cancellation does not enter LPC, but re-find the wave before any
  // release or notification so this helper stays correct if that changes.
  wave_it = g_gateway_room_output_waves.find(wave_id);
  if (wave_it == g_gateway_room_output_waves.end() ||
      item_index >= wave_it->second.items.size()) {
    return true;
  }
  auto &item = wave_it->second.items[item_index];
  auto *release_session =
      gateway_session_future_watch_cleanup_session(item.watch);
  gateway_release_room_output_wave_item(&item, release_session);
  const auto all_terminal =
      gateway_room_output_wave_all_terminal(wave_it->second);
  const auto notify_released =
      item.reservation_closed && !item.notification_finalized;

  if (all_terminal) {
    gateway_publish_room_output_wave(wave_id);
  } else if (notify_released) {
    // The callback can destruct a target and erase the wave. Do not touch the
    // item or wave after dispatch.
    gateway_notify_room_output_wave_item(&item, "released", false);
  }
  return true;
}

bool gateway_mark_room_output_wave_item_inline_fallback(
    GatewayRoomOutputWaveItem *item, GatewaySession *sess) {
  if (!item || !item->work || !sess || item->reservation_closed ||
      !gateway_session_has_pending_reservation(
          sess, item->watch.reservation_id) ||
      !gateway_pending_message_event_projection_matches(
          sess, item->watch.reservation_id,
          item->watch.projection_generation, true)) {
    return false;
  }
  item->terminal = true;
  item->completed = false;
  item->inline_fallback = true;
  item->wire_bytes.clear();
  return true;
}

bool gateway_room_output_wave_all_terminal(
    const GatewayRoomOutputWave &wave) {
  return !wave.items.empty() &&
      std::all_of(wave.items.begin(), wave.items.end(),
                  [](const GatewayRoomOutputWaveItem &item) {
                    return item.terminal;
                  });
}

size_t gateway_abort_room_output_wave(uint64_t wave_id, const char *reason,
                                      const std::string *skip_release_session) {
  auto wave_it = g_gateway_room_output_waves.find(wave_id);
  if (wave_it == g_gateway_room_output_waves.end()) {
    return 0;
  }
  if (wave_it->second.retry_schedule) {
    g_gateway_room_output_retry_schedule.erase(
        *wave_it->second.retry_schedule);
    wave_it->second.retry_schedule.reset();
  }
  auto wave = std::move(wave_it->second);
  g_gateway_room_output_waves.erase(wave_it);

  size_t cancelled = 0;
  for (auto &item : wave.items) {
    auto detached =
        gateway_detach_session_future_watch(item.watch.reservation_id);
    if (detached) {
      gateway_consume_cancelled_future(
          detached->future_id,
          reason && reason[0] ? reason : "room output wave aborted");
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
      ++cancelled;
    } else if (!item.terminal &&
               vm_owner_future_state(item.watch.future_id) !=
                   VM_OWNER_FUTURE_UNKNOWN) {
      gateway_consume_cancelled_future(
          item.watch.future_id,
          reason && reason[0] ? reason : "room output wave aborted");
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
      ++cancelled;
    }
    item.terminal = true;
    item.completed = false;
    item.wire_bytes.clear();
  }

  for (auto &item : wave.items) {
    auto *sess = gateway_find_session(item.watch.session_id.c_str());
    if (item.reservation_closed || !sess ||
        (skip_release_session &&
         item.watch.session_id == *skip_release_session)) {
      continue;
    }
    if (gateway_session_has_pending_reservation(
            sess, item.watch.reservation_id)) {
      if (!gateway_release_session_output(sess, item.watch.reservation_id)) {
        gateway_force_remove_session_output(sess,
                                            item.watch.reservation_id);
      }
    } else {
      gateway_force_remove_session_output(sess, item.watch.reservation_id);
    }
    item.reservation_closed = true;
  }
  for (auto &item : wave.items) {
    gateway_notify_room_output_wave_item(&item, "released", false);
  }
  g_gateway_runtime_counters.room_output_projection_failed.fetch_add(
      wave.items.size(), std::memory_order_relaxed);
  g_gateway_runtime_counters.room_output_projection_released.fetch_add(
      wave.items.size(), std::memory_order_relaxed);
  return cancelled;
}

bool gateway_queue_room_output_publish_retry(uint64_t wave_id) {
  auto wave_it = g_gateway_room_output_waves.find(wave_id);
  if (wave_it == g_gateway_room_output_waves.end() ||
      !gateway_room_output_wave_all_terminal(wave_it->second)) {
    return false;
  }
  auto &wave = wave_it->second;
  if (wave.retry_schedule) {
    return true;
  }
  const auto now_ms = gateway_session_now_ms();
  if (wave.retry_started_at_ms == 0) {
    wave.retry_started_at_ms = now_ms;
  }
  if (wave.retry_attempts >= kGatewayRoomOutputRetryMaxAttempts ||
      now_ms - wave.retry_started_at_ms >=
          kGatewayRoomOutputRetryMaxHoldMs) {
    g_gateway_runtime_counters.room_output_projection_retry_exhausted.fetch_add(
        1, std::memory_order_relaxed);
    gateway_abort_room_output_wave(
        wave_id, "room output wave publish retry exhausted", nullptr);
    return false;
  }

  const auto shift = std::min<uint32_t>(wave.retry_attempts, 6);
  const auto delay_ms = std::min<uint64_t>(
      kGatewayRoomOutputRetryBaseDelayMs << shift,
      kGatewayRoomOutputRetryMaxDelayMs);
  wave.retry_due_at_ms = now_ms + delay_ms;
  ++wave.retry_attempts;
  try {
    wave.retry_schedule = g_gateway_room_output_retry_schedule.emplace(
        wave.retry_due_at_ms, wave_id);
  } catch (const std::exception &) {
    wave.retry_schedule.reset();
    g_gateway_runtime_counters.room_output_projection_retry_exhausted.fetch_add(
        1, std::memory_order_relaxed);
    gateway_abort_room_output_wave(
        wave_id, "room output wave retry scheduling failed", nullptr);
    return false;
  }
  g_gateway_runtime_counters.room_output_projection_retry_enqueued.fetch_add(
      1, std::memory_order_relaxed);
  gateway_schedule_future_watch_timer();
  return true;
}

bool gateway_publish_room_output_wave(uint64_t wave_id) {
  auto wave_it = g_gateway_room_output_waves.find(wave_id);
  if (wave_it == g_gateway_room_output_waves.end() ||
      !gateway_room_output_wave_all_terminal(wave_it->second)) {
    return false;
  }
  auto &wave = wave_it->second;
  std::vector<GatewaySession *> sessions;
  std::vector<uint64_t> reservation_ids;
  std::vector<GatewayWireOutput> wire_outputs;
  std::vector<size_t> staged_indices;
  std::unordered_set<GatewaySession *> flush_sessions;
  size_t inline_fallback_count = 0;
  try {
    sessions.reserve(wave.items.size());
    reservation_ids.reserve(wave.items.size());
    wire_outputs.reserve(wave.items.size());
    staged_indices.reserve(wave.items.size());
    flush_sessions.reserve(wave.items.size());
    for (size_t index = 0; index < wave.items.size(); ++index) {
      auto &item = wave.items[index];
      if (item.reservation_closed) {
        continue;
      }
      GatewaySession *sess = nullptr;
      object_t *ob = nullptr;
      if (!gateway_session_future_watch_session_is_current(
              item.watch, &sess, &ob) ||
          !gateway_pending_message_event_projection_matches(
              sess, item.watch.reservation_id,
              item.watch.projection_generation, true) ||
          !gateway_session_has_pending_reservation(
              sess, item.watch.reservation_id)) {
        gateway_release_room_output_wave_item(
            &item, gateway_session_future_watch_cleanup_session(item.watch));
        continue;
      }

      const auto owner_current = item.watch.owner_id == vm_owner_id(ob) &&
          vm_owner_epoch_matches(ob, item.watch.owner_id.c_str(),
                                 item.watch.owner_epoch);
      auto use_inline = item.inline_fallback || !item.completed ||
          !owner_current || item.wire_bytes.empty();
      std::optional<GatewayWireOutput> wire_output;
      if (!use_inline) {
        wire_output = GatewayWireOutputFactory::validated_projected_wire(
            sess, item.wire_bytes);
        use_inline = !wire_output.has_value();
      }
      if (use_inline) {
        wire_output = gateway_prepare_projection_wire(sess, item.work);
      }
      if (!wire_output) {
        // Nothing has been staged or released yet. A dedicated bounded retry
        // schedule retains the complete wave and every original reservation.
        gateway_queue_room_output_publish_retry(wave_id);
        return false;
      }
      sessions.push_back(sess);
      reservation_ids.push_back(item.watch.reservation_id);
      wire_outputs.push_back(std::move(*wire_output));
      staged_indices.push_back(index);
      flush_sessions.insert(sess);
      if (use_inline) {
        ++inline_fallback_count;
      }
    }
  } catch (const std::exception &) {
    gateway_queue_room_output_publish_retry(wave_id);
    return false;
  }

  if (!sessions.empty() &&
      !gateway_stage_session_wire_outputs(sessions, reservation_ids,
                                          &wire_outputs)) {
    gateway_queue_room_output_publish_retry(wave_id);
    return false;
  }
  for (size_t index = 0; index < staged_indices.size(); ++index) {
    auto &item = wave.items[staged_indices[index]];
    item.completed = true;
    item.reservation_closed = true;
    item.wire_bytes.clear();
  }
  if (inline_fallback_count > 0) {
    g_gateway_runtime_counters.room_output_projection_inline_fallbacks.fetch_add(
        inline_fallback_count, std::memory_order_relaxed);
  }

  const auto completed_count = static_cast<size_t>(std::count_if(
      wave.items.begin(), wave.items.end(),
      [](const GatewayRoomOutputWaveItem &item) { return item.completed; }));
  const auto released_count = wave.items.size() - completed_count;
  if (wave.retry_schedule) {
    g_gateway_room_output_retry_schedule.erase(*wave.retry_schedule);
    wave.retry_schedule.reset();
  }
  auto completed_wave = std::move(wave);
  g_gateway_room_output_waves.erase(wave_it);
  g_gateway_runtime_counters.room_output_projection_completed.fetch_add(
      completed_count, std::memory_order_relaxed);
  g_gateway_runtime_counters.room_output_projection_released.fetch_add(
      released_count, std::memory_order_relaxed);
  g_gateway_runtime_counters.room_output_projection_failed.fetch_add(
      released_count, std::memory_order_relaxed);
  for (auto *sess : flush_sessions) {
    gateway_flush_session_output_fifo_with_writer(sess,
                                                  gateway_send_raw_to_fd);
  }
  for (auto &item : completed_wave.items) {
    gateway_notify_room_output_wave_item(
        &item, item.completed ? "completed" : "released", false);
  }
  return true;
}

void gateway_process_room_output_publish_retries(uint64_t now_ms) {
  const auto started_at_ns = gateway_session_now_ns();
  size_t examined = 0;
  bool wall_budget_hit = false;
  while (examined < kGatewayRoomOutputRetryBudget &&
         !g_gateway_room_output_retry_schedule.empty()) {
    if (gateway_session_now_ns() - started_at_ns >=
        kGatewayRoomOutputRetryWallBudgetNs) {
      wall_budget_hit = true;
      break;
    }
    auto scheduled = g_gateway_room_output_retry_schedule.begin();
    if (scheduled->first > now_ms) {
      break;
    }
    const auto wave_id = scheduled->second;
    g_gateway_room_output_retry_schedule.erase(scheduled);
    auto wave_it = g_gateway_room_output_waves.find(wave_id);
    if (wave_it == g_gateway_room_output_waves.end()) {
      ++examined;
      continue;
    }
    wave_it->second.retry_schedule.reset();
    ++examined;
    g_gateway_runtime_counters.room_output_projection_retry_attempted.fetch_add(
        1, std::memory_order_relaxed);
    if (now_ms - wave_it->second.retry_started_at_ms >=
        kGatewayRoomOutputRetryMaxHoldMs) {
      g_gateway_runtime_counters.room_output_projection_retry_exhausted.fetch_add(
          1, std::memory_order_relaxed);
      gateway_abort_room_output_wave(
          wave_id, "room output wave retry deadline exceeded", nullptr);
      continue;
    }
    gateway_publish_room_output_wave(wave_id);
  }
  if (wall_budget_hit) {
    g_gateway_runtime_counters
        .room_output_projection_retry_wall_budget_hits.fetch_add(
            1, std::memory_order_relaxed);
  } else if (examined >= kGatewayRoomOutputRetryBudget &&
             !g_gateway_room_output_retry_schedule.empty() &&
             g_gateway_room_output_retry_schedule.begin()->first <= now_ms) {
    g_gateway_runtime_counters.room_output_projection_retry_budget_hits.fetch_add(
        1, std::memory_order_relaxed);
  }
}

void gateway_cancel_room_output_wave_session_items(
    const std::string &session_id, GatewaySession *sess, const char *reason,
    bool release_reservations) {
  std::vector<uint64_t> wave_ids;
  for (const auto &[wave_id, wave] : g_gateway_room_output_waves) {
    if (std::any_of(wave.items.begin(), wave.items.end(),
                    [&session_id](const GatewayRoomOutputWaveItem &item) {
                      return item.watch.session_id == session_id;
                    })) {
      wave_ids.push_back(wave_id);
    }
  }

  for (const auto wave_id : wave_ids) {
    auto wave_it = g_gateway_room_output_waves.find(wave_id);
    if (wave_it == g_gateway_room_output_waves.end()) {
      continue;
    }
    std::vector<GatewaySessionFutureWatch> release_notifications;
    for (auto &item : wave_it->second.items) {
      if (item.watch.session_id != session_id) {
        continue;
      }
      auto detached =
          gateway_detach_session_future_watch(item.watch.reservation_id);
      if (detached) {
        gateway_consume_cancelled_future(detached->future_id, reason);
        g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
            1, std::memory_order_relaxed);
      } else if (!item.terminal &&
                 vm_owner_future_state(item.watch.future_id) !=
                     VM_OWNER_FUTURE_UNKNOWN) {
        gateway_consume_cancelled_future(item.watch.future_id, reason);
        g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
            1, std::memory_order_relaxed);
      }
      item.terminal = true;
      item.completed = false;
      item.wire_bytes.clear();
      if (release_reservations && sess) {
        if (gateway_session_has_pending_reservation(
                sess, item.watch.reservation_id)) {
          item.reservation_closed =
              gateway_release_session_output(
                  sess, item.watch.reservation_id) != 0 ||
              gateway_force_remove_session_output(
                  sess, item.watch.reservation_id);
        } else {
          item.reservation_closed = true;
        }
      } else if (!release_reservations) {
        // The caller immediately discards the dying session FIFO. Keep this
        // wave from writing that session while the remaining recipients drain.
        item.reservation_closed = true;
      }
      GatewaySession *notification_session = nullptr;
      object_t *notification_target = nullptr;
      if (!item.notification_finalized &&
          gateway_session_future_watch_cleanup_target(
              item.watch, &notification_session, &notification_target)) {
        item.notification_finalized = true;
        release_notifications.push_back(item.watch);
      }
    }
    for (const auto &notification : release_notifications) {
      GatewaySession *notification_session = nullptr;
      object_t *notification_target = nullptr;
      if (gateway_session_future_watch_cleanup_target(
              notification, &notification_session, &notification_target) &&
          !gateway_dispatch_future_output_notification(
              notification_target, notification.reservation_id, "released",
              notification.event_count, notification.slot_server_seq)) {
        g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(
            1, std::memory_order_relaxed);
      }
    }
    gateway_publish_room_output_wave(wave_id);
  }
}

int gateway_process_room_output_wave_watch(
    const GatewaySessionFutureWatch &watch, uint64_t now_ms) {
  auto completion_cpu_started_ns = get_current_thread_cpu_time_ns();
  auto wave_it =
      g_gateway_room_output_waves.find(watch.room_output_wave_id);
  if (wave_it == g_gateway_room_output_waves.end() ||
      watch.room_output_wave_index >= wave_it->second.items.size()) {
    auto detached =
        gateway_detach_session_future_watch(watch.reservation_id);
    if (detached) {
      gateway_consume_cancelled_future(detached->future_id,
                                       "room output wave missing");
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
    }
    auto *sess = gateway_find_session(watch.session_id.c_str());
    if (sess && gateway_session_has_pending_reservation(
                    sess, watch.reservation_id)) {
      gateway_release_session_output(sess, watch.reservation_id);
    }
    GatewaySession *notification_session = nullptr;
    object_t *notification_target = nullptr;
    if (gateway_session_future_watch_cleanup_target(
            watch, &notification_session, &notification_target) &&
        !gateway_dispatch_future_output_notification(
            notification_target, watch.reservation_id, "released",
            watch.event_count, watch.slot_server_seq)) {
      g_gateway_runtime_counters.future_watch_callback_failures.fetch_add(
          1, std::memory_order_relaxed);
    }
    g_gateway_runtime_counters.room_output_projection_failed.fetch_add(
        1, std::memory_order_relaxed);
    g_gateway_runtime_counters.room_output_projection_released.fetch_add(
        1, std::memory_order_relaxed);
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
    return 1;
  }
  auto &item = wave_it->second.items[watch.room_output_wave_index];
  GatewaySession *sess = nullptr;
  object_t *ob = nullptr;
  const auto watch_matches = item.watch.future_id == watch.future_id &&
      item.watch.reservation_id == watch.reservation_id;
  const auto session_current = gateway_session_future_watch_session_is_current(
      watch, &sess, &ob);
  const auto projection_current = session_current &&
      gateway_pending_message_event_projection_matches(
          sess, watch.reservation_id, watch.projection_generation, true) &&
      gateway_session_has_pending_reservation(sess, watch.reservation_id);
  if (!watch_matches || !projection_current) {
    gateway_fail_room_output_wave_item(
        watch.room_output_wave_id, watch.room_output_wave_index, watch,
        watch_matches ? "room output wave live validation failed"
                      : "room output wave watch identity failed");
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
    return 1;
  }

  const auto owner_current = watch.owner_id == vm_owner_id(ob) &&
      vm_owner_epoch_matches(ob, watch.owner_id.c_str(), watch.owner_epoch);
  if (!owner_current) {
    auto detached =
        gateway_detach_session_future_watch(watch.reservation_id);
    if (detached) {
      gateway_consume_cancelled_future(detached->future_id,
                                       "room output wave owner stale");
      g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
          1, std::memory_order_relaxed);
    }
    const auto fallback_ready =
        gateway_mark_room_output_wave_item_inline_fallback(&item, sess);
    if (!fallback_ready) {
      gateway_release_room_output_wave_item(&item, sess);
    }
    const auto all_terminal =
        gateway_room_output_wave_all_terminal(wave_it->second);
    const auto notify_released =
        !fallback_ready && item.reservation_closed;
    if (all_terminal) {
      gateway_publish_room_output_wave(watch.room_output_wave_id);
    } else if (notify_released) {
      gateway_notify_room_output_wave_item(&item, "released", false);
    }
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
    return 1;
  }

  auto future_state = vm_owner_future_state(watch.future_id);
  if (future_state == VM_OWNER_FUTURE_PENDING && now_ms < watch.deadline_ms) {
    if (gateway_requeue_session_future_watch(watch.reservation_id)) {
      return 0;
    }
    gateway_fail_room_output_wave_item(
        watch.room_output_wave_id, watch.room_output_wave_index, watch,
        "room output wave watch requeue failed");
    gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
    return 1;
  }

  if (future_state == VM_OWNER_FUTURE_PENDING) {
    auto *timed_out = vm_owner_future_timeout(
        watch.future_id, "gateway room output wave timed out");
    const auto terminal_changed =
        gateway_future_mapping_flag(timed_out, "terminal_changed");
    free_mapping(timed_out);
    if (terminal_changed) {
      g_gateway_runtime_counters.future_watches_timed_out.fetch_add(
          1, std::memory_order_relaxed);
    }
  }
  const auto take_started_ns = gateway_session_now_ns();
  auto output_future = vm_owner_future_take_string(watch.future_id);
  const auto take_finished_ns = gateway_session_now_ns();
  gateway_session_record_latency(
      g_gateway_runtime_counters.future_watch_take_ns_total,
      g_gateway_runtime_counters.future_watch_take_ns_max,
      g_gateway_runtime_counters.future_watch_take_samples,
      take_finished_ns - take_started_ns);
  if (output_future.terminal_at_ns > 0 &&
      take_started_ns >= output_future.terminal_at_ns) {
    gateway_session_record_latency(
        g_gateway_runtime_counters.future_watch_terminal_lag_ns_total,
        g_gateway_runtime_counters.future_watch_terminal_lag_ns_max,
        g_gateway_runtime_counters.future_watch_terminal_lag_samples,
        take_started_ns - output_future.terminal_at_ns);
  }
  gateway_detach_session_future_watch(watch.reservation_id);
  item.terminal = true;
  item.completed = output_future.state == VM_OWNER_FUTURE_COMPLETED &&
      output_future.string_result && !output_future.value.empty();
  if (item.completed) {
    item.inline_fallback = false;
    item.wire_bytes = std::move(output_future.value);
    g_gateway_runtime_counters.future_watches_completed.fetch_add(
        1, std::memory_order_relaxed);
  } else {
    g_gateway_runtime_counters.future_watches_failed.fetch_add(
        1, std::memory_order_relaxed);
    if (!gateway_mark_room_output_wave_item_inline_fallback(&item, sess)) {
      gateway_release_room_output_wave_item(&item, sess);
    }
  }

  const auto all_terminal = gateway_room_output_wave_all_terminal(
      wave_it->second);
  const auto notify_released = !item.completed && item.reservation_closed;
  if (notify_released) {
    gateway_notify_room_output_wave_item(&item, "released", false);
  }
  if (all_terminal) {
    const auto publish_started_ns = gateway_session_now_ns();
    gateway_publish_room_output_wave(watch.room_output_wave_id);
    gateway_session_record_latency(
        g_gateway_runtime_counters.room_output_projection_publish_ns_total,
        g_gateway_runtime_counters.room_output_projection_publish_ns_max,
        g_gateway_runtime_counters.room_output_projection_publish_samples,
        gateway_session_now_ns() - publish_started_ns);
  }
  gateway_record_future_completion_thread_cpu(completion_cpu_started_ns);
  return 1;
}

}  // namespace

mapping_t *gateway_owner_output_quiesce(const char *reason) {
  if (!vm_context_is_main_thread()) {
    auto *result = allocate_mapping(24);
    add_mapping_pair(result, "success", 0);
    add_mapping_string(result, "state", "main_thread_required");
    add_mapping_string(result, "quiesce_model",
                       "drain_then_immediate_owner_stop_v1");
    add_mapping_pair(result, "counts_available", 0);
    add_mapping_pair(result, "room_waves_before", -1);
    add_mapping_pair(result, "room_pending_before", -1);
    add_mapping_pair(result, "room_watches_before", -1);
    add_mapping_pair(result, "room_reservations_before", -1);
    add_mapping_pair(result, "session_watches_before", -1);
    add_mapping_pair(result, "session_reservations_before", -1);
    add_mapping_pair(result, "cancelled_futures", 0);
    add_mapping_pair(result, "released_reservations", 0);
    add_mapping_pair(result, "room_waves_after", -1);
    add_mapping_pair(result, "room_pending_after", -1);
    add_mapping_pair(result, "room_watches_after", -1);
    add_mapping_pair(result, "room_reservations_after", -1);
    add_mapping_pair(result, "session_watches_after", -1);
    add_mapping_pair(result, "session_reservations_after", -1);
    add_mapping_pair(result, "requires_immediate_owner_stop", 1);
    add_mapping_pair(result, "main_thread", 0);
    return result;
  }

  const auto count_room_watches = [] {
    long count = 0;
    for (const auto &[reservation_id, watch] :
         g_gateway_session_future_watches) {
      (void)reservation_id;
      if (watch.output_kind == GatewayFutureOutputKind::kValidatedWire &&
          watch.room_output_wave_id != 0) {
        ++count;
      }
    }
    return count;
  };
  const auto count_session_watches = [] {
    return g_gateway_session_future_watches.size() >
            static_cast<size_t>(std::numeric_limits<long>::max())
        ? std::numeric_limits<long>::max()
        : static_cast<long>(g_gateway_session_future_watches.size());
  };
  const auto count_reservations = [](bool room_only) {
    long count = 0;
    const auto increment = [&count] {
      if (count < std::numeric_limits<long>::max()) {
        ++count;
      }
    };
    for (const auto &[reservation_id, watch] :
         g_gateway_session_future_watches) {
      (void)reservation_id;
      const auto room_watch =
          watch.output_kind == GatewayFutureOutputKind::kValidatedWire &&
          watch.room_output_wave_id != 0;
      if (room_only && !room_watch) {
        continue;
      }
      auto *sess = gateway_find_session(watch.session_id.c_str());
      if (gateway_session_has_pending_reservation(sess,
                                                  watch.reservation_id)) {
        increment();
      }
    }
    for (const auto &[wave_id, wave] : g_gateway_room_output_waves) {
      (void)wave_id;
      for (const auto &item : wave.items) {
        if (item.reservation_closed ||
            g_gateway_session_future_watches.find(
                item.watch.reservation_id) !=
                g_gateway_session_future_watches.end()) {
          continue;
        }
        auto *sess =
            gateway_find_session(item.watch.session_id.c_str());
        if (gateway_session_has_pending_reservation(
                sess, item.watch.reservation_id)) {
          increment();
        }
      }
    }
    return count;
  };

  const auto waves_before =
      static_cast<long>(g_gateway_room_output_waves.size());
  const auto pending_before = gateway_room_output_projection_pending_count();
  const auto watches_before = count_room_watches();
  const auto reservations_before = count_reservations(true);
  const auto session_watches_before = count_session_watches();
  const auto session_reservations_before = count_reservations(false);
  size_t cancelled_futures = 0;

  while (!g_gateway_room_output_waves.empty()) {
    cancelled_futures += gateway_abort_room_output_wave(
        g_gateway_room_output_waves.begin()->first,
        reason && reason[0] ? reason : "gateway owner output quiesce",
        nullptr);
  }

  while (!g_gateway_session_future_watches.empty()) {
    const auto reservation_id =
        g_gateway_session_future_watches.begin()->first;
    auto detached = gateway_detach_session_future_watch(reservation_id);
    if (!detached) {
      break;
    }
    gateway_consume_cancelled_future(
        detached->future_id,
        reason && reason[0] ? reason : "gateway owner output quiesce");
    gateway_finalize_cancelled_session_future_watch(
        *detached,
        reason && reason[0] ? reason : "gateway owner output quiesce",
        true);
    ++cancelled_futures;
    g_gateway_runtime_counters.future_watches_cancelled.fetch_add(
        1, std::memory_order_relaxed);
    if (detached->output_kind == GatewayFutureOutputKind::kValidatedWire) {
      g_gateway_runtime_counters.room_output_projection_failed.fetch_add(
          1, std::memory_order_relaxed);
      g_gateway_runtime_counters.room_output_projection_released.fetch_add(
          1, std::memory_order_relaxed);
    }
  }

  const auto waves_after =
      static_cast<long>(g_gateway_room_output_waves.size());
  const auto pending_after = gateway_room_output_projection_pending_count();
  const auto watches_after = count_room_watches();
  const auto reservations_after = count_reservations(true);
  const auto session_watches_after = count_session_watches();
  const auto session_reservations_after = count_reservations(false);
  const auto success = waves_after == 0 && pending_after == 0 &&
                       watches_after == 0 && reservations_after == 0 &&
                       session_watches_after == 0 &&
                       session_reservations_after == 0;
  auto *result = allocate_mapping(24);
  add_mapping_pair(result, "success", success ? 1 : 0);
  add_mapping_string(result, "state",
                     success ? "quiesced" : "quiesce_incomplete");
  add_mapping_string(result, "quiesce_model",
                     "drain_then_immediate_owner_stop_v1");
  add_mapping_pair(result, "counts_available", 1);
  add_mapping_pair(result, "room_waves_before", waves_before);
  add_mapping_pair(result, "room_pending_before", pending_before);
  add_mapping_pair(result, "room_watches_before", watches_before);
  add_mapping_pair(result, "room_reservations_before", reservations_before);
  add_mapping_pair(result, "session_watches_before", session_watches_before);
  add_mapping_pair(result, "session_reservations_before",
                   session_reservations_before);
  add_mapping_pair(result, "cancelled_futures",
                   static_cast<long>(cancelled_futures));
  add_mapping_pair(result, "released_reservations",
                   std::max<long>(
                       0, session_reservations_before -
                              session_reservations_after));
  add_mapping_pair(result, "room_waves_after", waves_after);
  add_mapping_pair(result, "room_pending_after", pending_after);
  add_mapping_pair(result, "room_watches_after", watches_after);
  add_mapping_pair(result, "room_reservations_after", reservations_after);
  add_mapping_pair(result, "session_watches_after", session_watches_after);
  add_mapping_pair(result, "session_reservations_after",
                   session_reservations_after);
  add_mapping_pair(result, "requires_immediate_owner_stop", 1);
  add_mapping_pair(result, "main_thread", 1);
  return result;
}

int gateway_fill_session_protocol_output_with_writer(
    GatewaySession *sess, uint64_t reservation_id, const char *data, size_t len,
    GatewayOutputWriter writer) {
  if (!data || !writer) {
    return 0;
  }
  auto wire_output = GatewayWireOutputFactory::protocol_output(
      sess, std::string_view(data, len));
  return wire_output
      ? gateway_fill_session_wire_output_with_writer(
            sess, reservation_id, std::move(*wire_output), writer)
      : 0;
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

  if (!gateway_fill_session_protocol_output_with_writer(
          sess, reservation_id, data, len, gateway_send_raw_to_fd)) {
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

int gateway_session_pending_reservation_has_ready_successor_for_object(
    object_t *ob, uint64_t reservation_id) {
  if (!vm_context_is_main_thread() || !gateway_object_valid(ob)) {
    return 0;
  }
  return gateway_session_pending_reservation_has_ready_successor(
             gateway_find_session_by_object(ob), reservation_id)
             ? 1
             : 0;
}

int gateway_bind_session_object(const char *session_id, object_t *ob, const char *ip, int port,
                                int master_fd) {
  GatewaySession *sess;

  if (!gateway_object_valid(ob) ||
      !gateway_session_id_c_string_is_valid(session_id)) {
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
  gateway_track_session_output_fifo_budget(sess);
  gateway_move_session_output_fifo_budget(sess, master_fd);
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
  gateway_track_session_output_fifo_budget(sess);
  gateway_move_session_output_fifo_budget(sess, master_fd);
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
  sess = gateway_find_session(session_id.c_str());
  auto object_it = g_gateway_obj_to_session.find(ob);
  if (!sess || gateway_resolve_session_object(sess) != ob ||
      object_it == g_gateway_obj_to_session.end() ||
      object_it->second != sess) {
    return;
  }
  gateway_release_command_input_pending(sess);
  gateway_release_command_task_pending(sess);
  g_gateway_obj_to_session.erase(object_it);
  gateway_discard_session_output_fifo(sess);
  gateway_untrack_session_output_fifo_budget(sess);
  g_gateway_sessions.erase(session_id);
}

void gateway_cleanup_master_sessions(int master_fd) {
  for (const auto &entry : g_gateway_sessions) {
    auto *sess = entry.second.get();
    if (!sess || sess->master_fd != master_fd) {
      continue;
    }
    gateway_move_session_output_fifo_budget(sess, -1);
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
  const std::string session_id = sess->session_id;
  gateway_cancel_session_future_watches(session_id, sess, "gateway session exec", true);
  sess = gateway_find_session(session_id.c_str());
  if (!sess || !gateway_object_valid(new_ob) ||
      !gateway_object_valid(old_ob) || !new_ob->interactive ||
      gateway_resolve_session_object(sess) != old_ob) {
    return;
  }
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

  if (!sess || !data) {
    return 0;
  }

  if (g_gateway_debug) {
    debug_message("[gateway] output sid=%s len=%zu\n", session_id, len);
  }
  return gateway_enqueue_session_protocol_output(sess, data, len);
}

std::string gateway_encode_output_envelope_for_test(const std::string &session_id,
                                                    const char *data, size_t len) {
  return gateway_encode_output_envelope(session_id, data, len);
}

int gateway_enqueue_session_wire_json_for_test(
    GatewaySession *sess, const std::string &wire_json) {
  try {
    auto payload = nlohmann::json::parse(wire_json);
    auto wire_output = GatewayWireOutputFactory::southbound_json(sess, payload);
    return wire_output
        ? gateway_enqueue_session_wire_output(sess, std::move(*wire_output))
        : 0;
  } catch (const std::exception &) {
    return 0;
  }
}

int gateway_enqueue_session_payload_json_for_test(
    GatewaySession *sess, const std::string &payload_json) {
  try {
    auto wire_output = gateway_prepare_session_send_wire(
        sess, nlohmann::json::parse(payload_json));
    return wire_output
        ? gateway_enqueue_session_wire_output(sess, std::move(*wire_output))
        : 0;
  } catch (const std::exception &) {
    return 0;
  }
}

bool gateway_fill_projected_wires_for_test(
    const std::vector<GatewaySession *> &sessions,
    const std::vector<uint64_t> &reservation_ids,
    const std::vector<std::string> &wire_json,
    GatewayOutputWriter writer) {
  if (sessions.empty() || sessions.size() != reservation_ids.size() ||
      sessions.size() != wire_json.size() || !writer) {
    return false;
  }
  std::vector<GatewayWireOutput> wire_outputs;
  wire_outputs.reserve(sessions.size());
  for (size_t index = 0; index < sessions.size(); ++index) {
    auto wire_output = GatewayWireOutputFactory::validated_projected_wire(
        sessions[index], wire_json[index]);
    if (!wire_output) {
      return false;
    }
    wire_outputs.push_back(std::move(*wire_output));
  }
  if (!gateway_stage_session_wire_outputs(sessions, reservation_ids,
                                          &wire_outputs)) {
    return false;
  }
  for (auto *sess : sessions) {
    gateway_flush_session_output_fifo_with_writer(sess, writer);
  }
  return true;
}

void gateway_reset_projected_wire_full_validation_count_for_test() {
  g_gateway_projected_wire_full_validation_count.store(
      0, std::memory_order_relaxed);
}

uint64_t gateway_projected_wire_full_validation_count_for_test() {
  return g_gateway_projected_wire_full_validation_count.load(
      std::memory_order_relaxed);
}

bool gateway_drop_room_output_wave_for_test(uint64_t reservation_id) {
  const auto watch_it = g_gateway_session_future_watches.find(reservation_id);
  if (watch_it == g_gateway_session_future_watches.end() ||
      watch_it->second.room_output_wave_id == 0) {
    return false;
  }
  const auto wave_it =
      g_gateway_room_output_waves.find(watch_it->second.room_output_wave_id);
  if (wave_it == g_gateway_room_output_waves.end()) {
    return false;
  }
  if (wave_it->second.retry_schedule) {
    g_gateway_room_output_retry_schedule.erase(
        *wave_it->second.retry_schedule);
  }
  g_gateway_room_output_waves.erase(wave_it);
  return true;
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

std::string gateway_encode_preencoded_message_event_batch_for_test(
    const std::vector<std::string> &stable_children_json,
    const std::vector<std::string> &scope_types, const std::string &scope_id,
    const std::vector<LPC_INT> &message_seqs,
    const std::vector<LPC_INT> &server_seqs,
    const std::vector<LPC_INT> &message_epochs,
    const std::vector<LPC_INT> &sent_ats, LPC_INT slot_server_seq,
    LPC_INT slot_epoch, LPC_INT slot_sent_at) {
  std::vector<std::string_view> stable_views;
  std::vector<std::string_view> scope_type_views;
  std::string frame;

  stable_views.reserve(stable_children_json.size());
  for (const auto &stable_json : stable_children_json) {
    stable_views.emplace_back(stable_json);
  }
  scope_type_views.reserve(scope_types.size());
  for (const auto &scope_type : scope_types) {
    scope_type_views.emplace_back(scope_type);
  }
  if (!gateway_build_preencoded_message_event_batch_frame(
          stable_views, scope_type_views, scope_id, message_seqs, server_seqs,
          message_epochs, sent_ats, slot_server_seq, slot_epoch, slot_sent_at,
          &frame)) {
    return {};
  }
  return frame;
}

void gateway_clear_message_event_template_cache_for_test() {
  g_gateway_message_event_template_cache.clear();
  g_gateway_message_event_template_cache_bytes = 0;
}

object_t *gateway_create_session_internal(const char *session_id, svalue_t *data_val,
                                          const char *ip, int port, int master_fd) {
  object_t *ob;
  svalue_t *ret;
  interactive_t *user;
  int has_gateway_logon;

  if (!gateway_session_id_c_string_is_valid(session_id) ||
      gateway_find_session(session_id) || !g_event_base ||
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
  if (!gateway_session_id_c_string_is_valid(session_id)) {
    return 0;
  }
  const std::string session_key = session_id ? session_id : "";
  auto *sess = gateway_find_session(session_key.c_str());
  auto *ob = gateway_resolve_session_object(sess);
  const char *reason_code_str = reason_code && reason_code[0] ? reason_code : "client_disconnected";
  const char *reason_text_str = reason_text && reason_text[0] ? reason_text : reason_code_str;

  if (!sess) {
    return 0;
  }
  gateway_cancel_session_future_watches(
      session_key, sess, "gateway session destroyed", false);
  sess = gateway_find_session(session_key.c_str());
  if (!sess) {
    return 1;
  }
  ob = gateway_resolve_session_object(sess);
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

    sess = gateway_find_session(session_key.c_str());
    if (!sess) {
      return 1;
    }
    gateway_move_session_output_fifo_budget(sess, -1);
    sess->master_fd = -1;
    ob = resolve_active_session_owner(session_key.c_str(), ob);
    if (!ob || !ob->interactive) {
      auto *session_ob = gateway_resolve_session_object(sess);
      if (session_ob) {
        gateway_unbind_session_object(session_ob);
      } else {
        sess = gateway_find_session(session_key.c_str());
        if (!sess) {
          return 1;
        }
        gateway_release_command_input_pending(sess);
        gateway_release_command_task_pending(sess);
        gateway_discard_session_output_fifo(sess);
        gateway_untrack_session_output_fifo_budget(sess);
        g_gateway_sessions.erase(session_key);
      }
      return 1;
    }
    remove_interactive(ob, 0);
    return 1;
  }
  if (gateway_object_valid(ob)) {
    gateway_unbind_session_object(ob);
  } else {
    sess = gateway_find_session(session_key.c_str());
    if (!sess) {
      return 1;
    }
    gateway_release_command_input_pending(sess);
    gateway_release_command_task_pending(sess);
    gateway_discard_session_output_fifo(sess);
    gateway_untrack_session_output_fifo_budget(sess);
    g_gateway_sessions.erase(session_key);
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
      gateway_move_session_output_fifo_budget(sess, -1);
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
  auto *quiesced = gateway_owner_output_quiesce("gateway cleanup");
  free_mapping(quiesced);
  std::vector<std::string> session_ids;

  session_ids.reserve(g_gateway_sessions.size());
  for (const auto &entry : g_gateway_sessions) {
    session_ids.push_back(entry.first);
  }

  for (const auto &session_id : session_ids) {
    gateway_destroy_session_internal(session_id.c_str(), "gateway_cleanup", "gateway cleanup");
  }
  while (!g_gateway_room_output_waves.empty()) {
    gateway_abort_room_output_wave(g_gateway_room_output_waves.begin()->first,
                                   "gateway cleanup", nullptr);
  }
  g_gateway_room_output_retry_schedule.clear();

  for (const auto &entry : g_gateway_sessions) {
    gateway_discard_session_output_fifo(entry.second.get());
    gateway_untrack_session_output_fifo_budget(entry.second.get());
  }
  g_gateway_sessions.clear();
  g_gateway_obj_to_session.clear();
  g_gateway_master_output_fifo_wire_bytes.clear();
  g_gateway_detached_output_fifo_wire_bytes = 0;
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

  auto wire_output = gateway_prepare_session_send_wire(sess, std::move(payload));

  if (wire_output) {
    result = gateway_enqueue_session_wire_output(sess, std::move(*wire_output));
  }

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

void f_gateway_session_pending_reservation_has_ready_successor() {
  auto reservation_id = static_cast<uint64_t>(sp->u.number);
  auto *ob = (sp - 1)->u.ob;
  auto result =
      gateway_session_pending_reservation_has_ready_successor_for_object(
          ob, reservation_id);
  pop_2_elems();
  push_number(result);
}

void f_gateway_sessions_reserve_or_reuse() {
  auto *existing_ids = sp->u.arr;
  auto *targets = (sp - 1)->u.arr;
  std::vector<GatewaySession *> sessions;
  std::vector<uint64_t> requested_ids;
  GatewaySessionBatchReservationResult result;
  mapping_t *response;
  array_t *reservation_ids;
  array_t *reused;
  bool ok = false;

  if (targets && existing_ids && targets->size > 0 &&
      targets->size == existing_ids->size && vm_context_is_main_thread()) {
    sessions.reserve(static_cast<size_t>(targets->size));
    requested_ids.reserve(static_cast<size_t>(targets->size));
    ok = true;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      const auto *existing = &existing_ids->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob) ||
          existing->type != T_NUMBER || existing->u.number < 0) {
        ok = false;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        ok = false;
        break;
      }
      sessions.push_back(sess);
      requested_ids.push_back(static_cast<uint64_t>(existing->u.number));
    }
    if (ok) {
      ok = gateway_reserve_session_outputs(sessions, requested_ids, &result);
    }
  }

  reservation_ids = allocate_array(ok ? static_cast<int>(result.reservation_ids.size()) : 0);
  reused = allocate_array(ok ? static_cast<int>(result.reused.size()) : 0);
  if (ok) {
    for (size_t index = 0; index < result.reservation_ids.size(); ++index) {
      reservation_ids->item[index].type = T_NUMBER;
      reservation_ids->item[index].u.number =
          static_cast<LPC_INT>(result.reservation_ids[index]);
      reused->item[index].type = T_NUMBER;
      reused->item[index].u.number = result.reused[index] ? 1 : 0;
    }
  }

  response = allocate_mapping(3);
  add_mapping_pair(response, "ok", ok ? 1 : 0);
  add_mapping_array(response, "reservation_ids", reservation_ids);
  add_mapping_array(response, "reused", reused);
  free_array(reservation_ids);
  free_array(reused);
  pop_2_elems();
  push_refed_mapping(response);
}

void f_gateway_sessions_append_preencoded_message_event_wave() {
  const auto batch_limit = sp->u.number;
  const auto sent_at = (sp - 1)->u.number;
  auto *message_epochs = (sp - 2)->u.arr;
  auto *message_server_seqs = (sp - 3)->u.arr;
  auto *message_seqs = (sp - 4)->u.arr;
  const auto *scope_type = (sp - 5)->u.string;
  const auto scope_type_len = SVALUE_STRLEN(sp - 5);
  const auto *stable_json = (sp - 6)->u.string;
  const auto stable_json_len = SVALUE_STRLEN(sp - 6);
  auto *slot_server_seqs = (sp - 7)->u.arr;
  auto *reservation_ids = (sp - 8)->u.arr;
  auto *targets = (sp - 9)->u.arr;
  std::vector<GatewaySession *> sessions;
  std::vector<uint64_t> ids;
  std::vector<LPC_INT> slot_seqs;
  std::vector<LPC_INT> child_seqs;
  std::vector<LPC_INT> epochs;
  std::vector<LPC_INT> seqs;
  int result = 0;

  const auto append_ints = [](array_t *source, std::vector<LPC_INT> *target,
                              bool positive) {
    if (!source || !target || source->size <= 0) {
      return false;
    }
    target->reserve(static_cast<size_t>(source->size));
    for (int index = 0; index < source->size; ++index) {
      const auto *value = &source->item[index];
      if (value->type != T_NUMBER || (positive ? value->u.number <= 0
                                               : value->u.number < 0)) {
        return false;
      }
      target->push_back(value->u.number);
    }
    return true;
  };

  if (targets && reservation_ids && targets->size > 0 &&
      targets->size == reservation_ids->size && stable_json && stable_json_len > 0 &&
      scope_type && scope_type_len > 0 && sent_at > 0 && batch_limit > 0 &&
      vm_context_is_main_thread() && append_ints(slot_server_seqs, &slot_seqs, true) &&
      append_ints(message_server_seqs, &child_seqs, true) &&
      append_ints(message_epochs, &epochs, false) &&
      append_ints(message_seqs, &seqs, true) &&
      slot_seqs.size() == static_cast<size_t>(targets->size) &&
      child_seqs.size() == static_cast<size_t>(targets->size) &&
      epochs.size() == static_cast<size_t>(targets->size) &&
      seqs.size() == static_cast<size_t>(targets->size)) {
    sessions.reserve(static_cast<size_t>(targets->size));
    ids.reserve(static_cast<size_t>(targets->size));
    result = 1;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      const auto *reservation = &reservation_ids->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob) ||
          reservation->type != T_NUMBER || reservation->u.number <= 0) {
        result = 0;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        result = 0;
        break;
      }
      sessions.push_back(sess);
      ids.push_back(static_cast<uint64_t>(reservation->u.number));
    }
    if (result) {
      result = gateway_append_preencoded_message_event_wave(
          sessions, ids, slot_seqs, child_seqs, epochs, seqs,
          std::string(stable_json, stable_json_len),
          std::string(scope_type, scope_type_len), sent_at,
          static_cast<size_t>(batch_limit))
          ? 1
          : 0;
    }
  }

  pop_n_elems(10);
  push_number(result);
}

void f_gateway_sessions_reserve_and_append_preencoded_message_event_wave() {
  const auto batch_limit = sp->u.number;
  const auto sent_at = (sp - 1)->u.number;
  auto *message_epochs = (sp - 2)->u.arr;
  auto *message_seqs = (sp - 3)->u.arr;
  const auto *scope_type = (sp - 4)->u.string;
  const auto scope_type_len = SVALUE_STRLEN(sp - 4);
  const auto *stable_json = (sp - 5)->u.string;
  const auto stable_json_len = SVALUE_STRLEN(sp - 5);
  const auto first_server_seq = (sp - 6)->u.number;
  auto *existing_ids = (sp - 7)->u.arr;
  auto *targets = (sp - 8)->u.arr;
  std::vector<GatewaySession *> sessions;
  std::vector<uint64_t> requested_ids;
  std::vector<LPC_INT> epochs;
  std::vector<LPC_INT> seqs;
  GatewaySessionBatchReservationResult result;
  mapping_t *response;
  array_t *reservation_ids;
  array_t *reused;
  bool ok = false;

  const auto append_ints = [](array_t *source, std::vector<LPC_INT> *target,
                              bool positive) {
    if (!source || !target || source->size <= 0) {
      return false;
    }
    target->reserve(static_cast<size_t>(source->size));
    for (int index = 0; index < source->size; ++index) {
      const auto *value = &source->item[index];
      if (value->type != T_NUMBER || (positive ? value->u.number <= 0
                                               : value->u.number < 0)) {
        return false;
      }
      target->push_back(value->u.number);
    }
    return true;
  };

  if (targets && existing_ids && targets->size > 0 &&
      targets->size == existing_ids->size && stable_json &&
      stable_json_len > 0 && scope_type && scope_type_len > 0 && sent_at > 0 &&
      batch_limit > 0 && first_server_seq > 0 && vm_context_is_main_thread() &&
      append_ints(message_epochs, &epochs, false) &&
      append_ints(message_seqs, &seqs, true) &&
      epochs.size() == static_cast<size_t>(targets->size) &&
      seqs.size() == static_cast<size_t>(targets->size)) {
    sessions.reserve(static_cast<size_t>(targets->size));
    requested_ids.reserve(static_cast<size_t>(targets->size));
    ok = true;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      const auto *existing = &existing_ids->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob) ||
          existing->type != T_NUMBER || existing->u.number < 0) {
        ok = false;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        ok = false;
        break;
      }
      sessions.push_back(sess);
      requested_ids.push_back(static_cast<uint64_t>(existing->u.number));
    }
    if (ok) {
      ok = gateway_reserve_and_append_preencoded_message_event_wave(
          sessions, requested_ids, first_server_seq, epochs, seqs,
          std::string(stable_json, stable_json_len),
          std::string(scope_type, scope_type_len), sent_at,
          static_cast<size_t>(batch_limit), &result);
    }
  }

  reservation_ids =
      allocate_array(ok ? static_cast<int>(result.reservation_ids.size()) : 0);
  reused = allocate_array(ok ? static_cast<int>(result.reused.size()) : 0);
  if (ok) {
    for (size_t index = 0; index < result.reservation_ids.size(); ++index) {
      reservation_ids->item[index].type = T_NUMBER;
      reservation_ids->item[index].u.number =
          static_cast<LPC_INT>(result.reservation_ids[index]);
      reused->item[index].type = T_NUMBER;
      reused->item[index].u.number = result.reused[index] ? 1 : 0;
    }
  }
  response = allocate_mapping(4);
  add_mapping_pair(response, "ok", ok ? 1 : 0);
  add_mapping_array(response, "reservation_ids", reservation_ids);
  add_mapping_array(response, "reused", reused);
  add_mapping_pair(response, "wave_id",
                   ok ? static_cast<LPC_INT>(result.wave_id) : 0);
  free_array(reservation_ids);
  free_array(reused);
  pop_n_elems(9);
  push_refed_mapping(response);
}

void f_gateway_sessions_rollback_preencoded_message_event_wave() {
  const auto wave_id = static_cast<uint64_t>(sp->u.number);
  auto *reused = (sp - 1)->u.arr;
  auto *reservation_ids = (sp - 2)->u.arr;
  auto *targets = (sp - 3)->u.arr;
  std::vector<GatewaySession *> sessions;
  std::vector<uint64_t> ids;
  std::vector<bool> reuse_flags;
  int result = 0;

  if (targets && reservation_ids && reused && targets->size > 0 &&
      targets->size == reservation_ids->size && targets->size == reused->size &&
      wave_id > 0 && vm_context_is_main_thread()) {
    sessions.reserve(static_cast<size_t>(targets->size));
    ids.reserve(static_cast<size_t>(targets->size));
    reuse_flags.reserve(static_cast<size_t>(targets->size));
    result = 1;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      const auto *reservation = &reservation_ids->item[index];
      const auto *reuse = &reused->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob) ||
          reservation->type != T_NUMBER || reservation->u.number <= 0 ||
          reuse->type != T_NUMBER ||
          (reuse->u.number != 0 && reuse->u.number != 1)) {
        result = 0;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        result = 0;
        break;
      }
      sessions.push_back(sess);
      ids.push_back(static_cast<uint64_t>(reservation->u.number));
      reuse_flags.push_back(reuse->u.number == 1);
    }
    if (result) {
      result = gateway_rollback_preencoded_message_event_wave_with_writer(
          sessions, ids, reuse_flags, wave_id, gateway_send_raw_to_fd)
          ? 1
          : 0;
    }
  }
  pop_n_elems(4);
  push_number(result);
}

void f_gateway_sessions_reserve_and_append_compact_preencoded_message_event_wave() {
  const auto text_length = sp->u.number;
  const auto batch_limit = (sp - 1)->u.number;
  const auto sent_at = (sp - 2)->u.number;
  auto *message_epochs = (sp - 3)->u.arr;
  auto *message_seqs = (sp - 4)->u.arr;
  const auto *scope_type = (sp - 5)->u.string;
  const auto scope_type_len = SVALUE_STRLEN(sp - 5);
  const auto *stable_json = (sp - 6)->u.string;
  const auto stable_json_len = SVALUE_STRLEN(sp - 6);
  const auto first_server_seq = (sp - 7)->u.number;
  auto *targets = (sp - 8)->u.arr;
  std::vector<GatewaySession *> sessions;
  std::vector<LPC_INT> epochs;
  std::vector<LPC_INT> seqs;
  GatewaySessionCompactMessageEventWaveResult result;
  mapping_t *response;
  array_t *created_indices;
  array_t *created_ids;
  array_t *created_slot_seqs;
  array_t *full_indices;
  bool ok = false;

  const auto append_ints = [](array_t *source, std::vector<LPC_INT> *target,
                              bool positive) {
    if (!source || !target || source->size <= 0) {
      return false;
    }
    target->reserve(static_cast<size_t>(source->size));
    for (int index = 0; index < source->size; ++index) {
      const auto *value = &source->item[index];
      if (value->type != T_NUMBER ||
          (positive ? value->u.number <= 0 : value->u.number < 0)) {
        return false;
      }
      target->push_back(value->u.number);
    }
    return true;
  };

  if (targets && targets->size > 0 && stable_json && stable_json_len > 0 &&
      scope_type && scope_type_len > 0 && first_server_seq > 0 && sent_at > 0 &&
      batch_limit > 0 && text_length > 0 && vm_context_is_main_thread() &&
      append_ints(message_epochs, &epochs, false) &&
      append_ints(message_seqs, &seqs, true) &&
      epochs.size() == static_cast<size_t>(targets->size) &&
      seqs.size() == static_cast<size_t>(targets->size)) {
    sessions.reserve(static_cast<size_t>(targets->size));
    ok = true;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob)) {
        ok = false;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        ok = false;
        break;
      }
      sessions.push_back(sess);
    }
    if (ok) {
      ok = gateway_reserve_and_append_compact_preencoded_message_event_wave(
          sessions, first_server_seq, epochs, seqs,
          std::string(stable_json, stable_json_len),
          std::string(scope_type, scope_type_len), sent_at,
          static_cast<size_t>(batch_limit), static_cast<size_t>(text_length),
          &result);
    }
  }

  const auto created_count =
      ok ? static_cast<int>(result.created_indices.size()) : 0;
  const auto full_count = ok ? static_cast<int>(result.full_indices.size()) : 0;
  created_indices = allocate_array(created_count);
  created_ids = allocate_array(created_count);
  created_slot_seqs = allocate_array(created_count);
  full_indices = allocate_array(full_count);
  for (int index = 0; index < created_count; ++index) {
    created_indices->item[index].type = T_NUMBER;
    created_indices->item[index].u.number =
        static_cast<LPC_INT>(result.created_indices[index]);
    created_ids->item[index].type = T_NUMBER;
    created_ids->item[index].u.number =
        static_cast<LPC_INT>(result.created_reservation_ids[index]);
    created_slot_seqs->item[index].type = T_NUMBER;
    created_slot_seqs->item[index].u.number =
        result.created_slot_server_seqs[index];
  }
  for (int index = 0; index < full_count; ++index) {
    full_indices->item[index].type = T_NUMBER;
    full_indices->item[index].u.number =
        static_cast<LPC_INT>(result.full_indices[index]);
  }
  response = allocate_mapping(8);
  add_mapping_pair(response, "ok", ok ? 1 : 0);
  add_mapping_array(response, "created_indices", created_indices);
  add_mapping_array(response, "created_reservation_ids", created_ids);
  add_mapping_array(response, "created_slot_server_seqs", created_slot_seqs);
  add_mapping_array(response, "full_indices", full_indices);
  add_mapping_pair(response, "created_count", created_count);
  add_mapping_pair(response, "reused_count",
                   ok ? static_cast<LPC_INT>(result.reused_count) : 0);
  add_mapping_pair(response, "wave_id",
                   ok ? static_cast<LPC_INT>(result.wave_id) : 0);
  free_array(created_indices);
  free_array(created_ids);
  free_array(created_slot_seqs);
  free_array(full_indices);
  pop_n_elems(9);
  push_refed_mapping(response);
}

void f_gateway_sessions_commit_compact_preencoded_message_event_wave() {
  const auto wave_id = static_cast<uint64_t>(sp->u.number);
  auto *targets = (sp - 1)->u.arr;
  std::vector<GatewaySession *> sessions;
  int result = 0;
  if (targets && targets->size > 0 && wave_id > 0 &&
      vm_context_is_main_thread()) {
    sessions.reserve(static_cast<size_t>(targets->size));
    result = 1;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob)) {
        result = 0;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        result = 0;
        break;
      }
      sessions.push_back(sess);
    }
    if (result) {
      result = gateway_commit_compact_preencoded_message_event_wave(
                   sessions, wave_id)
          ? 1
          : 0;
    }
  }
  pop_n_elems(2);
  push_number(result);
}

void f_gateway_sessions_rollback_compact_preencoded_message_event_wave() {
  const auto wave_id = static_cast<uint64_t>(sp->u.number);
  auto *targets = (sp - 1)->u.arr;
  std::vector<GatewaySession *> sessions;
  int result = 0;
  if (targets && targets->size > 0 && wave_id > 0 &&
      vm_context_is_main_thread()) {
    sessions.reserve(static_cast<size_t>(targets->size));
    result = 1;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob)) {
        result = 0;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        result = 0;
        break;
      }
      sessions.push_back(sess);
    }
    if (result) {
      result = gateway_rollback_compact_preencoded_message_event_wave_with_writer(
                   sessions, wave_id, gateway_send_raw_to_fd)
          ? 1
          : 0;
    }
  }
  pop_n_elems(2);
  push_number(result);
}

void f_gateway_session_pending_message_event_batch_status() {
  const auto reservation_id = static_cast<uint64_t>(sp->u.number);
  auto *ob = (sp - 1)->u.ob;
  GatewayPendingMessageEventBatchStatus status;
  mapping_t *response;
  auto *sess = gateway_find_session_by_object(ob);
  const auto ok = vm_context_is_main_thread() && sess && reservation_id > 0 &&
                  gateway_pending_message_event_batch_status(
                      sess, reservation_id, &status);
  response = allocate_mapping(6);
  add_mapping_pair(response, "ok", ok ? 1 : 0);
  add_mapping_pair(response, "event_count",
                   ok ? static_cast<LPC_INT>(status.event_count) : 0);
  add_mapping_pair(response, "text_length_total",
                   ok ? static_cast<LPC_INT>(status.text_length_total) : 0);
  add_mapping_pair(response, "created_at_ns",
                   ok ? static_cast<LPC_INT>(status.created_at_ns) : 0);
  add_mapping_pair(response, "last_append_at_ns",
                   ok ? static_cast<LPC_INT>(status.last_append_at_ns) : 0);
  add_mapping_pair(response, "registered", ok && status.registered ? 1 : 0);
  pop_n_elems(2);
  push_refed_mapping(response);
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

void f_gateway_session_fill_preencoded_message_event_batch() {
  const auto slot_sent_at = sp->u.number;
  const auto slot_epoch = (sp - 1)->u.number;
  const auto slot_server_seq = (sp - 2)->u.number;
  auto *sent_ats = (sp - 3)->u.arr;
  auto *message_epochs = (sp - 4)->u.arr;
  auto *server_seqs = (sp - 5)->u.arr;
  auto *message_seqs = (sp - 6)->u.arr;
  const auto *scope_id = (sp - 7)->u.string;
  const auto scope_id_len = SVALUE_STRLEN(sp - 7);
  auto *scope_types = (sp - 8)->u.arr;
  auto *stable_children = (sp - 9)->u.arr;
  const auto reservation_id = static_cast<uint64_t>((sp - 10)->u.number);
  auto *ob = (sp - 11)->u.ob;
  std::vector<std::string_view> stable_children_json;
  std::vector<std::string_view> scope_type_values;
  std::vector<LPC_INT> message_seq_values;
  std::vector<LPC_INT> server_seq_values;
  std::vector<LPC_INT> message_epoch_values;
  std::vector<LPC_INT> sent_at_values;
  std::string frame;
  int result = 0;

  const auto append_strings = [](array_t *source,
                                 std::vector<std::string_view> *target) {
    if (!source || !target || source->size <= 0) {
      return false;
    }
    target->reserve(static_cast<size_t>(source->size));
    for (int index = 0; index < source->size; ++index) {
      const auto *value = &source->item[index];
      if (value->type != T_STRING || !value->u.string) {
        target->clear();
        return false;
      }
      target->emplace_back(value->u.string, SVALUE_STRLEN(value));
    }
    return true;
  };
  const auto append_ints = [](array_t *source, std::vector<LPC_INT> *target) {
    if (!source || !target || source->size <= 0) {
      return false;
    }
    target->reserve(static_cast<size_t>(source->size));
    for (int index = 0; index < source->size; ++index) {
      const auto *value = &source->item[index];
      if (value->type != T_NUMBER) {
        target->clear();
        return false;
      }
      target->push_back(value->u.number);
    }
    return true;
  };

  if (scope_id && scope_id_len > 0 && vm_context_is_main_thread() &&
      append_strings(stable_children, &stable_children_json) &&
      append_strings(scope_types, &scope_type_values) &&
      append_ints(message_seqs, &message_seq_values) &&
      append_ints(server_seqs, &server_seq_values) &&
      append_ints(message_epochs, &message_epoch_values) &&
      append_ints(sent_ats, &sent_at_values) &&
      gateway_build_preencoded_message_event_batch_frame(
          stable_children_json, scope_type_values,
          std::string_view(scope_id, scope_id_len), message_seq_values,
          server_seq_values, message_epoch_values, sent_at_values,
          slot_server_seq, slot_epoch, slot_sent_at, &frame)) {
    result = gateway_fill_session_output_for_object(
        ob, reservation_id, frame.data(), frame.size());
  }

  pop_n_elems(12);
  push_number(result);
}

void f_gateway_session_fill_pending_message_event_batch() {
  const auto slot_epoch = sp->u.number;
  const auto *scope_id = (sp - 1)->u.string;
  const auto scope_id_len = SVALUE_STRLEN(sp - 1);
  const auto reservation_id = static_cast<uint64_t>((sp - 2)->u.number);
  auto *ob = (sp - 3)->u.ob;
  const auto result = gateway_fill_pending_message_event_batch_for_object(
      ob, reservation_id, scope_id, scope_id_len, slot_epoch);
  pop_n_elems(4);
  push_number(result);
}

void f_gateway_sessions_fill_pending_message_event_batches() {
  auto *slot_epochs = sp->u.arr;
  auto *scope_ids = (sp - 1)->u.arr;
  auto *reservation_ids = (sp - 2)->u.arr;
  auto *targets = (sp - 3)->u.arr;
  std::vector<GatewaySession *> sessions;
  std::vector<uint64_t> ids;
  std::vector<std::string> scopes;
  std::vector<LPC_INT> epochs;
  GatewayPendingMessageEventBatchFillResult result;
  mapping_t *response;
  array_t *filled;
  array_t *event_counts;
  array_t *text_length_totals;
  array_t *slot_server_seqs;
  bool ok = false;

  if (targets && reservation_ids && scope_ids && slot_epochs && targets->size > 0 &&
      reservation_ids->size == targets->size && scope_ids->size == targets->size &&
      slot_epochs->size == targets->size && vm_context_is_main_thread()) {
    const auto count = static_cast<size_t>(targets->size);
    sessions.reserve(count);
    ids.reserve(count);
    scopes.reserve(count);
    epochs.reserve(count);
    ok = true;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      const auto *reservation = &reservation_ids->item[index];
      const auto *scope = &scope_ids->item[index];
      const auto *epoch = &slot_epochs->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob) ||
          reservation->type != T_NUMBER || reservation->u.number <= 0 ||
          scope->type != T_STRING || !scope->u.string || SVALUE_STRLEN(scope) == 0 ||
          epoch->type != T_NUMBER || epoch->u.number < 0) {
        ok = false;
        break;
      }
      auto *sess = gateway_find_session_by_object(target->u.ob);
      if (!sess) {
        ok = false;
        break;
      }
      sessions.push_back(sess);
      ids.push_back(static_cast<uint64_t>(reservation->u.number));
      scopes.emplace_back(scope->u.string, SVALUE_STRLEN(scope));
      epochs.push_back(epoch->u.number);
    }
    if (ok) {
      ok = gateway_fill_pending_message_event_batches_with_writer(
          sessions, ids, scopes, epochs, gateway_send_raw_to_fd, &result);
    }
  }

  const auto result_count = ok ? static_cast<int>(result.filled.size()) : 0;
  filled = allocate_array(result_count);
  event_counts = allocate_array(result_count);
  text_length_totals = allocate_array(result_count);
  slot_server_seqs = allocate_array(result_count);
  for (int index = 0; index < result_count; ++index) {
    filled->item[index].type = T_NUMBER;
    filled->item[index].u.number = result.filled[index] ? 1 : 0;
    event_counts->item[index].type = T_NUMBER;
    event_counts->item[index].u.number = result.event_counts[index];
    text_length_totals->item[index].type = T_NUMBER;
    text_length_totals->item[index].u.number =
        result.text_length_totals[index];
    slot_server_seqs->item[index].type = T_NUMBER;
    slot_server_seqs->item[index].u.number = result.slot_server_seqs[index];
  }
  response = allocate_mapping(5);
  add_mapping_pair(response, "ok", ok ? 1 : 0);
  add_mapping_array(response, "filled", filled);
  add_mapping_array(response, "event_counts", event_counts);
  add_mapping_array(response, "text_length_totals", text_length_totals);
  add_mapping_array(response, "slot_server_seqs", slot_server_seqs);
  free_array(filled);
  free_array(event_counts);
  free_array(text_length_totals);
  free_array(slot_server_seqs);
  pop_n_elems(4);
  push_refed_mapping(response);
}

void f_gateway_sessions_submit_pending_message_event_batches() {
  const auto timeout_ms = static_cast<int>(sp->u.number);
  auto *slot_epochs = (sp - 1)->u.arr;
  auto *scope_ids = (sp - 2)->u.arr;
  auto *reservation_ids = (sp - 3)->u.arr;
  auto *targets = (sp - 4)->u.arr;
  std::vector<object_t *> target_objects;
  std::vector<uint64_t> ids;
  std::vector<std::string> scopes;
  std::vector<LPC_INT> epochs;
  GatewayPendingMessageEventBatchOwnerSubmitResult result;
  bool ok = false;

  if (targets && reservation_ids && scope_ids && slot_epochs &&
      targets->size > 0 && reservation_ids->size == targets->size &&
      scope_ids->size == targets->size &&
      slot_epochs->size == targets->size && timeout_ms > 0 &&
      vm_context_is_main_thread()) {
    const auto count = static_cast<size_t>(targets->size);
    target_objects.reserve(count);
    ids.reserve(count);
    scopes.reserve(count);
    epochs.reserve(count);
    ok = true;
    for (int index = 0; index < targets->size; ++index) {
      const auto *target = &targets->item[index];
      const auto *reservation = &reservation_ids->item[index];
      const auto *scope = &scope_ids->item[index];
      const auto *epoch = &slot_epochs->item[index];
      if (target->type != T_OBJECT || !gateway_object_valid(target->u.ob) ||
          reservation->type != T_NUMBER || reservation->u.number <= 0 ||
          scope->type != T_STRING || !scope->u.string ||
          SVALUE_STRLEN(scope) == 0 || epoch->type != T_NUMBER ||
          epoch->u.number < 0) {
        ok = false;
        break;
      }
      target_objects.push_back(target->u.ob);
      ids.push_back(static_cast<uint64_t>(reservation->u.number));
      scopes.emplace_back(scope->u.string, SVALUE_STRLEN(scope));
      epochs.push_back(epoch->u.number);
    }
    if (ok) {
      ok = gateway_submit_pending_message_event_batches_for_objects(
          target_objects, ids, scopes, epochs, timeout_ms, &result);
    }
  }

  const auto result_count =
      ok ? static_cast<int>(result.submitted.size()) : 0;
  auto *submitted = allocate_array(result_count);
  auto *filled_inline = allocate_array(result_count);
  auto *event_counts = allocate_array(result_count);
  auto *text_length_totals = allocate_array(result_count);
  auto *slot_server_seqs = allocate_array(result_count);
  auto *future_ids = allocate_array(result_count);
  for (int index = 0; index < result_count; ++index) {
    submitted->item[index].type = T_NUMBER;
    submitted->item[index].u.number = result.submitted[index] ? 1 : 0;
    filled_inline->item[index].type = T_NUMBER;
    filled_inline->item[index].u.number =
        result.filled_inline[index] ? 1 : 0;
    event_counts->item[index].type = T_NUMBER;
    event_counts->item[index].u.number = result.event_counts[index];
    text_length_totals->item[index].type = T_NUMBER;
    text_length_totals->item[index].u.number =
        result.text_length_totals[index];
    slot_server_seqs->item[index].type = T_NUMBER;
    slot_server_seqs->item[index].u.number =
        result.slot_server_seqs[index];
    future_ids->item[index].type = T_NUMBER;
    future_ids->item[index].u.number =
        static_cast<LPC_INT>(result.future_ids[index]);
  }
  auto *response = allocate_mapping(7);
  add_mapping_pair(response, "ok", ok ? 1 : 0);
  add_mapping_array(response, "submitted", submitted);
  add_mapping_array(response, "filled_inline", filled_inline);
  add_mapping_array(response, "event_counts", event_counts);
  add_mapping_array(response, "text_length_totals", text_length_totals);
  add_mapping_array(response, "slot_server_seqs", slot_server_seqs);
  add_mapping_array(response, "future_ids", future_ids);
  free_array(submitted);
  free_array(filled_inline);
  free_array(event_counts);
  free_array(text_length_totals);
  free_array(slot_server_seqs);
  free_array(future_ids);
  pop_n_elems(5);
  push_refed_mapping(response);
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

void f_gateway_owner_output_quiesce() {
  auto *result = gateway_owner_output_quiesce(
      "gateway owner output quiesce efun");
  push_refed_mapping(result);
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

  map = allocate_mapping(20);
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
  add_mapping_pair(map, "session_fifo_wire_bytes",
                   static_cast<long>(sess->output_fifo_wire_bytes));
  add_mapping_pair(
      map, "session_fifo_wire_limit_bytes",
      static_cast<long>(gateway_session_output_fifo_wire_limit(sess)));
  add_mapping_pair(
      map, "session_fifo_wire_bytes_rejected",
      static_cast<long>(sess->output_fifo_wire_bytes_rejected));
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
