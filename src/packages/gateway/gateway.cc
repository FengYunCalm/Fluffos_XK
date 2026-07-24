#include "base/package_api.h"

#include "gateway.h"

#include "backend.h"
#include "base/internal/port.h"
#include "base/internal/rc.h"
#include "vm/context.h"
#include "vm/owner.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

int g_gateway_debug = 0;
size_t g_gateway_max_packet_size = 1024 * 1024;
int g_gateway_max_masters = 16;
int g_gateway_max_sessions = 4096;
int g_gateway_heartbeat_interval = 15;
int g_gateway_heartbeat_timeout = 45;
int g_gateway_reconnect_grace = 60;
GatewayRuntimeCounters g_gateway_runtime_counters;

namespace {
constexpr int kGatewayDefaultMaxMasters = 16;
constexpr int kGatewayDefaultHeartbeatInterval = 15;
constexpr int kGatewayDefaultHeartbeatTimeout = 45;
constexpr int kGatewayDefaultReconnectGrace = 60;
constexpr int kGatewayMaxJsonDepth = 20;
// Read admission is cheap once gateway_receive execution is deferred to the
// owner main queue. Admit a useful cross-session batch before the fair owner
// drain, while keeping a hard bound for malformed or unbounded masters.
constexpr int kGatewayReadFrameBudget = 128;
// Cap admitted owner-main work before socket reads can outrun the fair drain.
// The gap between high and low watermarks is one deferred drain quantum, which
// avoids toggling EV_READ for every completed task under a synchronized wave.
constexpr long kGatewayMainQueueReadHighWatermark = 96;
constexpr long kGatewayMainQueueReadLowWatermark = 32;
// A zero-delay event_base_once callback is made active immediately. A
// self-rescheduling backlog can therefore keep due timeout callbacks behind
// its active queue; one millisecond returns this continuation to the timer
// queue without changing per-master FIFO or the frame budget.
constexpr auto kGatewayReadContinuationDelay = std::chrono::milliseconds(1);
constexpr int kGatewayReadBatchMainDrainBudget = 32;
constexpr auto kGatewayReadBatchMainDrainWallBudget = std::chrono::milliseconds(12);
constexpr int kGatewayDeferredMainDrainBudget = 64;
// Keep the read callback's first-service slice small, but let the timer-queue
// continuation retire a useful backlog quantum without returning every few
// tasks. The positive delay still gives socket, flush and timer callbacks a
// Libevent scheduling point between deferred quanta.
constexpr auto kGatewayDeferredMainDrainBaseWallBudget = std::chrono::milliseconds(24);
constexpr auto kGatewayDeferredMainDrainBacklogWallBudget = std::chrono::milliseconds(48);
constexpr long kGatewayDeferredMainDrainBacklogThreshold = 64;
constexpr auto kGatewayDeferredMainDrainContinuationDelay = std::chrono::milliseconds(1);
constexpr int kGatewayDeferredMainDrainWaitTimerQueueOnly = 1;

evconnlistener *g_gateway_listener = nullptr;
event *g_gateway_heartbeat_timer = nullptr;
std::unordered_map<int, std::unique_ptr<GatewayMaster>> g_gateway_masters;
std::atomic<long> g_gateway_read_dispatch_pending_masters{0};
int g_gateway_next_fd = 1;
int g_gateway_listen_port = 0;
time_t g_gateway_started_at = 0;
bool g_gateway_main_drain_scheduled = false;
TickEvent *g_gateway_main_drain_event = nullptr;

void gateway_handle_hello(int fd, const nlohmann::json &msg);
void gateway_handle_login(int fd, const nlohmann::json &msg);
void gateway_handle_data(int fd, const nlohmann::json &msg);
void gateway_handle_discon(int fd, const nlohmann::json &msg);
void gateway_handle_sys(int fd, const nlohmann::json &msg);
int gateway_dispatch_buffered_frames(GatewayMaster *master, int budget);
void gateway_schedule_buffered_read(int fd);
int gateway_main_queue_admission_budget(int budget);
void gateway_pause_all_reads_for_main_queue_pressure();
void gateway_resume_main_queue_reads_if_below_low_watermark();

void gateway_stop_heartbeat_timer();
int gateway_start_heartbeat_timer();

bool gateway_object_valid_local(object_t *ob) {
  return ob && !(ob->flags & O_DESTRUCTED) && ob->obname && ob->obname[0] != '\0';
}

uint64_t gateway_now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

void gateway_record_max(std::atomic<uint64_t> &counter, uint64_t value) {
  auto current = counter.load(std::memory_order_relaxed);
  while (value > current && !counter.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
  }
}

void gateway_record_latency(std::atomic<uint64_t> &total, std::atomic<uint64_t> &max,
                            std::atomic<uint64_t> &samples, uint64_t elapsed_ns) {
  total.fetch_add(elapsed_ns, std::memory_order_relaxed);
  samples.fetch_add(1, std::memory_order_relaxed);
  gateway_record_max(max, elapsed_ns);
}

void gateway_record_thread_cpu(std::atomic<uint64_t> &total, std::atomic<uint64_t> &max,
                               std::atomic<uint64_t> &samples,
                               std::atomic<uint64_t> &unavailable, int64_t started_ns) {
  auto finished_ns = get_current_thread_cpu_time_ns();
  if (started_ns < 0 || finished_ns < started_ns) {
    unavailable.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  auto elapsed_ns = static_cast<uint64_t>(finished_ns - started_ns);
  total.fetch_add(elapsed_ns, std::memory_order_relaxed);
  samples.fetch_add(1, std::memory_order_relaxed);
  gateway_record_max(max, elapsed_ns);
}

void gateway_enable_master_tcp_nodelay(evutil_socket_t fd) {
  int one = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
#ifndef _WIN32
                 &one,
#else
                 reinterpret_cast<const char *>(&one),
#endif
                 sizeof(one)) == 0) {
    g_gateway_runtime_counters.master_tcp_nodelay_enabled.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  g_gateway_runtime_counters.master_tcp_nodelay_failed.fetch_add(1, std::memory_order_relaxed);
}

long gateway_avg_us(const std::atomic<uint64_t> &total, const std::atomic<uint64_t> &samples) {
  auto sample_count = samples.load(std::memory_order_relaxed);
  if (sample_count == 0) {
    return 0;
  }
  return static_cast<long>((total.load(std::memory_order_relaxed) / sample_count) / 1000);
}

long gateway_avg_value(const std::atomic<uint64_t> &total, const std::atomic<uint64_t> &samples) {
  auto sample_count = samples.load(std::memory_order_relaxed);
  if (sample_count == 0) {
    return 0;
  }
  return static_cast<long>(total.load(std::memory_order_relaxed) / sample_count);
}

long gateway_max_us(const std::atomic<uint64_t> &max) {
  return static_cast<long>(max.load(std::memory_order_relaxed) / 1000);
}

void gateway_add_latency_fields(mapping_t *map, const char *prefix,
                                const std::atomic<uint64_t> &total,
                                const std::atomic<uint64_t> &max,
                                const std::atomic<uint64_t> &samples) {
  auto field_prefix = std::string(prefix);
  add_mapping_pair(map, (field_prefix + "_samples").c_str(),
                   static_cast<long>(samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, (field_prefix + "_total_us").c_str(),
                   static_cast<long>(total.load(std::memory_order_relaxed) / 1000));
  add_mapping_pair(map, (field_prefix + "_max_us").c_str(), gateway_max_us(max));
}

void gateway_record_main_drain(const VMOwnerMainDrainResult &result, int budget) {
  g_gateway_runtime_counters.main_drain_runs.fetch_add(1, std::memory_order_relaxed);
  g_gateway_runtime_counters.main_drain_tasks_total.fetch_add(static_cast<uint64_t>(result.dispatched),
                                                              std::memory_order_relaxed);
  gateway_record_max(g_gateway_runtime_counters.main_drain_tasks_max,
                     static_cast<uint64_t>(result.dispatched));
  if (result.dispatched >= budget) {
    g_gateway_runtime_counters.main_drain_budget_hits.fetch_add(1, std::memory_order_relaxed);
  }
}

VMOwnerMainDrainResult gateway_drain_owner_main_tasks_with_budget(
    int budget, std::chrono::nanoseconds wall_budget) {
  auto result = vm_owner_drain_main_tasks_with_budget(
      budget, static_cast<uint64_t>(std::max<int64_t>(0, wall_budget.count())));
  gateway_record_main_drain(result, budget);
  return result;
}

int gateway_drain_owner_main_tasks_now(int budget) {
  return gateway_drain_owner_main_tasks_with_budget(
             budget, std::chrono::nanoseconds(0))
      .dispatched;
}

std::chrono::nanoseconds gateway_deferred_main_drain_wall_budget(long backlog) {
  return backlog >= kGatewayDeferredMainDrainBacklogThreshold
             ? kGatewayDeferredMainDrainBacklogWallBudget
             : kGatewayDeferredMainDrainBaseWallBudget;
}

std::shared_ptr<svalue_t> gateway_copy_svalue(svalue_t *value, const char *tag) {
  if (!value) {
    return nullptr;
  }

  auto payload = std::shared_ptr<svalue_t>(new svalue_t{}, [tag](svalue_t *copied) {
    free_svalue(copied, tag ? tag : "gateway_payload");
    delete copied;
  });
  assign_svalue_no_free(payload.get(), value);
  return payload;
}

void gateway_drain_owner_main_tasks_later() {
  if (!g_event_base) {
    return;
  }
  if (g_gateway_main_drain_scheduled) {
    g_gateway_runtime_counters.main_drain_deferred_coalesced.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  g_gateway_main_drain_scheduled = true;
  g_gateway_runtime_counters.main_drain_deferred_scheduled.fetch_add(1, std::memory_order_relaxed);
  auto scheduled_at = gateway_now_ns();
  g_gateway_main_drain_event = add_walltime_event(
      kGatewayDeferredMainDrainContinuationDelay, [scheduled_at] {
    auto callback_started_at = gateway_now_ns();
    g_gateway_main_drain_event = nullptr;
    g_gateway_main_drain_scheduled = false;
    g_gateway_runtime_counters.main_drain_deferred_executed.fetch_add(1, std::memory_order_relaxed);
    auto backlog_before = std::max<long>(0, vm_owner_main_queue_total_depth());
    auto wall_budget = gateway_deferred_main_drain_wall_budget(backlog_before);
    if (backlog_before >= kGatewayDeferredMainDrainBacklogThreshold) {
      g_gateway_runtime_counters.main_drain_deferred_backlog_boosted.fetch_add(
          1, std::memory_order_relaxed);
    }
    auto drain_result = gateway_drain_owner_main_tasks_with_budget(
        kGatewayDeferredMainDrainBudget, wall_budget);
    g_gateway_runtime_counters.main_drain_deferred_tasks_total.fetch_add(
        static_cast<uint64_t>(drain_result.dispatched), std::memory_order_relaxed);
    gateway_record_max(g_gateway_runtime_counters.main_drain_deferred_tasks_max,
                       static_cast<uint64_t>(drain_result.dispatched));
    gateway_record_latency(g_gateway_runtime_counters.main_drain_deferred_wall_ns_total,
                           g_gateway_runtime_counters.main_drain_deferred_wall_ns_max,
                           g_gateway_runtime_counters.main_drain_deferred_wall_samples,
                           drain_result.elapsed_ns);
    gateway_record_max(
        g_gateway_runtime_counters.main_drain_deferred_main_task_wall_ns_max,
        drain_result.max_main_task_elapsed_ns);
    g_gateway_runtime_counters.main_drain_deferred_main_tasks_exceeding_wall_budget.fetch_add(
        static_cast<uint64_t>(drain_result.main_tasks_exceeding_wall_budget),
        std::memory_order_relaxed);
    if (drain_result.wall_budget_yielded) {
      g_gateway_runtime_counters.main_drain_deferred_wall_budget_yields.fetch_add(
          1, std::memory_order_relaxed);
    }
    if (drain_result.task_budget_yielded) {
      g_gateway_runtime_counters.main_drain_deferred_task_budget_yields.fetch_add(
          1, std::memory_order_relaxed);
    }
    auto remaining = static_cast<uint64_t>(
        std::max<long>(0, drain_result.remaining_main_tasks));
    g_gateway_runtime_counters.main_drain_deferred_remaining_total.fetch_add(
        remaining, std::memory_order_relaxed);
    g_gateway_runtime_counters.main_drain_deferred_remaining_samples.fetch_add(
        1, std::memory_order_relaxed);
    gateway_record_max(g_gateway_runtime_counters.main_drain_deferred_remaining_max,
                       remaining);
    if (drain_result.dispatched > 0) {
      gateway_record_latency(g_gateway_runtime_counters.main_drain_deferred_wait_ns_total,
                             g_gateway_runtime_counters.main_drain_deferred_wait_ns_max,
                             g_gateway_runtime_counters.main_drain_deferred_wait_samples,
                             callback_started_at - scheduled_at);
    }
    if (drain_result.remaining_main_tasks > 0 ||
        drain_result.remaining_cleanup_tasks > 0) {
      gateway_drain_owner_main_tasks_later();
    }
    gateway_resume_main_queue_reads_if_below_low_watermark();
  }, BackendEventPriority::kGateway);
}

void gateway_service_admitted_receive_tasks() {
  if (!g_event_base) {
    return;
  }

  // The read callback has already admitted a bounded cross-session batch, so
  // one count-and-wall bounded drain here preserves per-owner round-robin,
  // guarantees prompt first service, and returns to Libevent before a costly
  // admitted batch monopolizes the current callback.
  auto drain_result = gateway_drain_owner_main_tasks_with_budget(
      kGatewayReadBatchMainDrainBudget, kGatewayReadBatchMainDrainWallBudget);
  g_gateway_runtime_counters.read_batch_drain_runs.fetch_add(1,
                                                              std::memory_order_relaxed);
  g_gateway_runtime_counters.read_batch_drain_tasks_total.fetch_add(
      static_cast<uint64_t>(drain_result.dispatched), std::memory_order_relaxed);
  gateway_record_max(g_gateway_runtime_counters.read_batch_drain_tasks_max,
                     static_cast<uint64_t>(drain_result.dispatched));
  gateway_record_latency(g_gateway_runtime_counters.read_batch_drain_wall_ns_total,
                         g_gateway_runtime_counters.read_batch_drain_wall_ns_max,
                         g_gateway_runtime_counters.read_batch_drain_wall_samples,
                         drain_result.elapsed_ns);
  if (drain_result.wall_budget_yielded) {
    g_gateway_runtime_counters.read_batch_drain_wall_budget_yields.fetch_add(
        1, std::memory_order_relaxed);
  }
  if (drain_result.task_budget_yielded) {
    g_gateway_runtime_counters.read_batch_drain_task_budget_yields.fetch_add(
        1, std::memory_order_relaxed);
  }
  auto remaining = static_cast<uint64_t>(
      std::max<long>(0, drain_result.remaining_main_tasks));
  g_gateway_runtime_counters.read_batch_drain_remaining_total.fetch_add(
      remaining, std::memory_order_relaxed);
  g_gateway_runtime_counters.read_batch_drain_remaining_samples.fetch_add(
      1, std::memory_order_relaxed);
  gateway_record_max(g_gateway_runtime_counters.read_batch_drain_remaining_max,
                     remaining);
  gateway_record_max(
      g_gateway_runtime_counters.read_batch_drain_main_task_wall_ns_max,
      drain_result.max_main_task_elapsed_ns);
  g_gateway_runtime_counters.read_batch_drain_main_tasks_exceeding_wall_budget.fetch_add(
      static_cast<uint64_t>(drain_result.main_tasks_exceeding_wall_budget),
      std::memory_order_relaxed);
  if (drain_result.remaining_main_tasks > 0 ||
      drain_result.remaining_cleanup_tasks > 0) {
    g_gateway_runtime_counters.read_batch_drain_backlog_rescheduled.fetch_add(
        1, std::memory_order_relaxed);
    gateway_drain_owner_main_tasks_later();
  }
  gateway_resume_main_queue_reads_if_below_low_watermark();
}

void gateway_apply_receive(object_t *user, svalue_t *data_sv) {
  if (!gateway_object_valid_local(user) || !data_sv) {
    g_gateway_runtime_counters.receive_tasks_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  auto copy_started_at = gateway_now_ns();
  auto payload = gateway_copy_svalue(data_sv, "gateway_receive_payload");
  gateway_record_latency(g_gateway_runtime_counters.receive_payload_copy_ns_total,
                         g_gateway_runtime_counters.receive_payload_copy_ns_max,
                         g_gateway_runtime_counters.receive_payload_copy_samples,
                         gateway_now_ns() - copy_started_at);

  auto enqueued_at = gateway_now_ns();
  if (vm_owner_enqueue_main_task(user, "gateway", "gateway_receive", [user, payload, enqueued_at] {
        if (!gateway_object_valid_local(user)) {
          return;
        }
        gateway_record_latency(g_gateway_runtime_counters.receive_enqueue_to_dispatch_ns_total,
                               g_gateway_runtime_counters.receive_enqueue_to_dispatch_ns_max,
                               g_gateway_runtime_counters.receive_enqueue_to_dispatch_samples,
                               gateway_now_ns() - enqueued_at);
        save_command_giver(user);
        {
          VMCurrentInteractiveScope interactive_scope(vm_context(), user);
          vm_owner_record_task_trace(vm_owner_id(user), "gateway", "gateway_receive", vm_owner_epoch(user),
                                     "dispatched");
          g_gateway_runtime_counters.receive_tasks_dispatched.fetch_add(1, std::memory_order_relaxed);
          set_eval(max_eval_cost);
          push_svalue(payload.get());
          auto apply_started_at = gateway_now_ns();
          auto apply_cpu_started_at = get_current_thread_cpu_time_ns();
          safe_apply("gateway_receive", user, 1, ORIGIN_DRIVER);
          gateway_record_thread_cpu(
              g_gateway_runtime_counters.receive_apply_thread_cpu_ns_total,
              g_gateway_runtime_counters.receive_apply_thread_cpu_ns_max,
              g_gateway_runtime_counters.receive_apply_thread_cpu_samples,
              g_gateway_runtime_counters.receive_apply_thread_cpu_unavailable, apply_cpu_started_at);
          gateway_record_latency(g_gateway_runtime_counters.receive_apply_ns_total,
                                 g_gateway_runtime_counters.receive_apply_ns_max,
                                 g_gateway_runtime_counters.receive_apply_samples,
                                 gateway_now_ns() - apply_started_at);
        }
        restore_command_giver();
      }, nullptr, VM_OWNER_MAIN_TASK_IO_ADAPTER) != 0) {
    g_gateway_runtime_counters.receive_tasks_enqueued.fetch_add(1, std::memory_order_relaxed);
    auto main_queue_depth = std::max<long>(0, vm_owner_main_queue_total_depth());
    gateway_record_latency(g_gateway_runtime_counters.receive_main_queue_depth_total,
                           g_gateway_runtime_counters.receive_main_queue_depth_max,
                           g_gateway_runtime_counters.receive_main_queue_depth_samples,
                           static_cast<uint64_t>(main_queue_depth));
    if (g_event_base) {
      // The buffered-read callback owns the first bounded drain after it has
      // admitted the whole frame batch. Do not execute or schedule a drain per
      // frame here; that would either serialize the parser or place the first
      // command behind the full active-event queue.
      g_gateway_runtime_counters.receive_deferred_drain_requests.fetch_add(1,
                                                                           std::memory_order_relaxed);
    } else {
      // Unit/bootstrap paths without a running event base still need a bounded
      // synchronous fallback. Product gateway reads always take the branch above.
      g_gateway_runtime_counters.receive_inline_drain_calls.fetch_add(1, std::memory_order_relaxed);
      gateway_drain_owner_main_tasks_now(kGatewayDeferredMainDrainBudget);
    }
  } else {
    g_gateway_runtime_counters.receive_tasks_rejected.fetch_add(1, std::memory_order_relaxed);
  }
}

svalue_t json_to_gateway_svalue(const nlohmann::json &value) {
  svalue_t sv = {};

  if (value.is_object()) {
    auto count = static_cast<int>(value.size());
    array_t *keys = allocate_array(count);
    array_t *values = allocate_array(count);
    int i = 0;
    for (const auto &entry : value.items()) {
      keys->item[i].type = T_STRING;
      keys->item[i].subtype = STRING_MALLOC;
      keys->item[i].u.string = string_copy(entry.key().c_str(), "gateway_json_key");
      auto item = json_to_gateway_svalue(entry.value());
      assign_svalue_no_free(&values->item[i], &item);
      free_svalue(&item, "gateway_json_value");
      i++;
    }
    sv.type = T_MAPPING;
    sv.u.map = mkmapping(keys, values);
    free_array(keys);
    free_array(values);
    return sv;
  }
  if (value.is_array()) {
    auto count = static_cast<int>(value.size());
    sv.type = T_ARRAY;
    sv.u.arr = allocate_array(count);
    for (int i = 0; i < count; i++) {
      auto item = json_to_gateway_svalue(value[i]);
      assign_svalue_no_free(&sv.u.arr->item[i], &item);
      free_svalue(&item, "gateway_json_array_item");
    }
    return sv;
  }
  if (value.is_string()) {
    sv.type = T_STRING;
    sv.subtype = STRING_MALLOC;
    sv.u.string = string_copy(value.get_ref<const std::string &>().c_str(), "gateway_json_string");
    return sv;
  }
  if (value.is_boolean()) {
    sv.type = T_NUMBER;
    sv.u.number = value.get<bool>() ? 1 : 0;
    return sv;
  }
  if (value.is_number_integer()) {
    sv.type = T_NUMBER;
    sv.u.number = value.get<LPC_INT>();
    return sv;
  }
  if (value.is_number_unsigned()) {
    sv.type = T_NUMBER;
    sv.u.number = static_cast<LPC_INT>(value.get<std::uint64_t>());
    return sv;
  }
  if (value.is_number_float()) {
    sv.type = T_REAL;
    sv.u.real = value.get<LPC_FLOAT>();
    return sv;
  }

  sv.type = T_NUMBER;
  sv.u.number = 0;
  return sv;
}

bool gateway_svalue_to_json_impl(const svalue_t *sv, nlohmann::json *out, int depth) {
  if (!sv || !out || depth > kGatewayMaxJsonDepth) {
    return false;
  }

  switch (sv->type) {
    case T_NUMBER:
      *out = sv->u.number;
      return true;
    case T_REAL:
      *out = sv->u.real;
      return true;
    case T_STRING:
      *out = sv->u.string ? nlohmann::json(std::string(sv->u.string)) : nlohmann::json("");
      return true;
    case T_ARRAY: {
      nlohmann::json arr = nlohmann::json::array();
      for (int i = 0; i < sv->u.arr->size; i++) {
        nlohmann::json item;
        if (!gateway_svalue_to_json_impl(&sv->u.arr->item[i], &item, depth + 1)) {
          return false;
        }
        arr.push_back(item);
      }
      *out = std::move(arr);
      return true;
    }
    case T_MAPPING: {
      nlohmann::json obj = nlohmann::json::object();
      for (int i = 0; i < sv->u.map->table_size; i++) {
        for (auto *node = sv->u.map->table[i]; node; node = node->next) {
          if (node->values[0].type != T_STRING || !node->values[0].u.string) {
            return false;
          }
          nlohmann::json item;
          if (!gateway_svalue_to_json_impl(&node->values[1], &item, depth + 1)) {
            return false;
          }
          obj[std::string(node->values[0].u.string)] = std::move(item);
        }
      }
      *out = std::move(obj);
      return true;
    }
    case T_OBJECT:
      if (!sv->u.ob || (sv->u.ob->flags & O_DESTRUCTED)) {
        *out = nullptr;
        return true;
      }
      *out = std::string(sv->u.ob->obname);
      return true;
    default:
      *out = nullptr;
      return true;
  }
}

int gateway_svalue_to_json_string_impl(const svalue_t *sv, std::string *out) {
  nlohmann::json value;

  if (!out || !gateway_svalue_to_json_impl(sv, &value, 0)) {
    return 0;
  }
  *out = value.dump();
  return 1;
}

void gateway_send_json_to_fd(int fd, const nlohmann::json &payload) {
  auto encoded = payload.dump();
  gateway_send_raw_to_fd(fd, encoded.c_str(), encoded.size());
}

bool gateway_status_to_json(nlohmann::json *out) {
  if (!out) {
    return false;
  }

  auto *status = gateway_status_internal();
  svalue_t status_sv = {};
  status_sv.type = T_MAPPING;
  status_sv.u.map = status;
  auto ok = gateway_svalue_to_json_impl(&status_sv, out, 0);
  free_mapping(status);
  return ok;
}

void gateway_remove_master(int fd);

void gateway_handle_heartbeat(int fd) {
  auto it = g_gateway_masters.find(fd);
  if (it == g_gateway_masters.end() || !it->second) {
    return;
  }
  it->second->last_active = get_current_time();
}

int next_gateway_fd() {
  while (g_gateway_masters.count(g_gateway_next_fd)) {
    g_gateway_next_fd++;
    if (g_gateway_next_fd <= 0) {
      g_gateway_next_fd = 1;
    }
  }
  return g_gateway_next_fd++;
}

void gateway_remove_master(int fd) {
  auto it = g_gateway_masters.find(fd);
  if (it == g_gateway_masters.end()) {
    return;
  }
  if (it->second && it->second->read_dispatch_pending) {
    it->second->read_dispatch_pending = false;
    auto pending = g_gateway_read_dispatch_pending_masters.load(std::memory_order_acquire);
    while (pending > 0 &&
           !g_gateway_read_dispatch_pending_masters.compare_exchange_weak(
               pending, pending - 1, std::memory_order_acq_rel,
               std::memory_order_acquire)) {
    }
  }
  gateway_cleanup_master_sessions(fd);
  g_gateway_masters.erase(it);
}

void gateway_handle_hello(int fd, const nlohmann::json &msg) {
  if (g_gateway_debug) {
    debug_message("[gateway] hello fd=%d\n", fd);
  }
  gateway_handle_heartbeat(fd);
}

void gateway_handle_login(int fd, const nlohmann::json &msg) {
  std::string session_id;
  std::string ip;
  int port = 0;
  svalue_t data_sv = {};
  bool has_data = false;

  if (!msg.contains("cid") || !msg["cid"].is_string()) {
    return;
  }
  if (g_gateway_debug) {
    debug_message("[gateway] login fd=%d cid=%s\n", fd, msg["cid"].get_ref<const std::string &>().c_str());
  }
  session_id = msg["cid"].get<std::string>();
  if (session_id.empty()) {
    return;
  }
  if (msg.contains("data") && msg["data"].is_object()) {
    const auto &data = msg["data"];
    if (data.contains("ip") && data["ip"].is_string()) {
      ip = data["ip"].get<std::string>();
    }
    if (data.contains("port") && data["port"].is_number_integer()) {
      port = data["port"].get<int>();
    }
    data_sv = json_to_gateway_svalue(data);
    has_data = true;
  }

  if (gateway_find_session(session_id.c_str())) {
    if (gateway_rebind_session_internal(session_id.c_str(), ip.c_str(), port, fd)) {
      if (has_data) {
        free_svalue(&data_sv, "gateway_login_data");
      }
      return;
    }
    gateway_destroy_session_internal(session_id.c_str(), "session_stale",
                                     "stale session replaced by gateway replay");
    if (gateway_find_session(session_id.c_str())) {
      if (has_data) {
        free_svalue(&data_sv, "gateway_login_data");
      }
      return;
    }
  }

  auto payload = gateway_copy_svalue(has_data ? &data_sv : nullptr, "gateway_login_payload");
  if (vm_owner_enqueue_main_task(master_ob, "gateway", "gateway_login",
                                 [session_id, ip, port, fd, payload] {
                                   if (fd >= 0 && !gateway_has_master(fd)) {
                                     vm_owner_record_task_trace(vm_owner_id(master_ob), "gateway", "gateway_login",
                                                                vm_owner_epoch(master_ob), "master_stale");
                                     return;
                                   }
                                   gateway_create_session_internal(session_id.c_str(), payload ? payload.get() : nullptr,
                                                                   ip.c_str(), port, fd);
                                 },
                                 nullptr, VM_OWNER_MAIN_TASK_IO_ADAPTER) != 0) {
    auto drained = gateway_drain_owner_main_tasks_now(kGatewayDeferredMainDrainBudget);
    if (drained == 0 || drained >= kGatewayDeferredMainDrainBudget) {
      gateway_drain_owner_main_tasks_later();
    }
  }

  if (has_data) {
    free_svalue(&data_sv, "gateway_login_data");
  }
}

void gateway_handle_data(int fd, const nlohmann::json &msg) {
  std::string session_id;
  GatewaySession *sess = nullptr;
  object_t *user = nullptr;
  svalue_t data_sv = {};

  if (!msg.contains("cid") || !msg["cid"].is_string() || !msg.contains("data")) {
    g_gateway_runtime_counters.data_frames_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  g_gateway_runtime_counters.data_frames_received.fetch_add(1, std::memory_order_relaxed);
  if (g_gateway_debug) {
    debug_message("[gateway] data fd=%d cid=%s\n", fd, msg["cid"].get_ref<const std::string &>().c_str());
  }
  session_id = msg["cid"].get<std::string>();
  if (session_id.empty()) {
    g_gateway_runtime_counters.data_frames_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  sess = gateway_find_session(session_id.c_str());
  if (!sess || sess->master_fd != fd) {
    g_gateway_runtime_counters.data_frames_rejected.fetch_add(1, std::memory_order_relaxed);
    g_gateway_runtime_counters.stale_master_frames_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  user = sess ? sess->user_ob : nullptr;
  if (!gateway_object_valid_local(user)) {
    g_gateway_runtime_counters.data_frames_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  sess->last_active = get_current_time();
  if (user->interactive) {
    user->interactive->last_time = sess->last_active;
  }
  {
    auto decode_started_at = gateway_now_ns();
    data_sv = json_to_gateway_svalue(msg["data"]);
    gateway_record_latency(g_gateway_runtime_counters.receive_decode_ns_total,
                           g_gateway_runtime_counters.receive_decode_ns_max,
                           g_gateway_runtime_counters.receive_decode_samples,
                           gateway_now_ns() - decode_started_at);
  }
  g_gateway_runtime_counters.data_frames_applied.fetch_add(1, std::memory_order_relaxed);
  gateway_apply_receive(user, &data_sv);
  free_svalue(&data_sv, "gateway_data");
}

void gateway_handle_discon(int fd, const nlohmann::json &msg) {
  std::string reason_code = "client_disconnected";
  std::string reason_text = "client disconnect";

  if (!msg.contains("cid") || !msg["cid"].is_string()) {
    return;
  }
  if (g_gateway_debug) {
    debug_message("[gateway] discon fd=%d cid=%s\n", fd, msg["cid"].get_ref<const std::string &>().c_str());
  }
  auto *sess = gateway_find_session(msg["cid"].get_ref<const std::string &>().c_str());
  if (!sess || sess->master_fd != fd) {
    g_gateway_runtime_counters.stale_master_frames_rejected.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (msg.contains("reason_code") && msg["reason_code"].is_string() &&
      !msg["reason_code"].get_ref<const std::string &>().empty()) {
    reason_code = msg["reason_code"].get<std::string>();
  }
  if (msg.contains("reason_text") && msg["reason_text"].is_string() &&
      !msg["reason_text"].get_ref<const std::string &>().empty()) {
    reason_text = msg["reason_text"].get<std::string>();
  } else if (msg.contains("reason") && msg["reason"].is_string() &&
             !msg["reason"].get_ref<const std::string &>().empty()) {
    reason_text = msg["reason"].get<std::string>();
  }
  gateway_destroy_session_internal(msg["cid"].get_ref<const std::string &>().c_str(),
                                   reason_code.c_str(), reason_text.c_str());
}

void gateway_handle_sys(int fd, const nlohmann::json &msg) {
  std::string action;

  gateway_handle_heartbeat(fd);
  if (!msg.contains("action") || !msg["action"].is_string()) {
    return;
  }

  action = msg["action"].get<std::string>();
  if (g_gateway_debug) {
    debug_message("[gateway] sys fd=%d action=%s\n", fd, action.c_str());
  }

  if (action == "ping") {
    nlohmann::json response = {
        {"type", "sys"},
        {"action", "pong"},
    };
    if (msg.contains("ts")) {
      response["ts"] = msg["ts"];
    }
    nlohmann::json status;
    if (gateway_status_to_json(&status)) {
      response["data"] = std::move(status);
    }
    gateway_send_json_to_fd(fd, response);
    return;
  }

  if (action == "status") {
    nlohmann::json response = {
        {"type", "sys"},
        {"action", "status"},
    };
    if (msg.contains("ts")) {
      response["ts"] = msg["ts"];
    }
    nlohmann::json status;
    if (gateway_status_to_json(&status)) {
      response["data"] = std::move(status);
    }
    gateway_send_json_to_fd(fd, response);
    return;
  }

  if (action == "pong") {
    return;
  }

  if (msg.contains("cid") && msg["cid"].is_string()) {
    auto session_id = msg["cid"].get<std::string>();
    auto *sess = gateway_find_session(session_id.c_str());
    auto *user = sess ? sess->user_ob : nullptr;
    if (gateway_object_valid_local(user)) {
      svalue_t data_sv = {};
      sess->last_active = get_current_time();
      if (user->interactive) {
        user->interactive->last_time = sess->last_active;
      }
      if (msg.contains("data")) {
        data_sv = json_to_gateway_svalue(msg["data"]);
      } else {
        data_sv.type = T_NUMBER;
        data_sv.u.number = 0;
      }
      gateway_apply_receive(user, &data_sv);
      free_svalue(&data_sv, "gateway_sys_data");
      return;
    }
  }

  if (auto *gateway_d = find_object("/adm/daemons/gateway_d")) {
    svalue_t msg_sv = json_to_gateway_svalue(msg);
    save_command_giver(gateway_d);
    VMOwnerScope owner_scope(vm_context(), vm_owner_id(gateway_d), vm_owner_epoch(gateway_d));
    vm_owner_record_task_trace(vm_owner_id(gateway_d), "gateway", "receive_system_message",
                               vm_owner_epoch(gateway_d), "dispatched");
    set_eval(max_eval_cost);
    push_svalue(&msg_sv);
    safe_apply("receive_system_message", gateway_d, 1, ORIGIN_DRIVER);
    restore_command_giver();
    free_svalue(&msg_sv, "gateway_sys_msg");
  }
}

void gateway_dispatch_message(int fd, const nlohmann::json &msg) {
  std::string type;

  if (!msg.is_object() || !msg.contains("type") || !msg["type"].is_string()) {
    return;
  }
  type = msg["type"].get<std::string>();
  if (type == "hello") {
    gateway_handle_hello(fd, msg);
    return;
  }
  if (type == "login") {
    gateway_handle_login(fd, msg);
    return;
  }
  if (type == "data") {
    gateway_handle_data(fd, msg);
    return;
  }
  if (type == "discon") {
    gateway_handle_discon(fd, msg);
    return;
  }
  if (type == "sys") {
    gateway_handle_sys(fd, msg);
    return;
  }
}

void gateway_eventcb(bufferevent * /*bev*/, short events, void *ctx) {
  auto *master = reinterpret_cast<GatewayMaster *>(ctx);
  if (!master) {
    return;
  }
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    gateway_remove_master(master->fd);
  }
}

void gateway_heartbeat_timer_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*ctx*/) {
  gateway_check_heartbeat_timeouts();
  gateway_check_session_timeouts();
  if (g_gateway_heartbeat_timer && g_gateway_heartbeat_interval > 0) {
    timeval tv = {g_gateway_heartbeat_interval, 0};
    evtimer_add(g_gateway_heartbeat_timer, &tv);
  }
}

int gateway_start_heartbeat_timer() {
  gateway_stop_heartbeat_timer();
  if (!g_event_base || g_gateway_heartbeat_interval <= 0) {
    return 0;
  }

  g_gateway_heartbeat_timer = evtimer_new(g_event_base, gateway_heartbeat_timer_cb, nullptr);
  if (!g_gateway_heartbeat_timer) {
    return 0;
  }

  timeval tv = {g_gateway_heartbeat_interval, 0};
  evtimer_add(g_gateway_heartbeat_timer, &tv);
  return 1;
}

void gateway_stop_heartbeat_timer() {
  if (!g_gateway_heartbeat_timer) {
    return;
  }

  evtimer_del(g_gateway_heartbeat_timer);
  event_free(g_gateway_heartbeat_timer);
  g_gateway_heartbeat_timer = nullptr;
}

size_t gateway_read_buffer_available(const GatewayMaster *master) {
  if (!master || master->read_buffer_offset >= master->read_buffer.size()) {
    return 0;
  }
  return master->read_buffer.size() - master->read_buffer_offset;
}

void gateway_compact_read_buffer(GatewayMaster *master) {
  if (!master || master->read_buffer_offset == 0) {
    return;
  }
  if (master->read_buffer_offset >= master->read_buffer.size()) {
    master->read_buffer.clear();
    master->read_buffer_offset = 0;
    return;
  }

  auto remaining = gateway_read_buffer_available(master);
  master->read_buffer.erase(0, master->read_buffer_offset);
  master->read_buffer_offset = 0;
  g_gateway_runtime_counters.read_dispatch_buffer_compactions.fetch_add(
      1, std::memory_order_relaxed);
  g_gateway_runtime_counters.read_dispatch_buffer_compacted_bytes.fetch_add(
      static_cast<uint64_t>(remaining), std::memory_order_relaxed);
}

bool gateway_buffer_has_complete_frame(const GatewayMaster *master) {
  uint32_t frame_len;
  auto available = gateway_read_buffer_available(master);

  if (!master || available < sizeof(frame_len)) {
    return false;
  }
  memcpy(&frame_len, master->read_buffer.data() + master->read_buffer_offset,
         sizeof(frame_len));
  frame_len = ntohl(frame_len);
  if (frame_len == 0 || frame_len > 16 * 1024 * 1024) {
    return true;
  }
  return available >= sizeof(frame_len) + frame_len;
}

/*
 * Read-dispatch pressure only counts masters already admitted into the
 * GatewayMaster cursor. A socket can still have a complete frame in
 * libevent's native input buffer, or a frame can straddle that buffer and our
 * cursor. Inspect the length header without draining either buffer. Incomplete
 * frames are deliberately ignored so a stalled partial TCP write cannot starve
 * optional cache maintenance.
 */
bool gateway_master_has_buffered_input(const GatewayMaster *master) {
  evbuffer *input;
  size_t cursor_available;
  size_t native_available;
  size_t available;
  size_t cursor_header_bytes;
  unsigned char header[sizeof(uint32_t)] = {};
  uint32_t frame_len;

  if (!master) {
    return false;
  }
  cursor_available = gateway_read_buffer_available(master);
  input = master->bev ? bufferevent_get_input(master->bev) : nullptr;
  native_available = input ? evbuffer_get_length(input) : 0;
  if (native_available > SIZE_MAX - cursor_available) {
    return true;
  }
  available = cursor_available + native_available;
  if (available < sizeof(frame_len)) {
    return false;
  }

  cursor_header_bytes = std::min(cursor_available, sizeof(header));
  if (cursor_header_bytes > 0) {
    memcpy(header, master->read_buffer.data() + master->read_buffer_offset,
           cursor_header_bytes);
  }
  if (cursor_header_bytes < sizeof(header)) {
    if (!input || evbuffer_copyout(input, header + cursor_header_bytes,
                                   sizeof(header) - cursor_header_bytes) !=
                     static_cast<ev_ssize_t>(sizeof(header) - cursor_header_bytes)) {
      return false;
    }
  }

  memcpy(&frame_len, header, sizeof(frame_len));
  frame_len = ntohl(frame_len);
  if (frame_len == 0 || frame_len > 16 * 1024 * 1024) {
    return true;
  }
  return available >= sizeof(frame_len) + frame_len;
}

int gateway_dispatch_buffered_frames(GatewayMaster *master, int budget) {
  int dispatched = 0;
  int admission_budget;

  if (!master || budget <= 0) {
    return 0;
  }
  admission_budget = gateway_main_queue_admission_budget(budget);
  if (admission_budget <= 0) {
    gateway_pause_all_reads_for_main_queue_pressure();
    return 0;
  }
  while (dispatched < admission_budget &&
         gateway_read_buffer_available(master) >= sizeof(uint32_t)) {
    uint32_t frame_len;
    auto available = gateway_read_buffer_available(master);
    auto *frame_start = master->read_buffer.data() + master->read_buffer_offset;

    memcpy(&frame_len, frame_start, sizeof(frame_len));
    frame_len = ntohl(frame_len);
    if (frame_len == 0 || frame_len > 16 * 1024 * 1024) {
      gateway_remove_master(master->fd);
      return -1;
    }
    if (available < sizeof(uint32_t) + frame_len) {
      break;
    }

    auto payload = std::string(frame_start + sizeof(uint32_t), frame_len);
    master->read_buffer_offset += sizeof(uint32_t) + frame_len;
    g_gateway_runtime_counters.read_dispatch_front_shift_bytes_avoided.fetch_add(
        static_cast<uint64_t>(gateway_read_buffer_available(master)),
        std::memory_order_relaxed);
    dispatched++;
    try {
      auto msg = nlohmann::json::parse(payload);
      gateway_dispatch_message(master->fd, msg);
      master->messages_received++;
    } catch (...) {
      continue;
    }
  }
  if (!gateway_buffer_has_complete_frame(master)) {
    gateway_compact_read_buffer(master);
  }
  if (gateway_main_queue_pending_count() >= kGatewayMainQueueReadHighWatermark) {
    gateway_pause_all_reads_for_main_queue_pressure();
  }
  return dispatched;
}

void gateway_record_read_dispatch(int dispatched, bool backlog) {
  if (dispatched < 0) {
    return;
  }
  g_gateway_runtime_counters.read_dispatch_runs.fetch_add(1, std::memory_order_relaxed);
  g_gateway_runtime_counters.read_dispatch_frames_total.fetch_add(
      static_cast<uint64_t>(dispatched), std::memory_order_relaxed);
  gateway_record_max(g_gateway_runtime_counters.read_dispatch_frames_max,
                     static_cast<uint64_t>(dispatched));
  if (backlog && dispatched >= kGatewayReadFrameBudget) {
    g_gateway_runtime_counters.read_dispatch_budget_hits.fetch_add(1, std::memory_order_relaxed);
  }
}

void gateway_mark_read_dispatch_pending(GatewayMaster *master) {
  if (!master || master->read_dispatch_pending) {
    return;
  }
  master->read_dispatch_pending = true;
  g_gateway_read_dispatch_pending_masters.fetch_add(1, std::memory_order_release);
}

void gateway_release_read_dispatch_pending(GatewayMaster *master) {
  if (!master || !master->read_dispatch_pending) {
    return;
  }
  master->read_dispatch_pending = false;
  auto pending = g_gateway_read_dispatch_pending_masters.load(std::memory_order_acquire);
  while (pending > 0 &&
         !g_gateway_read_dispatch_pending_masters.compare_exchange_weak(
             pending, pending - 1, std::memory_order_acq_rel,
             std::memory_order_acquire)) {
  }
}

bool gateway_has_read_pause_reason(const GatewayMaster *master, GatewayReadPauseReason reason) {
  return master && (master->read_dispatch_pause_reasons & static_cast<uint8_t>(reason));
}

bool gateway_add_read_pause_reason(GatewayMaster *master, GatewayReadPauseReason reason) {
  if (!master || !master->bev || gateway_has_read_pause_reason(master, reason)) {
    return false;
  }
  if (master->read_dispatch_pause_reasons == 0 &&
      bufferevent_disable(master->bev, EV_READ) != 0) {
    return false;
  }
  if (master->read_dispatch_pause_reasons == 0) {
    master->read_dispatch_input_paused = true;
    g_gateway_runtime_counters.read_dispatch_input_paused.fetch_add(1, std::memory_order_relaxed);
  }
  master->read_dispatch_pause_reasons |= static_cast<uint8_t>(reason);
  return true;
}

bool gateway_remove_read_pause_reason(GatewayMaster *master, GatewayReadPauseReason reason) {
  if (!master || !master->bev || !gateway_has_read_pause_reason(master, reason)) {
    return false;
  }
  const auto remaining = static_cast<uint8_t>(
      master->read_dispatch_pause_reasons & ~static_cast<uint8_t>(reason));
  if (remaining != 0) {
    master->read_dispatch_pause_reasons = remaining;
    return true;
  }
  if (bufferevent_enable(master->bev, EV_READ) != 0) {
    return false;
  }
  master->read_dispatch_pause_reasons = 0;
  master->read_dispatch_input_paused = false;
  g_gateway_runtime_counters.read_dispatch_input_resumed.fetch_add(1, std::memory_order_relaxed);
  return true;
}

// A master may be paused for both a buffered-frame continuation and global
// owner-main pressure; clearing either reason must not re-enable EV_READ while
// the other still applies.
void gateway_pause_buffered_read(GatewayMaster *master) {
  gateway_add_read_pause_reason(master, GATEWAY_READ_PAUSE_BUFFERED_BACKLOG);
}

void gateway_resume_buffered_read(GatewayMaster *master) {
  gateway_remove_read_pause_reason(master, GATEWAY_READ_PAUSE_BUFFERED_BACKLOG);
}

bool gateway_pause_main_queue_read(GatewayMaster *master) {
  if (!gateway_add_read_pause_reason(master, GATEWAY_READ_PAUSE_MAIN_QUEUE)) {
    return false;
  }
  g_gateway_runtime_counters.main_queue_read_paused.fetch_add(1, std::memory_order_relaxed);
  return true;
}

bool gateway_resume_main_queue_read(GatewayMaster *master) {
  if (!gateway_remove_read_pause_reason(master, GATEWAY_READ_PAUSE_MAIN_QUEUE)) {
    return false;
  }
  g_gateway_runtime_counters.main_queue_read_resumed.fetch_add(1, std::memory_order_relaxed);
  return true;
}

long gateway_main_queue_read_paused_count() {
  long paused = 0;
  for (const auto &entry : g_gateway_masters) {
    if (gateway_has_read_pause_reason(entry.second.get(), GATEWAY_READ_PAUSE_MAIN_QUEUE)) {
      paused++;
    }
  }
  return paused;
}

void gateway_pause_all_reads_for_main_queue_pressure() {
  int newly_paused = 0;
  for (const auto &entry : g_gateway_masters) {
    newly_paused += gateway_pause_main_queue_read(entry.second.get()) ? 1 : 0;
  }
  if (newly_paused > 0) {
    g_gateway_runtime_counters.main_queue_read_pressure_events.fetch_add(
        1, std::memory_order_relaxed);
  }
}

int gateway_main_queue_admission_budget(int budget) {
  if (budget <= 0) {
    return 0;
  }
  const auto pending = gateway_main_queue_pending_count();
  const auto remaining = kGatewayMainQueueReadHighWatermark - pending;
  if (remaining >= budget) {
    return budget;
  }
  g_gateway_runtime_counters.main_queue_read_admission_limited.fetch_add(
      1, std::memory_order_relaxed);
  if (remaining <= 0) {
    gateway_pause_all_reads_for_main_queue_pressure();
    return 0;
  }
  return static_cast<int>(remaining);
}

void gateway_schedule_buffered_read(int fd) {
  auto it = g_gateway_masters.find(fd);
  if (it == g_gateway_masters.end() || !it->second || !g_event_base) {
    return;
  }
  auto *master = it->second.get();
  gateway_mark_read_dispatch_pending(master);
  if (master->read_dispatch_scheduled) {
    gateway_pause_buffered_read(master);
    g_gateway_runtime_counters.read_dispatch_deferred_coalesced.fetch_add(1,
                                                                         std::memory_order_relaxed);
    return;
  }

  master->read_dispatch_scheduled = true;
  gateway_pause_buffered_read(master);
  g_gateway_runtime_counters.read_dispatch_deferred_scheduled.fetch_add(1,
                                                                        std::memory_order_relaxed);
  master->read_dispatch_event = add_walltime_event(
      kGatewayReadContinuationDelay, [fd] {
    auto current = g_gateway_masters.find(fd);
    if (current == g_gateway_masters.end() || !current->second) {
      return;
    }
    auto *scheduled_master = current->second.get();
    scheduled_master->read_dispatch_event = nullptr;
    scheduled_master->read_dispatch_scheduled = false;
    g_gateway_runtime_counters.read_dispatch_deferred_executed.fetch_add(
        1, std::memory_order_relaxed);
    auto dispatched = gateway_dispatch_buffered_frames(scheduled_master,
                                                       kGatewayReadFrameBudget);
    gateway_service_admitted_receive_tasks();
    if (dispatched < 0) {
      return;
    }
    auto backlog = gateway_buffer_has_complete_frame(scheduled_master);
    gateway_record_read_dispatch(dispatched, backlog);
    if (backlog) {
      if (gateway_has_read_pause_reason(scheduled_master,
                                        GATEWAY_READ_PAUSE_MAIN_QUEUE)) {
        gateway_mark_read_dispatch_pending(scheduled_master);
      } else {
        gateway_schedule_buffered_read(fd);
      }
    } else {
      gateway_release_read_dispatch_pending(scheduled_master);
      gateway_resume_buffered_read(scheduled_master);
    }
  }, BackendEventPriority::kGateway);
}

void gateway_resume_main_queue_reads_if_below_low_watermark() {
  if (gateway_main_queue_pending_count() > kGatewayMainQueueReadLowWatermark) {
    return;
  }
  for (const auto &entry : g_gateway_masters) {
    auto *master = entry.second.get();
    if (!gateway_has_read_pause_reason(master, GATEWAY_READ_PAUSE_MAIN_QUEUE)) {
      continue;
    }
    if (gateway_buffer_has_complete_frame(master) &&
        !master->read_dispatch_scheduled) {
      gateway_schedule_buffered_read(entry.first);
    }
    gateway_resume_main_queue_read(master);
  }
}

void gateway_readcb(bufferevent *bev, void *ctx) {
  auto *master = reinterpret_cast<GatewayMaster *>(ctx);
  auto *input = static_cast<evbuffer *>(nullptr);
  size_t len;
  std::string chunk;

  if (!master || !bev) {
    return;
  }

  input = bufferevent_get_input(bev);
  if (!input) {
    return;
  }

  len = evbuffer_get_length(input);
  if (len == 0) {
    return;
  }

  chunk.resize(len);
  if (evbuffer_remove(input, chunk.data(), len) <= 0) {
    return;
  }
  master->last_active = get_current_time();
  gateway_compact_read_buffer(master);
  master->read_buffer += chunk;
  gateway_record_max(
      g_gateway_runtime_counters.read_dispatch_buffer_peak_bytes,
      static_cast<uint64_t>(gateway_read_buffer_available(master)));
  if (master->read_dispatch_scheduled) {
    gateway_schedule_buffered_read(master->fd);
    return;
  }

  if (gateway_buffer_has_complete_frame(master)) {
    gateway_mark_read_dispatch_pending(master);
  }
  auto dispatched = gateway_dispatch_buffered_frames(master, kGatewayReadFrameBudget);
  gateway_service_admitted_receive_tasks();
  if (dispatched < 0) {
    return;
  }
  auto backlog = gateway_buffer_has_complete_frame(master);
  gateway_record_read_dispatch(dispatched, backlog);
  if (backlog) {
    if (gateway_has_read_pause_reason(master, GATEWAY_READ_PAUSE_MAIN_QUEUE)) {
      gateway_mark_read_dispatch_pending(master);
    } else {
      gateway_schedule_buffered_read(master->fd);
    }
  } else {
    gateway_release_read_dispatch_pending(master);
  }
}

void gateway_listener_cb(evconnlistener *listener, evutil_socket_t fd,
                         sockaddr *sa, int socklen, void * /*ctx*/) {
  char ipbuf[INET6_ADDRSTRLEN] = {0};
  if (g_gateway_max_masters > 0 && static_cast<int>(g_gateway_masters.size()) >= g_gateway_max_masters) {
    evutil_closesocket(fd);
    return;
  }

  gateway_enable_master_tcp_nodelay(fd);
  auto *base = evconnlistener_get_base(listener);
  auto bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!bev) {
    evutil_closesocket(fd);
    return;
  }
  if (bufferevent_priority_set(
          bev, static_cast<int>(BackendEventPriority::kGateway)) != 0) {
    bufferevent_free(bev);
    return;
  }

  if (sa && sa->sa_family == AF_INET) {
    evutil_inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(sa)->sin_addr, ipbuf,
                     sizeof(ipbuf));
  } else if (sa && sa->sa_family == AF_INET6) {
    evutil_inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(sa)->sin6_addr, ipbuf,
                     sizeof(ipbuf));
  }

  auto master = std::make_unique<GatewayMaster>();
  master->fd = next_gateway_fd();
  master->bev = bev;
  master->ip = ipbuf;
  master->connected_at = get_current_time();
  master->last_active = master->connected_at;

  bufferevent_setcb(bev, gateway_readcb, nullptr, gateway_eventcb, master.get());
  bufferevent_enable(bev, EV_READ | EV_WRITE);
  g_gateway_masters[master->fd] = std::move(master);
}

void gateway_listener_error_cb(evconnlistener * /*listener*/, void * /*ctx*/) {
  debug_message("Gateway listener error.\n");
}
}  // namespace

int gateway_svalue_to_json_string(const svalue_t *sv, std::string *out) {
  return gateway_svalue_to_json_string_impl(sv, out);
}

// C++ regression hook for gateway owner-scope tests; not part of the LPC/runtime API.
bool gateway_dispatch_message_for_test(int fd, const char *payload) {
  if (!payload) {
    return false;
  }
  try {
    gateway_dispatch_message(fd, nlohmann::json::parse(payload));
    return true;
  } catch (...) {
    return false;
  }
}

int gateway_dispatch_buffered_frames_for_test(GatewayMaster *master, int budget) {
  return gateway_dispatch_buffered_frames(master, budget);
}

void gateway_set_read_dispatch_pending_for_test(GatewayMaster *master, bool pending) {
  if (pending) {
    gateway_mark_read_dispatch_pending(master);
  } else {
    gateway_release_read_dispatch_pending(master);
  }
}

void gateway_service_admitted_receive_tasks_for_test() {
  gateway_service_admitted_receive_tasks();
}

bool gateway_master_has_buffered_input_for_test(const GatewayMaster *master) {
  return gateway_master_has_buffered_input(master);
}

GatewayMaster::~GatewayMaster() {
  gateway_release_read_dispatch_pending(this);
  if (read_dispatch_event) {
    read_dispatch_event->cancel();
    read_dispatch_event = nullptr;
  }
  if (bev) {
    bufferevent_free(bev);
    bev = nullptr;
  }
}

void init_gateway(void) {
  g_gateway_debug = CONFIG_INT(__RC_GATEWAY_DEBUG__) ? 1 : 0;
  g_gateway_max_packet_size = CONFIG_INT(__RC_GATEWAY_PACKET_SIZE__) > 0
                                  ? static_cast<size_t>(CONFIG_INT(__RC_GATEWAY_PACKET_SIZE__))
                                  : static_cast<size_t>(1024 * 1024);
  g_gateway_max_masters = kGatewayDefaultMaxMasters;
  g_gateway_max_sessions = g_gateway_max_sessions > 0 ? g_gateway_max_sessions : 4096;
  g_gateway_heartbeat_interval = kGatewayDefaultHeartbeatInterval;
  g_gateway_heartbeat_timeout = kGatewayDefaultHeartbeatTimeout;
  g_gateway_reconnect_grace = kGatewayDefaultReconnectGrace;
  if (!g_gateway_started_at) {
    g_gateway_started_at = get_current_time();
  }
  debug_message("Gateway config: port=%d external=%d debug=%d packet_size=%d\n",
                CONFIG_INT(__RC_GATEWAY_PORT__), CONFIG_INT(__RC_GATEWAY_EXTERNAL__),
                g_gateway_debug, CONFIG_INT(__RC_GATEWAY_PACKET_SIZE__));
  if (g_gateway_debug) {
    debug_message("Gateway debug mode enabled.\n");
  }
  if (CONFIG_INT(__RC_GATEWAY_PORT__) > 0) {
    gateway_listen_internal(CONFIG_INT(__RC_GATEWAY_PORT__), CONFIG_INT(__RC_GATEWAY_EXTERNAL__));
  }
  gateway_start_heartbeat_timer();
  debug_message("Gateway package initialized.\n");
}

void cleanup_gateway(void) {
  gateway_stop_heartbeat_timer();
  if (g_gateway_main_drain_event) {
    g_gateway_main_drain_event->cancel();
    g_gateway_main_drain_event = nullptr;
  }
  g_gateway_main_drain_scheduled = false;
  cleanup_gateway_sessions();
  g_gateway_masters.clear();
  g_gateway_read_dispatch_pending_masters.store(0, std::memory_order_release);
  if (g_gateway_listener) {
    evconnlistener_free(g_gateway_listener);
    g_gateway_listener = nullptr;
  }
  g_gateway_listen_port = 0;
}

int gateway_listen_internal(int port, int bind_all) {
  sockaddr_in sin{};

  if (port <= 0 || port > 65535 || !g_event_base) {
    debug_message("Gateway listen skipped: invalid port or missing event base.\n");
    return 0;
  }

  if (g_gateway_listener) {
    evconnlistener_free(g_gateway_listener);
    g_gateway_listener = nullptr;
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = bind_all ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);

  g_gateway_listener = evconnlistener_new_bind(
      g_event_base, gateway_listener_cb, nullptr,
      LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
      reinterpret_cast<sockaddr *>(&sin), sizeof(sin));
  if (!g_gateway_listener) {
    g_gateway_listen_port = 0;
    debug_message("Gateway listener failed to bind on %s:%d\n",
                  bind_all ? "0.0.0.0" : "127.0.0.1", port);
    return 0;
  }

  evconnlistener_set_error_cb(g_gateway_listener, gateway_listener_error_cb);
  g_gateway_listen_port = port;
  debug_message("Accepting [Gateway] connections on %s:%d\n",
                bind_all ? "0.0.0.0" : "127.0.0.1", port);
  return 1;
}

int gateway_send_raw_to_fd(int fd, const char *data, size_t len) {
  auto it = g_gateway_masters.find(fd);
  uint32_t net_len;
  auto *output = static_cast<evbuffer *>(nullptr);

  if (!data || len == 0 || len > g_gateway_max_packet_size || it == g_gateway_masters.end()) {
    g_gateway_runtime_counters.raw_writes_failed.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  if (!it->second || !it->second->bev || it->second->closing) {
    g_gateway_runtime_counters.raw_writes_failed.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  output = bufferevent_get_output(it->second->bev);
  if (!output) {
    g_gateway_runtime_counters.raw_writes_failed.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  net_len = htonl(static_cast<uint32_t>(len));
  if (evbuffer_add(output, &net_len, sizeof(net_len)) != 0) {
    g_gateway_runtime_counters.raw_writes_failed.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  if (evbuffer_add(output, data, len) != 0) {
    g_gateway_runtime_counters.raw_writes_failed.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }

  g_gateway_runtime_counters.raw_writes_sent.fetch_add(1, std::memory_order_relaxed);
  it->second->messages_sent++;
  it->second->last_active = get_current_time();

  return 1;
}

int gateway_ping_master_internal(int fd) {
  static const char *ping_msg = "{\"type\":\"sys\",\"action\":\"ping\"}";
  return gateway_send_raw_to_fd(fd, ping_msg, strlen(ping_msg));
}

bool gateway_has_master(int fd) {
  return g_gateway_masters.find(fd) != g_gateway_masters.end();
}

void gateway_check_heartbeat_timeouts() {
  std::vector<int> to_remove;
  time_t now = get_current_time();

  if (g_gateway_heartbeat_timeout <= 0) {
    return;
  }

  for (const auto &entry : g_gateway_masters) {
    if (!entry.second) {
      continue;
    }
    if ((now - entry.second->last_active) > g_gateway_heartbeat_timeout) {
      to_remove.push_back(entry.first);
    }
  }

  for (int fd : to_remove) {
    if (g_gateway_debug) {
      debug_message("[gateway] heartbeat timeout fd=%d\n", fd);
    }
    gateway_remove_master(fd);
  }
}

long gateway_read_dispatch_pending_count() {
  return g_gateway_read_dispatch_pending_masters.load(std::memory_order_acquire);
}

long gateway_buffered_input_pending_count() {
  long pending = 0;
  for (const auto &entry : g_gateway_masters) {
    if (gateway_master_has_buffered_input(entry.second.get())) {
      pending++;
    }
  }
  return pending;
}

long gateway_command_pressure_count() {
  return gateway_session_command_pending_count() +
         gateway_read_dispatch_pending_count();
}

long gateway_main_queue_pending_count() {
  return std::max<long>(0, vm_owner_main_queue_total_depth());
}

mapping_t *gateway_status_internal() {
  mapping_t *map;
  int uptime;

  uptime = g_gateway_started_at ? static_cast<int>(get_current_time() - g_gateway_started_at) : 0;
  map = allocate_mapping(130);
  add_mapping_pair(map, "listening", g_gateway_listener ? 1 : 0);
  add_mapping_pair(map, "gateway_event_priority_levels",
                   kBackendEventPriorityLevels);
  add_mapping_pair(map, "gateway_normal_event_priority",
                   static_cast<int>(BackendEventPriority::kNormal));
  add_mapping_pair(map, "gateway_io_event_priority",
                   static_cast<int>(BackendEventPriority::kGateway));
  add_mapping_pair(
      map, "gateway_background_dispatch_max_interval_us",
      static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
                            kBackendBackgroundDispatchMaxInterval)
                            .count()));
  add_mapping_pair(map, "gateway_background_dispatch_max_callbacks",
                   kBackendBackgroundDispatchMaxCallbacks);
  add_mapping_pair(map, "gateway_background_dispatch_min_priority",
                   static_cast<int>(kBackendBackgroundDispatchMinPriority));
  add_mapping_pair(map, "port", g_gateway_listen_port);
  add_mapping_pair(map, "masters", static_cast<int>(g_gateway_masters.size()));
  add_mapping_pair(map, "sessions", gateway_get_session_count());
  add_mapping_pair(map, "session_fifo_contract_ready", 1);
  add_mapping_pair(map, "session_fifo_depth", gateway_session_fifo_depth_total());
  add_mapping_pair(map, "session_fifo_pending_reservations",
                   gateway_session_fifo_pending_reservations_total());
  add_mapping_pair(map, "session_fifo_enqueued", static_cast<long>(gateway_session_fifo_enqueued_total()));
  add_mapping_pair(map, "session_fifo_flushed", static_cast<long>(gateway_session_fifo_flushed_total()));
  add_mapping_pair(map, "session_fifo_rejected", static_cast<long>(gateway_session_fifo_rejected_total()));
  add_mapping_pair(map, "gateway_data_frames_received",
                   static_cast<long>(g_gateway_runtime_counters.data_frames_received.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_data_frames_applied",
                   static_cast<long>(g_gateway_runtime_counters.data_frames_applied.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_data_frames_rejected",
                   static_cast<long>(g_gateway_runtime_counters.data_frames_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_stale_master_frames_rejected",
                   static_cast<long>(g_gateway_runtime_counters.stale_master_frames_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_sessions_detached_total",
                   static_cast<long>(g_gateway_runtime_counters.sessions_detached.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_session_rebind_attempts",
                   static_cast<long>(g_gateway_runtime_counters.session_rebind_attempts.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_session_rebind_completed",
                   static_cast<long>(g_gateway_runtime_counters.session_rebind_completed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_session_rebind_rejected",
                   static_cast<long>(g_gateway_runtime_counters.session_rebind_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_session_reconnect_expired",
                   static_cast<long>(g_gateway_runtime_counters.session_reconnect_expired.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_tasks_enqueued",
      static_cast<long>(g_gateway_runtime_counters.receive_tasks_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_tasks_dispatched",
      static_cast<long>(g_gateway_runtime_counters.receive_tasks_dispatched.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_tasks_rejected",
      static_cast<long>(g_gateway_runtime_counters.receive_tasks_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_command_callbacks",
                   static_cast<long>(g_gateway_runtime_counters.command_callbacks.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_command_tasks_enqueued",
      static_cast<long>(g_gateway_runtime_counters.command_tasks_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_command_tasks_rejected",
      static_cast<long>(g_gateway_runtime_counters.command_tasks_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_command_tasks_rejected_pending",
      static_cast<long>(g_gateway_runtime_counters.command_tasks_rejected_pending.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_command_tasks_finished",
      static_cast<long>(g_gateway_runtime_counters.command_tasks_finished.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_command_tasks_stale",
                   static_cast<long>(g_gateway_runtime_counters.command_tasks_stale.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_command_tasks_cleared",
      static_cast<long>(g_gateway_runtime_counters.command_tasks_cleared.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_command_input_pending_sessions",
                   gateway_session_command_input_pending_count());
  add_mapping_pair(map, "gateway_command_task_pending_sessions",
                   gateway_session_command_task_pending_count());
  add_mapping_pair(map, "gateway_command_pending_sessions",
                   gateway_session_command_pending_count());
  add_mapping_pair(map, "gateway_read_dispatch_pending_masters",
                   gateway_read_dispatch_pending_count());
  add_mapping_pair(map, "gateway_buffered_input_pending_masters",
                   gateway_buffered_input_pending_count());
  add_mapping_pair(map, "gateway_command_pressure", gateway_command_pressure_count());
  add_mapping_pair(map, "gateway_main_queue_pending", gateway_main_queue_pending_count());
  add_mapping_pair(map, "gateway_main_queue_read_high_watermark",
                   kGatewayMainQueueReadHighWatermark);
  add_mapping_pair(map, "gateway_main_queue_read_low_watermark",
                   kGatewayMainQueueReadLowWatermark);
  add_mapping_pair(
      map, "gateway_main_queue_read_admission_limited",
      static_cast<long>(g_gateway_runtime_counters.main_queue_read_admission_limited.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_queue_read_pressure_events",
      static_cast<long>(g_gateway_runtime_counters.main_queue_read_pressure_events.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_queue_read_paused",
      static_cast<long>(g_gateway_runtime_counters.main_queue_read_paused.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_queue_read_resumed",
      static_cast<long>(g_gateway_runtime_counters.main_queue_read_resumed.load(
          std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_main_queue_read_paused_masters",
                   gateway_main_queue_read_paused_count());
  add_mapping_pair(map, "gateway_reply_tasks_enqueued",
                   static_cast<long>(g_gateway_runtime_counters.reply_tasks_enqueued.load(
                       std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_reply_tasks_inline_fallbacks",
                   static_cast<long>(g_gateway_runtime_counters.reply_tasks_inline_fallbacks.load(
                       std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_reply_reschedule_cmd_in_buf",
                   static_cast<long>(g_gateway_runtime_counters.reply_reschedule_cmd_in_buf.load(
                       std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_enqueued",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_enqueued.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_flushed",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_flushed.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_rejected",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_reserved",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_reserved.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_filled",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_filled.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_released",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_released.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_reservation_misses",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_reservation_misses.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_head_blocked_fills",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_head_blocked_fills.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_head_blocked_predecessors_total",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_head_blocked_predecessors_total.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_output_fifo_head_blocked_predecessors_max",
      static_cast<long>(g_gateway_runtime_counters.output_fifo_head_blocked_predecessors_max.load(
          std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_future_watch_pending", gateway_session_future_watch_count());
  add_mapping_pair(map, "gateway_generic_future_watch_pending", gateway_future_watch_count());
  add_mapping_pair(
      map, "gateway_generic_future_watches_registered",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watches_registered.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watches_rejected",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watches_rejected.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watches_completed",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watches_completed.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watches_failed",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watches_failed.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watches_timed_out",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watches_timed_out.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watches_cancelled",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watches_cancelled.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watch_callbacks",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watch_callbacks.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_generic_future_watch_callback_failures",
      static_cast<long>(g_gateway_runtime_counters.generic_future_watch_callback_failures.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watches_registered",
      static_cast<long>(g_gateway_runtime_counters.future_watches_registered.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watches_rejected",
      static_cast<long>(g_gateway_runtime_counters.future_watches_rejected.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watches_completed",
      static_cast<long>(g_gateway_runtime_counters.future_watches_completed.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watches_failed",
      static_cast<long>(g_gateway_runtime_counters.future_watches_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watches_timed_out",
      static_cast<long>(g_gateway_runtime_counters.future_watches_timed_out.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watches_cancelled",
      static_cast<long>(g_gateway_runtime_counters.future_watches_cancelled.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watch_callbacks",
      static_cast<long>(g_gateway_runtime_counters.future_watch_callbacks.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watch_callback_failures",
      static_cast<long>(g_gateway_runtime_counters.future_watch_callback_failures.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watch_poll_runs",
      static_cast<long>(g_gateway_runtime_counters.future_watch_poll_runs.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watch_poll_items",
      static_cast<long>(g_gateway_runtime_counters.future_watch_poll_items.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watch_poll_budget_hits",
      static_cast<long>(g_gateway_runtime_counters.future_watch_poll_budget_hits.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_future_watch_completion_event_ready", 1);
  add_mapping_pair(
      map, "gateway_future_watch_completion_notifications",
      static_cast<long>(g_gateway_runtime_counters.future_watch_completion_notifications.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_future_watch_completion_wakeups",
      static_cast<long>(g_gateway_runtime_counters.future_watch_completion_wakeups.load(
          std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_future_watch_timer_wakeups",
                   static_cast<long>(g_gateway_runtime_counters.future_watch_timer_wakeups.load(
                       std::memory_order_relaxed)));
  gateway_add_latency_fields(map, "gateway_output_reserve",
                             g_gateway_runtime_counters.output_reserve_ns_total,
                             g_gateway_runtime_counters.output_reserve_ns_max,
                             g_gateway_runtime_counters.output_reserve_samples);
  gateway_add_latency_fields(map, "gateway_future_watch_register",
                             g_gateway_runtime_counters.future_watch_register_ns_total,
                             g_gateway_runtime_counters.future_watch_register_ns_max,
                             g_gateway_runtime_counters.future_watch_register_samples);
  gateway_add_latency_fields(map, "gateway_future_watch_terminal_lag",
                             g_gateway_runtime_counters.future_watch_terminal_lag_ns_total,
                             g_gateway_runtime_counters.future_watch_terminal_lag_ns_max,
                             g_gateway_runtime_counters.future_watch_terminal_lag_samples);
  gateway_add_latency_fields(map, "gateway_future_watch_take",
                             g_gateway_runtime_counters.future_watch_take_ns_total,
                             g_gateway_runtime_counters.future_watch_take_ns_max,
                             g_gateway_runtime_counters.future_watch_take_samples);
  gateway_add_latency_fields(map, "gateway_future_watch_callback",
                             g_gateway_runtime_counters.future_watch_callback_ns_total,
                             g_gateway_runtime_counters.future_watch_callback_ns_max,
                             g_gateway_runtime_counters.future_watch_callback_samples);
  gateway_add_latency_fields(map, "gateway_future_watch_end_to_end",
                             g_gateway_runtime_counters.future_watch_end_to_end_ns_total,
                             g_gateway_runtime_counters.future_watch_end_to_end_ns_max,
                             g_gateway_runtime_counters.future_watch_end_to_end_samples);
  add_mapping_pair(
      map, "gateway_future_watch_main_completion_thread_cpu_total_us",
      static_cast<long>(
          g_gateway_runtime_counters.future_watch_main_completion_thread_cpu_ns_total.load(
              std::memory_order_relaxed) /
          1000));
  add_mapping_pair(
      map, "gateway_future_watch_main_completion_thread_cpu_unavailable",
      static_cast<long>(
          g_gateway_runtime_counters.future_watch_main_completion_thread_cpu_unavailable.load(
              std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_raw_writes_sent",
                   static_cast<long>(g_gateway_runtime_counters.raw_writes_sent.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_raw_writes_failed",
                   static_cast<long>(g_gateway_runtime_counters.raw_writes_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_master_tcp_nodelay_enabled",
      static_cast<long>(g_gateway_runtime_counters.master_tcp_nodelay_enabled.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_master_tcp_nodelay_failed",
      static_cast<long>(g_gateway_runtime_counters.master_tcp_nodelay_failed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_main_drain_runs",
                   static_cast<long>(g_gateway_runtime_counters.main_drain_runs.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_tasks_total",
      static_cast<long>(g_gateway_runtime_counters.main_drain_tasks_total.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_tasks_max",
      static_cast<long>(g_gateway_runtime_counters.main_drain_tasks_max.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_budget_hits",
      static_cast<long>(g_gateway_runtime_counters.main_drain_budget_hits.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_scheduled",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_scheduled.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_coalesced",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_coalesced.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_executed",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_executed.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_main_drain_deferred_task_budget",
                   kGatewayDeferredMainDrainBudget);
  add_mapping_pair(
      map, "gateway_main_drain_deferred_base_wall_budget_us",
      static_cast<long>(kGatewayDeferredMainDrainBaseWallBudget.count() * 1000));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_backlog_wall_budget_us",
      static_cast<long>(kGatewayDeferredMainDrainBacklogWallBudget.count() * 1000));
  add_mapping_pair(map, "gateway_main_drain_deferred_backlog_threshold",
                   kGatewayDeferredMainDrainBacklogThreshold);
  add_mapping_pair(
      map, "gateway_main_drain_deferred_backlog_boosted",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_backlog_boosted.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_tasks_total",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_tasks_total.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_tasks_max",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_tasks_max.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wall_samples",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_wall_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wall_total_us",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_wall_ns_total.load(
                            std::memory_order_relaxed) /
                        1000));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wall_avg_us",
      gateway_avg_us(g_gateway_runtime_counters.main_drain_deferred_wall_ns_total,
                     g_gateway_runtime_counters.main_drain_deferred_wall_samples));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wall_max_us",
      gateway_max_us(g_gateway_runtime_counters.main_drain_deferred_wall_ns_max));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wall_budget_yields",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_wall_budget_yields.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_task_budget_yields",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_task_budget_yields.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_remaining_samples",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_remaining_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_remaining_total",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_remaining_total.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_remaining_avg",
      gateway_avg_value(g_gateway_runtime_counters.main_drain_deferred_remaining_total,
                        g_gateway_runtime_counters.main_drain_deferred_remaining_samples));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_remaining_max",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_remaining_max.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_main_task_wall_max_us",
      gateway_max_us(g_gateway_runtime_counters.main_drain_deferred_main_task_wall_ns_max));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_main_tasks_exceeding_wall_budget",
      static_cast<long>(
          g_gateway_runtime_counters.main_drain_deferred_main_tasks_exceeding_wall_budget.load(
              std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_read_batch_drain_task_budget",
                   kGatewayReadBatchMainDrainBudget);
  add_mapping_pair(
      map, "gateway_read_batch_drain_wall_budget_us",
      static_cast<long>(kGatewayReadBatchMainDrainWallBudget.count() * 1000));
  add_mapping_pair(
      map, "gateway_read_batch_drain_runs",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_runs.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_tasks_total",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_tasks_total.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_tasks_max",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_tasks_max.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_backlog_rescheduled",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_backlog_rescheduled.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_wall_samples",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_wall_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_wall_total_us",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_wall_ns_total.load(
                            std::memory_order_relaxed) /
                        1000));
  add_mapping_pair(
      map, "gateway_read_batch_drain_wall_avg_us",
      gateway_avg_us(g_gateway_runtime_counters.read_batch_drain_wall_ns_total,
                     g_gateway_runtime_counters.read_batch_drain_wall_samples));
  add_mapping_pair(
      map, "gateway_read_batch_drain_wall_max_us",
      gateway_max_us(g_gateway_runtime_counters.read_batch_drain_wall_ns_max));
  add_mapping_pair(
      map, "gateway_read_batch_drain_wall_budget_yields",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_wall_budget_yields.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_task_budget_yields",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_task_budget_yields.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_remaining_samples",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_remaining_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_remaining_total",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_remaining_total.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_remaining_avg",
      gateway_avg_value(g_gateway_runtime_counters.read_batch_drain_remaining_total,
                        g_gateway_runtime_counters.read_batch_drain_remaining_samples));
  add_mapping_pair(
      map, "gateway_read_batch_drain_remaining_max",
      static_cast<long>(g_gateway_runtime_counters.read_batch_drain_remaining_max.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_batch_drain_main_task_wall_max_us",
      gateway_max_us(g_gateway_runtime_counters.read_batch_drain_main_task_wall_ns_max));
  add_mapping_pair(
      map, "gateway_read_batch_drain_main_tasks_exceeding_wall_budget",
      static_cast<long>(
          g_gateway_runtime_counters.read_batch_drain_main_tasks_exceeding_wall_budget.load(
              std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_read_dispatch_budget", kGatewayReadFrameBudget);
  add_mapping_pair(
      map, "gateway_read_dispatch_runs",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_runs.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_frames_total",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_frames_total.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_frames_max",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_frames_max.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_budget_hits",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_budget_hits.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_deferred_scheduled",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_deferred_scheduled.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_deferred_coalesced",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_deferred_coalesced.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_deferred_executed",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_deferred_executed.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_input_paused",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_input_paused.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_input_resumed",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_input_resumed.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_buffer_compactions",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_buffer_compactions.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_buffer_compacted_bytes",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_buffer_compacted_bytes.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_front_shift_bytes_avoided",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_front_shift_bytes_avoided.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_read_dispatch_buffer_peak_bytes",
      static_cast<long>(g_gateway_runtime_counters.read_dispatch_buffer_peak_bytes.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_inline_drain_calls",
      static_cast<long>(g_gateway_runtime_counters.receive_inline_drain_calls.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_deferred_drain_requests",
      static_cast<long>(g_gateway_runtime_counters.receive_deferred_drain_requests.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_main_queue_depth_samples",
      static_cast<long>(g_gateway_runtime_counters.receive_main_queue_depth_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_main_queue_depth_total",
      static_cast<long>(g_gateway_runtime_counters.receive_main_queue_depth_total.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_main_queue_depth_avg",
      gateway_avg_value(g_gateway_runtime_counters.receive_main_queue_depth_total,
                        g_gateway_runtime_counters.receive_main_queue_depth_samples));
  add_mapping_pair(
      map, "gateway_receive_main_queue_depth_max",
      static_cast<long>(g_gateway_runtime_counters.receive_main_queue_depth_max.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wait_samples",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_wait_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wait_total_us",
      static_cast<long>(g_gateway_runtime_counters.main_drain_deferred_wait_ns_total.load(std::memory_order_relaxed) /
                        1000));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wait_avg_us",
      gateway_avg_us(g_gateway_runtime_counters.main_drain_deferred_wait_ns_total,
                     g_gateway_runtime_counters.main_drain_deferred_wait_samples));
  add_mapping_pair(
      map, "gateway_main_drain_deferred_wait_max_us",
      gateway_max_us(g_gateway_runtime_counters.main_drain_deferred_wait_ns_max));
  add_mapping_pair(map, "gateway_main_drain_deferred_wait_timer_queue_only",
                   kGatewayDeferredMainDrainWaitTimerQueueOnly);
  add_mapping_pair(
      map, "gateway_receive_decode_samples",
      static_cast<long>(g_gateway_runtime_counters.receive_decode_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_receive_decode_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.receive_decode_ns_total,
                                  g_gateway_runtime_counters.receive_decode_samples));
  add_mapping_pair(map, "gateway_receive_decode_max_us",
                   gateway_max_us(g_gateway_runtime_counters.receive_decode_ns_max));
  add_mapping_pair(
      map, "gateway_receive_payload_copy_samples",
      static_cast<long>(g_gateway_runtime_counters.receive_payload_copy_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_receive_payload_copy_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.receive_payload_copy_ns_total,
                                  g_gateway_runtime_counters.receive_payload_copy_samples));
  add_mapping_pair(map, "gateway_receive_payload_copy_max_us",
                   gateway_max_us(g_gateway_runtime_counters.receive_payload_copy_ns_max));
  add_mapping_pair(
      map, "gateway_receive_enqueue_to_dispatch_samples",
      static_cast<long>(
          g_gateway_runtime_counters.receive_enqueue_to_dispatch_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_receive_enqueue_to_dispatch_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.receive_enqueue_to_dispatch_ns_total,
                                  g_gateway_runtime_counters.receive_enqueue_to_dispatch_samples));
  add_mapping_pair(map, "gateway_receive_enqueue_to_dispatch_max_us",
                   gateway_max_us(g_gateway_runtime_counters.receive_enqueue_to_dispatch_ns_max));
  add_mapping_pair(
      map, "gateway_receive_apply_samples",
      static_cast<long>(g_gateway_runtime_counters.receive_apply_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_receive_apply_total_us",
                   static_cast<long>(g_gateway_runtime_counters.receive_apply_ns_total.load(
                       std::memory_order_relaxed) /
                                      1000));
  add_mapping_pair(map, "gateway_receive_apply_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.receive_apply_ns_total,
                                  g_gateway_runtime_counters.receive_apply_samples));
  add_mapping_pair(map, "gateway_receive_apply_max_us",
                   gateway_max_us(g_gateway_runtime_counters.receive_apply_ns_max));
  add_mapping_pair(
      map, "gateway_receive_apply_thread_cpu_samples",
      static_cast<long>(g_gateway_runtime_counters.receive_apply_thread_cpu_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_receive_apply_thread_cpu_total_us",
      static_cast<long>(g_gateway_runtime_counters.receive_apply_thread_cpu_ns_total.load(
          std::memory_order_relaxed) /
                         1000));
  add_mapping_pair(
      map, "gateway_receive_apply_thread_cpu_avg_us",
      gateway_avg_us(g_gateway_runtime_counters.receive_apply_thread_cpu_ns_total,
                     g_gateway_runtime_counters.receive_apply_thread_cpu_samples));
  add_mapping_pair(
      map, "gateway_receive_apply_thread_cpu_max_us",
      gateway_max_us(g_gateway_runtime_counters.receive_apply_thread_cpu_ns_max));
  add_mapping_pair(
      map, "gateway_receive_apply_thread_cpu_unavailable",
      static_cast<long>(g_gateway_runtime_counters.receive_apply_thread_cpu_unavailable.load(
          std::memory_order_relaxed)));
  add_mapping_pair(
      map, "gateway_command_enqueue_to_dispatch_samples",
      static_cast<long>(
          g_gateway_runtime_counters.command_enqueue_to_dispatch_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_command_enqueue_to_dispatch_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.command_enqueue_to_dispatch_ns_total,
                                  g_gateway_runtime_counters.command_enqueue_to_dispatch_samples));
  add_mapping_pair(map, "gateway_command_enqueue_to_dispatch_max_us",
                   gateway_max_us(g_gateway_runtime_counters.command_enqueue_to_dispatch_ns_max));
  add_mapping_pair(
      map, "gateway_command_execute_samples",
      static_cast<long>(g_gateway_runtime_counters.command_execute_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_command_execute_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.command_execute_ns_total,
                                  g_gateway_runtime_counters.command_execute_samples));
  add_mapping_pair(map, "gateway_command_execute_max_us",
                   gateway_max_us(g_gateway_runtime_counters.command_execute_ns_max));
  add_mapping_pair(
      map, "gateway_reply_enqueue_to_dispatch_samples",
      static_cast<long>(g_gateway_runtime_counters.reply_enqueue_to_dispatch_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_reply_enqueue_to_dispatch_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.reply_enqueue_to_dispatch_ns_total,
                                  g_gateway_runtime_counters.reply_enqueue_to_dispatch_samples));
  add_mapping_pair(map, "gateway_reply_enqueue_to_dispatch_total_us",
                   static_cast<long>(g_gateway_runtime_counters.reply_enqueue_to_dispatch_ns_total.load(
                                         std::memory_order_relaxed) /
                                     1000));
  add_mapping_pair(map, "gateway_reply_enqueue_to_dispatch_max_us",
                   gateway_max_us(g_gateway_runtime_counters.reply_enqueue_to_dispatch_ns_max));
  add_mapping_pair(
      map, "gateway_reply_execute_samples",
      static_cast<long>(
          g_gateway_runtime_counters.reply_execute_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_reply_execute_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.reply_execute_ns_total,
                                  g_gateway_runtime_counters.reply_execute_samples));
  add_mapping_pair(map, "gateway_reply_execute_total_us",
                   static_cast<long>(g_gateway_runtime_counters.reply_execute_ns_total.load(
                                         std::memory_order_relaxed) /
                                     1000));
  add_mapping_pair(map, "gateway_reply_execute_max_us",
                   gateway_max_us(g_gateway_runtime_counters.reply_execute_ns_max));
  add_mapping_pair(
      map, "gateway_output_enqueue_to_dispatch_samples",
      static_cast<long>(g_gateway_runtime_counters.output_enqueue_to_dispatch_samples.load(
          std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_output_enqueue_to_dispatch_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.output_enqueue_to_dispatch_ns_total,
                                  g_gateway_runtime_counters.output_enqueue_to_dispatch_samples));
  add_mapping_pair(map, "gateway_output_enqueue_to_dispatch_total_us",
                   static_cast<long>(g_gateway_runtime_counters.output_enqueue_to_dispatch_ns_total.load(
                                         std::memory_order_relaxed) /
                                     1000));
  add_mapping_pair(map, "gateway_output_enqueue_to_dispatch_max_us",
                   gateway_max_us(g_gateway_runtime_counters.output_enqueue_to_dispatch_ns_max));
  add_mapping_pair(
      map, "gateway_output_execute_samples",
      static_cast<long>(
          g_gateway_runtime_counters.output_execute_samples.load(std::memory_order_relaxed)));
  add_mapping_pair(map, "gateway_output_execute_avg_us",
                   gateway_avg_us(g_gateway_runtime_counters.output_execute_ns_total,
                                  g_gateway_runtime_counters.output_execute_samples));
  add_mapping_pair(map, "gateway_output_execute_total_us",
                   static_cast<long>(g_gateway_runtime_counters.output_execute_ns_total.load(
                                         std::memory_order_relaxed) /
                                     1000));
  add_mapping_pair(map, "gateway_output_execute_max_us",
                   gateway_max_us(g_gateway_runtime_counters.output_execute_ns_max));
  add_mapping_string(map, "gateway_io_boundary", "main_thread_io_adapter");
  add_mapping_pair(map, "debug", g_gateway_debug);
  add_mapping_pair(map, "max_packet_size", static_cast<LPC_INT>(g_gateway_max_packet_size));
  add_mapping_pair(map, "max_masters", g_gateway_max_masters);
  add_mapping_pair(map, "max_sessions", g_gateway_max_sessions);
  add_mapping_pair(map, "heartbeat_interval", g_gateway_heartbeat_interval);
  add_mapping_pair(map, "heartbeat_timeout", g_gateway_heartbeat_timeout);
  add_mapping_pair(map, "reconnect_grace", g_gateway_reconnect_grace);
  add_mapping_string(map, "heartbeat_timer", g_gateway_heartbeat_timer ? "active" : "inactive");
  add_mapping_pair(map, "uptime", uptime);
  return map;
}

void f_is_gateway_user() {
  auto *ob = sp->u.ob;

  if (sp->type != T_OBJECT || !ob || (ob->flags & O_DESTRUCTED)) {
    if (sp->type == T_OBJECT) {
      free_object(&sp->u.ob, "f_is_gateway_user");
    }
    put_number(0);
    return;
  }

  free_object(&sp->u.ob, "f_is_gateway_user");
  put_number(gateway_is_session(ob) ? 1 : 0);
}

void f_gateway_listen() {
  int bind_all = 0;
  int port = 0;

  if (st_num_arg > 1 && sp->type == T_NUMBER) {
    bind_all = sp->u.number;
    pop_stack();
  }
  if (sp->type == T_NUMBER) {
    port = sp->u.number;
  }
  pop_stack();
  put_number(gateway_listen_internal(port, bind_all));
}

void f_gateway_main_queue_pending() { put_number(gateway_main_queue_pending_count()); }

void f_gateway_buffered_input_pending() {
  put_number(gateway_buffered_input_pending_count());
}

void f_gateway_command_pending() { put_number(gateway_command_pressure_count()); }

void f_gateway_status() {
  auto *map = gateway_status_internal();
  push_refed_mapping(map);
}

void f_gateway_config() {
  int num_args = st_num_arg;
  const char *key = (num_args >= 1 && (sp - num_args + 1)->type == T_STRING)
                        ? (sp - num_args + 1)->u.string
                        : nullptr;
  svalue_t *val = num_args >= 2 ? (sp - num_args + 2) : nullptr;

  if (!key) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  if (strcmp(key, "max_sessions") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_max_sessions = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_max_sessions);
    return;
  }
  if (strcmp(key, "max_masters") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_max_masters = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_max_masters);
    return;
  }
  if (strcmp(key, "timeout") == 0 || strcmp(key, "heartbeat_timeout") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_heartbeat_timeout = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_heartbeat_timeout);
    return;
  }
  if (strcmp(key, "heartbeat_interval") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_heartbeat_interval = val->u.number;
      gateway_start_heartbeat_timer();
    }
    pop_n_elems(num_args);
    push_number(g_gateway_heartbeat_interval);
    return;
  }
  if (strcmp(key, "reconnect_grace") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_reconnect_grace = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_reconnect_grace);
    return;
  }
  if (strcmp(key, "debug") == 0) {
    if (val && val->type == T_NUMBER) {
      g_gateway_debug = val->u.number ? 1 : 0;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_debug);
    return;
  }
  if (strcmp(key, "max_packet_size") == 0) {
    if (val && val->type == T_NUMBER && val->u.number >= 1024) {
      g_gateway_max_packet_size = static_cast<size_t>(val->u.number);
    }
    pop_n_elems(num_args);
    push_number(static_cast<LPC_INT>(g_gateway_max_packet_size));
    return;
  }

  pop_n_elems(num_args);
  push_number(0);
}

void f_gateway_set_heartbeat() {
  int num_args = st_num_arg;
  int interval = (num_args >= 1 && (sp - num_args + 1)->type == T_NUMBER)
                     ? (sp - num_args + 1)->u.number
                     : g_gateway_heartbeat_interval;
  int timeout = (num_args >= 2 && (sp - num_args + 2)->type == T_NUMBER)
                    ? (sp - num_args + 2)->u.number
                    : g_gateway_heartbeat_timeout;

  pop_n_elems(num_args);
  if (interval > 0) {
    g_gateway_heartbeat_interval = interval;
  }
  if (timeout > 0) {
    g_gateway_heartbeat_timeout = timeout;
  }
  gateway_start_heartbeat_timer();
  push_number(1);
}

void f_gateway_check_timeout() {
  if (st_num_arg > 0) {
    pop_n_elems(st_num_arg);
  }
  gateway_check_heartbeat_timeouts();
  gateway_check_session_timeouts();
  push_number(1);
}

void f_gateway_ping_master() {
  int num_args = st_num_arg;
  int master_fd = (num_args >= 1 && (sp - num_args + 1)->type == T_NUMBER)
                      ? (sp - num_args + 1)->u.number
                      : 0;
  int result = 0;

  if (num_args > 0) {
    pop_n_elems(num_args);
  }

  if (master_fd > 0) {
    result = gateway_ping_master_internal(master_fd);
  } else {
    for (const auto &entry : g_gateway_masters) {
      result += gateway_ping_master_internal(entry.first);
    }
  }

  push_number(result);
}

void f_gateway_send() {
  int num_args = st_num_arg;
  svalue_t *data_sv = num_args >= 1 ? (sp - num_args + 1) : nullptr;
  int master_fd = (num_args >= 2 && (sp - num_args + 2)->type == T_NUMBER)
                      ? (sp - num_args + 2)->u.number
                      : 0;
  std::string encoded;
  int sent = 0;

  if (!data_sv || !gateway_svalue_to_json_string(data_sv, &encoded)) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  pop_n_elems(num_args);
  if (master_fd > 0) {
    sent = gateway_send_raw_to_fd(master_fd, encoded.c_str(), encoded.size());
    push_number(sent);
    return;
  }

  for (const auto &entry : g_gateway_masters) {
    sent += gateway_send_raw_to_fd(entry.first, encoded.c_str(), encoded.size());
  }
  push_number(sent);
}
