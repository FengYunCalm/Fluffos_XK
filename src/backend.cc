/* 92/04/18 - cleaned up stylistically by Sulam@TMI */
#include "base/std.h"

#include "backend.h"

#include <chrono>
#include <event2/dns.h>     // for evdns_set_log_fn
#include <event2/event.h>   // for event_add, etc
#include <event2/thread.h>  // for thread support
#include <cmath>            // for exp
#include <cstddef>          // for size_t
#include <cstdio>           // for NULL, sprintf
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <ctime>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <sys/types.h>  // for int64_t
#include <deque>        // for deque
#include <functional>   // for _Bind, less, bind, function
#include <map>          // for multimap, _Rb_tree_iterator
#include <utility>      // for pair, make_pair
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "vm/vm.h"
#include "vm/owner.h"

#include "packages/core/heartbeat.h"
#include "packages/core/reclaim.h"
#ifdef PACKAGE_MUDLIB_STATS
#include "packages/mudlib_stats/mudlib_stats.h"
#endif
#ifdef PACKAGE_SOCKETS
#include "packages/sockets/socket_efuns.h"
#endif

// FIXME: rewrite other part so this could become static.
struct event_base *g_event_base = nullptr;

namespace {
constexpr size_t kDestructedObjectCleanupTickBudget = 1024;

void libevent_log(int severity, const char *msg) {
  if (severity == EVENT_LOG_ERR) {
    debug(all, "libevent:%d:%s\n", severity, msg);
  } else {
    debug(event, "libevent:%d:%s\n", severity, msg);
  }
}
void libevent_dns_log(int severity, const char *msg) {
  if (severity == EVENT_LOG_ERR) {
    debug(all, "libevent dns:%d:%s\n", severity, msg);
  } else {
    debug(dns, "libevent dns:%d:%s\n", severity, msg);
  }
}
}  // namespace
// Initialize backend
event_base *init_backend() {
  event_set_log_callback(libevent_log);
  evdns_set_log_fn(libevent_dns_log);
#ifdef DEBUG
  event_enable_debug_logging(EVENT_DBG_ALL);
  event_enable_debug_mode();
#endif
#ifdef _WIN32
  evthread_use_windows_threads();
#else
  evthread_use_pthreads();
#endif
  auto *event_config = event_config_new();
  if (!event_config) {
    fatal("Unable to allocate Libevent backend configuration.\n");
    return nullptr;
  }
  struct timeval max_background_dispatch_interval {
    static_cast<long>(kBackendBackgroundDispatchMaxInterval.count() / 1000),
        static_cast<long>(
            (kBackendBackgroundDispatchMaxInterval.count() % 1000) * 1000),
  };
  if (event_config_set_max_dispatch_interval(
          event_config, &max_background_dispatch_interval,
          kBackendBackgroundDispatchMaxCallbacks,
          static_cast<int>(kBackendBackgroundDispatchMinPriority)) != 0) {
    event_config_free(event_config);
    fatal("Unable to configure bounded Libevent background dispatch.\n");
    return nullptr;
  }
  g_event_base = event_base_new_with_config(event_config);
  event_config_free(event_config);
  if (!g_event_base ||
      event_base_priority_init(g_event_base, kBackendEventPriorityLevels) != 0) {
    fatal("Unable to initialize Libevent backend priorities.\n");
  }
  vm_context_set_event_base(vm_context(), g_event_base);
  debug_message("Event backend in use: %s\n", event_base_get_method(g_event_base));
  return g_event_base;
}

namespace {
// This is the current game time. Use a large type to avoid dealing with rollover.
std::atomic<uint64_t> g_current_gametick{0};
}

uint64_t current_gametick() { return g_current_gametick.load(std::memory_order_relaxed); }

int time_to_next_gametick(std::chrono::milliseconds msec) {
  return std::max(1, (int)(ceil(msec.count() / (double)CONFIG_INT(__RC_GAMETICK_MSEC__))));
}

std::chrono::milliseconds gametick_to_time(int ticks) {
  return std::chrono::milliseconds(CONFIG_INT(__RC_GAMETICK_MSEC__)) * ticks;
}

namespace {
// TODO: remove the need for this
// Global variable for game ticket event handle.
struct event *g_ev_tick = nullptr;

inline struct timeval gametick_timeval() {
  static struct timeval const val{
      CONFIG_INT(__RC_GAMETICK_MSEC__) / 1000,         // secs
      CONFIG_INT(__RC_GAMETICK_MSEC__) % 1000 * 1000,  // usecs
  };
  return val;
}

// Global structure to holding all events to be executed on gameticks.
using TickQueue = std::multimap<uint64_t, TickEvent *, std::less<>>;
TickQueue g_tick_queue;
std::mutex g_tick_queue_mutex;

// Call all events for current tick
inline size_t call_tick_events() {
  size_t processed = 0;
  // Loop until there are no more events to run.
  //
  // NOTE: some event, like call_out(0), will add event to tick_queue during
  // callback, We need to keep looping until there isn't any eligible events
  // left.
  while (true) {
    std::deque<TickEvent *> all_events;
    {
      std::lock_guard<std::mutex> lock(g_tick_queue_mutex);
      auto iter_end = g_tick_queue.upper_bound(current_gametick());
      // No more eligible events.
      if (iter_end == g_tick_queue.begin()) {
        break;
      }
      auto iter_start = g_tick_queue.begin();

      // Extract and erase eligible events while the queue is stable. Callbacks run below.
      for (auto iter = iter_start; iter != iter_end; iter++) {
        all_events.push_back(iter->second);
      }
      g_tick_queue.erase(iter_start, iter_end);
    }

    // TODO: randomly shuffle the events

    for (auto *event : all_events) {
      if (event->is_valid()) {
        event->callback();
      }
      delete event;
      processed++;
    }
  }
  return processed;
}

void on_game_tick(evutil_socket_t /*fd*/, short /*what*/, void *arg) {
  call_tick_events();
  vm_owner_drain_main_tasks(1024);
  remove_destructed_objects_bounded(kDestructedObjectCleanupTickBudget);
  auto next_gametick = g_current_gametick.fetch_add(1, std::memory_order_relaxed) + 1;
  vm_context_set_current_gametick(vm_context(), next_gametick);

  auto *ev = *(reinterpret_cast<struct event **>(arg));
  auto t = gametick_timeval();
  event_add(ev, &t);
}

}  // namespace

TickEvent *add_gametick_event(int delay_ticks, TickEvent::callback_type callback) {
  auto *event = new TickEvent(callback);
  std::lock_guard<std::mutex> lock(g_tick_queue_mutex);
  g_tick_queue.insert(TickQueue::value_type(current_gametick() + delay_ticks, event));
  return event;
}

namespace {
struct WalltimeEvent {
  explicit WalltimeEvent(TickEvent::callback_type callback, BackendEventPriority priority)
      : tick(callback), priority(priority) {}

  TickEvent tick;
  BackendEventPriority priority;
  struct event *native_event{nullptr};
};

std::unordered_set<WalltimeEvent *> g_walltime_events;
std::mutex g_walltime_events_mutex;

void remove_walltime_event(WalltimeEvent *walltime_event) {
  std::lock_guard<std::mutex> lock(g_walltime_events_mutex);
  g_walltime_events.erase(walltime_event);
}

void destroy_walltime_event(WalltimeEvent *walltime_event) {
  if (!walltime_event) {
    return;
  }
  if (walltime_event->native_event) {
    event_free(walltime_event->native_event);
    walltime_event->native_event = nullptr;
  }
  delete walltime_event;
}

void on_walltime_event(evutil_socket_t /*fd*/, short /*what*/, void *arg) {
  auto *walltime_event = reinterpret_cast<WalltimeEvent *>(arg);
  remove_walltime_event(walltime_event);
  if (walltime_event->tick.is_valid()) {
    walltime_event->tick.callback();
  }
  destroy_walltime_event(walltime_event);
}
}  // namespace

// Schedule a immediate event on main loop.
TickEvent *add_walltime_event(std::chrono::milliseconds delay_msecs,
                              TickEvent::callback_type callback,
                              BackendEventPriority priority) {
  if (!g_event_base) {
    fatal("Cannot schedule walltime event without a Libevent backend.\n");
  }
  if (delay_msecs.count() < 0) {
    delay_msecs = std::chrono::milliseconds(0);
  }
  auto *walltime_event = new WalltimeEvent(std::move(callback), priority);
  walltime_event->native_event =
      evtimer_new(g_event_base, on_walltime_event, walltime_event);
  if (!walltime_event->native_event ||
      event_priority_set(walltime_event->native_event,
                         static_cast<int>(priority)) != 0) {
    destroy_walltime_event(walltime_event);
    fatal("Unable to create prioritized walltime event.\n");
  }

  struct timeval val {
    (int)(delay_msecs.count() / 1000), (int)(delay_msecs.count() % 1000 * 1000),
  };
  {
    std::lock_guard<std::mutex> lock(g_walltime_events_mutex);
    g_walltime_events.insert(walltime_event);
  }
  if (delay_msecs.count() == 0) {
    event_active(walltime_event->native_event, EV_TIMEOUT, 1);
  } else if (event_add(walltime_event->native_event, &val) != 0) {
    remove_walltime_event(walltime_event);
    destroy_walltime_event(walltime_event);
    fatal("Unable to schedule prioritized walltime event.\n");
  }
  return &walltime_event->tick;
}

void clear_tick_events() {
  TickQueue leftover_events;
  std::vector<WalltimeEvent *> leftover_walltime_events;
  {
    std::lock_guard<std::mutex> lock(g_tick_queue_mutex);
    leftover_events.swap(g_tick_queue);
  }
  {
    std::lock_guard<std::mutex> lock(g_walltime_events_mutex);
    leftover_walltime_events.reserve(g_walltime_events.size());
    for (auto *event : g_walltime_events) {
      leftover_walltime_events.push_back(event);
    }
    g_walltime_events.clear();
  }
  int i = 0;
  for (auto &iter : leftover_events) {
    delete iter.second;
    i++;
  }
  for (auto *event : leftover_walltime_events) {
    event->tick.cancel();
    destroy_walltime_event(event);
    i++;
  }
  debug_message("clear_tick_events: %d leftover events cleared.\n", i);
}

size_t tick_event_queue_size_for_test() {
  std::lock_guard<std::mutex> lock(g_tick_queue_mutex);
  return g_tick_queue.size();
}

size_t run_tick_events_for_test() { return call_tick_events(); }

size_t walltime_event_queue_size_for_test() {
  std::lock_guard<std::mutex> lock(g_walltime_events_mutex);
  return g_walltime_events.size();
}

int walltime_event_priority_for_test(TickEvent *event) {
  std::lock_guard<std::mutex> lock(g_walltime_events_mutex);
  for (auto *walltime_event : g_walltime_events) {
    if (&walltime_event->tick == event && walltime_event->native_event) {
      return event_get_priority(walltime_event->native_event);
    }
  }
  return -1;
}

namespace {
void look_for_objects_to_swap();
}

// FIXME:
void call_remove_destructed_objects() {
  add_gametick_event(time_to_next_gametick(std::chrono::minutes(5)),
                     TickEvent::callback_type(call_remove_destructed_objects));
  remove_destructed_objects();
}
/*
 * This is the backend. We will stay here for ever (almost).
 */
void backend(struct event_base *base) {
  clear_state();
  g_current_gametick.store(0, std::memory_order_relaxed);
  vm_context_set_current_gametick(vm_context(), current_gametick());

  // Register various tick events
  add_gametick_event(0, TickEvent::callback_type(call_heart_beat));
  add_gametick_event(time_to_next_gametick(std::chrono::minutes(5)),
                     TickEvent::callback_type(look_for_objects_to_swap));
  add_gametick_event(time_to_next_gametick(std::chrono::minutes(30)),
                     TickEvent::callback_type([] { return reclaim_objects(true); }));
#ifdef PACKAGE_MUDLIB_STATS
  add_gametick_event(time_to_next_gametick(std::chrono::minutes(60)),
                     TickEvent::callback_type(mudlib_stats_decay));
#endif
  add_gametick_event(time_to_next_gametick(std::chrono::minutes(5)),
                     TickEvent::callback_type(call_remove_destructed_objects));

  // NOTE: we don't use EV_PERSITENT here because that use fix-rate scheduling.
  //
  // Schedule a repeating tick for advancing virtual time.
  // Gametick provides a fixed-delay scheduling with a guaranteed minimum delay for
  // heartbeats, callouts, and various cleaning function.
  g_ev_tick = evtimer_new(base, on_game_tick, &g_ev_tick);
  if (!g_ev_tick ||
      event_priority_set(g_ev_tick,
                         static_cast<int>(BackendEventPriority::kNormal)) != 0) {
    fatal("Unable to create normal-priority gametick event.\n");
  }

  auto t = gametick_timeval();
  event_add(g_ev_tick, &t);

  try {
    event_base_loop(base, 0);
  } catch (...) {  // catch everything
    fatal("BUG: jumped out of event loop!");
  }
  // We've reached here meaning we are in shutdown sequence.
  shutdownMudOS(-1);
} /* backend() */

namespace {
/*
 * Despite the name, this routine takes care of several things.
 * It will run once every 5 minutes.
 *
 * . It will loop through all objects.
 *
 *   . If an object is found in a state of not having done reset, and the
 *     delay to next reset has passed, then reset() will be done.
 *
 *   . If the object has a existed more than the time limit given for swapping,
 *     then 'clean_up' will first be called in the object
 *
 * There are some problems if the object self-destructs in clean_up, so
 * special care has to be taken of how the linked list is used.
 */
void look_for_objects_to_swap() {
  auto time_to_clean_up = CONFIG_INT(__TIME_TO_CLEAN_UP__);

  /* Next time is in 5 minutes */
  add_gametick_event(time_to_next_gametick(std::chrono::seconds(5 * 60)),
                     TickEvent::callback_type(look_for_objects_to_swap));

  object_t *ob, *next_ob, *last_good_ob;
  /*
   * Objects object can be destructed, which means that next object to
   * investigate is saved in next_ob. If very unlucky, that object can be
   * destructed too. In that case, the loop is simply restarted.
   */
  next_ob = obj_list;
  last_good_ob = obj_list;
  while (true) {
    while ((ob = (object_t *)next_ob)) {
      int ready_for_clean_up = 0;

      if (ob->flags & O_DESTRUCTED) {
        if (last_good_ob->flags & O_DESTRUCTED) {
          ob = obj_list; /* restart */
        } else {
          ob = (object_t *)last_good_ob;
        }
      }
      next_ob = ob->next_all;

      /*
       * Check reference time before reset() is called.
       */
      if (gametick_to_time(current_gametick() - ob->time_of_ref) >=
          std::chrono::seconds(time_to_clean_up)) {
        ready_for_clean_up = 1;
      }
      if (!CONFIG_INT(__RC_NO_RESETS__) && !CONFIG_INT(__RC_LAZY_RESETS__)) {
        /*
         * Should this object have reset(1) called ?
         */
        if ((ob->flags & O_WILL_RESET) && (current_gametick() >= ob->next_reset) &&
            !(ob->flags & O_RESET_STATE)) {
          debug(d_flag, "RESET /%s\n", ob->obname);
          reset_object(ob);
          if (ob->flags & O_DESTRUCTED) {
            continue;
          }
        }
      }
      if (time_to_clean_up > 0) {
        /*
         * Has enough time passed, to give the object a chance to
         * self-destruct ? Save the O_RESET_STATE, which will be cleared.
         *
         * Only call clean_up in objects that has defined such a function.
         *
         * Only if the clean_up returns a non-zero value, will it be called
         * again.
         */

        if (ready_for_clean_up && (ob->flags & O_WILL_CLEAN_UP)) {
          int const save_reset_state = ob->flags & O_RESET_STATE;

          debug(d_flag, "clean up /%s\n", ob->obname);

          /*
           * Supply a flag to the object that says if this program is
           * inherited by other objects. Cloned objects might as well
           * believe they are not inherited. Swapped objects will not
           * have a ref count > 1 (and will have an invalid ob->prog
           * pointer).
           *
           * Note that if it is in the apply_low cache, it will also
           * get a flag of 1, which may cause the mudlib not to clean
           * up the object.  This isn't bad because:
           * (1) one expects it is rare for objects that have untouched
           * long enough to clean_up to still be in the cache, especially
           * on busy MUDs.
           * (2) the ones that are are the more heavily used ones, so
           * keeping them around seems justified.
           */

          push_number(ob->flags & (O_CLONE) ? 0 : ob->prog->ref);
          set_eval(max_eval_cost);
          auto *svp = safe_apply(APPLY_CLEAN_UP, ob, 1, ORIGIN_DRIVER);
          if (!svp || (svp->type == T_NUMBER && svp->u.number == 0)) {
            ob->flags &= ~O_WILL_CLEAN_UP;
          }
          ob->flags |= save_reset_state;
        }
      }
      last_good_ob = ob;
    }
    break;
  }
} /* look_for_objects_to_swap() */

}  // namespace

namespace {
// TODO: Figure out what to do with this.
const int K_NUM_CONST = 5;
const double CONSTS[K_NUM_CONST]{
    exp(0 / 900.0), exp(-1 / 900.0), exp(-2 / 900.0), exp(-3 / 900.0), exp(-4 / 900.0),
};
double load_av = 0.0;
}  // namespace

void update_load_av() {
  static long last_time;
  int n;
  double c;
  static int acc = 0;

  auto now = get_current_time();
  acc++;
  if (now == last_time) {
    return;
  }
  n = now - last_time;
  if (n < K_NUM_CONST) {
    c = CONSTS[n];
  } else {
    c = exp(-n / 900.0);
  }
  load_av = c * load_av + acc * (1 - c) / n;
  last_time = now;
  acc = 0;
} /* update_load_av() */

static double compile_av = 0.0;

void update_compile_av(int lines) {
  static long last_time;
  int n;
  double c;
  static int acc = 0;

  auto now = get_current_time();
  acc += lines;
  if (now == last_time) {
    return;
  }
  n = now - last_time;
  if (n < K_NUM_CONST) {
    c = CONSTS[n];
  } else {
    c = exp(-n / 900.0);
  }
  compile_av = c * compile_av + acc * (1 - c) / n;
  last_time = now;
  acc = 0;
} /* update_compile_av() */

char *query_load_av() {
  static char buff[100];

  sprintf(buff, "%.2f cmds/s, %.2f comp lines/s", load_av, compile_av);
  return (buff);
} /* query_load_av() */
