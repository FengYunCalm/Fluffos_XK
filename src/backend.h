#ifndef BACKEND_H
#define BACKEND_H

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>

/*
 * backend.c
 */

// Global event base
extern struct event_base *g_event_base;

// Initialization of main game loop.
struct event_base *init_backend();

// This is the main game loop.
void backend(struct event_base *);

constexpr int kBackendEventPriorityLevels = 2;

enum class BackendEventPriority : int {
  kNormal = 0,
  kGateway = 0,
  kBackground = 1,
};

constexpr size_t kBackendTickEventCallbackBudget = 64;
constexpr auto kBackendTickEventWallBudget = std::chrono::milliseconds(4);
constexpr auto kBackendTickContinuationDelay = std::chrono::milliseconds(1);
constexpr int kBackendOwnerMainDrainTaskBudget = 64;
constexpr auto kBackendOwnerMainDrainWallBudget = std::chrono::milliseconds(8);
constexpr auto kBackendOwnerMainDrainContinuationDelay =
    std::chrono::milliseconds(1);

struct BackendRuntimeStatus {
  uint64_t tick_slice_runs{0};
  uint64_t tick_slice_callbacks_total{0};
  uint64_t tick_slice_callbacks_max{0};
  uint64_t tick_slice_budget_yields{0};
  uint64_t tick_slice_wall_yields{0};
  uint64_t tick_continuations_scheduled{0};
  uint64_t tick_continuations_executed{0};
  uint64_t owner_main_slice_runs{0};
  uint64_t owner_main_slice_tasks_total{0};
  uint64_t owner_main_slice_tasks_max{0};
  uint64_t owner_main_slice_task_budget_yields{0};
  uint64_t owner_main_slice_wall_yields{0};
  uint64_t owner_main_tasks_exceeding_wall_budget{0};
  uint64_t owner_main_continuations_scheduled{0};
  uint64_t owner_main_continuations_executed{0};
  bool owner_main_continuation_pending{false};
};

BackendRuntimeStatus backend_runtime_status();

// Re-poll after a bounded Gateway/background batch so newly due normal work,
// or newly ready Gateway I/O ahead of optional warmups, can be admitted.
constexpr auto kBackendBackgroundDispatchMaxInterval = std::chrono::milliseconds(2);
constexpr int kBackendBackgroundDispatchMaxCallbacks = 8;
constexpr auto kBackendBackgroundDispatchMinPriority =
    BackendEventPriority::kBackground;

// API for registering game tick event.
// Game ticks provides guaranteed spacing intervals between each invocation.
struct TickEvent {
  using callback_type = std::function<void()>;
  callback_type callback;

  TickEvent(callback_type &callback) : callback(callback) {}

  void cancel() noexcept { valid_.store(false, std::memory_order_release); }
  bool is_valid() const noexcept { return valid_.load(std::memory_order_acquire); }

 private:
  std::atomic<bool> valid_{true};
};

// Register a event to run on game ticks.
TickEvent *add_gametick_event(int delay_ticks, TickEvent::callback_type callback);
// Realtime event will be executed as close to designated walltime as possible.
TickEvent *add_walltime_event(std::chrono::milliseconds delay_msecs,
                              TickEvent::callback_type callback,
                              BackendEventPriority priority = BackendEventPriority::kNormal);

// Used in shutdownMudos()
void clear_tick_events();

// Native test support for exercising the queue without running the event loop.
size_t tick_event_queue_size_for_test();
size_t run_tick_events_for_test();
size_t walltime_event_queue_size_for_test();
int walltime_event_priority_for_test(TickEvent *event);

// Util to help translate gameticks with time.
uint64_t current_gametick();
int time_to_next_gametick(std::chrono::milliseconds msec);
std::chrono::milliseconds gametick_to_time(int ticks);

void update_load_av();
void update_compile_av(int);
char *query_load_av();

#endif
