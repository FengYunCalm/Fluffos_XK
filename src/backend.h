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

constexpr int kBackendEventPriorityLevels = 3;

enum class BackendEventPriority : int {
  kNormal = 0,
  kGateway = 1,
  kBackground = 2,
};

// Re-poll after a bounded Gateway/background batch so newly due normal work,
// or newly ready Gateway I/O ahead of optional warmups, can be admitted.
constexpr auto kBackendBackgroundDispatchMaxInterval = std::chrono::milliseconds(2);
constexpr int kBackendBackgroundDispatchMaxCallbacks = 8;
constexpr auto kBackendBackgroundDispatchMinPriority =
    BackendEventPriority::kGateway;

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
