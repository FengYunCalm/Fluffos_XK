// Timer implementation with POSIX timer, only works on linux
#ifdef __linux__

#include "base/std.h"

#include "vm/internal/posix_timers.h"

#include <cstdio>   // for perror()
#include <cstdlib>  // for exit()
#include <mutex>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "base/internal/vm_thread_local.h"
#include "vm/internal/eval_limit.h"

namespace {
std::once_flag eval_signal_handler_once;

void set_eval_timer_thread_id(struct sigevent &sev, pid_t thread_id) {
#if defined(__GLIBC__)
  // glibc exposes the Linux SIGEV_THREAD_ID slot only through this ABI field.
  sev._sigev_un._tid = thread_id;
#elif defined(sigev_notify_thread_id)
  // musl exposes the same Linux slot through the public compatibility macro.
  sev.sigev_notify_thread_id = thread_id;
#else
#error "Linux libc does not expose a SIGEV_THREAD_ID target field"
#endif
}

void eval_timer_handler(int /*sig*/, siginfo_t *si, void * /*uc*/) {
  if (!si->si_value.sival_ptr) {
    outoftime = 1;
  }
}

void install_eval_signal_handler() {
  std::call_once(eval_signal_handler_once, [] {
    struct sigaction sa = {};
    sa.sa_sigaction = eval_timer_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGVTALRM, &sa, nullptr) < 0) {
      perror("init_posix_timers: sigaction");
      exit(-1);
    }
  });
}

class ThreadEvalTimer {
 public:
  ThreadEvalTimer() = default;
  ~ThreadEvalTimer() {
    if (initialized_) {
      timer_delete(timer_id_);
    }
  }

  ThreadEvalTimer(const ThreadEvalTimer &) = delete;
  ThreadEvalTimer &operator=(const ThreadEvalTimer &) = delete;

  void initialize() {
    if (initialized_) {
      return;
    }

    install_eval_signal_handler();

    struct sigevent sev = {};
    sev.sigev_signo = SIGVTALRM;
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_value.sival_ptr = nullptr;
    set_eval_timer_thread_id(sev, static_cast<pid_t>(syscall(SYS_gettid)));

    int result = -1;
// Only CLOCK_REALTIME is standard.
#if defined(CLOCK_MONOTONIC_COARSE)
    result = timer_create(CLOCK_MONOTONIC_COARSE, &sev, &timer_id_);
#endif
#if defined(CLOCK_MONOTONIC)
    if (result < 0) {
      result = timer_create(CLOCK_MONOTONIC, &sev, &timer_id_);
    }
#endif
    if (result < 0) {
      result = timer_create(CLOCK_REALTIME, &sev, &timer_id_);
    }
    if (result < 0) {
      perror("init_posix_timers: timer_create");
      exit(-1);
    }
    initialized_ = true;
  }

  void set(uint64_t micros) {
    initialize();
    struct itimerspec it = {};
    it.it_value.tv_sec = micros / 1000000;
    it.it_value.tv_nsec = micros % 1000000 * 1000;
    timer_settime(timer_id_, 0, &it, nullptr);
  }

  uint64_t get() {
    initialize();
    struct itimerspec it = {};
    if (timer_gettime(timer_id_, &it) < 0) {
      return 100;
    }
    return it.it_value.tv_sec * static_cast<uint64_t>(1000000) +
           it.it_value.tv_nsec / 1000;
  }

 private:
  timer_t timer_id_{};
  bool initialized_{false};
};

FLUFFOS_VM_THREAD_LOCAL ThreadEvalTimer eval_timer;
}  // namespace

/* Called by main() to initialize the eval timer for the current VM thread. */
void init_posix_timers(void) { eval_timer.initialize(); }

/* Set the eval timer for the current VM thread to the given microseconds. */
void posix_eval_timer_set(uint64_t micros) { eval_timer.set(micros); }

/* Return the remaining microseconds on the current VM thread's eval timer. */
uint64_t posix_eval_timer_get(void) { return eval_timer.get(); }

#endif  // __linux__
