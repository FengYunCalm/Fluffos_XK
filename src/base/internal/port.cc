#include "config.h"

#include "base/internal/port.h"

#include "base/internal/rc.h"
#include "base/internal/rusage.h"

#include <random>
#include <unistd.h>
#include <cstring>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#endif

// Returns a pseudo-random number in the range 0 .. n-1
int64_t random_number(int64_t n) {
  static bool called = false;
  static std::mt19937_64 engine;

  if (!called) {
    std::random_device rd;
    engine.seed(rd());
    called = true;
  }

  std::uniform_int_distribution<int64_t> dist(0, n - 1);
  return dist(engine);
}

// Returns a secure random number in the range 0 .. n-1
int64_t secure_random_number(int64_t n) {
#ifdef __WIN32
  // On windows we trust default, since we use MINGW which is pretty recent
  static std::random_device rd;
#else
  // On linux & osx we use urandom by default
  static std::random_device rd("/dev/urandom");
#endif
  std::uniform_int_distribution<int64_t> dist(0, n - 1);
  return dist(rd);
}

/*
 * The function time() can't really be trusted to return an integer.
 * But MudOS uses the 'current_time', which is an integer number
 * of seconds. To make this more portable, the following functions
 * should be defined in such a way as to return the number of seconds since
 * some chosen year. The old behaviour of time(), is to return the number
 * of seconds since 1970.
 */

time_t get_current_time() {
  struct timeval t = {};
  gettimeofday(&t, nullptr);
  return t.tv_sec;
}

/*
 * Get a microsecond clock sample.
 */
void get_usec_clock(long *sec, long *usec) {
  struct timeval tv {};

  gettimeofday(&tv, nullptr);
  *sec = tv.tv_sec;
  *usec = tv.tv_usec;
}

long get_cpu_times(unsigned long *secs, unsigned long *usecs) {
  struct rusage rus {};

  if (getrusage(RUSAGE_SELF, &rus) < 0) {
    return 0;
  }
  *secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
  *usecs = rus.ru_utime.tv_usec + rus.ru_stime.tv_usec;

  return 1;
}

int64_t get_current_thread_cpu_time_ns() {
#ifdef _WIN32
  FILETIME created{};
  FILETIME exited{};
  FILETIME kernel{};
  FILETIME user{};
  if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) {
    return -1;
  }

  ULARGE_INTEGER kernel_ticks{};
  ULARGE_INTEGER user_ticks{};
  kernel_ticks.LowPart = kernel.dwLowDateTime;
  kernel_ticks.HighPart = kernel.dwHighDateTime;
  user_ticks.LowPart = user.dwLowDateTime;
  user_ticks.HighPart = user.dwHighDateTime;

  constexpr uint64_t kNanosecondsPerFiletimeTick = 100;
  const auto max_ticks = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) /
                         kNanosecondsPerFiletimeTick;
  if (user_ticks.QuadPart > max_ticks || kernel_ticks.QuadPart > max_ticks - user_ticks.QuadPart) {
    return -1;
  }
  return static_cast<int64_t>((kernel_ticks.QuadPart + user_ticks.QuadPart) *
                              kNanosecondsPerFiletimeTick);
#elif defined(CLOCK_THREAD_CPUTIME_ID)
  struct timespec ts {};
  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0 || ts.tv_nsec < 0 ||
      ts.tv_nsec >= 1000000000L) {
    return -1;
  }

  constexpr uint64_t kNanosecondsPerSecond = 1000000000ULL;
  const auto seconds = static_cast<uint64_t>(ts.tv_sec);
  const auto max_seconds = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) /
                           kNanosecondsPerSecond;
  if (seconds > max_seconds) {
    return -1;
  }
  return static_cast<int64_t>(seconds * kNanosecondsPerSecond + ts.tv_nsec);
#else
  return -1;
#endif
}

/* return the current working directory */
char *get_current_dir(char *buf, int limit) { return getcwd(buf, limit); /* POSIX */ }

/* jemalloc stub, this function can't otherwise be replaced */
#ifdef HAVE_JEMALLOC
char *strdup(const char *str) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif
  if (!str) {
    errno = EINVAL;
    return nullptr;
  }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
  size_t const ln = strlen(str);
  void *p = malloc(ln + 1);
  return static_cast<char *>(memcpy(p, str, ln + 1));
}
#endif
