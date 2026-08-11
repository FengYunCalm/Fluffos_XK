#ifndef _STRALLOC_H_
#define _STRALLOC_H_

#include "base/internal/options_incl.h"
#include "base/internal/vm_thread_local.h"

#include <atomic>
#include <cstdint>
#include <climits>  // for UINT_MAX
#include <cstring>  // for strlen
#include <sstream>  // for std::stringstream

#ifdef DEBUGMALLOC
char *int_string_copy(const char *const, const char *);
char *int_string_unlink(const char *, const char *);
char *int_new_string(unsigned int, const char *);
char *int_alloc_cstring(const char *, const char *);
#else
char *int_string_copy(const char *const);
char *int_string_unlink(const char *);
char *int_new_string(unsigned int);
char *int_alloc_cstring(const char *);
#endif

#ifdef DEBUGMALLOC
#define string_copy(x, y) int_string_copy(x, y)
#define string_unlink(x, y) int_string_unlink(x, y)
#define new_string(x, y) int_new_string(x, y)
#define alloc_cstring(x, y) int_alloc_cstring(x, y)
#else
#define string_copy(x, y) int_string_copy(x)
#define string_unlink(x, y) int_string_unlink(x)
#define new_string(x, y) int_new_string(x)
#define alloc_cstring(x, y) int_alloc_cstring(x)
#endif

struct outbuffer_t;

/* ref-count debugging code */
#undef NOISY_DEBUG
#define NOISY_STRING "workroom"

/* implementation */
#ifdef NOISY_DEBUG
void bp(void);
#ifdef NOISY_STRING
#define NDBG(x) \
  if (strcmp(STRING(x), NOISY_STRING) == 0) debug_message("%s - %d\n", STRING(x), REFS(x)), bp()
#else
#define NDBG(x) debug_message("%s - %d\n", STRING(x), REFS(x)), bp()
#endif
#else
#define NDBG(x)
#endif

#define CHECK_STRING_STATS
#if defined(DEBUG) && defined(DEBUGMALLOC_EXTENSIONS)
/* Uncomment for very complete string ref checking, but be warned it runs
   _very_ slowly.  A conditional definition like:

   (current_prog && strcmp(current_prog->name, "foo") == 0 ?
   check_string_stats(0) : 0)

   is usually best.
 */
void check_string_stats(outbuffer_t *);
#undef CHECK_STRING_STATS
// #define CHECK_STRING_STATS check_string_stats(nullptr)  // enable when need to debug
#define CHECK_STRING_STATS
#endif

namespace stralloc_detail {
template <typename Length>
constexpr uint64_t bytes_with_terminator(Length length) noexcept {
  return static_cast<uint64_t>(length + 1);
}

constexpr int64_t logical_length(unsigned int stored_length) noexcept {
  return stored_length == UINT_MAX ? -1 : static_cast<int64_t>(stored_length);
}

inline void adjust_byte_counter(std::atomic<uint64_t> &counter, int64_t delta) noexcept {
  if (delta >= 0) {
    counter.fetch_add(static_cast<uint64_t>(delta), std::memory_order_relaxed);
    return;
  }
  const auto magnitude = static_cast<uint64_t>(-(delta + 1)) + 1;
  counter.fetch_sub(magnitude, std::memory_order_relaxed);
}
}  // namespace stralloc_detail

#define ADD_NEW_STRING(len, overhead)                                                \
  do {                                                                               \
    num_distinct_strings.fetch_add(1, std::memory_order_relaxed);                    \
    bytes_distinct_strings.fetch_add(stralloc_detail::bytes_with_terminator((len)),  \
                                     std::memory_order_relaxed);                     \
    overhead_bytes.fetch_add(static_cast<uint64_t>(overhead),                        \
                             std::memory_order_relaxed);                             \
  } while (0)
#define SUB_NEW_STRING(len, overhead)                                                \
  do {                                                                               \
    num_distinct_strings.fetch_sub(1, std::memory_order_relaxed);                    \
    bytes_distinct_strings.fetch_sub(stralloc_detail::bytes_with_terminator((len)),  \
                                     std::memory_order_relaxed);                     \
    overhead_bytes.fetch_sub(static_cast<uint64_t>(overhead),                        \
                             std::memory_order_relaxed);                             \
  } while (0)
#define ADD_STRING(len)                                                              \
  do {                                                                               \
    allocd_strings.fetch_add(1, std::memory_order_relaxed);                          \
    allocd_bytes.fetch_add(stralloc_detail::bytes_with_terminator((len)),            \
                           std::memory_order_relaxed);                               \
    CHECK_STRING_STATS;                                                              \
  } while (0)
#define ADD_STRING_SIZE(len)                                                         \
  do {                                                                               \
    const auto string_size_delta = static_cast<int64_t>(len);                        \
    stralloc_detail::adjust_byte_counter(allocd_bytes, string_size_delta);            \
    stralloc_detail::adjust_byte_counter(bytes_distinct_strings, string_size_delta);  \
  } while (0)
#define SUB_STRING(len)                                                              \
  do {                                                                               \
    allocd_strings.fetch_sub(1, std::memory_order_relaxed);                          \
    allocd_bytes.fetch_sub(stralloc_detail::bytes_with_terminator((len)),            \
                           std::memory_order_relaxed);                               \
    CHECK_STRING_STATS;                                                              \
  } while (0)

// The layout of malloc_block_s must be same as block_s
typedef struct malloc_block_s {
  void *_padding1;
  unsigned int _padding2;
#ifdef DEBUGMALLOC_EXTENSIONS
  unsigned int extra_ref;
#endif
  unsigned int size;
  unsigned short ref;
} malloc_block_t;

#define MSTR_BLOCK(x) (((malloc_block_t *)(x)) - 1)
#define MSTR_EXTRA_REF(x) (MSTR_BLOCK(x)->extra_ref)
#define MSTR_REF(x) (MSTR_BLOCK(x)->ref)
#define MSTR_SIZE(x) (MSTR_BLOCK(x)->size)
#define MSTR_UPDATE_SIZE(x, y)                                                        \
  SAFE(const auto requested_string_size = (y);                                       \
       const auto stored_string_size =                                               \
           requested_string_size > UINT_MAX ? UINT_MAX                               \
                                            : static_cast<unsigned int>(requested_string_size); \
       ADD_STRING_SIZE(stralloc_detail::logical_length(stored_string_size) -         \
                       stralloc_detail::logical_length(MSTR_SIZE(x)));                \
       MSTR_BLOCK(x)->size = stored_string_size;)

#define FREE_MSTR(x)                                                                      \
  SAFE(DEBUG_CHECK(MSTR_REF(x) != 1, "FREE_MSTR used on a multiply referenced string\n"); \
       svalue_strlen_size = MSTR_SIZE(x);                                                 \
       SUB_NEW_STRING(svalue_strlen_size, sizeof(malloc_block_t)); FREE(MSTR_BLOCK(x));   \
       SUB_STRING(svalue_strlen_size);)

/* This counts on some rather crucial alignment between malloc_block_t and
 * block_t.  COUNTED_STRLEN(x) is the same as strlen(sv->u.string) when
 * sv->subtype is STRING_MALLOC or STRING_SHARED, and runs significantly
 * faster.
 */
#define COUNTED_STRLEN(x)               \
  ((svalue_strlen_size = MSTR_SIZE(x)), \
   svalue_strlen_size != UINT_MAX ? svalue_strlen_size : strlen((x) + UINT_MAX) + UINT_MAX)
/* return the number of references to a STRING_MALLOC or STRING_SHARED
   string */
#define COUNTED_REF(x) MSTR_REF(x)

/* ref == 0 means the string has been referenced USHRT_MAX times and is
   immortal */
#define INC_COUNTED_REF(x) \
  if (MSTR_REF(x)) { MSTR_REF(x)++; }
/* This is a conditional expression that evaluates to zero if the block
   should be deallocated */
#define DEC_COUNTED_REF(x) (!(MSTR_REF(x) == 0 || --MSTR_REF(x) > 0))

typedef struct block_s {
  struct block_s *next; /* next block in the hash chain */
  unsigned int hash;
#if defined(DEBUGMALLOC_EXTENSIONS)  //|| (SIZEOF_CHAR_P == 8)
  unsigned int extra_ref;
#endif
  /* these two must be last */
  unsigned int size;   /* length of the string */
  unsigned short refs; /* reference count    */
} block_t;

static_assert(sizeof(malloc_block_t) == sizeof(block_t),
              "Block size mismatch, this will cause memory corruption!");

#define NEXT(x) (x)->next
#define REFS(x) (x)->refs
#define EXTRA_REF(x) (x)->extra_ref
#define SIZE(x) (x)->size
#define HASH(x) (x)->hash
#define BLOCK(x) (((block_t *)(x)) - 1) /* pointer arithmetic */
#define STRING(x) ((char *)(x + 1))

#define SHARED_STRLEN(x) COUNTED_STRLEN(x)

#define SVALUE_STRLEN(x) \
  (((x)->subtype & STRING_COUNTED) ? COUNTED_STRLEN((x)->u.string) : strlen((x)->u.string))

/* For quick checks.  Avoid strlen(), etc.  This is  */
#define SVALUE_STRLEN_DIFFERS(x, y)                                     \
  ((((x)->subtype & STRING_COUNTED) && ((y)->subtype & STRING_COUNTED)) \
       ? MSTR_SIZE((x)->u.string) != MSTR_SIZE((y)->u.string)           \
       : 0)
/*
 * stralloc.c
 */
void init_strings(void);
const char *findstring(const char *);
const char *int_make_shared_string(const char *, const char *);
const char *int_ref_string(const char *, const char *);
#define ref_string(x) int_ref_string(x, __CURRENT_FILE_LINE__)
void int_free_string(const char *, const char *);
#define free_string(x) int_free_string(x, __CURRENT_FILE_LINE__)
void deallocate_string(char *);
uint64_t add_string_status(outbuffer_t *, int);

char *extend_string(const char *, int);

extern FLUFFOS_VM_THREAD_LOCAL unsigned int svalue_strlen_size;

#define make_shared_string(s) int_make_shared_string(s, __CURRENT_FILE_LINE__)
void stralloc_print_entry(std::stringstream &ss, block_t* entry);
void dump_stralloc(outbuffer_t *out);
#endif
