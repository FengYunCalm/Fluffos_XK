#ifndef FLUFFOS_SRC_COMPILER_INTERNAL_COMPILE_ARENA_H_
#define FLUFFOS_SRC_COMPILER_INTERNAL_COMPILE_ARENA_H_

// #1247 C-S1: compile-scope monotonic arena -- the sole owner of the
// compiler's scratch chunk pool. Explicit begin/end (NOT RAII: error() is
// longjmp, machine.h:38 [[noreturn]], so cross-frame destructors never
// run; compile_file() calls begin() at entry and end() on BOTH the success
// and the error-cleanup paths).
//
// Pool: one static 1MB base chunk plus up to kMaxRetainedStandardChunks
// retained 1MB standard chunks; oversize exact-fit chunks are always
// released at scope end. Allocation is a max_align_t-aligned monotonic
// bump that never crosses a chunk. Individual deallocation is a no-op.

#include <cstddef>
#include <cstdint>

namespace compile_arena {

constexpr size_t kBaseChunkSize = 1u << 20;  // 1MB
constexpr size_t kMaxRetainedStandardChunks = 8;

// Start a compile scope: rewind the bump cursor to the base chunk. The
// retained chunk pool survives across scopes.
void begin() noexcept;

// End a compile scope: release oversize chunks and any standard chunks
// beyond the retention ceiling, return the pool to the retained list,
// rewind the base cursor. Safe to call without begin().
void end() noexcept;

// Monotonic bump allocation, max_align_t aligned, never crossing a chunk.
// Returns nullptr only for size 0 (callers treat 0 as no-op).
void *alloc(size_t size);

// Allocate len+1 bytes and NUL-terminate (len excludes the NUL).
char *alloc_string(size_t len);

// Observability (mud_status()).
size_t cycle_bytes() noexcept;       // bytes used in the current scope
size_t peak_cycle_bytes() noexcept;  // high-water of cycle_bytes
size_t chunk_mallocs() noexcept;     // malloc() calls for chunks
size_t reset_count() noexcept;       // end() calls
size_t retained_chunks() noexcept;  // chunks in the retained pool
size_t retained_heap_bytes() noexcept;  // heap bytes of retained chunks

}  // namespace compile_arena

#endif /* FLUFFOS_SRC_COMPILER_INTERNAL_COMPILE_ARENA_H_ */
