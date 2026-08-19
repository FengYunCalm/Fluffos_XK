// #1247 C-S1: compile-scope monotonic arena implementation.

#include "compile_arena.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <new>

#include "base/std.h"

namespace compile_arena {

namespace {

struct Chunk {
  Chunk *next;      // retained-pool / live-chain link
  size_t size;      // usable bytes of data
  size_t used;      // bump cursor
  bool oversize;    // exact-fit chunk: always released at scope end
  char *data;       // points into the static base array or the malloc'd block
};

// Static base chunk: 1MB in BSS, never freed.
alignas(max_align_t) char g_base_data[kBaseChunkSize];
Chunk g_base{nullptr, kBaseChunkSize, 0, false, g_base_data};

// Live chain: chunks allocated during the current scope (base excluded).
Chunk *g_live = nullptr;
// Retained pool: standard chunks kept across scopes (LIFO).
Chunk *g_retained = nullptr;
size_t g_retained_count = 0;

Chunk *g_current = &g_base;

size_t g_cycle_bytes = 0;
size_t g_peak_cycle_bytes = 0;
size_t g_chunk_mallocs = 0;
size_t g_reset_count = 0;
size_t g_retained_heap_bytes = 0;

constexpr size_t kChunkHeaderSize = sizeof(Chunk);

size_t align_up(size_t n) {
  constexpr size_t kAlign = alignof(max_align_t);
  return (n + kAlign - 1) & ~(kAlign - 1);
}

Chunk *new_chunk(size_t size, bool oversize) {
  void *mem = DMALLOC(kChunkHeaderSize + size, TAG_COMPILER, "compile_arena");
  g_chunk_mallocs++;
  Chunk *c = new (mem) Chunk;
  c->next = nullptr;
  c->size = size;
  c->used = 0;
  c->oversize = oversize;
  c->data = reinterpret_cast<char *>(mem) + kChunkHeaderSize;
  return c;
}

void free_chunk(Chunk *c) {
  // Oversize chunks never enter the retained pool, so they never touch
  // g_retained_heap_bytes (only retained standard chunks are accounted).
  FREE(c);
}

// Take a standard chunk from the retained pool, or allocate one.
Chunk *acquire_standard() {
  if (g_retained) {
    Chunk *c = g_retained;
    g_retained = c->next;
    g_retained_count--;
    g_retained_heap_bytes -= c->size;
    c->next = nullptr;
    c->used = 0;
    return c;
  }
  return new_chunk(kBaseChunkSize, false);
}

}  // namespace

void begin() noexcept {
  // A previous error() exception (simulate.cc:2325) may have left the
  // live chain populated (end() does not run on that path); drain it
  // first so the scope starts clean and the retained pool stays bounded.
  if (g_live) {
    end();
  }
  g_base.used = 0;
  g_current = &g_base;
  g_cycle_bytes = 0;
}

void end() noexcept {
  // Release the live chain: oversize chunks always; standard chunks go
  // back to the retained pool up to the ceiling, then are freed.
  Chunk *c = g_live;
  g_live = nullptr;
  while (c) {
    Chunk *next = c->next;
    if (c->oversize) {
      free_chunk(c);
    } else if (g_retained_count < kMaxRetainedStandardChunks) {
      c->next = g_retained;
      g_retained = c;
      g_retained_count++;
      g_retained_heap_bytes += c->size;
    } else {
      free_chunk(c);
    }
    c = next;
  }
  g_base.used = 0;
  g_current = &g_base;
  g_cycle_bytes = 0;
  g_reset_count++;
}

void *alloc(size_t size) {
  if (size == 0) return nullptr;
  size_t need = align_up(size);
  Chunk *c = g_current;
  if (c->used + need > c->size) {
    // Need a fresh chunk. Oversize (exact-fit) when the request exceeds a
    // standard chunk; otherwise take/allocate a standard chunk.
    if (need > kBaseChunkSize) {
      c = new_chunk(need, true);
    } else {
      c = acquire_standard();
    }
    c->next = g_live;
    g_live = c;
    g_current = c;
  }
  char *p = c->data + c->used;
  c->used += need;
  g_cycle_bytes += need;
  if (g_cycle_bytes > g_peak_cycle_bytes) {
    g_peak_cycle_bytes = g_cycle_bytes;
  }
  return p;
}

char *alloc_string(size_t len) {
  char *p = static_cast<char *>(alloc(len + 1));
  if (p) p[len] = '\0';
  return p;
}

size_t cycle_bytes() noexcept { return g_cycle_bytes; }
size_t peak_cycle_bytes() noexcept { return g_peak_cycle_bytes; }
size_t chunk_mallocs() noexcept { return g_chunk_mallocs; }
size_t reset_count() noexcept { return g_reset_count; }
size_t retained_chunks() noexcept { return g_retained_count; }
size_t retained_heap_bytes() noexcept { return g_retained_heap_bytes; }

}  // namespace compile_arena
