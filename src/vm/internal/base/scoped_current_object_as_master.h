/*
 * scoped_current_object_as_master.h
 *
 * RAII helper: temporarily set the VM TLS `current_object` to `master_ob`
 * and restore it on scope exit. Unified replacement for the three
 * pre-existing idioms across tests/tools/benches:
 *   1. bare `current_object = master_ob;` assignments (no restore),
 *   2. manual save/restore pairs (e.g. load_object_for_test),
 *   3. local FixtureGuard structs that restored current_object in their
 *      destructor.
 *
 * This header is intentionally GTest-free and self-contained so that
 * non-test tools (lpcc, fuzz_compile, fuzz_restore, main_symbol) and the
 * benchmarks can include it without pulling in test frameworks.
 */

#ifndef SRC_VM_INTERNAL_BASE_SCOPED_CURRENT_OBJECT_AS_MASTER_H_
#define SRC_VM_INTERNAL_BASE_SCOPED_CURRENT_OBJECT_AS_MASTER_H_

#include "vm/internal/base/machine.h"
// Upward include of vm/internal/master.h (master_ob declaration site) is
// deliberate: base/ is the ownership layer of current_object, and this is
// the only base/ header reaching outside the subtree. master.h has no
// includes of its own (forward declarations only), so there is no cycle.
#include "vm/internal/master.h"

// Sets current_object to master_ob on construction and restores the
// previously stored value on destruction.
//
// Default construction forces the assignment unconditionally (matches the
// bare-assignment idiom). Construction with conditional_t only assigns when
// current_object is null and master_ob exists (matches the
// load_object_for_test idiom).
class ScopedCurrentObjectAsMaster {
 public:
  struct conditional_t {};

  ScopedCurrentObjectAsMaster() : saved_(current_object) {
    current_object = master_ob;
  }
  explicit ScopedCurrentObjectAsMaster(conditional_t) : saved_(current_object) {
    if (current_object == nullptr && master_ob != nullptr) {
      current_object = master_ob;
    }
  }
  ~ScopedCurrentObjectAsMaster() { current_object = saved_; }

  ScopedCurrentObjectAsMaster(const ScopedCurrentObjectAsMaster &) = delete;
  ScopedCurrentObjectAsMaster &operator=(const ScopedCurrentObjectAsMaster &) = delete;

 private:
  object_t *saved_;
};

#endif /* SRC_VM_INTERNAL_BASE_SCOPED_CURRENT_OBJECT_AS_MASTER_H_ */
