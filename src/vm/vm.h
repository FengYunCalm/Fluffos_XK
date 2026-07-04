/*
 * vm_incl.h
 *
 *  Created on: Nov 16, 2014
 *      Author: sunyc
 */

#ifndef SRC_VM_INCL_H_
#define SRC_VM_INCL_H_

// This file is the main API bundle for interacting with vm layer.

#include "vm/context.h"

// for apply()
#include "applies_table.autogen.h"
#include "vm/internal/apply.h"

// for all EFUN defines
#include "efuns.autogen.h"

// for calling into master.
#include "vm/internal/master.h"

// TODO: remove this.
#include "vm/internal/simul_efun.h"

// for everything?
#include "vm/internal/base/machine.h"

// FIXME: merge this?
#include "vm/internal/eval_limit.h"
#include "vm/internal/simulate.h"

// init vm layer.
void vm_init();

#include <cstddef>  // for size_t
#include <cstdint>  // for uint64_t
#include <ctime>    // for time_t
// VM boot time, inited in vm_init().
extern time_t boot_time;

// Start running VM, this include load master/simul_efun objects and doing preload.
void vm_start();

// Reset vm
void clear_state(void);

// Remove destructed objects
void remove_destructed_objects(void);
size_t remove_destructed_objects_bounded(size_t max_count);
size_t vm_destructed_object_backlog_size(void);
uint64_t vm_destructed_object_cleanup_total(void);
uint64_t vm_destructed_object_cleanup_batches(void);
uint64_t vm_destructed_object_cleanup_last_removed(void);

#endif /* SRC_VM_INCL_H_ */
