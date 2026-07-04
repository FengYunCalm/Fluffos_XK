/*
 * vm.cc
 *
 *  Created on: Nov 16, 2014
 *      Author: sunyc
 */

#include "base/std.h"

#include <atomic>
#include <cstddef>
#include <limits>
#include <cstdlib>

#include "applies_table.autogen.h"
#include "vm/context.h"
#include "vm/internal/base/machine.h"  // for reset_machine
#include "vm/internal/eval_limit.h"
#include "vm/internal/master.h"
#include "vm/internal/simul_efun.h"
#include "vm/internal/simulate.h"
#include "compiler/internal/lex.h"       // for add_predefines, fixme!
#include "compiler/internal/compiler.h"  // for init_locals, fixme!

#include "packages/core/add_action.h"
#include "packages/core/replace_program.h"
#ifdef PACKAGE_MUDLIB_STATS
#include "packages/mudlib_stats/mudlib_stats.h"
#endif

time_t boot_time;

namespace {
std::atomic<uint64_t> destructed_object_cleanup_total{0};
std::atomic<uint64_t> destructed_object_cleanup_batches{0};
std::atomic<uint64_t> destructed_object_cleanup_last_removed{0};

/* The epilog() in master.c is supposed to return an array of files to load.
 * The preload() in master object called to do the actual loading.
 */
void preload_objects() {
  // Legacy: epilog() has a int param to make it to avoid load anything.
  // I'm not sure who would use that.
  push_number(0);
  auto ret = safe_apply_master_ob(APPLY_EPILOG, 1);

  if ((ret == nullptr) || (ret == (svalue_t *)-1) || (ret->type != T_ARRAY)) {
    return;
  }

  auto prefiles = ret->u.arr;
  if ((prefiles == nullptr) || (prefiles->size < 1)) {
    return;
  }

  // prefiles (the global apply return value) would have been freed on next apply call.
  // so we have to increase ref here to make sure it is around.
  prefiles->ref++;

  debug_message("\nLoading preload files ...\n");

  for (int i = 0; i < prefiles->size; i++) {
    if (prefiles->item[i].type != T_STRING) {
      continue;
    }
    debug_message("%s...\n", prefiles->item[i].u.string);

    push_svalue(&prefiles->item[i]);
    set_eval(max_eval_cost);
    safe_apply_master_ob(APPLY_PRELOAD, 1);
  }
  free_array(prefiles);
} /* preload_objects() */

}  // namespace

void vm_init() {
  boot_time = get_current_time();
  vm_context_set_boot_time(vm_context(), boot_time);

  init_eval(); /* in eval.cc */

  init_strings();     /* in stralloc.c */
  init_identifiers(); /* in lex.c */
  init_locals();      /* in compiler.c */

  max_eval_cost = CONFIG_INT(__MAX_EVAL_COST__);
  set_inc_list(CONFIG_STR(__INCLUDE_DIRS__));

  add_predefines();
  reset_machine(1);

  set_eval(max_eval_cost);

#ifndef NO_ADD_ACTION
  init_living(); /* in add_actions.cc */
#endif
}

void vm_start() {
  error_context_t econ;
  save_context(&econ);
  try {
    debug_message("Loading simul_efun file : %s\n", CONFIG_STR(__SIMUL_EFUN_FILE__));
    init_simul_efun(CONFIG_STR(__SIMUL_EFUN_FILE__));
    debug_message("Loading master file: %s\n", CONFIG_STR(__MASTER_FILE__));
    init_master(CONFIG_STR(__MASTER_FILE__));
  } catch (const char *) {
    debug_message("The simul_efun (%s) and master (%s) objects must be loadable.\n",
                  CONFIG_STR(__SIMUL_EFUN_FILE__), CONFIG_STR(__MASTER_FILE__));
    debug_message("Please check log files for exact error. \n");
    restore_context(&econ);
    pop_context(&econ);
    exit(-1);
  }
  pop_context(&econ);

  // TODO: move this to correct location.
#ifdef PACKAGE_MUDLIB_STATS
  restore_stat_files();
#endif

  preload_objects();
}

/*
 * There are global variables that must be zeroed before any execution.
 *
 * This routine must only be called from top level, not from inside
 * stack machine execution (as stack will be cleared).
 */
void clear_state() {
  vm_context_set_current_object(vm_context(), nullptr);
  set_command_giver(nullptr);
  vm_context_set_current_interactive(vm_context(), nullptr);
  vm_context_set_previous_object(vm_context(), nullptr);
  vm_context_set_current_program(vm_context(), nullptr);
  vm_context_set_caller_type(vm_context(), 0);
  vm_context_set_call_origin(vm_context(), 0);
  vm_context_set_inherit_offsets(vm_context(), 0, 0);
  vm_context_set_stack_temporary_depth(vm_context(), 0);
  vm_context_set_current_error_context(vm_context(), nullptr);
  vm_context_set_error_flags(vm_context(), 0, 0);
  vm_context_set_error_depths(vm_context(), 0, 0);
  vm_context_set_load_object_depth(vm_context(), 0);
  vm_context_set_restricted_destruct_object(vm_context(), nullptr);
  vm_context_reset_execution(vm_context());
  reset_machine(0); /* Pop down the stack. */
} /* clear_state() */

/* All destructed objects are moved into a sperate linked list,
 * and deallocated after program execution.  */
// TODO: find where they are
extern object_t *obj_list_destruct;
size_t remove_destructed_objects_bounded(size_t max_count) {
  if (max_count == 0) {
    destructed_object_cleanup_last_removed.store(0, std::memory_order_relaxed);
    return 0;
  }

  if (obj_list_replace) {
    replace_programs();
  }

  size_t removed = 0;
  while (obj_list_destruct && removed < max_count) {
    auto *ob = obj_list_destruct;
    obj_list_destruct = ob->next_all;
    if (obj_list_destruct) {
      obj_list_destruct->prev_all = nullptr;
    }
    ob->next_all = nullptr;
    ob->prev_all = nullptr;
    destruct2(ob);
    removed++;
  }

  destructed_object_cleanup_last_removed.store(removed, std::memory_order_relaxed);
  if (removed > 0) {
    destructed_object_cleanup_total.fetch_add(removed, std::memory_order_relaxed);
    destructed_object_cleanup_batches.fetch_add(1, std::memory_order_relaxed);
    vm_context_sync_object_store(vm_context());
  }
  return removed;
}

void remove_destructed_objects() {
  (void)remove_destructed_objects_bounded(std::numeric_limits<size_t>::max());
} /* remove_destructed_objects() */

size_t vm_destructed_object_backlog_size() {
  size_t count = 0;
  for (auto *ob = obj_list_destruct; ob; ob = ob->next_all) {
    count++;
  }
  return count;
}

uint64_t vm_destructed_object_cleanup_total() {
  return destructed_object_cleanup_total.load(std::memory_order_relaxed);
}

uint64_t vm_destructed_object_cleanup_batches() {
  return destructed_object_cleanup_batches.load(std::memory_order_relaxed);
}

uint64_t vm_destructed_object_cleanup_last_removed() {
  return destructed_object_cleanup_last_removed.load(std::memory_order_relaxed);
}
