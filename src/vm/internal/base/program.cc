#include "base/std.h"

#include "vm/internal/base/machine.h"
#include "vm/internal/base/apply_cache.h"

void reference_prog(program_t *progp, const char *from) {
  progp->ref++;
  debug(d_flag, "reference_prog: /%s ref %d (%s)\n", progp->filename, progp->ref, from);
}

void deallocate_program(program_t *progp) {
  int i;

  debug(d_flag, "free_prog: /%s\n", progp->filename);
  apply_cache_invalidate_program(progp);

  total_prog_block_size -= progp->total_size;
  total_num_prog_blocks -= 1;

  /* Free all function names. */
  for (i = 0; i < progp->num_functions_defined; i++) {
    if (progp->function_table[i].funcname) {
      free_string(progp->function_table[i].funcname);
    }
  }
  /* Free all strings */
  for (i = 0; i < progp->num_strings; i++) {
    free_string(progp->strings[i]);
  }
  /* Free all variable names */
  for (i = 0; i < progp->num_variables_defined; i++) {
    free_string(progp->variable_table[i]);
  }
  /* Free all inherited objects */
  for (i = 0; i < progp->num_inherited; i++) {
    program_t *tmp = progp->inherit[i].prog;
    free_prog(&tmp);  // don't want to mess up the prog pointer in the inherited ob
  }
  free_string(progp->filename);

  /*
   * We're going away for good, not just being swapped, so free up
   * line_number stuff.
   */
  if (progp->file_info) {
    FREE(progp->file_info);
  }

  if (progp->apply_lookup_table != nullptr) {
    apply_cache_items -= progp->apply_lookup_table->size();
    progp->apply_lookup_table.reset(nullptr);
  }

  FREE((char *)progp);
}

/*
 * Decrement reference count for a program. If it is 0, then free the prgram.
 * The flag free_sub_strings tells if the propgram plus all used strings
 * should be freed. They normally are, except when objects are swapped,
 * as we want to be able to read the program in again from the swap area.
 * That means that strings are not swapped.
 */
void free_prog(program_t **progp) {
  (*progp)->ref--;
  if ((*progp)->ref > 0) {
    *progp = (program_t *)2;  // NULL;
    return;
  }
  if ((*progp)->func_ref > 0) {
    *progp = (program_t *)3;  // NULL;
    return;
  }

  deallocate_program(*progp);
  *progp = (program_t *)4;  // NULL;
}

char *variable_name(program_t *prog, int idx) {
  int i = prog->num_inherited - 1;
  int first;

  if (i > -1) {
    first = prog->inherit[i].variable_index_offset + prog->inherit[i].prog->num_variables_total;
  } else {
    return prog->variable_table[idx];
  }
  if (idx >= first) {
    return prog->variable_table[idx - first];
  }
  while (idx < prog->inherit[i].variable_index_offset) {
    i--;
  }
  return variable_name(prog->inherit[i].prog, idx - prog->inherit[i].variable_index_offset);
}

function_t *find_func_entry(program_t *prog, int index) {
  int low, mid, high;

  /* Walk up the inheritance tree to the real definition */
  if (prog->function_flags[index] & FUNC_ALIAS) {
    index = prog->function_flags[index] & ~FUNC_ALIAS;
  }

  while (prog->function_flags[index] & FUNC_INHERITED) {
    low = 0;
    high = prog->num_inherited - 1;

    while (high > low) {
      mid = (low + high + 1) >> 1;
      if (prog->inherit[mid].function_index_offset > index) {
        high = mid - 1;
      } else {
        low = mid;
      }
    }
    index -= prog->inherit[low].function_index_offset;
    prog = prog->inherit[low].prog;
  }

  index -= prog->last_inherited;

  return prog->function_table + index;
}

// #1247 B-S1: program_layout_digest implementation.
//
// FNV-1a 64 over the layout, walked in the runtime's depth-first slot
// order (inherits first, then this program's defined variables). Each
// inherited variable is hashed with the full inherit path from the root
// program so two private variables with the same name on different
// inherit paths cannot collide. Effective variable types use
// DECL_MODIFY along the inherit chain (the same rule the compiler's
// copy_variables uses), and every inherit edge folds in its type_mod.
// The digest is the layout_id producer for ObjectVariableBlock; it is
// not a collision-free substitute for the full structural comparison
// (B-S2), which remains the migration gate.
namespace {
void digest_walk(const program_t *prog, const std::string &path, uint64_t *h) {
  // Mix helper: FNV-1a step over a byte range.
  auto mix = [h](const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
      *h ^= static_cast<unsigned char>(p[i]);
      *h *= 1099511628211ULL;
    }
  };
  for (int i = 0; i < prog->num_inherited; i++) {
    const inherit_t &inh = prog->inherit[i];
    const char *fname = inh.prog && inh.prog->filename ? inh.prog->filename : "";
    mix(fname, strlen(fname));
    mix(reinterpret_cast<const char *>(&inh.type_mod), sizeof(inh.type_mod));
    mix("|", 1);
    if (inh.prog) {
      std::string child_path = path;
      child_path += "/";
      child_path += fname;
      digest_walk(inh.prog, child_path, h);
    }
  }
  for (int i = 0; i < prog->num_variables_defined; i++) {
    const char *name = prog->variable_table ? prog->variable_table[i] : "";
    int type = prog->variable_types ? prog->variable_types[i] : 0;
    mix(path.data(), path.size());
    mix(":", 1);
    mix(name, strlen(name));
    mix(":", 1);
    mix(reinterpret_cast<const char *>(&type), sizeof(type));
    mix("|", 1);
  }
}
}  // namespace

uint64_t program_layout_digest(const program_t *prog) noexcept {
  uint64_t h = 14695981039346656037ULL;  // FNV-1a 64 offset basis
  if (prog) {
    std::string path;
    digest_walk(prog, path, &h);
  }
  return h;
}
