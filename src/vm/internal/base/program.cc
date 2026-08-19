#include "base/std.h"

#include "vm/internal/base/machine.h"
#include "vm/internal/base/apply_cache.h"
#include "vm/internal/layout_digest.h"

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
//
// B-S2: the byte format is intentionally identical to
// canonical_layout_serialization() in recompile_layout.cc ("inh:" /
// "var:" records with the same fields, plus class-schema digests) so
// that digest(prog) == digest(canonical(describe(prog))) is testable and
// a single process never holds two digest algorithms. The equivalence is
// locked by GTest (TestProgramLayoutDigestMatchesDescriptor).
namespace {
using layout_digest::fnv_mix;

// Class schema digest of one class definition (path + name + member
// (name,type) sequence). Shared with recompile_layout.cc via
// layout_digest.h primitives.
uint64_t layout_class_schema_digest(const program_t *prog, const class_def_t &cd,
                                      const std::string &path) {
  uint64_t h = layout_digest::kFnvOffset;
  const char *cls_name =
      prog->strings && cd.classname < prog->num_strings ? prog->strings[cd.classname] : "";
  h = fnv_mix(h, path.data(), path.size());
  h = fnv_mix(h, ":", 1);
  h = fnv_mix(h, cls_name, strlen(cls_name));
  for (int m = 0; m < cd.size; m++) {
    const class_member_entry_t &cme = prog->class_members[cd.index + m];
    const char *mname =
        prog->strings && cme.membername < prog->num_strings ? prog->strings[cme.membername] : "";
    h = fnv_mix(h, "|", 1);
    h = fnv_mix(h, mname, strlen(mname));
    h = fnv_mix(h, ":", 1);
    int t = cme.type;
    h = fnv_mix(h, reinterpret_cast<const char *>(&t), sizeof(t));
  }
  return h;
}

// Class schema digest of a class-typed variable at its defining program.
// 0 when not class-typed or unresolvable (fail-closed: mismatch rejects).
uint64_t layout_class_digest_for(const program_t *prog, int raw_type, const std::string &path) {
  if (!(raw_type & TYPE_MOD_CLASS)) return 0;
  int idx = raw_type & CLASS_NUM_MASK;
  if (!prog->classes || idx >= prog->num_classes) return 0;
  return layout_class_schema_digest(prog, prog->classes[idx], path);
}

// Collect the class definition set of prog and its inherit graph
// (deduplicated by {defining path, class name}), mirroring
// recompile_layout.cc's collect_classes.
struct LayoutClassRecord {
  std::string defining_path;
  std::string class_name;
  std::vector<std::pair<std::string, int>> members;  // (name, type)
};

void layout_collect_classes(const program_t *prog, const std::string &path,
                            std::vector<LayoutClassRecord> *out) {
  if (!prog) return;
  for (int i = 0; i < prog->num_inherited; i++) {
    const inherit_t &inh = prog->inherit[i];
    if (inh.prog) {
      std::string child_path = path;
      child_path += "/";
      child_path += (inh.prog->filename ? inh.prog->filename : "");
      layout_collect_classes(inh.prog, child_path, out);
    }
  }
  if (!prog->classes) return;
  for (int i = 0; i < prog->num_classes; i++) {
    const class_def_t &cd = prog->classes[i];
    const char *cls_name =
        prog->strings && cd.classname < prog->num_strings ? prog->strings[cd.classname] : nullptr;
    if (!cls_name) continue;
    LayoutClassRecord rec;
    rec.defining_path = path;
    rec.class_name = cls_name;
    for (int m = 0; m < cd.size; m++) {
      const class_member_entry_t &cme = prog->class_members[cd.index + m];
      rec.members.emplace_back(
          prog->strings && cme.membername < prog->num_strings ? prog->strings[cme.membername] : "",
          cme.type);
    }
    bool dup = false;
    for (const auto &existing : *out) {
      if (existing.defining_path == rec.defining_path && existing.class_name == rec.class_name) {
        dup = true;
        break;
      }
    }
    if (!dup) out->push_back(std::move(rec));
  }
}

// Depth-first collection matching canonical_layout_serialization's byte
// order: ALL inherit-edge records (DFS order) first, then ALL variable
// records (slot order). Returns the subtree digest used as the parent
// edge's nested_layout_digest -- the FNV over the subtree's own edge
// records followed by its variable records (the same canonical order).
uint64_t digest_walk(const program_t *prog, const std::string &path, uint64_t *h,
                     const std::vector<const inherit_t *> &mod_chain,
                     std::vector<std::string> *edge_recs, std::vector<std::string> *var_recs) {
  uint64_t nested_h = layout_digest::kFnvOffset;
  std::vector<std::string> sub_edges;
  std::vector<std::string> sub_vars;
  for (int i = 0; i < prog->num_inherited; i++) {
    const inherit_t &inh = prog->inherit[i];
    const char *fname = inh.prog && inh.prog->filename ? inh.prog->filename : "";
    std::string child_path = path;
    child_path += "/";
    child_path += fname;
    uint64_t nested = 0;
    if (inh.prog) {
      std::vector<const inherit_t *> chain = mod_chain;
      chain.push_back(&inh);
      nested = digest_walk(inh.prog, child_path, &nested_h, chain, &sub_edges, &sub_vars);
    }
    sub_edges.push_back(layout_digest::inherit_record(child_path, fname, inh.type_mod, nested));
  }
  for (int i = 0; i < prog->num_variables_defined; i++) {
    const char *name = prog->variable_table ? prog->variable_table[i] : "";
    int raw = prog->variable_types ? prog->variable_types[i] : 0;
    int t = raw;
    for (auto it = mod_chain.rbegin(); it != mod_chain.rend(); ++it) {
      t = DECL_MODIFY(t, (*it)->type_mod);
    }
    uint64_t cd = layout_class_digest_for(prog, raw, path);
    sub_vars.push_back(layout_digest::variable_record(path, name, t, cd));
  }
  // Canonical order: edge records, then variable records.
  for (const auto &e : sub_edges) {
    nested_h = fnv_mix(nested_h, e.data(), e.size());
  }
  for (const auto &v : sub_vars) {
    nested_h = fnv_mix(nested_h, v.data(), v.size());
  }
  // Publish this subtree's records into the caller's accumulators.
  for (const auto &e : sub_edges) edge_recs->push_back(e);
  for (const auto &v : sub_vars) var_recs->push_back(v);
  return nested_h;
}
}  // namespace

uint64_t program_layout_digest(const program_t *prog) noexcept {
  if (prog && prog->layout_digest_cache != 0) {
    return prog->layout_digest_cache;
  }
  uint64_t h = layout_digest::kFnvOffset;  // FNV-1a 64 offset basis
  if (prog) {
    std::string path;
    std::vector<const inherit_t *> chain;
    std::vector<std::string> edges;
    std::vector<std::string> vars;
    digest_walk(prog, path, &h, chain, &edges, &vars);
    // Top-level canonical order: ALL edges (DFS), then ALL variables
    // (slot order), then classes (sorted), matching
    // canonical_layout_serialization.
    for (const auto &e : edges) h = fnv_mix(h, e.data(), e.size());
    for (const auto &v : vars) h = fnv_mix(h, v.data(), v.size());
    // Classes mix AFTER variables, matching canonical_layout_serialization
    // (inherits; variables; classes), sorted by {path, name}.
    std::vector<LayoutClassRecord> classes;
    layout_collect_classes(prog, path, &classes);
    std::sort(classes.begin(), classes.end(),
              [](const LayoutClassRecord &a, const LayoutClassRecord &b) {
                if (a.defining_path != b.defining_path) return a.defining_path < b.defining_path;
                return a.class_name < b.class_name;
              });
    for (const auto &c : classes) {
      std::string members;
      for (const auto &m : c.members) {
        members += m.first + ":" + std::to_string(m.second) + "|";
      }
      std::string rec = layout_digest::class_record(c.defining_path, c.class_name, members);
      h = fnv_mix(h, rec.data(), rec.size());
    }
  }
  if (prog) {
    // Cache for the hot path (object creation / replace / recompile all
    // call this per object). 0 is the sentinel; a genuine FNV result of 0
    // is recomputed every time, which is harmless.
    const_cast<program_t *>(prog)->layout_digest_cache = h;
  }
  return h;
}
