// #1247 B-S2: pure layout description/classification. No driver state.

#include "vm/internal/recompile_layout.h"

#include <algorithm>
#include <cstring>
#include <map>

#include "vm/internal/base/program.h"  // program_t, DECL_MODIFY, inherit_t
#include "vm/internal/base/class.h"    // class_def_t, class_member_entry_t
#include "vm/internal/base/svalue.h"   // TYPE_MOD_CLASS, CLASS_NUM_MASK
#include "vm/internal/layout_digest.h"

namespace {

using layout_digest::fnv_mix;

// Class schema digest of one class definition (path + name + member
// (name,type) sequence). Pure; shared with program.cc via layout_digest.h.
uint64_t class_schema_digest(const std::string &path, const char *class_name,
                             const std::vector<RecompileLayoutClassMember> &members) {
  uint64_t h = layout_digest::kFnvOffset;
  h = fnv_mix(h, path.data(), path.size());
  h = fnv_mix(h, ":", 1);
  h = fnv_mix(h, class_name, strlen(class_name));
  for (const auto &m : members) {
    h = fnv_mix(h, "|", 1);
    h = fnv_mix(h, m.name.data(), m.name.size());
    h = fnv_mix(h, ":", 1);
    layout_digest::fnv_mix_int(&h, m.type);
  }
  return h;
}

// Resolve the class schema of a class-typed variable at its defining
// program. Returns 0 when the variable is not class-typed or the schema
// cannot be resolved (fail-closed: a digest mismatch then rejects).
uint64_t class_digest_for(const program_t *prog, int raw_type, const std::string &path) {
  if (!(raw_type & TYPE_MOD_CLASS)) return 0;
  int idx = raw_type & CLASS_NUM_MASK;
  if (!prog->classes || idx >= prog->num_classes) return 0;
  const class_def_t &cd = prog->classes[idx];
  const char *cls_name = prog->strings && cd.classname < prog->num_strings
                             ? prog->strings[cd.classname]
                             : nullptr;
  if (!cls_name) return 0;
  std::vector<RecompileLayoutClassMember> members;
  for (int m = 0; m < cd.size; m++) {
    const class_member_entry_t &cme = prog->class_members[cd.index + m];
    RecompileLayoutClassMember member;
    member.name =
        prog->strings && cme.membername < prog->num_strings ? prog->strings[cme.membername] : "";
    member.type = cme.type;
    members.push_back(std::move(member));
  }
  return class_schema_digest(path, cls_name, members);
}

// Fold the effective declared type of a variable defined in `prog` along
// the inherit-edge chain from the defining program outward to the root
// (mod_chain holds edges root-first; iterate reverse).
int effective_type_for(const program_t *prog, int var_index,
                       const std::vector<const inherit_t *> &mod_chain) {
  int t = prog->variable_types ? prog->variable_types[var_index] : 0;
  for (auto it = mod_chain.rbegin(); it != mod_chain.rend(); ++it) {
    t = DECL_MODIFY(t, (*it)->type_mod);
  }
  return t;
}

struct WalkState {
  RecompileLayout *out;
  std::vector<const inherit_t *> mod_chain;
  int slot{0};
};

// Collect the class definition set of prog and its inherit graph into
// out->classes (deduplicated by {defining path, class name}).
void collect_classes(const program_t *prog, const std::string &path, WalkState *st) {
  if (!prog) return;
  for (int i = 0; i < prog->num_inherited; i++) {
    const inherit_t &inh = prog->inherit[i];
    if (inh.prog) {
      std::string child_path = path;
      child_path += "/";
      child_path += (inh.prog->filename ? inh.prog->filename : "");
      collect_classes(inh.prog, child_path, st);
    }
  }
  if (!prog->classes) return;
  for (int i = 0; i < prog->num_classes; i++) {
    const class_def_t &cd = prog->classes[i];
    const char *cls_name = prog->strings && cd.classname < prog->num_strings
                               ? prog->strings[cd.classname]
                               : nullptr;
    if (!cls_name) continue;
    RecompileLayoutClass cls;
    cls.defining_inherit_path = path;
    cls.class_name = cls_name;
    for (int m = 0; m < cd.size; m++) {
      const class_member_entry_t &cme = prog->class_members[cd.index + m];
      RecompileLayoutClassMember member;
      member.name =
          prog->strings && cme.membername < prog->num_strings ? prog->strings[cme.membername] : "";
      member.type = cme.type;
      cls.members.push_back(std::move(member));
    }
    bool dup = false;
    for (const auto &existing : st->out->classes) {
      if (existing.defining_inherit_path == cls.defining_inherit_path &&
          existing.class_name == cls.class_name) {
        dup = true;
        break;
      }
    }
    if (!dup) {
      cls.schema_digest =
          class_schema_digest(cls.defining_inherit_path, cls.class_name.c_str(), cls.members);
      st->out->classes.push_back(std::move(cls));
    }
  }
}

// Depth-first walk in variable-block slot order. Returns the digest of
// this subtree's canonical representation -- edge records (DFS) followed
// by ALL variable records of the subtree (slot order), the same byte
// order canonical_layout_serialization uses -- which becomes the parent
// edge's nested_layout_digest. Subtree variable records are published
// into *out_vars so the top level can emit them after the edge section.
uint64_t walk_layout(const program_t *prog, const std::string &path, WalkState *st,
                     std::vector<std::string> *out_vars) {
  uint64_t h = layout_digest::kFnvOffset;
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
      st->mod_chain.push_back(&inh);
      nested = walk_layout(inh.prog, child_path, st, &sub_vars);
      st->mod_chain.pop_back();
    }
    RecompileLayoutInherit entry;
    entry.slot = st->slot;
    entry.inherit_path = child_path;
    entry.filename_text = fname;
    entry.type_mod = inh.type_mod;
    entry.nested_layout_digest = nested;
    st->out->inherits.push_back(std::move(entry));
    sub_edges.push_back(layout_digest::inherit_record(child_path, fname, inh.type_mod, nested));
  }

  collect_classes(prog, path, st);

  for (int i = 0; i < prog->num_variables_defined; i++) {
    const char *name = prog->variable_table ? prog->variable_table[i] : "";
    int raw = prog->variable_types ? prog->variable_types[i] : 0;
    RecompileLayoutVariable v;
    v.slot = st->slot++;
    v.inherit_path = path;
    v.name_text = name ? name : "";
    v.effective_decl_type = effective_type_for(prog, i, st->mod_chain);
    v.class_schema_digest = class_digest_for(prog, raw, path);
    st->out->variables.push_back(v);
    sub_vars.push_back(layout_digest::variable_record(path, v.name_text, v.effective_decl_type,
                                                     v.class_schema_digest));
  }
  // Canonical order: this subtree's edge records, then ALL its variable
  // records (recursively collected).
  for (const auto &e : sub_edges) {
    h = fnv_mix(h, e.data(), e.size());
  }
  for (const auto &v : sub_vars) {
    h = fnv_mix(h, v.data(), v.size());
  }
  // Publish this subtree's variable records to the caller (the parent
  // edge's canonical representation includes them).
  for (const auto &v : sub_vars) out_vars->push_back(v);
  return h;
}

}  // namespace

RecompileLayout describe_recompile_layout(program_t *prog) {
  RecompileLayout out;
  WalkState st{&out, {}, 0};
  std::string root_path;
  std::vector<std::string> unused_vars;
  walk_layout(prog, root_path, &st, &unused_vars);
  out.num_variables_total = st.slot;
  std::sort(out.classes.begin(), out.classes.end(),
            [](const RecompileLayoutClass &a, const RecompileLayoutClass &b) {
              if (a.defining_inherit_path != b.defining_inherit_path)
                return a.defining_inherit_path < b.defining_inherit_path;
              return a.class_name < b.class_name;
            });
  return out;
}

bool recompile_layouts_match(const RecompileLayout &a, const RecompileLayout &b,
                             std::string *first_diff) {
  if (a.num_variables_total != b.num_variables_total) {
    if (first_diff) *first_diff = "num_variables_total";
    return false;
  }
  if (a.variables.size() != b.variables.size()) {
    if (first_diff) *first_diff = "variables.size";
    return false;
  }
  for (size_t i = 0; i < a.variables.size(); i++) {
    const auto &va = a.variables[i];
    const auto &vb = b.variables[i];
    if (va.slot != vb.slot || va.inherit_path != vb.inherit_path || va.name_text != vb.name_text ||
        va.effective_decl_type != vb.effective_decl_type ||
        va.class_schema_digest != vb.class_schema_digest) {
      if (first_diff) {
        *first_diff = "variable[" + std::to_string(i) + "] " + va.name_text + " != " + vb.name_text;
      }
      return false;
    }
  }
  if (a.inherits.size() != b.inherits.size()) {
    if (first_diff) *first_diff = "inherits.size";
    return false;
  }
  for (size_t i = 0; i < a.inherits.size(); i++) {
    const auto &ia = a.inherits[i];
    const auto &ib = b.inherits[i];
    if (ia.slot != ib.slot || ia.inherit_path != ib.inherit_path ||
        ia.filename_text != ib.filename_text || ia.type_mod != ib.type_mod ||
        ia.nested_layout_digest != ib.nested_layout_digest) {
      if (first_diff) {
        *first_diff = "inherit[" + std::to_string(i) + "] " + ia.filename_text + " != " +
                      ib.filename_text;
      }
      return false;
    }
  }
  if (a.classes.size() != b.classes.size()) {
    if (first_diff) *first_diff = "classes.size";
    return false;
  }
  for (size_t i = 0; i < a.classes.size(); i++) {
    const auto &ca = a.classes[i];
    const auto &cb = b.classes[i];
    if (ca.defining_inherit_path != cb.defining_inherit_path || ca.class_name != cb.class_name ||
        ca.schema_digest != cb.schema_digest || ca.members.size() != cb.members.size()) {
      if (first_diff) *first_diff = "class[" + std::to_string(i) + "] " + ca.class_name;
      return false;
    }
    for (size_t m = 0; m < ca.members.size(); m++) {
      if (ca.members[m].name != cb.members[m].name || ca.members[m].type != cb.members[m].type) {
        if (first_diff)
          *first_diff = "class[" + std::to_string(i) + "].member[" + std::to_string(m) + "]";
        return false;
      }
    }
  }
  return true;
}

std::string canonical_layout_serialization(const RecompileLayout &layout) {
  std::string out;
  for (const auto &inh : layout.inherits) {
    out += layout_digest::inherit_record(inh.inherit_path, inh.filename_text, inh.type_mod,
                                         inh.nested_layout_digest);
  }
  for (const auto &v : layout.variables) {
    out += layout_digest::variable_record(v.inherit_path, v.name_text, v.effective_decl_type,
                                          v.class_schema_digest);
  }
  for (const auto &c : layout.classes) {
    std::string members;
    for (const auto &m : c.members) {
      members += m.name + ":" + std::to_string(m.type) + "|";
    }
    out += layout_digest::class_record(c.defining_inherit_path, c.class_name, members);
  }
  return out;
}

uint64_t layout_serialization_digest(const std::string &bytes) {
  return fnv_mix(layout_digest::kFnvOffset, bytes.data(), bytes.size());
}

RecompileLayoutDiff classify_recompile_layout(const RecompileLayout &old_l,
                                              const RecompileLayout &new_l) {
  RecompileLayoutDiff diff;

  // Fail-closed on unresolvable identities.
  auto identity_ok = [](const RecompileLayoutVariable &v) {
    return !v.inherit_path.empty() || !v.name_text.empty();
  };
  for (const auto &v : old_l.variables) {
    if (!identity_ok(v)) {
      diff.flags |= kUnresolvable;
      diff.reject_reasons.push_back("old layout: unresolvable variable identity");
    }
  }
  for (const auto &v : new_l.variables) {
    if (!identity_ok(v)) {
      diff.flags |= kUnresolvable;
      diff.reject_reasons.push_back("new layout: unresolvable variable identity");
    }
  }

  // Duplicate stable identities within one side are never migratable.
  auto check_dupes = [&diff](const RecompileLayout &l, const char *side) {
    std::vector<VariableIdentity> ids;
    for (const auto &v : l.variables) {
      ids.push_back({v.inherit_path, v.name_text});
    }
    std::sort(ids.begin(), ids.end());
    for (size_t i = 1; i < ids.size(); i++) {
      if (ids[i] == ids[i - 1]) {
        diff.flags |= kDuplicateIdentity;
        diff.reject_reasons.push_back(std::string(side) + " layout: duplicate identity " +
                                      ids[i].inherit_path + "/" + ids[i].name_text);
      }
    }
  };
  check_dupes(old_l, "old");
  check_dupes(new_l, "new");

  // Inherit graph / edge type_mod changes are always rejected.
  if (old_l.inherits.size() != new_l.inherits.size()) {
    diff.flags |= kInheritChanged;
    diff.reject_reasons.push_back("inherit edge count changed");
  } else {
    for (size_t i = 0; i < old_l.inherits.size(); i++) {
      const auto &ia = old_l.inherits[i];
      const auto &ib = new_l.inherits[i];
      if (ia.inherit_path != ib.inherit_path || ia.filename_text != ib.filename_text ||
          ia.type_mod != ib.type_mod || ia.nested_layout_digest != ib.nested_layout_digest) {
        diff.flags |= kInheritChanged;
        diff.reject_reasons.push_back("inherit edge " + ia.inherit_path + " changed");
        break;
      }
    }
  }

  // Class schema set must be identical (covers class values kept in mixed).
  if (old_l.classes.size() != new_l.classes.size()) {
    diff.flags |= kClassSchemaChanged;
    diff.reject_reasons.push_back("class definition count changed");
  } else {
    for (size_t i = 0; i < old_l.classes.size(); i++) {
      const auto &ca = old_l.classes[i];
      const auto &cb = new_l.classes[i];
      if (ca.schema_digest != cb.schema_digest) {
        diff.flags |= kClassSchemaChanged;
        diff.reject_reasons.push_back("class schema changed: " + ca.class_name);
        break;
      }
    }
  }

  // Match by stable identity.
  struct SlotInfo {
    int slot;
    int decl_type;
    uint64_t class_digest;
  };
  std::map<VariableIdentity, SlotInfo> old_by_id;
  for (const auto &v : old_l.variables) {
    old_by_id[{v.inherit_path, v.name_text}] = {v.slot, v.effective_decl_type, v.class_schema_digest};
  }
  std::map<VariableIdentity, int> new_slots;
  for (const auto &v : new_l.variables) {
    VariableIdentity id{v.inherit_path, v.name_text};
    new_slots[id] = v.slot;
    auto it = old_by_id.find(id);
    if (it == old_by_id.end()) {
      diff.flags |= kAddedVariable;
      diff.added.push_back(id);
    } else {
      VariableMatch m;
      m.identity = id;
      m.old_slot = it->second.slot;
      m.new_slot = v.slot;
      if (it->second.decl_type != v.effective_decl_type) {
        diff.flags |= kTypeChanged;
        diff.reject_reasons.push_back("variable type changed: " + id.inherit_path + "/" +
                                      id.name_text);
      }
      if (it->second.class_digest != v.class_schema_digest) {
        diff.flags |= kClassSchemaChanged;
        diff.reject_reasons.push_back("variable class schema changed: " + id.inherit_path + "/" +
                                      id.name_text);
      }
      diff.matches.push_back(m);
    }
  }
  for (const auto &v : old_l.variables) {
    VariableIdentity id{v.inherit_path, v.name_text};
    if (old_by_id.count(id) &&
        std::none_of(diff.matches.begin(), diff.matches.end(),
                     [&id](const VariableMatch &m) { return m.identity == id; })) {
      diff.flags |= kRemovedVariable;
      diff.removed.push_back(id);
    }
  }

  // Reorder: matches are in new-layout order (built by iterating new_l);
  // the old slots must appear in the same relative order, otherwise the
  // layout reordered the matched variables.
  for (size_t i = 1; i < diff.matches.size(); i++) {
    if (diff.matches[i - 1].old_slot > diff.matches[i].old_slot) {
      diff.flags |= kReordered;
      break;
    }
  }

  return diff;
}
