#include "compiler/internal/lpc_modern_profile.h"

#include <cstring>
#include <initializer_list>
#include <sstream>
#include <utility>

const std::array<LpcOwnerAuditRule, 4> &lpc_owner_audit_rules() {
  static const std::array<LpcOwnerAuditRule, 4> rules{{
      {"cross_owner_mutable_write", "owner_boundary", "error",
       "strict owner code must route cross-owner mutable writes through owner message, future, or commit"},
      {"bare_object_payload", "payload", "error",
       "strict owner callbacks and messages must use ObjectHandle, snapshot, or frozen payloads"},
      {"unfrozen_callback_payload", "callback", "error",
       "driver callbacks admitted to owner executor must carry frozen or deep-copied payloads"},
      {"direct_save_object_hot_path", "persistence", "warning",
       "strict owner hot paths should use snapshot persistence instead of direct save_object"},
  }};
  return rules;
}

bool lpc_modern_pragma_name(const char *name, int *flag) {
  if (std::strcmp(name, "modern_lpc") == 0) {
    *flag = LPC_MODERN_PRAGMA_MODERN_LPC;
    return true;
  }
  if (std::strcmp(name, "strict_owner") == 0) {
    *flag = LPC_MODERN_PRAGMA_STRICT_OWNER;
    return true;
  }
  return false;
}

const char *lpc_modern_pragma_name_for_flag(int flag) {
  switch (flag) {
    case LPC_MODERN_PRAGMA_MODERN_LPC:
      return "modern_lpc";
    case LPC_MODERN_PRAGMA_STRICT_OWNER:
      return "strict_owner";
    default:
      return "";
  }
}

namespace {
const LpcOwnerAuditRule *owner_audit_rule(const char *code) {
  for (const auto &rule : lpc_owner_audit_rules()) {
    if (std::strcmp(rule.code, code) == 0) {
      return &rule;
    }
  }
  return nullptr;
}

std::string strip_line_comment(const std::string &line) {
  auto comment = line.find("//");
  if (comment == std::string::npos) {
    return line;
  }
  return line.substr(0, comment);
}

void add_finding(LpcOwnerAuditReport *report, const char *code, int line, size_t column,
                 const std::string &excerpt) {
  auto *rule = owner_audit_rule(code);
  if (!rule) {
    return;
  }
  LpcOwnerAuditFinding finding;
  finding.code = rule->code;
  finding.category = rule->category;
  finding.severity = rule->severity;
  finding.message = rule->message;
  finding.line = line;
  finding.column = static_cast<int>(column + 1);
  finding.excerpt = excerpt;
  report->findings.push_back(std::move(finding));
}

bool contains_any(const std::string &line, std::initializer_list<const char *> needles) {
  for (auto *needle : needles) {
    if (line.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}
}  // namespace

LpcOwnerAuditReport lpc_owner_audit_source(const std::string &source) {
  LpcOwnerAuditReport report;
  std::istringstream input(source);
  std::string line;
  int line_number = 0;

  while (std::getline(input, line)) {
    line_number++;
    auto code = strip_line_comment(line);
    if (code.find("#pragma modern_lpc") != std::string::npos) {
      report.modern_lpc = true;
    }
    if (code.find("#pragma strict_owner") != std::string::npos) {
      report.strict_owner = true;
    }

    auto call_other = code.find("call_other(");
    auto move_object = code.find("move_object(");
    auto destruct = code.find("destruct(");
    if (call_other != std::string::npos) {
      add_finding(&report, "cross_owner_mutable_write", line_number, call_other, line);
    } else if (move_object != std::string::npos) {
      add_finding(&report, "cross_owner_mutable_write", line_number, move_object, line);
    } else if (destruct != std::string::npos) {
      add_finding(&report, "cross_owner_mutable_write", line_number, destruct, line);
    }

    auto save_object = code.find("save_object(");
    if (save_object != std::string::npos) {
      add_finding(&report, "direct_save_object_hot_path", line_number, save_object, line);
    }

    if (contains_any(code, {"owner_async(", "owner_send(", "owner_call_async("}) &&
        contains_any(code, {"this_object()", "previous_object()", "find_object("})) {
      auto owner_call = code.find("owner_");
      add_finding(&report, "bare_object_payload", line_number, owner_call, line);
    }

    auto call_out = code.find("call_out(");
    if (call_out != std::string::npos &&
        contains_any(code, {"this_object()", "previous_object()", "find_object("})) {
      add_finding(&report, "unfrozen_callback_payload", line_number, call_out, line);
    }
  }

  return report;
}
