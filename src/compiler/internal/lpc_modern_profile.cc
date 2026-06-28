#include "compiler/internal/lpc_modern_profile.h"

#include <cstring>

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
