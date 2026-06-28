#ifndef LPC_MODERN_PROFILE_H
#define LPC_MODERN_PROFILE_H

#include <array>

inline constexpr const char *kLpcModernProfileSchemaV1 = "lpc_modern_profile_v1";
inline constexpr const char *kLpcOwnerAuditSchemaV1 = "lpcc_owner_audit_v1";
inline constexpr const char *kLpcModernProfileModeOptIn = "opt_in_pragma";
inline constexpr const char *kLpcStrictOwnerPolicyV1 = "strict_owner_owner_safe_payloads_v1";

enum LpcModernPragmaFlag {
  LPC_MODERN_PRAGMA_MODERN_LPC = 1 << 0,
  LPC_MODERN_PRAGMA_STRICT_OWNER = 1 << 1,
};

struct LpcOwnerAuditRule {
  const char *code;
  const char *category;
  const char *severity;
  const char *message;
};

const std::array<LpcOwnerAuditRule, 4> &lpc_owner_audit_rules();
bool lpc_modern_pragma_name(const char *name, int *flag);
const char *lpc_modern_pragma_name_for_flag(int flag);

#endif /* LPC_MODERN_PROFILE_H */
