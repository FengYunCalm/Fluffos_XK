#ifndef SRC_VM_FROZEN_VALUE_H_
#define SRC_VM_FROZEN_VALUE_H_

#include "base/package_api.h"

#include <memory>
#include <string>

struct VMFrozenValue {
  svalue_t value{const0u};

  VMFrozenValue() = default;
  VMFrozenValue(const VMFrozenValue &) = delete;
  VMFrozenValue &operator=(const VMFrozenValue &) = delete;
  ~VMFrozenValue();
};

bool vm_copy_frozen_svalue(svalue_t *dest, svalue_t *source);
std::shared_ptr<VMFrozenValue> vm_clone_frozen_value(svalue_t *source);
bool vm_frozen_value_safe(const svalue_t *value, int depth, const char *error_prefix, std::string *error);

#endif /* SRC_VM_FROZEN_VALUE_H_ */
