#include "base/package_api.h"

#include "vm/owner.h"

#include <atomic>

namespace {
constexpr const char *kDefaultOwnerId = "owner/global";
std::atomic<uint64_t> total_checks{0};
std::atomic<uint64_t> mismatch_checks{0};

bool valid_owner_id(const char *owner_id) {
  return owner_id && owner_id[0] != '\0';
}
}  // namespace

const char *vm_owner_default_id() { return kDefaultOwnerId; }

const char *vm_owner_id(object_t *object) {
  if (!object || !valid_owner_id(object->vm_owner_id)) {
    return kDefaultOwnerId;
  }
  return object->vm_owner_id;
}

void vm_owner_set_id(object_t *object, const char *owner_id) {
  if (!object) {
    return;
  }
  if (!valid_owner_id(owner_id)) {
    owner_id = kDefaultOwnerId;
  }
  if (object->vm_owner_id && std::strcmp(object->vm_owner_id, owner_id) == 0) {
    return;
  }
  vm_owner_clear_id(object);
  object->vm_owner_id = make_shared_string(owner_id);
}

void vm_owner_clear_id(object_t *object) {
  if (object && object->vm_owner_id) {
    free_string(object->vm_owner_id);
    object->vm_owner_id = nullptr;
  }
}

bool vm_owner_matches(object_t *object, const char *expected_owner_id) {
  if (!valid_owner_id(expected_owner_id)) {
    expected_owner_id = kDefaultOwnerId;
  }
  return std::strcmp(vm_owner_id(object), expected_owner_id) == 0;
}

void vm_owner_record_check(object_t *object, const char *expected_owner_id, bool matched) {
  total_checks.fetch_add(1, std::memory_order_relaxed);
  if (!matched) {
    mismatch_checks.fetch_add(1, std::memory_order_relaxed);
  }
}

uint64_t vm_owner_total_checks() { return total_checks.load(std::memory_order_relaxed); }

uint64_t vm_owner_mismatch_checks() { return mismatch_checks.load(std::memory_order_relaxed); }

mapping_t *vm_owner_status(object_t *object) {
  auto *map = allocate_mapping(6);
  add_mapping_string(map, "owner_id", vm_owner_id(object));
  add_mapping_string(map, "default_owner_id", kDefaultOwnerId);
  add_mapping_pair(map, "total_checks", static_cast<long>(vm_owner_total_checks()));
  add_mapping_pair(map, "mismatch_checks", static_cast<long>(vm_owner_mismatch_checks()));
  if (object && object->obname) {
    add_mapping_string(map, "object", object->obname);
  } else {
    add_mapping_string(map, "object", "");
  }
  add_mapping_pair(map, "has_explicit_owner", object && object->vm_owner_id ? 1 : 0);
  return map;
}
