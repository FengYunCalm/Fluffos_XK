#include "vm/frozen_value.h"

#include <cstring>

namespace {
const char *safe_error_prefix(const char *error_prefix) { return error_prefix && error_prefix[0] ? error_prefix : "value"; }

bool copy_frozen_array(svalue_t *dest, array_t *source) {
  auto *array = allocate_array(source ? source->size : 0);
  for (int i = 0; source && i < source->size; i++) {
    if (!vm_copy_frozen_svalue(&array->item[i], &source->item[i])) {
      free_array(array);
      return false;
    }
  }
  dest->type = T_ARRAY;
  dest->subtype = 0;
  dest->u.arr = array;
  return true;
}

bool copy_frozen_mapping(svalue_t *dest, mapping_t *source) {
  auto *map = allocate_mapping(source ? MAP_COUNT(source) : 0);
  if (source) {
    for (unsigned int i = 0; i <= source->table_size; i++) {
      for (auto *node = source->table[i]; node; node = node->next) {
        if (node->values[0].type != T_STRING) {
          free_mapping(map);
          return false;
        }
        svalue_t key{T_STRING, STRING_SHARED, {0}};
        key.u.string = make_shared_string(node->values[0].u.string ? node->values[0].u.string : "");
        auto *slot = find_for_insert(map, &key, 1);
        free_svalue(&key, "frozen mapping key");
        if (!vm_copy_frozen_svalue(slot, &node->values[1])) {
          free_mapping(map);
          return false;
        }
      }
    }
  }
  dest->type = T_MAPPING;
  dest->subtype = 0;
  dest->u.map = map;
  return true;
}
}  // namespace

VMFrozenValue::~VMFrozenValue() { free_svalue(&value, "vm frozen value"); }

bool vm_copy_frozen_svalue(svalue_t *dest, svalue_t *source) {
  if (!source) {
    *dest = const0u;
    return true;
  }
  switch (source->type) {
    case T_NUMBER:
    case T_REAL:
      *dest = *source;
      return true;
    case T_STRING:
      dest->type = T_STRING;
      dest->subtype = STRING_SHARED;
      dest->u.string = make_shared_string(source->u.string ? source->u.string : "");
      return true;
    case T_ARRAY:
      return copy_frozen_array(dest, source->u.arr);
    case T_MAPPING:
      return copy_frozen_mapping(dest, source->u.map);
    default:
      return false;
  }
}

std::shared_ptr<VMFrozenValue> vm_clone_frozen_value(svalue_t *source) {
  std::string error;
  if (!vm_frozen_value_safe(source, 0, "frozen value", &error)) {
    return nullptr;
  }
  auto value = std::make_shared<VMFrozenValue>();
  if (!vm_copy_frozen_svalue(&value->value, source)) {
    return nullptr;
  }
  return value;
}

bool vm_frozen_value_safe(const svalue_t *value, int depth, const char *error_prefix, std::string *error) {
  auto prefix = safe_error_prefix(error_prefix);
  if (!value) {
    return true;
  }
  if (depth > 8) {
    *error = std::string(prefix) + " nesting is too deep";
    return false;
  }
  switch (value->type) {
    case T_NUMBER:
    case T_REAL:
    case T_STRING:
      return true;
    case T_ARRAY:
      for (int i = 0; i < value->u.arr->size; i++) {
        if (!vm_frozen_value_safe(&value->u.arr->item[i], depth + 1, error_prefix, error)) {
          return false;
        }
      }
      return true;
    case T_MAPPING:
      for (unsigned int i = 0; i <= value->u.map->table_size; i++) {
        for (auto *node = value->u.map->table[i]; node; node = node->next) {
          if (node->values[0].type != T_STRING) {
            *error = std::string(prefix) + " mapping keys must be strings";
            return false;
          }
          if (!vm_frozen_value_safe(&node->values[1], depth + 1, error_prefix, error)) {
            return false;
          }
        }
      }
      return true;
    default:
      *error = std::string(prefix) + " must be frozen data, not object/function/buffer/class";
      return false;
  }
}
