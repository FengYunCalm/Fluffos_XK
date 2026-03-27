#include "base/package_api.h"

#include "packages/core/file.h"

#include "vm/internal/base/interpret.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace {
constexpr int k_max_json_depth = 20;

nlohmann::json svalue_to_plain_json(const svalue_t *sv, int depth) {
  if (depth > k_max_json_depth) {
    error("write_json: Maximum JSON nesting depth exceeded.\n");
  }

  switch (sv->type) {
    case T_NUMBER:
      return sv->u.number;
    case T_REAL:
      return sv->u.real;
    case T_STRING:
      if (!sv->u.string) {
        return "";
      }
      return std::string(sv->u.string);
    case T_ARRAY: {
      nlohmann::json arr = nlohmann::json::array();
      for (int i = 0; i < sv->u.arr->size; i++) {
        arr.push_back(svalue_to_plain_json(&sv->u.arr->item[i], depth + 1));
      }
      return arr;
    }
    case T_MAPPING: {
      nlohmann::json obj = nlohmann::json::object();
      for (int i = 0; i < sv->u.map->table_size; i++) {
        for (auto *node = sv->u.map->table[i]; node; node = node->next) {
          if (node->values[0].type != T_STRING) {
            error("write_json: mapping key must be string.\n");
          }
          obj[std::string(node->values[0].u.string)] =
              svalue_to_plain_json(&node->values[1], depth + 1);
        }
      }
      return obj;
    }
    case T_OBJECT: {
      if (!sv->u.ob || (sv->u.ob->flags & O_DESTRUCTED)) {
        return nullptr;
      }
      char *name = add_slash(sv->u.ob->obname);
      std::string result(name);
      FREE_MSTR(name);
      return result;
    }
    default:
      return nullptr;
  }
}

svalue_t json_to_svalue_plain(const nlohmann::json &value, int depth) {
  if (depth > k_max_json_depth) {
    error("read_json: Maximum JSON nesting depth exceeded.\n");
  }

  svalue_t sv = {};

  if (value.is_object()) {
    auto count = static_cast<int>(value.size());
    array_t *keys = allocate_array(count);
    array_t *values = allocate_array(count);

    int i = 0;
    for (const auto &entry : value.items()) {
      keys->item[i].type = T_STRING;
      keys->item[i].subtype = STRING_MALLOC;
      keys->item[i].u.string =
          string_copy(entry.key().c_str(), "read_json: key");

      auto item = json_to_svalue_plain(entry.value(), depth + 1);
      assign_svalue_no_free(&values->item[i], &item);
      free_svalue(&item, "read_json: value");
      i++;
    }

    sv.type = T_MAPPING;
    sv.u.map = mkmapping(keys, values);
    free_array(keys);
    free_array(values);
    return sv;
  }

  if (value.is_array()) {
    sv.type = T_ARRAY;
    auto count = static_cast<int>(value.size());
    sv.u.arr = allocate_array(count);
    for (int i = 0; i < count; i++) {
      auto item = json_to_svalue_plain(value[i], depth + 1);
      assign_svalue_no_free(&sv.u.arr->item[i], &item);
      free_svalue(&item, "read_json: array item");
    }
    return sv;
  }

  if (value.is_string()) {
    sv.type = T_STRING;
    sv.subtype = STRING_MALLOC;
    sv.u.string =
        string_copy(value.get<std::string>().c_str(), "read_json: string");
    return sv;
  }

  if (value.is_boolean()) {
    sv.type = T_NUMBER;
    sv.u.number = value.get<bool>() ? 1 : 0;
    return sv;
  }

  if (value.is_number_unsigned()) {
    sv.type = T_NUMBER;
    sv.u.number = static_cast<LPC_INT>(value.get<std::uint64_t>());
    return sv;
  }

  if (value.is_number_integer()) {
    sv.type = T_NUMBER;
    sv.u.number = value.get<LPC_INT>();
    return sv;
  }

  if (value.is_number_float()) {
    sv.type = T_REAL;
    sv.u.real = value.get<LPC_FLOAT>();
    return sv;
  }

  if (value.is_null()) {
    sv.type = T_NUMBER;
    sv.u.number = 0;
    return sv;
  }

  sv.type = T_NUMBER;
  sv.u.number = 0;
  return sv;
}
}  // namespace

svalue_t read_json(const char *file) {
  char *content = read_file(file, 0, 0);
  if (!content) {
    error("read_json: unable to read file '%s'.\n", file);
  }

  svalue_t result = {};
  try {
    auto parsed = nlohmann::json::parse(content);
    result = json_to_svalue_plain(parsed, 0);
  } catch (const nlohmann::json::exception &err) {
    FREE_MSTR(content);
    error("read_json: %s\n", err.what());
  }

  FREE_MSTR(content);
  return result;
}

int write_json(const char *file, const svalue_t *value) {
  auto json_value = svalue_to_plain_json(value, 0);
  std::string content = json_value.dump();
  return write_file(file, content.c_str(), 1);
}
