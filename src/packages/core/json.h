#ifndef PACKAGES_CORE_JSON_H
#define PACKAGES_CORE_JSON_H

#include <string>

struct svalue_t;

std::string json_encode_frozen_value(const svalue_t *value);
bool try_json_encode_frozen_value(const svalue_t *value, std::string *result);

#endif
