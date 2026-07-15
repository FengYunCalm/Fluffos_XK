---
layout: doc
title: general / json_encode_frozen_or_zero
---
# json_encode_frozen_or_zero

### NAME

    json_encode_frozen_or_zero() - try to encode frozen LPC data as JSON

### SYNOPSIS

    string | zero json_encode_frozen_or_zero(mixed value);

### DESCRIPTION

    Encodes numbers, strings, arrays, and string-key mappings directly as a
    JSON string. Returns 0 instead of raising an error when the value does not
    satisfy the owner frozen-data contract. This is intended for hot paths
    that can fall back to a more permissive encoder without constructing an
    LPC runtime error and stack trace.

### RETURN VALUE

    A JSON string on success, or 0 for objects, functions, buffers, classes,
    non-string mapping keys, or values deeper than the frozen-data limit.

### SEE ALSO

    json_encode_frozen(3), read_json(3), write_json(3)
