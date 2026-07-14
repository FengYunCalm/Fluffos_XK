---
layout: doc
title: general / json_encode_frozen
---
# json_encode_frozen

### NAME

    json_encode_frozen() - encode frozen LPC data as JSON

### SYNOPSIS

    string json_encode_frozen(mixed value);

### DESCRIPTION

    Encodes numbers, strings, arrays, and string-key mappings directly as a
    JSON string. The value must satisfy the owner frozen-data contract, so the
    function is safe to call from controlled owner LPC tasks. Mapping output
    follows the same key traversal order as keys(). String control characters
    are escaped according to the JSON specification.

### ERRORS

    json_encode_frozen() raises an error for objects, functions, buffers,
    classes, non-string mapping keys, or values deeper than the frozen-data
    limit.

### SEE ALSO

    read_json(3), write_json(3), owner_call_async(3)
