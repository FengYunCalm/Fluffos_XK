---
layout: doc
title: filesystem / write_json
---
# write_json

### NAME

    write_json() - write an LPC value as JSON to a file

### SYNOPSIS

    int write_json(string file, mixed value);

### DESCRIPTION

    Serializes the LPC value to JSON and overwrites the file. Mappings encode
    as JSON objects and arrays encode as JSON arrays. Objects are encoded as
    their file name (string). Unsupported LPC types are encoded as JSON null.
    Returns 1 on success and 0 on failure.

### ERRORS

    write_json() raises an error if the nesting depth exceeds the maximum
    allowed, or if a mapping contains a non-string key.

### SEE ALSO

    read_json(3), read_file(3), write_file(3), valid_read(4), valid_write(4)
