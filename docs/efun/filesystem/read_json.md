---
layout: doc
title: filesystem / read_json
---
# read_json

### NAME

    read_json() - read a JSON file into an LPC value

### SYNOPSIS

    mixed read_json(string file);

### DESCRIPTION

    Reads the entire file and parses it as JSON. JSON objects are decoded as
    mappings with string keys; arrays are decoded as LPC arrays. Numbers are
    decoded as int or float based on the JSON value. JSON booleans map to 1/0
    and JSON null maps to 0.

### ERRORS

    read_json() raises an error if the file is missing/unreadable, if the JSON
    is invalid, or if the nesting depth exceeds the maximum allowed.

### SEE ALSO

    write_json(3), read_file(3), write_file(3), valid_read(4), valid_write(4)
