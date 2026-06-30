---
layout: doc
title: interactive / set_encoding
---
# set_encoding

### SYNOPSIS

    string set_encoding( string encoding | void );

### DESCRIPTION

    set output/input encoding for current player.

    If given encoding name is not available, an error will be thrown. The available encoding name
    depends on your ICU version. GBK, GB2312, Big5, and UTF-8 are common boundary encodings for
    Chinese mudlibs and clients.

    If no argument present, reset the player to no encoding, which means UTF-8.

    Returns the canonical encoding name from ICU, and it will be the same as query_encoding() returns.

    The VM keeps internal LPC strings in canonical UTF-8. set_encoding() only changes the interactive
    session boundary: input is decoded before entering the VM, and output is encoded before being sent
    to the player. For source files use #pragma source_encoding("GBK") when a legacy LPC file is not
    UTF-8. For data buffers use string_encode(), string_decode(), or buffer_transcode().

### SEE ALSO

    query_encoding(3), string_encode(3), string_decode(3), buffer_transcode(3)
