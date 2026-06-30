---
layout: doc
title: interactive / set_encoding
---
# set_encoding

### SYNOPSIS / 语法

    string set_encoding( string encoding | void );

### DESCRIPTION / 描述

    set output/input encoding for current player.

    设置当前玩家的输入/输出编码。

    If given encoding name is not available, an error will be thrown. The available encoding name
    depends on your ICU version. GBK, GB2312, Big5, and UTF-8 are common boundary encodings for
    Chinese mudlibs and clients.

    如果给定的编码名称不可用，会抛出错误。可用编码取决于 ICU 版本。GBK、GB2312、Big5
    和 UTF-8 是中文 mudlib 与客户端常见的边界编码。

    If no argument present, reset the player to no encoding, which means UTF-8.

    如果没有指定参数，会重置玩家编码为 UTF-8。

    Returns the canonical encoding name from ICU, and it will be the same as query_encoding() returns.

    返回 ICU 规范编码名，并与 query_encoding() 返回值一致。

    The VM keeps internal LPC strings in canonical UTF-8. set_encoding() only changes the interactive
    session boundary: input is decoded before entering the VM, and output is encoded before being sent
    to the player. For source files use #pragma source_encoding("GBK") when a legacy LPC file is not
    UTF-8. For data buffers use string_encode(), string_decode(), or buffer_transcode().

    VM 内部 LPC 字符串保持规范 UTF-8。set_encoding() 只改变 interactive session 边界：
    玩家输入进入 VM 前会先解码，输出发送给玩家前会按 session encoding 编码。遗留 LPC
    源文件不是 UTF-8 时，使用 #pragma source_encoding("GBK") 这类源码边界声明。处理外部
    数据 buffer 时，使用 string_encode()、string_decode() 或 buffer_transcode()。

### SEE ALSO / 参考

    query_encoding(3), string_encode(3), string_decode(3), buffer_transcode(3)
