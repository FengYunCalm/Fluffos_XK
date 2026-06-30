---
layout: doc
title: interactive / set_encoding
---
# set_encoding

### 名称

    set_encoding() - 设置当前玩家的输入输出编码

### 语法

    string set_encoding( string encoding | void );

### 描述

    设置当前玩家的输入/输出编码。

    如果给定的编码名称不可用，会抛出错误。可用编码取决于你的 ICU 版本。GBK、GB2312、
    Big5 和 UTF-8 是中文 mudlib 与客户端常见的边界编码。

    如果没有指定编码，会重置玩家的编码为 UTF-8。

    返回值为 ICU 规范的编码名称，与 query_encoding() 返回值相同。

    VM 内部 LPC 字符串继续使用规范 UTF-8。set_encoding() 只改变 interactive session
    边界：玩家输入进入 VM 前会先解码，输出发送给玩家前会按 session encoding 编码。
    如果遗留 LPC 源文件不是 UTF-8，请使用 #pragma source_encoding("GBK") 这类源码边界
    声明。处理外部数据 buffer 时，请使用 string_encode()、string_decode() 或
    buffer_transcode()，不要把外部字节编码混入 VM 内部字符串语义。

### 参考

    query_encoding(3), string_encode(3), string_decode(3), buffer_transcode(3)
