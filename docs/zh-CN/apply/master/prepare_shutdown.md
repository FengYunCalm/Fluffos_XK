---
layout: doc
title: master / prepare_shutdown
---
# prepare_shutdown

### 名称

    prepare_shutdown - 在 Driver 受控退出前准备 mudlib 状态

### 语法

    void prepare_shutdown( int exit_code );

### 描述

    Driver 会在受控清理运行时之前调用一次这个可选的 master apply。无论退出来自
    shutdown() 外部函数还是系统信号，都会进入该回调。SIGTERM 使用成功退出码 0；
    SIGHUP 保留历史停机约定，使用退出码 -1。

    回调在 Driver 主线程执行，并且早于异步任务、gateway 输出和 Owner worker 的
    停止。mudlib 只能在这里执行有界的同步持久化；不要递归调用 shutdown()，也不要
    投递必须等待后续事件循环才能完成的任务。

    回调抛出的错误会被隔离，不会取消进程退出。

### 参考

    shutdown(3), crash(4)
