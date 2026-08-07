---
layout: doc
title: master / prepare_shutdown
---
# prepare_shutdown

### NAME

    prepare_shutdown - prepare mudlib state for controlled driver shutdown

### SYNOPSIS

    void prepare_shutdown( int exit_code );

### DESCRIPTION

    The driver calls this optional master apply once before controlled runtime
    teardown. It is used for both the shutdown() efun and signal-driven
    shutdown. SIGTERM requests a successful exit code of 0; SIGHUP keeps the
    historical halt convention and requests -1.

    The callback runs on the driver main thread before asynchronous work,
    gateway output, and owner workers are stopped. Mudlibs should perform only
    bounded synchronous persistence here. They should not call shutdown()
    recursively or enqueue work that requires a later event-loop turn.

    Errors raised by the callback are isolated and do not cancel process
    shutdown.

### SEE ALSO

    shutdown(3), crash(4)
