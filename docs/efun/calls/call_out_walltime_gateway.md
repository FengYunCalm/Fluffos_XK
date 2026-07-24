---
layout: doc
title: calls / call_out_walltime_gateway
---
# call_out_walltime_gateway

### NAME

    call_out_walltime_gateway - delayed required-protocol callback in the same object

### SYNOPSIS

    int call_out_walltime_gateway( string | function fun, int | float delay, mixed arg ... );

### DESCRIPTION

    This efun has the same handle, cancellation, object-destruction, and shutdown
    lifecycle as call_out_walltime(), but schedules the callback at the backend's
    Gateway priority. It is intended for bounded protocol lifecycle work that must
    make progress alongside Gateway input and owner-main continuations. It must not
    be used for optional maintenance, unbounded business loops, or to bypass owner
    and thread-safety boundaries.

### SEE ALSO

    call_out, call_out_walltime, call_out_walltime_background, remove_call_out,
    call_out_info
