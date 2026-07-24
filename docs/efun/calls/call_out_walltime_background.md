---
layout: doc
title: calls / call_out_walltime_background
---
# call_out_walltime_background

### NAME

    call_out_walltime_background - delayed low-priority function call in the same object

### SYNOPSIS

    int call_out_walltime_background( string | function fun, int | float delay, mixed arg ... );

### DESCRIPTION

    This efun has the same handle, cancellation, object-destruction, and shutdown
    lifecycle as call_out_walltime(), but schedules the callback at the backend's
    background priority. It is intended for optional cache warming and maintenance
    work that must yield to both normal-priority timers and Gateway I/O. The callback
    still runs on the normal LPC callback path and must not be used to bypass owner
    or thread-safety boundaries.

### SEE ALSO

    call_out, call_out_walltime, call_out_walltime_gateway, remove_call_out,
    call_out_info
