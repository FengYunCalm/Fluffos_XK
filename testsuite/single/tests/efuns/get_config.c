void do_tests() {
    ASSERT(get_config(0) == MUD_NAME);
    ASSERT(catch(get_config(-1)));

    // Port number is runtime-configurable (the isolated runner configures
    // port 0 = OS-assigned). -ftest runs the suite before the listeners
    // bind, so get_config reports the configured value: 0 is legal here
    // (the actual port is exposed via sys_network_ports()/logs after bind).
    ASSERT(get_config(256) >= 0);
    ASSERT(get_config(256) <= 65535);
}
