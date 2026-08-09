void do_tests() {
    ASSERT(get_config(0) == MUD_NAME);
    ASSERT(catch(get_config(-1)));

    // Port number is runtime-configurable (the isolated runner picks free
    // ports); assert a valid port range instead of a fixed value.
    ASSERT(get_config(256) >= 1);
    ASSERT(get_config(256) <= 65535);
}
