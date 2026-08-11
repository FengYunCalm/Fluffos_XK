void do_tests() {
    mixed *ports = sys_network_ports();

    ASSERT_EQ(1, arrayp(ports));
    ASSERT_EQ(4, sizeof(ports));

    // Structure assertions only: the isolated runner assigns free ports, so
    // the concrete port numbers are not part of the contract. Ports are
    // ordered by display index (1..4) with the kinds and TLS flags from
    // testsuite/etc/config.test.
    ASSERT_EQ(1, ports[0][0]);
    ASSERT_EQ("telnet", ports[0][1]);
    ASSERT_EQ(0, ports[0][3]); // no tls

    ASSERT_EQ(2, ports[1][0]);
    ASSERT_EQ("websocket", ports[1][1]);
    ASSERT_EQ(0, ports[1][3]); // no tls

    ASSERT_EQ(3, ports[2][0]);
    ASSERT_EQ("websocket", ports[2][1]);
    ASSERT_EQ(1, ports[2][3]); // tls

    ASSERT_EQ(4, ports[3][0]);
    ASSERT_EQ("telnet", ports[3][1]);
    ASSERT_EQ(1, ports[3][3]); // tls
}
