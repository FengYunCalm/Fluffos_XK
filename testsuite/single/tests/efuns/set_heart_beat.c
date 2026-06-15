int x = 0;
object stale_target;

void heart_beat() {
    x++;
    switch (x) {
      case 1:
        write("heartbeat test 1.\n");
        ASSERT_EQ(1, query_heart_beat(this_object()));
        set_heart_beat(2);
        ASSERT_EQ(2, query_heart_beat(this_object()));
        break;
      case 2:
        write("heartbeat test 2.\n");
        ASSERT_EQ(2, query_heart_beat(this_object()));
        set_heart_beat(1);
        ASSERT_EQ(1, query_heart_beat(this_object()));
        set_heart_beat(0);
        ASSERT_EQ(0, query_heart_beat(this_object()));
        set_heart_beat(1);
        ASSERT_EQ(1, query_heart_beat(this_object()));
        break;
      case 3:
        write("heartbeat test 3.\n");
        ASSERT_EQ(1, query_heart_beat(this_object()));
        set_heart_beat(0);
        ASSERT_EQ(0, query_heart_beat(this_object()));
        set_heart_beat(1);
        ASSERT_EQ(1, query_heart_beat(this_object()));
        set_heart_beat(0);
        ASSERT_EQ(0, query_heart_beat(this_object()));
        break;
      default:
        ASSERT(0);
    }
}

void do_tests() {
    x = 0;
    set_heart_beat(0);
    ASSERT(!query_heart_beat(this_object()));
    set_heart_beat(1);
    ASSERT_EQ(1, query_heart_beat(this_object()));

    stale_target = load_object("/single/void");
    stale_target->reset_heartbeat_called();
    stale_target->start_heartbeat();
    ASSERT_EQ(1, query_heart_beat(stale_target));
    call_out("check_stale_heartbeat", 2);
}

void check_stale_heartbeat() {
    int before = stale_target->get_heartbeat_called();
    ASSERT(before > 0);
    vm_set_owner_id(stale_target, "owner/test/heartbeat-stale-new");
    call_out("finish_stale_heartbeat", 2, before);
}

void finish_stale_heartbeat(int before) {
    ASSERT_EQ(before, stale_target->get_heartbeat_called());
    stale_target->stop_heartbeat();
    ASSERT_EQ(0, query_heart_beat(stale_target));
}
