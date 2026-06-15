void dummy() {}

void assert_payload_error(mapping result, string error) {
    ASSERT_EQ(0, result["success"]);
    ASSERT_EQ(0, result["frozen_payload"]);
    ASSERT_EQ(error, result["error"]);
}

void do_tests() {
    mapping result, future;
    string target_owner = "owner/test/payload";

    result = owner_send(target_owner, ([
        "type": "payload_ok",
        "payload_key": "payload/v1",
        "data": ({ 1, "two", ([ "nested": 3 ]) }),
    ]));
    ASSERT_EQ(1, result["success"]);
    ASSERT_EQ(1, result["frozen_payload"]);
    ASSERT_EQ(1, result["requires_owner_mailbox"]);
    ASSERT_EQ(0, result["direct_cross_owner_write"]);

    future = owner_future_poll(result["future_id"]);
    ASSERT_EQ(1, future["success"]);
    ASSERT_EQ("pending", future["state"]);
    vm_owner_drain(target_owner, 1);
    future = owner_future_poll(result["future_id"]);
    ASSERT_EQ(1, future["success"]);
    ASSERT_EQ("completed", future["state"]);

    assert_payload_error(owner_send(target_owner, ([ "type": "bad_object", "object": this_object() ])),
                         "owner payload must be frozen data, not object/function/buffer/class");
    assert_payload_error(owner_call_async(this_object(), "dummy", ([ "callback": (: dummy :) ])),
                         "owner payload must be frozen data, not object/function/buffer/class");
    assert_payload_error(owner_publish_snapshot(([ 1: "bad_key" ])),
                         "owner payload mapping keys must be strings");
    assert_payload_error(owner_publish_snapshot(([ "deep": ({ ({ ({ ({ ({ ({ ({ ({ ({ ({ 1 }) }) }) }) }) }) }) }) }) }) ])),
                         "owner payload nesting is too deep");
}
