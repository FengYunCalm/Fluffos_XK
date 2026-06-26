int called;

class owner_payload_box {
    int value;
}

mapping dummy(mapping payload) {
    called += payload["value"];
    return ([ "reply": called + 1, "payload_key": payload["payload_key"] ]);
}

mapping deep_result(mapping payload) {
    return ([ "deep": ({ ({ ({ ({ ({ ({ ({ ({ ({ ({ payload["value"] }) }) }) }) }) }) }) }) }) }) ]);
}

void assert_payload_error(mapping result, string error) {
    ASSERT_EQ(0, result["success"]);
    ASSERT_EQ(0, result["frozen_payload"]);
    ASSERT_EQ(error, result["error"]);
}

void assert_latest_message_trace(int future_id, string message_type,
                                 string state, string result_key,
                                 string error, string target_status,
                                 int pending, int completed, int failed,
                                 int terminal, int frozen_result,
                                 int target_current) {
    mapping trace = vm_owner_message_trace(1);
    mixed *events = trace["events"];
    mapping event;

    ASSERT_EQ("owner_message_trace", trace["trace_kind"]);
    ASSERT_EQ("owner_message_lifecycle_trace", trace["trace_model"]);
    ASSERT(arrayp(events));
    ASSERT_EQ(1, sizeof(events));
    event = events[0];
    ASSERT(mapp(event));
    ASSERT_EQ("owner_message_lifecycle_event", event["trace_model"]);
    ASSERT_EQ(future_id, event["message_id"]);
    ASSERT_EQ(message_type, event["message_type"]);
    ASSERT_EQ(state, event["state"]);
    ASSERT_EQ("owner_main_queue", event["route"]);
    ASSERT_EQ(result_key, event["result_key"]);
    ASSERT_EQ(error, event["error"]);
    ASSERT_EQ(target_status, event["target_handle_status"]);
    ASSERT_EQ(pending, event["pending"]);
    ASSERT_EQ(completed, event["completed"]);
    ASSERT_EQ(failed, event["failed"]);
    ASSERT_EQ(terminal, event["terminal"]);
    ASSERT_EQ(0, event["direct_cross_owner_write"]);
    ASSERT_EQ(1, event["payload_frozen"]);
    ASSERT_EQ(frozen_result, event["frozen_result"]);
    ASSERT_EQ(1, event["has_target_handle"]);
    ASSERT_EQ(target_current, event["target_handle_current"]);
    ASSERT_EQ(0, event["requires_owner_mailbox"]);
    ASSERT_EQ(1, event["requires_owner_main_queue"]);
    ASSERT_EQ(1, event["main_required"]);
    ASSERT_EQ(1, event["queued_on_main"]);
    ASSERT_EQ(1, event["message_only_cross_owner"]);
}

void do_tests() {
    mapping result, future, bad_mapping, async_payload;
    int i;
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
    ASSERT_EQ(1, future["payload_frozen"]);
    ASSERT_EQ(0, future["frozen_result"]);
    vm_owner_drain(target_owner, 1);
    future = owner_future_poll(result["future_id"]);
    ASSERT_EQ(1, future["success"]);
    ASSERT_EQ("completed", future["state"]);
    ASSERT_EQ(1, future["payload_frozen"]);
    ASSERT_EQ(0, future["frozen_result"]);

    async_payload = ([ "payload_key": "dummy/v1", "value": 2 ]);
    result = owner_call_async(this_object(), "dummy", async_payload);
    ASSERT_EQ(1, result["success"]);
    ASSERT_EQ(1, result["frozen_payload"]);
    ASSERT_EQ(1, result["async_only"]);
    ASSERT_EQ(1, result["target_handle_valid"]);
    ASSERT_EQ(0, result["requires_owner_mailbox"]);
    ASSERT_EQ(1, result["requires_owner_main_queue"]);
    ASSERT_EQ(1, result["main_required"]);
    ASSERT_EQ(1, result["queued_on_main"]);
    ASSERT_EQ(file_name(this_object())[1..], result["target_object_path"]);
    ASSERT_EQ(vm_owner_epoch(this_object()), result["target_owner_epoch"]);
    ASSERT_EQ(1, result["target_object_id"] > 0);
    assert_latest_message_trace(result["future_id"], "dummy", "message_submitted",
                                "", "", "current", 1, 0, 0, 0, 0, 1);
    ASSERT_EQ(0, called);
    async_payload["value"] = 99;
    ASSERT_EQ(1, vm_owner_drain_main(1));
    ASSERT_EQ(2, called);
    future = owner_future_poll(result["future_id"]);
    ASSERT_EQ(1, future["success"]);
    ASSERT_EQ("completed", future["state"]);
    ASSERT_EQ(1, future["payload_frozen"]);
    ASSERT_EQ(1, future["frozen_result"]);
    ASSERT_EQ(3, future["result"]["reply"]);
    ASSERT_EQ("dummy/v1", future["result"]["payload_key"]);
    assert_latest_message_trace(result["future_id"], "dummy", "completed",
                                "dummy", "", "current", 0, 1, 0, 1, 1, 1);

    vm_set_owner_id(this_object(), "owner/test/payload/stale-old");
    result = owner_call_async(this_object(), "dummy", ([ "payload_key": "stale-owner/v1", "value": 7 ]));
    ASSERT_EQ(1, result["success"]);
    ASSERT_EQ(1, result["target_handle_current"]);
    ASSERT_EQ("current", result["target_handle_status"]);
    ASSERT_EQ(1, result["requires_owner_main_queue"]);
    ASSERT_EQ("owner/test/payload/stale-old", result["target_owner_id"]);
    vm_set_owner_id(this_object(), "owner/test/payload/stale-new");
    ASSERT_EQ(1, vm_owner_drain_main(1));
    ASSERT_EQ(2, called);
    future = owner_future_poll(result["future_id"]);
    ASSERT_EQ(1, future["success"]);
    ASSERT_EQ("failed", future["state"]);
    ASSERT_EQ("owner_mismatch", future["target_handle_status"]);
    ASSERT_EQ(0, future["target_handle_current"]);
    ASSERT_EQ("stale target: owner_mismatch", future["error"]);
    ASSERT_EQ(1, future["payload_frozen"]);
    ASSERT_EQ(0, future["frozen_result"]);
    assert_latest_message_trace(result["future_id"], "dummy", "failed",
                                "", "stale target: owner_mismatch",
                                "owner_mismatch", 0, 0, 1, 1, 0, 0);

    assert_payload_error(owner_send(target_owner, ([ "type": "bad_object", "object": this_object() ])),
                         "owner payload must be frozen data, not object/function/buffer/class");
    assert_payload_error(owner_call_async(this_object(), "dummy", ([ "callback": (: dummy :) ])),
                         "owner payload must be frozen data, not object/function/buffer/class");
    assert_payload_error(owner_send(target_owner, ([ "type": "bad_buffer", "data": allocate_buffer(4) ])),
                         "owner payload must be frozen data, not object/function/buffer/class");
    assert_payload_error(owner_publish_snapshot(([ "box": new(class owner_payload_box) ])),
                         "owner payload must be frozen data, not object/function/buffer/class");
    bad_mapping = ([]);
    for (i = 0; i < 64; i++) {
        bad_mapping[sprintf("key/%d", i)] = i;
    }
    bad_mapping[1] = "bad_key";
    assert_payload_error(owner_publish_snapshot(bad_mapping),
                         "owner payload mapping keys must be strings");
    assert_payload_error(owner_publish_snapshot(([ "deep": ({ ({ ({ ({ ({ ({ ({ ({ ({ ({ 1 }) }) }) }) }) }) }) }) }) }) ])),
                         "owner payload nesting is too deep");

    result = owner_call_async(this_object(), "deep_result", ([ "payload_key": "deep-result/v1", "value": 1 ]));
    ASSERT_EQ(1, result["success"]);
    ASSERT_EQ(1, result["frozen_payload"]);
    ASSERT_EQ(1, vm_owner_drain_main(1));
    future = owner_future_poll(result["future_id"]);
    ASSERT_EQ(1, future["success"]);
    ASSERT_EQ("failed", future["state"]);
    ASSERT_EQ("owner async result must be frozen data", future["error"]);
    ASSERT_EQ(1, future["payload_frozen"]);
    ASSERT_EQ(0, future["frozen_result"]);
}
