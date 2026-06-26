class worker_payload_box {
    int value;
}

void assert_worker_error(mapping result, string error) {
    ASSERT_EQ(0, result["success"]);
    ASSERT_EQ(error, result["error"]);
}

void do_tests() {
    mapping bad_mapping;

    assert_worker_error(vm_worker_task("snapshot_digest",
        ([ "type": "bad_object", "object": this_object() ]),
        ([ "repeat": 1 ])),
        "worker value contains unsupported type");

    assert_worker_error(vm_worker_submit("snapshot_digest",
        ([ "type": "bad_function", "callback": (: do_tests :) ]),
        ([ "repeat": 1 ])),
        "worker value contains unsupported type");

    assert_worker_error(vm_worker_task("snapshot_digest",
        ([ "type": "bad_buffer", "data": allocate_buffer(4) ]),
        ([ "repeat": 1 ])),
        "worker value contains unsupported type");

    assert_worker_error(vm_worker_submit("snapshot_digest",
        ([ "type": "bad_class", "box": new(class worker_payload_box) ]),
        ([ "repeat": 1 ])),
        "worker value contains unsupported type");

    bad_mapping = ([]);
    bad_mapping["ok"] = "value";
    bad_mapping[1] = "bad_key";
    assert_worker_error(vm_worker_task("snapshot_digest", bad_mapping, ([ "repeat": 1 ])),
        "worker mapping keys must be strings");

    assert_worker_error(vm_worker_submit("snapshot_digest",
        ([ "deep": ({ ({ ({ ({ ({ ({ ({ ({ ({ ({ 1 }) }) }) }) }) }) }) }) }) }) ]),
        ([ "repeat": 1 ])),
        "worker value nesting is too deep");

    bad_mapping = vm_worker_submit_batch(({
        ([ "task": "snapshot_digest",
           "snapshot": ([ "nested_object": this_object() ]),
           "options": ([ "repeat": 1 ]) ]),
    }));
    ASSERT_EQ(0, bad_mapping["success"]);
    ASSERT_EQ(0, bad_mapping["accepted"]);
    ASSERT_EQ(1, bad_mapping["rejected"]);
    ASSERT_EQ(1, sizeof(bad_mapping["results"]));
    ASSERT_EQ("worker value contains unsupported type", bad_mapping["results"][0]["error"]);
}
