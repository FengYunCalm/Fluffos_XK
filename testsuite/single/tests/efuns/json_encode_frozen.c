void do_tests() {
    mixed nested;
    mixed *decoded_controls;
    mapping value;
    string controls;
    string native_json;
    int index;

    value = ([
        "message": "line 1\nline 2\t\\\"",
        "items": ({ ([ "id": "item/1", "count": 2 ]), 3, 1.25 }),
        "enabled": 1,
    ]);
    native_json = json_encode_frozen(value);
    ASSERT_EQ(json_encode(value), native_json);
    ASSERT_EQ(value, json_decode(native_json));

    controls = sprintf("%c%c%c%c%c", 8, 12, 1, 27, 31);
    native_json = json_encode_frozen(controls);
    ASSERT_EQ("\"\\b\\f\\u0001\\u001b\\u001f\"", native_json);
    ASSERT_EQ(controls, json_decode(native_json));

    controls = "";
    for (index = 1; index < 32; index++)
        controls += sprintf("%c", index);
    native_json = json_encode_frozen(({ controls }));
    decoded_controls = json_decode(native_json);
    ASSERT_EQ(1, sizeof(decoded_controls));
    ASSERT_EQ(controls, decoded_controls[0]);

    ASSERT_EQ(json_encode(({ 0.0, -1.5, 1.23456789 })),
              json_encode_frozen(({ 0.0, -1.5, 1.23456789 })));
    ASSERT_EQ("[]", json_encode_frozen(({})));
    ASSERT_EQ("{}", json_encode_frozen(([])));
    ASSERT_EQ(json_encode(value), json_encode_frozen_or_zero(value));

    nested = 1;
    for (index = 0; index < 8; index++)
        nested = ({ nested });
    ASSERT_EQ(nested, json_decode(json_encode_frozen(nested)));
    nested = ({ nested });
    ASSERT(catch(json_encode_frozen(nested)));
    ASSERT_EQ(0, json_encode_frozen_or_zero(nested));

    ASSERT(catch(json_encode_frozen(this_object())));
    ASSERT(catch(json_encode_frozen(([ 1: "bad key" ]))));
    ASSERT(catch(json_encode_frozen(allocate_buffer(4))));
    ASSERT_EQ(0, json_encode_frozen_or_zero(this_object()));
    ASSERT_EQ(0, json_encode_frozen_or_zero(([ 1: "bad key" ])));
    ASSERT_EQ(0, json_encode_frozen_or_zero(allocate_buffer(4)));
}
