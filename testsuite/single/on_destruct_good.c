void create()
{
    set_notify_destruct(1) ;
}

void on_destruct()
{
    debug_message("on_destruct() called in " __FILE__) ;
    rm("/data/test_on_destruct_good") ;
}

void dummy()
{
}

mapping owner_async_echo(mapping payload)
{
    return ([
        "reply": payload["value"] + 1,
        "payload_key": payload["payload_key"],
        "target_owner_id": vm_owner_id(this_object()),
    ]);
}

object owner_async_non_frozen_result(mapping payload)
{
    return this_object();
}
