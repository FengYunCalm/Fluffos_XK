mapping last_system_message = ([]);
string last_owner_id = "";
int last_owner_epoch = 0;
string last_this_player = "";

void receive_system_message(mapping msg) {
    last_system_message = msg;
    last_owner_id = vm_owner_id(this_object());
    last_owner_epoch = vm_owner_epoch(this_object());
    last_this_player = this_player() ? file_name(this_player()) : "";
}

mapping query_last_system_message() {
    return ([
        "owner_id": last_owner_id,
        "owner_epoch": last_owner_epoch,
        "this_player": last_this_player,
        "type": last_system_message["type"],
        "action": last_system_message["action"],
        "source": last_system_message["source"],
    ]);
}
