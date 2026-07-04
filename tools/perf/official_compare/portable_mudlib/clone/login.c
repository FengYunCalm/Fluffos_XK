void logon()
{
    object user;

    write("PORTABLE_READY\nname: ");
    input_to("receive_name");
}

void receive_name(string name)
{
    object user = new("/clone/user");

    user->set_name(name && name != "" ? name : "portable");
    exec(user, this_object());
    user->setup();
    destruct(this_object());
}
