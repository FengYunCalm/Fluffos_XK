private string name;

void set_name(string value)
{
    name = value;
}

string query_name()
{
    return name || "portable";
}

void setup()
{
    enable_commands();
    add_action("command_hook", "", 1);
    write("READY " + query_name() + "\n> ");
}

int command_hook(string arg)
{
    string verb = query_verb();

    if (verb == "quit") {
        write("BYE\n");
        destruct(this_object());
        return 1;
    }
    if (verb == "bench") {
        return "/std/bench_target"->run_command(arg);
    }
    write("UNKNOWN\n> ");
    return 1;
}

void catch_tell(string str)
{
    receive(str);
}

void receive_message(string cls, string msg)
{
    receive(msg);
}
