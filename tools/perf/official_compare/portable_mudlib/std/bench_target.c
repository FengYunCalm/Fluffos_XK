private int counter;

int noop(int value)
{
    return value + 1;
}

private int do_apply(int rounds)
{
    int i;
    int sum;

    for (i = 0; i < rounds; i++) {
        sum += noop(i);
    }
    return sum;
}

private int do_call_other(int rounds)
{
    int i;
    int sum;

    for (i = 0; i < rounds; i++) {
        sum += call_other(this_object(), "noop", i);
    }
    return sum;
}

private int do_mapping(int rounds)
{
    int i;
    mapping data = ([]);

    for (i = 0; i < rounds; i++) {
        data["k" + i] = i;
    }
    for (i = 0; i < rounds; i++) {
        counter += data["k" + i];
    }
    return sizeof(data);
}

private int do_string(int rounds)
{
    int i;
    string out = "";

    for (i = 0; i < rounds; i++) {
        out += "x" + i;
    }
    return strlen(out);
}

private int do_array(int rounds)
{
    int i;
    mixed *items = ({});

    for (i = 0; i < rounds; i++) {
        items += ({ i });
    }
    return sizeof(items);
}

private int do_clone(int rounds)
{
    int i;
    object ob;

    for (i = 0; i < rounds; i++) {
        ob = new("/std/bench_clone");
        ob->set_value(i);
        counter += ob->query_value();
        destruct(ob);
    }
    return rounds;
}

int run_command(string arg)
{
    string token;
    string kind;
    int result;

    if (sscanf(arg || "", "%s %s", token, kind) != 2) {
        write("ERR malformed\n> ");
        return 1;
    }
    switch (kind) {
    case "apply":
        result = do_apply(64);
        break;
    case "call_other":
        result = do_call_other(64);
        break;
    case "mapping":
        result = do_mapping(48);
        break;
    case "string":
        result = do_string(48);
        break;
    case "array":
        result = do_array(48);
        break;
    case "clone":
        result = do_clone(12);
        break;
    default:
        result = do_apply(8);
        break;
    }
    write("OK " + token + " " + kind + " " + result + "\n> ");
    return 1;
}
