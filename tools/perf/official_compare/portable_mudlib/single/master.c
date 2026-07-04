nosave int has_error;

object connect()
{
    return new("/clone/login");
}

void flag(string str)
{
    string file;
    object ob;
    mixed err;

    if (str == "shutdown") {
        shutdown(0);
        return;
    }
    file = str || "";
    if (sscanf(file, "test:%s", file) != 1) {
        write("unsupported portable flag: " + file + "\n");
        shutdown(-1);
        return;
    }
    err = catch(ob = load_object("/" + file));
    if (!err && ob) {
        err = catch(call_other(ob, "do_tests"));
    }
    if (err || !ob) {
        write(sprintf("portable benchmark failed: err=%O ob=%O file=%O\n", err, ob, file));
        shutdown(-1);
        return;
    }
    shutdown(0);
}

string *epilog(int load_empty)
{
    return ({ "/std/bench_target" });
}

void preload(string file)
{
    catch(call_other(file, "??"));
}

void log_error(string file, string message)
{
    write_file("/log/compile", message);
}

void error_handler(mapping error)
{
    write_file("/log/runtime", sprintf("%O\n", error));
}

int valid_read(string file, mixed user, string func) { return 1; }
int valid_write(string file, mixed user, string func) { return 1; }
int valid_seteuid(object ob, string id) { return 1; }
int valid_exec(string name, object from, object to) { return 1; }
int valid_bind(object binder, object old_owner, object new_owner) { return 1; }
int valid_shadow(object ob) { return 1; }
int valid_hide(object ob) { return 1; }
int valid_override(string file, string name, string mainfile) { return 1; }
int valid_socket(object ob, string func, mixed *info) { return 1; }

string get_root_uid() { return "Root"; }
string get_bb_uid() { return "Backbone"; }
string creator_file(string file) { return "Root"; }
string domain_file(string file) { return "Root"; }
string author_file(string file) { return "Root"; }

mixed compile_object(string file)
{
    return 0;
}

void destruct_environment_of(object ob)
{
    if (interactive(ob)) {
        tell_object(ob, "moved from destructed environment\n");
    }
}

string make_path_absolute(string file)
{
    return file;
}
