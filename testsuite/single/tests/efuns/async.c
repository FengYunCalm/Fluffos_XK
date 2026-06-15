#ifdef __PACKAGE_ASYNC__
nosave int calledGetDir, calledWrite, calledRead;
nosave int calledStale;
nosave int ownerMainQueuedBefore;
#endif

void do_tests() {
#ifndef __PACKAGE_ASYNC__
    write("PACKAGE_ASYNC is not enabled, skipping async tests...\n");
    return;
#else
    ownerMainQueuedBefore = vm_owner_runtime_status()["main_queued"];

    // async_getdir
    async_getdir("/nonexistant/", function(mixed res) {
        write("ASYNC: async_getdir callback\n");
        ASSERT_EQ(({ }), res); // ({ }), but get_dir("/nonexistant/") == 0
        calledGetDir++;
    });
    async_getdir("/nonexistant", function(mixed res) {
        write("ASYNC: async_getdir callback\n");
        ASSERT_EQ(get_dir("/nonexistant"), res); // ({ })
        calledGetDir++;
    });
    async_getdir("/u/", function(mixed res) {
        write("ASYNC: async_getdir callback\n");
        ASSERT_EQ(get_dir("/u/"), res);
        calledGetDir++;
    });
    call_out((: async_getdir, "/std/", function(mixed res) {
        write("ASYNC: call_out async_getdir callback\n");
        ASSERT_EQ(get_dir("/std/"), res);
        calledGetDir++;
    } :), 1);

    rm("/log/testfile"); // ensure test file is deleted pre-test

    // async_write
    async_write("/log", "test data written to file", 1, function(int res) {
        write("ASYNC: async_write callback\n");
        ASSERT_EQ(-1, res);
        calledWrite++;
    });
    async_write("/log/testfile", "test data written to file", 1, function(int res) {
        write("ASYNC: async_write callback\n");
        ASSERT_EQ(0, res);
        calledWrite++;
    });

    // async_read
    async_read("/log", function(mixed res) {
        write("ASYNC: async_read callback\n");
        ASSERT_EQ(-1, res);
        calledRead++;
    });
    async_read("/log/testfile", function(mixed res) {
        write("ASYNC: async_read callback\n");
        ASSERT_EQ("test data written to file", res);
        calledRead++;
    });

    call_out(function() {
        rm("/log/testfile"); // ensure test file is deleted post-test
        ASSERT_EQ(4, calledGetDir);
        ASSERT_EQ(2, calledWrite);
        ASSERT_EQ(2, calledRead);
        ASSERT(vm_owner_runtime_status()["main_queued"] > ownerMainQueuedBefore);
        async_getdir("/std/", function(mixed res) {
            calledStale++;
        });
        vm_set_owner_id(this_object(), "owner/test/async-stale-new");
        call_out(function() {
            ASSERT_EQ(0, calledStale);
        }, 1);
    }, 2);
#endif
}
