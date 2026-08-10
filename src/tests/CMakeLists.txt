# GTEST
find_package(GTest)

if(${GTEST_FOUND})
  include(GoogleTest)
  enable_testing()

  add_executable(lpc_tests test_lpc.cc)
  target_link_libraries(lpc_tests PRIVATE ${FLUFFOS_LINK} GTest::GTest  GTest::Main)
  target_compile_definitions(lpc_tests PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

  add_executable(ofile_tests test_ofile.cc)
  target_link_libraries(ofile_tests PRIVATE ${FLUFFOS_LINK} GTest::GTest  GTest::Main)
  target_compile_definitions(ofile_tests PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

  gtest_discover_tests(lpc_tests ofile_tests DISCOVERY_TIMEOUT 60)
endif()

add_executable(owner_runtime_bench owner_runtime_bench.cc)
target_link_libraries(owner_runtime_bench PRIVATE ${FLUFFOS_LINK})

# Gateway frame parser fuzz targets (T15/F08). Two targets: a standalone
# deterministic smoke binary (all compilers) and a real libFuzzer target
# (clang; no custom main so the fuzzer runtime provides it).
add_executable(gateway_fuzz_smoke gateway_fuzz.cc)
target_link_libraries(gateway_fuzz_smoke PRIVATE ${FLUFFOS_LINK})
target_compile_definitions(gateway_fuzz_smoke PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")
# The smoke binary needs a main(); libFuzzer builds use the fuzzer runtime's
# main instead. A separate source shim keeps both targets clean.
add_executable(gateway_fuzz gateway_fuzz.cc)
# When built with clang + -fsanitize=fuzzer, the fuzzer runtime provides
# main() and LLVMFuzzerTestOneInput is the entry; the standalone smoke path
# lives in gateway_fuzz_smoke. Guard the local main() so it never conflicts.
target_link_libraries(gateway_fuzz PRIVATE ${FLUFFOS_LINK})
target_compile_definitions(gateway_fuzz PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")
target_compile_definitions(gateway_fuzz PRIVATE -DGATEWAY_FUZZ_NO_MAIN=1)
# Real libFuzzer target: enable via -DGATEWAY_FUZZ_LIBFUZZER=ON with clang.
# Links the fuzzer runtime (which provides main) alongside ASan/UBSan.
if(GATEWAY_FUZZ_LIBFUZZER)
  target_compile_options(gateway_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
  target_link_options(gateway_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
target_compile_definitions(owner_runtime_bench PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

add_executable(lpc_vm_bench lpc_vm_bench.cc)
target_link_libraries(lpc_vm_bench PRIVATE ${FLUFFOS_LINK})
target_compile_definitions(lpc_vm_bench PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

add_executable(object_store_bench object_store_bench.cc)
target_link_libraries(object_store_bench PRIVATE ${FLUFFOS_LINK})
target_compile_definitions(object_store_bench PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

add_executable(gateway_full_wire_bench gateway_full_wire_bench.cc)
target_link_libraries(gateway_full_wire_bench PRIVATE ${FLUFFOS_LINK})
