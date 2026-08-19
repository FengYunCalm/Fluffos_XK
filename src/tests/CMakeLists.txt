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
add_executable(bench_compile bench_compile.cc)
target_link_libraries(owner_runtime_bench PRIVATE ${FLUFFOS_LINK})
target_link_libraries(bench_compile PRIVATE ${FLUFFOS_LINK})

# Gateway frame parser fuzz targets (T15/F08/R2-F02).
#
# Default build graph: only gateway_fuzz_smoke (real main() from the shim).
# The libFuzzer target gateway_fuzz is created EXCLUSIVELY when
# GATEWAY_FUZZ_LIBFUZZER=ON with clang (the fuzzer runtime provides main),
# so plain `make all/install` and CodeQL builds never link a no-main target.
if(GATEWAY_FUZZ_LIBFUZZER AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR
    "GATEWAY_FUZZ_LIBFUZZER=ON requires a Clang compiler for "
    "-fsanitize=fuzzer (found ${CMAKE_CXX_COMPILER_ID} "
    "${CMAKE_CXX_COMPILER_VERSION}). Configure the default build without "
    "this option, or reconfigure with clang.")
endif()

add_library(gateway_fuzz_core OBJECT gateway_fuzz.cc)
target_compile_definitions(gateway_fuzz_core PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")
target_link_libraries(gateway_fuzz_core PRIVATE ${FLUFFOS_LINK})

add_executable(gateway_fuzz_smoke gateway_fuzz_smoke_main.cc)
target_link_libraries(gateway_fuzz_smoke PRIVATE gateway_fuzz_core ${FLUFFOS_LINK})
target_compile_definitions(gateway_fuzz_smoke PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

if(GATEWAY_FUZZ_LIBFUZZER)
  add_executable(gateway_fuzz gateway_fuzz.cc)
  target_link_libraries(gateway_fuzz PRIVATE ${FLUFFOS_LINK})
  target_compile_definitions(gateway_fuzz PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")
  target_compile_options(gateway_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
  target_link_options(gateway_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
target_compile_definitions(owner_runtime_bench PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")
target_compile_definitions(bench_compile PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

add_executable(lpc_vm_bench lpc_vm_bench.cc)
target_link_libraries(lpc_vm_bench PRIVATE ${FLUFFOS_LINK})
target_compile_definitions(lpc_vm_bench PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

add_executable(object_store_bench object_store_bench.cc)
target_link_libraries(object_store_bench PRIVATE ${FLUFFOS_LINK})
target_compile_definitions(object_store_bench PRIVATE -DTESTSUITE_DIR="${CMAKE_SOURCE_DIR}/testsuite")

add_executable(gateway_full_wire_bench gateway_full_wire_bench.cc)
target_link_libraries(gateway_full_wire_bench PRIVATE ${FLUFFOS_LINK})
