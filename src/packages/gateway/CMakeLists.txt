option(PACKAGE_GATEWAY "gateway package for Go gateway communication" ON)

if(PACKAGE_GATEWAY)
    add_library(package_gateway STATIC gateway.cc gateway_session.cc)
    target_include_directories(package_gateway PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../)
endif()
