cmake_minimum_required(VERSION 3.16)
project(chinadns_ng C)

option(ENABLE_WOLFSSL "Enable DNS-over-TLS upstream support" OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "chinadns-ng supports Linux only")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_executable(chinadns-ng
    src/main.c
    src/core.c
    src/config.c
    src/server.c
    src/cache.c
    src/local_rr.c
    src/dns.c
    src/dnl.c
    src/ipset.c
    src/nl.c
    src/net.c
    src/tag.c
    src/log.c
    src/misc.c)

target_include_directories(chinadns-ng PRIVATE src)
target_compile_options(chinadns-ng PRIVATE
    -Wall -Wextra -fno-strict-aliasing)

if(ENABLE_WOLFSSL)
    target_compile_definitions(chinadns-ng PRIVATE ENABLE_WOLFSSL)
    find_library(WOLFSSL_LIBRARY wolfssl)
    if(NOT WOLFSSL_LIBRARY)
        message(FATAL_ERROR "wolfSSL library not found")
    endif()
    target_link_libraries(chinadns-ng PRIVATE ${WOLFSSL_LIBRARY})
endif()
