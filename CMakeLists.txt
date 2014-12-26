cmake_minimum_required(VERSION 2.8.4)

project(libuv_webserver)

set(SOURCE_FILES webserver.c)

include_directories(${PROJECT_SOURCE_DIR}/deps "/usr/local/include")

link_directories("/usr/local/lib" "${PROJECT_SOURCE_DIR}/deps/http-parser")

add_executable(libuv_webserver ${SOURCE_FILES})

target_link_libraries(libuv_webserver "libuv.a" "libhttp_parser.a")
