cmake_minimum_required(VERSION 2.8)

project(usched)

add_subdirectory(lib/calm)

add_library(usched SHARED coro.h coro.c usched.c usched.h)
target_compile_definitions(usched PRIVATE _GNU_SOURCE)
target_link_libraries(usched PRIVATE calm)
