cmake_minimum_required(VERSION 3.16)
project(hidrs_os_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

add_executable(hidrs_os_engine
    src/main.cpp
    src/event_writer.cpp
    src/process_monitor.cpp
    src/behavior_detector.cpp
    src/response_engine.cpp
)

target_include_directories(hidrs_os_engine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(hidrs_os_engine PRIVATE -Wall -Wextra -pthread)

target_link_libraries(hidrs_os_engine PRIVATE Threads::Threads)
