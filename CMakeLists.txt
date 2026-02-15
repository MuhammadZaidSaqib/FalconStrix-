cmake_minimum_required(VERSION 4.0)
project(FalconStrix)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(FalconStrix
        backend.cpp
)
