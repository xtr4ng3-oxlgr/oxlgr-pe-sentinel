cmake_minimum_required(VERSION 3.16)

project(oxlgr-pe-sentinel
    VERSION 1.0.0
    DESCRIPTION "Defensive C++ PE analyzer for entropy, imports, overlays and static indicators"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(oxlgr-pe-sentinel
    src/main.cpp
    src/entropy.cpp
    src/strings.cpp
    src/indicators.cpp
    src/pe_parser.cpp
    src/report.cpp
)

target_include_directories(oxlgr-pe-sentinel PRIVATE include)

if(MSVC)
    target_compile_options(oxlgr-pe-sentinel PRIVATE /W4 /permissive-)
else()
    target_compile_options(oxlgr-pe-sentinel PRIVATE -Wall -Wextra -Wpedantic)
endif()
