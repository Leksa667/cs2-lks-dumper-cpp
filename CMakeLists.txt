# cs2-lks-dumper — Counter-Strike 2 memory dumper
# Author: Leksa667 — https://github.com/Leksa667/cs2-lks-dumper-cpp

cmake_minimum_required(VERSION 3.20)
project(cs2-lks-dumper VERSION 0.1.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

add_executable(cs2-lks-dumper
    src/main.cpp
)

target_include_directories(cs2-lks-dumper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(cs2-lks-dumper PRIVATE
    nlohmann_json::nlohmann_json
)

if(MSVC)
    target_compile_options(cs2-lks-dumper PRIVATE /W4 /permissive-)
    target_compile_definitions(cs2-lks-dumper PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    target_compile_options(cs2-lks-dumper PRIVATE -Wall -Wextra -Wpedantic)
endif()
