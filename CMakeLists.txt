cmake_minimum_required(VERSION 3.16)

project(cpp-demo)

# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-fsanitize=address,undefined -g)
add_link_options(-fsanitize=address,undefined)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_testing()
include(GoogleTest)
enable_fuzz_testing()

add_library(lib_iso15765
    ${CMAKE_SOURCE_DIR}/lib/lib_iqueue.h
    ${CMAKE_SOURCE_DIR}/lib/lib_iqueue.c
    ${CMAKE_SOURCE_DIR}/src/lib_iso15765.c
    ${CMAKE_SOURCE_DIR}/src/lib_iso15765.h
)

target_include_directories(lib_iso15765 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/lib
)

add_executable(example
    ${CMAKE_SOURCE_DIR}/exm/ISO15765Development.c
)

target_link_libraries(example
    lib_iso15765
)

add_subdirectory(fuzz-tests)
add_subdirectory(cifuzz-spark)
