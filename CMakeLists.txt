cmake_minimum_required(VERSION 2.8)
project(dynfilefs C ASM)
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc -Wl,-static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wl,-gc-sections -Os -s")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64")

# lib
add_library(dynfilefs
    src/dynfilefs.c
)

# main
add_executable(dynfilefs_mount
    src/main.c
)
include_directories(
    include
)
target_link_libraries(dynfilefs_mount dynfilefs fuse pthread dl)
