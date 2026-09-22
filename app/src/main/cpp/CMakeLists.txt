cmake_minimum_required(VERSION 3.22.1)

project(pure_media_policy LANGUAGES CXX)

add_library(pure_media_policy SHARED native_media_policy.cpp)

target_compile_features(pure_media_policy PRIVATE cxx_std_17)
target_compile_options(
    pure_media_policy
    PRIVATE
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections
        -fno-ident
)

if(DEFINED AMICE_PLUGIN AND NOT AMICE_PLUGIN STREQUAL "")
    # AMICE is a host clang pass plugin. The caller must provide a matching
    # plugin/libLLVM/NDK bundle and enable its passes in the build environment.
    target_compile_options(pure_media_policy PRIVATE "-fpass-plugin=${AMICE_PLUGIN}")
endif()

target_link_options(
    pure_media_policy
    PRIVATE
        "-Wl,--gc-sections"
        "-Wl,--exclude-libs,ALL"
)

find_library(log-lib log)
target_link_libraries(pure_media_policy PRIVATE ${log-lib})