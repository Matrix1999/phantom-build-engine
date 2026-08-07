# CMakeLists.txt — Guard / Cipher native build with OLLVM hardening
#
# ════════════════════════════════════════════════════════════════════════════
# OLLVM REQUIREMENT
# ════════════════════════════════════════════════════════════════════════════
# This file assumes your NDK toolchain has been replaced with an OLLVM-patched
# Clang (ollvm17 / ollvm19 or any compatible fork).  Set the NDK path to your
# OLLVM NDK in local.properties:
#
#   ndk.dir=/path/to/ollvm-ndk
#
# Alternatively, point cmake.dir + cmake.version in local.properties to a
# standalone OLLVM CMake toolchain.
#
# Standard NDK clang will compile this file fine but will NOT obfuscate —
# the -mllvm flags are silently ignored by a stock clang.
#
# ════════════════════════════════════════════════════════════════════════════
# OLLVM PASSES APPLIED (in order)
# ════════════════════════════════════════════════════════════════════════════
#
#  -sub         Instruction substitution: replaces arithmetic (ADD, XOR, etc.)
#               with semantically equivalent but structurally different chains.
#               Example: a + b → (a | b) + (a & b)
#
#  -sub_loop=3  Apply the substitution pass 3 times, chaining transforms so
#               even a constant like `128 + 3` becomes a 6-instruction sequence.
#               Key effect: closes the MOVZ #constant gap — no literal 131/9/0xA3
#               will appear in compiled guard_mba.h helper functions.
#
#  -bcf         Bogus Control Flow: inserts fake if-branches using opaque
#               predicates (e.g. y*(y+1)%2 == 0) before real basic blocks.
#               Makes IDA/Ghidra decompilation of guards unreadable.
#
#  -bcf_loop=2  Apply bogus CF twice — each pass sees the output of the last,
#               so blocks are wrapped in two layers of fake branches.
#
#  -fla         Control Flow Flattening: restructures function bodies as a
#               while(true) { switch(state) { ... } } dispatcher.
#               IDA/Ghidra cannot reconstruct the original call graph.
#
#  -split       Random basic-block splitting — further fragments flattened
#               blocks, spreading constants across more instructions.
#
#  -icall       Indirect calls: replaces direct BL function calls with BLR Xn
#               through an obfuscated pointer table.  Prevents traceable call
#               graphs and defeats PLT-hook detection via call-site scanning.
#               NOTE: this is what made `BL memcmp` disappear from the cert check.
#
#  -ibr         Indirect branches: same as -icall but for unconditional jumps.
#
# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL MANUAL HARDENING (in guard_mba.h)
# ════════════════════════════════════════════════════════════════════════════
#
#  The -sub pass only runs on arithmetic instructions already in the IR.
#  It cannot obfuscate a compile-time literal that the front-end folds before
#  any LLVM pass runs.  guard_mba.h closes this gap by:
#
#    • Expressing every sensitive constant (SIGKILL=9, __NR_tgkill=131,
#      XOR keys 0xA3/0x5A, pulse counter 0x5E3, mask 0xFFF) as a runtime
#      computation inside a __attribute__((noinline)) function.
#    • With -sub_loop=3 those functions are further transformed — the
#      combination means nothing in the binary equals the original constant.
#
# ════════════════════════════════════════════════════════════════════════════

cmake_minimum_required(VERSION 3.22)
project(cipher_guard C CXX)

# ── Sources ──────────────────────────────────────────────────────────────────
set(GUARD_SOURCES
    guard.cpp
    # guard_mba.h and guard_pstrings.inc are headers included by guard.cpp
)

# ════════════════════════════════════════════════════════════════════════════
# VMP interpreter — ported from maoabc/nmmp (nmmvm core)
# Compiled as a separate static lib so it can keep C++ exceptions enabled
# while cipher_guard uses -fno-exceptions / -fno-rtti.
# ════════════════════════════════════════════════════════════════════════════
file(GLOB VMP_CPP_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/vmp/*.cpp")
file(GLOB VMP_C_SRCS   "${CMAKE_CURRENT_SOURCE_DIR}/vmp/*.c")

add_library(vmp_interp STATIC ${VMP_CPP_SRCS} ${VMP_C_SRCS})

target_include_directories(vmp_interp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/vmp
    ${CMAKE_CURRENT_SOURCE_DIR}/vmp/include
    ${CMAKE_CURRENT_SOURCE_DIR}/vmp/cutils
)

target_compile_options(vmp_interp PRIVATE
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -std=c++17
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    # NOTE: exceptions are intentionally ENABLED here — the VMP interpreter
    # uses C++ exception semantics internally (DexCatch / Exception.cpp).
    # -fno-exceptions is NOT set for this target.
)

target_link_options(vmp_interp PRIVATE
    -Wl,--gc-sections
)

# ── Output: static library linked into the final protected .so ───────────────
add_library(cipher_guard STATIC ${GUARD_SOURCES})

target_include_directories(cipher_guard PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/vmp/include   # expose vm.h to guard.cpp if needed
)

# ── Base compile flags ────────────────────────────────────────────────────────
target_compile_options(cipher_guard PRIVATE
    # Optimisation level — O2 is required for OLLVM passes to run.
    # O0 / optnone disables all LLVM passes including OLLVM.
    # O2 gives the best obfuscation quality.
    -O2

    # Strip ALL symbol information from .text — function names, debug info.
    # Combined with the linker flag below, the .so ships with zero symbols.
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections

    # Disable exceptions + RTTI — shrinks code, removes demangleable names.
    -fno-exceptions
    -fno-rtti

    # C++ standard
    -std=c++17

    # Hardening: stack canary + fortify
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2

    # ── OLLVM obfuscation passes ─────────────────────────────────────────
    # NOTE: these are -mllvm flags passed straight to the LLVM backend.
    #       Standard NDK clang silently ignores unknown -mllvm arguments,
    #       so this file is safe to commit even when OLLVM is not in use.

    # Instruction substitution (closes the MOVZ #constant gap)
    -mllvm -mllvm=-sub
    -mllvm -mllvm=-sub_loop=3

    # Bogus control flow (wraps every basic block in fake branches)
    -mllvm -mllvm=-bcf
    -mllvm -mllvm=-bcf_loop=2

    # Control flow flattening (turns functions into switch dispatchers)
    -mllvm -mllvm=-fla

    # Basic block splitting (further fragments flattened blocks)
    -mllvm -mllvm=-split

    # Indirect calls (replaces BL with BLR through pointer table)
    -mllvm -mllvm=-icall

    # Indirect branches
    -mllvm -mllvm=-ibr
)

# ── Linker flags ──────────────────────────────────────────────────────────────
target_link_options(cipher_guard PRIVATE
    # Strip all symbols from the final .so
    -Wl,--strip-all
    # Dead-code elimination — remove any unreachable sections
    -Wl,--gc-sections
)

# ── Android system libraries ──────────────────────────────────────────────────
find_library(log-lib log)
find_library(z-lib z)
target_link_libraries(cipher_guard
    vmp_interp
    ${log-lib}
    ${z-lib}
)

# ════════════════════════════════════════════════════════════════════════════
# HOW TO WIRE INTO build.gradle
# ════════════════════════════════════════════════════════════════════════════
#
# In your module's build.gradle, add inside android { defaultConfig { ... } }:
#
#   externalNativeBuild {
#       cmake {
#           path "src/main/cpp/CMakeLists.txt"
#           version "3.22.1"
#       }
#   }
#
#   defaultConfig {
#       externalNativeBuild {
#           cmake {
#               cppFlags "-std=c++17"
#               arguments "-DANDROID_STL=c++_static"
#               abiFilters "arm64-v8a", "armeabi-v7a"
#           }
#       }
#   }
#
# Then rebuild — AGP will invoke CMake with your OLLVM clang, and the
# resulting libcipher_guard.a can replace (or augment) libcipher_arm64.a.
# ════════════════════════════════════════════════════════════════════════════
