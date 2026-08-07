# phantom/CMakeLists.txt
#
# Build libphantom.so from phantom_key.c using the OLLVM toolchain.
#
# Prerequisites:
#   • OLLVM-patched Clang in PATH (or set via -DCMAKE_C_COMPILER=…)
#   • Android NDK r25c+ (for the sysroot / toolchain file)
#
# Typical invocation (arm64-v8a):
#
#   cmake -B build-arm64 \
#         -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-21 \
#         -DCMAKE_C_COMPILER=/path/to/ollvm/bin/clang \
#         -DCMAKE_BUILD_TYPE=Release \
#         src/main/cpp/phantom
#   cmake --build build-arm64
#
# Then ARX-encrypt each output .so with the blob key defined in
# DexCrypto.blobKey() ("Ph4nt0mBl0bK3y!!") and store as:
#   assets/phantom/libphantom_arm64.blob   (arm64-v8a)
#   assets/phantom/libphantom_arm.blob     (armeabi-v7a)
#
# The blob key must match DexCrypto.blobKey() exactly.
# See docs/build-phantom.md for the full CI recipe.

cmake_minimum_required(VERSION 3.22)
project(phantom C)

set(CMAKE_C_STANDARD 11)

# ── OLLVM passes ─────────────────────────────────────────────────────────────
# Enable all three obfuscation passes.  Adjust strength as needed.
set(OLLVM_FLAGS
    -mllvm -fla            # control-flow flattening
    -mllvm -bcf            # bogus control flow
    -mllvm -bcf_prob=100   # 100% bogus-CF coverage — PHANTOM ELITE
    -mllvm -bcf_loop=4     # 4 bogus-CF iterations — PHANTOM ELITE
    -mllvm -sub            # instruction substitution
    -mllvm -sub_loop=3     # 3 substitution iterations
    -mllvm -sobf           # string obfuscation
    -mllvm -split          # basic block splitting
    -mllvm -split_num=5    # 5 splits per block — PHANTOM ELITE
    -mllvm -ibr            # indirect branching
    -mllvm -icall          # indirect calls
    -mllvm -igv            # indirect global variables
)

# ── Source ────────────────────────────────────────────────────────────────────
add_library(phantom SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/../phantom_key.c
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(phantom PRIVATE
    -O2
    -fvisibility=hidden         # hide all symbols by default
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    ${OLLVM_FLAGS}
)

# Only export the JNI entry-point.
target_link_options(phantom PRIVATE
    -Wl,--version-script,${CMAKE_CURRENT_BINARY_DIR}/phantom.map
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,--strip-all
)

target_link_libraries(phantom
    android
    log
    # Static-link zlib so inflateInit_ is baked into libphantom.so.
    # Dynamic -lz causes "cannot locate symbol inflateInit_" when the .so
    # is loaded via System.load(absolutePath) — Android's linker gives it
    # an isolated namespace that cannot see the APK's libz.so at runtime.
    -Wl,-Bstatic,-lz,-Bdynamic
    pthread     # needed by detect_frida_loop background thread
)

# ── Export map — only the two JNI symbols are visible ────────────────────────
# nativeDecryptShard : key derivation + DEX shard decryption
# nativeWipeShard    : wipe DEX magic from the Java byte[] after ART parses it
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/phantom.map
"{\n  global:\n    Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard;\n    Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard;\n  local: *;\n};\n"
)
