# assets/phantom/

This directory holds the files that DexPacker bundles into every protected APK's
`assets/phantom/` at pack time.

## Required files (not committed — built by CI)

| File | Description |
|---|---|
| `libphantom_arm64.blob` | OLLVM-compiled `libphantom.so` (arm64-v8a), ARX-encrypted |
| `libphantom_arm.blob`   | OLLVM-compiled `libphantom.so` (armeabi-v7a), ARX-encrypted |

These blobs **must** be present before calling `DexPacker.pack()`.  If they are
missing, packing will throw an `IOException` with a clear message rather than
silently producing a broken APK.

## How to build and place the blobs

See [`docs/build-phantom.md`](../../docs/build-phantom.md) for the full recipe.

Short version:
```bash
# 1. Build with OLLVM + NDK (see CMakeLists.txt)
cmake -B build-arm64 … src/main/cpp/phantom && cmake --build build-arm64
cmake -B build-arm   … src/main/cpp/phantom && cmake --build build-arm

# 2. Encrypt
python3 docs/encrypt_blob.py build-arm64/libphantom.so src/main/assets/phantom/libphantom_arm64.blob
python3 docs/encrypt_blob.py build-arm/libphantom.so   src/main/assets/phantom/libphantom_arm.blob
```

## What ends up in the protected APK

`DexPacker.pack()` reads these blobs from the Dex2c Mega app's own assets and
copies them into the output APK's `assets/phantom/`.  The stub loader
(`DexProtector.install()`) then:

1. Picks the ABI-appropriate blob (`arm64` or `arm`).
2. Decrypts it with the hardcoded blob key (via `DexCrypto.loadPhantomLib()`).
3. Writes the decrypted `.so` to `getCodeCacheDir()/libphantom.so`.
4. Calls `System.load()`.
5. Calls `nativeGetKey(salt, certHash, pkgName)` to derive the 16-byte DEX key.
