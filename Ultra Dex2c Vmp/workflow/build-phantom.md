# Building libphantom.so (OLLVM + NDK CI Recipe)

`libphantom.so` is the native library that derives the per-APK DEX decryption
key at runtime via `nativeGetKey(salt, certHash, pkgName)`.  It must be
compiled with OLLVM so the ARX KDF and the SHA-256 implementation are
obfuscated before shipping.

> **Do not compile this on Replit.**  Use a dedicated CI runner with the OLLVM
> toolchain installed (GitHub Actions example below).

---

## Source file

```
src/main/cpp/phantom_key.c
```

Exports exactly one JNI symbol:

```c
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeGetKey
```

---

## Required toolchain

| Component | Version |
|---|---|
| Android NDK | r25c or later |
| OLLVM-patched Clang | obfuscator-llvm 13.x or hikari fork |
| CMake | 3.22+ |

---

## Build steps (manual)

### arm64-v8a

```bash
cmake -B build-arm64 \
      -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-21 \
      -DCMAKE_C_COMPILER=/opt/ollvm/bin/clang \
      -DCMAKE_BUILD_TYPE=Release \
      src/main/cpp/phantom

cmake --build build-arm64 --target phantom
# output: build-arm64/libphantom.so
```

### armeabi-v7a

```bash
cmake -B build-arm \
      -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=armeabi-v7a \
      -DANDROID_PLATFORM=android-21 \
      -DCMAKE_C_COMPILER=/opt/ollvm/bin/clang \
      -DCMAKE_BUILD_TYPE=Release \
      src/main/cpp/phantom

cmake --build build-arm --target phantom
# output: build-arm/libphantom.so
```

---

## Encrypting the blobs

The stub decrypts each blob with the ARX cipher using the hardcoded blob key
defined in `DexCrypto.blobKey()`:

```
"Ph4nt0mBl0bK3y!!"   (16 bytes, ASCII)
```

Encrypt each `.so` with the same cipher before committing:

```python
# encrypt_blob.py — reference implementation matching DexCrypto.exfr()
# Run: python3 encrypt_blob.py libphantom.so libphantom_arm64.blob
import sys, struct, zlib

BLOB_KEY = b"Ph4nt0mBl0bK3y!!"

def le32(b, off): return struct.unpack_from('<I', b, off)[0]
def rol32(v, n):  return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def expand(key):
    iArr = [le32(key, i*4) for i in range(4)]
    r = [iArr[0]]
    t = list(iArr[1:])
    for i2 in range(26):
        t[i2%3] = (rol32(t[i2%3], 24) + r[-1] ^ i2) & 0xFFFFFFFF
        r.append((rol32(r[-1], 3) ^ t[i2%3]) & 0xFFFFFFFF)
    return r

def step(sub, iArr):
    i, i2 = sub
    for k in iArr:
        i2 = ((rol32(i2, 24) + i) ^ k) & 0xFFFFFFFF
        i  = (rol32(i, 3) ^ i2) & 0xFFFFFFFF
    return [i, i2]

def cipher(data, key):
    sch = expand(key)
    state = [le32(key, 0)^le32(key, 8), le32(key, 4)^le32(key, 12)]
    out, pos = bytearray(data), 0
    while pos < len(out):
        if pos % 8 == 0:
            state = step(state, sch)
        word = state[(pos%8)//4]
        byte_shift = (pos % 4) * 8
        out[pos] ^= (word >> byte_shift) & 0xFF
        pos += 1
    return bytes(out)

src, dst = sys.argv[1], sys.argv[2]
raw = open(src,'rb').read()
compressed = zlib.compress(raw)        # DexCrypto wraps in Deflater
encrypted  = cipher(compressed, BLOB_KEY)
open(dst,'wb').write(encrypted)
print(f"Wrote {len(encrypted)} bytes → {dst}")
```

Place the resulting files at:

```
stub-loader/src/main/assets/phantom/libphantom_arm64.blob
stub-loader/src/main/assets/phantom/libphantom_arm.blob
```

---

## GitHub Actions example

```yaml
name: Build libphantom

on: [push]

jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4

      - name: Install NDK
        run: |
          wget -q https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
          unzip -q android-ndk-r25c-linux.zip
          echo "NDK=$PWD/android-ndk-r25c" >> $GITHUB_ENV

      - name: Install OLLVM
        run: |
          # Replace with your OLLVM build / release URL
          wget -q https://github.com/<your-org>/ollvm-build/releases/download/v13/ollvm-linux.tar.gz
          tar xf ollvm-linux.tar.gz -C /opt
          echo "/opt/ollvm/bin" >> $GITHUB_PATH

      - name: Build arm64-v8a
        run: |
          cmake -B build-arm64 \
            -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
            -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 \
            -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release \
            src/main/cpp/phantom
          cmake --build build-arm64 --target phantom

      - name: Build armeabi-v7a
        run: |
          cmake -B build-arm \
            -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
            -DANDROID_ABI=armeabi-v7a -DANDROID_PLATFORM=android-21 \
            -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release \
            src/main/cpp/phantom
          cmake --build build-arm --target phantom

      - name: Encrypt blobs
        run: |
          python3 docs/encrypt_blob.py build-arm64/libphantom.so libphantom_arm64.blob
          python3 docs/encrypt_blob.py build-arm/libphantom.so    libphantom_arm.blob

      - uses: actions/upload-artifact@v4
        with:
          name: phantom-blobs
          path: |
            libphantom_arm64.blob
            libphantom_arm.blob
```

---

## Checklist before shipping

- [ ] `phantom_key.c` compiles without warnings
- [ ] JNI symbol visible: `nm -D libphantom.so | grep nativeGetKey`
- [ ] All other symbols stripped: `nm -D libphantom.so | wc -l` should be 1
- [ ] Blobs encrypted with `encrypt_blob.py` using the correct blob key
- [ ] Blob key in `DexCrypto.blobKey()` matches `encrypt_blob.py` BLOB_KEY
- [ ] `PhantomKey.arx()` test vectors match `arx_kdf()` in C (see unit tests)
