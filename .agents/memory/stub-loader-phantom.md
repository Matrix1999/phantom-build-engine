---
name: Stub-loader & phantom_key.c architecture
description: Full structural knowledge of the Ultra Dex2c VMP stub-loader (Java) and phantom native key (C) components — for use before any future edits.
---

## Stub-loader Java files
Location: `Ultra Dex2c Vmp/stub-loader/src/main/java/com/ultra/dex2cvmp/`

### ProxyApplication.java
- Entry point: `attachBaseContext` → `new DexProtector(base).install(base)`
- `realApplication()`: replaces the ProxyApplication with the real app via reflection into ActivityThread/LoadedApk/mAllApplications/mProviderMap. Uses `Const.getRealApp()` for class name.

### data/Const.java
- `DP_LIB = "phantom"` — asset subdirectory
- `BUNDLE_FILE = "phantom.vmp"` — single-file encrypted shard bundle
- `APP_CFG = "app.cfg"` — real Application class name
- `SALT_ASSET = "ph_salt"` — 16-byte random salt
- `PHANTOM_BLOB_ARM64/ARM` — blob asset filenames
- `REAL_APP` private field, only set via `setRealApp()`

### utils/DexCrypto.java
- Two native methods: `nativeDecryptShard(salt, pkgNameUtf8, encShard)` and `nativeWipeShard(dexBytes)`
- Blob key stored split: `ASSET_KEY_MASK` (16 bytes) XORed with first 16 bytes of `phantom.vmp` header at runtime → reconstructed `key[]`
- `loadPhantomLib(ctx, masked)`: decrypt blob, write to `code_cache/libphantom.so`, `System.load()`, then `soFile.delete()` (inode stays mapped)
- Pre-loads `libz` before `System.load` to fix isolated linker namespace
- ARX stream cipher in Java: `exfr()` → `FxIjsF()` (27-word key schedule) → `nDnv()` (per-8-byte-block state advance)
- Blob decrypt pipeline: outer `InflaterInputStream` → ARX XOR → `InflaterOutputStream`

### utils/DexProtector.java
- `install()` steps:
  1. Read `phantom.vmp`, extract first 16 bytes as masked blob key
  2. `DexCrypto.loadPhantomLib(ctx, maskedBlobKey)` → loads libphantom.so
  3. Read `app.cfg` → `Const.setRealApp()`
  4. Read 16-byte salt from `ph_salt`
  5. Parse `phantom.vmp` body (after 16-byte header): `shardCount` int + `shardCount` size ints
  6. API 27+: `loadInMemory()` using `InMemoryDexClassLoader`; API <27: `loadViaFiles()`
- `loadInMemory()`: decrypt each shard via native, wrap in `ByteBuffer`, create `InMemoryDexClassLoader(buffers, parent)`, `copyNativeLibDirs(parent, inMemory)`, `patchLoadedApkClassLoader()`, then `nativeWipeShard()` each shard
- `patchLoadedApkClassLoader()`: patches `ActivityThread.mPackages → LoadedApk.mClassLoader` and `ContextImpl.mClassLoader`
- `copyNativeLibDirs()`: copies `nativeLibraryDirectories` + `nativeLibraryPathElements` from parent PathClassLoader into InMemoryDexClassLoader's DexPathList
- `loadViaFiles()`: writes shards as `shard-N.dex` to `app_dex/`, calls legacy `loadDex()` via dexElements reflection
- String literals obfuscated with `k(char...)` builder to avoid DEX string pool exposure

### utils/MyClassLoader.java
- Legacy per-API dexElements injection (API 14–26). Not used by current `DexProtector` flow (which uses `invokeMakeElements` directly). Dead code for API 27+ path.

### utils/FileUtils.java
- `deleteFloor()`, `delFolder()`, `mkdir()` — directory cleanup helpers
- `deleteFiles()` uses reflection to call `File.delete()` (obfuscation technique)
- `delete()` method is broken/dead (calls non-existent `File.delete(int)`)

### utils/Reflect.java
- `findField(instance, name)` — walks superclass chain
- `findMethod(instance, name, paramTypes)` — walks superclass chain
- `invokeMethod(className/class, obj, name, args, paramTypes)`
- `getFieldValue/setFieldValue/getFieldOjbect/setFieldOjbect`

### utils/CommonUtils.java
- `exit()` — reflective `System.exit(0)` (obfuscated)
- `encryptStrings(str, i)` — XOR-based string cipher with hardcoded char[] tables

---

## phantom/encrypt_blob.py
Location: `Ultra Dex2c Vmp/phantom/encrypt_blob.py`

- `BLOB_KEY = b"Ph4nt0mBl0bK3y!!"` — must match `DexCrypto.ASSET_KEY_MASK` XOR with phantom.vmp header
- Encrypt pipeline: `compress(XOR(compress(plaintext)))` → `.blob` file
- Decrypt (Java) pipeline: `InflaterInputStream` → ARX XOR → `InflaterOutputStream`
- Python ARX cipher: `_expand_key()` (27-word schedule), `_step()` (8-byte block), `arx_cipher()` (self-inverse XOR stream)
- Self-verifying: `verify_roundtrip()` confirms round-trip after encryption

---

## src/main/cpp/phantom_key.c
Location: `Ultra Dex2c Vmp/src/main/cpp/phantom_key.c` (1397 lines)

### Exports (two JNI symbols only, via version script)
- `Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard`
- `Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard`

### Security layers
- LAYER 1: `nativeWipeShard` — zeroes entire returned DEX byte[] in 64 KB chunks
- LAYER 2: `detect_frida_loop` — 5s background thread: threads, namedpipes, websocket, memdiskcompare, ptrace, eBPF, riru/zygisk, root
- LAYER 3: `g_block_rooted` — runtime flag from `salt[0] bit-7`; enables `detect_root()` + `detect_riru_zygisk()` in loop

### Constructor (`__attribute__((constructor))`)
- `detect_frida_init()`: `prctl(PR_SET_DUMPABLE, 0)`, parse proc/maps for ELF checksums, launch `detect_frida_loop` thread

### Frida detection methods
- `detect_ptrace()` — `/proc/self/status` TracerPid
- `detect_frida_threads()` — all tasks: comm file (JDWP/gum-js-loop/gmain) + per-task status TracerPid
- `detect_frida_websocket()` — port scan 127.0.0.1 for fixed Sec-WebSocket-Accept `tyZql/Y8dNFFyopTrHadWzvbvRs=`
- `detect_frida_namedpipe()` — `/proc/self/fd` scan for linjector named pipe
- `detect_frida_memdiskcompare()` — ELF section checksum memory vs disk
- `detect_ebpf_uprobe()` — `/sys/kernel/debug/tracing/uprobe_events` scan for `libart`/`dex_dump`
- `detect_riru_zygisk()` — maps scan + `dl_iterate_phdr` + known install paths
- `detect_root()` / `check_rooted()` — su binaries, SELinux permissive, CapEff, build.prop test-keys, Magisk mounts, hook dirs

### Kill switch
- `nuke_app()` — raw `tgkill(pid, tid, SIGKILL)` via inline syscall (arm64) or `syscall()` (arm32); uncatchable

### Syscall wrappers
- arm64: fully raw via inline asm (`svc #0`); arm32: `syscall()` wrapper
- Wrappers: `my_openat`, `my_read`, `my_write`, `my_lseek`, `my_close`, `my_nanosleep`, `my_readlinkat`, `my_mprotect`, `my_madvise`, `my_socket`, `my_connect`

### Crypto
- `sha256()` — self-contained, hashes package name inside native (never returns hash to Java)
- `arx_kdf(salt[16], pkg_hash[32], out[16])` — 8-round ARX mixing; byte-identical to Java `DexSeed.arx()`
- `arx_ctx_init(key[16])` — 27-word schedule + 2-word state
- `arx_advance_block()` — fully unrolled 27-step block advance
- `arx_xor(buf, len)` — streaming XOR keystream
- `inflate_alloc()` — zlib inflate with realloc growth loop

### nativeDecryptShard pipeline
1. Extract `salt[0] bit-7` → `g_block_rooted`, clear bit, optionally `check_rooted()`
2. SHA-256 package name → `pkg_hash`
3. `arx_kdf(salt, pkg_hash, key)`
4. Copy encrypted shard to native heap
5. Outer `inflate_alloc` (zlib)
6. `arx_xor` in-place
7. Inner `inflate_alloc` (zlib)
8. Return plaintext DEX; zero all key material on `cleanup` label

**Why:** Key is never returned to Java; zeroed on return via `goto cleanup` pattern.
**How to apply:** Any change to KDF or cipher must be mirrored in Java `DexCrypto.exfr/FxIjsF/nDnv` AND `encrypt_blob.py arx_cipher` to stay byte-identical.

---

## DexPacker toggle & Block-Rooted toggle (packer side)

### DexPacker toggle
- UI: `SettingsFragment.sw_dex_packer` → `dex2c_prefs / dex_packer_enabled` (default OFF)
- `ApkProtector.protectApk()` reads `dex_packer_enabled` after all dex2c/VMP work is done
- When ON: calls `new DexPacker(context).pack(outputApk, packedUnsigned, packWorkDir)` — encrypts stripped DEX shards and injects `ProxyApplication` stub loader
- Stacks on top of dex2c: dex2c removes bytecode → DexPacker encrypts the empty shells
- If sign is requested, re-signs the packed APK (DexPacker changes the ZIP, invalidating V1)

### Block-Rooted toggle
- UI: `SettingsFragment.sw_block_rooted` → `dex2c_mega_prefs / block_rooted_enabled` (default ON)
- Stored in a separate prefs file (`dex2c_mega_prefs`) shared with `ProtectViewModel`
- Auto-saves on toggle change (no Save button needed for this setting)

**Pack time** (`DexPacker.pack()`):
1. Reads `block_rooted_enabled` fresh from SharedPreferences
2. Generates random 16-byte salt (`DexSeed.randomSalt()`)
3. ON → `salt[0] |= 0x80`; OFF → `salt[0] &= 0x7F`
4. Strips flag for KDF: `saltForKdf[0] &= 0x7F` — derived key is identical either way
5. Writes raw salt (flag bit intact) to `assets/phantom/ph_salt`
6. Same two `.blob` files used for both ON and OFF — no separate builds

**Runtime** (`phantom_key.c` — `nativeDecryptShard()`):
1. Reads `(salt[0] & 0x80) != 0` → extracts flag
2. Strips bit before KDF: `salt[0] &= 0x7F`
3. Sets global `g_block_rooted`
4. If ON: immediately calls `check_rooted()` — SELinux permissive, su binaries, CapEff elevated, Magisk mounts, hook dirs, build.prop test-keys → any hit → `nuke_app()` (raw tgkill SIGKILL)
5. Background `detect_frida_loop` (5s) checks `g_block_rooted` before running `detect_root()` + `detect_riru_zygisk()` each cycle

**Why hidden in salt bit-7:** Java only sees an opaque 16-byte array. A Frida hook on the Java layer cannot read or patch the flag — it is already consumed in C before `nativeDecryptShard` returns.
