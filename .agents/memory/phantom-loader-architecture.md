---
name: Phantom loader architecture
description: Durable architecture, cross-file contracts, and security caveats for the Phantom/bootstrap native loader and stub-loader.
---

The protection system is intentionally a two-stage loader:

1. The bootstrap library receives an authenticated outer envelope, verifies its header as associated data, decrypts XChaCha20-Poly1305 ciphertext, decompresses the ELF, and writes a temporary native library.
2. The loaded Phantom library validates and decrypts the protected DEX shards in native code, creates an in-memory class loader, and swaps the proxy Application for the real one.

**Why:** Treating the bootstrap and Phantom library as one encryption path causes key, asset, and JNI mismatches. They use distinct stages and key-derivation paths, with separate framing and validation.

The stable runtime contracts are:

- Bootstrap exports only the native blob-decryption entry point.
- Phantom exports the shard-loading and Application-swap JNI entry points; the legacy plaintext shard-return path is disabled.
- ABI-specific bootstrap/Phantom assets, obfuscated asset names, the VMP bundle framing, and JNI symbol names must remain synchronized.
- Workflow audits must run before symbol/VM-section stripping; post-strip artifacts are expected to hide those audit markers.

**Why:** The Java stub, native libraries, generated assets, and CI workflows are coupled even though they live in different directories.

The cryptographic material is embedded or reconstructable in shipped code and build tooling. XChaCha20-Poly1305 authenticates the outer envelope and the inner native processing wipes transient buffers, but this is anti-analysis/anti-dumping protection, not a device-bound confidential key store. The AES-CBC detection-string layer has no authentication and should not be treated as an integrity boundary.

**How to apply:** Never expose or log key material; do not describe these embedded keys as secrets. Preserve authenticated parsing, constant-time tag checks, buffer wiping, and “no plaintext return” behavior when modifying the pipeline.

Compatibility-sensitive areas include the reflective ActivityThread/LoadedApk patching, `InMemoryDexClassLoader`, ART mapping wiping, and the runtime API requirement for protected loading. The stub-loader module advertises a lower minimum API than the protected loader functionally supports, so Android-version behavior must be tested before changing compatibility declarations.

**Why:** These operations depend on hidden or version-sensitive Android internals and can fail at runtime even when the Gradle build succeeds.

The Phantom build workflow currently has a source-directory naming mismatch relative to the imported project directory, while the bootstrap workflow uses the imported directory name. Any CI repair must normalize those paths without changing the project structure.

**How to apply:** Check workflow paths against the actual imported directory before attempting a build; keep the pre-strip audits and generated asset installation steps intact.