---
name: ART direct DEX lifetime
description: Compatibility constraint for native direct-buffer delivery into InMemoryDexClassLoader.
---

Native direct-buffer DEX storage cannot be wiped or unmapped immediately after `InMemoryDexClassLoader` construction because ART may resolve classes lazily afterward. Keep successful mappings read-only and non-dumpable for the loader lifetime; wipe and unmap failed or teardown mappings.

**Why:** Immediate cleanup can leave startup apparently successful but break later class resolution on Android ART versions that retain the direct buffer backing.

**How to apply:** Any future stronger cleanup must be gated by Android/runtime validation or an alternative payload architecture such as full native/VMP transformation, not enabled unconditionally in the loader.