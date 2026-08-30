---
name: Android linker compatibility
description: Platform-compatibility rule for Phantom startup checks across Android API levels.
---

Phantom must not use linker-program-header versus `/proc/self/maps` layout comparison as a startup fail-closed gate. Android Bionic can expose valid auxiliary or vendor linker records that do not map cleanly to the process-map model, producing false crashes on otherwise valid devices.

**Why:** A protected app reached the Phantom pre-decrypt stage and was killed solely because a device reported “invalid linker ELF metadata”; the check was a detector false positive, not blob authentication failure.

**How to apply:** Keep platform-independent integrity, signer, TEE, and active-instrumentation checks separate. Treat linker-layout inspection as diagnostic-only, or omit it from the runtime gate. `InMemoryDexClassLoader` support begins at API 26 (Android 8.0).