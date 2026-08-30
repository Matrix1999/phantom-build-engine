---
name: Guard signature and TEE gates
description: Security-gate architecture and execution order for the native guard integrity layer.
---

`guard.cpp` is a later-stage integrity layer, not the outer Phantom blob loader. The `blob authentication failed` exception from `DexCrypto.loadPhantomLib` occurs before `libphantom.so` is loaded, so changing the signer/TEE guard cannot repair that bootstrap envelope mismatch.

The guard has two independent evidence sources:

- The signer gate resolves the APK, scans its ZIP signing entries, extracts a certificate from the first supported PKCS#7/X.509 record, hashes the certificate DER, and compares it with a generated expected signer digest.
- The hardware gate generates or retrieves a Keystore P-256 key, creates a signer-bound proof, reads KeyMint/attestation evidence, checks the attestation extension and challenge, validates the certificate chain against pinned Google attestation roots, and enforces key continuity through a no-backup record or controlled legacy migration.

**Why:** Signer identity and hardware-backed key continuity are deliberately separate; neither source alone is allowed to authorize a supported device.

The final policy is fail-closed for supported hardware: signer verification must pass, the TEE evidence collector must complete all required facts with its mirrored bitmask/arithmetic seal, and the combined signer/TEE result must pass. TEE can be treated as unsupported for compatibility on devices/providers that cannot expose the required attestation, but a supported device with failed or incomplete evidence terminates.

**How to apply:** Preserve the execution order and completion flags when modifying the guard. Treat the signer digest comparison, certificate-chain checks, DER parsing, challenge equality, continuity record, and evidence seal as software checks around a hardware-backed private-key operation—not as proof that every check executes inside the TEE.

The hardware-backed boundary is limited to Keystore/KeyMint private-key generation, storage, and signing plus the attestation claim of security level. APK ZIP/PKCS#7 parsing, SHA-256 comparisons, Java X.509 verification, root pinning, package/signer binding, boot-state interpretation, continuity storage, and final policy reduction execute in software and remain observable to an instrumented process.

**Why:** This distinction is important for threat modeling: the design raises the cost of tampering but does not make embedded policy, keys, or verification logic confidential against a local runtime attacker.