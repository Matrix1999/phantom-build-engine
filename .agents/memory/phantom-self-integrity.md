---
name: Phantom self-integrity
description: How Phantom detects post-load executable code patching across its shipped ABIs.
---

Phantom self-integrity uses a per-ABI build-time digest of the executable ELF PT_LOAD segments, combined as a SHA-256 hash-of-hashes. Runtime hashing uses the same loaded segments and compares against a constant embedded in the Phantom binary. The stamp is stored outside executable code so it does not create a recursive hash dependency; the authenticated PHB3 envelope remains the pre-load protection.

**Why:** Hashing mutable data or relying on a single patchable Java comparison would create false positives or an easy bypass. Executable-segment hashing catches code-page changes while avoiding ordinary data/relocation state.

**How to apply:** Any change to Phantom executable code requires the ABI stamping/rebuild workflow before producing new blobs. This remains best-effort userspace protection and cannot defeat a privileged kernel that can hide modified pages.