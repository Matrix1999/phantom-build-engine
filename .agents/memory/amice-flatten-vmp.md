---
name: Amice flatten and VMP
description: Compatibility rule for combining Amice VM flattening with instruction-level virtualization in Phantom builds.
---

Keep VM flattening enabled globally, but annotate VM-critical functions with both `+vm_virtualize` and `-vm_flatten`.

**Why:** The Amice build used by Phantom can flatten a function before VM materialization even when the requested pass order lists virtualization first. Flattened IR may then be rejected as containing undef/poison values. Per-function exclusion preserves global flattening while allowing mandatory VMP bytecode generation.

**How to apply:** Use targeted `-vm_flatten` only on functions whose explicit VMP output is required. Smoke tests should confirm Amice logs actual bytecode generation and reject explicit skip messages; do not assume compilation alone or a guessed section-name pattern proves virtualization.