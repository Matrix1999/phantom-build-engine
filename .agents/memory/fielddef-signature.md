---
name: FieldDef.of() signature — vova7878/DexFile v1.6.0
description: Correct parameter order for FieldDef.of() in the vova7878 DexFile library
---

## Correct signature
```java
FieldDef.of(String name, TypeId type, int accessFlags, int hiddenApiFlags,
            EncodedValue initialValue, Iterable<Annotation> annotations)
```

## Why this matters
- `initialValue` comes BEFORE `annotations` — opposite of what you might expect.
- Passing them swapped gives: `NavigableSet<Annotation> cannot be converted to EncodedValue`.
- Omitting `hiddenApiFlags` gives: `NavigableSet<Annotation> cannot be converted to int`.
- Confirmed by reading the .class bytecode constant pool from DexFile-v1.6.0.jar directly.

## How to apply
To strip a field's initial value while preserving everything else:
```java
FieldDef.of(f.getName(), f.getType(), f.getAccessFlags(), f.getHiddenApiFlags(),
            null, f.getAnnotations())
```
