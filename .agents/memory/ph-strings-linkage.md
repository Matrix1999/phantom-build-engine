---
name: ph_strings extern-C linkage
description: Why ph_strings_register must use extern "C" in its definition inside ph_strings.cpp
---

## Rule
`ph_strings_register(JNIEnv* env)` in `ph_strings.cpp` (a .cpp file) MUST be declared `extern "C"`.

## Why
`jni_init.cpp` declares it as `extern "C" void ph_strings_register(JNIEnv* env)` (C linkage).
`ph_strings.cpp` is compiled as C++ — without `extern "C"` on the definition, the compiler emits
the C++-mangled symbol (e.g. `_Z22ph_strings_registerP7_JNIEnv`).
The linker cannot match the two and leaves `ph_strings_register` as an unresolved external in the .so.
At dlopen time this causes: `cannot locate symbol "ph_strings_register"`.

## How to apply
In `NativeStringGen.java`, ALL generated JNI function headers must use `extern "C"`:
```cpp
extern "C" JNIEXPORT void JNICALL Java_<ClassName>_phStrInject(JNIEnv* env, jclass clz) {
extern "C" void ph_strings_register(JNIEnv* env) {
```
Not just `JNIEXPORT void JNICALL ...` — JNIEXPORT only sets visibility, it does NOT disable C++ mangling.

## VMP vs DEX2C difference
VMP mode: RegisterNatives via NativeUtil.classesInit0() — function pointer, mangling irrelevant.
DEX2C mode: ART static Java_* symbol lookup — requires exact unmangled symbol name.
Missing extern "C" on phStrInject causes UnsatisfiedLinkError in DEX2C mode only.
