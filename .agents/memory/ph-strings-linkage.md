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

## VMP vs DEX2C JNI_OnLoad file difference — CONFIRMED FIX
VMP mode generates `jni_init.cpp`; DEX2C mode generates `jni_onload.cpp`.
`patchJniInitForStrings` in ApkProtector must check BOTH filenames or it silently skips DEX2C.
When it skips: `ph_strings_register` is never called → RegisterNatives never fires → LLD --gc-sections
strips `Java_REVERSAL_1X_phStrInject` (no reference chain despite JNIEXPORT) → UnsatisfiedLinkError.
Fix (confirmed working): fall through from `jni_init.cpp` to `jni_onload.cpp` when the first is absent.
Both `patchJniInitForStrings` and NdkBuilder's `patchJniOnload` insert before "return JNI_VERSION_1_6;"
so ordering is: ph_strings_register → classloader capture → fonts_register_natives → return.

## VMP vs DEX2C symbol lookup
VMP mode: RegisterNatives via NativeUtil.classesInit0() — function pointer, mangling irrelevant.
DEX2C mode: relies on ph_strings_register → RegisterNatives in JNI_OnLoad as primary path;
static Java_* lookup is the fallback but LLD gc-sections can remove it if no reference exists.
