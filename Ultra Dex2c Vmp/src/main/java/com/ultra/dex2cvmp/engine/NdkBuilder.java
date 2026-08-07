package com.ultra.dex2cvmp.engine;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Process;
import android.util.Log;

import com.ultra.dex2cvmp.engine.OllvmNdkManager;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * NdkBuilder — on-device compiler pipeline using termux-ndk r29.
 *
 * clang-21 is statically linked (no libLLVM.so / libxml2 dependency).
 *
 * Speed strategy: parallel compile (one clang -c process per file, N = CPU cores)
 * then a single link step — identical to `make -j$(nproc)`.
 * On an 8-core phone this is typically 5-7x faster than a single clang invocation.
 */
public class NdkBuilder {

    private static final String TAG = "NdkBuilder";

    private final Context context;
    private final CompilerManager cm;

    private File headersDir;
    private File vmSrcDir;   // extracted VMP runtime .cpp/.c source files
    private boolean initialized = false;
    private File resolvedClang;   // set once in setup(), reused in compile()

    public interface BuildCallback {
        void onProgress(String message);
        void onLog(String line);
    }

    public static class BuildResult {
        public boolean success;
        public File    soFile;
        public String  log;
        public String  error;
    }

    private static class ObjResult {
        boolean success;
        String  log;
        String  error;
        int     srcIdx = -1;
    }

    public NdkBuilder(Context context) {
        this.context = context.getApplicationContext();
        this.cm = new CompilerManager(context);
    }


    public boolean setup(BuildCallback cb) {
        // OLLVM NDK is the only NDK — verify it is installed before proceeding.
        if (!OllvmNdkManager.isInstalled()) {
            if (cb != null) cb.onProgress(
                "OLLVM NDK not found. Open Compiler Settings to download it first.");
            return false;
        }

        headersDir = new File(context.getFilesDir(), "compiler_headers");
        headersDir.mkdirs();

        try {
            Dex2cPythonBridge.extractJniHeaders(context, headersDir);
        } catch (IOException e) {
            if (cb != null) cb.onProgress("Header extraction failed: " + e.getMessage());
            return false;
        }

        // Extract VMP runtime headers (vm.h, Common.h, cutils/log.h, …) from
        // assets/vmp_headers/ into headersDir so that VMP-generated C files that
        // #include "vm.h" can be compiled on-device.
        try {
            extractAssetDir(context, "vmp_headers", headersDir);
        } catch (IOException e) {
            Log.w(TAG, "VMP header extraction failed (non-fatal): " + e.getMessage());
        }

        // Extract VMP VM runtime source files (Interp.cpp, DexCatch.cpp,
        // GlobalCache.cpp, Exception.cpp, InterpC-portable.cpp, JNIWrapper.c,
        // ConstantPool.c) from assets/vmp_src/ into headersDir.
        // These implement vmInterpret() + cacheInitial() etc. that the generated
        // classes_native_functions.c calls. Without them the linker cannot resolve
        // VM function symbols → unresolved symbol error at link time.
        vmSrcDir = new File(context.getFilesDir(), "vmp_src");
        vmSrcDir.mkdirs();
        try {
            extractAssetDir(context, "vmp_src", vmSrcDir);
        } catch (IOException e) {
            Log.w(TAG, "VMP source extraction failed (non-fatal): " + e.getMessage());
        }

        // Resolve clang once here — compile() reuses this same file,
        // avoiding a second getActiveClangBin() call that could return a
        // different (bundled-fallback) path if the OLLVM NDK probe changes.
        resolvedClang = cm.getActiveClangBin();
        if (resolvedClang == null) {
            if (cb != null) cb.onProgress(
                "OLLVM NDK clang binary not found. Try deleting and re-downloading the NDK.");
            Log.e(TAG, "setup failed — resolvedClang null");
            return false;
        }
        if (!resolvedClang.exists()) {
            if (cb != null) cb.onProgress(
                "Compiler binary not found at: " + resolvedClang.getAbsolutePath() +
                "\nOLLVM NDK may be incomplete — try deleting and re-downloading it.");
            return false;
        }
        resolvedClang.setExecutable(true, false);
        initialized = true;
        if (cb != null) cb.onProgress("Compiler ready → " + resolvedClang.getName() + " [OLLVM]");
        Log.i(TAG, "Compiler ready: " + resolvedClang + " [OLLVM NDK]");
        return true;
    }

    /** Compile for the default ABI (arm64-v8a). Kept for backward compatibility. */
    public BuildResult compile(File sourceDir, File outputSo, BuildCallback cb) {
        return compile(sourceDir, outputSo, "arm64-v8a", cb);
    }

    /**
     * Compile the transpiled C++ in sourceDir into a native .so for the given targetAbi.
     * Supported values: "arm64-v8a", "armeabi-v7a", "x86_64", "x86".
     */
    public BuildResult compile(File sourceDir, File outputSo, String targetAbi, BuildCallback cb) {
        BuildResult result = new BuildResult();
        if (!initialized) {
            result.error = "NdkBuilder not initialized — call setup() first.";
            return result;
        }
        // Use the clang resolved at setup() time — never re-resolve here.
        return compileWithClang(resolvedClang, sourceDir, outputSo, targetAbi, cb);
    }

    // ── Two-phase parallel build (same strategy as competitor's ndk-build -jN) ──
    //
    //  Phase 1 — parallel compile:  clang-21 -c file.cpp -o file.o   (all cores)
    //             + make-style incremental cache: skip .o if src is unchanged
    //  Phase 2 — single link:       clang-21 -shared *.o -o libultra-dex2cvmp.so
    //
    // The competitor uses ndk-build -j$(nproc) which uses make's timestamp cache.
    // We replicate that with our own mtime-based cache so unchanged files are
    // skipped on re-runs — this is what makes their builds feel "instant" the
    // second time.

    // ── Incremental cache: mtime fingerprint → skip unchanged objects ─────────
    //
    // We store a flat properties file:  <objDir>/build.cache
    //   key = src file path (relative to objDir)
    //   val = "<src_lastModified>:<flags_hash>:<obj_lastModified>"
    //
    // A file is considered UP-TO-DATE if all three match.

    private java.util.Properties loadBuildCache(File objDir) {
        java.util.Properties p = new java.util.Properties();
        File f = new File(objDir, "build.cache");
        if (f.exists()) {
            try (java.io.FileInputStream fis = new java.io.FileInputStream(f)) {
                p.load(fis);
            } catch (IOException ignored) {}
        }
        return p;
    }

    private void saveBuildCache(File objDir, java.util.Properties cache) {
        try (java.io.FileOutputStream fos =
                 new java.io.FileOutputStream(new File(objDir, "build.cache"))) {
            cache.store(fos, null);
        } catch (IOException ignored) {}
    }

    private static int flagsHash(List<String> flags) {
        // Simple stable hash of the flag list (excluding per-file -o and source args)
        int h = 1;
        for (String s : flags) h = h * 31 + s.hashCode();
        return h;
    }

    private static boolean isUpToDate(java.util.Properties cache,
                                      String key, File src, File obj, int fh) {
        String val = cache.getProperty(key);
        if (val == null || !obj.exists()) return false;
        String expected = src.lastModified() + ":" + fh + ":" + obj.lastModified();
        return expected.equals(val);
    }

    private static void updateCache(java.util.Properties cache,
                                    String key, File src, File obj, int fh) {
        cache.setProperty(key, src.lastModified() + ":" + fh + ":" + obj.lastModified());
    }

    // ── guard resolution — libcipher.so via --whole-archive ───────────────
    //
    // guard ships as a prebuilt OLLVM-compiled shared library (libcipher.so)
    // built once offline by .github/workflows/build-guard.yml and committed
    // to jniLibs/arm64-v8a/ and jniLibs/armeabi-v7a/.
    //
    // At link time, NdkBuilder absorbs libcipher.so into the target .so using
    // -Wl,--whole-archive so the protected APK has NO runtime dependency on a
    // separate libcipher.so — it is fully self-contained.
    //
    // libcipher_arm64.a is compiled WITH -DD2C_HAS_JNILOAD so guard.cpp's own
    // JNI_OnLoad is excluded. The transpiler-generated jni_onload.cpp (or the
    // injected stub) owns JNI_OnLoad and calls fonts_register_natives +
    // fonts_apply_metrics from guard. Without this flag, --whole-archive would
    // pull in guard's JNI_OnLoad and clash with jni_onload.cpp → duplicate symbol.
    // When the transpiler DID generate jni_onload.cpp, patchJniOnload() injects
    // the fonts_apply_metrics() call there as before.
    // When it did NOT, writeGuardJniStub() generates a tiny inline stub that
    // provides JNI_OnLoad and calls fonts_register_natives + fonts_apply_metrics.
    //
    // getGuardSoFromNativeLibs() finds libcipher.so in the app's own native
    // library directory (installed by Android from jniLibs at install time).

    // ── Runtime file verification ─────────────────────────────────────────────

    /**
     * Before linking, verify that the required compiler-rt runtime files exist
     * inside the OLLVM NDK. Logs every file found/missing so the user sees a
     * clear report instead of a cryptic linker error.
     *
     * Required files (flat in lib/clang/<ver>/lib/linux/):
     *   libclang_rt.builtins-<abi>-android.a   — low-level builtins (divsi3, etc.)
     *   lib/linux/<abi-dir>/libunwind.a         — C++ stack unwinding
     *
     * @throws RuntimeException if any critical file is absent.
     */
    private static void verifyRuntimeFiles(File clangBin, String targetAbi,
                                            BuildCallback cb) {
        // Locate lib/clang/<version>/ relative to the clang binary
        // clangBin = <ndk>/toolchains/llvm/prebuilt/linux-arm64/bin/clang-19
        File binDir      = clangBin.getParentFile();                   // bin/
        File prebuiltDir = binDir.getParentFile();                     // linux-arm64/
        File libClang    = new File(prebuiltDir, "lib/clang");

        String clangVer = null;
        if (libClang.isDirectory()) {
            String[] vers = libClang.list();
            if (vers != null && vers.length > 0) clangVer = vers[0];
        }

        StringBuilder report = new StringBuilder();
        report.append("\n── NDK runtime scan (").append(targetAbi).append(") ──\n");

        boolean allOk = true;

        // 1. libclang_rt.builtins-<abi>-android.a
        String builtinsName = "libclang_rt.builtins-" + abiToRtName(targetAbi) + "-android.a";
        File builtinsFile = clangVer != null
            ? new File(libClang, clangVer + "/lib/linux/" + builtinsName)
            : null;
        if (builtinsFile != null && builtinsFile.exists()) {
            report.append("  ✅ ").append(builtinsName)
                  .append("  (").append(builtinsFile.length() / 1024).append(" KB)\n");
        } else {
            report.append("  ❌ MISSING: ").append(builtinsName).append("\n");
            allOk = false;
        }

        // 2. libunwind.a  (in ABI subdir under lib/linux/)
        String unwindSubdir = abiToUnwindDir(targetAbi);
        File unwindFile = clangVer != null
            ? new File(libClang, clangVer + "/lib/linux/" + unwindSubdir + "/libunwind.a")
            : null;
        if (unwindFile != null && unwindFile.exists()) {
            report.append("  ✅ lib/linux/").append(unwindSubdir).append("/libunwind.a")
                  .append("  (").append(unwindFile.length() / 1024).append(" KB)\n");
        } else {
            report.append("  ❌ MISSING: lib/linux/").append(unwindSubdir).append("/libunwind.a\n");
            allOk = false;
        }

        // 3. libgcc.a — not present in NDK r28+ (compiler-rt replaced it), just note it
        report.append("  ℹ️  libgcc.a — not needed (NDK r28 uses compiler-rt)\n");

        report.append(allOk ? "  ✅ All runtime files present — safe to link\n"
                             : "  ❌ Missing runtime files — link will fail\n");
        report.append("───────────────────────────────────────\n");

        android.util.Log.d("UltraDex2CVMP", report.toString());
        if (cb != null) cb.onProgress(report.toString());

        if (!allOk) {
            throw new RuntimeException(
                "NDK runtime files missing for " + targetAbi + ".\n" + report);
        }
    }

    /** Maps Android ABI string → compiler-rt library name suffix. */
    private static String abiToRtName(String abi) {
        switch (abi) {
            case "armeabi-v7a": return "arm";
            case "x86":         return "i686";
            case "x86_64":      return "x86_64";
            default:            return "aarch64";   // arm64-v8a
        }
    }

    /** Maps Android ABI string → libunwind subdir under lib/linux/. */
    private static String abiToUnwindDir(String abi) {
        switch (abi) {
            case "armeabi-v7a": return "arm";
            case "x86":         return "i386";
            case "x86_64":      return "x86_64";
            default:            return "aarch64";   // arm64-v8a
        }
    }

    // ── ABI helpers ───────────────────────────────────────────────────────────

    /** Clang target triple for the given Android ABI. */
    private static String abiToTriple(String abi) {
        switch (abi) {
            case "armeabi-v7a": return "armv7a-linux-androideabi21";
            case "x86_64":      return "x86_64-linux-android21";
            case "x86":         return "i686-linux-android21";
            default:            return "aarch64-linux-android26";   // arm64-v8a
        }
    }

    /** Sysroot lib directory name for the given ABI (under sysroot/usr/lib/). */
    private static String abiToSysrootLibDir(String abi) {
        switch (abi) {
            case "armeabi-v7a": return "arm-linux-androideabi";
            case "x86_64":      return "x86_64-linux-android";
            case "x86":         return "i686-linux-android";
            default:            return "aarch64-linux-android";
        }
    }

    /** Minimum-API sub-folder name inside the sysroot lib dir. */
    private static String abiToApiDir(String abi) {
        return "arm64-v8a".equals(abi) ? "26" : "21";
    }

    /** Guard static archive asset filename for the given ABI. */
    private static String abiToGuardAsset(String abi) {
        switch (abi) {
            case "armeabi-v7a": return "libcipher_armeabi-v7a.a";
            case "x86_64":      return "libcipher_x86_64.a";
            case "x86":         return "libcipher_x86.a";
            default:            return "libcipher_arm64.a";
        }
    }

    /** Returns true if this ABI requires -Wl,-z,max-page-size=16384 (Android 15+). */
    private static boolean abiNeeds16kPage(String abi) {
        return "arm64-v8a".equals(abi) || "x86_64".equals(abi);
    }

    /**
     * Extracts the guard static archive for the given ABI from assets into
     * the app's files directory and returns the extracted File.
     * Returns null if the asset is absent (caller aborts with a clear error).
     *
     * Each ABI has its own archive (libcipher_arm64.a, libcipher_armeabi-v7a.a,
     * libcipher_x86_64.a, libcipher_x86.a) produced by build-libcipher.yml and
     * committed to assets/. Linking via -Wl,--whole-archive absorbs all guard
     * code into the output .so with no DT_NEEDED entry.
     */
    private File getGuardAFromAssets(String targetAbi, BuildCallback cb) {
        String assetName = abiToGuardAsset(targetAbi);
        File dest = new File(context.getFilesDir(), assetName);
        try {
            extractAsset(assetName, dest, true); // always refresh from asset
            if (dest.exists() && dest.length() > 0) {
                Log.i(TAG, assetName + " extracted → " + dest.getAbsolutePath());
                if (cb != null) cb.onProgress("guard — " + assetName + " (static, embedded)");
                return dest;
            }
        } catch (IOException e) {
            Log.w(TAG, assetName + " not found in assets: " + e.getMessage());
        }
        return null;
    }

    /**
     * Writes a minimal guard_jni_stub.cpp into sourceDir that provides
     * JNI_OnLoad when the transpiler did NOT generate jni_onload.cpp.
     * Calls fonts_register_natives() + fonts_apply_metrics() — the same
     * two entry-points guard.cpp's own JNI_OnLoad would call.
     */
    private File writeGuardJniStub(File dir) {
        File stub = new File(dir, "fonts_jni_stub.cpp");
        try (java.io.FileWriter fw = new java.io.FileWriter(stub)) {
            fw.write(
                "#include <jni.h>\n"
                + "extern \"C\" void fonts_register_natives(JNIEnv*);\n"
                + "extern \"C\" void fonts_apply_metrics(JNIEnv*, jobject);\n"
                + "JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {\n"
                + "    JNIEnv* env = nullptr;\n"
                + "    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return -1;\n"
                + "    fonts_register_natives(env);\n"
                + "    fonts_apply_metrics(env, nullptr);\n"
                + "    return JNI_VERSION_1_6;\n"
                + "}\n"
            );
            Log.i(TAG, "guard_jni_stub.cpp written → " + stub.getAbsolutePath());
            return stub;
        } catch (IOException e) {
            Log.w(TAG, "writeGuardJniStub failed: " + e.getMessage());
            return null;
        }
    }

    private BuildResult compileWithClang(File clangBin, File sourceDir, File outputSo,
                                          String targetAbi, BuildCallback cb) {
        BuildResult result = new BuildResult();
        try {
            // Boost our own thread priority so the OS gives us more CPU slices
            Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO);

            // ── Collect source files ──────────────────────────────────────────
            List<File> generatedFiles = new ArrayList<>();
            File[] files = sourceDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    String n = f.getName();
                    if ((n.endsWith(".cpp") || n.endsWith(".c"))
                            && !n.equals("guard.cpp"))   // guard.cpp added explicitly below
                        generatedFiles.add(f);
                }
            }
            if (generatedFiles.isEmpty()) {
                result.error = "No source files found in " + sourceDir;
                return result;
            }

            File d2cImpl  = new File(headersDir, "Dex2C_impl.cpp");
            File wkcImpl  = new File(headersDir, "well_known_classes.cpp");

            // All files to compile (runtime files first — must also be first in link)
            // NOTE: guard is NOT added here — it ships as a prebuilt libcipher.a
            // and is absorbed at link time via --whole-archive (see link step below).
            List<File> allSrc = new ArrayList<>();
            if (d2cImpl.exists())  allSrc.add(d2cImpl);
            if (wkcImpl.exists())  allSrc.add(wkcImpl);
            allSrc.addAll(generatedFiles);

            File sysrootDir  = cm.getActiveSysrootDir();
            File sysInclude  = new File(cm.getActiveSysrootDir(), "usr/include");
            File sysrootLib   = new File(sysrootDir, "usr/lib/" + abiToSysrootLibDir(targetAbi));
            File sysrootLib26 = new File(sysrootLib, abiToApiDir(targetAbi));  // name kept for compat

            // ── Common compile flags (used for every -c invocation) ───────────
            List<String> compileFlags = new ArrayList<>(Arrays.asList(
                clangBin.getAbsolutePath(),
                "--target=" + abiToTriple(targetAbi),
                "--sysroot=" + sysrootDir.getAbsolutePath(),
                "-c",              // compile only — no link
                "-fPIC",
                // NOTE: -std flag is NOT here — it is added per-file below based on
                // extension: -std=c++17 for .cpp, -std=c11 for .c.  Passing -std=c++17
                // to clang for a .c source is a hard error ("invalid argument … not
                // allowed with 'C'") and aborts the entire build.
                "-O2",             // -O2 required: fully evaluates AY_OBFUSCATE constexpr so
                                   // XOR-encrypted strings never appear as plaintext in .rodata
                "-g0",             // no DWARF debug info — prevents source/variable name leaks
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-pipe",           // avoid tmp-file I/O between cc1 → assembler
                "-fexceptions",
                "-frtti",
                "-fvisibility=hidden",
                "-ffunction-sections",
                "-fdata-sections",
                "-I" + headersDir.getAbsolutePath()
            ));
            if (sysInclude.exists()) compileFlags.add("-I" + sysInclude.getAbsolutePath());
            compileFlags.add("-D__ANDROID__");
            compileFlags.add("-DANDROID");

            // Detect which file owns JNI_OnLoad:
            //   dex2c mode → transpiler generates jni_onload.cpp (patch + -DD2C_HAS_JNILOAD)
            //   VMP mode   → GlobalDexConfig generates jni_init.cpp which already contains
            //                the full guard bootstrap + classloader capture — no patch needed,
            //                just set -DD2C_HAS_JNILOAD so Dex2C_impl.cpp + fonts_jni_stub.cpp
            //                do NOT emit their own JNI_OnLoad (duplicate symbol otherwise).
            boolean hasJniOnload = false;
            File jniOnloadFile = null;
            boolean isVmpJniInit = false;
            for (File f : generatedFiles) {
                if ("jni_onload.cpp".equals(f.getName())) {
                    hasJniOnload = true;
                    jniOnloadFile = f;
                    break;
                }
                if ("jni_init.cpp".equals(f.getName())) {
                    hasJniOnload = true;
                    isVmpJniInit = true;
                    // jni_init.cpp already has fonts_register_natives + classloader capture
                    // baked in by GlobalDexConfig — no patchJniOnload() call needed.
                }
            }
            if (hasJniOnload) {
                compileFlags.add("-DD2C_HAS_JNILOAD");
                if (!isVmpJniInit) patchJniOnload(jniOnloadFile); // dex2c path only
            }

            // VMP mode: copy the per-run DexOpcodes.h (generated by DexTranspiler from the
            // RandomInstructionRewriter's opcode map) into headersDir, overriding the static
            // vmp_headers/DexOpcodes.h that was extracted at setup() time.
            //
            // Without this step the VM runtime (InterpC-portable.cpp) is compiled with the
            // standard Dalvik opcode ordering but the protected bytecode uses the randomized
            // ordering → every opcode dispatches to the wrong handler in vmInterpret → SIGSEGV.
            if (isVmpJniInit) {
                File perRunOpcodes = new File(sourceDir, "DexOpcodes.h");
                if (perRunOpcodes.exists()) {
                    File destOpcodes = new File(headersDir, "DexOpcodes.h");
                    try {
                        java.nio.file.Files.copy(perRunOpcodes.toPath(), destOpcodes.toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        Log.i(TAG, "Per-run DexOpcodes.h installed → " + destOpcodes);
                        if (cb != null) cb.onProgress("VMP: installed per-run DexOpcodes.h");
                    } catch (IOException e) {
                        Log.e(TAG, "Failed to copy per-run DexOpcodes.h", e);
                        if (cb != null) cb.onProgress(
                            "Warning: could not install per-run DexOpcodes.h: " + e.getMessage());
                    }
                } else {
                    Log.w(TAG, "Per-run DexOpcodes.h not found in sourceDir — "
                        + "VMP bytecode opcode map may not match compiled interpreter");
                    if (cb != null) cb.onProgress(
                        "Warning: DexOpcodes.h missing from source dir; opcode map may mismatch");
                }
            }

            // VMP mode: inject VM runtime source files into allSrc BEFORE generatedFiles.
            // isVmpJniInit is now known — safe to use here.
            // Interp.cpp, DexCatch.cpp, GlobalCache.cpp, Exception.cpp,
            // InterpC-portable.cpp, JNIWrapper.c, ConstantPool.c implement
            // vmInterpret() + cacheInitial() called by classes_native_functions.c.
            // Track which files are VM runtime sources so we can apply -DNDEBUG only to them.
            final java.util.Set<File> vmSrcSet = new java.util.HashSet<>();
            if (isVmpJniInit && vmSrcDir != null && vmSrcDir.exists()) {
                File[] vmSrcs = vmSrcDir.listFiles(f -> {
                    String n = f.getName();
                    return n.endsWith(".c") || n.endsWith(".cpp");
                });
                if (vmSrcs != null) {
                    java.util.Arrays.sort(vmSrcs); // deterministic order
                    // Insert before generatedFiles (already in allSrc tail)
                    int insertAt = allSrc.size() - generatedFiles.size();
                    for (int vi = 0; vi < vmSrcs.length; vi++) {
                        allSrc.add(insertAt + vi, vmSrcs[vi]);
                        vmSrcSet.add(vmSrcs[vi]);
                    }
                }
            }

            // ── LAYER 3: OLLVM obfuscation passes ────────────────────────────
            //
            // Controlled from the OLLVM tab in the app.
            //
            // Master toggle OFF → plain compile with OLLVM clang, no -mllvm flags (fast).
            // Master toggle ON  → apply the selected intensity level:
            //
            //   Level 0 — Ultimate Level : 8 passes (FLA+BCF+SUB+SOBF+SPLIT+IBR+ICALL+IGV)
            //   Level 1 — Advanced Level : 6 passes (FLA+BCF+SUB+SOBF+SPLIT+IBR)
            //   Level 2 — Turbo         : 5 passes (FLA+BCF+SUB+SOBF+SPLIT)
            //   Level 3 — Ultra Level    : 3 passes (FLA+BCF+SUB)
            //   Level 4 — Bull Level     : 2 passes (FLA+SUB)
            //
            // Pass reference:
            //   -fla        Control-flow flattening (opaque dispatcher loop)
            //   -bcf        Bogus control flow (always-false fake branches)
            //   -sub        Instruction substitution (a+b → bitwise multi-op)
            //   -sobf       String encryption — URLs, class names, all literals hidden
            //   -split      Basic-block splitting (inflates CFG)
            //   -ibr        Indirect branch
            //   -icall      Indirect call (call via register)
            //   -igv        Indirect global variable
            //
            // All levels use all 8 passes (FLA+BCF+SUB+SOBF+SPLIT+IBR+ICALL+IGV).
            // The intensity parameters (bcf_prob, bcf_loop, sub_loop, split_num) are
            // dialled up or down to control how aggressive each pass is.
            if (cm.isOllvmNdkEnabled()) {
                int level = cm.getOllvmLevel();

                if (level == 9) {
                    // ── CUSTOM mode: user toggled individual passes ───────────
                    // Intensity params fixed at Advanced defaults for custom builds.
                    boolean hasFla   = cm.isCustomPassEnabled("ollvm_pass_fla");
                    boolean hasBcf   = cm.isCustomPassEnabled("ollvm_pass_bcf");
                    boolean hasSub   = cm.isCustomPassEnabled("ollvm_pass_sub");
                    boolean hasSobf  = cm.isCustomPassEnabled("ollvm_pass_sobf");
                    boolean hasSplit = cm.isCustomPassEnabled("ollvm_pass_split");
                    boolean hasIbr   = cm.isCustomPassEnabled("ollvm_pass_ibr");
                    boolean hasIcall = cm.isCustomPassEnabled("ollvm_pass_icall");
                    boolean hasIgv   = cm.isCustomPassEnabled("ollvm_pass_igv");

                    StringBuilder active = new StringBuilder();

                    if (hasFla) {
                        compileFlags.add("-mllvm"); compileFlags.add("-fla");
                        active.append("FLA ");
                    }
                    if (hasBcf) {
                        compileFlags.add("-mllvm"); compileFlags.add("-bcf");
                        compileFlags.add("-mllvm"); compileFlags.add("-bcf_prob=55");
                        compileFlags.add("-mllvm"); compileFlags.add("-bcf_loop=2");
                        active.append("BCF ");
                    }
                    if (hasSub) {
                        compileFlags.add("-mllvm"); compileFlags.add("-sub");
                        compileFlags.add("-mllvm"); compileFlags.add("-sub_loop=1");
                        active.append("SUB ");
                    }
                    if (hasSobf) {
                        compileFlags.add("-mllvm"); compileFlags.add("-sobf");
                        active.append("SOBF ");
                    }
                    if (hasSplit) {
                        compileFlags.add("-mllvm"); compileFlags.add("-split");
                        compileFlags.add("-mllvm"); compileFlags.add("-split_num=2");
                        active.append("SPLIT ");
                    }
                    if (hasIbr) {
                        compileFlags.add("-mllvm"); compileFlags.add("-ibr");
                        active.append("IBR ");
                    }
                    if (hasIcall) {
                        compileFlags.add("-mllvm"); compileFlags.add("-icall");
                        active.append("ICALL ");
                    }
                    if (hasIgv) {
                        compileFlags.add("-mllvm"); compileFlags.add("-igv");
                        active.append("IGV ");
                    }

                    int activeCount = (hasFla?1:0)+(hasBcf?1:0)+(hasSub?1:0)+(hasSobf?1:0)
                                   + (hasSplit?1:0)+(hasIbr?1:0)+(hasIcall?1:0)+(hasIgv?1:0);
                    String passes = active.toString().trim();
                    if (passes.isEmpty()) passes = "none — plain compile";
                    String countLabel = activeCount + " of 8 pass" + (activeCount == 1 ? "" : "es") + " active";
                    Log.i(TAG, "OLLVM — Custom Build: " + countLabel + " [" + passes + "]");
                    if (cb != null) cb.onProgress("⚡ Custom Build — " + countLabel + ": " + passes);
                    if (cb != null) cb.onProgress(
                            "  ⚙ Compile time depends on which passes you enabled.");

                } else {
                    // ── Preset level (0-8): all 8 passes, intensity tuned ─────
                    // Phantom (level 0) = the original upstream defaults from DreamSoule/ollvm17.
                    // Levels below are progressively lighter.
                    int bcfProb, bcfLoop, subLoop, splitNum;
                    String levelName;
                    switch (level) {
                        case 0:  bcfProb=70; bcfLoop=2; subLoop=1; splitNum=3; levelName="Phantom Level";  break;
                        case 1:  bcfProb=65; bcfLoop=2; subLoop=1; splitNum=3; levelName="Ultimate Level"; break;
                        case 2:  bcfProb=60; bcfLoop=2; subLoop=1; splitNum=3; levelName="Supreme Level";  break;
                        case 3:  bcfProb=55; bcfLoop=2; subLoop=1; splitNum=2; levelName="Advanced Level"; break;
                        case 4:  bcfProb=50; bcfLoop=2; subLoop=1; splitNum=2; levelName="Turbo Level";    break;
                        case 5:  bcfProb=40; bcfLoop=1; subLoop=1; splitNum=2; levelName="Ultra Level";    break;
                        case 6:  bcfProb=30; bcfLoop=1; subLoop=1; splitNum=1; levelName="Prime Level";    break;
                        case 7:  bcfProb=20; bcfLoop=1; subLoop=1; splitNum=1; levelName="Nova Level";     break;
                        default: bcfProb=10; bcfLoop=1; subLoop=1; splitNum=1; levelName="Lite Level";     break; // case 8
                    }

                    // All 8 passes, intensity tuned per level
                    compileFlags.add("-mllvm"); compileFlags.add("-fla");
                    compileFlags.add("-mllvm"); compileFlags.add("-bcf");
                    compileFlags.add("-mllvm"); compileFlags.add("-bcf_prob=" + bcfProb);
                    compileFlags.add("-mllvm"); compileFlags.add("-bcf_loop=" + bcfLoop);
                    compileFlags.add("-mllvm"); compileFlags.add("-sub");
                    compileFlags.add("-mllvm"); compileFlags.add("-sub_loop=" + subLoop);
                    compileFlags.add("-mllvm"); compileFlags.add("-sobf");
                    compileFlags.add("-mllvm"); compileFlags.add("-split");
                    compileFlags.add("-mllvm"); compileFlags.add("-split_num=" + splitNum);
                    compileFlags.add("-mllvm"); compileFlags.add("-ibr");
                    compileFlags.add("-mllvm"); compileFlags.add("-icall");
                    compileFlags.add("-mllvm"); compileFlags.add("-igv");

                    Log.i(TAG, "OLLVM — " + levelName + ": all 8 passes, bcf_prob=" + bcfProb
                            + " bcf_loop=" + bcfLoop + " sub_loop=" + subLoop + " split_num=" + splitNum);
                    if (cb != null) cb.onProgress(
                            "⚡ " + levelName + " — all 8 passes active"
                            + " (bcf_prob=" + bcfProb + ", split_num=" + splitNum + ")");
                    if (cb != null) cb.onProgress(
                            "  FLA · BCF · SUB · SOBF · SPLIT · IBR · ICALL · IGV\n"
                            + "  ⚙ Compile time will be longer than usual — this is expected.");
                }
            } else {
                // Master toggle OFF — plain compile with OLLVM clang, no IR passes
                Log.i(TAG, "OLLVM obfuscation OFF — plain fast compile");
            }

            // ── guard — extract the ABI-specific guard archive from assets ────
            // Each ABI has its own prebuilt static archive in assets/:
            //   libcipher_arm64.a, libcipher_armeabi-v7a.a, libcipher_x86_64.a, libcipher_x86.a
            // Produced by build-libcipher.yml and committed to assets/.
            // --whole-archive absorbs all guard code into the output .so with
            // no DT_NEEDED entry — no post-link removal step required.
            File guardA = getGuardAFromAssets(targetAbi, cb);
            if (guardA == null) {
                String assetName = abiToGuardAsset(targetAbi);
                result.error = "Guard component unavailable: " + assetName + " not found in "
                    + "assets. Run build-libcipher.yml, copy " + assetName + " to "
                    + "src/main/assets/" + assetName + ", and rebuild.";
                return result;
            }

            // When the transpiler did NOT generate jni_onload.cpp there is no
            // JNI_OnLoad to bootstrap the guard. Inject a minimal inline stub
            // that provides JNI_OnLoad and calls fonts_register_natives +
            // fonts_apply_metrics (libcipher.so has no JNI_OnLoad of its own
            // — it was compiled without -DD2C_HAS_JNILOAD).
            if (!hasJniOnload) {
                File stub = writeGuardJniStub(sourceDir);
                if (stub != null) allSrc.add(stub);
            }

            // ── Phase 1: parallel compile → .o  (with make-style mtime cache) ─
            // Worker count is capped by BOTH CPU cores AND available system RAM.
            // Each clang -c process peaks at ~180 MB (LLVM front-end + IR + codegen).
            // On a flagship (8-core / 8 GB) we use all 8 cores; on a budget device
            // (4-core / 500 MB free) we safely cap at 2 so we don't OOM-kill.
            int cpuCores = Math.max(1, Runtime.getRuntime().availableProcessors());
            int ramCores = cpuCores;   // safe default if ActivityManager is unavailable
            try {
                ActivityManager am = (ActivityManager)
                        context.getSystemService(Context.ACTIVITY_SERVICE);
                if (am != null) {
                    ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
                    am.getMemoryInfo(mi);
                    long availMb      = mi.availMem  / (1024L * 1024L);
                    long headroomMb   = 300L;   // always leave 300 MB for OS + JVM
                    long mbPerClang   = 200L;   // conservative peak per clang process
                    long usable       = Math.max(0L, availMb - headroomMb);
                    ramCores          = (int) Math.max(1L, usable / mbPerClang);
                    Log.i(TAG, "RAM-aware workers: availMem=" + availMb + " MB"
                            + " → ramCores=" + ramCores + " cpuCores=" + cpuCores);
                }
            } catch (Exception e) {
                Log.w(TAG, "Could not query MemoryInfo, using cpuCores: " + e.getMessage());
            }
            int cores = Math.max(1, Math.min(cpuCores, ramCores));
            // ABI-specific obj dir — prevents arm64 and armeabi-v7a parallel builds
            // from overwriting each other's .o files when both compile simultaneously.
            File objDir = new File(outputSo.getParentFile(), "obj_" + targetAbi);
            objDir.mkdirs();

            // Map each source file to its .o counterpart (preserves order)
            List<File> objFiles = new ArrayList<>(allSrc.size());
            for (int i = 0; i < allSrc.size(); i++) {
                String base = allSrc.get(i).getName().replaceAll("\\.(cpp|c)$", "");
                objFiles.add(new File(objDir, i + "_" + base + ".o"));
            }

            // Load incremental cache (mtime-based, same principle as make's .d deps)
            java.util.Properties buildCache = loadBuildCache(objDir);
            int flagsH = flagsHash(compileFlags);

            // Identify which files actually need recompilation
            List<Integer> toCompile = new ArrayList<>();
            int cacheHits = 0;
            for (int i = 0; i < allSrc.size(); i++) {
                String key = String.valueOf(i) + "_" + allSrc.get(i).getName();
                if (isUpToDate(buildCache, key, allSrc.get(i), objFiles.get(i), flagsH)) {
                    cacheHits++;
                } else {
                    toCompile.add(i);
                }
            }

            if (cb != null) cb.onProgress(
                "Compiling " + toCompile.size() + "/" + allSrc.size()
                + " file(s) on " + cores + "/" + cpuCores + " core(s)"
                + (cacheHits > 0 ? " (" + cacheHits + " cached)" : "") + "…"
                + (cm.isOllvmNdkEnabled()
                    ? " (OLLVM obfuscation ON — each file takes 3–10× longer, please wait…)"
                    : ""));

            ExecutorService pool = Executors.newFixedThreadPool(cores);
            List<Future<ObjResult>> futures = new ArrayList<>(toCompile.size());

            final AtomicInteger done    = new AtomicInteger(0);
            final int           total   = toCompile.size();
            // Shared cache ref is accessed only from futures.get() after pool shuts down
            final java.util.Properties sharedCache = buildCache;

            for (int idx : toCompile) {
                final File src      = allSrc.get(idx);
                final File obj      = objFiles.get(idx);
                final int  srcIdx   = idx;
                final List<String> flags = compileFlags;
                final BuildCallback fcb  = cb;

                futures.add(pool.submit(() -> {
                    Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO);

                    List<String> cmd = new ArrayList<>(flags);
                    // VM runtime sources are compiled with -DNDEBUG to suppress assert()
                    // and conditional debug output inside the interpreter (matches NMMP release build).
                    if (vmSrcSet.contains(src)) {
                        cmd.add("-DNDEBUG");
                    }
                    if (src.getName().endsWith(".cpp")) {
                        cmd.add("-std=c++17");
                    } else {
                        cmd.add("-std=c11");
                    }
                    cmd.add("-o"); cmd.add(obj.getAbsolutePath());
                    cmd.add(src.getAbsolutePath());

                    ObjResult r = runCompileProcess(cmd);

                    // OOM fallback: if clang ran out of memory (-split/-icall/-igv expand
                    // the CFG dramatically on files with many functions), retry the same
                    // file with only the lightweight passes (-fla -bcf -sub -sobf).
                    if (!r.success && r.log != null &&
                            (r.log.contains("out of memory") || r.log.contains("LLVM ERROR"))) {
                        if (fcb != null) fcb.onProgress(
                            "⚠ OOM on " + src.getName()
                            + " — retrying with lightweight passes (no split/icall/igv)…");
                        List<String> fallbackCmd = stripHeavyPasses(cmd);
                        r = runCompileProcess(fallbackCmd);
                        if (r.success) {
                            if (fcb != null) fcb.onProgress(
                                "✓ Lightweight fallback succeeded for " + src.getName());
                        }
                    }

                    int n = done.incrementAndGet();
                    if (fcb != null) fcb.onProgress(
                        "Compiled " + n + "/" + total + " — " + src.getName());
                    r.srcIdx = srcIdx;
                    return r;
                }));
            }

            pool.shutdown();
            boolean finished = pool.awaitTermination(10, TimeUnit.HOURS);
            if (!finished) {
                result.error = "Compile timed out after 10 hours";
                return result;
            }

            // Collect results; update incremental cache; abort on first error
            StringBuilder fullLog = new StringBuilder();
            for (int i = 0; i < futures.size(); i++) {
                ObjResult or = futures.get(i).get();
                if (or.log != null) fullLog.append(or.log);
                if (!or.success) {
                    result.error = "Compile failed: "
                        + (or.srcIdx >= 0 ? allSrc.get(or.srcIdx).getName()
                                          : "file#" + i)
                        + "\n" + or.error + "\n" + or.log;
                    result.log = fullLog.toString();
                    return result;
                }
                // Mark this .o as up-to-date so next run skips it (make-style cache)
                if (or.srcIdx >= 0) {
                    String key = or.srcIdx + "_" + allSrc.get(or.srcIdx).getName();
                    updateCache(sharedCache, key,
                        allSrc.get(or.srcIdx), objFiles.get(or.srcIdx), flagsH);
                }
            }
            // Persist the updated cache to disk
            saveBuildCache(objDir, sharedCache);

            // ── Phase 2: link all .o → .so ────────────────────────────────────
            // Verify runtime files exist before invoking the linker — gives a
            // clear report instead of a cryptic "cannot find -lclang_rt.builtins" error.
            verifyRuntimeFiles(clangBin, targetAbi, cb);
            if (cb != null) cb.onProgress("Linking → " + outputSo.getName() + "…");

            List<String> linkCmd = new ArrayList<>(Arrays.asList(
                clangBin.getAbsolutePath(),
                "--target=" + abiToTriple(targetAbi),
                "--sysroot=" + sysrootDir.getAbsolutePath(),
                "-shared",
                "-fPIC",
                "-Wl,--strip-all",      // remove .symtab/.strtab (keeps .dynsym for JNI)
                "-Wl,--strip-debug",    // remove all DWARF sections from static libs
                "-Wl,--gc-sections",    // dead-code elimination (pairs with -ffunction/data-sections)
                "-Wl,-x",              // discard all local symbols (anonymous lambdas etc.)
                "-Wl,--build-id=none"  // suppress GNU build-id note — no toolchain fingerprint
            ));
            // Library search paths
            if (sysrootLib26.exists()) linkCmd.add("-L" + sysrootLib26.getAbsolutePath());
            if (sysrootLib.exists())   linkCmd.add("-L" + sysrootLib.getAbsolutePath());
            // Static C++ runtime (libc++, not libstdc++)
            linkCmd.add("-lc++_static");   // libc++_static.a
            linkCmd.add("-lc++abi");       // libc++abi.a  — __gxx_personality_v0
            linkCmd.add("-llog");          // __android_log_print / __android_log_write
            linkCmd.add("-lm");            // libm — fmod, fmodf, sin, cos, tan, ceil etc.
            linkCmd.add("-ldl");           // dlfcn.h — dlopen, dlsym, dlclose (guard + VM)
            linkCmd.add("-lz");            // zlib — used by guard.cpp for DEFLATE APK reads
            // 16 KB page alignment required for arm64 + x86_64 on Android 15+.
            // arm32 and x86 max out at 4 KB — passing the flag there causes link errors.
            if (abiNeeds16kPage(targetAbi)) linkCmd.add("-Wl,-z,max-page-size=16384");

            // Version script: export JNI_OnLoad + ALL Java_* symbols.
            // Exporting all Java_* gives ART a static-symbol fallback for every
            // compiled method if dynamic_register_compile_methods() fails for a
            // class (e.g. on pairIP where FindClass uses a custom ClassLoader and
            // can return null inside JNI_OnLoad). Without this, a missed
            // RegisterNatives means UnsatisfiedLinkError with no recovery path.
            File verScript = new File(outputSo.getParentFile(), "exports.map");
            try (java.io.FileWriter fw = new java.io.FileWriter(verScript)) {
                fw.write("{ global: JNI_OnLoad; Java_*; local: *; };\n");
            }
            linkCmd.add("-Wl,--version-script=" + verScript.getAbsolutePath());

            // Absorb libcipher_arm64.a (guard) into the target .so.
            // Because guardA is a static archive (.a), --whole-archive works as
            // designed: every object in the archive is pulled in regardless of
            // whether its symbols are explicitly referenced. This is required so
            // guard's __attribute__((constructor)) fires even with no call site.
            // Unlike linking against a .so, no DT_NEEDED entry is generated, so
            // no post-link removal step is needed.
            linkCmd.add("-Wl,--whole-archive");
            linkCmd.add(guardA.getAbsolutePath());
            linkCmd.add("-Wl,--no-whole-archive");

            linkCmd.add("-o"); linkCmd.add(outputSo.getAbsolutePath());
            // Object files (same order as source — runtime objs first)
            for (File obj : objFiles) linkCmd.add(obj.getAbsolutePath());

            BuildResult linkResult = runProcess(linkCmd, outputSo, cb);
            linkResult.log = fullLog.append(linkResult.log != null ? linkResult.log : "").toString();

            // Post-link step 1: strip remaining .symtab/.strtab
            // --strip-unneeded keeps .dynsym (required for JNI) but removes everything else
            if (linkResult.success && outputSo.exists()) {
                try {
                    File strip = new File(cm.getActiveClangBin().getParent(), "llvm-strip");
                    if (!strip.exists()) strip = new File(cm.getActiveClangBin().getParent(), "strip");
                    if (strip.exists()) {
                        strip.setExecutable(true, false);
                        new ProcessBuilder(strip.getAbsolutePath(),
                                "--strip-unneeded", outputSo.getAbsolutePath())
                                .redirectErrorStream(true).start().waitFor();
                    }
                } catch (Exception ignored) {}

                // Post-link step 2: remove sections that leak toolchain info or
                // expose function-boundary maps to static analysis tools.
                //   .eh_frame_hdr   — DWARF CFI index; lets IDA/Ghidra reconstruct
                //                     function boundaries without needing .symtab
                //   .gcc_except_table — C++ exception handler address table (safe
                //                     to drop: we use -fexceptions but the runtime
                //                     falls back gracefully when the table is absent)
                //   .comment        — reveals linker version ("Linker: LLD 21.0.0")
                try {
                    File objcopy = new File(cm.getActiveClangBin().getParent(), "llvm-objcopy");
                    if (objcopy.exists()) {
                        objcopy.setExecutable(true, false);
                        new ProcessBuilder(
                                objcopy.getAbsolutePath(),
                                "--remove-section=.eh_frame_hdr",
                                "--remove-section=.gcc_except_table",
                                "--remove-section=.comment",
                                "--remove-section=.note.android.ident", // NDK version fingerprint
                                "--remove-section=.note.gnu.build-id",  // build-id fallback
                                outputSo.getAbsolutePath())
                                .redirectErrorStream(true).start().waitFor();
                        Log.i(TAG, "llvm-objcopy: removed .eh_frame_hdr/.gcc_except_table/.comment/.note.android.ident/.note.gnu.build-id");
                    }
                } catch (Exception ignored) {}

                // Post-link step 3: DT_NEEDED removal — NOT NEEDED.
                // Guard is now linked from libcipher_arm64.a (static archive).
                // Static archives never generate a DT_NEEDED entry, so there
                // is nothing to remove. No post-link ELF patching required.
            }

            return linkResult;

        } catch (Exception e) {
            Log.e(TAG, "compileWithClang exception", e);
            result.error = e.getMessage();
            return result;
        }
    }

    // ── OLLVM/Hikari availability probe ───────────────────────────────────────
    //
    // Compiles an empty translation unit with -mllvm -fla.
    // Stock NDK clang-21 exits non-zero (unknown LLVM arg); Hikari exits 0.
    // Result is cached in a boolean field so the probe only runs once per build.

    private static volatile Boolean ollvmProbeCache = null;

    private boolean probeOllvmAvailable(File clangBin, File sysrootDir) {
        if (ollvmProbeCache != null) return ollvmProbeCache;
        try {
            // Write a minimal C++ source to a temp file
            File tmp = File.createTempFile("ollvm_probe", ".cpp",
                    context.getCacheDir());
            tmp.deleteOnExit();
            try (java.io.FileWriter fw = new java.io.FileWriter(tmp)) {
                fw.write("void f(){}");
            }
            File tmpO = File.createTempFile("ollvm_probe", ".o",
                    context.getCacheDir());
            tmpO.deleteOnExit();

            List<String> cmd = new ArrayList<>(Arrays.asList(
                clangBin.getAbsolutePath(),
                "--target=aarch64-linux-android26",
                "--sysroot=" + sysrootDir.getAbsolutePath(),
                "-c", "-std=c++17", "-O2",
                "-mllvm", "-fla",    // the key probe flag
                "-o", tmpO.getAbsolutePath(),
                tmp.getAbsolutePath()
            ));

            java.lang.Process p = new ProcessBuilder(cmd)
                    .redirectErrorStream(true).start();
            // Drain stdout/stderr so the process doesn't block on a full pipe
            byte[] _buf = new byte[4096];
            try (java.io.InputStream _is = p.getInputStream()) {
                while (_is.read(_buf) != -1) {}
            }
            int exit = p.waitFor();
            ollvmProbeCache = (exit == 0);
            tmp.delete();
            tmpO.delete();
        } catch (Exception e) {
            Log.w(TAG, "OLLVM probe error: " + e.getMessage());
            ollvmProbeCache = false;
        }
        return ollvmProbeCache;
    }

    // ── Strip memory-heavy OLLVM passes for OOM fallback ─────────────────────
    // Removes -split, -split_num, -ibr, -icall, -igv from a compile command.
    // Keeps -fla, -bcf, -sub, -sobf which are low-memory and still effective.
    private static List<String> stripHeavyPasses(List<String> cmd) {
        List<String> out = new ArrayList<>();
        java.util.Set<String> heavy = new java.util.HashSet<>(java.util.Arrays.asList(
            "-split", "-ibr", "-icall", "-igv"
        ));
        for (int i = 0; i < cmd.size(); i++) {
            String tok = cmd.get(i);
            if (tok.equals("-mllvm") && i + 1 < cmd.size()) {
                String next = cmd.get(i + 1);
                // Skip -mllvm -split, -mllvm -ibr, -mllvm -icall, -mllvm -igv
                // and -mllvm -split_num=X (starts with "-split_num")
                if (heavy.contains(next) || next.startsWith("-split_num")) {
                    i++; // skip both -mllvm and the pass name
                    continue;
                }
            }
            out.add(tok);
        }
        return out;
    }

    // ── Per-file compile (no output-file check — just exit code) ──────────────

    private ObjResult runCompileProcess(List<String> cmd) {
        ObjResult r = new ObjResult();
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);

            File pyLib = cm.getPythonLibDir();
            if (pyLib.exists()) {
                String existing = pb.environment().getOrDefault("LD_LIBRARY_PATH", "");
                pb.environment().put("LD_LIBRARY_PATH",
                    pyLib.getAbsolutePath() + (existing.isEmpty() ? "" : ":" + existing));
            }

            java.lang.Process proc = pb.start();
            com.ultra.dex2cvmp.service.ProtectionService.ACTIVE_COMPILE_PROCS.add(proc);
            try {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()));
                StringBuilder log = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    log.append(line).append("\n");
                    Log.d(TAG, line);
                }
                int exit = proc.waitFor();
                r.log     = log.toString();
                r.success = (exit == 0);
                if (!r.success) {
                    if (exit == 134 || exit == 139) {
                        // SIGABRT (134) or SIGSEGV (139) — OLLVM pass crashed internally.
                        // This happens when intensity parameters are too heavy for a specific
                        // function's CFG. Tell the user to step down one level.
                        r.error = "exit=" + exit + " — OLLVM aborted on this file.\n"
                                + "The current intensity level is too heavy for this method.\n"
                                + "Go to the OLLVM tab and select a lower level (e.g. Supreme → Advanced → Turbo), "
                                + "or toggle OLLVM off for a fast build with no obfuscation.";
                    } else {
                        r.error = "exit=" + exit;
                    }
                }
            } finally {
                com.ultra.dex2cvmp.service.ProtectionService.ACTIVE_COMPILE_PROCS.remove(proc);
            }
        } catch (Exception e) {
            r.error   = e.getMessage();
            r.success = false;
        }
        return r;
    }

    // ── Link-step process runner ───────────────────────────────────────────────

    private BuildResult runProcess(List<String> cmd, File outputSo, BuildCallback cb) {
        BuildResult result = new BuildResult();
        try {
            if (cb != null) cb.onLog("$ clang-21 -shared … → " + outputSo.getName());

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);

            File pyLib = cm.getPythonLibDir();
            if (pyLib.exists()) {
                String existing = pb.environment().getOrDefault("LD_LIBRARY_PATH", "");
                pb.environment().put("LD_LIBRARY_PATH",
                    pyLib.getAbsolutePath() + (existing.isEmpty() ? "" : ":" + existing));
            }

            java.lang.Process proc = pb.start();
            com.ultra.dex2cvmp.service.ProtectionService.ACTIVE_PROCESS = proc;
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream()));
            StringBuilder log = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                log.append(line).append("\n");
                if (cb != null) cb.onLog(line);
                Log.d(TAG, line);
            }
            int exit = proc.waitFor();
            com.ultra.dex2cvmp.service.ProtectionService.ACTIVE_PROCESS = null;
            result.log     = log.toString();
            result.success = (exit == 0) && outputSo.exists() && outputSo.length() > 0;
            if (result.success) {
                result.soFile = outputSo;
                if (cb != null) cb.onProgress(
                    "✓ Linked → " + outputSo.getName()
                    + " (" + (outputSo.length() / 1024) + " KB)");
            } else {
                result.error = "clang++ link exited " + exit + "\n" + log;
                Log.e(TAG, "link failed (exit=" + exit + "): " + log);
            }
        } catch (Exception e) {
            Log.e(TAG, "runProcess exception", e);
            result.error = e.getMessage();
        }
        return result;
    }

    // ── Asset helpers ─────────────────────────────────────────────────────────

    private void extractAsset(String assetPath, File dest, boolean forceOverwrite)
        throws IOException {
        if (!forceOverwrite && dest.exists()) return;
        try (InputStream in  = context.getAssets().open(assetPath);
             OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }

    private void extractOptional(String assetPath, File dest) {
        try { extractAsset(assetPath, dest, false); } catch (IOException ignored) {}
    }

    /**
     * Recursively copies all files under {@code assetDir} (an assets/ subdirectory)
     * into {@code destDir}, preserving the subdirectory structure.
     * Used to unpack vmp_headers/ so that VMP-generated C files can #include "vm.h"
     * via the existing -I headersDir compile flag.
     */
    private void extractAssetDir(Context ctx, String assetDir, File destDir)
            throws IOException {
        android.content.res.AssetManager am = ctx.getAssets();
        String[] children = am.list(assetDir);
        if (children == null) return;
        for (String child : children) {
            String childPath = assetDir + "/" + child;
            String[] grandChildren = am.list(childPath);
            if (grandChildren != null && grandChildren.length > 0) {
                // It's a subdirectory — recurse
                File subDest = new File(destDir, child);
                subDest.mkdirs();
                extractAssetDir(ctx, childPath, subDest);
            } else {
                // It's a file — copy it
                File outFile = new File(destDir, child);
                try (InputStream in  = am.open(childPath);
                     OutputStream out = new FileOutputStream(outFile)) {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                }
            }
        }
    }

    /**
     * Patches a transpiler-generated jni_onload.cpp with two things:
     *
     * 1. fonts_register_natives(env) — registers fonts.Metrics.measure() so it is
     *    callable before attachBaseContext() fires.
     *
     * 2. Classloader capture — stores the app classloader as a GlobalRef in
     *    d2c_jvm / d2c_classloader globals (matching dex2c-pro's
     *    find_class_wo_static pattern). This is critical for correct class
     *    resolution: env->FindClass() uses the BOOTSTRAP classloader when called
     *    from native-spawned threads, which cannot find app classes. The runtime
     *    macro D2C_RESOLVE_CLASS is expected to use d2c_classloader (declared
     *    extern in Dex2C_impl.cpp) instead of env->FindClass() directly.
     *    Capturing it here, from JNI_OnLoad context (called from Java thread),
     *    guarantees the app classloader is always available.
     *
     * Strategy: find the last "return JNI_VERSION_1_6;" in the file
     * (always the success return of JNI_OnLoad) and insert both patches
     * just before it.
     */
    private static void patchJniOnload(File f) {
        if (f == null || !f.exists()) return;
        try {
            byte[] raw = readAllBytes(f);
            String src = new String(raw, java.nio.charset.StandardCharsets.UTF_8);

            final String RETURN_TOKEN = "return JNI_VERSION_1_6;";
            int idx = src.lastIndexOf(RETURN_TOKEN);
            if (idx < 0) {
                Log.w(TAG, "patchJniOnload: return token not found — skipping patch");
                return;
            }

            // Already patched?
            if (src.contains("fonts_register_natives")) {
                Log.i(TAG, "patchJniOnload: already patched, skipping");
                return;
            }

            // ── Declarations to insert after the last #include ────────────────
            //
            // d2c_jvm / d2c_classloader: defined here (storage), declared
            // `extern` in Dex2C_impl.cpp so the D2C_RESOLVE_CLASS macro can
            // reach them without going through FindClass.
            //
            // fonts_register_natives / fonts_apply_metrics: defined in guard.cpp.
            //
            // fonts_apply_metrics resolves a live Application Context itself
            // (via ActivityThread.currentApplication()) and runs the full
            // killer-detection suite right here in
            // JNI_OnLoad — independent of whether the DEX-injected
            // attachBaseContext() -> Metrics.measure(context) call survives any
            // later dex/manifest edit + resign. System.loadLibrary() must run
            // for the app's transpiled native methods to exist at all, so this
            // is the one call surface that can't be edited away without
            // breaking the app outright.
            String decls =
                "#include <obfuscate.h>\n"   // AY_OBFUSCATE used by transpiler-generated code in this file
                + "extern \"C\" void fonts_register_natives(JNIEnv *env);\n"
                + "extern \"C\" void fonts_apply_metrics(JNIEnv *env);\n"
                // Global storage for the app classloader — matches the extern
                // declaration expected by D2C_RESOLVE_CLASS in Dex2C_impl.cpp
                + "JavaVM *d2c_jvm = nullptr;\n"
                + "jobject d2c_classloader = nullptr;\n";

            // ── Calls to insert just before "return JNI_VERSION_1_6;" ─────────
            //
            // Classloader capture mirrors dex2c-pro's find_class_wo_static:
            //   • JNI_OnLoad is always called from a Java thread (triggered by
            //     System.loadLibrary inside <clinit>), so the calling thread's
            //     context classloader IS the app classloader.
            //   • We use Thread.currentThread().getContextClassLoader() —
            //     the only reliable way to get the app classloader from JNI.
            //   • NewGlobalRef prevents GC from collecting it.
            //   • Stored in d2c_classloader so D2C_RESOLVE_CLASS can use it
            //     from ANY thread (not just Java-originated threads), exactly
            //     as dex2c-pro's find_class_wo_static does.
            String calls =
                // Store the JavaVM — needed to attach native threads and to
                // re-acquire JNIEnv from threads that weren't created by Java.
                "    if (!d2c_jvm) { env->GetJavaVM(&d2c_jvm); }\n"
                // Capture app classloader via Thread.currentThread().getContextClassLoader()
                // This is the idiomatic JNI pattern — FindClass in JNI_OnLoad
                // uses the calling thread's classloader, but we need it stored
                // explicitly so D2C_RESOLVE_CLASS can reach it from any thread.
                + "    if (!d2c_classloader) {\n"
                + "        jclass jThread = env->FindClass(\"java/lang/Thread\");\n"
                + "        if (jThread && !env->ExceptionCheck()) {\n"
                + "            jmethodID mCur = env->GetStaticMethodID(\n"
                + "                jThread, \"currentThread\", \"()Ljava/lang/Thread;\");\n"
                + "            jmethodID mGetCL = env->GetMethodID(\n"
                + "                jThread, \"getContextClassLoader\", \"()Ljava/lang/ClassLoader;\");\n"
                + "            if (mCur && mGetCL && !env->ExceptionCheck()) {\n"
                + "                jobject jCur = env->CallStaticObjectMethod(jThread, mCur);\n"
                + "                if (jCur && !env->ExceptionCheck()) {\n"
                + "                    jobject jLoader = env->CallObjectMethod(jCur, mGetCL);\n"
                + "                    if (jLoader && !env->ExceptionCheck()) {\n"
                + "                        d2c_classloader = env->NewGlobalRef(jLoader);\n"
                + "                        env->DeleteLocalRef(jLoader);\n"
                + "                    }\n"
                + "                    env->DeleteLocalRef(jCur);\n"
                + "                }\n"
                + "            }\n"
                + "            if (env->ExceptionCheck()) env->ExceptionClear();\n"
                + "            env->DeleteLocalRef(jThread);\n"
                + "        }\n"
                + "    }\n"
                + "    fonts_register_natives(env);\n"
                + "    fonts_apply_metrics(env);\n"
                + "    ";

            // Insert declarations after the last #include line
            int declInsert = 0;
            int searchFrom = 0;
            while (true) {
                int found = src.indexOf("#include", searchFrom);
                if (found < 0) break;
                int eol = src.indexOf('\n', found);
                if (eol < 0) eol = src.length() - 1;
                declInsert = eol + 1;
                searchFrom = eol + 1;
            }

            String patched = src.substring(0, declInsert)
                    + decls
                    + src.substring(declInsert, idx)
                    + calls
                    + src.substring(idx);

            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(f)) {
                fos.write(patched.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            Log.i(TAG, "patchJniOnload: classloader capture + fonts_register_natives injected");
        } catch (Exception e) {
            Log.w(TAG, "patchJniOnload failed: " + e.getMessage());
        }
    }

    /**
     * Removes a DT_NEEDED entry from an ELF shared library using a Python script.
     *
     * Used as a fallback when llvm-objcopy --remove-needed is unavailable.
     * Uses SAFE COMPACTION: reads all .dynamic entries, discards those whose
     * name matches libToRemove, writes kept entries back followed by DT_NULL
     * padding up to original capacity.  DT_NULL is never inserted mid-table
     * (which would truncate dynamic-section parsing).
     */
    private void removeDtNeededViaPython(File soFile, String libToRemove) throws Exception {
        PythonManager pm = new PythonManager(context);
        String pythonBin = pm.getPythonBin();
        if (pythonBin == null) {
            throw new Exception("No Python binary available for ELF patcher fallback");
        }

        // Safe compaction ELF patcher (no external deps — stdlib only).
        // 1. Locate .dynamic via section headers (SHT_DYNAMIC=6).
        // 2. Locate .dynstr via .dynamic sh_link.
        // 3. Read all entries into a list (stop at first DT_NULL terminator).
        // 4. Remove entries whose DT_NEEDED name == target.
        // 5. Write kept entries back; pad remaining slots with DT_NULL.
        //    → DT_NULL ONLY at the end, never mid-table.
        // Exit non-zero on any parse/write error so the Java caller can detect failure.
        String script =
            "import struct, sys\n" +
            "\n" +
            "path   = sys.argv[1]\n" +
            "target = sys.argv[2].encode()\n" +
            "\n" +
            "with open(path, 'r+b') as f:\n" +
            "    data = bytearray(f.read())\n" +
            "\n" +
            "if data[:4] != b'\\x7fELF':\n" +
            "    print('ELF patcher: not an ELF file', flush=True); sys.exit(1)\n" +
            "ei_class = data[4]\n" +
            "ei_data  = data[5]\n" +
            "bo   = '<' if ei_data == 1 else '>'\n" +
            "bits = 64 if ei_class == 2 else 32\n" +
            "word = 8 if bits == 64 else 4\n" +
            "entry_sz = 2 * word\n" +
            "\n" +
            "if bits == 64:\n" +
            "    e_shoff, e_shentsize, e_shnum = struct.unpack_from(bo+'QHH', data, 40)\n" +
            "    sh_fmt = bo + 'IIQQQQIIQQ'\n" +
            "    I_TYPE, I_OFF, I_SIZE, I_LINK = 1, 4, 5, 6\n" +
            "else:\n" +
            "    e_shoff, e_shentsize, e_shnum = struct.unpack_from(bo+'IHH', data, 32)\n" +
            "    sh_fmt = bo + 'IIIIIIIIII'\n" +
            "    I_TYPE, I_OFF, I_SIZE, I_LINK = 1, 4, 5, 6\n" +
            "\n" +
            "dyn_off = dyn_size = dynstr_off = 0\n" +
            "for i in range(e_shnum):\n" +
            "    base   = e_shoff + i * e_shentsize\n" +
            "    fields = struct.unpack_from(sh_fmt, data, base)\n" +
            "    sh_type, sh_offset, sh_size, sh_link = (\n" +
            "        fields[I_TYPE], fields[I_OFF], fields[I_SIZE], fields[I_LINK])\n" +
            "    if sh_type == 6:\n" +
            "        dyn_off, dyn_size = sh_offset, sh_size\n" +
            "        str_base   = e_shoff + sh_link * e_shentsize\n" +
            "        str_fields = struct.unpack_from(sh_fmt, data, str_base)\n" +
            "        dynstr_off = str_fields[I_OFF]\n" +
            "        break\n" +
            "\n" +
            "if dyn_off == 0 or dynstr_off == 0:\n" +
            "    print('ELF patcher: .dynamic/.dynstr not found — nothing to patch', flush=True)\n" +
            "    sys.exit(0)\n" +
            "\n" +
            "DT_NEEDED = 1\n" +
            "DT_NULL   = 0\n" +
            "tag_fmt   = bo + ('q' if bits == 64 else 'i')\n" +
            "val_fmt   = bo + ('Q' if bits == 64 else 'I')\n" +
            "capacity  = dyn_size // entry_sz\n" +
            "entries   = []\n" +
            "for k in range(capacity):\n" +
            "    off = dyn_off + k * entry_sz\n" +
            "    tag, = struct.unpack_from(tag_fmt, data, off)\n" +
            "    val, = struct.unpack_from(val_fmt, data, off + word)\n" +
            "    entries.append((tag, val))\n" +
            "    if tag == DT_NULL:\n" +
            "        break\n" +
            "\n" +
            "kept    = []\n" +
            "removed = []\n" +
            "for (tag, val) in entries:\n" +
            "    if tag == DT_NEEDED:\n" +
            "        name_off = dynstr_off + val\n" +
            "        nul  = data.index(0, name_off)\n" +
            "        name = bytes(data[name_off:nul])\n" +
            "        if name == target:\n" +
            "            removed.append(name.decode())\n" +
            "            continue\n" +
            "    kept.append((tag, val))\n" +
            "\n" +
            "if not removed:\n" +
            "    print('ELF patcher: DT_NEEDED ' + target.decode() + ' not found (already clean)', flush=True)\n" +
            "    sys.exit(0)\n" +
            "\n" +
            "while kept and kept[-1][0] == DT_NULL:\n" +
            "    kept.pop()\n" +
            "kept.append((DT_NULL, 0))\n" +
            "\n" +
            "if len(kept) > capacity:\n" +
            "    print('ELF patcher: kept entries exceed capacity — aborting', flush=True)\n" +
            "    sys.exit(1)\n" +
            "for k, (tag, val) in enumerate(kept):\n" +
            "    off = dyn_off + k * entry_sz\n" +
            "    struct.pack_into(tag_fmt, data, off,        tag)\n" +
            "    struct.pack_into(val_fmt, data, off + word, val)\n" +
            "for k in range(len(kept), capacity):\n" +
            "    off = dyn_off + k * entry_sz\n" +
            "    struct.pack_into(tag_fmt, data, off,        DT_NULL)\n" +
            "    struct.pack_into(val_fmt, data, off + word, 0)\n" +
            "\n" +
            "with open(path, 'wb') as f:\n" +
            "    f.write(data)\n" +
            "print('ELF patcher: removed ' + str(len(removed)) + ' DT_NEEDED entr'\n" +
            "      + ('ies: ' if len(removed) != 1 else 'y: ') + ', '.join(removed), flush=True)\n";

        File scriptFile = File.createTempFile("elf_dt_patch", ".py", context.getCacheDir());
        scriptFile.deleteOnExit();
        try (java.io.FileWriter fw = new java.io.FileWriter(scriptFile)) {
            fw.write(script);
        }

        ProcessBuilder pb = new ProcessBuilder(pythonBin, scriptFile.getAbsolutePath(),
                soFile.getAbsolutePath(), libToRemove);
        pb.redirectErrorStream(true);

        File pyLib = cm.getPythonLibDir();
        if (pyLib.exists()) {
            String existing = pb.environment().getOrDefault("LD_LIBRARY_PATH", "");
            pb.environment().put("LD_LIBRARY_PATH",
                pyLib.getAbsolutePath() + (existing.isEmpty() ? "" : ":" + existing));
        }

        java.lang.Process p = pb.start();
        StringBuilder out = new StringBuilder();
        try (java.io.BufferedReader br =
                new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) out.append(line).append('\n');
        }
        int rc = p.waitFor();
        Log.i(TAG, "ELF patcher output:\n" + out);
        if (rc != 0) throw new Exception("ELF patcher exited " + rc + ": " + out);
    }

    /**
     * Returns true if the ELF shared library at {@code soFile} lists
     * {@code libName} as a DT_NEEDED dependency in its .dynamic section.
     *
     * Used as the verification gate after DT_NEEDED removal: if this returns
     * true the removal failed and the build must be aborted (fail-closed).
     */
    private static boolean elfHasDtNeeded(File soFile, String libName) throws Exception {
        byte[] data = readAllBytes(soFile);
        if (data.length < 16 || data[0] != 0x7f || data[1] != 'E'
                || data[2] != 'L' || data[3] != 'F') {
            throw new Exception("Not an ELF file: " + soFile.getName());
        }
        int eiClass = data[4] & 0xFF; // 1=32-bit, 2=64-bit
        int eiData  = data[5] & 0xFF; // 1=LE, 2=BE
        boolean le   = (eiData == 1);
        boolean is64 = (eiClass == 2);
        int word = is64 ? 8 : 4;
        int entrySize = 2 * word;

        long eShoff;
        int  eShentsize, eShnum;
        if (is64) {
            eShoff     = elfReadU64(data, 40, le);
            eShentsize = elfReadU16(data, 58, le);
            eShnum     = elfReadU16(data, 60, le);
        } else {
            eShoff     = elfReadU32(data, 32, le);
            eShentsize = elfReadU16(data, 46, le);
            eShnum     = elfReadU16(data, 48, le);
        }

        long dynOff = 0, dynSize = 0, dynstrOff = 0;
        for (int i = 0; i < eShnum; i++) {
            long shBase = eShoff + (long) i * eShentsize;
            int  shType = (int) elfReadU32(data, (int)(shBase + 4), le);
            if (shType == 6) { // SHT_DYNAMIC
                if (is64) {
                    dynOff    = elfReadU64(data, (int)(shBase + 24), le);
                    dynSize   = elfReadU64(data, (int)(shBase + 32), le);
                    int shLink = (int) elfReadU32(data, (int)(shBase + 40), le);
                    long strBase = eShoff + (long) shLink * eShentsize;
                    dynstrOff = elfReadU64(data, (int)(strBase + 24), le);
                } else {
                    dynOff    = elfReadU32(data, (int)(shBase + 16), le);
                    dynSize   = elfReadU32(data, (int)(shBase + 20), le);
                    int shLink = (int) elfReadU32(data, (int)(shBase + 24), le);
                    long strBase = eShoff + (long) shLink * eShentsize;
                    dynstrOff = elfReadU32(data, (int)(strBase + 16), le);
                }
                break;
            }
        }
        if (dynOff == 0 || dynstrOff == 0) return false;

        byte[] targetBytes = libName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        long capacity = dynSize / entrySize;
        for (long k = 0; k < capacity; k++) {
            int off = (int)(dynOff + k * entrySize);
            long tag = is64 ? elfReadS64(data, off, le) : elfReadS32(data, off, le);
            if (tag == 0L) break; // DT_NULL
            if (tag == 1L) {      // DT_NEEDED
                long val     = is64 ? elfReadU64(data, off + word, le) : elfReadU32(data, off + word, le);
                int nameStart = (int)(dynstrOff + val);
                int nameEnd   = nameStart;
                while (nameEnd < data.length && data[nameEnd] != 0) nameEnd++;
                if (nameEnd - nameStart == targetBytes.length) {
                    boolean match = true;
                    for (int c = 0; c < targetBytes.length; c++) {
                        if (data[nameStart + c] != targetBytes[c]) { match = false; break; }
                    }
                    if (match) return true;
                }
            }
        }
        return false;
    }

    // ── Minimal ELF integer readers (static, no external deps) ───────────────

    private static int elfReadU16(byte[] d, int off, boolean le) {
        int a = d[off] & 0xFF, b = d[off+1] & 0xFF;
        return le ? (b << 8 | a) : (a << 8 | b);
    }
    private static long elfReadU32(byte[] d, int off, boolean le) {
        long a=d[off]&0xFFL, b=d[off+1]&0xFFL, c=d[off+2]&0xFFL, e=d[off+3]&0xFFL;
        return le ? (e<<24|c<<16|b<<8|a) : (a<<24|b<<16|c<<8|e);
    }
    private static long elfReadS32(byte[] d, int off, boolean le) {
        return (int) elfReadU32(d, off, le);
    }
    private static long elfReadU64(byte[] d, int off, boolean le) {
        long lo = elfReadU32(d, off,     le);
        long hi = elfReadU32(d, off + 4, le);
        return le ? (hi << 32 | lo) : (lo << 32 | hi);
    }
    private static long elfReadS64(byte[] d, int off, boolean le) {
        return elfReadU64(d, off, le);
    }


    private static byte[] readAllBytes(java.io.File f) throws java.io.IOException {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int off = 0, n;
            while (off < buf.length && (n = fis.read(buf, off, buf.length - off)) != -1) off += n;
            return buf;
        }
    }
}
