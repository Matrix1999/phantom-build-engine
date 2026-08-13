package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Environment;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedClassDef;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.ultra.dex2cvmp.engine.packer.DexPacker;
import com.ultra.dex2cvmp.engine.packer.ManifestPatcher;
import com.ultra.dex2cvmp.engine.vmp.Dex2c;
import com.ultra.dex2cvmp.engine.vmp.DexConfig;
import com.ultra.dex2cvmp.engine.vmp.GlobalDexConfig;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.RegisterNativesUtilClassDef;
import com.ultra.dex2cvmp.ui.SettingsFragment;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

public class ApkProtector {

    public interface ProgressCallback {
        void onProgress(int percent, String message);
    }


    private final Context context;
    private ProgressCallback callback;

    public ApkProtector(Context context) {
        this.context = context;
    }

    public void setProgressCallback(ProgressCallback cb) { this.callback = cb; }

    private void report(int pct, String msg) {
        if (callback != null) callback.onProgress(pct, msg);
    }

    /** Legacy overload — defaults to dex2c mode (backwards-compatible). */
    public String protect(Uri inputUri, String filterText, boolean signOutput) throws Exception {
        return protect(inputUri, filterText, signOutput, false, false);
    }

    public String protect(Uri inputUri, String filterText, boolean signOutput, boolean useVmp) throws Exception {
        return protect(inputUri, filterText, signOutput, useVmp, false);
    }

    public String protect(Uri inputUri, String filterText, boolean signOutput, boolean useVmp,
                          boolean blockRootedDevices) throws Exception {
        // Auto-clear the entire app cache before every protection run.
        // This mirrors the manual "Clear Cache" button in Settings and ensures
        // no leftover temp files, old dex2c_mega_* work dirs, or stale compiler
        // artifacts can interfere with the new job.
        File baseCache = context.getCacheDir();
        File[] allCached = baseCache.listFiles();
        if (allCached != null) {
            for (File f : allCached) deleteDir(f);
        }

        File cacheDir = new File(baseCache, "dex2c_mega_" + System.currentTimeMillis());
        cacheDir.mkdirs();
        try {
            report(5, "Copying APK…");
            File inputApk = copyToCache(inputUri, cacheDir);
            return protectApk(inputApk, filterText, signOutput, useVmp, blockRootedDevices, cacheDir);
        } finally {
            deleteDir(cacheDir);
        }
    }

    private String protectApk(File inputApk, String filterText,
                               boolean signOutput, boolean useVmp,
                               boolean blockRootedDevices, File cacheDir) throws Exception {

        String libName = getLibraryName();
        List<String> targetAbis = getTargetAbis();

        // ── 1. Init compiler (auto-extracts from bundled asset on first run) ──
        report(8, "Initialising compiler…");
        NdkBuilder ndk = new NdkBuilder(context);
        boolean compilerReady = ndk.setup(new NdkBuilder.BuildCallback() {
            public void onProgress(String m) { report(10, m); }
            public void onLog(String l) {}
        });
        if (!compilerReady) {
            throw new Exception("Compiler initialisation failed — cannot protect APK.");
        }

        // ── 3. Validate class list ────────────────────────────────
        report(20, "Checking class list…");
        if (filterText == null || filterText.trim().isEmpty())
            throw new Exception("No classes selected to protect.");
        long classCount = filterText.lines().filter(l -> !l.isBlank()).count();
        report(25, classCount + " class(es) selected for protection");

        // ── 4. Extract DEX files (needed for bytecode patching later) ────────
        report(30, "Extracting DEX…");
        File dexDir = new File(cacheDir, "dex");
        dexDir.mkdirs();
        List<File> dexFiles = extractDexFiles(inputApk, dexDir);
        if (dexFiles.isEmpty()) throw new Exception("No DEX files found in APK.");

        // ── 5. Transpile APK → C / C++ ───────────────────────────────────────
        // MODE_VMP  : maoabc/nmmp VMP interpreter — custom opcodes + C VM
        // MODE_DEX2C: codehasan/dex2c Python transpiler (default)
        int transpileMode = useVmp ? DexTranspiler.MODE_VMP : DexTranspiler.MODE_DEX2C;
        String modeLabel  = useVmp ? "VMP" : "dex2c";
        report(35, "Transpiling " + classCount + " class(es) [" + modeLabel + "]…");
        File cSourceDir = new File(cacheDir, "c_src");
        cSourceDir.mkdirs();

        DexTranspiler transpiler = new DexTranspiler(context);
        DexTranspiler.TranspileResult transpileResult = transpiler.transpile(
                inputApk.getAbsolutePath(), filterText, cSourceDir,
                transpileMode, msg -> report(40, msg));

        int transpiled = transpileResult != null ? transpileResult.successCount() : 0;

        if (transpileResult != null) {
            for (String e : transpileResult.errors) report(42, "  " + e);
        }

        // Surface the Python debug log if present
        File debugLog = new File(cSourceDir, "dex_bridge_debug.log");
        if (debugLog.exists()) {
            try {
                List<String> logLines = new ArrayList<>();
                try (BufferedReader br = new BufferedReader(new FileReader(debugLog))) {
                    String line;
                    while ((line = br.readLine()) != null) logLines.add(line);
                }
                int start = Math.max(0, logLines.size() - 20);
                for (int i = start; i < logLines.size(); i++) {
                    report(43, "LOG> " + logLines.get(i));
                }
            } catch (Exception ignored) {}
        }

        if (transpiled == 0) {
            String errs = transpileResult != null
                    ? String.join(" | ", transpileResult.errors.subList(
                            0, Math.min(5, transpileResult.errors.size())))
                    : "unknown";
            throw new Exception("Transpiler produced no output. " + errs);
        }
        report(50, "Transpiled " + transpiled + " method(s) → C++");

        // ── 5b. guard layer ──────────────────────────────────────────────────
        // guard ships as libcipher.so (OLLVM prebuilt) in the app's jniLibs.
        // NdkBuilder.getGuardSoFromNativeLibs() finds it and links it into the
        // target .so via --whole-archive.  No source, no key, no decrypt.

        // ── 5.5. Bytecode strip + native string encryption (before compile) ──
        //
        // This block used to run AFTER compile (old step 7). It is now placed
        // BEFORE compile so that ph_strings.cpp (generated below) is present in
        // cSourceDir when NdkBuilder compiles step 6. patchAll only modifies DEX
        // files in dexDir — it never touches cSourceDir — so reordering is safe.

        report(53, "Determining target methods…");
        Set<String> compiledKeys;
        if (useVmp && transpileResult.vmpConfig != null) {
            compiledKeys = buildVmpKeysFromShellDex(transpileResult.vmpConfig);
            report(54, "VMP: " + compiledKeys.size() + " method(s) targeted for native strip");
            report(54, "VMP: injecting NativeUtil class into DEX…");
            injectVmpNativeUtil(transpileResult.vmpConfig, dexDir, libName);
            report(54, "VMP: NativeUtil + classesInit0 hooks injected");
        } else {
            compiledKeys = transpileResult.compiled.keySet();
        }

        // Target class descriptors derived from compiled method keys.
        Set<String> targetTypes = new HashSet<>();
        for (String k : compiledKeys) {
            int arrow = k.indexOf("->");
            if (arrow > 0) targetTypes.add(k.substring(0, arrow));
        }

        // ── 5.5a. Pre-scan: read static String field values BEFORE patchAll ──
        // patchAll modifies dexFiles in-place; we must read them now while they
        // still contain the original static_values entries.
        report(55, "Scanning static String fields in target classes…");
        Map<String, List<NativeStringGen.StringEntry>> strTable =
                scanStaticStrings(dexFiles, targetTypes);
        Set<String> classesWithStrings = strTable.keySet();
        if (!classesWithStrings.isEmpty()) {
            int strTotal = 0;
            for (List<NativeStringGen.StringEntry> v : strTable.values()) strTotal += v.size();
            report(56, "Found " + strTotal + " String field(s) in "
                    + classesWithStrings.size() + " class(es) — will strip + encrypt");
        }

        // ── 5.5b. Strip DEX bytecode (methods → ACC_NATIVE, String values → null) ──
        report(57, "Patching " + compiledKeys.size() + " method(s) → ACC_NATIVE stubs…");
        int stripped = Tier1DexPatcher.patchAll(dexDir, compiledKeys, libName,
                classesWithStrings, msg -> report(58, msg));
        report(59, "Stripped " + stripped + " method(s)");

        if (!compiledKeys.isEmpty()) {
            report(59, "Verifying " + compiledKeys.size() + " method stubs…");
            verifyStrippedKeys(dexDir, compiledKeys);
            report(59, "Verification passed — all stubs confirmed ACC_NATIVE");
        }

        // ── 5.5c. Generate ph_strings.cpp into cSourceDir (compiled in step 6) ──
        if (!strTable.isEmpty()) {
            NativeStringGen.generate(strTable, cSourceDir);
            report(59, "ph_strings.cpp generated — string injection baked into .so");
        }

        // ── 5.5d. Export stripped DEX ZIP for user inspection ────────────────
        String modeTag = useVmp ? "vmp" : "dex2c";
        File strippedDexZip = exportStrippedDexZip(dexDir, modeTag);
        if (strippedDexZip != null) {
            report(59, "Stripped DEX → " + strippedDexZip.getName()
                    + " (" + (strippedDexZip.length() / 1024) + " KB) — open to verify");
        }

        // ── 6. Compile C++ → .so  (all ABIs in parallel) ─────────────────────
        // Before this fix, ABIs compiled sequentially — arm64 finished before
        // armeabi-v7a even started, wasting the full arm64 compile time (~4 min).
        // Now both ABIs run on separate threads simultaneously, halving wall time.
        report(55, "Compiling native library for " + targetAbis.size() + " ABI(s)…");
        File libsDir = new File(cacheDir, "libs");

        // Trace log — written per ABI, arm64-v8a overwrites (first), others append
        File traceLog = new File(Environment.getExternalStorageDirectory(), "Ultra Dex2C-VMP/build_trace.log");
        traceLog.getParentFile().mkdirs();

        // Result carrier for each ABI task
        final class AbiResult {
            final String abi;
            final File   soFile;
            final NdkBuilder.BuildResult build;
            AbiResult(String a, File f, NdkBuilder.BuildResult b) { abi = a; soFile = f; build = b; }
        }

        ExecutorService abiPool = Executors.newFixedThreadPool(targetAbis.size());
        List<Future<AbiResult>> abiFutures = new ArrayList<>(targetAbis.size());

        for (int abiIdx = 0; abiIdx < targetAbis.size(); abiIdx++) {
            final String abi     = targetAbis.get(abiIdx);
            final boolean isPrimary = (abiIdx == 0);   // arm64-v8a is always first
            final File abiSoFile = new File(cacheDir,
                    "lib" + libName + "_" + abi.replace("-", "_") + ".so");

            abiFutures.add(abiPool.submit(() -> {
                // Each ABI gets its own trace writer to avoid interleaving
                PrintWriter tw = null;
                try {
                    tw = new PrintWriter(new FileWriter(traceLog, !isPrimary));
                } catch (Exception ignored) {}
                final PrintWriter traceWriter = tw;

                NdkBuilder.BuildResult br = ndk.compile(cSourceDir, abiSoFile, abi,
                        new NdkBuilder.BuildCallback() {
                            public void onProgress(String m) {
                                report(60, "[" + abi + "] " + m);
                                android.util.Log.i("NdkBuilder", "[" + abi + "] " + m);
                                if (traceWriter != null) { traceWriter.println("[PROGRESS][" + abi + "] " + m); traceWriter.flush(); }
                            }
                            public void onLog(String l) {
                                report(61, l);
                                android.util.Log.d("Clang", l);
                                if (traceWriter != null) { traceWriter.println(l); traceWriter.flush(); }
                            }
                        });
                if (traceWriter != null) traceWriter.close();
                return new AbiResult(abi, abiSoFile, br);
            }));
        }

        abiPool.shutdown();
        abiPool.awaitTermination(10, TimeUnit.HOURS);

        // Collect results — throw on first failure, copy .so on success
        File primarySoFile = null;
        for (int i = 0; i < abiFutures.size(); i++) {
            AbiResult ar = abiFutures.get(i).get();
            if (!ar.build.success || ar.build.soFile == null) {
                android.util.Log.e("ApkProtector", "Compile FAILED [" + ar.abi + "]:\n" + ar.build.error);
                throw new Exception("Compilation failed [" + ar.abi + "]:\n" + ar.build.error
                        + "\n(full log → /sdcard/Ultra Dex2C-VMP/build_trace.log)");
            }
            report(65, "[" + ar.abi + "] Native library compiled (" + (ar.soFile.length() / 1024) + " KB)");

            // Place into libs/<abi>/lib<name>.so
            File abiDir = new File(libsDir, ar.abi);
            abiDir.mkdirs();
            copyFile(ar.soFile, new File(abiDir, "lib" + libName + ".so"));

            if (primarySoFile == null) primarySoFile = ar.soFile;  // arm64-v8a is first
        }

        // soFile alias — used for the SO integrity hash below (arm64-v8a canonical)
        File soFile = primarySoFile;

        // Step 5.5 (bytecode strip + string encryption) already ran before compile.
        report(70, "Bootstrap via per-class <clinit> — attachBaseContext untouched");

        // ── 8. Repack APK ─────────────────────────────────────────
        File assetsDir = new File(cacheDir, "assets_inject");
        assetsDir.mkdirs();

        // Read all prefs once — used in stamps and in the final DEX packer step.
        SharedPreferences prefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        boolean dexPackerEnabled  = prefs.getBoolean(SettingsFragment.KEY_DEX_PACKER,         false);
        boolean manifestDexEnabled = prefs.getBoolean(SettingsFragment.KEY_MANIFEST_DEX_CHECK, true);
        boolean sigCheckEnabled    = prefs.getBoolean(SettingsFragment.KEY_SIG_CHECK,          true);

        // ── 8b. Manifest-hash + dex-count integrity stamps ────────────────────
        //
        // When DEX packer is ON the output APK will look different from the
        // un-packed one in two ways:
        //   1. AndroidManifest.xml — android:name is changed to ProxyApplication
        //   2. DEX files           — all originals replaced by exactly 1 stub.dex
        //
        // guard.cpp reads the installed APK (packed state), so the stamps must
        // reflect THAT state — otherwise the integrity check crashes on first launch.
        // We pre-compute the patched manifest bytes here (ManifestPatcher is fast)
        // so the stamp matches what DexPacker will produce later.
        if (manifestDexEnabled) {
            if (dexPackerEnabled) {
                report(81, "DEX packer ON — stamping packed manifest + stub DEX count (1)…");
                byte[] rawManifest = readZipEntry(inputApk, "AndroidManifest.xml");
                if (rawManifest == null || rawManifest.length == 0)
                    throw new Exception("AndroidManifest.xml missing in input APK.");
                // Run ManifestPatcher just to get the patched bytes for the hash.
                // DexPacker will run it again later when it does the real repack.
                byte[] packedManifest = ManifestPatcher.parseManifest(
                        rawManifest, DexPacker.PROXY_APP);
                // DEX count in the packed APK = 1 (only stub.dex → classes.dex)
                writeIntegrityStamps(packedManifest, 1, assetsDir);
                report(81, "Packed-state stamps written (manifest=ProxyApplication, dexCount=1)");
            } else {
                report(81, "Stamping manifest + DEX-count integrity check…");
                writeIntegrityStamps(inputApk, dexDir, assetsDir);
                report(81, "Integrity stamps written");
            }
        } else {
            report(81, "Manifest & DEX check disabled — writing sentinel stamps…");
            writeDisabledStamps(assetsDir);
        }

        // ── 8c. Native SO self-integrity stamp ───────────────────────────────
        // DexPacker does not touch lib/ so this stamp is valid regardless.
        report(82, "Hashing native .so → writing SO integrity stamp…");
        writeNativeSoHash(soFile, assetsDir);
        report(82, "SO integrity stamp written (" + (soFile.length() / 1024) + " KB hashed)");

        // ── 8d. Signature certificate hash stamp ─────────────────────────────
        if (sigCheckEnabled) {
            report(83, "Stamping signing certificate hash…");
            writeSignatureHash(inputApk, assetsDir);
            report(83, "Certificate stamp written");
        } else {
            report(83, "Signature check disabled — writing sentinel stamp…");
            writeDisabledSigHash(assetsDir);
        }

        report(85, "Rebuilding APK — merging DEX + .so + assets…");
        File outputApk = buildOutputPath(signOutput);
        ApkRebuilder.rebuild(inputApk, outputApk, dexDir, libsDir, assetsDir,
                msg -> report(87, msg));
        report(92, "APK assembled (" + (outputApk.length() / 1024) + " KB)");

        if (signOutput) {
            report(93, "Signing APK with test key…");
            File signed = new File(outputApk.getParent(),
                    outputApk.getName().replace("_unsigned", ""));
            ApkSigner.sign(context, outputApk, signed);
            outputApk.delete();
            outputApk = signed;
            report(dexPackerEnabled ? 95 : 98,
                    "APK signed — " + (outputApk.length() / 1024) + " KB");
        }

        // ── 9. DEX packer — runs AFTER dex2c/VMP is fully done ───────────────
        //
        // Sequence matters:
        //   dex2c/VMP  → transpile Java → C++, compile .so, strip DEX bytecode
        //   DEX packer → encrypt the (already-stripped) DEX + inject stub loader
        //
        // The stripped DEX files contain only ACC_NATIVE stubs — no bytecode.
        // Encrypting them on top means: even if someone decrypts the DEX at rest,
        // there is still no bytecode to read. The actual logic is in the .so only.
        if (dexPackerEnabled) {
            report(96, "DEX packer: encrypting DEX shards + injecting stub loader…");
            File packWorkDir = new File(cacheDir, "pack_work");
            packWorkDir.mkdirs();
            // Packed APK is always produced unsigned; we re-sign below if needed.
            File packedUnsigned = new File(outputApk.getParent(),
                    outputApk.getName().replace(".apk", "_dexpacked_unsigned.apk"));

            new DexPacker(context).pack(outputApk, packedUnsigned, packWorkDir, blockRootedDevices);
            report(97, "DEX packer: stub injected — "
                    + (packedUnsigned.length() / 1024) + " KB packed APK");

            // Delete the intermediate (pre-pack) APK — we only keep the final.
            outputApk.delete();
            outputApk = packedUnsigned;

            // Re-sign the packed APK if the user asked for a signed output.
            // DexPacker modifies the ZIP (manifest + DEX entries change), which
            // invalidates the V1 block written above, so a fresh sign is required.
            if (signOutput) {
                report(98, "DEX packer: re-signing packed APK…");
                File packedSigned = new File(packedUnsigned.getParent(),
                        packedUnsigned.getName().replace("_dexpacked_unsigned", "_dexpacked"));
                ApkSigner.sign(context, packedUnsigned, packedSigned);
                packedUnsigned.delete();
                outputApk = packedSigned;
                report(99, "DEX packer: signed — " + (outputApk.length() / 1024) + " KB");
            }
        }

        report(100, "Done! → " + outputApk.getName());
        return outputApk.getAbsolutePath();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private File buildOutputPath(boolean signOutput) {
        File dir = new File(Environment.getExternalStorageDirectory(), "Ultra Dex2C-VMP");
        dir.mkdirs();
        String ts = String.valueOf(System.currentTimeMillis());
        return new File(dir, "protected_" + ts + (signOutput ? "_unsigned.apk" : ".apk"));
    }

    /**
     * Pre-scan DEX files for static String fields with hardcoded initializer values
     * in the target classes. Must be called BEFORE Tier1DexPatcher.patchAll() so the
     * original static_values entries are still present in the DEX files.
     *
     * Uses smali/dexlib2 (already a project dependency) whose Field API gives direct
     * access to EncodedValue / StringEncodedValue without needing vova7878 internals.
     *
     * @param dexFiles    DEX files extracted from the input APK (unmodified at call time)
     * @param targetTypes DEX type descriptors (e.g. "Lcom/example/Foo;") of target classes
     * @return ordered map: classDesc → list of {fieldName, value} entries to strip
     */
    private Map<String, List<NativeStringGen.StringEntry>> scanStaticStrings(
            List<File> dexFiles, Set<String> targetTypes) {
        Map<String, List<NativeStringGen.StringEntry>> table = new LinkedHashMap<>();
        if (targetTypes.isEmpty()) return table;
        for (File f : dexFiles) {
            try {
                DexBackedDexFile dex = DexBackedDexFile.fromInputStream(
                        null, new java.io.BufferedInputStream(new java.io.FileInputStream(f)));
                for (com.android.tools.smali.dexlib2.iface.ClassDef cls : dex.getClasses()) {
                    String clsType = cls.getType();
                    if (!targetTypes.contains(clsType)) continue;
                    List<NativeStringGen.StringEntry> entries = new ArrayList<>();
                    for (com.android.tools.smali.dexlib2.iface.Field field
                            : cls.getStaticFields()) {
                        if (!"Ljava/lang/String;".equals(field.getType())) continue;
                        com.android.tools.smali.dexlib2.iface.value.EncodedValue ev =
                                field.getInitialValue();
                        if (!(ev instanceof
                                com.android.tools.smali.dexlib2.iface.value.StringEncodedValue))
                            continue;
                        String val = ((com.android.tools.smali.dexlib2.iface.value
                                .StringEncodedValue) ev).getValue();
                        if (val == null) continue;
                        entries.add(new NativeStringGen.StringEntry(field.getName(), val));
                        android.util.Log.d("ApkProtector",
                                "  str field: " + field.getName() + " in " + clsType);
                    }
                    if (!entries.isEmpty()) table.put(clsType, entries);
                }
            } catch (Exception e) {
                android.util.Log.w("ApkProtector",
                        "scanStaticStrings [" + f.getName() + "]: " + e.getMessage());
            }
        }
        return table;
    }

    /**
     * Zips every *.dex file in {@code dexDir} (the stripped/processed DEX files)
     * and writes the zip to /sdcard/Ultra Dex2C-VMP/stripped_dex_<mode>_<ts>.zip.
     *
     * Both dex2c and VMP mode call this — the zip lets the user open it with any
     * tool (jadx, apktool, dex2jar) and confirm that the targeted methods are
     * replaced by ACC_NATIVE stubs with no bytecode.
     *
     * @param dexDir  directory containing the final stripped classes*.dex files
     * @param mode    label embedded in the zip name — "dex2c" or "vmp"
     * @return the written zip file, or null if nothing was zipped
     */
    private File exportStrippedDexZip(File dexDir, String mode) {
        try {
            File[] dexFiles = dexDir.listFiles((d, n) -> n.endsWith(".dex"));
            if (dexFiles == null || dexFiles.length == 0) return null;

            File outDir = new File(Environment.getExternalStorageDirectory(), "Ultra Dex2C-VMP");
            outDir.mkdirs();
            File zip = new File(outDir,
                    "stripped_dex_" + mode + "_" + System.currentTimeMillis() + ".zip");

            try (ZipOutputStream zos = new ZipOutputStream(
                    new BufferedOutputStream(new FileOutputStream(zip)))) {
                for (File dex : dexFiles) {
                    zos.putNextEntry(new ZipEntry(dex.getName()));
                    try (FileInputStream fis = new FileInputStream(dex)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = fis.read(buf)) != -1) zos.write(buf, 0, n);
                    }
                    zos.closeEntry();
                }
            }
            return zip;
        } catch (Exception e) {
            android.util.Log.w("ApkProtector",
                    "exportStrippedDexZip failed: " + e.getMessage());
            return null;
        }
    }

    private List<File> extractDexFiles(File apk, File outDir) throws IOException {
        List<File> result = new ArrayList<>();
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apk))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                // Strip leading "./" produced by some APK build tools (apktool, AAPT1)
                if (name.startsWith("./")) name = name.substring(2);
                if (name.matches("classes\\d*\\.dex")) {
                    File out = new File(outDir, name);
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = zis.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    result.add(out);
                }
            }
        }
        return result;
    }

    // placeTier1Libs removed — libs are placed per-ABI inside the compile loop above.

    /** Reads the configured library name from Settings, falling back to the default. */
    private String getLibraryName() {
        SharedPreferences prefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        String name = prefs.getString(SettingsFragment.KEY_LIBRARY_NAME,
                SettingsFragment.DEFAULT_LIBRARY_NAME);
        if (name == null || name.trim().isEmpty() || !name.matches("[A-Za-z0-9_-]+")) {
            return SettingsFragment.DEFAULT_LIBRARY_NAME;
        }
        return name;
    }

    /** Reads the configured target ABIs from Settings. Both default ON, both user-toggleable. */
    private List<String> getTargetAbis() {
        SharedPreferences prefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        List<String> abis = new ArrayList<>();
        if (prefs.getBoolean(SettingsFragment.KEY_ABI_ARM64,   true)) abis.add("arm64-v8a");
        if (prefs.getBoolean(SettingsFragment.KEY_ABI_ARMEABI, true)) abis.add("armeabi-v7a");
        // x86_64 / x86 not supported — no guard archives shipped for those ABIs
        return abis;
    }

    // ── Integrity stamp helpers ────────────────────────────────────────────

    /**
     * Stamps the protected APK with two AES-256-CBC encrypted asset files:
     *   assets/font_metrics.dat — FNV-1a64 hash of AndroidManifest.xml
     *   assets/font_index.dat   — count of classes*.dex files in dexDir
     *
     * guard.cpp's detect_metrics_tamper() verifies both on every launch and
     * crashes on any mismatch. This catches ANY tamper that changes the
     * manifest (e.g. declaring a new provider) or adds/removes a DEX file
     * (e.g. injecting a dialog-killer DEX), without needing hardcoded names.
     *
     * Called AFTER patchAll() so dexDir contains the final DEX set (including
     * the fonts/Metrics guard DEX merged in by patchAll).
     * Called AFTER assetsDir is created so the stamp files land in assetsDir
     * and get merged into the output APK by ApkRebuilder.rebuild().
     *
     * When DEX packer is enabled, call the overload below with pre-computed
     * patched manifest bytes and dexCount=1 instead of this one.
     */
    private void writeIntegrityStamps(File inputApk, File dexDir, File assetsDir) throws Exception {
        byte[] manifestBytes = readZipEntry(inputApk, "AndroidManifest.xml");
        if (manifestBytes == null || manifestBytes.length == 0)
            throw new Exception("AndroidManifest.xml not found in input APK — cannot stamp integrity check.");

        File[] dexFiles = dexDir.listFiles((d, n) -> n.matches("classes(\\d*)\\.dex"));
        int dexCount = dexFiles != null ? dexFiles.length : 0;
        if (dexCount == 0)
            throw new Exception("No DEX files found to stamp — refusing to ship without an integrity check.");

        writeIntegrityStamps(manifestBytes, dexCount, assetsDir);
    }

    /**
     * Low-level overload: stamp with caller-supplied manifest bytes and DEX count.
     *
     * Used by the DEX-packer path: ManifestPatcher is run early to get the
     * patched manifest bytes (ProxyApplication already swapped in), and
     * dexCount=1 because the packed APK contains only the stub classes.dex.
     * This means guard.cpp verifies the packed state, not the pre-pack state.
     */
    private void writeIntegrityStamps(byte[] manifestBytes, int dexCount, File assetsDir) throws Exception {
        if (manifestBytes == null || manifestBytes.length == 0)
            throw new Exception("Manifest bytes empty — cannot stamp integrity check.");
        if (dexCount == 0)
            throw new Exception("DEX count is 0 — refusing to ship without an integrity check.");

        long hash = fnv1a64(manifestBytes);

        byte[] hashBytes  = new byte[8];
        byte[] countBytes = new byte[4];
        for (int i = 0; i < 8; i++) hashBytes[i]  = (byte) ((hash    >>> (8 * i)) & 0xFF);
        for (int i = 0; i < 4; i++) countBytes[i] = (byte) ((dexCount >>> (8 * i)) & 0xFF);

        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_metrics.dat"), hashBytes, key, iv);
            writeEncrypted(new File(assetsDir, "font_index.dat"),   countBytes, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
        android.util.Log.i("ApkProtector",
            "Integrity stamps written — manifest hash=0x" + Long.toHexString(hash)
            + " dexCount=" + dexCount);
    }

    /**
     * Writes sentinel stamp files (hash=0, count=0) when the user disables
     * the Manifest & Dex integrity check in Settings.
     *
     * guard.cpp's detect_metrics_tamper() detects (expected_hash==0 &&
     * expected_count==0) after decryption and returns 0 (clean) immediately,
     * so the protected APK runs without any manifest/dex verification.
     *
     * The stamp files must still be present in the APK (guard.cpp crashes if
     * they are missing) — only their payload is zeroed, not the files themselves.
     */
    private void writeDisabledStamps(File assetsDir) throws Exception {
        byte[] hashBytes  = new byte[8];   // all zeros → expected_hash  == 0
        byte[] countBytes = new byte[4];   // all zeros → expected_count == 0
        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_metrics.dat"), hashBytes, key, iv);
            writeEncrypted(new File(assetsDir, "font_index.dat"),   countBytes, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
        android.util.Log.i("ApkProtector", "Sentinel stamps written (manifest/dex check DISABLED)");
    }

    /**
     * Computes FNV-1a64 of the compiled user .so and writes the result
     * AES-256-CBC encrypted to assets/font_glyph.dat.
     *
     * guard.cpp's detect_so_tamper() reads this file at:
     *   • fonts_init() — ELF __attribute__((constructor)), before any Java
     *   • Every 4096 lvm_method_exec opcode dispatches (VM pulse)
     *   • The forked background watchdog child (every 5 s)
     *
     * Behaviour:
     *   • Missing font_glyph.dat  → immediate crash_now()
     *   • Hash mismatch            → immediate crash_now()
     *   • Sentinel (hash == 0)     → check skipped (used when SO integrity disabled)
     */
    private void writeNativeSoHash(File soFile, File assetsDir) throws Exception {
        // Read the entire compiled .so
        byte[] soBytes;
        try (java.io.FileInputStream fis = new java.io.FileInputStream(soFile);
             java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) baos.write(buf, 0, n);
            soBytes = baos.toByteArray();
        }

        long hash = fnv1a64(soBytes);

        // Pack as little-endian 8 bytes — same layout guard.cpp uses with memcpy
        byte[] hashBytes = new byte[8];
        for (int i = 0; i < 8; i++) hashBytes[i] = (byte) ((hash >>> (8 * i)) & 0xFF);

        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_glyph.dat"), hashBytes, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
        android.util.Log.i("ApkProtector",
            "SO integrity stamp: hash=0x" + Long.toHexString(hash)
            + " size=" + soBytes.length + " bytes");
    }

    // ── Signature hash helpers ─────────────────────────────────────────────

    /**
     * Extracts the X.509 DER certificate from META-INF/*.RSA (PKCS#7 block),
     * SHA-256s it, AES-256-CBC encrypts the 32-byte digest, and writes it to
     * assets/font_kern.dat.
     *
     * The hash is the SHA-256 of the raw X.509 DER certificate — the same
     * value any cert-viewer tool shows for the signing certificate.
     * guard.cpp parses the same PKCS#7 block at runtime and extracts the
     * identical X.509 DER bytes to verify the hash.
     *
     * Throws if no signing certificate is found (input APK not V1-signed).
     */
    private void writeSignatureHash(File inputApk, File assetsDir) throws Exception {
        byte[] pkcs7   = readPkcs7Blob(inputApk);   // raw META-INF/*.RSA bytes
        byte[] certDer = extractX509Der(pkcs7);      // X.509 DER cert inside PKCS#7
        byte[] digest  = sha256(certDer);
        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_kern.dat"), digest, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }

        // ── Show full SHA-256 — matches cert viewer tools exactly ─────────────
        // report() uses LiveData.postValue() internally. Rapid successive calls
        // from a background thread are coalesced by Android — only the last one
        // reaches the UI. A 120 ms sleep between each line lets the main thread
        // observe each update before the next one fires, so all lines appear.
        String fullHex = bytesToHex(digest, digest.length);
        report(83, "[D2CG] Cert size  : " + certDer.length + " bytes (X.509 DER)");
        try { Thread.sleep(120); } catch (InterruptedException ignored) {}
        report(84, "[D2CG] SHA-256    : " + fullHex);
        try { Thread.sleep(120); } catch (InterruptedException ignored) {}
        report(85, "[D2CG] ✓ Matches cert viewer — verify with:");
        try { Thread.sleep(120); } catch (InterruptedException ignored) {}
        report(86, "[D2CG]   apksigner verify --print-certs your.apk | grep SHA-256");
    }

    /**
     * Extracts the X.509 DER certificate from a PKCS#7 SignedData blob.
     * Uses CertificateFactory which handles the full ASN.1 parsing.
     * Falls back to the raw blob if parsing fails (should never happen for
     * a valid V1-signed APK).
     */
    private static byte[] extractX509Der(byte[] pkcs7) throws Exception {
        try {
            java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(pkcs7);
            java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
            java.util.Collection<? extends java.security.cert.Certificate> certs =
                cf.generateCertificates(bais);
            if (!certs.isEmpty())
                return certs.iterator().next().getEncoded(); // X.509 DER bytes
        } catch (Exception ignored) { /* fall through */ }
        // Fallback: should not reach here for a valid APK
        return pkcs7;
    }

    /**
     * Writes a 32-zero-byte sentinel (AES-encrypted) to assets/font_kern.dat.
     * guard.cpp sees all-zero digest and skips the signature check.
     */
    private void writeDisabledSigHash(File assetsDir) throws Exception {
        byte[] sentinel = new byte[32]; // all zeros
        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_kern.dat"), sentinel, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
    }

    /**
     * Reads the first META-INF/*.RSA / *.DSA / *.EC entry from {@code apk}
     * as raw bytes (the PKCS#7 SignedData blob). Caller must then call
     * extractX509Der() to get the actual X.509 DER certificate inside it.
     *
     * @throws Exception if no signing certificate entry is present (APK not
     *                   V1-signed — user must sign the APK before protection).
     */
    private static byte[] readPkcs7Blob(File apk) throws Exception {
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(apk)) {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry e = entries.nextElement();
                String n = e.getName();
                if (n.startsWith("META-INF/") &&
                        (n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC"))) {
                    try (java.io.InputStream is = zf.getInputStream(e)) {
                        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        int r;
                        while ((r = is.read(buf)) != -1) baos.write(buf, 0, r);
                        byte[] cert = baos.toByteArray();
                        if (cert.length > 0) {
                            android.util.Log.i("ApkProtector",
                                "Cert entry: " + n + " (" + cert.length + " bytes)");
                            return cert;
                        }
                    }
                }
            }
        }
        throw new Exception(
            "No V1 signing certificate found in META-INF/.\n" +
            "The input APK must be signed BEFORE protection.\n" +
            "Sign it externally (e.g. apksigner / Android Studio), then protect.\n" +
            "Do NOT use Ultra Dex2C-VMP's built-in signer — sign first, then protect.\n" +
            "Or disable 'Signature Verification' in Settings to skip this check.");
    }

    /** SHA-256 convenience wrapper. */
    private static byte[] sha256(byte[] data) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data);
    }

    /** Returns the first {@code maxBytes} bytes of {@code b} as a hex string. */
    private static String bytesToHex(byte[] b, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(b.length, maxBytes); i++)
            sb.append(String.format("%02x", b[i] & 0xff));
        return sb.toString();
    }

    /**
     * FNV-1a 64-bit hash. MUST match guard.cpp's fnv1a64() bit-for-bit
     * (same algorithm, same little-endian byte layout when serialised).
     */
    private static long fnv1a64(byte[] data) {
        long h = 0xcbf29ce484222325L; // 14695981039346656037 unsigned as 64-bit bit pattern
        for (byte b : data) {
            h ^= (b & 0xFFL);
            h *= 0x100000001b3L;  // 1099511628211
        }
        return h;
    }

    /** Reads a named entry from a ZIP/APK file into a byte array. */
    private static byte[] readZipEntry(File zipFile, String entryName) throws java.io.IOException {
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(zipFile)) {
            java.util.zip.ZipEntry e = zf.getEntry(entryName);
            if (e == null) return null;
            try (java.io.InputStream in = zf.getInputStream(e)) {
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
                return baos.toByteArray();
            }
        }
    }

    /**
     * Reconstructs the AES-256 key guard.cpp derives via build_key256()
     * (KEY_HI/KEY_LO/K2_HI/K2_LO XOR split). MUST stay in sync with guard.cpp.
     */
    private static byte[] buildGuardKey() {
        int[] keyHi = {0xA1,0x2B,0x1C,0xF4,0x83,0x65,0xC0,0x31,0x57,0xD4,0xE9,0x28,0x15,0x8A,0x44,0x60};
        int[] keyLo = {0x72,0x61,0x67,0x65,0x46,0x4B,0x4F,0x51,0x43,0x6C,0x4A,0x74,0x6C,0x6C,0x69,0x6F};
        int[] k2Hi  = {0xA2,0x76,0xFC,0x0B,0xD9,0x14,0x83,0xEE,0x6B,0xCA,0x39,0x42,0xF1,0xDE,0xB0,0x79};
        int[] k2Lo  = {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
        byte[] key = new byte[32];
        for (int i = 0; i < 16; i++) key[i]      = (byte) (keyHi[i] ^ keyLo[i]);
        for (int i = 0; i < 16; i++) key[16 + i] = (byte) (k2Hi[i]  ^ k2Lo[i]);
        return key;
    }

    /**
     * Reconstructs the AES IV guard.cpp derives via build_iv()
     * (IV_HI/IV_LO XOR split). MUST stay in sync with guard.cpp.
     */
    private static byte[] buildGuardIv() {
        int[] ivHi = {0x27,0xE5,0x58,0x1D,0xD0,0x83,0xF7,0x64,0xA3,0x35,0xC1,0x78,0x82,0x13,0x6A,0x2E};
        int[] ivLo = {0x69,0x69,0x69,0x67,0x65,0x71,0x61,0x69,0x6B,0x66,0x66,0x63,0x66,0x73,0x43,0x5B};
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) iv[i] = (byte) (ivHi[i] ^ ivLo[i]);
        return iv;
    }

    /** AES-256-CBC encrypts {@code plain} (PKCS5 padded) and writes ciphertext to {@code dest}. */
    private static void writeEncrypted(File dest, byte[] plain, byte[] key, byte[] iv) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.IvParameterSpec(iv));
        byte[] enc = cipher.doFinal(plain);
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(enc);
        }
    }

    private File copyToCache(Uri uri, File dir) throws IOException {
        File dest = new File(dir, "input.apk");
        try (InputStream in = context.getContentResolver().openInputStream(uri);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(dest), 1 << 16)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
        return dest;
    }

    // ── VMP helpers ──────────────────────────────────────────────────────────

    /**
     * VMP mode — inject NativeUtil class + per-class classesXInit0 clinit hooks.
     *
     * Reads each VMP shell DEX (which already has selected methods marked
     * ACC_NATIVE) and uses injectCallRegisterNativeInsns to prepend a
     * NativeUtil.classesXInit0(offset) call into every protected class's
     * static initialiser.  The result is written back to dexDir so that
     * Tier1DexPatcher can then inject System.loadLibrary on top of it.
     *
     * The NativeUtil synthetic class (which owns all the classesXInit0 native
     * methods) is merged into classes.dex so it is always available at runtime.
     */
    private void injectVmpNativeUtil(GlobalDexConfig vmpConfig,
                                     File dexDir, String libName) throws IOException {
        List<DexConfig> configs = vmpConfig.getConfigs();
        if (configs.isEmpty()) return;

        Opcodes opcodes = null;
        for (DexConfig cfg : configs) {
            File shellDex = cfg.getShellDexFile();
            if (!shellDex.exists()) {
                android.util.Log.w("ApkProtector",
                        "VMP NativeUtil: shell DEX missing — " + shellDex.getName());
                continue;
            }
            Set<String> handled = cfg.getHandledNativeClasses();
            if (handled == null || handled.isEmpty()) {
                android.util.Log.d("ApkProtector",
                        "VMP NativeUtil: no handled classes for " + cfg.getDexName());
                continue;
            }
            if (opcodes == null) {
                DexBackedDexFile probe = DexBackedDexFile.fromInputStream(
                        null, new BufferedInputStream(new FileInputStream(shellDex)));
                opcodes = probe.getOpcodes();
            }
            // injectCallRegisterNativeInsns reads the shell DEX (methods already native)
            // and prepends classesXInit0(offset) to each protected class's <clinit>.
            DexPool startPool = new DexPool(opcodes);
            List<DexPool> pools = Dex2c.injectCallRegisterNativeInsns(
                    cfg, startPool, Collections.emptySet(), 60000);
            for (int i = 0; i < pools.size(); i++) {
                String name = (i == 0) ? cfg.getDexName() + ".dex"
                        : "classes" + (dexDir.listFiles(
                                f -> f.getName().matches("classes\\d*\\.dex")).length + i) + ".dex";
                File target = new File(dexDir, name);
                Dex2c.writeDexPool035(pools.get(i), target);
                android.util.Log.i("ApkProtector",
                        "VMP NativeUtil: wrote classesInit0-injected DEX → " + target.getName());
            }
        }

        // Inject the NativeUtil synthetic class into classes.dex
        File mainDex = new File(dexDir, "classes.dex");
        if (mainDex.exists()) {
            try {
                List<String> methodNames = new ArrayList<>();
                for (DexConfig cfg : configs) methodNames.add(cfg.getRegisterNativesMethodName());
                String utilType = "L" + configs.get(0).getRegisterNativesClassName() + ";";
                DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                        null, new BufferedInputStream(new FileInputStream(mainDex)));
                DexPool pool = new DexPool(dexFile.getOpcodes());
                for (ClassDef cls : dexFile.getClasses()) pool.internClass(cls);
                pool.internClass(new RegisterNativesUtilClassDef(utilType, methodNames, libName));
                Dex2c.writeDexPool035(pool, mainDex);
                android.util.Log.i("ApkProtector",
                        "VMP NativeUtil: injected NativeUtil ("
                                + methodNames.size() + " method(s)) into classes.dex");
            } catch (Exception e) {
                android.util.Log.e("ApkProtector",
                        "VMP NativeUtil: injection failed — " + e.getMessage(), e);
            }
        }
    }

    /**
     * VMP mode — derive compiledKeys directly from the VMP shell DEX files.
     *
     * VMP's own buildFilter() already respected the user's method-level selection
     * (manual tree: individual method ticks, whole-class ticks, class-list entries)
     * when it produced each shell DEX.  Every method marked ACC_NATIVE in the shell
     * DEX is exactly what the user chose to protect — no filter re-parsing needed.
     *
     * This mirrors how dex2c mode works: compiled.keySet() = exactly what was
     * transpiled.  Here: ACC_NATIVE in shell DEX = exactly what VMP converted.
     *
     * Shell DEX files live in vmpOutDir (inside cSourceDir/vmp/), untouched by
     * injectVmpNativeUtil which only writes to dexDir — so ordering doesn't matter.
     */
    /**
     * Build the set of method keys that VMP actually processed, for use by
     * Tier1DexPatcher as the definitive list of methods to strip + classes to
     * inject System.loadLibrary into.
     *
     * BUG FIX: previously this scanned the SHELL DEX for native methods.  The
     * shell DEX contains every class from the original APK — bystander classes
     * are copied in as-is with their original methods.  Any class that already
     * had a native method before protection (e.g. GMS NativeOnCompleteListener,
     * Firebase classes, JNI wrappers) would be falsely added to compiledKeys,
     * causing Tier1DexPatcher to inject System.loadLibrary into their <clinit>
     * even though we never touched them.
     *
     * Fix: scan the IMPL DEX instead.  The impl DEX contains ONLY the methods
     * that passed filter.acceptMethod() inside splitDex() — exactly the set of
     * methods VMP processed.  Bystander classes and pre-existing native methods
     * from third-party code never appear there.
     */
    private Set<String> buildVmpKeysFromShellDex(GlobalDexConfig vmpConfig)
            throws IOException {
        Set<String> keys = new HashSet<>();

        for (DexConfig cfg : vmpConfig.getConfigs()) {
            // Prefer in-memory impl bytes (already in DexConfig from writeDexPool035)
            // to avoid an extra disk read.
            DexBackedDexFile dex;
            byte[] implBytes = cfg.getImplDexBytes();
            if (implBytes != null) {
                dex = DexBackedDexFile.fromInputStream(null,
                        new java.io.BufferedInputStream(
                                new java.io.ByteArrayInputStream(implBytes)));
            } else {
                File implDex = cfg.getImplDexFile();
                if (!implDex.exists()) {
                    android.util.Log.w("ApkProtector",
                            "VMP impl DEX missing — skipping: " + implDex.getName());
                    continue;
                }
                dex = DexBackedDexFile.fromInputStream(null,
                        new BufferedInputStream(new FileInputStream(implDex)));
            }

            for (DexBackedClassDef cls : dex.getClasses()) {
                String clsType = cls.getType();
                for (com.android.tools.smali.dexlib2.iface.Method m : cls.getMethods()) {
                    String name = m.getName();
                    // <init> / <clinit> are never VMP'd (ART rejects native constructors;
                    // <clinit> is handled by the loadLibrary injection, not stripping).
                    if ("<init>".equals(name) || "<clinit>".equals(name)) continue;
                    StringBuilder key = new StringBuilder(clsType)
                            .append("->").append(name).append("(");
                    for (CharSequence p : m.getParameterTypes()) key.append(p);
                    key.append(")").append(m.getReturnType());
                    keys.add(key.toString());
                }
            }
        }
        android.util.Log.i("ApkProtector",
                "VMP impl DEX keys: " + keys.size() + " → " + keys);
        return keys;
    }

    /**
     * Scan every DEX in dexDir and confirm each compiledKey is present and ACC_NATIVE.
     * Logs a ✓ / ✗ line per method visible in the UI progress log.
     * If any method was NOT stripped a clear warning is shown — never silently succeeds.
     */
    private void verifyStrippedKeys(File dexDir, Set<String> compiledKeys) {
        int ACC_NATIVE = com.android.tools.smali.dexlib2.AccessFlags.NATIVE.getValue();
        // Index: "Lclass;->method(sig)V" → found-and-native?
        Map<String, Boolean> result = new LinkedHashMap<>();
        for (String k : compiledKeys) result.put(k, false);

        File[] dexFiles = dexDir.listFiles((d, n) -> n.matches("classes(\\d*)\\.dex"));
        if (dexFiles != null) {
            for (File dexFile : dexFiles) {
                try {
                    DexBackedDexFile dex = DexBackedDexFile.fromInputStream(
                            null, new BufferedInputStream(new FileInputStream(dexFile)));
                    for (com.android.tools.smali.dexlib2.dexbacked.DexBackedClassDef cls
                            : dex.getClasses()) {
                        String clsType = cls.getType();
                        for (com.android.tools.smali.dexlib2.iface.Method m : cls.getMethods()) {
                            StringBuilder kb = new StringBuilder(clsType)
                                    .append("->").append(m.getName()).append("(");
                            for (CharSequence p : m.getParameterTypes()) kb.append(p);
                            kb.append(")").append(m.getReturnType());
                            String key = kb.toString();
                            if (result.containsKey(key)) {
                                result.put(key, (m.getAccessFlags() & ACC_NATIVE) != 0);
                            }
                        }
                    }
                } catch (Exception e) {
                    android.util.Log.w("ApkProtector", "Strip verify: cannot read " + dexFile.getName() + " — " + e.getMessage());
                }
            }
        }

        int ok = 0, bad = 0;
        for (Map.Entry<String, Boolean> e : result.entrySet()) {
            if (e.getValue()) {
                ok++;
                android.util.Log.i("ApkProtector", "Strip ✓ " + e.getKey());
            } else {
                bad++;
                String msg = "Strip ✗ NOT native: " + e.getKey();
                android.util.Log.w("ApkProtector", msg);
                report(78, msg);
            }
        }
        String summary = bad == 0
                ? "Verify ✓ all " + ok + " method(s) confirmed native"
                : "Verify ✗ " + bad + " method(s) NOT stripped (" + ok + " ok) — check logcat";
        android.util.Log.i("ApkProtector", summary);
        report(78, summary);
    }

    private void copyFile(File src, File dst) throws IOException {
        try (InputStream in  = new BufferedInputStream(new FileInputStream(src), 1 << 16);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(dst), 1 << 16)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }

    private void deleteDir(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDir(f); else f.delete();
        }
        dir.delete();
    }

}
