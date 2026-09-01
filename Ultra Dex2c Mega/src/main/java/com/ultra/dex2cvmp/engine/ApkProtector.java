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

        // A run directory is never shared with another protection request.  The
        // random suffix prevents two rapid selections of the same APK from ever
        // seeing each other's DEX, generated source, object, or packer files.
        File cacheDir = new File(baseCache, "dex2c_mega_" + System.currentTimeMillis()
                + "_" + java.util.UUID.randomUUID());
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
        // This directory is reused by the protection service. Never let a DEX
        // from an earlier run reach the inspection ZIP or the rebuilt APK.
        if (dexDir.exists()) deleteDir(dexDir);
        if (dexDir.exists() || !dexDir.mkdirs()) {
            throw new IOException("Unable to prepare a clean DEX workspace.");
        }
        List<File> dexFiles = extractDexFiles(inputApk, dexDir);
        int restoredBeforeVmp = restoreMissingDexFiles(inputApk, dexDir);
        if (restoredBeforeVmp > 0) {
            report(30, "Restored " + restoredBeforeVmp
                    + " missing original DEX file(s) before VMP injection");
        }
        dexFiles = new ArrayList<>(collectWorkspaceDex(dexDir).values());
        dexFiles.sort(Comparator.comparingInt(ApkProtector::dexOrdinal));
        if (dexFiles.isEmpty()) throw new Exception("No DEX files found in APK.");
        // Preserve the original APK DEX set before VMP adds synthetic gate
        // DEXes. Non-Phantom inspection ZIPs use this list for their focused
        // selected-DEX view; Phantom mode instead archives the complete final
        // DEX workspace after all injections and patches are finished.
        List<File> originalDexFiles = new ArrayList<>(dexFiles);

        // Validate the user's original selections before adding VMP gate DEXes
        // or starting either converter. A missing class must be reported now,
        // rather than causing a conservative all-DEX scan and a long run that
        // cannot protect the requested target.
        try {
            DexTranspiler.validateSelectedClasses(
                    originalDexFiles, filterText, msg -> report(32, msg));
        } catch (IllegalArgumentException missingClass) {
            report(32, "Class validation failed — protection stopped.");
            throw missingClass;
        }

        // ── 5. Transpile APK → C / C++ ───────────────────────────────────────
        // MODE_VMP  : maoabc/nmmp VMP interpreter — custom opcodes + C VM
        // MODE_DEX2C: codehasan/dex2c Python transpiler (default)
        int transpileMode = useVmp ? DexTranspiler.MODE_VMP : DexTranspiler.MODE_DEX2C;
        String modeLabel  = useVmp ? "VMP" : "DEX2C";
        report(35, "Transpiling " + classCount + " class(es) [" + modeLabel + "]…");
        File cSourceDir = new File(cacheDir, "c_src");
        cSourceDir.mkdirs();
        SharedPreferences protectionPrefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        boolean sigCheckEnabled = protectionPrefs.getBoolean(SettingsFragment.KEY_SIG_CHECK, true);
        boolean dexPackerEnabled = protectionPrefs.getBoolean(
                SettingsFragment.KEY_DEX_PACKER, false);
        byte[] signerCipher = buildSignerCipher(inputApk, signOutput, sigCheckEnabled);
        // Phantom consumes a separate copy of the existing encrypted evidence;
        // no plaintext signer digest is added to the bundle.
        byte[] phantomSignerCipher = signerCipher.clone();

        // ── VMP gates: string token + encrypted signer payload ─────────────────
        // Extra DEX files avoid rewriting the input ZIP before conversion.
        File stringGateDexFile = null;
        File signerGateDexFile = null;
        String effectiveFilterText = filterText;
        if (useVmp) {
            try {
                java.security.SecureRandom _gr = new java.security.SecureRandom();
                int gateToken = _gr.nextInt() | 0x01000000;  // non-zero, non-trivial
                GateContext.token   = gateToken;
                GateContext.enabled = true;
                stringGateDexFile = PhStringGateInjector.inject(dexDir, gateToken);
                signerGateDexFile = SignerGateInjector.injectInto(
                        stringGateDexFile, signerCipher);
                // VMP owns both gate classes in one synthetic DEX.
                // SignerGate.part0() through part11()
                // must reach the VMP output; the generated native bridge retrieves
                // the encrypted payload only through those virtualized methods.
                effectiveFilterText = filterText.trim()
                        + "\nclass " + GateContext.CLASS_DESC.replace('/', '.') + " { *; }"
                        + "\nclass " + GateContext.SIGNER_CLASS_DESC.replace('/', '.') + " { *; }";
                report(35, "VMP gate DEX injected: " + stringGateDexFile.getName()
                        + " (PhStringGate + SignerGate)");
            } catch (Exception gateEx) {
                GateContext.enabled = false;
                GateContext.token   = 0;
                throw new Exception("VMP signer gate injection failed.", gateEx);
            }
        } else {
            GateContext.enabled = false;
            GateContext.token   = 0;
            report(35, "DEX2C selected — signer payload will use native C++ only");
        }

        DexTranspiler transpiler = new DexTranspiler(context);
        List<File> gateDexList = null;
        if (stringGateDexFile != null || signerGateDexFile != null) {
            gateDexList = new ArrayList<>(1);
            if (stringGateDexFile != null) gateDexList.add(stringGateDexFile);
            if (signerGateDexFile != null && !gateDexList.contains(signerGateDexFile)) {
                gateDexList.add(signerGateDexFile);
            }
        }
        DexTranspiler.TranspileResult transpileResult = transpiler.transpile(
                inputApk.getAbsolutePath(), effectiveFilterText, cSourceDir,
                transpileMode, msg -> report(40, msg), dexFiles, gateDexList);

        int transpiled = transpileResult != null ? transpileResult.successCount() : 0;

        if (transpileResult != null) {
            for (String e : transpileResult.errors) {
                report(42, "  " + e);
                if (e.startsWith("registration_error:")) {
                    throw new Exception("DEX2C native registration source generation failed: " + e);
                }
            }
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
        Set<String> compiledKeys = new HashSet<>();
        if (useVmp) {
            if (transpileResult == null || transpileResult.vmpConfig == null) {
                throw new Exception("VMP output is missing; refusing to build.");
            }
            Set<String> vmpKeys = buildVmpKeysFromShellDex(transpileResult.vmpConfig);
            Set<String> missingRequested = new LinkedHashSet<>(
                    transpileResult.requestedVmpMethodKeys);
            missingRequested.removeAll(vmpKeys);
            if (!missingRequested.isEmpty()) {
                throw new Exception("VMP omitted " + missingRequested.size()
                        + " selected method(s); refusing to continue: "
                        + missingRequested);
            }
            if (!transpileResult.requestedVmpMethodKeys.isEmpty()) {
                report(54, "VMP: verified "
                        + transpileResult.requestedVmpMethodKeys.size()
                        + " exact selected method(s) reached native output");
            }
            report(54, "VMP: injecting NativeUtil class into DEX…");
            injectVmpNativeUtil(transpileResult.vmpConfig, dexDir, libName,
                    originalDexFiles.size() > 1, stringGateDexFile);
            report(54, "VMP: NativeUtil + classesInit0 hooks injected");
            compiledKeys.addAll(vmpKeys);
            verifySignerGateVirtualized(vmpKeys);
            report(54, "VMP: SignerGate.part0()–part11() virtualized");
            report(54, "VMP: " + compiledKeys.size() + " method(s) targeted for native strip");
        } else {
            int dex2cMethods = 0;
            for (String key : transpileResult.compiled.keySet()) {
                if (key.contains("->")) {
                    compiledKeys.add(key);
                    dex2cMethods++;
                }
            }
            report(54, "DEX2C: " + dex2cMethods + " application method(s) targeted for native strip");
        }

        // Target class descriptors derived from compiled method keys.
        Set<String> targetTypes = new HashSet<>();
        for (String k : compiledKeys) {
            int arrow = k.indexOf("->");
            if (arrow > 0) targetTypes.add(k.substring(0, arrow));
        }

        // ── 5.5a–d. Static String field encryption (toggled by Settings) ────────
        // When OFF: field initializers stay in the DEX as-is, no ph_strings.cpp,
        // no field stripping, no inline-literal obfuscation. Behaviour is identical
        // to a version of the engine that never had string encryption.
        boolean stringEncryptEnabled = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(SettingsFragment.KEY_STRING_ENCRYPT, true);
        Map<String, List<NativeStringGen.StringEntry>> strTable = new java.util.HashMap<>();
        Set<String> classesWithStrings = new java.util.HashSet<>();

        if (stringEncryptEnabled) {
            // ── 5.5a. Pre-scan: read static String field values BEFORE patchAll ──
            // patchAll modifies dexFiles in-place; we must read them now while they
            // still contain the original static_values entries.
            report(55, "Scanning static String fields in target classes…");
            strTable = scanStaticStrings(dexFiles, targetTypes);
            classesWithStrings = strTable.keySet();
            if (!classesWithStrings.isEmpty()) {
                int strTotal = 0;
                for (List<NativeStringGen.StringEntry> v : strTable.values()) strTotal += v.size();
                report(56, "Found " + strTotal + " String field(s) in "
                        + classesWithStrings.size() + " class(es) — will strip + encrypt");
            }
        } else {
            report(55, "String field encryption OFF — field initializers kept as-is in DEX");
        }

        // ── 5.5b. Strip DEX bytecode (methods → ACC_NATIVE, String values → null) ──
        // classesWithStrings is empty when encryption is OFF, so patchAll skips
        // all field stripping but still converts method bodies to ACC_NATIVE stubs.
        report(57, "Patching " + compiledKeys.size() + " method(s) → ACC_NATIVE stubs…");
        int stripped = Tier1DexPatcher.patchAll(dexDir, compiledKeys, libName,
                classesWithStrings, msg -> report(58, msg));
        report(59, "Stripped " + stripped + " method(s)");

        if (!compiledKeys.isEmpty()) {
            report(59, "Verifying " + compiledKeys.size() + " method stubs…");
            verifyStrippedKeys(dexDir, compiledKeys);
            report(59, "Verification passed — all stubs confirmed ACC_NATIVE");
        }

        if (stringEncryptEnabled) {
            // ── 5.5c. Generate ph_strings.cpp into cSourceDir (compiled in step 6) ──
            if (!strTable.isEmpty()) {
                NativeStringGen.generate(strTable, cSourceDir);
                report(59, "ph_strings.cpp generated — string injection baked into .so");
                // Patch jni_init.cpp to call ph_strings_register(env) from JNI_OnLoad.
                patchJniInitForStrings(cSourceDir);
            }

            // ── 5.5d. Obfuscate inline NewStringUTF literals in transpiled C++ ───
            // Replaces env->NewStringUTF("literal") with XOR-decrypt calls so no
            // plaintext string reaches the compiler or lands in .rodata.
            try {
                int obfCount = DexStringObfuscator.obfuscate(cSourceDir);
                if (obfCount > 0) {
                    report(59, "Obfuscated " + obfCount
                            + " inline string literal(s) in transpiled C++ → no plaintext in .rodata");
                }
            } catch (Exception obfEx) {
                report(59, "String literal obfuscation warning (non-fatal): " + obfEx.getMessage());
                android.util.Log.w("DexStringObf", "obfuscate() failed", obfEx);
            }
        }

        // DEX2C stores the encrypted signer payload in native C++. VMP keeps it
        // in the injected SignerGate class and recovers it through VMP opcodes.
        File signerBridgeSource = SignerGateNativeGen.generate(cSourceDir, useVmp, signerCipher);
        java.util.Arrays.fill(signerCipher, (byte) 0);
        if (!signerBridgeSource.isFile() || signerBridgeSource.length() == 0) {
            throw new Exception("Signer bridge source was not generated.");
        }
        report(59, useVmp
                ? "VMP signer gate generated — encrypted SHA-256 recovered through vmCode"
                : "Native signer payload generated — encrypted SHA-256 stays in C++");

        if (dexPackerEnabled) {
            // The transpilers may operate on only the selected/hot DEX files, but
            // the inspection ZIP and Phantom payload require the complete runtime
            // set. Restore only missing originals; never overwrite patched DEXes.
            int restoredOriginalDex = restoreMissingDexFiles(inputApk, dexDir);
            report(59, restoredOriginalDex == 0
                    ? "Final DEX workspace contains all original DEX files"
                    : "Restored " + restoredOriginalDex
                            + " missing original DEX file(s) before inspection ZIP");
        }

        // ── 5.5d. Export the final DEX set for inspection ─────────────────────
        //
        // With Phantom packer enabled, the inspection ZIP must mirror the complete
        // protected DEX workspace before encryption: original DEXes, injected VMP
        // gate DEXes, NativeUtil/support DEXes, and any overflow shards. The packer
        // consumes this same final set and bundles every classes*.dex file.
        //
        // Without the packer, retain the smaller focused ZIP containing only final
        // DEXes that contain selected target classes.
        if (dexPackerEnabled) {
            String modeTag = useVmp ? "vmp" : "dex2c";
            File strippedDexZip = exportStrippedDexZip(
                    dexDir, modeTag, targetTypes, originalDexFiles, true);
            if (strippedDexZip != null) {
                int finalDexCount = collectWorkspaceDex(dexDir).size();
                report(59, "Stripped DEX [" + finalDexCount + " file(s)] → "
                        + strippedDexZip.getName()
                        + " (" + (strippedDexZip.length() / 1024) + " KB) — open to verify");
            }
        } else {
            report(59, "Phantom packer OFF — skipping stripped DEX ZIP export");
        }

        // ── 6. Compile C++ → .so  (all ABIs in parallel) ─────────────────────
        // Both ABIs run at the same time, but they share one compiler-process
        // budget. Without this semaphore each ABI could create a full
        // RAM-aware clang pool, oversubscribing CPU and memory on-device.
        report(55, "Compiling native library for " + targetAbis.size() + " ABI(s)…");
        File libsDir = new File(cacheDir, "libs");

        // DexOpcodes.h is generated once per VMP run and consumed by every ABI.
        // Install it before the parallel ABI tasks start: compiler_headers is shared,
        // so per-ABI replacement races can otherwise produce a spurious IOException
        // or expose a partially replaced header to clang.
        if (useVmp) {
            ndk.prepareVmpHeaders(cSourceDir, new NdkBuilder.BuildCallback() {
                public void onProgress(String m) { report(55, m); }
                public void onLog(String l) {}
            });
        }

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

        // Keep both ABI queues moving while ensuring the total number of live
        // clang processes never exceeds four. If the device exposes fewer CPU
        // cores, lower the shared budget accordingly. With two ABIs this gives
        // the intended 2 workers per ABI on normal 4+ core devices.
        final int sharedNativeWorkers = Math.max(1, Math.min(4,
                Runtime.getRuntime().availableProcessors()));
        final int perAbiWorkers = targetAbis.size() > 1
                ? Math.max(1, sharedNativeWorkers / targetAbis.size())
                : sharedNativeWorkers;
        final Semaphore sharedAbiWorkerSlots = new Semaphore(sharedNativeWorkers);
        report(55, "Shared native worker budget: " + sharedNativeWorkers
                + " total (" + perAbiWorkers + " per ABI)");

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
                        }, perAbiWorkers, sharedAbiWorkerSlots);
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

        // Read the remaining prefs once — used in stamps and in the final packer step.
        SharedPreferences prefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        boolean manifestDexEnabled  = prefs.getBoolean(SettingsFragment.KEY_MANIFEST_DEX_CHECK, true);
        // Keep the Settings-tab control: it affects only the signer decision,
        // never the selected VMP/DEX2C engine.
        sigCheckEnabled             = prefs.getBoolean(SettingsFragment.KEY_SIG_CHECK,          true);

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
                        rawManifest, DexPacker.PROXY_APP, true);
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

        // The signer ciphertext was embedded before native compilation. It is
        // never emitted as an APK asset. The Settings toggle controls whether
        // the generated payload is enforcement-enabled.
        report(83, sigCheckEnabled
                ? "Signer gate embedded in native protection output"
                : "Signature verification disabled by Settings");

        report(85, "Rebuilding APK — merging DEX + .so + assets…");
        File outputApk = buildOutputPath(signOutput);
        ApkRebuilder.rebuild(inputApk, outputApk, dexDir, libsDir, assetsDir,
                msg -> report(87, msg));
        report(92, "APK assembled (" + (outputApk.length() / 1024) + " KB)");

        if (dexPackerEnabled) {
            // ApkRebuilder can restore a missing original DEX directly into the
            // intermediate APK. Reconcile that complete APK back into the direct
            // Phantom workspace so fallback-only files cannot be omitted.
            int reconciledDex = reconcileDexWorkspace(outputApk, dexDir);
            report(92, "Verified complete final DEX set (" + reconciledDex
                    + " file(s)) for Phantom");
        }

        // Phantom packing changes the ZIP after this assembly.  Signing here
        // would create a disposable signature and waste a full apksig pass, so
        // packed outputs are signed only once after their final ZIP is written.
        if (signOutput && !dexPackerEnabled) {
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

            // The final, stripped DEX files are already in this job's clean
            // workspace.  Give them directly to the packer instead of extracting
            // the freshly rebuilt APK a second time.
            try {
                new DexPacker(context).pack(outputApk, packedUnsigned, packWorkDir,
                        dexDir, blockRootedDevices, phantomSignerCipher);
            } finally {
                java.util.Arrays.fill(phantomSignerCipher, (byte) 0);
            }
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
        } else {
            java.util.Arrays.fill(phantomSignerCipher, (byte) 0);
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
    /**
     * Patches jni_init.cpp (generated by GlobalDexConfig / VMP transpiler) to call
     * ph_strings_register(env) from JNI_OnLoad, before the final return statement.
     * This guarantees phStrInject natives are registered via RegisterNatives — reliable
     * regardless of ART's static Java_* lookup or LLD --gc-sections dead-stripping.
     */
    private void patchJniInitForStrings(File cSourceDir) {
        // VMP mode generates jni_init.cpp; DEX2C mode generates jni_onload.cpp.
        // Try both so ph_strings_register(env) is injected into JNI_OnLoad
        // regardless of which mode was used.
        File jniInit = new File(cSourceDir, "jni_init.cpp");
        if (!jniInit.exists()) {
            jniInit = new File(cSourceDir, "jni_onload.cpp");  // DEX2C fallback
        }
        if (!jniInit.exists()) {
            android.util.Log.w("ApkProtector",
                    "patchJniInitForStrings: neither jni_init.cpp nor jni_onload.cpp found — skipping");
            return;
        }
        final String fileName = jniInit.getName();
        try {
            String src = new String(java.nio.file.Files.readAllBytes(jniInit.toPath()),
                    java.nio.charset.StandardCharsets.UTF_8);

            // Already patched (idempotent)
            if (src.contains("ph_strings_register")) return;

            // 1. Insert extern declaration after the last #include line so it
            //    appears after all system headers (avoids forward-decl ordering issues).
            String externDecl = "extern \"C\" void ph_strings_register(JNIEnv* env);\n";
            int lastIncludeEnd = 0;
            int search = 0;
            while (true) {
                int found = src.indexOf("#include", search);
                if (found < 0) break;
                int eol = src.indexOf('\n', found);
                if (eol < 0) eol = src.length() - 1;
                lastIncludeEnd = eol + 1;
                search = eol + 1;
            }
            src = src.substring(0, lastIncludeEnd) + externDecl + src.substring(lastIncludeEnd);

            // 2. Insert call before the last "return JNI_VERSION_1_6;"
            //    NdkBuilder.patchJniOnload() uses the same anchor so this call
            //    ends up just before both guard bootstrap and the return statement.
            String returnStmt = "return JNI_VERSION_1_6;";
            int retIdx = src.lastIndexOf(returnStmt);
            if (retIdx >= 0) {
                src = src.substring(0, retIdx)
                        + "ph_strings_register(env);\n    "
                        + src.substring(retIdx);
            } else {
                android.util.Log.w("ApkProtector",
                        "patchJniInitForStrings: 'return JNI_VERSION_1_6;' not found in "
                        + fileName + " — ph_strings_register not injected");
            }

            java.nio.file.Files.write(jniInit.toPath(),
                    src.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            android.util.Log.i("ApkProtector",
                    "patchJniInitForStrings: ph_strings_register injected into " + fileName + " ✓");
        } catch (Exception e) {
            android.util.Log.e("ApkProtector",
                    "patchJniInitForStrings failed (" + fileName + "): " + e.getMessage());
        }
    }

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
     * Writes the inspection ZIP to
     * /sdcard/Ultra Dex2C-VMP/stripped_dex_<mode>_<ts>.zip.
     *
     * When the Phantom packer is enabled, every final classes*.dex file is included:
     * original DEXes, injected gate/support DEXes, and overflow shards. This makes
     * the ZIP the complete pre-encryption DEX payload that the packer consumes.
     *
     * When the packer is disabled, both DEX2C and VMP keep the focused inspection
     * behavior and include only final original DEXes containing selected classes.
     *
     * @param dexDir  directory containing the final stripped classes*.dex files
     * @param mode    label embedded in the zip name — "dex2c" or "vmp"
     * @param targetTypes  class descriptors selected for native protection
     * @param originalDexFiles  DEX files extracted from the input APK before
     *                          synthetic gate DEX injection
     * @param includeCompleteDexSet whether Phantom packer mode requires every final
     *                               classes*.dex file in the archive
     * @return the written zip file, or null if nothing was zipped
     */
    private File exportStrippedDexZip(File dexDir, String mode,
                                      Set<String> targetTypes,
                                       List<File> originalDexFiles,
                                       boolean includeCompleteDexSet) {
        try {
            if (dexDir == null || !dexDir.isDirectory()) {
                android.util.Log.w("ApkProtector",
                        "Final DEX workspace unavailable for inspection ZIP");
                return null;
            }

            List<File> selectedDexFiles = new ArrayList<>();
            if (includeCompleteDexSet) {
                // The Phantom packer scans this exact filename contract. Use the
                // same contract here so the diagnostic archive cannot silently
                // omit an injected or overflow DEX shard.
                File[] finalDexFiles = dexDir.listFiles(
                        f -> f.isFile() && f.getName().matches("classes\\d*\\.dex"));
                if (finalDexFiles != null) {
                    selectedDexFiles.addAll(Arrays.asList(finalDexFiles));
                }
                if (selectedDexFiles.isEmpty()) {
                    android.util.Log.w("ApkProtector",
                            "No final classes*.dex files available for complete inspection ZIP");
                    return null;
                }
            } else {
                if (targetTypes == null || targetTypes.isEmpty()
                        || originalDexFiles == null || originalDexFiles.isEmpty()) {
                    android.util.Log.w("ApkProtector",
                            "No selected original DEX files available for inspection ZIP");
                    return null;
                }

                for (File originalDex : originalDexFiles) {
                    if (originalDex == null
                            || !originalDex.getName().matches("classes\\d*\\.dex")) continue;
                    File finalDex = new File(dexDir, originalDex.getName());
                    if (finalDex.isFile() && dexContainsAnyTarget(finalDex, targetTypes)) {
                        selectedDexFiles.add(finalDex);
                    }
                }
            }

            if (selectedDexFiles.isEmpty()) {
                android.util.Log.w("ApkProtector",
                        includeCompleteDexSet
                                ? "No final DEX files available for inspection ZIP"
                                : "No original DEX contains the selected protection classes");
                return null;
            }

            selectedDexFiles.sort(Comparator.comparingInt(ApkProtector::dexOrdinal));

            File outDir = new File(Environment.getExternalStorageDirectory(), "Ultra Dex2C-VMP");
            outDir.mkdirs();
            File zip = new File(outDir,
                    "stripped_dex_" + mode + "_" + System.currentTimeMillis() + ".zip");

            try (ZipOutputStream zos = new ZipOutputStream(
                    new BufferedOutputStream(new FileOutputStream(zip)))) {
                for (File dex : selectedDexFiles) {
                    zos.putNextEntry(new ZipEntry(dex.getName()));
                    try (FileInputStream fis = new FileInputStream(dex)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = fis.read(buf)) != -1) zos.write(buf, 0, n);
                    }
                    zos.closeEntry();
                }
            }
            android.util.Log.i("ApkProtector",
                    "Inspection ZIP includes " + selectedDexFiles.size()
                            + " final DEX file(s)"
                            + (includeCompleteDexSet ? " (complete Phantom payload set)" : ""));
            android.util.Log.i("ApkProtector",
                    "Inspection ZIP DEX inventory: "
                            + sortedDexNames(selectedDexFiles.stream()
                                    .map(File::getName)
                                    .collect(java.util.stream.Collectors.toList())));
            return zip;
        } catch (Exception e) {
            android.util.Log.w("ApkProtector",
                    "exportStrippedDexZip failed: " + e.getMessage());
            return null;
        }
    }

    /** Canonical classes.dex/classes2.dex/classes3.dex ordering. */
    private static int dexOrdinal(File dex) {
        String name = dex.getName();
        if ("classes.dex".equals(name)) return 1;
        try {
            return Integer.parseInt(name.substring("classes".length(), name.length() - 4));
        } catch (Exception ignored) {
            return Integer.MAX_VALUE;
        }
    }

    private boolean dexContainsAnyTarget(File dexFile, Set<String> targetTypes) {
        try (InputStream in = new BufferedInputStream(new FileInputStream(dexFile))) {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(null, in);
            for (ClassDef cls : dex.getClasses()) {
                if (targetTypes.contains(cls.getType())) return true;
            }
        } catch (Exception e) {
            android.util.Log.w("ApkProtector",
                    "Unable to inspect " + dexFile.getName() + " for selected classes: "
                            + e.getMessage());
        }
        return false;
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

    /**
     * Restore original DEX entries that are absent from the mutable final
     * workspace. Existing entries are transformed/patched output and remain
     * authoritative, so this method is deliberately additive.
     */
    private int restoreMissingDexFiles(File sourceApk, File dexDir) throws IOException {
        Map<String, String> sourceDex = collectDexEntries(sourceApk);
        Map<String, File> workspaceDex = collectWorkspaceDex(dexDir);
        int restored = 0;

        try (ZipFile zip = new ZipFile(sourceApk)) {
            for (Map.Entry<String, String> item : sourceDex.entrySet()) {
                if (workspaceDex.containsKey(item.getKey())) continue;
                ZipEntry entry = zip.getEntry(item.getValue());
                if (entry == null) {
                    throw new IOException("Original DEX entry disappeared: " + item.getValue());
                }
                File destination = new File(dexDir, item.getKey());
                copyDexEntry(zip, entry, destination);
                workspaceDex.put(item.getKey(), destination);
                restored++;
                android.util.Log.i("ApkProtector",
                        "Restored missing original DEX into final workspace: "
                                + item.getKey());
            }
        }

        if (!workspaceDex.keySet().containsAll(sourceDex.keySet())) {
            throw new IOException("Unable to restore complete original DEX set: expected="
                    + sortedDexNames(sourceDex.keySet()) + " workspace="
                    + sortedDexNames(workspaceDex.keySet()));
        }
        return restored;
    }

    /**
     * Make the direct Phantom workspace byte-for-byte equivalent to the DEX
     * entries in the rebuilt APK. The rebuilt APK is authoritative because it
     * includes ApkRebuilder fallback entries as well as every patched DEX.
     */
    private int reconcileDexWorkspace(File rebuiltApk, File dexDir) throws IOException {
        Map<String, String> apkDex = collectDexEntries(rebuiltApk);
        if (apkDex.isEmpty()) {
            throw new IOException("Rebuilt APK contains no classes*.dex entries.");
        }
        Map<String, File> workspaceDex = collectWorkspaceDex(dexDir);

        try (ZipFile zip = new ZipFile(rebuiltApk)) {
            for (Map.Entry<String, String> item : apkDex.entrySet()) {
                String name = item.getKey();
                ZipEntry entry = zip.getEntry(item.getValue());
                if (entry == null) {
                    throw new IOException("Rebuilt APK DEX entry disappeared: " + item.getValue());
                }
                File workspaceFile = workspaceDex.get(name);
                if (workspaceFile == null || !sameFileBytes(zip, entry, workspaceFile)) {
                    File destination = new File(dexDir, name);
                    copyDexEntry(zip, entry, destination);
                    workspaceDex.put(name, destination);
                    android.util.Log.i("ApkProtector",
                            (workspaceFile == null ? "Restored" : "Refreshed")
                                    + " Phantom workspace DEX from rebuilt APK: " + name);
                }
            }
        }

        List<String> workspaceOnly = new ArrayList<>();
        for (String name : workspaceDex.keySet()) {
            if (!apkDex.containsKey(name)) workspaceOnly.add(name);
        }
        if (!workspaceOnly.isEmpty()) {
            throw new IOException("Final DEX workspace contains file(s) absent from rebuilt APK: "
                    + sortedDexNames(workspaceOnly));
        }

        Map<String, File> verified = collectWorkspaceDex(dexDir);
        if (!verified.keySet().equals(apkDex.keySet())) {
            throw new IOException("Final DEX set mismatch before Phantom packing: APK="
                    + sortedDexNames(apkDex.keySet()) + " workspace="
                    + sortedDexNames(verified.keySet()));
        }

        try (ZipFile zip = new ZipFile(rebuiltApk)) {
            for (Map.Entry<String, String> item : apkDex.entrySet()) {
                ZipEntry entry = zip.getEntry(item.getValue());
                File workspaceFile = verified.get(item.getKey());
                if (entry == null || workspaceFile == null
                        || !sameFileBytes(zip, entry, workspaceFile)) {
                    throw new IOException("Final DEX bytes differ after reconciliation: "
                            + item.getKey());
                }
            }
        }

        android.util.Log.i("ApkProtector",
                "Verified Phantom DEX inventory: " + sortedDexNames(verified.keySet()));
        return verified.size();
    }

    /**
     * Return canonical DEX name -> actual ZIP entry name. Normalizing a leading
     * "./" keeps this consistent with ApkRebuilder and FastZip.
     */
    private Map<String, String> collectDexEntries(File apk) throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                String actual = entry.getName();
                String bare = actual.startsWith("./") ? actual.substring(2) : actual;
                if (!bare.matches("classes\\d*\\.dex")) continue;
                if (result.put(bare, actual) != null) {
                    throw new IOException("Duplicate normalized DEX entry in APK: " + bare);
                }
            }
        }
        return result;
    }

    private Map<String, File> collectWorkspaceDex(File dexDir) throws IOException {
        Map<String, File> result = new LinkedHashMap<>();
        File[] files = dexDir.listFiles(
                f -> f.isFile() && f.getName().matches("classes\\d*\\.dex"));
        if (files == null) return result;
        for (File file : files) {
            if (result.put(file.getName(), file) != null) {
                throw new IOException("Duplicate DEX filename in final workspace: "
                        + file.getName());
            }
        }
        return result;
    }

    private void copyDexEntry(ZipFile zip, ZipEntry entry, File destination)
            throws IOException {
        File parent = destination.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("Unable to create DEX workspace directory: " + parent);
        }
        File temp = new File(parent, destination.getName() + ".restore");
        try {
            try (InputStream in = new BufferedInputStream(zip.getInputStream(entry));
                 OutputStream out = new BufferedOutputStream(new FileOutputStream(temp))) {
                byte[] buffer = new byte[65536];
                int count;
                while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
            }
            try {
                Files.move(temp.toPath(), destination.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temp.toPath(), destination.toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            if (temp.exists()) temp.delete();
        }
    }

    private boolean sameFileBytes(ZipFile zip, ZipEntry entry, File file)
            throws IOException {
        if (!file.isFile() || (entry.getSize() >= 0 && entry.getSize() != file.length())) {
            return false;
        }
        try (InputStream zipIn = new BufferedInputStream(zip.getInputStream(entry));
             InputStream fileIn = new BufferedInputStream(new FileInputStream(file))) {
            byte[] zipBuffer = new byte[65536];
            byte[] fileBuffer = new byte[65536];
            while (true) {
                int zipCount = zipIn.read(zipBuffer);
                int fileCount = fileIn.read(fileBuffer);
                if (zipCount != fileCount) return false;
                if (zipCount == -1) return true;
                for (int i = 0; i < zipCount; i++) {
                    if (zipBuffer[i] != fileBuffer[i]) return false;
                }
            }
        }
    }

    private List<String> sortedDexNames(Collection<String> names) {
        List<String> sorted = new ArrayList<>(names);
        sorted.sort((a, b) -> {
            int order = Integer.compare(dexOrdinal(new File(a)), dexOrdinal(new File(b)));
            return order != 0 ? order : a.compareTo(b);
        });
        return sorted;
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

    // ── Signer gate helpers ─────────────────────────────────────────────────

    /**
     * Builds the exact 48-byte AES-CBC payload consumed by guard.cpp. Generated
     * native C++ receives this encrypted value, never the plaintext certificate hash.
     */
    private byte[] buildSignerCipher(File inputApk, boolean signOutput,
                                     boolean signatureVerificationEnabled) throws Exception {
        if (!signatureVerificationEnabled) {
            // The guard decrypts before checking the sentinel, so this must be
            // AES-CBC(ciphertext of 32 zero bytes), not literal zero ciphertext.
            report(35, "Signature verification disabled — no signer SHA-256 will be protected.");
            byte[] key = buildGuardKey();
            byte[] iv = buildGuardIv();
            try {
                return encryptGuardPayload(new byte[32], key, iv);
            } finally {
                java.util.Arrays.fill(key, (byte) 0);
                java.util.Arrays.fill(iv, (byte) 0);
            }
        }
        byte[] certDer;
        String certificateSource;
        if (signOutput) {
            // The final APK uses the built-in signer, so bind the gate to that
            // certificate rather than the incoming APK's certificate.
            certDer = ApkSigner.getSigningCertDer(context);
            certificateSource = "output signer";
        } else {
            byte[] pkcs7 = readPkcs7Blob(inputApk);
            certDer = extractX509Der(pkcs7);
            java.util.Arrays.fill(pkcs7, (byte) 0);
            certificateSource = "uploaded APK";
        }

        byte[] digest = sha256(certDer);
        reportSignerFingerprint(certificateSource, certDer.length, digest);
        byte[] key = buildGuardKey();
        byte[] iv = buildGuardIv();
        try {
            byte[] cipher = encryptGuardPayload(digest, key, iv);
            if (cipher.length != GateContext.SIGNER_CIPHER_BYTES) {
                throw new Exception("Signer payload must be 48 bytes after AES-CBC padding.");
            }
            return cipher;
        } finally {
            java.util.Arrays.fill(certDer, (byte) 0);
            java.util.Arrays.fill(digest, (byte) 0);
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv, (byte) 0);
        }
    }

    /**
     * Reports the complete certificate fingerprint as distinct progress events.
     * The protection UI receives callbacks from a worker thread through
     * LiveData, which can coalesce back-to-back updates. Small gaps preserve all
     * lines in the visible build log, including the full 64-character SHA-256.
     */
    private void reportSignerFingerprint(String certificateSource, int certLength, byte[] digest) {
        String fullHex = bytesToHex(digest, digest.length);
        String prefix = "[D2CG] " + certificateSource;
        report(35, prefix + " cert size  : " + certLength + " bytes (X.509 DER)");
        pauseProgressReport();
        report(36, prefix + " SHA-256    : " + fullHex);
        android.util.Log.i("ApkProtector",
                "Signer SHA-256 (" + certificateSource + "): " + fullHex);
        pauseProgressReport();
        report(37, prefix + " ✓ protecting this certificate in native C++");
    }

    private static void pauseProgressReport() {
        try {
            Thread.sleep(120);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
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
            "Sign it externally (e.g. apksigner / Android Studio), then protect.");
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

    /** AES-CBC helper for data embedded into generated native/VMP sources. */
    private static byte[] encryptGuardPayload(byte[] plain, byte[] key, byte[] iv) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.IvParameterSpec(iv));
        return cipher.doFinal(plain);
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
     * methods) is merged into the combined synthetic gate DEX for multidex APKs.
     * Single-D​​EX APKs retain the primary-D​​EX compatibility fallback.
     */
    private void injectVmpNativeUtil(GlobalDexConfig vmpConfig,
                                     File dexDir, String libName,
                                     boolean originalApkWasMultidex,
                                     File combinedGateDex) throws IOException {
        List<DexConfig> configs = vmpConfig.getConfigs();
        if (configs.isEmpty()) return;

        long installStarted = System.nanoTime();
        int installedDexCount = 0;
        Opcodes opcodes = null;
        for (DexConfig cfg : configs) {
            Set<String> handled = cfg.getHandledNativeClasses();
            if (handled == null || handled.isEmpty()) {
                android.util.Log.d("ApkProtector",
                        "VMP NativeUtil: no handled classes for " + cfg.getDexName());
                continue;
            }

            // Fast path: Dex2c finalized the classesInit0 hooks immediately after
            // JNI generation, while the shell classes were still in memory.
            // Installing those files is a copy, not a second full DEX rebuild.
            List<File> finalizedShellDexes = cfg.getFinalizedShellDexFiles();
            if (finalizedShellDexes != null && !finalizedShellDexes.isEmpty()) {
                for (int i = 0; i < finalizedShellDexes.size(); i++) {
                    File source = finalizedShellDexes.get(i);
                    if (!source.isFile()) {
                        throw new IOException("Finalized VMP shell DEX missing: " + source.getName());
                    }
                    String name = (i == 0) ? cfg.getDexName() + ".dex"
                            : GateContext.nextSyntheticDexFile(dexDir).getName();
                    File target = new File(dexDir, name);
                    Files.copy(source.toPath(), target.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                    installedDexCount++;
                    android.util.Log.i("ApkProtector",
                            "VMP NativeUtil: installed pre-injected DEX → " + target.getName());
                }
                continue;
            }

            // Compatibility fallback for an older/externally-created DexConfig.
            File shellDex = cfg.getShellDexFile();
            if (!shellDex.exists()) {
                android.util.Log.w("ApkProtector",
                        "VMP NativeUtil: shell DEX missing — " + shellDex.getName());
                continue;
            }
            if (opcodes == null) {
                DexBackedDexFile probe = DexBackedDexFile.fromInputStream(
                        null, new BufferedInputStream(new FileInputStream(shellDex)));
                opcodes = probe.getOpcodes();
            }
            DexPool startPool = new DexPool(opcodes);
            List<DexPool> pools = Dex2c.injectCallRegisterNativeInsns(
                    cfg, startPool, Collections.emptySet(), 60000);
            for (int i = 0; i < pools.size(); i++) {
                String name = (i == 0) ? cfg.getDexName() + ".dex"
                        : GateContext.nextSyntheticDexFile(dexDir).getName();
                File target = new File(dexDir, name);
                Dex2c.writeDexPool035(pools.get(i), target);
                installedDexCount++;
                android.util.Log.i("ApkProtector",
                        "VMP NativeUtil: wrote classesInit0-injected DEX → " + target.getName());
            }
        }
        long installMs = (System.nanoTime() - installStarted) / 1_000_000L;
        report(54, "VMP: installed " + installedDexCount
                + " pre-injected shell DEX(es) in " + installMs + " ms");

        // Multidex APKs do not require NativeUtil to live in the primary DEX.
        // Merge it into the already-small combined gate DEX instead of
        // creating another support DEX or rewriting a large application DEX.
        if (originalApkWasMultidex) {
            if (combinedGateDex == null) {
                throw new IOException("VMP combined gate DEX is unavailable.");
            }
            File gateDex = new File(dexDir, combinedGateDex.getName());
            if (!gateDex.isFile()) {
                throw new IOException("VMP combined gate DEX is missing: "
                        + gateDex.getName());
            }

            long supportStarted = System.nanoTime();
            String utilType = "L" + configs.get(0).getRegisterNativesClassName() + ";";
            List<String> methodNames = new ArrayList<>();
            for (DexConfig cfg : configs) {
                methodNames.add(cfg.getRegisterNativesMethodName());
            }

            DexBackedDexFile gateDexFile;
            try (BufferedInputStream input = new BufferedInputStream(
                    new FileInputStream(gateDex))) {
                gateDexFile = DexBackedDexFile.fromInputStream(null, input);
            }

            boolean foundStringGate = false;
            boolean foundSignerGate = false;
            boolean foundNativeUtil = false;
            DexPool combinedPool = new DexPool(gateDexFile.getOpcodes());
            for (ClassDef cls : gateDexFile.getClasses()) {
                String type = cls.getType();
                foundStringGate |= ("L" + GateContext.CLASS_DESC + ";").equals(type);
                foundSignerGate |= ("L" + GateContext.SIGNER_CLASS_DESC + ";").equals(type);
                foundNativeUtil |= utilType.equals(type);
                combinedPool.internClass(cls);
            }
            if (!foundStringGate || !foundSignerGate) {
                throw new IOException("Combined gate DEX is missing "
                        + (!foundStringGate ? "PhStringGate" : "")
                        + (!foundStringGate && !foundSignerGate ? " and " : "")
                        + (!foundSignerGate ? "SignerGate" : ""));
            }
            if (foundNativeUtil) {
                throw new IOException("Combined gate DEX already contains NativeUtil.");
            }
            combinedPool.internClass(new RegisterNativesUtilClassDef(
                    utilType, methodNames, libName));
            Dex2c.writeDexPool035(combinedPool, gateDex);

            long supportMs = (System.nanoTime() - supportStarted) / 1_000_000L;
            report(54, "VMP: NativeUtil merged with PhStringGate + SignerGate in "
                    + gateDex.getName() + " in " + supportMs
                    + " ms — main classes.dex left untouched");
            return;
        }

        // Single-D​​EX compatibility path: keep NativeUtil in classes.dex so
        // legacy runtimes that do not install secondary DEX files still work.
        File mainDex = new File(dexDir, "classes.dex");
        if (mainDex.exists()) {
            try {
                long mainDexStarted = System.nanoTime();
                List<String> methodNames = new ArrayList<>();
                for (DexConfig cfg : configs) methodNames.add(cfg.getRegisterNativesMethodName());
                String utilType = "L" + configs.get(0).getRegisterNativesClassName() + ";";
                DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                        null, new BufferedInputStream(new FileInputStream(mainDex)));
                DexPool pool = new DexPool(dexFile.getOpcodes());
                for (ClassDef cls : dexFile.getClasses()) pool.internClass(cls);
                pool.internClass(new RegisterNativesUtilClassDef(utilType, methodNames, libName));
                Dex2c.writeDexPool035(pool, mainDex);
                long mainDexMs = (System.nanoTime() - mainDexStarted) / 1_000_000L;
                android.util.Log.i("ApkProtector",
                        "VMP NativeUtil: injected NativeUtil ("
                                + methodNames.size() + " method(s)) into classes.dex in "
                                + mainDexMs + " ms");
                report(54, "VMP: NativeUtil main DEX merge completed in "
                        + mainDexMs + " ms");
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
            try {
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
            } finally {
                // The impl bytes are only needed to derive this run's definitive
                // method set. Release them even if parsing fails so large failed
                // jobs do not retain every generated impl DEX in memory.
                cfg.clearImplDexBytes();
            }
        }
        android.util.Log.i("ApkProtector",
                "VMP impl DEX keys: " + keys.size() + " → " + keys);
        return keys;
    }

    /** Fails closed if the synthetic signer methods did not reach the VMP output. */
    private static void verifySignerGateVirtualized(Set<String> compiledKeys) throws Exception {
        String type = "L" + GateContext.SIGNER_CLASS_DESC + ";->";
        for (int i = 0; i < GateContext.SIGNER_PART_COUNT; i++) {
            String key = type + GateContext.signerPartMethodName(i) + "()I";
            if (!compiledKeys.contains(key)) {
                throw new Exception("VMP signer gate was not virtualized: " + key);
            }
        }
    }

    /**
     * Scan every DEX in dexDir and confirm each compiledKey is present and ACC_NATIVE.
     * Logs a ✓ / ✗ line per method visible in the UI progress log.
     * If any method was NOT stripped a clear warning is shown — never silently succeeds.
     */
    private void verifyStrippedKeys(File dexDir, Set<String> compiledKeys) throws IOException {
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
        if (bad != 0) {
            throw new IOException(summary);
        }
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
