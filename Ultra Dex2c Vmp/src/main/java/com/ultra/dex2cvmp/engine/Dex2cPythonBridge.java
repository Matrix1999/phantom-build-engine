package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Dex2cPythonBridge — runs the bundled codehasan/dex2c Python transpiler.
 *
 * Extraction: version-based marker. If the installed versionCode differs from the
 * marker, the entire scripts dir is wiped and re-extracted fresh (guarantees the
 * on-device scripts always match the bundled APK assets).
 *
 * Python binary: tries bin/python3.XX versioned names first (actual ELF binary in
 * Termux tarballs) before falling back to the generic bin/python3 wrapper.
 *
 * Pre-flight: runs a trivial Python one-liner before the bridge to confirm the
 * interpreter and file-write paths work, providing actionable diagnostics.
 *
 * Result: bridge writes JSON to outputDir/dcc_result.json; stdout is read as
 * a fallback in case an older cached script runs.
 */
public class Dex2cPythonBridge {

    private static final String TAG             = "Dex2cPythonBridge";
    private static final String ASSETS_SRC      = "dex2c_python";
    private static final String MARKER          = ".version";
    private static final String RESULT_FILENAME = "dcc_result.json";

    static { System.loadLibrary("scripts"); }
    private static native byte[] nativeGetScripts();

    private final Context       context;
    private final PythonManager python;

    public Dex2cPythonBridge(Context context) {
        this.context = context.getApplicationContext();
        this.python  = new PythonManager(context);
    }

    public boolean isAvailable()   { return python.isAvailable(); }
    public String  getStatusLabel(){ return python.getStatusLabel(); }

    // ── Public API ────────────────────────────────────────────────────────────

    public DexTranspiler.TranspileResult transpile(
            String apkPath,
            String filterText,
            File outputDir,
            DexTranspiler.TranspileCallback cb) {

        DexTranspiler.TranspileResult result = new DexTranspiler.TranspileResult();

        // ── 0. Repair Python libs: fix broken symlink stubs ──────────────────
        CompilerManager cm0 = new CompilerManager(context);
        repairPythonLibs(cm0.getPythonInstallDir());

        // ── 1. Resolve Python binary (versioned ELF first) ───────────────────
        String pythonBin = resolveWorkingPython(python.getPythonBin(),
                                                python.getExtraEnvironment(), result);
        if (pythonBin == null) return result;

        File filterFile = null;
        File resultFile = new File(outputDir, RESULT_FILENAME);

        try {
            if (cb != null) cb.onProgress("Extracting Ultra Dex2C-VMP scripts…");
            File scriptsDir = ensureExtracted();

            outputDir.mkdirs();
            resultFile.delete();

            File bridgeScript = new File(scriptsDir, "filter_bridge.py");
            if (!bridgeScript.exists()) {
                result.errors.add("filter_bridge.py missing — clear app data and retry");
                return result;
            }

            // ── 2. Pre-flight: confirm Python can write a file ────────────────
            String pfail = preflight(pythonBin, python.getExtraEnvironment(), outputDir);
            if (pfail != null) {
                result.errors.add("Python pre-flight failed: " + pfail);
                return result;
            }

            // ── 3. Write filter.txt (one class name per line from user selection) ──
            if (filterText != null && !filterText.trim().isEmpty()) {
                filterFile = File.createTempFile("dex2c_filter_", ".txt", context.getCacheDir());
                try (PrintWriter pw = new PrintWriter(filterFile, "UTF-8")) {
                    for (String line : filterText.split("[\r\n]+")) {
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty()) pw.println(trimmed);
                    }
                }
            }
            if (filterFile == null) {
                result.errors.add("No classes selected to protect.");
                return result;
            }

            // ── 4. Build command ──────────────────────────────────────────────
            List<String> cmd = new ArrayList<>();
            cmd.add(pythonBin);
            cmd.add("-u");
            cmd.add(bridgeScript.getAbsolutePath());
            cmd.add("--apk");    cmd.add(apkPath);
            cmd.add("--filter"); cmd.add(filterFile.getAbsolutePath());
            cmd.add("--outdir"); cmd.add(outputDir.getAbsolutePath());
            cmd.add("--result"); cmd.add(resultFile.getAbsolutePath());

            if (cb != null) cb.onProgress("Running native transpiler…");
            Log.i(TAG, "cmd=" + cmd);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(python.getExtraEnvironment());
            pb.environment().put("PYTHONPATH",              scriptsDir.getAbsolutePath());
            pb.environment().put("PYTHONDONTWRITEBYTECODE", "1");
            pb.redirectErrorStream(true);

            Process proc = pb.start();
            com.ultra.dex2cvmp.service.ProtectionService.ACTIVE_PROCESS = proc;

            StringBuilder console = new StringBuilder();
            Thread reader = readStream(proc.getInputStream(), console, cb);
            reader.join();

            int exitCode = proc.waitFor();
            com.ultra.dex2cvmp.service.ProtectionService.ACTIVE_PROCESS = null;
            Log.i(TAG, "bridge exit=" + exitCode);
            if (console.length() > 0) Log.i(TAG, "bridge output: " + console);

            // ── 5. Try result file (new bridge writes here) ───────────────────
            if (resultFile.exists()) {
                parseResultFile(resultFile, outputDir, result, cb);
                return result;
            }

            // ── 6. Fallback: old bridge printed JSON to stdout ────────────────
            String stdout = console.toString().trim();
            int jsonStart = stdout.lastIndexOf("{\"");
            if (jsonStart >= 0) {
                Log.i(TAG, "Falling back to stdout JSON");
                parseResultJson(stdout.substring(jsonStart), outputDir, result, cb);
                return result;
            }

            // ── 7. Nothing worked ─────────────────────────────────────────────
            String snippet = stdout.length() > 0
                    ? " | " + stdout.substring(0, Math.min(400, stdout.length()))
                    : "";
            result.errors.add("Transpiler produced no output. Exit=" + exitCode
                    + " bin=" + pythonBin + snippet);

        } catch (Exception e) {
            Log.e(TAG, "Bridge exception", e);
            result.errors.add("Bridge error: " + e.getMessage());
        } finally {
            if (filterFile != null) filterFile.delete();
        }

        return result;
    }

    // ── Python binary resolution ──────────────────────────────────────────────

    /**
     * The Termux Python tarball ships bin/python3 as a shell wrapper; the actual
     * ELF interpreter is bin/python3.13 (or similar versioned name). We scan the
     * bin/ directory for versioned names first so we always exec the real binary.
     *
     * Also verifies the binary actually works before accepting it.
     */
    private String resolveWorkingPython(String defaultBin,
                                         Map<String, String> env,
                                         DexTranspiler.TranspileResult result) {
        if (defaultBin == null) {
            result.errors.add("Python not found. Open Tools Setup to download the runtime.");
            return null;
        }

        // Build candidate list: versioned ELF binaries first, generic wrapper last
        List<String> candidates = new ArrayList<>();
        File binDir = new File(defaultBin).getParentFile();
        if (binDir != null && binDir.exists()) {
            // Add versioned names in descending version order
            for (int v = 15; v >= 8; v--) {
                File f = new File(binDir, "python3." + v);
                if (f.exists()) candidates.add(f.getAbsolutePath());
            }
        }
        // Always add the default as final fallback
        candidates.add(defaultBin);

        for (String candidate : candidates) {
            if (!new File(candidate).canExecute()) continue;
            if (quickVerify(candidate, env)) {
                if (!candidate.equals(defaultBin))
                    Log.i(TAG, "Using versioned Python binary: " + candidate);
                return candidate;
            }
        }

        result.errors.add("Python binary not working. bin=" + defaultBin
                + " (try deleting & re-downloading Python in Tools Setup)");
        return null;
    }

    /** Run `python3 -c "import sys; sys.exit(42)"` — returns true only if exit == 42. */
    private boolean quickVerify(String bin, Map<String, String> env) {
        try {
            ProcessBuilder pb = new ProcessBuilder(bin, "-c", "import sys; sys.exit(42)");
            pb.environment().putAll(env);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            drain(p.getInputStream());
            return p.waitFor() == 42;
        } catch (Exception e) {
            Log.w(TAG, "quickVerify failed for " + bin + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Pre-flight: verify Python can write a file to the output directory.
     * Returns null on success, or a diagnostic string on failure.
     */
    private String preflight(String bin, Map<String, String> env, File outputDir) {
        File testFile = new File(outputDir, ".dcc_prefly");
        testFile.delete();
        // Escape the path safely for embedding in Python string (only forward-slashes on Android)
        String escapedPath = testFile.getAbsolutePath().replace("\\", "\\\\").replace("'", "\\'");
        String pyCode = "import sys; open('" + escapedPath + "','w').write('ok'); sys.exit(42)";
        try {
            ProcessBuilder pb = new ProcessBuilder(bin, "-c", pyCode);
            pb.environment().putAll(env);
            pb.redirectErrorStream(true);
            StringBuilder out = new StringBuilder();
            Process p = pb.start();
            readStream(p.getInputStream(), out, null).join();
            int code = p.waitFor();
            boolean wrote = testFile.exists();
            testFile.delete();
            if (code == 42 && wrote) return null; // success
            return "exit=" + code + " wrote=" + wrote
                    + (out.length() > 0 ? " | " + out.toString().trim().substring(0, Math.min(200, out.toString().trim().length())) : "");
        } catch (Exception e) {
            testFile.delete();
            return "exception: " + e.getMessage();
        }
    }

    // ── JSON parsing ──────────────────────────────────────────────────────────

    private void parseResultFile(File f, File outputDir,
                                  DexTranspiler.TranspileResult result,
                                  DexTranspiler.TranspileCallback cb) throws Exception {
        parseResultJson(readFile(f), outputDir, result, cb);
        f.delete();
    }

    private void parseResultJson(String raw, File outputDir,
                                  DexTranspiler.TranspileResult result,
                                  DexTranspiler.TranspileCallback cb) throws Exception {
        JSONObject json    = new JSONObject(raw);
        int        success = json.optInt("success", 0);

        JSONArray methods = json.optJSONArray("methods");
        if (methods != null) {
            for (int i = 0; i < methods.length(); i++) {
                JSONObject entry = methods.getJSONObject(i);
                String dexKey = entry.getString("dex_key");
                String fname  = entry.getString("file");
                result.compiled.put(dexKey, new File(outputDir, fname).getAbsolutePath());
            }
        }

        JSONArray errors = json.optJSONArray("errors");
        if (errors != null) {
            for (int i = 0; i < errors.length(); i++)
                result.errors.add(errors.getString(i));
        }

        if (cb != null) cb.onProgress("Transpiled " + success + " method(s)");
    }

    // ── Extraction ────────────────────────────────────────────────────────────

    /**
     * Extracts assets to filesDir/dex2c_python/.
     * Cache key = PackageInfo.lastUpdateTime — changes on every install/update
     * automatically, so no manual version bumping is ever needed.
     */
    private File ensureExtracted() throws IOException {
        File dest   = new File(context.getFilesDir(), ASSETS_SRC);
        File marker = new File(dest, MARKER);

        long currentStamp = getInstallTime();
        long cachedStamp  = readInstallTimeMarker(marker);

        boolean upToDate = (currentStamp != 0)
                        && (cachedStamp == currentStamp)
                        && dest.exists();

        if (upToDate) {
            Log.i(TAG, "Scripts up-to-date (installTime=" + currentStamp + ")");
            return dest;
        }

        Log.i(TAG, "Re-extracting scripts: cached=" + cachedStamp
                 + " current=" + currentStamp);
        deleteDir(dest);
        dest.mkdirs();
        extractFromSo(dest);
        if (currentStamp != 0) writeInstallTimeMarker(marker, currentStamp);
        Log.i(TAG, "Extraction complete");
        return dest;
    }

    /** Returns PackageInfo.lastUpdateTime — unique per install, changes on reinstall. */
    private long getInstallTime() {
        try {
            PackageInfo pi = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            return pi.lastUpdateTime;
        } catch (Exception e) {
            return 0;
        }
    }

    private long readInstallTimeMarker(File marker) {
        if (!marker.exists()) return 0;
        try (BufferedReader br = new BufferedReader(new FileReader(marker))) {
            String line = br.readLine();
            return line != null ? Long.parseLong(line.trim()) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private void writeInstallTimeMarker(File marker, long stamp) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(marker))) {
            pw.println(stamp);
        } catch (Exception e) {
            Log.w(TAG, "Could not write install-time marker: " + e);
        }
    }

    private void deleteDir(File dir) {
        if (!dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDir(f);
            else f.delete();
        }
        dir.delete();
    }

    private static byte[] getCertFingerprint(Context ctx) {
        try {
            android.content.pm.PackageInfo pi = ctx.getPackageManager()
                .getPackageInfo(ctx.getPackageName(),
                    android.content.pm.PackageManager.GET_SIGNATURES);
            android.content.pm.Signature sig = pi.signatures[0];
            return java.security.MessageDigest.getInstance("SHA-256")
                .digest(sig.toByteArray());
        } catch (Exception e) { return new byte[32]; }
    }

    // ── Blob decryption key: K[i]^M[i] from scripts_jni.c ───────────────────
    // K = {0xA8,0x32,0x75,0xBC,0x5D,0x90,0x49,0x79, 0x5B,0xDA,0x72,0x3E,0xB5,0x74,0x94,0x5C,
    //      0x95,0xA9,0xD1,0xD2,0x41,0x4E,0xFF,0x76, 0xBB,0x7E,0xCC,0x98,0xA8,0xE7,0xCE,0x3C}
    // M = {0x5A,0xC3,0x8E,0x11,0x77,0xF0,0x6B,0x9D, 0x4E,0x32,0xA1,0x07,0xBC,0x28,0x55,0xE9,
    //      0x83,0x6A,0xD4,0x2F,0x91,0x4C,0xB8,0x05, 0x60,0xCE,0x37,0x1A,0xF5,0x88,0x3C,0x57}
    private static final byte[] BLOB_KEY = {
        (byte)0xF2,(byte)0xF1,(byte)0xFB,(byte)0xAD,(byte)0x2A,(byte)0x60,(byte)0x22,(byte)0xE4,
        (byte)0x15,(byte)0xE8,(byte)0xD3,(byte)0x39,(byte)0x09,(byte)0x5C,(byte)0xC1,(byte)0xB5,
        (byte)0x16,(byte)0xC3,(byte)0x05,(byte)0xFD,(byte)0xD0,(byte)0x02,(byte)0x47,(byte)0x73,
        (byte)0xDB,(byte)0xB0,(byte)0xFB,(byte)0x82,(byte)0x5D,(byte)0x6F,(byte)0xF2,(byte)0x6B
    };

    /**
     * Read scripts.blob from APK assets and return the decrypted ZIP bytes.
     * Blob format: [MAGIC 4B LE][zip_len 4B LE][XOR-encrypted zip data]
     * This replicates exactly what nativeGetScripts() did in C (scripts_jni.c).
     */
    private static byte[] decryptBlobAsset(Context ctx) throws IOException {
        byte[] raw;
        try (InputStream is = ctx.getAssets().open("scripts.blob");
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] tmp = new byte[65536]; int n;
            while ((n = is.read(tmp)) != -1) baos.write(tmp, 0, n);
            raw = baos.toByteArray();
        }
        if (raw.length < 8) throw new IOException("scripts.blob too small (" + raw.length + " B)");
        int magic = (raw[0] & 0xFF) | ((raw[1] & 0xFF) << 8) | ((raw[2] & 0xFF) << 16) | ((raw[3] & 0xFF) << 24);
        if (magic != 0x4D433244) throw new IOException("scripts.blob bad magic: 0x" + Integer.toHexString(magic));
        int zipLen = (raw[4] & 0xFF) | ((raw[5] & 0xFF) << 8) | ((raw[6] & 0xFF) << 16) | ((raw[7] & 0xFF) << 24);
        if (zipLen <= 0 || zipLen > raw.length - 8) throw new IOException("scripts.blob bad zipLen=" + zipLen);
        byte[] dec = new byte[zipLen];
        for (int i = 0; i < zipLen; i++) dec[i] = (byte)(raw[8 + i] ^ BLOB_KEY[i % 32]);
        return dec;
    }

    /** Extract dex2c_python/ entries from the assets blob into destBase. */
    private void extractFromSo(File destBase) throws IOException {
        byte[] zipBytes = decryptBlobAsset(context);
        File jniDest = new File(context.getFilesDir(), "compiler_headers");
        jniDest.mkdirs();
        destBase.mkdirs();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                File outFile;
                if (name.startsWith("dex2c_python/")) {
                    outFile = new File(destBase, name.substring("dex2c_python/".length()));
                } else if (name.startsWith("jni_nc/")) {
                    outFile = new File(jniDest, name.substring("jni_nc/".length()));
                } else {
                    zis.closeEntry();
                    continue;
                }
                if (entry.isDirectory()) { outFile.mkdirs(); zis.closeEntry(); continue; }
                outFile.getParentFile().mkdirs();
                try (OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile), 65536)) {
                    byte[] buf = new byte[65536]; int n;
                    while ((n = zis.read(buf)) != -1) os.write(buf, 0, n);
                }
                zis.closeEntry();
            }
        }
    }

    /** Extract only jni_nc/ entries into headersDir (called by NdkBuilder).
     *  Cache key = lastUpdateTime so every fresh install auto-clears stale headers. */
    static void extractJniHeaders(Context context, File headersDir) throws IOException {
        headersDir.mkdirs();
        // Derive install-time stamp (same logic as getInstallTime())
        long installTime = 0;
        try {
            PackageInfo pi = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            installTime = pi.lastUpdateTime;
        } catch (Exception ignored) {}

        // Check stamp — named after the install timestamp so it changes on reinstall
        File stamp = new File(headersDir, ".hdr_t" + installTime);
        if (installTime != 0 && stamp.exists()) return;

        // Wipe ALL stale headers (including old .hdr_v* or .hdr_t* stamps)
        File[] existing = headersDir.listFiles();
        if (existing != null) for (File f : existing) f.delete();

        byte[] zipBytes = decryptBlobAsset(context);
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (!name.startsWith("jni_nc/")) { zis.closeEntry(); continue; }
                File outFile = new File(headersDir, name.substring("jni_nc/".length()));
                if (entry.isDirectory()) { outFile.mkdirs(); zis.closeEntry(); continue; }
                outFile.getParentFile().mkdirs();
                try (OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile), 65536)) {
                    byte[] buf = new byte[65536]; int n;
                    while ((n = zis.read(buf)) != -1) os.write(buf, 0, n);
                }
                zis.closeEntry();
            }
        }
        // Write install-time stamp so we skip re-extraction until next install
        try { stamp.createNewFile(); } catch (Exception ignored) {}
    }

    // ── Stream / file helpers ─────────────────────────────────────────────────

    private Thread readStream(InputStream is, StringBuilder sb,
                               DexTranspiler.TranspileCallback cb) {
        Thread t = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append('\n');
                    if (cb != null) cb.onProgress(line);
                }
            } catch (IOException ignored) {}
        });
        t.start();
        return t;
    }

    private void drain(InputStream is) {
        try { byte[] b = new byte[4096]; while (is.read(b) != -1); } catch (Exception ignored) {}
    }

    private String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        }
        return sb.toString().trim();
    }

    // ── Runtime repair for 0-byte .so stubs (symlinks extracted as empty files) ─

    /**
     * Scans the Python install directory for 0-byte .so files that were created
     * instead of proper symlinks (due to the old TarInputStream not handling
     * TAR type '2' symlink entries). For each such file, we try to find the
     * corresponding versioned .so and either symlink or copy it.
     *
     * Example: libz.so.1 (0 bytes) → libz.so.1.2.13 (real) → symlink created.
     */
    private void repairPythonLibs(File pythonInstallDir) {
        if (pythonInstallDir == null || !pythonInstallDir.exists()) return;
        repairBrokenSoFiles(pythonInstallDir);
        // Also recurse into lib/ and lib/pythonX.Y/
        File libDir = new File(pythonInstallDir, "lib");
        if (!libDir.exists()) return;
        repairBrokenSoFiles(libDir);
        File[] children = libDir.listFiles();
        if (children != null) {
            for (File child : children) {
                if (child.isDirectory()) repairBrokenSoFiles(child);
            }
        }
    }

    private void repairBrokenSoFiles(File dir) {
        File[] files = dir.listFiles();
        if (files == null) return;
        // Collect all files that actually have content (real .so files)
        Map<String, File> realFiles = new HashMap<>();
        for (File f : files) {
            if (!f.isDirectory() && f.length() > 0) realFiles.put(f.getName(), f);
        }
        // Fix each 0-byte file that looks like a .so
        for (File f : files) {
            if (f.isDirectory() || f.length() > 0) continue;
            if (!f.getName().contains(".so")) continue;
            // Find a real file whose name starts with this name + "."
            // e.g., "libz.so.1" → find "libz.so.1.2.13"
            String prefix = f.getName() + ".";
            File source = null;
            for (Map.Entry<String, File> e : realFiles.entrySet()) {
                if (e.getKey().startsWith(prefix)) { source = e.getValue(); break; }
            }
            if (source == null) continue;
            // Create a symlink pointing to the source file name (relative, same dir)
            try {
                f.delete();
                Os.symlink(source.getName(), f.getAbsolutePath());
                Log.i(TAG, "repairPythonLibs: symlinked " + f.getName() + " -> " + source.getName());
            } catch (ErrnoException ex) {
                // Fallback: copy the bytes
                Log.w(TAG, "repairPythonLibs: symlink failed, copying " + source.getName() + " to " + f.getName() + ": " + ex.getMessage());
                try (InputStream in  = new FileInputStream(source);
                     OutputStream out = new FileOutputStream(f)) {
                    byte[] buf = new byte[65536]; int n;
                    while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                    f.setExecutable(true, false);
                } catch (IOException ioEx) {
                    Log.e(TAG, "repairPythonLibs: copy also failed: " + ioEx.getMessage());
                }
            }
        }
    }
}
