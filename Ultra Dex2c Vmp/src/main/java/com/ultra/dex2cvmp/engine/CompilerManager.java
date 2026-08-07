package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.content.SharedPreferences;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import com.ultra.dex2cvmp.service.NdkDownloadService;
import java.io.*;
import java.util.zip.GZIPInputStream;

public class CompilerManager {

    private static final String TAG          = "CompilerManager";
    private static final String PYTHON_ASSET = "python3_bundle";

    private static final String PREFS_NAME     = "dex2c_prefs";
    private static final String KEY_USE_OLLVM  = "use_ollvm_ndk";
    private static final String KEY_OLLVM_LEVEL = "ollvm_level";

    public interface ProgressCallback {
        void onProgress(int pct, String msg);
    }

    private final Context context;

    public CompilerManager(Context context) {
        this.context = context.getApplicationContext();
        OllvmNdkManager.init(this.context);
    }

    // ── OLLVM NDK toggle ──────────────────────────────────────────────────────

    private SharedPreferences prefs() {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public boolean isOllvmNdkEnabled() {
        return prefs().getBoolean(KEY_USE_OLLVM, false);
    }

    public void setOllvmNdkEnabled(boolean enabled) {
        prefs().edit().putBoolean(KEY_USE_OLLVM, enabled).apply();
    }

    /**
     * Returns the selected obfuscation level.
     * 0-8 = preset intensity levels.  9 = LEVEL_CUSTOM (user-selected passes).
     * Only relevant when isOllvmNdkEnabled() is true.
     */
    public int getOllvmLevel() {
        return prefs().getInt(KEY_OLLVM_LEVEL, 0);
    }

    /**
     * Returns whether an individual OLLVM pass is enabled in custom mode.
     * Pass keys match the KEY_PASS_* constants in OllvmFragment.
     * Defaults to true so all passes are active on first launch.
     *
     * @param passKey  e.g. "ollvm_pass_fla", "ollvm_pass_bcf", …
     */
    public boolean isCustomPassEnabled(String passKey) {
        return prefs().getBoolean(passKey, false);
    }

    /**
     * Returns the OLLVM clang binary, or null if the NDK is not installed.
     * OLLVM NDK is the only NDK — there is no bundled fallback.
     */
    public File getActiveClangBin() {
        if (!OllvmNdkManager.isInstalled()) return null;
        return OllvmNdkManager.findClangBin();
    }

    /**
     * Returns the OLLVM sysroot directory, or null if the NDK is not installed.
     */
    public File getActiveSysrootDir() {
        if (!OllvmNdkManager.isInstalled()) return null;
        return OllvmNdkManager.findSysrootDir();
    }

    public File getPythonInstallDir() {
        return new File(context.getFilesDir(), "python3");
    }

    public boolean isPythonInstalled() {
        return new File(getPythonInstallDir(), ".installed").exists();
    }

    public File getPythonBin() {
        return new File(getPythonInstallDir(), "bin/python3");
    }

    public File getPythonLibDir() {
        return new File(getPythonInstallDir(), "lib");
    }

    public String getPythonStatusLabel() {
        if (!isPythonInstalled()) return "Python not ready";
        return "Python 3 Ready";
    }

    /**
     * Silently extracts the bundled Python 3 runtime from assets if not already done.
     * Safe to call from any background thread.
     * @return true if Python is ready (already installed or just extracted), false on failure
     */
    public boolean ensurePythonExtracted() {
        if (isPythonInstalled()) return true;

        // Guard: verify the bundled asset is physically present in the APK.
        // If missing, the build was produced without python3_bundle in assets/ —
        // log a fatal error immediately so the cause is obvious in logcat.
        try {
            context.getAssets().open(PYTHON_ASSET).close();
        } catch (IOException missing) {
            Log.wtf(TAG, "FATAL: bundled asset '" + PYTHON_ASSET + "' not found in APK. "
                    + "Ensure python3_bundle is placed under src/main/assets/ before building.", missing);
            return false;
        }

        File destDir = getPythonInstallDir();
        destDir.mkdirs();

        try (InputStream raw = context.getAssets().open(PYTHON_ASSET);
             GZIPInputStream gzip = new GZIPInputStream(new BufferedInputStream(raw, 65536))) {

            NdkDownloadService.TarInputStream tar = new NdkDownloadService.TarInputStream(gzip);
            NdkDownloadService.TarEntry entry;
            while ((entry = tar.nextEntry()) != null) {
                String name = entry.name;
                if (name.isEmpty() || name.equals(".") || name.equals("./")) continue;
                File dest = new File(destDir, name);
                if (!dest.getCanonicalPath().startsWith(destDir.getCanonicalPath())) continue;
                if (entry.isDirectory) {
                    dest.mkdirs();
                } else if (entry.isSymlink && entry.linkTarget != null && !entry.linkTarget.isEmpty()) {
                    dest.getParentFile().mkdirs();
                    dest.delete();
                    try {
                        Os.symlink(entry.linkTarget, dest.getAbsolutePath());
                    } catch (ErrnoException ex) {
                        Log.w(TAG, "symlink failed: " + entry.linkTarget + " -> " + dest);
                    }
                } else {
                    dest.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(dest)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = tar.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    if ((entry.mode & 0111) != 0) dest.setExecutable(true, false);
                }
            }

            makePythonExecutable(destDir);
            new File(destDir, ".installed").createNewFile();
            Log.i(TAG, "Python 3 extracted from bundled assets");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Failed to extract bundled Python: " + e.getMessage(), e);
            return false;
        }
    }

    private void makePythonExecutable(File dir) {
        File binDir = new File(dir, "bin");
        if (binDir.exists()) {
            File[] bins = binDir.listFiles();
            if (bins != null) for (File f : bins) f.setExecutable(true, false);
        }
        File libDir = new File(dir, "lib");
        if (libDir.exists()) {
            File[] libs = libDir.listFiles();
            if (libs != null) for (File f : libs) {
                if (f.getName().endsWith(".so") || f.getName().contains(".so."))
                    f.setExecutable(true, false);
            }
        }
    }
}
