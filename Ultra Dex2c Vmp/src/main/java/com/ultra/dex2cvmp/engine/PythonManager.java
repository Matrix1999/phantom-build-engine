package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.util.Log;
import java.io.*;
import java.util.*;

/**
 * PythonManager — finds a usable Python 3 interpreter on the device.
 *
 * Detection order (first working candidate wins):
 *   1. Downloaded standalone  — filesDir/python3/bin/python3  (via PythonDownloadService)
 *   2. Termux                 — /data/data/com.termux/files/usr/bin/python3
 *   3. System PATH candidates — /usr/bin/python3, /usr/local/bin/python3, etc.
 *   4. sh -c which python3    — PATH search fallback
 *
 * When using the downloaded standalone Python, callers must apply the extra
 * environment returned by getExtraEnvironment() to their ProcessBuilder so
 * Python can locate its stdlib (PYTHONHOME) and shared libs (LD_LIBRARY_PATH).
 */
public class PythonManager {

    private static final String TAG = "PythonManager";

    private static final String[] SYSTEM_CANDIDATES = {
        "/data/data/com.termux/files/usr/bin/python3",
        "/data/data/com.termux/files/usr/bin/python",
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/bin/python3",
    };

    private final Context         context;
    private final CompilerManager cm;

    private String              cachedPythonPath = null;
    private Map<String, String> cachedEnv        = null;

    public PythonManager(Context context) {
        this.context = context.getApplicationContext();
        this.cm      = new CompilerManager(context);
    }

    /**
     * Returns the path to a working python3 binary, or null if none found.
     * Result is cached after the first successful lookup.
     */
    public String getPythonBin() {
        if (cachedPythonPath != null) return cachedPythonPath;
        resolveInterpreter();
        return cachedPythonPath;
    }

    /**
     * Extra environment variables that must be set when launching python3 as
     * a subprocess. Only non-empty when using the downloaded standalone runtime
     * (PYTHONHOME + LD_LIBRARY_PATH). Always empty/null-safe when using Termux
     * or system Python — those runtimes handle their own paths.
     *
     * Apply via:
     *   pb.environment().putAll(pm.getExtraEnvironment());
     */
    public Map<String, String> getExtraEnvironment() {
        if (cachedEnv != null) return cachedEnv;
        resolveInterpreter();
        return cachedEnv != null ? cachedEnv : Collections.emptyMap();
    }

    /** True if a Python interpreter is available on this device. */
    public boolean isAvailable() {
        return getPythonBin() != null;
    }

    /** True if the downloaded standalone Python is installed and will be used. */
    public boolean isUsingDownloaded() {
        String bin = getPythonBin();
        return bin != null && bin.equals(cm.getPythonBin().getAbsolutePath());
    }

    /** Human-readable status for the UI. */
    public String getStatusLabel() {
        String bin = getPythonBin();
        if (bin == null) {
            return "Python not found — open Tools Setup to download the runtime";
        }
        if (isUsingDownloaded()) {
            return "Python 3 ready · standalone";
        }
        if (bin.contains("termux")) {
            return "Python ready · system";
        }
        return "Python ready · " + bin;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private void resolveInterpreter() {
        // 0. Auto-extract bundled Python from assets if not yet done (silent, no user action needed)
        if (!cm.isPythonInstalled()) {
            cm.ensurePythonExtracted();
        }

        // 1. Downloaded/extracted standalone Python (highest priority — trust .installed marker + executable bit)
        //    We do NOT run verify() here because spawning a subprocess during detection is fragile
        //    on Android (SELinux, LD_LIBRARY_PATH timing). The .installed marker guarantees the
        //    extraction completed and makePythonExecutable() ran.
        File downloaded = cm.getPythonBin();
        if (cm.isPythonInstalled() && downloaded.canExecute()) {
            Log.i(TAG, "Using downloaded Python: " + downloaded);
            cachedPythonPath = downloaded.getAbsolutePath();
            cachedEnv        = buildDownloadedEnv();
            return;
        }
        // If marker exists but binary lost its execute bit (e.g. after a restore), re-apply it.
        if (cm.isPythonInstalled() && downloaded.exists()) {
            downloaded.setExecutable(true, false);
            if (downloaded.canExecute()) {
                Log.i(TAG, "Using downloaded Python (re-chmod): " + downloaded);
                cachedPythonPath = downloaded.getAbsolutePath();
                cachedEnv        = buildDownloadedEnv();
                return;
            }
        }

        // 2. Termux / system path candidates
        for (String path : SYSTEM_CANDIDATES) {
            if (new File(path).canExecute()) {
                if (verify(path, Collections.emptyMap())) {
                    Log.i(TAG, "Using system Python: " + path);
                    cachedPythonPath = path;
                    cachedEnv        = Collections.emptyMap();
                    return;
                }
            }
        }

        // 3. Search PATH via shell
        String fromPath = findOnPath();
        if (fromPath != null) {
            Log.i(TAG, "Using PATH Python: " + fromPath);
            cachedPythonPath = fromPath;
            cachedEnv        = Collections.emptyMap();
            return;
        }

        Log.w(TAG, "No Python interpreter found on this device.");
    }

    /** Build the env vars needed so standalone Python finds its stdlib + .so files. */
    private Map<String, String> buildDownloadedEnv() {
        File installDir = cm.getPythonInstallDir();
        Map<String, String> env = new HashMap<>();
        env.put("PYTHONHOME", installDir.getAbsolutePath());
        env.put("LD_LIBRARY_PATH", cm.getPythonLibDir().getAbsolutePath());
        return Collections.unmodifiableMap(env);
    }

    /** Run `python3 --version` to confirm the binary actually works. */
    private boolean verify(String pythonBin, Map<String, String> extraEnv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(pythonBin, "--version")
                    .redirectErrorStream(true);
            pb.environment().putAll(extraEnv);
            Process p = pb.start();
            p.waitFor();
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /** Try `which python3` via sh to find Python on PATH. */
    private String findOnPath() {
        try {
            Process p = new ProcessBuilder("sh", "-c", "which python3 || which python")
                    .redirectErrorStream(true)
                    .start();
            p.waitFor();
            if (p.exitValue() != 0) return null;
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            if (line != null) line = line.trim();
            if (line != null && !line.isEmpty() && new File(line).canExecute()) {
                if (verify(line, Collections.emptyMap())) return line;
            }
        } catch (Exception ignored) {}
        return null;
    }
}
