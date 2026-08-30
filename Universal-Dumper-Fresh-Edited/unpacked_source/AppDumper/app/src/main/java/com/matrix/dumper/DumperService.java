package com.matrix.dumper;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;

/**
 * DumperService — pure /proc/PID/mem approach, no Frida.
 *
 * Flow:
 *   1. Extract dump_dex_mem.py from assets → Termux home (if missing); skip if already there
 *   2. Launch target app via monkey, wait for process to appear
 *   3. Wait for protector to finish decrypting (timing per protector type)
 *   4. Run: su -c "python3 dump_dex_mem.py <PID> <tmpDir> <pkg>"
 *   5. Stream output lines to LogActivity in real time
 *   6. Move saved DEX files from /data/local/tmp staging → /sdcard/Matrix-Dumper/<pkg>/
 *   7. Broadcast completion, post notification
 */
public class DumperService extends Service {

    private static final String TAG    = "DumperService";
    public  static final String CHANNEL        = "dumper_ch";
    public  static final String ACTION_LOG     = "com.matrix.dumper.LOG";
    public  static final String ACTION_DONE    = "com.matrix.dumper.DONE";
    public  static final String EXTRA_LINE     = "line";
    public  static final String EXTRA_PACKAGE  = "pkg";
    public  static final String EXTRA_EXIT     = "exit";
    public  static final String EXTRA_DEX_COUNT= "dex_count";

    // Primary install location — Termux home, same place the user pushes it manually
    private static final String TERMUX_HOME       = "/data/data/com.termux/files/home";
    private static final String DUMPER_SCRIPT     = TERMUX_HOME + "/dump_dex_mem.py";

    // Fallback location used when Termux home isn't accessible
    private static final String DUMPER_SCRIPT_TMP = "/data/local/tmp/dump_dex_mem.py";

    // Resolved path after extractScript() — either DUMPER_SCRIPT or DUMPER_SCRIPT_TMP
    private String activeScriptPath = DUMPER_SCRIPT;

    private static final String PYTHON_TERMUX = "/data/data/com.termux/files/usr/bin/python3";
    private static final String TERMUX_USR    = "/data/data/com.termux/files/usr";
    private static final String TERMUX_LIB    = "/data/data/com.termux/files/usr/lib";
    private static final String PYTHON_SYSTEM = "/usr/bin/python3";

    // Final output on sdcard (readable by file managers / ADB pull)
    private static final String DUMP_ROOT = "/sdcard/Matrix-Dumper";

    // World-writable staging: dump_dex_mem.py (root) writes here;
    // we then mv files to DUMP_ROOT (requires MANAGE_EXTERNAL_STORAGE)
    private static final String TMP_ROOT  = "/data/local/tmp/matrix_dumper_tmp";

    private static final int MAX_RELAUNCH = 3;
    private static final SimpleDateFormat TS =
            new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

    @Override public void onCreate() { super.onCreate(); createChannel(); }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        String pkg  = intent.getStringExtra("packageName");
        String apk  = intent.getStringExtra("apkPath");
        String prot = intent.getStringExtra("protection");
        startForeground(1, buildNotif("Dumping " + pkg));
        new Thread(() -> runDump(pkg, apk, prot)).start();
        return START_NOT_STICKY;
    }

    // ── Main dump pipeline ────────────────────────────────────────────────────

    private void runDump(String pkg, String apk, String protName) {
        AppInfo.ProtectionType type = AppInfo.ProtectionType.UNKNOWN;
        try { type = AppInfo.ProtectionType.valueOf(protName); } catch (Exception ignored) {}

        final String dumpDir = DUMP_ROOT + "/" + pkg;
        final String tmpDir  = TMP_ROOT  + "/" + pkg;

        new File(dumpDir).mkdirs();
        ShellUtils.runAsRoot(
            "rm -f \"" + dumpDir + "\"/*.dex \"" + dumpDir + "\"/*.cdex 2>/dev/null; true");

        log(pkg, "INIT", "══════════════════════════════════════");
        log(pkg, "INIT", "  Matrix Dumper  |  runtime engine  ");
        log(pkg, "INIT", "══════════════════════════════════════");
        log(pkg, "INIT", "Target:     " + pkg);
        log(pkg, "INIT", "Protection: " + type.label);
        log(pkg, "INIT", "Output:     " + dumpDir);
        log(pkg, "INIT", "──────────────────────────────────────");

        // ── Root check ────────────────────────────────────────────────────────
        log(pkg, "ROOT", "Verifying root access...");
        if (!ShellUtils.isRootAvailable()) {
            log(pkg, "ERROR", "Root NOT available — grant Magisk root to Matrix Dumper");
            finish(pkg, -1, 0); return;
        }
        log(pkg, "ROOT", "Root confirmed (uid=0)");

        // ── SELinux permissive — helps /proc/PID/mem on strict ROMs ──────────
        ShellUtils.runAsRoot("setenforce 0 2>/dev/null; true");
        log(pkg, "ROOT", "SELinux set to permissive");

        // ── Extract dump_dex_mem.py to Termux home (skip if already there) ──────
        if (!extractScript(pkg)) {
            log(pkg, "ERROR", "Failed to place dump_dex_mem.py — check assets bundle");
            finish(pkg, -1, 0); return;
        }
        log(pkg, "SCRIPT", "Dumper script active: " + activeScriptPath);

        // ── Locate Python 3 ───────────────────────────────────────────────────
        String python = findPython(pkg);
        if (python == null) {
            finish(pkg, -1, 0); return;
        }
        log(pkg, "SCRIPT", "Python: " + python);
        log(pkg, "SCRIPT", "──────────────────────────────────────");

        // ── Create world-writable staging dir ─────────────────────────────────
        ShellUtils.runAsRoot("rm -rf \"" + tmpDir + "\"");
        ShellUtils.runAsRoot("mkdir -p \"" + tmpDir + "\"");
        ShellUtils.runAsRoot("chmod 777 \"" + tmpDir + "\"");

        // ── Read user settings ────────────────────────────────────────────────
        int  extraWaitSec = SettingsManager.getExtraWaitSec(this);
        boolean multiPass = SettingsManager.isMultiPass(this);
        boolean forceStop = SettingsManager.isForceStop(this);
        log(pkg, "INIT", "Settings → extra-wait=" + extraWaitSec + "s"
            + "  multi-pass=" + multiPass + "  force-stop=" + forceStop);

        // ── Force-stop target before launch (clean slate) ─────────────────────
        if (forceStop) {
            log(pkg, "LAUNCH", "Force-stopping " + pkg + " for clean launch...");
            ShellUtils.runAsRoot("am force-stop " + pkg);
            sleep(2000);
        }

        // ── Launch target app + get PID ───────────────────────────────────────
        String pid = launchAndGetPid(pkg, type);
        if (pid == null) { finish(pkg, -1, 0); return; }

        // ── Wait for protector to finish decrypting ───────────────────────────
        long decryptWaitMs = decryptWait(type) + (extraWaitSec * 1000L);
        log(pkg, "WAIT", "Waiting " + (decryptWaitMs / 1000) + "s for DEX decryption"
            + (extraWaitSec > 0 ? " (+" + extraWaitSec + "s extra)" : "") + "...");
        sleep(decryptWaitMs);

        // Confirm process is still alive after wait
        String livePid = ShellUtils.getPid(pkg);
        if (livePid.isEmpty() || !livePid.matches("\\d+")) {
            log(pkg, "WARN", "Process died during wait — anti-debug? Trying anyway...");
            livePid = pid;
        }

        // ── Run dump passes ───────────────────────────────────────────────────
        log(pkg, "DUMP", "══════════════════════════════════════");
        int passes = multiPass ? 3 : 1;
        if (multiPass) log(pkg, "DUMP", "Multi-pass mode: " + passes + " memory sweeps");
        log(pkg, "DUMP", "Starting scan  PID=" + livePid);
        log(pkg, "DUMP", "══════════════════════════════════════");

        for (int pass = 1; pass <= passes; pass++) {
            if (pass > 1) {
                log(pkg, "DUMP", "──────────────────────────────────────");
                log(pkg, "DUMP", "Pass " + pass + "/" + passes + " — 3s cooldown...");
                sleep(3000);
            }
            final String passCmd = python + " \"" + activeScriptPath + "\""
                       + " " + livePid + " " + tmpDir + " " + pkg + " 2>&1";
            runPassBlocking(pkg, pass, passes, passCmd);
        }

        log(pkg, "DUMP", "──────────────────────────────────────");
        log(pkg, "DUMP", "All passes complete");

        // ── Move DEX files + dump.txt from staging → sdcard ──────────────────
        log(pkg, "DONE", "Moving DEX files → " + dumpDir);
        ShellUtils.runAsRoot(
            "for f in \"" + tmpDir + "\"/*.dex \"" + tmpDir + "\"/*.cdex; do " +
            "  [ -f \"$f\" ] && mv -f \"$f\" \"" + dumpDir + "/\"; " +
            "done 2>/dev/null; true");
        ShellUtils.runAsRoot("chmod 644 \"" + dumpDir + "\"/*.dex 2>/dev/null; true");
        // Move dump.txt if present
        ShellUtils.runAsRoot(
            "[ -f \"" + tmpDir + "/dump.txt\" ] && " +
            "mv -f \"" + tmpDir + "/dump.txt\" \"" + dumpDir + "/dump.txt\" 2>/dev/null; true");
        ShellUtils.runAsRoot("chmod 644 \"" + dumpDir + "/dump.txt\" 2>/dev/null; true");
        // Move stubs.txt if present
        ShellUtils.runAsRoot(
            "[ -f \"" + tmpDir + "/stubs.txt\" ] && " +
            "mv -f \"" + tmpDir + "/stubs.txt\" \"" + dumpDir + "/stubs.txt\" 2>/dev/null; true");
        ShellUtils.runAsRoot("chmod 644 \"" + dumpDir + "/stubs.txt\" 2>/dev/null; true");
        ShellUtils.runAsRoot("rm -rf \"" + tmpDir + "\"");

        // ── Count output ──────────────────────────────────────────────────────
        File outDir   = new File(dumpDir);
        File[] outFiles = outDir.listFiles();
        int  savedDex   = 0;
        long totalBytes = 0;
        if (outFiles != null) {
            for (File f : outFiles) {
                String n = f.getName().toLowerCase();
                if (n.endsWith(".dex") || n.endsWith(".cdex")) {
                    savedDex++;
                    totalBytes += f.length();
                    log(pkg, "DONE", "  " + f.getName() + "  (" + (f.length() / 1024) + " KB)");
                }
            }
        }

        log(pkg, "DONE", "──────────────────────────────────────");
        if (savedDex > 0) {
            log(pkg, "DONE", "[OK] COMPLETE — " + savedDex + " DEX file(s)  "
                    + (totalBytes / 1024) + " KB total");
            log(pkg, "DONE", "     Path: " + dumpDir);
        } else {
            log(pkg, "WARN", "No DEX files found.");
            log(pkg, "WARN", "Tips:");
            log(pkg, "WARN", "  1. Make sure the app is fully past its loading screen.");
            log(pkg, "WARN", "  2. Tap DUMP again after the app has been open 10+ seconds.");
            log(pkg, "WARN", "  3. If app crashes on launch — it may detect root/Magisk.");
        }
        log(pkg, "DONE", "══════════════════════════════════════");

        String notifTitle = savedDex > 0 ? "Dump complete" : "Dump finished — no DEX";
        String notifText  = savedDex > 0
            ? savedDex + " DEX file(s) saved  →  " + dumpDir
            : pkg + " — no DEX files found";
        sendCompletionNotif(notifTitle, notifText, pkg);
        finish(pkg, 0, savedDex);
    }

    // ── Run one dump pass, blocking via CountDownLatch ────────────────────────

    private void runPassBlocking(String pkg, int passNum, int total, String cmd) {
        CountDownLatch latch = new CountDownLatch(1);
        if (total > 1) log(pkg, "DUMP", "  → Pass " + passNum + "/" + total + " starting...");
        ShellUtils.runAsRootStreaming(cmd, new ShellUtils.OutputCallback() {
            @Override public void onLine(String line) {
                if (line == null || line.trim().isEmpty()) return;
                String l = line.trim();
                log(pkg, classifyLine(l), l);
            }
            @Override public void onDone(int code) {
                log(pkg, "DUMP", "Pass " + passNum + " exited  code=" + code);
                latch.countDown();
            }
        });
        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ── Launch app and get PID ────────────────────────────────────────────────

    private String launchAndGetPid(String pkg, AppInfo.ProtectionType type) {
        for (int attempt = 1; attempt <= MAX_RELAUNCH; attempt++) {
            log(pkg, "LAUNCH", "──────────────────────────────────────");
            log(pkg, "LAUNCH", "Launching " + pkg + " (attempt " + attempt + "/" + MAX_RELAUNCH + ")");

            ShellUtils.runAsRoot("am force-stop " + pkg);
            sleep(500);
            ShellUtils.runAsRoot(
                "monkey -p " + pkg + " -c android.intent.category.LAUNCHER 1 2>/dev/null");

            // Bring Matrix Dumper back to foreground so target runs in background
            ShellUtils.runAsRoot(
                "am start -n com.matrix.dumper/.LogActivity " +
                "--activity-single-top --activity-clear-top 2>/dev/null; true");

            log(pkg, "LAUNCH", "App started — waiting for process...");

            String pid = "";
            for (int i = 1; i <= 15; i++) {
                sleep(1000);
                pid = ShellUtils.getPid(pkg);
                if (!pid.isEmpty() && pid.matches("\\d+")) break;
                if (i % 3 == 0)
                    log(pkg, "LAUNCH", "  Still waiting (" + i + "s)...");
            }

            if (pid.isEmpty() || !pid.matches("\\d+")) {
                log(pkg, "WARN", "Process not found after 15s (attempt " + attempt + ")");
                if (attempt < MAX_RELAUNCH) { sleep(2000); continue; }
                log(pkg, "ERROR", "Could not start " + pkg + " after " + MAX_RELAUNCH + " attempts");
                return null;
            }

            log(pkg, "PID", "Process found  PID=" + pid);
            return pid;
        }
        return null;
    }

    // ── Decrypt wait per protector ────────────────────────────────────────────

    private long decryptWait(AppInfo.ProtectionType type) {
        switch (type) {
            case JIAGU_360:       return 7000L;
            case BAIDU:           return 10000L;
            case TENCENT_LEGU:    return 6000L;
            case TENCENT_TPSHELL: return 6000L;
            case IJIAMI:          return 5000L;
            case BANGCLE:         return 5000L;
            case DEXPROTECTOR:    return 3000L;
            case SHADOW_SAFETY:   return 8000L;
            case NETEASE:         return 5000L;
            case DPT_SHELL:       return 8000L;
            default:              return 4000L;
        }
    }

    // ── Log line classifier ───────────────────────────────────────────────────

    private String classifyLine(String l) {
        if (l.startsWith("[+]"))      return "SCAN";
        if (l.startsWith("[-] Skip")) return "SKIP";
        if (l.startsWith("[!]"))      return "WARN";
        if (l.contains("DONE"))       return "DONE";
        if (l.contains("Pass"))       return "SCAN";
        return "DUMP";
    }

    // ── Extract dump_dex_mem.py to Termux home ────────────────────────────────
    //
    //  Logic (mirrors how the gadget was handled):
    //    • Always extract from assets and overwrite Termux home (keeps script up to date).
    //    • Fallback → /data/local/tmp/ if Termux home is not accessible.
    //  activeScriptPath is updated to whichever path succeeded.

    private boolean extractScript(String pkg) {
        // ── Write asset to app cache dir (always — ensures latest version) ────
        File cacheFile = new File(getCacheDir(), "dump_dex_mem.py");
        try (InputStream is = getAssets().open("dump_dex_mem.py");
             FileOutputStream fo = new FileOutputStream(cacheFile)) {
            byte[] buf = new byte[8192]; int n;
            while ((n = is.read(buf)) != -1) fo.write(buf, 0, n);
        } catch (IOException e) {
            Log.e(TAG, "extractScript: failed to read asset", e);
            return false;
        }

        // ── Install to Termux home ─────────────────────────────────────────────
        ShellUtils.runAsRoot("mkdir -p \"" + TERMUX_HOME + "\"");
        ShellUtils.runAsRoot("cp \"" + cacheFile.getAbsolutePath() + "\" \"" + DUMPER_SCRIPT + "\"");
        ShellUtils.runAsRoot("chmod 755 \"" + DUMPER_SCRIPT + "\"");

        if (new File(DUMPER_SCRIPT).exists()) {
            log(pkg, "SCRIPT", "Installed dump_dex_mem.py → " + DUMPER_SCRIPT);
            activeScriptPath = DUMPER_SCRIPT;
            return true;
        }

        // ── Fallback: /data/local/tmp ──────────────────────────────────────────
        log(pkg, "SCRIPT", "Termux home not writable — falling back to " + DUMPER_SCRIPT_TMP);
        ShellUtils.runAsRoot("cp \"" + cacheFile.getAbsolutePath() + "\" " + DUMPER_SCRIPT_TMP);
        ShellUtils.runAsRoot("chmod 755 " + DUMPER_SCRIPT_TMP);

        if (new File(DUMPER_SCRIPT_TMP).exists()) {
            activeScriptPath = DUMPER_SCRIPT_TMP;
            return true;
        }

        Log.e(TAG, "extractScript: all install paths failed");
        return false;
    }

    // ── Python finder — 4-stage, fully automatic ──────────────────────────────
    //
    // Android 16 SELinux blocks execve() on app_data_file paths (/data/data/../)
    // even as root.  /data/local/tmp has shell_data_file context → always exec OK.
    //
    // Stage 1: wrapper script pointing to Termux python (works if SELinux permissive)
    // Stage 2: copy Termux python binary + libs to /data/local/tmp, run from there
    // Stage 3: if python not installed, trigger install via Termux RUN_COMMAND broadcast
    // Stage 4: system python3 fallback paths

    private static final String TERMUX_SH     = "/data/data/com.termux/files/usr/bin/sh";
    private static final String LAUNCHER_PATH  = "/data/local/tmp/matrix_py3.sh";
    private static final String COPY_BIN       = "/data/local/tmp/matrix_python3";
    private static final String COPY_LIB       = "/data/local/tmp/matrix_pylib";
    private static final String COPY_LAUNCHER  = "/data/local/tmp/matrix_py3_copy.sh";

    private void writeScript(File cache, String dest, String... lines) {
        try (java.io.PrintWriter pw = new java.io.PrintWriter(cache)) {
            for (String l : lines) pw.println(l);
        } catch (Exception e) { Log.e(TAG, "writeScript failed", e); return; }
        ShellUtils.runAsRoot("cp " + cache.getAbsolutePath() + " " + dest);
        ShellUtils.runAsRoot("chmod 755 " + dest);
    }

    private static final String DL_LAUNCHER = "/data/local/tmp/matrix_py3_dl.sh";

    /** Write the launcher wrapper for auto-downloaded Python. */
    private void writeDlLauncher() {
        writeScript(new File(getCacheDir(), "py3dl.sh"), DL_LAUNCHER,
            "#!/system/bin/sh",
            "export LD_LIBRARY_PATH=" + PythonInstaller.PYTHON_LIB,
            "export PYTHONHOME=" + PythonInstaller.PYTHON_HOME,
            "export HOME=/data/local/tmp",
            "export TMPDIR=/data/local/tmp",
            "export PYTHONPATH=",
            "exec " + PythonInstaller.PYTHON_BIN + " \"$@\""
        );
    }

    private String findPython(String pkg) {

        // ── Pre-check: already downloaded Python (fastest path on repeat runs) ─
        if (PythonInstaller.isInstalled()) {
            log(pkg, "SCRIPT", "Cached Python found — probing...");
            // Always re-apply chmod so lib-dynload .so files stay executable
            ShellUtils.runAsRoot("chmod -R 755 " + PythonInstaller.INSTALL_DIR + "/usr/ 2>/dev/null; true");
            writeDlLauncher();
            String ver = ShellUtils.runAsRoot("/system/bin/sh " + DL_LAUNCHER + " --version 2>&1");
            log(pkg, "SCRIPT", "Cached probe → [" + ver.trim() + "]");
            if (ver.contains("Python 3")) {
                log(pkg, "SCRIPT", "Python ready (cached): " + ver.trim());
                return "/system/bin/sh " + DL_LAUNCHER;
            }
            // Cached but broken — wipe and fall through to re-download
            log(pkg, "SCRIPT", "Cached Python broken — clearing...");
            ShellUtils.runAsRoot("rm -rf " + PythonInstaller.INSTALL_DIR);
        }

        // ── Stage 1: wrapper script → Termux python in-place ─────────────────
        writeScript(new File(getCacheDir(), "py3.sh"), LAUNCHER_PATH,
            "#!/system/bin/sh",
            "export LD_LIBRARY_PATH=" + TERMUX_LIB,
            "export HOME=" + TERMUX_HOME,
            "export PREFIX=" + TERMUX_USR,
            "export TMPDIR=/data/local/tmp",
            "export PYTHONHOME=" + TERMUX_USR,
            "export PATH=" + TERMUX_USR + "/bin:" + TERMUX_USR + "/sbin:/sbin:/system/bin",
            "exec " + PYTHON_TERMUX + " \"$@\""
        );
        String ver = ShellUtils.runAsRoot("/system/bin/sh " + LAUNCHER_PATH + " --version 2>&1");
        log(pkg, "SCRIPT", "Stage1 probe → [" + ver.trim() + "]");
        if (ver.contains("Python 3")) {
            log(pkg, "SCRIPT", "Python OK (in-place): " + ver.trim());
            return "/system/bin/sh " + LAUNCHER_PATH;
        }

        // ── Stage 2: copy Termux binary to /data/local/tmp ───────────────────
        log(pkg, "SCRIPT", "Stage2: copying Termux python3 to /data/local/tmp...");
        String cpBin = ShellUtils.runAsRoot(
            "cp " + PYTHON_TERMUX + " " + COPY_BIN + " 2>&1 && chmod 755 " + COPY_BIN + " && echo __ok__");
        log(pkg, "SCRIPT", "  cp bin → " + (cpBin.contains("__ok__") ? "ok" : cpBin.trim()));

        if (cpBin.contains("__ok__")) {
            ShellUtils.runAsRoot("mkdir -p " + COPY_LIB);
            ShellUtils.runAsRoot("cp " + TERMUX_LIB + "/libpython3*.so* " + COPY_LIB + "/ 2>/dev/null; true");
            ShellUtils.runAsRoot("cp " + TERMUX_LIB + "/libssl*.so*    " + COPY_LIB + "/ 2>/dev/null; true");
            ShellUtils.runAsRoot("cp " + TERMUX_LIB + "/libcrypto*.so* " + COPY_LIB + "/ 2>/dev/null; true");
            ShellUtils.runAsRoot("cp " + TERMUX_LIB + "/libz.so*       " + COPY_LIB + "/ 2>/dev/null; true");
            ShellUtils.runAsRoot("chmod 755 " + COPY_LIB + "/*.so* 2>/dev/null; true");
            writeScript(new File(getCacheDir(), "py3copy.sh"), COPY_LAUNCHER,
                "#!/system/bin/sh",
                "export LD_LIBRARY_PATH=" + COPY_LIB + ":" + TERMUX_LIB,
                "export PYTHONHOME=" + TERMUX_USR,
                "export HOME=" + TERMUX_HOME,
                "export TMPDIR=/data/local/tmp",
                "exec " + COPY_BIN + " \"$@\""
            );
            ver = ShellUtils.runAsRoot("/system/bin/sh " + COPY_LAUNCHER + " --version 2>&1");
            log(pkg, "SCRIPT", "Stage2 probe → [" + ver.trim() + "]");
            if (ver.contains("Python 3")) {
                log(pkg, "SCRIPT", "Python OK (copy mode): " + ver.trim());
                return "/system/bin/sh " + COPY_LAUNCHER;
            }
        }

        // ── Stage 3: auto-download Python from packages.termux.dev ───────────
        log(pkg, "SCRIPT", "Stage3: auto-downloading Python (~15 MB, one-time)...");
        if (PythonInstaller.install(this, (tag, msg) -> log(pkg, tag, msg))) {
            writeDlLauncher();
            ver = ShellUtils.runAsRoot("/system/bin/sh " + DL_LAUNCHER + " --version 2>&1");
            log(pkg, "SCRIPT", "Downloaded Python probe → [" + ver.trim() + "]");
            if (ver.contains("Python 3")) {
                log(pkg, "SCRIPT", "Python ready (downloaded): " + ver.trim());
                return "/system/bin/sh " + DL_LAUNCHER;
            }
            log(pkg, "ERROR", "Download succeeded but Python still not executable.");
            log(pkg, "ERROR", "Check: " + ver.trim());
        }

        // ── Stage 4: system python3 fallbacks ────────────────────────────────
        for (String c : new String[]{PYTHON_SYSTEM, "/usr/local/bin/python3", "/system/bin/python3", "python3"}) {
            ver = ShellUtils.runAsRoot(c + " --version 2>&1");
            if (ver.contains("Python 3")) {
                log(pkg, "SCRIPT", "System Python: " + c + " (" + ver.trim() + ")");
                return c;
            }
        }

        log(pkg, "ERROR", "Python 3 not found. Check internet connection for auto-install.");
        return null;
    }

    // ── Notification helpers ──────────────────────────────────────────────────

    private void sendCompletionNotif(String title, String text, String pkg) {
        Intent logIntent = new Intent(this, LogActivity.class);
        logIntent.putExtra("packageName", pkg);
        logIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent tapIntent = PendingIntent.getActivity(
            this, 2, logIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification notif;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm.getNotificationChannel("dumper_done") == null) {
                NotificationChannel done = new NotificationChannel(
                    "dumper_done", "Dump Results", NotificationManager.IMPORTANCE_HIGH);
                done.setShowBadge(true);
                nm.createNotificationChannel(done);
            }
            notif = new Notification.Builder(this, "dumper_done")
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentIntent(tapIntent)
                .setAutoCancel(true)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .build();
        } else {
            notif = new Notification.Builder(this)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentIntent(tapIntent)
                .setAutoCancel(true)
                .build();
        }
        ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).notify(42, notif);
    }

    private Notification buildNotif(String text) {
        PendingIntent pi = PendingIntent.getActivity(this, 0,
            new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return new Notification.Builder(this, CHANNEL)
                .setContentTitle("Matrix Dumper")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
        } else {
            return new Notification.Builder(this)
                .setContentTitle("Matrix Dumper")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
        }
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL, "Dumper", NotificationManager.IMPORTANCE_LOW);
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE))
                .createNotificationChannel(ch);
        }
    }

    // ── Broadcast helpers ─────────────────────────────────────────────────────

    private void log(String pkg, String tag, String msg) {
        String line = "[" + TS.format(new Date()) + "] [" + tag + "] " + msg;
        Log.d(TAG, line);
        Intent i = new Intent(ACTION_LOG);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_PACKAGE, pkg);
        i.putExtra(EXTRA_LINE, line);
        sendBroadcast(i);
    }

    private void finish(String pkg, int code, int dexCount) {
        Intent i = new Intent(ACTION_DONE);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_PACKAGE, pkg);
        i.putExtra(EXTRA_EXIT, code);
        i.putExtra(EXTRA_DEX_COUNT, dexCount);
        sendBroadcast(i);
        stopSelf();
    }

    private void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    @Override public IBinder onBind(Intent i) { return null; }
}
