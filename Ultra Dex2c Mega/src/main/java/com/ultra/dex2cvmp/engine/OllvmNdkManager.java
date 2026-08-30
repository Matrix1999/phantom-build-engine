package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import com.ultra.dex2cvmp.service.NdkDownloadService;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * OllvmNdkManager — optional OLLVM-patched NDK (android-ndk-r28c-ollvm).
 *
 * Source:  https://github.com/Matrix1999/ollvm-19  (arm64 + arm32 targets)
 * Fork:    https://github.com/Matrix1999/Android-NDK-
 *
 * Install path:  /data/data/com.ultra.dex2cvmp/files/ollvm_ndk/   (getFilesDir())
 *
 * Stored in app-private internal storage — inaccessible to file managers,
 * Termux, or any non-root process on the device. Automatically deleted when
 * the user uninstalls the app. Only accessible via the in-app Delete button.
 *
 * Download features:
 *   • Resume  — uses HTTP Range to continue a partial download after a network drop.
 *   • Retry   — retries automatically on any network error (exponential back-off,
 *               capped at 30 s) until the download succeeds or the user cancels.
 *   • Cancel  — call cancelDownload(); the loop exits cleanly at the next chunk boundary.
 *
 * Obfuscation passes (applied when this NDK is selected in Tools Setup):
 *   -fla   -bcf   -sub   -sobf   -split   -ibr   -icall   -igv   -fncmd
 */
public class OllvmNdkManager {

    private static final String TAG = "OllvmNdkManager";

    public static final String DOWNLOAD_URL =
        "https://github.com/Matrix1999/ollvm-19/releases/download/android-ndk-ollvm/android-ndk-r28c-ollvm.tar.xz";

    // Bump this marker version whenever the NDK is rebuilt with new capabilities.
    // Changing the name forces existing users to re-download automatically.
    private static final String MARKER        = ".ollvm_ndk_v2";  // v2 = arm64 + arm32
    private static final String TAR_FILENAME  = "android-ndk-r28c-ollvm.tar.xz";

    // Cancel flag — volatile so the background thread sees it immediately.
    private static volatile boolean sCancelled = false;

    // App context — set once via init() from CompilerManager constructor.
    private static Context sContext;

    /** Must be called once before any other method (done in CompilerManager constructor). */
    public static void init(Context ctx) {
        sContext = ctx.getApplicationContext();
    }

    // ── Paths ─────────────────────────────────────────────────────────────────
    // NDK lives in app-internal storage — executable, invisible to file managers,
    // and automatically deleted when the user uninstalls the app.

    public static File getInstallRoot() {
        return new File(sContext.getFilesDir(), "ollvm_ndk");
    }

    public static File getNdkDir() {
        return new File(getInstallRoot(), "android-ndk-r28c-ollvm");
    }

    public static boolean isInstalled() {
        return new File(getInstallRoot(), MARKER).exists() && getNdkDir().isDirectory();
    }

    public static File findClangBin() {
        File prebuiltBase = new File(getNdkDir(), "toolchains/llvm/prebuilt");
        if (!prebuiltBase.isDirectory()) {
            Log.w(TAG, "findClangBin: prebuilt dir missing: " + prebuiltBase);
            return null;
        }
        // README confirms prebuilt folder is "linux-arm64" on Termux/ARM64 devices
        String[] platforms = { "linux-arm64", "linux-aarch64", "linux-x86_64" };
        // Try well-known names first (fast path). clang-19 = OLLVM NDK r28c actual binary.
        String[] knownNames = { "clang-19", "clang-21", "clang-20", "clang-18", "clang" };
        for (String plat : platforms) {
            File binDir = new File(prebuiltBase, plat + "/bin");
            if (!binDir.isDirectory()) {
                Log.d(TAG, "findClangBin: skip " + plat + " (no bin dir)");
                continue;
            }
            Log.d(TAG, "findClangBin: scanning " + binDir);
            for (String name : knownNames) {
                File f = new File(binDir, name);
                if (f.exists()) {
                    Log.i(TAG, "findClangBin: found " + f);
                    f.setExecutable(true, false);
                    return f;
                }
            }
            // Fallback: scan directory for any file named exactly "clang" or "clang-N"
            // Handles OLLVM builds that use a non-standard version number.
            File[] entries = binDir.listFiles();
            if (entries != null) {
                Log.d(TAG, "findClangBin: bin dir has " + entries.length + " entries");
                File best = null;
                for (File f : entries) {
                    String n = f.getName();
                    if (!f.isFile()) continue;
                    if (n.equals("clang") || n.matches("clang-\\d+")) {
                        // Prefer versioned over plain "clang"
                        if (best == null || (!best.getName().contains("-") && n.contains("-"))) {
                            best = f;
                        }
                    }
                }
                if (best != null) {
                    Log.i(TAG, "findClangBin: scan found " + best);
                    best.setExecutable(true, false);
                    return best;
                }
            } else {
                Log.w(TAG, "findClangBin: listFiles() returned null for " + binDir);
            }
        }
        // Log what actually exists under prebuilt so we can diagnose
        File[] platDirs = prebuiltBase.listFiles();
        if (platDirs != null) {
            for (File pd : platDirs) {
                Log.w(TAG, "findClangBin: prebuilt contains: " + pd.getName() + (pd.isDirectory() ? "/" : ""));
                if (pd.isDirectory()) {
                    File bd = new File(pd, "bin");
                    if (bd.isDirectory()) {
                        File[] bins = bd.listFiles();
                        if (bins != null) for (File b : bins)
                            Log.w(TAG, "findClangBin:   bin/" + b.getName());
                    }
                }
            }
        }
        Log.w(TAG, "findClangBin: no clang binary found under " + prebuiltBase);
        return null;
    }

    public static File findSysrootDir() {
        File prebuiltBase = new File(getNdkDir(), "toolchains/llvm/prebuilt");
        if (!prebuiltBase.isDirectory()) return null;
        String[] platforms = { "linux-arm64", "linux-aarch64", "linux-x86_64" };
        for (String plat : platforms) {
            File sr = new File(prebuiltBase, plat + "/sysroot");
            if (sr.isDirectory()) return sr;
        }
        return null;
    }

    // ── Download / Install ────────────────────────────────────────────────────

    public interface DownloadCallback {
        /** Called from the background thread — caller must post to UI thread for view ops. */
        void onProgress(int pct, String message);
        /** Called exactly once when done (success or not). */
        void onDone(boolean success, String error);
    }

    /** Signal the background thread to stop at the next chunk boundary. */
    public static void cancelDownload() {
        sCancelled = true;
    }

    /**
     * Downloads and extracts the OLLVM NDK on a background thread.
     *
     * Resume: if a partial .tar.xz is already on disk its size is sent as
     *         the Range start — the server picks up from that byte offset.
     *
     * Retry:  on any IOException the thread sleeps (2 s → 4 s → … → 30 s max)
     *         and retries the download from the current file size. Extraction
     *         is only attempted once the full file is on disk.
     *
     * Cancel: set via cancelDownload(). The loop checks the flag after every
     *         chunk; onDone(false, "Cancelled") is called and the partial tar
     *         is left on disk so the next attempt can resume from it.
     */
    public static void downloadAndInstall(DownloadCallback cb) {
        sCancelled = false;

        new Thread(() -> {
            File root = getInstallRoot();
            root.mkdirs();
            File tarFile = new File(root, TAR_FILENAME);

            // ── Phase 1: Download with resume + retry ─────────────────────────
            try {
                if (!downloadWithResume(tarFile, cb)) return; // cancelled or error already reported
            } catch (Exception e) {
                Log.e(TAG, "Download phase failed", e);
                cb.onDone(false, e.getMessage());
                return;
            }

            if (sCancelled) {
                cb.onDone(false, "Cancelled");
                return;
            }

            // ── Phase 2: XZ decompress + TAR extract ──────────────────────────
            cb.onProgress(41, "Extracting…");
            try {
                extractTar(tarFile, root, cb);
            } catch (Exception e) {
                Log.e(TAG, "Extraction failed", e);
                tarFile.delete();
                cb.onDone(false, "Extraction failed: " + e.getMessage());
                return;
            }

            if (sCancelled) {
                cb.onDone(false, "Cancelled");
                return;
            }

            // ── Phase 3: Finalise ─────────────────────────────────────────────
            try {
                new File(root, MARKER).createNewFile();
            } catch (IOException e) {
                Log.w(TAG, "Could not write marker: " + e.getMessage());
            }
            tarFile.delete();
            Log.i(TAG, "OLLVM NDK installed at: " + root.getAbsolutePath());
            cb.onProgress(100, "OLLVM NDK ready ✓");
            cb.onDone(true, null);

        }, "ollvm-ndk-install").start();
    }

    // ── Resume-aware downloader with retry loop ───────────────────────────────

    /**
     * Returns true when the file is fully downloaded, false on cancel.
     * Throws on a permanent error (not expected in normal use).
     */
    private static boolean downloadWithResume(File tarFile, DownloadCallback cb)
            throws Exception {

        int  retryCount = 0;
        long retryDelay = 2_000; // ms, doubles each retry, capped at 30 s

        while (true) {
            if (sCancelled) { cb.onDone(false, "Cancelled"); return false; }

            long resumeFrom = tarFile.exists() ? tarFile.length() : 0L;

            try {
                String attempt = retryCount == 0 ? "Connecting…"
                        : "Retrying… (attempt " + (retryCount + 1) + ")";
                cb.onProgress(resumeFrom > 0 ? 1 : 0, attempt);

                URL url = new URL(DOWNLOAD_URL);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setInstanceFollowRedirects(true);
                conn.setConnectTimeout(20_000);
                conn.setReadTimeout(45_000);

                // Request server to resume from the current file size
                if (resumeFrom > 0) {
                    conn.setRequestProperty("Range", "bytes=" + resumeFrom + "-");
                }

                conn.connect();
                int status = conn.getResponseCode();

                if (status == HttpURLConnection.HTTP_OK) {
                    // Server doesn't support Range or file offset is 0 — start fresh
                    resumeFrom = 0;
                    if (tarFile.exists()) tarFile.delete();
                } else if (status == HttpURLConnection.HTTP_PARTIAL) {
                    // 206 Partial Content — server will stream from resumeFrom
                } else {
                    throw new IOException("Unexpected HTTP status: " + status);
                }

                long total = conn.getContentLengthLong();
                if (status == HttpURLConnection.HTTP_PARTIAL && resumeFrom > 0) {
                    // total from Content-Length is just the remaining bytes;
                    // full size = resumeFrom + total (or -1 if chunked)
                    if (total > 0) total += resumeFrom;
                }

                // Append mode when resuming
                try (InputStream netIn = new BufferedInputStream(conn.getInputStream(), 131_072);
                     FileOutputStream fo = new FileOutputStream(tarFile, resumeFrom > 0)) {

                    byte[] buf = new byte[131_072];
                    long downloaded = resumeFrom;
                    int n;

                    while ((n = netIn.read(buf)) != -1) {
                        if (sCancelled) {
                            // Leave partial file on disk for next resume
                            cb.onDone(false, "Cancelled");
                            return false;
                        }
                        fo.write(buf, 0, n);
                        downloaded += n;

                        if (total > 0) {
                            int pct = (int) (downloaded * 40L / total);
                            cb.onProgress(pct,
                                "Downloading… " + mb(downloaded) + " / " + mb(total) + " MB");
                        } else {
                            cb.onProgress(15,
                                "Downloading… " + mb(downloaded) + " MB");
                        }
                    }

                    // Android 16 / HTTP-2: the server can silently close the stream
                    // (RST_STREAM / GOAWAY) mid-transfer and read() returns -1 without
                    // throwing IOException — the loop exits thinking the download is done
                    // but the file is truncated.  Always verify the received byte count
                    // against Content-Length when the server provided one.
                    if (total > 0 && downloaded < total) {
                        throw new IOException(
                            "Incomplete download: got " + downloaded + " of " + total + " bytes");
                    }
                }

                // Success — break out of retry loop
                cb.onProgress(40, "Download complete — extracting…");
                return true;

            } catch (IOException e) {
                if (sCancelled) { cb.onDone(false, "Cancelled"); return false; }

                retryCount++;
                Log.w(TAG, "Network error (attempt " + retryCount + "): " + e.getMessage());

                String wait = retryDelay >= 1_000
                        ? (retryDelay / 1_000) + "s" : retryDelay + "ms";
                cb.onProgress(
                    tarFile.exists() ? (int)(tarFile.length() * 40L / Math.max(tarFile.length() * 3, 1)) : 0,
                    "Network lost — retrying in " + wait + "… (" + e.getMessage() + ")"
                );

                // Wait, but wake up immediately if cancelled
                long deadline = System.currentTimeMillis() + retryDelay;
                while (System.currentTimeMillis() < deadline) {
                    if (sCancelled) { cb.onDone(false, "Cancelled"); return false; }
                    try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                }

                // Exponential back-off capped at 30 s
                retryDelay = Math.min(retryDelay * 2, 30_000);
            }
        }
    }

    // ── TAR extractor ─────────────────────────────────────────────────────────

    private static void extractTar(File tarFile, File root, DownloadCallback cb)
            throws Exception {

        // Pass an explicit memory limit so we get a clean MemoryLimitException
        // instead of OutOfMemoryError on low-RAM / Android-16 devices.
        // 192 MB covers any LZMA2 dictionary the OLLVM NDK uses (typical: 64–128 MB).
        final int XZ_MEM_LIMIT = 192 * 1024 * 1024;
        try (FileInputStream fis = new FileInputStream(tarFile);
             BufferedInputStream bis = new BufferedInputStream(fis, 131_072);
             org.tukaani.xz.XZInputStream xzIn =
                     new org.tukaani.xz.XZInputStream(bis, XZ_MEM_LIMIT)) {

            NdkDownloadService.TarInputStream tar =
                    new NdkDownloadService.TarInputStream(xzIn);

            NdkDownloadService.TarEntry entry;
            int count = 0;

            while ((entry = tar.nextEntry()) != null) {
                if (sCancelled) return; // caller checks flag and reports done

                String name = entry.name;
                if (name.isEmpty() || name.equals(".") || name.equals("./")) continue;

                File dest = new File(root, name);
                // Path-traversal guard
                if (!dest.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator))
                    continue;

                if (entry.isDirectory) {
                    dest.mkdirs();
                } else if (entry.isSymlink && entry.linkTarget != null
                        && !entry.linkTarget.isEmpty()) {
                    dest.getParentFile().mkdirs();
                    dest.delete();
                    try { Os.symlink(entry.linkTarget, dest.getAbsolutePath()); }
                    catch (ErrnoException ex) { Log.w(TAG, "symlink: " + ex.getMessage()); }
                } else {
                    dest.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(dest)) {
                        byte[] buf = new byte[65_536];
                        int n;
                        while ((n = tar.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    if ((entry.mode & 0111) != 0) dest.setExecutable(true, false);
                }

                count++;
                if (count % 300 == 0) {
                    cb.onProgress(Math.min(95, 41 + count / 300),
                            "Extracting… " + count + " files");
                }
            }
        }
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    /** Deletes the entire install root. Call from a background thread. */
    public static void uninstall() {
        deleteRecursive(getInstallRoot());
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] ch = f.listFiles();
            if (ch != null) for (File c : ch) deleteRecursive(c);
        }
        f.delete();
    }

    // ── Util ──────────────────────────────────────────────────────────────────

    private static long mb(long bytes) { return bytes / 1_048_576; }
}
