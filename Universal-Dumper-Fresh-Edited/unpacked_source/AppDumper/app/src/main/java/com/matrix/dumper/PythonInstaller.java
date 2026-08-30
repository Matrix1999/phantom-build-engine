package com.matrix.dumper;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import org.tukaani.xz.XZInputStream;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 * Downloads Termux's Python (aarch64) from packages.termux.dev and extracts it to
 * /data/local/tmp/matrix_python/ — a path with shell_data_file SELinux context
 * that root can always execute from, unlike /data/data/com.termux/ which is blocked
 * by Android 16's app_data_file exec restriction even for root.
 *
 * This is a one-time download (~15 MB). Once cached the binary is reused on every run.
 */
public class PythonInstaller {

    private static final String TAG = "PythonInstaller";

    public static final String INSTALL_DIR = "/data/local/tmp/matrix_python";
    public static final String PYTHON_BIN  = INSTALL_DIR + "/usr/bin/python3";
    public static final String PYTHON_LIB  = INSTALL_DIR + "/usr/lib";
    public static final String PYTHON_HOME = INSTALL_DIR + "/usr";

    private static final String REPO_BASE  = "https://packages.termux.dev/apt/termux-main/";

    /** Maps Android ABI → Termux repo arch folder. */
    private static String getTermuxArch() {
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0
                ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        switch (abi) {
            case "armeabi-v7a": return "arm";
            case "x86_64":      return "x86_64";
            case "x86":         return "i686";
            default:            return "aarch64"; // arm64-v8a
        }
    }

    private static String getPkgIndex() {
        return REPO_BASE + "dists/stable/main/binary-" + getTermuxArch() + "/Packages";
    }

    // python + its Android compat runtime dependency
    private static final String[] REQUIRED_PKGS = { "python", "libandroid-support" };

    public interface LogCb { void log(String tag, String msg); }

    /**
     * Check via root shell — the app process (untrusted_app) cannot stat
     * shell_data_file paths like /data/local/tmp/matrix_python/, so
     * File.exists() always returns false even when files are there.
     */
    public static boolean isInstalled() {
        String r = ShellUtils.runAsRoot(
            "[ -f " + PYTHON_BIN + " -o -L " + PYTHON_BIN + " ] && echo __yes__ || echo __no__");
        return r.contains("__yes__");
    }

    // ── Public entry point ────────────────────────────────────────────────────

    public static boolean install(Context ctx, LogCb log) {
        try {
            log.log("SCRIPT", "Querying Termux package index...");
            List<String> urls = resolveUrls(log);
            if (urls.isEmpty()) {
                log.log("ERROR", "Package index unavailable — need internet access");
                return false;
            }

            // Extract into app's own cache dir — untrusted_app can always write there.
            // We cannot mkdir inside /data/local/tmp (shell_data_file) from the app
            // process due to SELinux; only a root shell can do that.
            File extractDir = new File(ctx.getCacheDir(), "py_extract");
            deleteDir(extractDir);
            extractDir.mkdirs();

            for (String url : urls) {
                String name = url.substring(url.lastIndexOf('/') + 1);
                log.log("SCRIPT", "Downloading " + name + "...");
                File tmp = new File(ctx.getCacheDir(), "termux_pkg.deb");
                download(url, tmp, log);
                log.log("SCRIPT", "Extracting " + name + "...");
                extractDeb(tmp, extractDir);           // always succeeds — app-owned dir
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }

            // Root-copy from app cache → /data/local/tmp/matrix_python/
            log.log("SCRIPT", "Installing to " + INSTALL_DIR + " (root copy)...");
            String mkRes = ShellUtils.runAsRoot("mkdir -p " + INSTALL_DIR + " && echo __ok__");
            if (!mkRes.contains("__ok__")) {
                log.log("ERROR", "mkdir " + INSTALL_DIR + " failed: " + mkRes.trim());
                return false;
            }
            // cp -a preserves symlinks; fall back to cp -rf if toybox doesn't support -a
            ShellUtils.runAsRoot(
                "cp -a " + extractDir.getAbsolutePath() + "/. " + INSTALL_DIR + "/ 2>/dev/null || " +
                "cp -rf " + extractDir.getAbsolutePath() + "/. " + INSTALL_DIR + "/");

            // Fix execute bits on the entire usr/ tree — this covers binaries,
            // shared libs in usr/lib/, AND C-extension .so files in lib-dynload/
            // (without which Python raises ModuleNotFoundError for built-in modules)
            ShellUtils.runAsRoot("chmod -R 755 " + INSTALL_DIR + "/usr/ 2>/dev/null; true");

            // If python3 symlink is still missing (cp -rf doesn't copy symlinks),
            // create it pointing to whatever python3.x binary exists
            ShellUtils.runAsRoot(
                "if [ ! -f " + PYTHON_BIN + " -a ! -L " + PYTHON_BIN + " ]; then " +
                "  REAL=$(ls " + INSTALL_DIR + "/usr/bin/python3.* 2>/dev/null | head -1); " +
                "  [ -n \"$REAL\" ] && ln -sf \"$REAL\" " + PYTHON_BIN + "; " +
                "fi");

            // Clean up cache
            deleteDir(extractDir);

            String probe = ShellUtils.runAsRoot(PYTHON_BIN + " --version 2>&1");
            log.log("SCRIPT", "Install probe → [" + probe.trim() + "]");
            log.log("SCRIPT", "Python ready at: " + PYTHON_BIN);
            return isInstalled();

        } catch (Exception e) {
            log.log("ERROR", "Auto-install failed: " + e.getMessage());
            Log.e(TAG, "install() exception", e);
            return false;
        }
    }

    private static void deleteDir(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDir(f);
            else //noinspection ResultOfMethodCallIgnored
                f.delete();
        }
        //noinspection ResultOfMethodCallIgnored
        dir.delete();
    }

    // ── Package index parsing ─────────────────────────────────────────────────

    private static List<String> resolveUrls(LogCb log) throws IOException {
        List<String> result = new ArrayList<>();

        String arch = getTermuxArch();
        log.log("SCRIPT", "Device ABI: " + Build.SUPPORTED_ABIS[0] + " → Termux arch: " + arch);
        URL url = new URL(getPkgIndex());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(30_000);
        String content;
        try {
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
            }
            content = sb.toString();
        } finally {
            conn.disconnect();
        }

        for (String pkg : REQUIRED_PKGS) {
            String debPath = findFilename(content, pkg);
            if (debPath != null) {
                result.add(REPO_BASE + debPath);
                log.log("SCRIPT", "  Resolved: " + debPath);
            } else {
                log.log("SCRIPT", "  Not in index: " + pkg + " (skipping)");
            }
        }
        return result;
    }

    private static String findFilename(String index, String pkg) {
        // Search for an exact "Package: <name>" paragraph
        String[] blocks = index.split("\n\n");
        for (String block : blocks) {
            boolean matchesPkg = false;
            String filename = null;
            for (String line : block.split("\n")) {
                if (line.equals("Package: " + pkg)) matchesPkg = true;
                if (line.startsWith("Filename: ")) filename = line.substring("Filename: ".length()).trim();
            }
            if (matchesPkg && filename != null) return filename;
        }
        return null;
    }

    // ── HTTP download with MB progress ───────────────────────────────────────

    private static void download(String urlStr, File dest, LogCb log) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(30_000);
        conn.setReadTimeout(120_000);
        try {
            int total = conn.getContentLength();
            try (InputStream  in  = conn.getInputStream();
                 FileOutputStream out = new FileOutputStream(dest)) {
                byte[] buf = new byte[65536];
                int downloaded = 0, lastMb = -1, n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    downloaded += n;
                    int mb = downloaded / (1024 * 1024);
                    if (mb != lastMb) {
                        lastMb = mb;
                        String progress = total > 0
                            ? mb + " / " + (total / 1024 / 1024) + " MB"
                            : mb + " MB";
                        log.log("SCRIPT", "  " + progress);
                    }
                }
            }
        } finally {
            conn.disconnect();
        }
    }

    // ── .deb (ar archive) extraction ─────────────────────────────────────────

    private static void extractDeb(File deb, File destDir) throws Exception {
        try (FileInputStream fis = new FileInputStream(deb)) {
            // ar magic: "!<arch>\n"
            byte[] magic = new byte[8];
            readFully(fis, magic);
            if (!"!<arch>\n".equals(new String(magic, "ASCII"))) {
                throw new IOException("Not a valid .deb file");
            }

            while (true) {
                byte[] hdr = new byte[60];
                if (!tryReadFully(fis, hdr)) break;   // EOF

                String eName = new String(hdr,  0, 16, "ASCII").trim();
                long   eSize = Long.parseLong(new String(hdr, 48, 10, "ASCII").trim());

                if (eName.startsWith("data.tar")) {
                    // Read compressed archive into memory (≤20 MB typical)
                    byte[] data = new byte[(int) eSize];
                    readFully(fis, data);
                    if (eName.contains(".xz")) {
                        try (XZInputStream xz = new XZInputStream(new ByteArrayInputStream(data))) {
                            extractTar(xz, destDir);
                        }
                    } else if (eName.contains(".gz")) {
                        try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(data))) {
                            extractTar(gz, destDir);
                        }
                    } else {
                        extractTar(new ByteArrayInputStream(data), destDir);
                    }
                    return; // data.tar is always the last relevant entry
                } else {
                    // Skip non-data entries; ar entries are 2-byte aligned
                    skipFully(fis, eSize + (eSize & 1));
                }
            }
            throw new IOException("data.tar not found inside .deb");
        }
    }

    // ── POSIX tar extraction ──────────────────────────────────────────────────

    private static void extractTar(InputStream in, File destDir) throws IOException {
        byte[] hdr = new byte[512];
        byte[] buf = new byte[65536];

        while (true) {
            readFully(in, hdr);
            if (isZeroBlock(hdr)) break; // two consecutive zero blocks = EOF

            // Parse name (ustar prefix support)
            String name   = cstr(hdr,   0, 100);
            String prefix = cstr(hdr, 345, 155);
            if (!prefix.isEmpty()) name = prefix + "/" + name;
            if (name.startsWith("./"))  name = name.substring(2);
            if (name.startsWith("/"))   name = name.substring(1);
            // Termux .deb packages store full install paths, e.g.:
            //   data/data/com.termux/files/usr/bin/python3
            // Strip the Termux root so files land at INSTALL_DIR/usr/bin/python3
            for (String pfx : new String[]{
                    "data/data/com.termux/files/",
                    "data/user/0/com.termux/files/" }) {
                if (name.startsWith(pfx)) { name = name.substring(pfx.length()); break; }
            }
            if (name.isEmpty()) continue;

            long fileSize = Long.parseLong(cstr(hdr, 124, 12).trim(), 8);
            char type = hdr[156] == 0 ? '0' : (char)(hdr[156] & 0xFF);

            File target = new File(destDir, name);

            if (type == '5') {
                // Directory
                target.mkdirs();
            } else if (type == '2') {
                // Symlink — java.nio.file.Files requires API 26; fall back to
                // Runtime.exec("ln -sf …") on API 24-25.
                String linkTarget = cstr(hdr, 157, 100);
                if (target.getParentFile() != null) target.getParentFile().mkdirs();
                if (Build.VERSION.SDK_INT >= 26) {
                    try {
                        java.nio.file.Path linkPath = target.toPath();
                        if (java.nio.file.Files.isSymbolicLink(linkPath) || target.exists())
                            java.nio.file.Files.delete(linkPath);
                        java.nio.file.Files.createSymbolicLink(linkPath,
                            java.nio.file.Paths.get(linkTarget));
                    } catch (Exception ignored) { }
                } else {
                    try {
                        target.delete();
                        Runtime.getRuntime().exec(
                            new String[]{"ln", "-sf", linkTarget, target.getAbsolutePath()}
                        ).waitFor();
                    } catch (Exception ignored) { }
                }
            } else {
                // Regular file (type '0', '\0', or '7')
                if (target.getParentFile() != null) target.getParentFile().mkdirs();
                try (FileOutputStream fos = new FileOutputStream(target)) {
                    long rem = fileSize;
                    while (rem > 0) {
                        int n = in.read(buf, 0, (int) Math.min(buf.length, rem));
                        if (n < 0) throw new EOFException("Truncated entry: " + name);
                        fos.write(buf, 0, n);
                        rem -= n;
                    }
                }
            }

            // Skip tar block padding
            long pad = (512 - (fileSize % 512)) % 512;
            if (pad > 0) skipFully(in, pad);
        }
    }

    // ── Stream helpers ────────────────────────────────────────────────────────

    private static String cstr(byte[] buf, int off, int len) {
        int end = off;
        while (end < off + len && buf[end] != 0) end++;
        try { return new String(buf, off, end - off, "UTF-8"); }
        catch (Exception e) { return ""; }
    }

    private static boolean isZeroBlock(byte[] buf) {
        for (byte b : buf) if (b != 0) return false;
        return true;
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new EOFException("Unexpected EOF");
            off += n;
        }
    }

    private static boolean tryReadFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) return false;
            off += n;
        }
        return true;
    }

    private static void skipFully(InputStream in, long n) throws IOException {
        while (n > 0) {
            long s = in.skip(n);
            if (s <= 0) { if (in.read() < 0) break; n--; }
            else n -= s;
        }
    }
}
