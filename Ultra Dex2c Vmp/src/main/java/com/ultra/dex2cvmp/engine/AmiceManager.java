package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.*;

/**
 * AmiceManager — manages the LLVM VMP plugin for aarch64-linux-android.
 *
 * Bundled inside the APK at assets/VMP_Plugin/libvmp_plugin.arm64.so.
 * On first use it is extracted to the app's private files directory so
 * clang-19 can load it via -fpass-plugin at compile time.
 *
 * No network access is required — the plugin ships with the app.
 *
 * Passes enabled (all 8):
 *   VMP, FLATTEN, MBA, BOGUS_CONTROL_FLOW, INDIRECT_CALL,
 *   INDIRECT_BRANCH, SPLIT_BASIC_BLOCK, STRING_ENCRYPTION
 */
public class AmiceManager {

    private static final String TAG         = "AmiceManager";
    private static final String ASSET_PATH  = "VMP_Plugin/libvmp_plugin.arm64.so";
    private static final String MARKER      = ".vmp_v1";
    private static final String SO_FILENAME = "libvmp_plugin.arm64.so";

    private static Context sContext;

    public static void init(Context ctx) {
        sContext = ctx.getApplicationContext();
    }

    // ── Paths ─────────────────────────────────────────────────────────────────

    public static File getInstallRoot() {
        return new File(sContext.getFilesDir(), "vmp_plugin");
    }

    public static File getPluginFile() {
        return new File(getInstallRoot(), SO_FILENAME);
    }

    public static boolean isInstalled() {
        File root = getInstallRoot();
        return new File(root, MARKER).exists() && getPluginFile().isFile();
    }

    // ── Extract from assets ───────────────────────────────────────────────────

    /**
     * Extracts libvmp_plugin.arm64.so from the APK assets to the private files dir
     * every single time it is called, so the latest bundled plugin is always used.
     *
     * @return true if ready to use after this call, false on error.
     */
    public static boolean ensureExtracted() {
        File root = getInstallRoot();
        root.mkdirs();
        File soFile = new File(root, SO_FILENAME);

        try {
            AssetManager am = sContext.getAssets();
            try (InputStream in  = new BufferedInputStream(am.open(ASSET_PATH), 65_536);
                 FileOutputStream out = new FileOutputStream(soFile)) {

                byte[] buf = new byte[65_536];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            }

            soFile.setExecutable(true, false);
            new File(root, MARKER).createNewFile();

            Log.i(TAG, "VMP plugin extracted: " + soFile.getAbsolutePath()
                    + " (" + soFile.length() + " bytes)");
            return true;

        } catch (IOException e) {
            Log.e(TAG, "Failed to extract VMP plugin from assets", e);
            soFile.delete();
            return false;
        }
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    public static void uninstall() {
        deleteRecursive(getInstallRoot());
        Log.i(TAG, "VMP plugin removed");
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] ch = f.listFiles();
            if (ch != null) for (File c : ch) deleteRecursive(c);
        }
        f.delete();
    }
}
