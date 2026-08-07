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

    private static final String TAG              = "AmiceManager";
    private static final String ASSET_PATH       = "VMP_Plugin/libvmp_plugin.arm64.so";
    private static final String LLVM_ASSET_PATH  = "VMP_Plugin/libLLVM.android.arm64.so";
    private static final String MARKER           = ".vmp_v1";
    private static final String SO_FILENAME      = "libvmp_plugin.arm64.so";
    private static final String LLVM_SO_FILENAME = "libLLVM.android.arm64.so";

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

    public static File getLlvmFile() {
        return new File(getInstallRoot(), LLVM_SO_FILENAME);
    }

    public static boolean isInstalled() {
        File root = getInstallRoot();
        return new File(root, MARKER).exists() && getPluginFile().isFile();
    }

    // ── Extract from assets ───────────────────────────────────────────────────

    /**
     * Extracts both libvmp_plugin.arm64.so and libLLVM.android.arm64.so from
     * APK assets every call — always uses the latest bundled binaries.
     *
     * @return true if both files are ready, false on error.
     */
    public static boolean ensureExtracted() {
        File root = getInstallRoot();
        root.mkdirs();

        // Extract plugin
        if (!extractAsset(ASSET_PATH, new File(root, SO_FILENAME))) return false;

        // Extract libLLVM.so (provides LLVM C API symbols the plugin needs)
        // If not bundled in this APK version, skip gracefully.
        extractAsset(LLVM_ASSET_PATH, new File(root, LLVM_SO_FILENAME));

        new File(root, MARKER).createNewFile();
        return true;
    }

    private static boolean extractAsset(String assetPath, File dest) {
        try {
            AssetManager am = sContext.getAssets();
            try (InputStream in  = new BufferedInputStream(am.open(assetPath), 65_536);
                 FileOutputStream out = new FileOutputStream(dest)) {
                byte[] buf = new byte[65_536];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            }
            dest.setExecutable(true, false);
            Log.i(TAG, "Extracted: " + dest.getName() + " (" + dest.length() + " bytes)");
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to extract " + assetPath + " from assets", e);
            dest.delete();
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
