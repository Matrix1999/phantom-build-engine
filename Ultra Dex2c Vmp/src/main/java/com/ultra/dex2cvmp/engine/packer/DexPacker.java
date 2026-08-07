package com.ultra.dex2cvmp.engine.packer;

import android.content.Context;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * DEX Packer — wraps a dex2c/VMP-processed APK with the com.ultra.dex2cvmp stub loader.
 *
 * Security model (per-APK random key):
 *   • A 16-byte cryptographically random salt is generated for every pack operation.
 *   • The 16-byte session key is derived via DexSeed.deriveKey(salt, pkgName).
 *   • salt is written to assets/phantom/ph_salt (raw, 16 bytes) so the stub can read it
 *     at runtime and call nativeGetKey() to reproduce the same key inside libphantom.so.
 *   • No static PROTECT_KEY string exists anywhere in the project.
 *   • Cert binding is omitted — signature tamper detection is handled by the app itself.
 *
 * Flow:
 *  1. Extract classes*.dex + AndroidManifest.xml from input APK.
 *  2. Parse manifest → capture real Application class, patch android:name → ProxyApplication.
 *  3. Generate random salt; derive session key from (salt, pkgName).
 *  4. Encrypt all DEX shards and bundle them into a single phantom.vmp payload.
 *     Bundle format: [4-byte shard count][count × 4-byte shard sizes][encrypted bytes…]
 *  5. Write assets/phantom/app.cfg  (real app class name, UTF-8).
 *     Write assets/phantom/ph_salt  (16-byte raw salt).
 *  6. Load pre-built stub.dex from our own app assets.
 *  7. Repack: stub.dex + patched manifest + phantom payload + rest of original APK.
 */
public class DexPacker {

    /** Asset sub-dir name in the output APK. Must match Const.DP_LIB. */
    public static final String ASSET_DIR = "phantom";

    /** Single-file bundle name. Must match Const.BUNDLE_FILE. */
    public static final String BUNDLE_FILE = "phantom.vmp";

    /** Fully-qualified stub Application class injected into the manifest. */
    public static final String PROXY_APP = "com.ultra.dex2cvmp.ProxyApplication";

    /** Asset name used to pass real app class to stub at runtime. */
    public static final String REAL_APP_ASSET = "app.cfg";

    /** Asset name for the 16-byte per-APK salt. Must match Const.SALT_ASSET. */
    public static final String SALT_ASSET = "ph_salt";

    /** Asset names for the OLLVM-compiled native KDF library, one per ABI.
     *  A single blob per ABI handles both root-blocking ON and OFF at runtime.
     *  The block-rooted toggle is encoded as bit 7 of salt[0] by DexPacker;
     *  libphantom.so reads and strips it before key derivation — Java never sees it. */
    public static final String BLOB_ARM64 = "libphantom_arm64.blob";
    public static final String BLOB_ARM   = "libphantom_arm.blob";

    private final Context context;

    public DexPacker(Context context) {
        this.context = context;
    }

    /**
     * Pack {@code inputApk} into {@code outputApk} using the stub loader.
     * The block-rooted toggle is read fresh from SharedPreferences at pack time
     * (dex2c_mega_prefs / block_rooted_enabled) so it always reflects whatever
     * the user last set in Settings — no stale in-memory value possible.
     *
     * @param inputApk  Dex2c/VMP-processed APK (will not be modified).
     * @param outputApk Destination for the packed APK (unsigned; sign separately).
     * @param workDir   Scratch directory for extracted + encrypted files.
     */
    public void pack(File inputApk, File outputApk, File workDir) throws Exception {
        boolean blockRootedDevices = context
                .getSharedPreferences("dex2c_mega_prefs", android.content.Context.MODE_PRIVATE)
                .getBoolean("block_rooted_enabled", true);
        // ── 1. Extract manifest + DEX files from input APK ───────────────────
        File extractDir = new File(workDir, "extracted");
        FastZip.extract(inputApk, extractDir);

        // ── 2. Parse + patch manifest ─────────────────────────────────────────
        File manifestFile = new File(extractDir, "AndroidManifest.xml");
        byte[] manifestBytes = readFile(manifestFile);
        byte[] patchedManifest = ManifestPatcher.parseManifest(manifestBytes, PROXY_APP);

        String realAppClass = ManifestPatcher.customApplication
                ? ManifestPatcher.customApplicationName
                : "android.app.Application";
        if (realAppClass.startsWith(".") && !ManifestPatcher.packageName.isEmpty()) {
            realAppClass = ManifestPatcher.packageName + realAppClass;
        }
        String pkgName = ManifestPatcher.packageName;

        // ── 3. Generate per-APK salt, embed block-rooted flag, derive session key ──
        // The flag is hidden in bit 7 of salt[0] — invisible to Java/hook layer.
        // libphantom.so reads + strips it before KDF, so the derived key is the
        // same whether the flag is set or not (clean salt = salt[0] & 0x7F for KDF).
        byte[] salt = DexSeed.randomSalt();
        if (blockRootedDevices) {
            salt[0] = (byte)(salt[0] | 0x80);   // set flag bit
        } else {
            salt[0] = (byte)(salt[0] & 0x7F);   // ensure flag bit is clear
        }
        byte[] saltForKdf = salt.clone();
        saltForKdf[0] = (byte)(saltForKdf[0] & 0x7F);  // strip flag for key derivation
        byte[] key  = DexSeed.deriveKey(saltForKdf, pkgName);
        java.util.Arrays.fill(saltForKdf, (byte) 0);

        // ── 4. Encrypt all DEX shards and bundle into one phantom.vmp ─────────
        File shardsDir = new File(workDir, "shards");
        shardsDir.mkdirs();

        List<byte[]> shards = new ArrayList<>();
        File classesDex = new File(extractDir, "classes.dex");
        if (classesDex.exists()) shards.add(encryptDexToBytes(classesDex, key));
        for (int i = 2; ; i++) {
            File dex = new File(extractDir, "classes" + i + ".dex");
            if (!dex.exists()) break;
            shards.add(encryptDexToBytes(dex, key));
        }

        // Zero the key as soon as all encryption is done.
        java.util.Arrays.fill(key, (byte) 0);

        // Write bundle: [16-byte masked blob key][4-byte count][count × 4-byte shard size][shard bytes…]
        // MASKED_BLOB_KEY[i] = BLOB_KEY[i] ^ ASSET_KEY_MASK[i]  (mask lives in stub DexCrypto)
        // Neither half alone reveals the key — both are needed.
        byte[] maskedBlobKey = {
            0x1D, 0x12, 0x28, (byte)0xFD, (byte)0x90, 0x1B, 0x05, (byte)0xB7,
            0x5B, (byte)0x96, 0x3E, (byte)0x9A, (byte)0xBD, 0x3B, (byte)0x92, 0x57
        };
        File bundleFile = new File(shardsDir, BUNDLE_FILE);
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(bundleFile))) {
            dos.write(maskedBlobKey);                              // 16-byte header
            dos.writeInt(shards.size());
            for (byte[] shard : shards) dos.writeInt(shard.length);
            for (byte[] shard : shards) dos.write(shard);
        }

        // ── 5. Write app.cfg and ph_salt ─────────────────────────────────────
        File realAppFile = new File(shardsDir, REAL_APP_ASSET);
        try (FileOutputStream fos = new FileOutputStream(realAppFile)) {
            fos.write(realAppClass.getBytes("UTF-8"));
        }

        File saltFile = new File(shardsDir, SALT_ASSET);
        try (FileOutputStream fos = new FileOutputStream(saltFile)) {
            fos.write(salt);
        }

        // ── 6. Copy libphantom blobs from our own app assets into shardsDir ───
        // One blob per ABI — the block-rooted toggle is baked into salt[0] bit 7
        // above; libphantom.so reads it at runtime. No separate rootblock blobs.
        copyAssetToDir(ASSET_DIR + "/" + BLOB_ARM64, new File(shardsDir, BLOB_ARM64));
        copyAssetToDir(ASSET_DIR + "/" + BLOB_ARM,   new File(shardsDir, BLOB_ARM));

        // ── 7. Load pre-built stub DEX from our assets ────────────────────────
        byte[] stubDex = readAsset("stub.dex");

        // ── 8. Repack ─────────────────────────────────────────────────────────
        FastZip.repack(inputApk, outputApk, stubDex, shardsDir, ASSET_DIR, patchedManifest);
    }


    // ── helpers ──────────────────────────────────────────────────────────────

    private byte[] encryptDexToBytes(File input, byte[] key) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream in = new FileInputStream(input)) {
            DexCrypto.encrypt(key, in, baos);
        }
        return baos.toByteArray();
    }

    private byte[] readFile(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            return data;
        }
    }

    private byte[] readAsset(String name) throws IOException {
        try (InputStream is = context.getAssets().open(name)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192]; int n;
            while ((n = is.read(buf)) > 0) baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }

    /**
     * Copy an asset from our own app into {@code dest}.
     *
     * This is a hard failure: if the libphantom blobs have not been compiled
     * and placed under assets/phantom/ yet, packing cannot produce a working
     * protected APK.  We throw immediately so the user gets a clear error
     * rather than a silently broken output that crashes on first launch.
     *
     * See docs/build-phantom.md for the OLLVM + NDK build recipe.
     */
    private void copyAssetToDir(String assetPath, File dest) throws IOException {
        try (InputStream is = context.getAssets().open(assetPath);
             FileOutputStream fos = new FileOutputStream(dest)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) fos.write(buf, 0, n);
        } catch (java.io.FileNotFoundException e) {
            throw new IOException(
                "libphantom blob not found: " + assetPath
                + "\nBuild the native library with OLLVM + NDK first.\n"
                + "See docs/build-phantom.md for the full CI recipe.", e);
        }
    }
}
