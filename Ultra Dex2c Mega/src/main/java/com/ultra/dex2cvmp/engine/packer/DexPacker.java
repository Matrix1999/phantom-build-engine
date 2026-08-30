package com.ultra.dex2cvmp.engine.packer;

import android.content.Context;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * DEX Packer — wraps a dex2c/VMP-processed APK with the com.ultra.dex2cvmp stub loader.
 *
 * Security model:
 *   • A 16-byte cryptographically random salt is generated for every pack operation.
 *   • A per-APK seed is derived via DexSeed.deriveKey(salt, pkgName), then
 *     narrowed to an independent 16-byte key for each shard.
 *   • Every shard is additionally wrapped by a universal XChaCha20-Poly1305 payload key
 *     mirrored inside the VMP-compiled Phantom native loader.
 *   • salt is written to assets/phantom/ph_salt (raw, 16 bytes) so the stub can read it
 *     at runtime and reproduce the inner key inside libphantom.so.
 *   • Cert binding is omitted — signature tamper detection is handled by the app itself.
 *
 * Flow:
 *  1. Extract classes*.dex + AndroidManifest.xml from input APK.
 *  2. Parse manifest → capture real Application class, patch android:name → ProxyApplication.
 *  3. Generate random salt; derive the per-APK seed from (salt, pkgName).
 *  4. Encrypt all DEX shards and bundle them into a single phantom.vmp payload.
 *     Bundle format: [32-byte blob header][4-byte version][4-byte shard count]
 *     [count × 4-byte shard sizes][XChaCha20-Poly1305 envelope records…]
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

    /** Version for the universal XChaCha20-Poly1305-wrapped shard bundle. */
    public static final int BUNDLE_VERSION = 6;

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
        pack(inputApk, outputApk, workDir,
                context.getSharedPreferences("dex2c_mega_prefs", android.content.Context.MODE_PRIVATE)
                       .getBoolean("block_rooted_enabled", true));
    }

    /**
     * Pack with an explicit blockRootedDevices flag — used by ApkProtector so the value
     * from the intent chain (already validated at dispatch time) overrides the pref read.
     */
    public void pack(File inputApk, File outputApk, File workDir, boolean blockRootedDevices)
            throws Exception {
        packInternal(inputApk, outputApk, workDir, null, blockRootedDevices);
    }

    /**
     * Pack an already-rebuilt APK using the caller's final DEX workspace.
     *
     * The workspace belongs to exactly one protection job and contains the
     * stripped, final classes*.dex files that were just inserted into inputApk.
     * Reading it directly avoids extracting the rebuilt APK only to encrypt the
     * same DEX files again.
     */
    public void pack(File inputApk, File outputApk, File workDir, File finalDexDir,
                     boolean blockRootedDevices) throws Exception {
        if (finalDexDir == null || !finalDexDir.isDirectory()) {
            throw new IOException("Final DEX workspace is unavailable for Phantom packing.");
        }
        packInternal(inputApk, outputApk, workDir, finalDexDir, blockRootedDevices);
    }

    private void packInternal(File inputApk, File outputApk, File workDir,
                              File finalDexDir, boolean blockRootedDevices) throws Exception {
        // ── 1. Read manifest and locate final DEX files ────────────────────────
        byte[] manifestBytes;
        File dexSourceDir;
        if (finalDexDir != null) {
            manifestBytes = readZipEntry(inputApk, "AndroidManifest.xml");
            dexSourceDir = finalDexDir;
        } else {
            // Compatibility path for direct callers that do not own a DEX
            // workspace. ApkProtector always uses the no-re-extraction path above.
            File extractDir = new File(workDir, "extracted");
            FastZip.extract(inputApk, extractDir);
            manifestBytes = readFile(new File(extractDir, "AndroidManifest.xml"));
            dexSourceDir = extractDir;
        }

        // ── 2. Parse + patch manifest ─────────────────────────────────────────
        // Phantom stores its native libraries in the packed APK. Force
        // extraction only in this Phantom manifest; normal DEX2C/VMP output
        // never reaches this path and keeps the source manifest unchanged.
        byte[] patchedManifest = ManifestPatcher.parseManifest(
                manifestBytes, PROXY_APP, true);

        String realAppClass = ManifestPatcher.customApplication
                ? ManifestPatcher.customApplicationName
                : "android.app.Application";
        if (realAppClass.startsWith(".") && !ManifestPatcher.packageName.isEmpty()) {
            realAppClass = ManifestPatcher.packageName + realAppClass;
        }
        String pkgName = ManifestPatcher.packageName;

        // ── 3. Generate per-APK salt, embed block-rooted flag, derive seed ──────
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

        // Collect every classes*.dex present in the final workspace, sorted in canonical
        // DEX order (classes.dex first, then classes2.dex, classes3.dex, …).
        // We must NOT use a sequential-break loop ("stop at first missing number")
        // because FastZip.extract() may have skipped a numbered DEX if the original
        // APK stored it with a "./" prefix.  Scanning the directory avoids silently
        // dropping all higher-numbered DEX files when a gap exists.
        File[] extractedFiles = dexSourceDir.listFiles();
        List<File> dexFiles = new ArrayList<>();
        if (extractedFiles != null) {
            for (File f : extractedFiles) {
                if (f.getName().matches("classes(\\d*)\\.dex")) dexFiles.add(f);
            }
        }
        // Sort: classes.dex (no number) first, then classes2, classes3, … numerically.
        dexFiles.sort((a, b) -> {
            String na = a.getName(), nb = b.getName();
            int ia = na.equals("classes.dex") ? 1
                    : Integer.parseInt(na.replace("classes", "").replace(".dex", ""));
            int ib = nb.equals("classes.dex") ? 1
                    : Integer.parseInt(nb.replace("classes", "").replace(".dex", ""));
            return Integer.compare(ia, ib);
        });
        if (dexFiles.isEmpty()) {
            throw new IOException("No final DEX files available for Phantom packing.");
        }
        List<String> dexNames = new ArrayList<>();
        for (File dexFile : dexFiles) dexNames.add(dexFile.getName());
        android.util.Log.i("DexPacker",
                "Phantom input DEX inventory (" + dexFiles.size() + "): " + dexNames);

        List<byte[]> shards = new ArrayList<>();
        for (int i = 0; i < dexFiles.size(); i++) {
            shards.add(encryptDexToBytes(dexFiles.get(i), key, i));
        }

        // Zero the key as soon as all encryption is done.
        java.util.Arrays.fill(key, (byte) 0);

        // Write bundle: [32-byte masked blob root][4-byte version][4-byte count]
        // [count × 4-byte shard size][XChaCha20-Poly1305 envelope shard bytes…]
        // MASKED_BLOB_ROOT[i] = BLOB_ROOT[i] ^ ASSET_KEY_MASK[i].
        // Neither half alone reveals the key — both are needed.
        byte[] maskedBlobRoot = {
            0x23, 0x56, 0x53, 0x22, 0x76, (byte)0x8c, (byte)0xb8, (byte)0xc9,
            0x62, 0x57, 0x26, 0x5a, (byte)0x82, (byte)0xa1, 0x2e, 0x02,
            (byte)0xec, (byte)0xa5, (byte)0x98, (byte)0xc0, (byte)0xea, 0x51, (byte)0x9b, 0x6c,
            0x27, (byte)0xd0, (byte)0xdb, 0x67, (byte)0xc6, 0x6f, (byte)0xc4, 0x0e
        };
        File bundleFile = new File(shardsDir, BUNDLE_FILE);
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(bundleFile))) {
            dos.write(maskedBlobRoot);                             // 32-byte header
            dos.writeInt(BUNDLE_VERSION);
            dos.writeInt(shards.size());
            for (byte[] shard : shards) dos.writeInt(shard.length);
            for (byte[] shard : shards) dos.write(shard);
        }
        android.util.Log.i("DexPacker",
                "Phantom bundle written with " + shards.size() + " DEX shard(s)");

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

    private byte[] encryptDexToBytes(File input, byte[] key, int shardIndex) throws Exception {
        byte[] shardKey = DexCrypto.deriveShardKey(key, shardIndex);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            try (InputStream in = new FileInputStream(input)) {
                DexCrypto.encrypt(shardKey, in, baos);
            }
        } finally {
            java.util.Arrays.fill(shardKey, (byte) 0);
        }
        byte[] inner = baos.toByteArray();
        try {
            return DexCrypto.encryptPayloadEnvelope(inner, shardIndex);
        } finally {
            java.util.Arrays.fill(inner, (byte) 0);
        }
    }

    private byte[] readFile(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            return data;
        }
    }

    private byte[] readZipEntry(File apk, String entryName) throws IOException {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry entry = zip.getEntry(entryName);
            if (entry == null) {
                entry = zip.getEntry("./" + entryName);
            }
            if (entry == null) {
                throw new IOException("APK is missing " + entryName);
            }
            try (InputStream in = zip.getInputStream(entry);
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                return out.toByteArray();
            }
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
