package com.ultra.dex2cvmp.utils;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
import android.os.Build;

import com.ultra.dex2cvmp.data.Const;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime DEX decryption + libphantom bootstrap for the stub loader.
 *
 * Key design:
 *  • All shard decryption and DEX loading happen inside libphantom.so via
 *    nativeLoadShards() — plaintext DEX bytes never cross the JNI boundary as
 *    a Java byte[].
 *  • libphantom.so is stored as a nonce-bound, HMAC-authenticated blob in
 *    assets/phantom/. loadPhantomLib(Context) reconstructs the distributed
 *    root, verifies the envelope, writes it to code_cache/, and calls
 *    System.load().
 *
 * ── Call order ────────────────────────────────────────────────────────────────
 *   DexCrypto.loadPhantomLib(ctx, maskedBlobRoot);
 *   ClassLoader cl = DexCrypto.nativeLoadShards(salt, pkg, encShards, parent);
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * NOTE: Only nativeLoadShards() and nativeSwapApplication() are exposed to
 * Java.  Plaintext DEX data never crosses the JNI boundary as a return value.
 */
public class DexCrypto {

    /** rotating-XOR decrypt — keeps obfuscated strings out of DEX string pool */
    private static String d(int[] e, int... k) {
        char[] c = new char[e.length];
        for (int i = 0; i < e.length; i++) c[i] = (char)(e[i] ^ k[i % k.length]);
        return new String(c);
    }

    /**
     * Decrypt all shards + load InMemoryDexClassLoader — entirely in native.
     *
     * This replaces the old per-shard Java decryption pattern and prevents
     * plaintext DEX data from being returned across the JNI boundary.
     *
     * nativeLoadShards() closes that gap:
     *  1. Decrypts every shard inside native code (key never leaves C stack).
     *  2. Moves plaintext into private page-aligned native mappings.
     *  3. Makes each mapping read-only and exposes only a direct ByteBuffer to ART.
     *  4. Calls new InMemoryDexClassLoader(ByteBuffer[], parent) via JNI —
     *     ART parses all DEX files synchronously inside that constructor.
     *  5. Keeps the read-only, MADV_DONTDUMP backing required by lazy ART.
     *  6. After construction, native code clears the DEX discovery markers from
     *     ART's anonymous readable mappings while retaining the live backing.
     *  7. Returns only the ClassLoader — no plaintext byte[] crosses JNI.
     *
     * Hooking the return yields only a ClassLoader reference, but a rooted
     * native/ART instrumenter can still inspect live ART mappings.
     *
     * @param context       application context; used only by Phantom's independent gate
     * @param salt          16-byte raw salt (with block-rooted flag in bit 7 of byte 0)
     * @param pkgNameUtf8   Package name encoded as UTF-8 bytes
     * @param signerCipher  encrypted 48-byte protected-signer record from phantom.vmp
     * @param encShards     Ciphertext shards (byte[][])
     * @param parent        Existing PathClassLoader to delegate non-app classes
     * @return              The constructed InMemoryDexClassLoader
     */
    public static native ClassLoader nativeLoadShards(
            Context context, byte[] salt, byte[] pkgNameUtf8, byte[] signerCipher,
            byte[][] encShards, ClassLoader parent);

    /**
     * Swap ProxyApplication → real Application entirely in native C.
     *
     * Does all ActivityThread reflection (mBoundApplication, LoadedApk,
     * mInitialApplication, mAllApplications, mProviderMap) via raw JNI
     * jobject pointers — no Java generic casts, no ClassCastException
     * possible on any Android version.
     *
     * Equivalent to the old ProxyApplication.realApplication() + patchProviders()
     * Java methods, but hidden inside OLLVM-obfuscated libphantom.so.
     *
     * @param classLoader  the current app ClassLoader (ProxyApplication.getClassLoader())
     * @param realAppClass the real Application class name from Const.getRealApp()
     * @param baseContext  ProxyApplication.getBaseContext()
     * @return             the newly created real Application, or null on failure
     */
    public static native Application nativeSwapApplication(
            ClassLoader classLoader, String realAppClass, Context baseContext);

    // ── Blob bootstrap ────────────────────────────────────────────────────────

    private static final int BLOB_ROOT_BYTES = 32;
    private static final int BLOB_NONCE_BYTES = 16;
    private static final int BLOB_TAG_BYTES = 32;
    private static final int BLOB_PREFIX_BYTES = 4 + BLOB_NONCE_BYTES;
    private static final byte[] BLOB_MAGIC = { 0x50, 0x48, 0x42, 0x33 };

    // One root share. The other 32-byte share is the phantom.vmp prefix.
    private static final byte[] ASSET_KEY_MASK = {
        0x4D, 0x7A, 0x1C, (byte)0x93, (byte)0xE4, 0x2B, 0x68, (byte)0xF5,
        0x37, (byte)0xA6, 0x5C, (byte)0xD1, (byte)0x8E, 0x42, (byte)0xB3, 0x76,
        (byte)0xC1, 0x3D, (byte)0x8F, 0x26, (byte)0xA9, (byte)0xE4, 0x51, 0x7C,
        (byte)0xB8, (byte)0xF6, 0x03, 0x2D, 0x71, (byte)0xAC, (byte)0x95, (byte)0xE0
    };

    /**
     * Extract the ABI-appropriate libphantom blob, authenticate it with the root
     * reconstructed from the two distributed shares, decrypt, and load it.
     *
     * @param ctx     app context
     * @param masked  first 32 bytes of phantom.vmp (masked blob root)
     */
    @SuppressLint("UnsafeDynamicallyLoadedCode")
    public static void loadPhantomLib(Context ctx, byte[] masked) throws Exception {
        if (masked == null || masked.length != BLOB_ROOT_BYTES) {
            throw new SecurityException("bad blob root share");
        }
        byte[] root = new byte[BLOB_ROOT_BYTES];
        for (int i = 0; i < BLOB_ROOT_BYTES; i++) {
            root[i] = (byte)(masked[i] ^ ASSET_KEY_MASK[i]);
        }

        File soFile = new File(ctx.getCodeCacheDir(), "libphantom.so");

        // Always delete and re-decrypt on every cold start so the cached
        // libphantom.so is never stale after an APK update or replacement.
        if (soFile.exists()) soFile.delete();

        String blobName = pickBlobName();
        String assetPath = Const.getLib() + "/" + blobName;

        InputStream bis = ctx.getAssets().open(assetPath);
        byte[] blob = readFully(bis);
        closeQuiet(bis);

        byte[] soBytes;
        try {
            soBytes = decryptBlob(blob, root);
        } finally {
            java.util.Arrays.fill(root, (byte) 0);
            java.util.Arrays.fill(blob, (byte) 0);
        }

        File parent = soFile.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();

        try {
            FileOutputStream fos = new FileOutputStream(soFile);
            try {
                fos.write(soBytes);
            } finally {
                closeQuiet(fos);
            }
        } finally {
            java.util.Arrays.fill(soBytes, (byte) 0);
        }
        soFile.setWritable(false, false);

        // Pre-load libz into the process namespace so libphantom.so can
        // resolve inflateInit_ when dlopen'd via System.load(absolutePath).
        // System.load() uses an isolated linker namespace that does NOT
        // automatically inherit system libs — pre-loading libz fixes that.
        try { System.loadLibrary("z"); } catch (UnsatisfiedLinkError ignored) {}
        System.load(soFile.getAbsolutePath());

        // Delete the .so file immediately after the kernel has mapped it into
        // the process — the inode stays alive (mapped pages hold a reference)
        // but the directory entry disappears, so a rooted attacker cannot read
        // it via a file path after this point.
        soFile.delete();
    }

    // ── Blob-only decrypt helpers (DexProtector must NOT use these for shards) ──

    /** Streaming decrypt — used only for the libphantom blob bootstrap. */
    public static void decrypt(byte[] key, InputStream input, OutputStream output) throws Exception {
        InflaterInputStream  is = new InflaterInputStream(input);
        InflaterOutputStream os = new InflaterOutputStream(output);
        exfr(key, is, os);
        os.close();
        is.close();
    }

    // ── Private implementation ────────────────────────────────────────────────

    /** Verify and decrypt a v3 blob envelope. */
    private static byte[] decryptBlob(byte[] blob, byte[] root) throws Exception {
        if (blob == null || blob.length <= BLOB_PREFIX_BYTES + BLOB_TAG_BYTES) {
            throw new SecurityException("truncated blob");
        }
        for (int i = 0; i < BLOB_MAGIC.length; i++) {
            if (blob[i] != BLOB_MAGIC[i]) throw new SecurityException("unsupported blob");
        }

        int tagOffset = blob.length - BLOB_TAG_BYTES;
        byte[] expected = blobMac(root, blob, tagOffset);
        byte[] supplied = new byte[BLOB_TAG_BYTES];
        System.arraycopy(blob, tagOffset, supplied, 0, BLOB_TAG_BYTES);
        boolean authentic = MessageDigest.isEqual(expected, supplied);
        java.util.Arrays.fill(expected, (byte) 0);
        java.util.Arrays.fill(supplied, (byte) 0);
        if (!authentic) throw new SecurityException("blob authentication failed");

        byte[] nonce = new byte[BLOB_NONCE_BYTES];
        System.arraycopy(blob, BLOB_MAGIC.length, nonce, 0, BLOB_NONCE_BYTES);
        byte[] streamKey = deriveStreamKey(root, nonce);
        java.util.Arrays.fill(nonce, (byte) 0);

        ByteArrayOutputStream out = new ByteArrayOutputStream(tagOffset - BLOB_PREFIX_BYTES);
        try {
            decrypt(streamKey,
                    new java.io.ByteArrayInputStream(
                            blob, BLOB_PREFIX_BYTES, tagOffset - BLOB_PREFIX_BYTES),
                    out);
            return out.toByteArray();
        } finally {
            java.util.Arrays.fill(streamKey, (byte) 0);
        }
    }

    private static byte[] deriveStreamKey(byte[] root, byte[] nonce) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(root);
        digest.update(nonce);
        digest.update(new byte[]{ 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d });
        byte[] expanded = digest.digest();
        byte[] streamKey = new byte[16];
        System.arraycopy(expanded, 0, streamKey, 0, streamKey.length);
        java.util.Arrays.fill(expanded, (byte) 0);
        return streamKey;
    }

    private static byte[] blobMac(byte[] root, byte[] blob, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(root, "HmacSHA256"));
        mac.update(blob, 0, length);
        return mac.doFinal();
    }

    /** Pick the right blob asset name for the current device ABI. */
    private static String pickBlobName() {
        String[] abis = (Build.VERSION.SDK_INT >= 21)
                ? Build.SUPPORTED_ABIS
                : new String[]{ Build.CPU_ABI, Build.CPU_ABI2 };
        for (String abi : abis) {
            if (abi != null && abi.startsWith(d(new int[]{0x0E,0x58,0x02,0x1C,0x5B},0x6F,0x2A))) return Const.getBlobArm64();
        }
        return Const.getBlobArm();
    }

    /** ARX stream cipher — key is 16 raw bytes (little-endian → 4 × int). */
    private static void exfr(byte[] key, InputStream in, OutputStream out) throws Exception {
        if (key == null || key.length < 16) throw new IllegalArgumentException("key must be 16 bytes");

        int[] iArr = new int[4];
        for (int i = 0; i < 4; i++) {
            int b = i * 4;
            iArr[i] = (key[b]     & 0xFF)
                    | ((key[b+1] & 0xFF) << 8)
                    | ((key[b+2] & 0xFF) << 16)
                    | ((key[b+3] & 0xFF) << 24);
        }
        int[] iArr2 = new int[]{ iArr[0] ^ iArr[2], iArr[1] ^ iArr[3] };
        iArr = FxIjsF(iArr);

        byte[] buf = new byte[8192];
        int pos = 0;
        while (true) {
            int read = in.read(buf);
            if (read < 0) return;
            int end = pos + read;
            int i5 = 0;
            while (pos < end) {
                int i6 = pos % 8;
                if (i6 == 0) nDnv(iArr, iArr2);
                buf[i5] = (byte) (((byte) (iArr2[i6 / 4] >> ((pos % 4) * 8))) ^ buf[i5]);
                pos++;
                i5++;
            }
            out.write(buf, 0, read);
        }
    }

    private static int[] FxIjsF(int[] iArr) {
        int[] r = new int[27];
        int i = iArr[0];
        r[0] = i;
        int[] t = new int[]{ iArr[1], iArr[2], iArr[3] };
        for (int i2 = 0; i2 < 26; i2++) {
            t[i2 % 3] = (((t[i2 % 3] >>> 8) | (t[i2 % 3] << 24)) + i) ^ i2;
            i = ((i << 3) | (i >>> 29)) ^ t[i2 % 3];
            r[i2 + 1] = i;
        }
        return r;
    }

    private static void nDnv(int[] iArr, int[] iArr2) {
        int i = iArr2[0], i2 = iArr2[1];
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[0];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[1];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[2];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[3];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[4];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[5];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[6];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[7];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[8];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[9];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[10]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[11]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[12]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[13]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[14]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[15]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[16]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[17]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[18]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[19]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[20]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[21]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[22]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[23]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[24]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[25]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[26];
        iArr2[0] = ((i<<3)|(i>>>29))^i2;
        iArr2[1] = i2;
    }

    // ── tiny helpers ──────────────────────────────────────────────────────────

    static byte[] readFully(InputStream is) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = is.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static void closeQuiet(Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException ignored) {}
    }
}
