package com.ultra.dex2cvmp.utils;

import android.annotation.SuppressLint;
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
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
 * Runtime DEX decryption + libphantom bootstrap for the stub loader.
 *
 * Key design:
 *  • Key derivation + shard decryption happen entirely inside libphantom.so
 *    via nativeDecryptShard() — the 16-byte key never crosses the JNI boundary.
 *  • libphantom.so is stored as an ARX-encrypted blob in assets/phantom/.
 *    loadPhantomLib(Context) decrypts it with the hardcoded blob key, writes
 *    it to code_cache/, and calls System.load().
 *
 * ── Call order ────────────────────────────────────────────────────────────────
 *   DexCrypto.loadPhantomLib(ctx);
 *   byte[] dex = DexCrypto.nativeDecryptShard(salt, pkgNameUtf8, encShard);
 * ─────────────────────────────────────────────────────────────────────────────
 */
public class DexCrypto {

    // ── Native entry-point ────────────────────────────────────────────────────

    /**
     * Derive key + decrypt one DEX shard entirely inside libphantom.so.
     *
     * The key is derived from (salt, pkgName) and consumed in-place — it is
     * never returned to Java.  Java receives only the plaintext DEX bytes.
     *
     * MUST be called only after {@link #loadPhantomLib(Context)}.
     *
     * @param salt        16-byte raw salt from assets/phantom/ph_salt.
     * @param pkgNameUtf8 Package name pre-encoded as standard UTF-8 bytes.
     * @param encShard    Encrypted shard bytes from the phantom.vmp bundle.
     * @return Plaintext DEX bytes.
     */
    public static native byte[] nativeDecryptShard(byte[] salt, byte[] pkgNameUtf8, byte[] encShard);

    /**
     * Layer-2a anti-dump — wipe DEX magic from a plaintext shard byte[].
     *
     * Call this immediately after InMemoryDexClassLoader (or the file-based
     * fallback) has consumed the byte[].  The native side zeroes:
     *   bytes  0-7  : dex\n magic + version string
     *   bytes 40-43 : endian_tag (0x12345678)
     *
     * ART has already fully parsed and mapped the DEX before this is called,
     * so zeroing the source array does not affect class resolution.
     * The byte[] will no longer match the scanner's DEX heuristics.
     *
     * MUST be called only after {@link #loadPhantomLib(Context)}.
     */
    public static native void nativeWipeShard(byte[] dexBytes);

    // ── Blob bootstrap ────────────────────────────────────────────────────────

    /**
     * Hardcoded blob-decryption key — built char-by-char so the value never
     * appears verbatim in the DEX string pool.
     * This key is ONLY used to decrypt the libphantom.so blob; it does NOT
     * protect any user data.  It is separate from, and weaker than, the per-APK
     * key stays inside libphantom.so (nativeDecryptShard).
     *
     * The blob key itself is NOT stored here — it is reconstructed at runtime by
     * XORing the masked bytes from phantom.vmp header with ASSET_KEY_MASK below.
     * Neither half alone reveals Ph4nt0mBl0bK3y!!.
     */

    // Half of the XOR pair — the other half lives as the first 16 bytes of phantom.vmp.
    // key[i] = phantom.vmp[i] ^ ASSET_KEY_MASK[i]
    private static final byte[] ASSET_KEY_MASK = {
        0x4D, 0x7A, 0x1C, (byte)0x93, (byte)0xE4, 0x2B, 0x68, (byte)0xF5,
        0x37, (byte)0xA6, 0x5C, (byte)0xD1, (byte)0x8E, 0x42, (byte)0xB3, 0x76
    };

    /**
     * Extract the ABI-appropriate libphantom blob from assets, decrypt it with
     * the blob key recovered from phantom.vmp header, write to codeCache, and load.
     *
     * @param ctx     app context
     * @param masked  first 16 bytes of phantom.vmp (XOR-masked blob key)
     */
    @SuppressLint("UnsafeDynamicallyLoadedCode")
    public static void loadPhantomLib(Context ctx, byte[] masked) throws Exception {
        // Reconstruct key in RAM — XOR the two halves together.
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = (byte)(masked[i] ^ ASSET_KEY_MASK[i]);

        File soFile = new File(ctx.getCodeCacheDir(), "libphantom.so");

        // Always delete and re-decrypt on every cold start so the cached
        // libphantom.so is never stale after an APK update or replacement.
        if (soFile.exists()) soFile.delete();

        String blobName = pickBlobName();
        String assetPath = Const.DP_LIB + "/" + blobName;

        InputStream bis = ctx.getAssets().open(assetPath);
        byte[] blob = readFully(bis);
        closeQuiet(bis);

        byte[] soBytes = decryptBlob(blob, key);

        File parent = soFile.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();

        FileOutputStream fos = new FileOutputStream(soFile);
        try {
            fos.write(soBytes);
        } finally {
            closeQuiet(fos);
        }
        soFile.setWritable(false, false);

        // Zero key immediately — it served its only purpose.
        java.util.Arrays.fill(key, (byte) 0);
        java.util.Arrays.fill(soBytes, (byte) 0);  // wipe decrypted .so from heap too

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

    /** Decrypt a raw blob byte[] using the supplied key. */
    private static byte[] decryptBlob(byte[] blob, byte[] key) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(blob.length);
        decrypt(key, new java.io.ByteArrayInputStream(blob), out);
        return out.toByteArray();
    }

    /** Pick the right blob asset name for the current device ABI. */
    private static String pickBlobName() {
        String[] abis = (Build.VERSION.SDK_INT >= 21)
                ? Build.SUPPORTED_ABIS
                : new String[]{ Build.CPU_ABI, Build.CPU_ABI2 };
        for (String abi : abis) {
            if (abi != null && abi.startsWith("arm64")) return Const.PHANTOM_BLOB_ARM64;
        }
        return Const.PHANTOM_BLOB_ARM;
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
