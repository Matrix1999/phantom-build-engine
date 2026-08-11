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
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
 * Runtime DEX decryption + libphantom bootstrap for the stub loader.
 *
 * Key design:
 *  • All shard decryption, DEX loading, and anti-dump wipes happen entirely
 *    inside libphantom.so via nativeLoadShards() — plaintext DEX bytes never
 *    cross the JNI boundary to Java.
 *  • libphantom.so is stored as an ARX-encrypted blob in assets/phantom/.
 *    loadPhantomLib(Context) decrypts it with the hardcoded blob key, writes
 *    it to code_cache/, and calls System.load().
 *
 * ── Call order ────────────────────────────────────────────────────────────────
 *   DexCrypto.loadPhantomLib(ctx, maskedBlobKey);
 *   ClassLoader cl = DexCrypto.nativeLoadShards(salt, pkg, encShards, parent);
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * NOTE: nativeDecryptShard / nativeWipeShard / nativeWipeArtDex are
 * intentionally NOT exposed here.  They still exist in libphantom.so for
 * internal use by nativeLoadShards, but no Java code should call them
 * directly — doing so would re-expose plaintext DEX bytes at the Java level.
 * Do not re-add Java declarations for those symbols.
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
     * This replaces the old pattern of calling nativeDecryptShard() per shard
     * from Java and then passing the returned byte[] to InMemoryDexClassLoader.
     * That pattern exposed the plaintext DEX at the Java level: a Frida hook
     * on the return of nativeDecryptShard() captured the full byte[] before
     * nativeWipeShard() ran.
     *
     * nativeLoadShards() closes that gap:
     *  1. Decrypts every shard to a native malloc buffer (key never leaves C stack).
     *  2. Copies each plaintext into a jbyteArray that exists only inside this
     *     JNI call — it is NEVER returned to Java code.
     *  3. Wraps each jbyteArray in ByteBuffer.wrap() via JNI.
     *  4. Calls new InMemoryDexClassLoader(ByteBuffer[], parent) via JNI —
     *     ART parses all DEX files synchronously inside that constructor.
     *  5. Zeroes every plaintext jbyteArray (Layer-2a wipe).
     *  6. Scans /proc/self/maps and zeroes ART's internal anonymous mmap
     *     copies via mprotect + direct write (Layer-2b wipe).
     *  7. Returns only the ClassLoader — no DEX bytes cross the JNI boundary.
     *
     * Hooking the return of this function yields only a ClassLoader reference.
     *
     * @param salt          16-byte raw salt (with block-rooted flag in bit 7 of byte 0)
     * @param pkgNameUtf8   Package name encoded as UTF-8 bytes
     * @param encShards     Ciphertext shards (byte[][])
     * @param parent        Existing PathClassLoader to delegate non-app classes
     * @return              The constructed InMemoryDexClassLoader
     */
    public static native ClassLoader nativeLoadShards(
            byte[] salt, byte[] pkgNameUtf8, byte[][] encShards, ClassLoader parent);

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

    /**
     * Hardcoded blob-decryption key — built char-by-char so the value never
     * appears verbatim in the DEX string pool.
     * This key is ONLY used to decrypt the libphantom.so blob; it does NOT
     * protect any user data.  It is separate from, and weaker than, the per-APK
     * key stays inside libphantom.so (nativeLoadShards).
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
        String assetPath = Const.getLib() + "/" + blobName;

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
