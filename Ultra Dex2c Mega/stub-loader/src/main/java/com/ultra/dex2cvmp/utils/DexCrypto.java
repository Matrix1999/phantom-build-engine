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

/**
 * Runtime DEX decryption + libphantom bootstrap for the stub loader.
 *
 * Key design:
 *  • All shard decryption, DEX loading, and anti-dump wipes happen entirely
 *    inside libphantom.so via nativeLoadShards() — plaintext DEX bytes never
 *    cross the JNI boundary to Java.
 *  • libphantom.so is stored as an XChaCha20-Poly1305 blob in assets/phantom/.
 *    A separately loaded bootstrap library owns blob-key reconstruction and
 *    authenticated decryption before this library is loaded.
 *
 * ── Call order ────────────────────────────────────────────────────────────────
 *   DexCrypto.loadPhantomLib(ctx);
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
     *  1. Decrypts every shard to a native malloc buffer (key never leaves C stack).
     *  2. Copies each plaintext into a jbyteArray that exists only inside this
     *     JNI call — it is never returned to Java code.
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

    /**
     * Verify and decrypt one outer Phantom blob into {@code outputPath}.
     *
     * The implementation lives in the separately loaded bootstrap library.
     * No blob key or cryptographic implementation is present in this Java DEX.
     */
    public static native boolean nativeDecryptBlob(byte[] blob, String outputPath);

    // ── Blob bootstrap ────────────────────────────────────────────────────────

    private static volatile boolean BOOTSTRAP_LOADED;

    /**
     * Load the ABI-appropriate bootstrap, ask it to authenticate/decrypt the
     * XChaCha20-Poly1305 libphantom blob, and then load the resulting library.
     *
     * The bootstrap is deliberately separate: libphantom.so cannot decrypt its
     * own envelope before Android has loaded it.
     */
    @SuppressLint("UnsafeDynamicallyLoadedCode")
    public static void loadPhantomLib(Context ctx) throws Exception {
        File bootstrapFile = new File(ctx.getCodeCacheDir(), "libph_bootstrap.so");
        File soFile = new File(ctx.getCodeCacheDir(), "libphantom.so");
        if (bootstrapFile.exists()) bootstrapFile.delete();
        if (soFile.exists()) soFile.delete();

        byte[] bootstrap = readAsset(ctx, Const.getLib() + "/" + pickBootstrapName());
        try {
            FileOutputStream bos = new FileOutputStream(bootstrapFile);
            try {
                bos.write(bootstrap);
            } finally {
                closeQuiet(bos);
            }
            bootstrapFile.setWritable(false, false);
            if (!BOOTSTRAP_LOADED) {
                System.load(bootstrapFile.getAbsolutePath());
                BOOTSTRAP_LOADED = true;
            }
        } finally {
            java.util.Arrays.fill(bootstrap, (byte) 0);
        }
        bootstrapFile.delete();

        File parent = soFile.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();

        byte[] blob = readAsset(ctx, Const.getLib() + "/" + pickBlobName());
        try {
            if (!nativeDecryptBlob(blob, soFile.getAbsolutePath())) {
                throw new SecurityException("blob authentication failed");
            }
        } finally {
            java.util.Arrays.fill(blob, (byte) 0);
        }
        soFile.setWritable(false, false);
        System.load(soFile.getAbsolutePath());

        // The mapped inode remains valid after the directory entry disappears.
        soFile.delete();
    }

    private static byte[] readAsset(Context ctx, String path) throws IOException {
        InputStream is = ctx.getAssets().open(path);
        try {
            return readFully(is);
        } finally {
            closeQuiet(is);
        }
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

    private static String pickBootstrapName() {
        String[] abis = (Build.VERSION.SDK_INT >= 21)
                ? Build.SUPPORTED_ABIS
                : new String[]{ Build.CPU_ABI, Build.CPU_ABI2 };
        for (String abi : abis) {
            if (abi != null && abi.startsWith(d(new int[]{0x0E,0x58,0x02,0x1C,0x5B},0x6F,0x2A))) {
                return Const.getBootstrapArm64();
            }
        }
        return Const.getBootstrapArm();
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
