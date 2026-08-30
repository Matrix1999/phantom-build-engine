package com.ultra.dex2cvmp.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;

import com.ultra.dex2cvmp.data.Const;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Installs the encrypted DEX shards from the phantom.vmp bundle.
 *
 * Security improvements over the old version:
 *
 *  1. libphantom.so bootstrap — the native library is stored as an
 *     authenticated nonce-bound blob inside assets/phantom/. loadPhantomLib()
 *     decrypts and System.load()s it before any key material is needed.
 *
 *  2. Plaintext DEX never crosses JNI — nativeLoadShards() decrypts all
 *     shards, loads InMemoryDexClassLoader, and wipes plaintext entirely in
 *     native.  Java only receives a ClassLoader reference.
 *
 *  3. InMemoryDexClassLoader (API 27+) — decrypted DEX bytes stay in
 *     ByteBuffers, never on disk.  PathClassLoader is re-parented to delegate
 *     through InMemoryDexClassLoader so only ONE loader owns the DexFile.
 *     This prevents the "register dex with multiple class loaders" crash on
 *     apps using android:appComponentFactory (PairIP, CoreComponentFactory).
 *     Devices below API 27 are not supported — no disk fallback exists.
 *
 *  4. Salt zeroed immediately after all shards are decrypted.
 */
public class DexProtector {
    @SuppressLint("StaticFieldLeak")
    public static Context mContext;
    private static final int PHANTOM_BUNDLE_VERSION = 5;
    private static final int BLOB_ROOT_SHARE_BYTES = 32;

    // ── Runtime string builders — no sensitive literals in DEX string pool ──────
    private static String k(char... c) { return new String(c); }
    private static String d(int[] e, int... k) {
        char[] c = new char[e.length];
        for (int i = 0; i < e.length; i++) c[i] = (char)(e[i] ^ k[i % k.length]);
        return new String(c);
    }
    /** "pathList" */
    private static String strPathList() {
        return d(new int[]{0x4A,0x10,0x4E,0x19,0x76,0x18,0x49,0x05},0x3A,0x71);
    }
    /** "android.app.ActivityThread" */
    private static String strActThreadCls() {
        return d(new int[]{0x7B,0x19,0x50,0x68,0x18,0x5D,0x7E,0x59,0x55,0x6A,0x07,0x1A,0x5B,0x14,0x40,0x73,0x01,0x5D,0x6E,0x0E,0x60,0x72,0x05,0x51,0x7B,0x13},0x1A,0x77,0x34);
    }
    /** "currentActivityThread" */
    private static String strCurActThread() {
        return d(new int[]{0x3D,0x59,0x2C,0x5E,0x3B,0x42,0x2A,0x6D,0x3D,0x58,0x37,0x5A,0x37,0x58,0x27,0x78,0x36,0x5E,0x3B,0x4D,0x3A},0x5E,0x2C);
    }
    /** "mPackages" */
    private static String strMPackages() {
        return d(new int[]{0x52,0x3A,0x5E,0x09,0x54,0x0B,0x58,0x0F,0x4C},0x3F,0x6A);
    }
    /** "mClassLoader" */
    private static String strMClassLoader() {
        return d(new int[]{0x3F,0x5E,0x3E,0x7C,0x21,0x6E,0x1E,0x72,0x33,0x79,0x37,0x6F},0x52,0x1D);
    }
    /** "nativeLibraryDirectories" */
    private static String strNativeLibDirs() {
        return d(new int[]{0x46,0x2A,0x03,0x41,0x3D,0x12,0x64,0x22,0x15,0x5A,0x2A,0x05,0x51,0x0F,0x1E,0x5A,0x2E,0x14,0x5C,0x24,0x05,0x41,0x2E,0x04},0x28,0x4B,0x77);
    }
    /** "nativeLibraryPathElements" */
    private static String strNativeLibElems() {
        return d(new int[]{0x52,0x38,0x65,0x55,0x2F,0x74,0x70,0x30,0x73,0x4E,0x38,0x63,0x45,0x09,0x70,0x48,0x31,0x54,0x50,0x3C,0x7C,0x59,0x37,0x65,0x4F},0x3C,0x59,0x11);
    }

    @SuppressLint("PrivateApi")
    public DexProtector(Context context) {
        mContext = context;
    }

    public void install(Context context) throws Exception {
        // ── Step 1: Read phantom.vmp — first 32 bytes are the masked blob root ──
        byte[] bundleBytes;
        byte[] maskedBlobRoot = new byte[BLOB_ROOT_SHARE_BYTES];
        {
            InputStream bs = mContext.getAssets().open(Const.getLib() + "/" + Const.getBundleFile());
            bundleBytes = DexCrypto.readFully(bs);
            bs.close();
        }
        if (bundleBytes.length < BLOB_ROOT_SHARE_BYTES + 8) {
            throw new RuntimeException(k('b','a','d',' ','v','m','p'));
        }
        System.arraycopy(bundleBytes, 0, maskedBlobRoot, 0, BLOB_ROOT_SHARE_BYTES);

        // ── Step 2: Bootstrap libphantom.so using the distributed root ────────
        DexCrypto.loadPhantomLib(context, maskedBlobRoot);
        Arrays.fill(maskedBlobRoot, (byte) 0);

        // ── Step 3: Read real Application class name ──────────────────────────
        try {
            InputStream ris = mContext.getAssets().open(Const.getLib() + "/" + Const.getAppCfg());
            byte[] buf = new byte[512];
            int n = ris.read(buf);
            ris.close();
            if (n > 0) {
                String realApp = new String(buf, 0, n, StandardCharsets.UTF_8).trim();
                if (!realApp.isEmpty()) Const.setRealApp(realApp);
            }
        } catch (Exception ignored) { }

        // ── Step 4: Read 16-byte salt from assets ─────────────────────────────
        byte[] salt = readAsset(context, Const.getLib() + "/" + Const.getSaltAsset());
        if (salt == null || salt.length != 16) {
            throw new RuntimeException(k('b','a','d',' ','s','a','l','t'));
        }

        // ── Step 5: Pre-encode pkg name (UTF-8) for native call ──────────────
        byte[] pkgNameUtf8 = context.getPackageName()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);

        try {
            // ── Step 6: Parse versioned phantom.vmp bundle ───────────────────────
            DataInputStream dis = new DataInputStream(
                    new ByteArrayInputStream(
                            bundleBytes,
                            BLOB_ROOT_SHARE_BYTES,
                            bundleBytes.length - BLOB_ROOT_SHARE_BYTES));
            int bundleVersion = dis.readInt();
            if (bundleVersion != PHANTOM_BUNDLE_VERSION) {
                throw new RuntimeException(k('b','a','d',' ','v','e','r'));
            }
            int shardCount = dis.readInt();
            if (shardCount <= 0 || shardCount > 64) {
                throw new RuntimeException(k('b','a','d',' ','c','o','u','n','t'));
            }
            int[] sizes = new int[shardCount];
            for (int i = 0; i < shardCount; i++) {
                sizes[i] = dis.readInt();
                if (sizes[i] < 40) {
                    throw new RuntimeException(k('b','a','d',' ','s','h','a','r','d'));
                }
            }

            if (Build.VERSION.SDK_INT < 27) {
                throw new RuntimeException(k('A','P','I','<','2','7'));
            }
            loadInMemory(context, dis, shardCount, sizes, salt, pkgNameUtf8);
        } finally {
            // Zero salt — key never leaves native.
            Arrays.fill(salt, (byte) 0);
        }
    }

    // ── In-memory path (API 27+) ──────────────────────────────────────────────

    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void loadInMemory(Context context, DataInputStream dis,
                              int shardCount, int[] sizes,
                              byte[] salt, byte[] pkgNameUtf8) throws Exception {

        // Read ciphertext shards — plaintext never exists in Java
        byte[][] encShards = new byte[shardCount][];
        for (int i = 0; i < shardCount; i++) {
            encShards[i] = new byte[sizes[i]];
            dis.readFully(encShards[i]);
        }

        ClassLoader parent = context.getClassLoader();

        // ── Single native call does everything ────────────────────────────
        // nativeLoadShards() decrypts all shards, constructs
        // InMemoryDexClassLoader via read-only native direct buffers, and keeps
        // plaintext out of Java byte[] objects — all inside one JNI call.
        //
         // WHY: The old per-shard Java decryption pattern exposed the full
         // plaintext DEX at the Java level between decryption and loading.
         // nativeLoadShards closes that gap:
        // hooking its return yields only a ClassLoader, not a byte[].
        ClassLoader inMemory = DexCrypto.nativeLoadShards(
                salt, pkgNameUtf8, encShards, parent);
        if (inMemory == null)
            throw new RuntimeException(k('n','L','S','f','a','i','l'));

        // Copy APK native lib dirs into the new loader and install it.
        copyNativeLibDirs(parent, inMemory);
        patchLoadedApkClassLoader(context, inMemory);
    }

    // ── ClassLoader replacement ───────────────────────────────────────────────

    /**
     * Patch LoadedApk.mClassLoader so that Android resolves all app classes
     * through {@code newCl}.  This is the safe alternative to merging
     * dexElements: the DEX is owned by exactly ONE classloader and there is
     * no "register dex with multiple class loaders" crash.
     *
     * newCl must already have the original PathClassLoader as its parent so
     * normal class delegation (framework + boot classes) still works.
     */
    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void patchLoadedApkClassLoader(Context context, ClassLoader newCl) throws Exception {
        // ActivityThread.currentActivityThread()
        Class<?> atCls = Class.forName(strActThreadCls());
        java.lang.reflect.Method current = atCls.getDeclaredMethod(strCurActThread());
        current.setAccessible(true);
        Object thread = current.invoke(null);

        // mPackages is ArrayMap<String, WeakReference<LoadedApk>>
        Field mPackagesField = atCls.getDeclaredField(strMPackages());
        mPackagesField.setAccessible(true);
        @SuppressWarnings("unchecked")
        android.util.ArrayMap<String, java.lang.ref.WeakReference<?>> mPackages =
                (android.util.ArrayMap<String, java.lang.ref.WeakReference<?>>) mPackagesField.get(thread);

        java.lang.ref.WeakReference<?> ref = mPackages.get(context.getPackageName());
        if (ref != null) {
            Object loadedApk = ref.get();
            if (loadedApk != null) {
                Field mClField = loadedApk.getClass().getDeclaredField(strMClassLoader());
                mClField.setAccessible(true);
                mClField.set(loadedApk, newCl);
            }
        }

        // Also patch the ContextImpl field if present (belt-and-suspenders).
        try {
            Field ctxCl = context.getClass().getDeclaredField(strMClassLoader());
            ctxCl.setAccessible(true);
            ctxCl.set(context, newCl);
        } catch (NoSuchFieldException ignored) { }
    }

    /**
     * Copy the APK's native library path elements from {@code src} (the original
     * PathClassLoader) into {@code dst} (InMemoryDexClassLoader).
     *
     * InMemoryDexClassLoader builds its DexPathList with only system native lib
     * dirs (/system/lib64, /system_ext/lib64).  Without this patch, any
     * System.loadLibrary() call from the protected DEX throws UnsatisfiedLinkError
     * because the APK's own lib dir (/data/app/<pkg>/lib/arm64) is not searched.
     */
    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void copyNativeLibDirs(ClassLoader src, ClassLoader dst) {
        try {
            Field plf = Reflect.findField(src, strPathList());
            Object srcPl = plf.get(src);

            Field plfDst = Reflect.findField(dst, strPathList());
            Object dstPl = plfDst.get(dst);

            for (String fieldName : new String[]{strNativeLibDirs(), strNativeLibElems()}) {
                try {
                    Field f = srcPl.getClass().getDeclaredField(fieldName);
                    f.setAccessible(true);
                    Object val = f.get(srcPl);

                    Field fd = dstPl.getClass().getDeclaredField(fieldName);
                    fd.setAccessible(true);
                    fd.set(dstPl, val);
                } catch (NoSuchFieldException ignored) { }
            }
        } catch (Exception ignored) {
            // Non-fatal: worst case System.loadLibrary falls back to parent CL.
        }
    }

    // ── Misc helpers ──────────────────────────────────────────────────────────

    private static byte[] readAsset(Context ctx, String path) {
        try {
            InputStream is = ctx.getAssets().open(path);
            byte[] data = DexCrypto.readFully(is);
            is.close();
            return data;
        } catch (Exception e) {
            return null;
        }
    }

    /** Expose the resolved real Application class name after install(). */
    public static String getRealAppClass() {
        return Const.getRealApp();
    }
}
