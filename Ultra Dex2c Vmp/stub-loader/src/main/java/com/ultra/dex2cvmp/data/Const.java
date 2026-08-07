package com.ultra.dex2cvmp.data;

/**
 * Runtime constants for the DEX loader stub.
 *
 * The old static PROTECT_KEY / getProtectKey() have been removed.
 * Key material is now derived at runtime by libphantom.so via
 * DexCrypto.nativeGetKey(salt, certHash, pkgName) so that:
 *   • No key string ever appears in the DEX string pool.
 *   • Each protected APK has a unique, per-pack random salt.
 *   • The derived key is bound to the signing certificate; re-signing
 *     with a different cert produces a wrong key and silent garbage output.
 *
 * REAL_APP is the only per-protected-APK value; DexProtector.install()
 * overwrites it from assets/phantom/app.cfg before realApplication() runs.
 */
public class Const {
    /** Asset sub-directory holding the phantom payload. */
    public static final String DP_LIB = "phantom";

    /** Single-file bundle containing all encrypted DEX shards. */
    public static final String BUNDLE_FILE = "phantom.vmp";

    /** Asset holding the real Application class name. */
    public static final String APP_CFG = "app.cfg";

    /**
     * Asset holding the 16-byte random salt written by DexPacker at protection
     * time.  Read by DexProtector.install() and passed to nativeGetKey().
     */
    public static final String SALT_ASSET = "ph_salt";

    /**
     * Asset sub-directory (inside phantom/) where the pre-built, AES-encrypted
     * libphantom native blobs are stored inside the protected APK.
     *
     * Files:
     *   phantom/libphantom_arm64.blob  — arm64-v8a build
     *   phantom/libphantom_arm.blob    — armeabi-v7a build
     *
     * These blobs are generated offline (OLLVM + NDK CI) and packed by
     * DexPacker.  The stub decrypts the ABI-appropriate blob at first launch,
     * writes it to getCodeCacheDir()/libphantom.so, and System.load()s it.
     */
    public static final String PHANTOM_BLOB_ARM64 = "libphantom_arm64.blob";
    public static final String PHANTOM_BLOB_ARM   = "libphantom_arm.blob";

    /**
     * Real Application class name — default is the base Application.
     * DexProtector.install() overwrites this from assets/phantom/app.cfg
     * before realApplication() is invoked.
     * Private — only settable via setRealApp() to prevent reflection patching.
     */
    private static String REAL_APP = "android.app.Application";

    public static String getRealApp() { return REAL_APP; }

    public static void setRealApp(String name) {
        if (name != null && !name.isEmpty()) REAL_APP = name;
    }
}
