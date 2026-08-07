package com.ultra.dex2cvmp.engine;

import android.content.Context;
import android.util.Log;
import com.ultra.dex2cvmp.Vault;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class ApkSigner {

    private static final String TAG = "ApkSigner";

    private static volatile boolean bcRegistered = false;

    /**
     * Replaces Android's stripped system BouncyCastle with the full 1.80 library.
     *
     * Android ships a stripped "BC" provider that deliberately omits JKS support.
     * Simply checking getProvider("BC") != null misses this — BC IS registered,
     * but it's the wrong one. We must remove it and insert the full version.
     * Safe to call multiple times (guarded by bcRegistered flag).
     *
     * Note: removal + insertion is done atomically. If insertion fails the old
     * provider slot is already gone, so we catch and log rather than crashing.
     */
    private static synchronized void ensureBC() {
        if (!bcRegistered) {
            try {
                Security.removeProvider("BC");
                Security.insertProviderAt(new BouncyCastleProvider(), 1);
                bcRegistered = true;
                Log.i(TAG, "Full BouncyCastle provider installed (JKS/PKCS12/BKS/UBER)");
            } catch (Exception e) {
                // If insertion fails, re-add Android's stripped BC so PKCS12 still works.
                Log.w(TAG, "Full BC install failed, re-adding system BC: " + e.getMessage());
                try { Security.addProvider(new BouncyCastleProvider()); } catch (Exception ignored) {}
            }
        }
    }

    public static void sign(Context context, File unsigned, File output) throws Exception {
        final File   keystoreFile = extractBuiltinKeystore(context);
        final String alias        = Vault.f();
        final char[] storePass    = Vault.g().toCharArray();
        final char[] keyPass      = storePass;
        Log.i(TAG, "Using built-in keystore (PKCS12)");

        // The built-in keystore is always PKCS12 — load it directly without
        // the try-all-types dance to avoid any BC provider dependency at this step.
        KeyStore ks;
        try {
            ks = KeyStore.getInstance("PKCS12");
            byte[] bytes;
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                bytes = readAllBytes(fis);
            }
            ks.load(new java.io.ByteArrayInputStream(bytes), storePass);
            Log.i(TAG, "Built-in keystore loaded: provider=" + ks.getProvider().getName()
                    + " aliases=" + java.util.Collections.list(ks.aliases()));
        } catch (Exception e) {
            // Fallback: try the universal loader (attempts BC-backed types too)
            Log.w(TAG, "Direct PKCS12 load failed (" + e.getMessage() + "), trying universal loader");
            ks = loadKeyStore(keystoreFile, storePass);
        }

        PrivateKey      privateKey = (PrivateKey)      ks.getKey(alias, keyPass);
        X509Certificate cert       = (X509Certificate) ks.getCertificate(alias);

        if (privateKey == null)
            throw new Exception("Key alias \"" + alias + "\" not found in keystore");

        Log.i(TAG, "Signing → input=" + unsigned.getName()
                + " (" + (unsigned.length() / 1024) + " KB)"
                + " key=" + privateKey.getAlgorithm()
                + " cert=" + cert.getSigAlgName());

        com.android.apksig.ApkSigner.SignerConfig signerConfig =
            new com.android.apksig.ApkSigner.SignerConfig.Builder(
                "CERT", privateKey, Collections.singletonList(cert)
            ).build();

        try {
            new com.android.apksig.ApkSigner.Builder(
                    Collections.singletonList(signerConfig))
                .setInputApk(unsigned)
                .setOutputApk(output)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(false)
                .setMinSdkVersion(26)
                .setAlignFileSize(true)
                .build()
                .sign();
        } catch (Exception e) {
            StringBuilder chain = new StringBuilder(e.getMessage());
            Throwable cause = e.getCause();
            while (cause != null) {
                chain.append(" → ").append(cause.getClass().getSimpleName())
                     .append(": ").append(cause.getMessage());
                cause = cause.getCause();
            }
            Log.e(TAG, "apksig failed: " + chain);
            throw new Exception("Signing failed: " + chain.toString(), e);
        }

        Log.i(TAG, "Signing done → " + output.getName()
                + " (" + (output.length() / 1024) + " KB)");
    }

    /**
     * Universal keystore loader — accepts PKCS12, JKS, BKS, JCEKS, UBER.
     *
     * Key design decisions (2025 research):
     *  1. Buffer the whole file into a byte[] first so each retry gets a fresh
     *     stream without re-opening the file (retrying on a half-read stream throws).
     *  2. ensureBC() already replaced Android's stripped BC with the full 1.80
     *     library, so every type below uses the same full provider — no special-
     *     casing needed per type.
     *  3. Try order: PKCS12 (most common / JDK 9+ default) → JKS (legacy Java
     *     keytool default, used by AIDE/AndroidIDE) → BKS (Android legacy) →
     *     JCEKS → UBER.  First one that loads without throwing wins.
     */
    public static KeyStore loadKeyStore(File file, char[] password) throws Exception {
        ensureBC();

        // Buffer entire file — mandatory so we can retry across multiple types.
        // readAllBytes() is API 33+, so we use a manual loop for API 26 compat.
        byte[] bytes;
        try (FileInputStream fis = new FileInputStream(file)) {
            bytes = readAllBytes(fis);
        }

        String[] types = {"PKCS12", "JKS", "BKS", "JCEKS", "UBER"};
        Exception last = null;

        for (String type : types) {
            try {
                KeyStore ks = KeyStore.getInstance(type);
                ks.load(new java.io.ByteArrayInputStream(bytes), password);
                Log.i(TAG, "Loaded keystore: type=" + type
                        + " provider=" + ks.getProvider().getName()
                        + " aliases=" + java.util.Collections.list(ks.aliases()));
                return ks;
            } catch (Exception e) {
                last = e;
                Log.v(TAG, "type=" + type + " failed: " + e.getMessage());
            }
        }

        throw new Exception(
                "Could not load keystore — tried PKCS12 / JKS / BKS / JCEKS / UBER.\n"
                + "Check your store password is correct. Last error: "
                + (last != null ? last.getMessage() : "unknown"), last);
    }

    /** API-26-safe replacement for InputStream.readAllBytes() (requires API 33). */
    private static byte[] readAllBytes(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    /**
     * Lists all key aliases in a keystore file — used by Settings to help users
     * find the right alias when they don't know it.
     */
    public static java.util.List<String> listAliases(File file, char[] password) {
        java.util.List<String> aliases = new java.util.ArrayList<>();
        try {
            KeyStore ks = loadKeyStore(file, password);
            java.util.Enumeration<String> en = ks.aliases();
            while (en.hasMoreElements()) aliases.add(en.nextElement());
        } catch (Exception e) {
            Log.w(TAG, "listAliases failed: " + e.getMessage());
        }
        return aliases;
    }

    private static File extractBuiltinKeystore(Context context) throws IOException {
        File ks = new File(context.getCacheDir(), "ks.p12");
        try (InputStream  in  = context.getAssets().open(Vault.e());
             OutputStream out = new FileOutputStream(ks)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
        return ks;
    }

    public static byte[] getDebugP12Bytes(Context context) throws IOException {
        try (InputStream in = context.getAssets().open("debug.p12")) {
            return readAllBytes(in);
        }
    }

    /**
     * Return the DER-encoded bytes of the signing certificate that will be used
     * when this app calls {@link #sign(Context, File, File)}.
     *
     * Used by DexPacker to bind the DEX encryption key to the signing cert so
     * that re-signing the protected APK with a different cert causes the runtime
     * KDF to derive a different (wrong) key and decryption silently fails.
     *
     * @return DER bytes of the X.509 signing cert, never null.
     * @throws Exception if the built-in keystore cannot be loaded.
     */
    public static byte[] getSigningCertDer(Context context) throws Exception {
        File keystoreFile = extractBuiltinKeystore(context);
        char[] storePass = Vault.g().toCharArray();

        KeyStore ks;
        try {
            ks = KeyStore.getInstance("PKCS12");
            byte[] bytes;
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                bytes = readAllBytes(fis);
            }
            ks.load(new java.io.ByteArrayInputStream(bytes), storePass);
        } catch (Exception e) {
            ks = loadKeyStore(keystoreFile, storePass);
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(Vault.f());
        if (cert == null) {
            throw new Exception("Signing cert not found in built-in keystore "
                    + "(alias=\"" + Vault.f() + "\")");
        }
        return cert.getEncoded();
    }
}
