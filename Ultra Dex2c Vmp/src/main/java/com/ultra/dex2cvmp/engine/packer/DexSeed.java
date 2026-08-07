package com.ultra.dex2cvmp.engine.packer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Per-APK key derivation for the Phantom DEX encryption scheme.
 *
 * A fresh 16-byte random salt is generated each time an APK is packed.
 * The 16-byte session key is then derived as:
 *
 *   key = ARX_KDF(salt[16], sha256(pkg_name)[0..7])
 *
 * The same KDF is implemented in native C (phantom_key.c) and is called at
 * runtime by libphantom.so via DexCrypto.nativeDecryptShard(salt, pkgNameUtf8, shard).
 * Cert binding has been removed — signature tamper detection is handled
 * separately by the app's own tamper check.
 *
 * ── Usage (packer side) ───────────────────────────────────────────────────────
 *   byte[] salt = DexSeed.randomSalt();
 *   byte[] key  = DexSeed.deriveKey(salt, "com.example.app");
 *   DexCrypto.encrypt(key, in, out);
 *   // store salt as assets/phantom/ph_salt (16 bytes, raw)
 * ─────────────────────────────────────────────────────────────────────────────
 */
public final class DexSeed {

    private DexSeed() {}

    /** Generate a cryptographically random 16-byte salt. */
    public static byte[] randomSalt() {
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Derive a 16-byte encryption key.
     *
     * @param salt     16-byte random salt (stored as {@code assets/phantom/ph_salt}).
     * @param pkgName  Package name exactly as it appears in AndroidManifest.xml.
     * @return 16-byte key suitable for {@link DexCrypto#encrypt}.
     */
    public static byte[] deriveKey(byte[] salt, String pkgName) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] pkgHash = sha256.digest(
                    pkgName == null ? new byte[0] : pkgName.getBytes(StandardCharsets.UTF_8));
            return arx(salt, pkgHash);
        } catch (Exception e) {
            throw new RuntimeException("DexSeed.deriveKey failed", e);
        }
    }

    // ── ARX KDF ──────────────────────────────────────────────────────────────

    /**
     * ARX (Add-Rotate-XOR) key derivation.
     * Must stay byte-for-byte identical to the C implementation in phantom_key.c.
     *
     * @param salt    16-byte salt
     * @param pkgHash ≥8-byte pkg-name SHA-256
     * @return 16-byte derived key
     */
    static byte[] arx(byte[] salt, byte[] pkgHash) {
        // Initialise 4-word state from salt (little-endian).
        int s0 = le32(salt, 0);
        int s1 = le32(salt, 4);
        int s2 = le32(salt, 8);
        int s3 = le32(salt, 12);

        // Mix package-name hash: 8 rounds.
        int ph0 = le32(pkgHash, 0);
        int ph1 = le32(pkgHash, 4);
        for (int r = 0; r < 8; r++) {
            s0 = Integer.rotateLeft(s0 ^ ph0, 11) + s1;
            s1 = Integer.rotateLeft(s1 ^ ph1, 13) + s2;
            s2 = Integer.rotateLeft(s2 ^ ph0, 17) + s3;
            s3 = Integer.rotateLeft(s3 ^ ph1, 19) + s0;
        }

        // Serialise output (little-endian).
        byte[] key = new byte[16];
        putLE32(key, 0,  s0);
        putLE32(key, 4,  s1);
        putLE32(key, 8,  s2);
        putLE32(key, 12, s3);
        return key;
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static int le32(byte[] b, int off) {
        return  (b[off]     & 0xFF)
              | ((b[off+1]  & 0xFF) << 8)
              | ((b[off+2]  & 0xFF) << 16)
              | ((b[off+3]  & 0xFF) << 24);
    }

    private static void putLE32(byte[] b, int off, int v) {
        b[off]   = (byte)  v;
        b[off+1] = (byte) (v >>> 8);
        b[off+2] = (byte) (v >>> 16);
        b[off+3] = (byte) (v >>> 24);
    }
}
