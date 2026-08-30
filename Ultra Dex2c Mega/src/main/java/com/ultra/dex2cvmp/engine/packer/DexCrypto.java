package com.ultra.dex2cvmp.engine.packer;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.DeflaterInputStream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
 * Host-side cipher helpers for DexPacker.
 *
 * The inner compatibility layer still uses the per-APK salt/package ARX key.
 * The outer payload envelope uses one universal XChaCha20-Poly1305 key that is mirrored
 * inside the VMP-compiled Phantom native loader.  Keeping the two layers
 * separate means the existing salt/root-policy path remains unchanged while a
 * public salt/package derivation is no longer sufficient to recover a shard.
 */
public class DexCrypto {

    /*
     * Universal payload key.
     *
     * This is intentionally not the Phantom blob bootstrap key.  It is used
     * only for the outer DEX envelope and must match the obfuscated/rebuilt
     * value in phantom_key.c.  The protector-side copy is never packaged into
     * a protected APK; the runtime copy is compiled into the Phantom blob.
     */
    private static final byte[] UNIVERSAL_PAYLOAD_KEY = {
            (byte) 0x9f, 0x2a, (byte) 0x81, (byte) 0xd4,
            0x53, 0x6c, (byte) 0xe7, 0x18,
            (byte) 0xb0, 0x4d, (byte) 0x92, (byte) 0xaf,
            0x37, (byte) 0xc8, 0x05, 0x7e,
            0x61, (byte) 0xfa, 0x2c, (byte) 0x90,
            0x1b, (byte) 0xd3, 0x48, (byte) 0xbe,
            0x76, 0x04, (byte) 0xe1, 0x59,
            (byte) 0xca, 0x33, (byte) 0x8d, (byte) 0xf0
    };
    private static final SecureRandom PAYLOAD_RANDOM = new SecureRandom();
    private static final int XCHACHA_NONCE_BYTES = 24;
    private static final int CHACHA_TAG_BYTES = 16;

    /** Decrypt {@code input} stream into {@code output} stream using {@code keyBytes}. */
    public static void decrypt(byte[] keyBytes, InputStream input, OutputStream output) throws Exception {
        InflaterInputStream  is = new InflaterInputStream(input);
        InflaterOutputStream os = new InflaterOutputStream(output);
        exfr(keyBytes, is, os);
        os.close();
        is.close();
    }

    /**
     * Wrap one already-compressed/ARX-protected shard in the universal
     * authenticated payload envelope.
     *
     * Record format consumed by phantom_key.c:
     *   [24-byte random nonce][XChaCha20 ciphertext + 16-byte Poly1305 tag]
     *
     * The shard index is authenticated as associated data so records cannot
     * be reordered or transplanted between positions without detection.
     */
    public static byte[] encryptPayloadEnvelope(byte[] inner, int shardIndex)
            throws GeneralSecurityException, IOException {
        if (inner == null) throw new IllegalArgumentException("inner shard is null");
        if (shardIndex < 0) throw new IllegalArgumentException("negative shard index");

        byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
        byte[] aad = shardAad(shardIndex);
        PAYLOAD_RANDOM.nextBytes(nonce);
        try {
            byte[] ciphertextAndTag = xchacha20Poly1305Encrypt(
                    UNIVERSAL_PAYLOAD_KEY, nonce, aad, inner);

            ByteArrayOutputStream out =
                    new ByteArrayOutputStream(nonce.length + ciphertextAndTag.length);
            out.write(nonce);
            out.write(ciphertextAndTag);
            Arrays.fill(ciphertextAndTag, (byte) 0);
            return out.toByteArray();
        } finally {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(aad, (byte) 0);
        }
    }

    private static byte[] shardAad(int shardIndex) {
        return new byte[] {
                (byte) (shardIndex >>> 24),
                (byte) (shardIndex >>> 16),
                (byte) (shardIndex >>> 8),
                (byte) shardIndex
        };
    }

    /*
     * Portable XChaCha20-Poly1305-IETF implementation for the packer.
     * The packer can run on Android 8.1, so it cannot rely on a provider that
     * was added in a newer Android release. BigInteger is used only here,
     * outside the protected runtime; native loading uses fixed-width arithmetic.
     */
    private static byte[] xchacha20Poly1305Encrypt(
            byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("key must be 32 bytes");
        }
        if (nonce == null || nonce.length != XCHACHA_NONCE_BYTES) {
            throw new IllegalArgumentException("nonce must be 24 bytes");
        }

        byte[] subkey = hChaCha20(key, nonce);
        byte[] ietfNonce = new byte[12];
        System.arraycopy(nonce, 16, ietfNonce, 4, 8);
        try {
            return chacha20Poly1305Encrypt(subkey, ietfNonce, aad, plaintext);
        } finally {
            Arrays.fill(subkey, (byte) 0);
            Arrays.fill(ietfNonce, (byte) 0);
        }
    }

    private static byte[] hChaCha20(byte[] key, byte[] nonce) {
        int[] x = new int[16];
        x[0] = 0x61707865;
        x[1] = 0x3320646e;
        x[2] = 0x79622d32;
        x[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) x[4 + i] = le32(key, i * 4);
        for (int i = 0; i < 4; i++) x[12 + i] = le32(nonce, i * 4);

        for (int round = 0; round < 10; round++) {
            quarterRound(x, 0, 4, 8, 12);
            quarterRound(x, 1, 5, 9, 13);
            quarterRound(x, 2, 6, 10, 14);
            quarterRound(x, 3, 7, 11, 15);
            quarterRound(x, 0, 5, 10, 15);
            quarterRound(x, 1, 6, 11, 12);
            quarterRound(x, 2, 7, 8, 13);
            quarterRound(x, 3, 4, 9, 14);
        }

        byte[] subkey = new byte[32];
        store32(subkey, 0, x[0]);
        store32(subkey, 4, x[1]);
        store32(subkey, 8, x[2]);
        store32(subkey, 12, x[3]);
        store32(subkey, 16, x[12]);
        store32(subkey, 20, x[13]);
        store32(subkey, 24, x[14]);
        store32(subkey, 28, x[15]);
        Arrays.fill(x, 0);
        return subkey;
    }

    private static byte[] chacha20Poly1305Encrypt(
            byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        if (key == null || key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        if (nonce == null || nonce.length != 12) throw new IllegalArgumentException("nonce must be 12 bytes");
        if (aad == null) aad = new byte[0];
        if (plaintext == null) plaintext = new byte[0];

        byte[] firstBlock = chacha20Block(key, nonce, 0);
        byte[] polyKey = Arrays.copyOf(firstBlock, 32);
        byte[] ciphertext = chacha20Xor(key, nonce, 1, plaintext);
        byte[] macInput = poly1305Input(aad, ciphertext);
        byte[] tag = poly1305Mac(polyKey, macInput);
        byte[] result = new byte[ciphertext.length + CHACHA_TAG_BYTES];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(tag, 0, result, ciphertext.length, tag.length);

        Arrays.fill(firstBlock, (byte) 0);
        Arrays.fill(polyKey, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);
        Arrays.fill(macInput, (byte) 0);
        Arrays.fill(tag, (byte) 0);
        return result;
    }

    private static byte[] chacha20Xor(byte[] key, byte[] nonce, int counter, byte[] input) {
        byte[] output = new byte[input.length];
        for (int offset = 0; offset < input.length; offset += 64) {
            byte[] stream = chacha20Block(key, nonce, counter++);
            int count = Math.min(64, input.length - offset);
            for (int i = 0; i < count; i++) {
                output[offset + i] = (byte)(input[offset + i] ^ stream[i]);
            }
            Arrays.fill(stream, (byte) 0);
        }
        return output;
    }

    private static byte[] chacha20Block(byte[] key, byte[] nonce, int counter) {
        int[] x = new int[16];
        int[] original = new int[16];
        int[] constants = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        System.arraycopy(constants, 0, x, 0, 4);
        for (int i = 0; i < 8; i++) x[4 + i] = le32(key, i * 4);
        x[12] = counter;
        x[13] = le32(nonce, 0);
        x[14] = le32(nonce, 4);
        x[15] = le32(nonce, 8);
        System.arraycopy(x, 0, original, 0, x.length);

        for (int round = 0; round < 10; round++) {
            quarterRound(x, 0, 4, 8, 12);
            quarterRound(x, 1, 5, 9, 13);
            quarterRound(x, 2, 6, 10, 14);
            quarterRound(x, 3, 7, 11, 15);
            quarterRound(x, 0, 5, 10, 15);
            quarterRound(x, 1, 6, 11, 12);
            quarterRound(x, 2, 7, 8, 13);
            quarterRound(x, 3, 4, 9, 14);
        }

        byte[] output = new byte[64];
        for (int i = 0; i < 16; i++) store32(output, i * 4, x[i] + original[i]);
        Arrays.fill(x, 0);
        Arrays.fill(original, 0);
        return output;
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    private static int le32(byte[] b, int offset) {
        return (b[offset] & 0xff) | ((b[offset + 1] & 0xff) << 8)
                | ((b[offset + 2] & 0xff) << 16) | ((b[offset + 3] << 24));
    }

    private static void store32(byte[] b, int offset, int v) {
        b[offset] = (byte)v;
        b[offset + 1] = (byte)(v >>> 8);
        b[offset + 2] = (byte)(v >>> 16);
        b[offset + 3] = (byte)(v >>> 24);
    }

    private static byte[] poly1305Input(byte[] aad, byte[] ciphertext) {
        int aadPad = (16 - (aad.length & 15)) & 15;
        int cipherPad = (16 - (ciphertext.length & 15)) & 15;
        byte[] input = new byte[aad.length + aadPad + ciphertext.length + cipherPad + 16];
        int offset = 0;
        System.arraycopy(aad, 0, input, offset, aad.length);
        offset += aad.length + aadPad;
        System.arraycopy(ciphertext, 0, input, offset, ciphertext.length);
        offset += ciphertext.length + cipherPad;
        putLe64(input, offset, (long)aad.length);
        putLe64(input, offset + 8, (long)ciphertext.length);
        return input;
    }

    private static void putLe64(byte[] b, int offset, long value) {
        for (int i = 0; i < 8; i++) {
            b[offset + i] = (byte)value;
            value >>>= 8;
        }
    }

    private static byte[] poly1305Mac(byte[] oneTimeKey, byte[] input) {
        byte[] rBytes = Arrays.copyOfRange(oneTimeKey, 0, 16);
        rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
        rBytes[4] &= (byte)252; rBytes[8] &= (byte)252; rBytes[12] &= (byte)252;
        BigInteger r = littleUnsigned(rBytes);
        BigInteger p = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
        BigInteger accumulator = BigInteger.ZERO;
        for (int offset = 0; offset < input.length; offset += 16) {
            int count = Math.min(16, input.length - offset);
            byte[] block = new byte[count + 1];
            System.arraycopy(input, offset, block, 0, count);
            block[count] = 1;
            accumulator = accumulator.add(littleUnsigned(block)).multiply(r).mod(p);
        }
        byte[] sBytes = Arrays.copyOfRange(oneTimeKey, 16, 32);
        BigInteger tagValue = accumulator.add(littleUnsigned(sBytes))
                .mod(BigInteger.ONE.shiftLeft(128));
        byte[] tag = littleBytes(tagValue, CHACHA_TAG_BYTES);
        Arrays.fill(rBytes, (byte) 0);
        Arrays.fill(sBytes, (byte) 0);
        return tag;
    }

    private static BigInteger littleUnsigned(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) reversed[i] = bytes[bytes.length - 1 - i];
        return new BigInteger(1, reversed);
    }

    private static byte[] littleBytes(BigInteger value, int length) {
        byte[] bigEndian = value.toByteArray();
        byte[] output = new byte[length];
        for (int i = 0; i < length; i++) {
            int source = bigEndian.length - 1 - i;
            output[i] = source >= 0 ? bigEndian[source] : 0;
        }
        return output;
    }

    /** Encrypt {@code input} stream into {@code output} stream using {@code keyBytes}. */
    public static void encrypt(byte[] keyBytes, InputStream input, OutputStream output) throws Exception {
        DeflaterInputStream  is = new DeflaterInputStream(input);
        DeflaterOutputStream os = new DeflaterOutputStream(output);
        exfr(keyBytes, is, os);
        os.close();
        is.close();
    }

    /**
     * Derive an independent compatibility-layer key for one shard.
     * The native Phantom loader mirrors this exact digest.
     */
    public static byte[] deriveShardKey(byte[] baseKey, int shardIndex)
            throws GeneralSecurityException {
        if (baseKey == null || baseKey.length != 16) {
            throw new IllegalArgumentException("base key must be 16 bytes");
        }
        if (shardIndex < 0) {
            throw new IllegalArgumentException("negative shard index");
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(baseKey);
        digest.update(new byte[] {
                0x50, 0x48, 0x53, 0x48, 0x41, 0x52, 0x44, 0x31
        }); // "PHSHARD1"
        digest.update((byte)(shardIndex >>> 24));
        digest.update((byte)(shardIndex >>> 16));
        digest.update((byte)(shardIndex >>> 8));
        digest.update((byte)shardIndex);
        byte[] expanded = digest.digest();
        byte[] shardKey = Arrays.copyOf(expanded, 16);
        Arrays.fill(expanded, (byte) 0);
        return shardKey;
    }

    // ── internal cipher ───────────────────────────────────────────────────────

    private static void exfr(byte[] key, @NotNull InputStream inputStream, OutputStream outputStream) throws Exception {
        if (key == null || key.length < 16) throw new IllegalArgumentException("key must be 16 bytes");

        // Pack 16 key bytes into 4 × 32-bit words (little-endian).
        int[] iArr = new int[4];
        for (int i = 0; i < 4; i++) {
            int base = i * 4;
            iArr[i] = (key[base]     & 0xFF)
                    | ((key[base + 1] & 0xFF) << 8)
                    | ((key[base + 2] & 0xFF) << 16)
                    | ((key[base + 3] & 0xFF) << 24);
        }

        // Initial cipher state derived from key words.
        int[] iArr2 = new int[]{ iArr[0] ^ iArr[2], iArr[1] ^ iArr[3] };

        iArr = FxIjsF(iArr);
        byte[] bArr = new byte[8192];
        int i3 = 0;
        while (true) {
            int read = inputStream.read(bArr);
            if (read < 0) return;
            int i4 = i3 + read;
            int i5 = 0;
            while (i3 < i4) {
                int i6 = i3 % 8;
                int i7 = i6 / 4;
                int i8 = i3 % 4;
                if (i6 == 0) nDnv(iArr, iArr2);
                bArr[i5] = (byte) (((byte) (iArr2[i7] >> (i8 * 8))) ^ bArr[i5]);
                i3++;
                i5++;
            }
            outputStream.write(bArr, 0, read);
        }
    }

    @Contract(pure = true)
    private static int @NotNull [] FxIjsF(int @NotNull [] iArr) {
        int[] iArr2 = new int[27];
        int i = iArr[0];
        iArr2[0] = i;
        int[] iArr3 = new int[]{ iArr[1], iArr[2], iArr[3] };
        for (int i2 = 0; i2 < 26; i2++) {
            iArr3[i2 % 3] = (((iArr3[i2 % 3] >>> 8) | (iArr3[i2 % 3] << 24)) + i) ^ i2;
            i = ((i << 3) | (i >>> 29)) ^ iArr3[i2 % 3];
            iArr2[i2 + 1] = i;
        }
        return iArr2;
    }

    private static void nDnv(int @NotNull [] iArr, int @NotNull [] iArr2) {
        int i = iArr2[0];
        int i2 = iArr2[1];
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[0];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[1];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[2];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[3];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[4];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[5];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[6];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[7];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[8];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[9];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[10];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[11];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[12];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[13];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[14];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[15];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[16];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[17];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[18];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[19];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[20];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[21];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[22];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[23];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[24];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[25];
        i = ((i << 3) | (i >>> 29)) ^ i2;
        i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[26];
        iArr2[0] = ((i << 3) | (i >>> 29)) ^ i2;
        iArr2[1] = i2;
    }
}
