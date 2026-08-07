package com.ultra.dex2cvmp.engine.packer;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.util.zip.DeflaterInputStream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
 * Host-side cipher helpers for DexPacker.
 *
 * Key is now a raw 16-byte array derived by PhantomKey.deriveKey() rather than
 * the old static PROTECT_KEY string.  The ARX stream cipher is unchanged; only
 * the key-expansion step is updated to consume bytes directly (4 bytes → 1 int,
 * little-endian), making full use of all 16 key bytes.
 */
public class DexCrypto {

    /** Decrypt {@code input} stream into {@code output} stream using {@code keyBytes}. */
    public static void decrypt(byte[] keyBytes, InputStream input, OutputStream output) throws Exception {
        InflaterInputStream  is = new InflaterInputStream(input);
        InflaterOutputStream os = new InflaterOutputStream(output);
        exfr(keyBytes, is, os);
        os.close();
        is.close();
    }

    /** Encrypt {@code input} stream into {@code output} stream using {@code keyBytes}. */
    public static void encrypt(byte[] keyBytes, InputStream input, OutputStream output) throws Exception {
        DeflaterInputStream  is = new DeflaterInputStream(input);
        DeflaterOutputStream os = new DeflaterOutputStream(output);
        exfr(keyBytes, is, os);
        os.close();
        is.close();
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
