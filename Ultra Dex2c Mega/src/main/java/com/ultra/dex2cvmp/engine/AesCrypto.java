package com.ultra.dex2cvmp.engine;

import java.util.Arrays;

/**
 * NativeStringCipher (kept as AesCrypto for compatibility) —
 * ChaCha20 + XOR double-layer string encryption.
 *
 * Replaces the previous AES-256-CBC implementation.
 * ChaCha20 is a stream cipher — no block padding, no S-boxes,
 * no key schedule. Output length == input length, which
 * simplifies the generated C code considerably.
 *
 * Java side : encrypt(plain, xorKey, cc20Key, nonce)
 *             XOR-encrypt → ChaCha20-encrypt → stored bytes
 *
 * C side    : getCipherImplCode() returns ph_aes_impl.h with a
 *             compact ChaCha20 decrypt-only implementation.
 *             Decryption is the same op as encryption (stream cipher):
 *             ChaCha20-decrypt → XOR-decrypt → plaintext
 */
public final class AesCrypto {

    private AesCrypto() {}

    // ── Java-side encryption ─────────────────────────────────────────────────

    /**
     * Double-encrypt: XOR (position-twisted) then ChaCha20.
     *
     * @param plain   plaintext bytes
     * @param xorKey  32-byte XOR key (two 16-byte halves, same scheme as before)
     * @param cc20Key 32-byte ChaCha20 key
     * @param nonce   12-byte ChaCha20 nonce (NOT 16 — stream cipher, no IV)
     * @return ciphertext, same length as plain (no padding)
     */
    /** XOR first 4 bytes of nonce with strIdx (little-endian) to give each string a unique nonce. */
    static byte[] tweakNonce(byte[] nonce, int strIdx) {
        byte[] n = nonce.clone();
        n[0] ^= (byte)( strIdx        & 0xFF);
        n[1] ^= (byte)((strIdx >>  8) & 0xFF);
        n[2] ^= (byte)((strIdx >> 16) & 0xFF);
        n[3] ^= (byte)((strIdx >> 24) & 0xFF);
        return n;
    }

    /** Encrypt with a per-string unique nonce (base nonce XOR le32(strIdx)). */
    public static byte[] encrypt(byte[] plain, byte[] xorKey,
                                 byte[] cc20Key, byte[] nonce, int strIdx) {
        return encrypt(plain, xorKey, cc20Key, tweakNonce(nonce, strIdx));
    }

    public static byte[] encrypt(byte[] plain, byte[] xorKey,
                                 byte[] cc20Key, byte[] nonce) {
        // Step 1: XOR encrypt
        byte[] xored = new byte[plain.length];
        for (int i = 0; i < plain.length; i++) {
            int ki = (i < 16 ? (xorKey[i & 15] & 0xFF)
                              : (xorKey[16 + (i & 15)] & 0xFF))
                   ^ ((i * 0x1D) & 0xFF);
            xored[i] = (byte)(plain[i] ^ ki);
        }
        // Step 2: ChaCha20 stream cipher
        return chaCha20(cc20Key, nonce, xored);
    }

    // ── Java ChaCha20 implementation ─────────────────────────────────────────
    // Pure Java — no javax.crypto dependency, works on all Android API levels.

    private static int rotl(int v, int n) {
        return (v << n) | (v >>> (32 - n));
    }

    private static void qr(int[] s, int a, int b, int c, int d) {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl(s[d],  8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl(s[b],  7);
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xFF)
             | ((b[off+1] & 0xFF) << 8)
             | ((b[off+2] & 0xFF) << 16)
             | ((b[off+3] & 0xFF) << 24);
    }

    /** Generate one 64-byte ChaCha20 keystream block from the given state. */
    private static byte[] cc20Block(int[] st) {
        int[] ws = Arrays.copyOf(st, 16);
        for (int i = 0; i < 10; i++) {
            qr(ws, 0, 4,  8, 12); qr(ws, 1, 5,  9, 13);
            qr(ws, 2, 6, 10, 14); qr(ws, 3, 7, 11, 15);
            qr(ws, 0, 5, 10, 15); qr(ws, 1, 6, 11, 12);
            qr(ws, 2, 7,  8, 13); qr(ws, 3, 4,  9, 14);
        }
        byte[] out = new byte[64];
        for (int i = 0; i < 16; i++) {
            int v = ws[i] + st[i];
            out[i*4]   = (byte)  v;
            out[i*4+1] = (byte) (v >>  8);
            out[i*4+2] = (byte) (v >> 16);
            out[i*4+3] = (byte) (v >> 24);
        }
        return out;
    }

    /**
     * ChaCha20 stream cipher — encrypt or decrypt (same operation).
     * key=32 bytes, nonce=12 bytes, counter starts at 0.
     */
    static byte[] chaCha20(byte[] key, byte[] nonce, byte[] data) {
        byte[] out = new byte[data.length];
        // Build initial state (RFC 8439 layout)
        int[] st = new int[16];
        st[0]  = 0x61707865; st[1] = 0x3320646e;
        st[2]  = 0x79622d32; st[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) st[4 + i] = le32(key, i * 4);
        st[12] = 0; // block counter
        st[13] = le32(nonce, 0);
        st[14] = le32(nonce, 4);
        st[15] = le32(nonce, 8);

        for (int pos = 0; pos < data.length; pos += 64) {
            byte[] block = cc20Block(st);
            st[12]++; // increment counter for next block
            int end = Math.min(64, data.length - pos);
            for (int j = 0; j < end; j++) out[pos + j] = (byte)(data[pos + j] ^ block[j]);
        }
        return out;
    }

    // ── C ChaCha20 implementation (self-contained header) ────────────────────

    /**
     * Returns a C header string with a compact, correct ChaCha20
     * decrypt implementation. No external dependencies. All symbols static.
     *
     * Exposed API:
     *   void _pha_cc20_dec(const uint8_t* key,    // 32-byte key
     *                      const uint8_t* nonce,  // 12-byte nonce
     *                      uint8_t* data,         // in/out: ciphertext → plaintext
     *                      int len)               // byte count (same before & after)
     *
     * Note: ChaCha20 is a stream cipher — decrypt == encrypt,
     *       output length always equals input length (no padding).
     */
    public static String getAesImplCode() {
        StringBuilder s = new StringBuilder(3000);
        s.append("// ph_aes_impl.h — ChaCha20 stream cipher (auto-generated, do not edit)\n");
        s.append("// Replaces AES-256-CBC. No padding, no S-boxes, no key schedule.\n");
        s.append("// Output length == input length. Decrypt == encrypt (stream cipher).\n");
        s.append("#pragma once\n");
        s.append("#include <stdint.h>\n");
        s.append("#include <string.h>\n\n");

        // Rotate-left helper
        s.append("#define _PHAR(v,n) (((v)<<(n))|((v)>>(32-(n))))\n\n");

        // Quarter-round
        s.append("static void _pha_qr(uint32_t* s,int a,int b,int c,int d){\n");
        s.append("    s[a]+=s[b];s[d]^=s[a];s[d]=_PHAR(s[d],16);\n");
        s.append("    s[c]+=s[d];s[b]^=s[c];s[b]=_PHAR(s[b],12);\n");
        s.append("    s[a]+=s[b];s[d]^=s[a];s[d]=_PHAR(s[d], 8);\n");
        s.append("    s[c]+=s[d];s[b]^=s[c];s[b]=_PHAR(s[b], 7);}\n\n");

        // One 64-byte keystream block
        s.append("static void _pha_cc20_blk(const uint32_t* st,uint8_t* out){\n");
        s.append("    uint32_t s[16]; memcpy(s,st,64);\n");
        s.append("    for(int i=0;i<10;i++){\n");
        s.append("        _pha_qr(s,0,4, 8,12);_pha_qr(s,1,5, 9,13);\n");
        s.append("        _pha_qr(s,2,6,10,14);_pha_qr(s,3,7,11,15);\n");
        s.append("        _pha_qr(s,0,5,10,15);_pha_qr(s,1,6,11,12);\n");
        s.append("        _pha_qr(s,2,7, 8,13);_pha_qr(s,3,4, 9,14);}\n");
        s.append("    for(int i=0;i<16;i++){\n");
        s.append("        uint32_t v=s[i]+st[i];\n");
        s.append("        out[i*4]=(uint8_t)v;out[i*4+1]=(uint8_t)(v>>8);\n");
        s.append("        out[i*4+2]=(uint8_t)(v>>16);out[i*4+3]=(uint8_t)(v>>24);}}\n\n");

        // le32 helper (inline for C compatibility)
        s.append("#define _PHA_LE32(b,i) ((uint32_t)(b)[i]|((uint32_t)(b)[(i)+1]<<8)|((uint32_t)(b)[(i)+2]<<16)|((uint32_t)(b)[(i)+3]<<24))\n\n");

        // Main decrypt function
        s.append("static void _pha_cc20_dec(const uint8_t* key,const uint8_t* nonce,\n");
        s.append("                          uint8_t* data,int len){\n");
        s.append("    uint32_t st[16];\n");
        s.append("    st[0]=0x61707865u;st[1]=0x3320646eu;st[2]=0x79622d32u;st[3]=0x6b206574u;\n");
        s.append("    for(int i=0;i<8;i++) st[4+i]=_PHA_LE32(key,i*4);\n");
        s.append("    st[12]=0;\n");
        s.append("    st[13]=_PHA_LE32(nonce,0);\n");
        s.append("    st[14]=_PHA_LE32(nonce,4);\n");
        s.append("    st[15]=_PHA_LE32(nonce,8);\n");
        s.append("    uint8_t _blk[64];\n");
        s.append("    for(int i=0;i<len;i+=64){\n");
        s.append("        _pha_cc20_blk(st,_blk);\n");
        s.append("        st[12]++;\n");
        s.append("        int e=(len-i<64)?len-i:64;\n");
        s.append("        for(int j=0;j<e;j++) data[i+j]^=_blk[j];}\n");
        s.append("    memset(_blk,0,64);\n");
        s.append("    memset(st,0,64);}\n");

        return s.toString();
    }
}
