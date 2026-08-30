// phantom_cipher.h — AES-256-CBC string protection for phantom_key.c
//
// Mirrors the guard.cpp / guard_pstrings.inc pattern exactly, but uses
// an INDEPENDENT phantom-specific master key so the two .so files share
// no key material.
//
// Two-tier protection (matches guard.cpp):
//   • Ciphertext in .rodata  — only random bytes, no readable strings
//   • Key derived at runtime — ph_build_key256() uses split volatile arrays
//     so no single MOVZ/MOV instruction holds the full key byte; amice's MBA
//     pass hides the combine arithmetic further
//   • Per-string unique key  — FNV-1a(idx) mixes the master key so each
//     string has a completely independent AES key; cracking one reveals nothing
//   • Plaintext XOR 0x5A     — second layer post-decrypt
//   • ph_reveal_ns() is annotated +vm_virtualize — decrypt runs inside VMP
//
// Usage:
//   char buf[SP_BUF_SZ];
//   ph_reveal_ns(PH_IDX_PROC_SELFSTATUS, SP_PROC_SELFSTATUS,
//                SP_PROC_SELFSTATUS_LEN, buf);
//   // ... use buf ...
//   PH_ZERO(buf, SP_BUF_SZ);
//
// Or with the convenience macro:
//   PH_AES(path, PROC_SELFSTATUS);   // declares char path[SP_BUF_SZ], decrypts
//   // ... use path ...
//   PH_ZERO(path, SP_BUF_SZ);
//
// IMPORTANT: always PH_ZERO the buffer when done — the plaintext must not
// linger on the stack after the detection call returns.

#ifndef PHANTOM_CIPHER_H
#define PHANTOM_CIPHER_H

#include <stdint.h>
#include <string.h>

// ════════════════════════════════════════════════════════════════════════════
// AES S-box / Inverse S-box / RCON — identical to guard.cpp
// (Same standard FIPS 197 tables; duplicated here so phantom_key.c links
//  independently without pulling in guard.cpp's translation unit.)
// ════════════════════════════════════════════════════════════════════════════

static const uint8_t PH_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t PH_RSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const uint8_t PH_RCON[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static inline uint8_t ph_gf_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) ? 0x1b : 0));
}
static inline uint8_t ph_gf_mul(uint8_t x, uint8_t y) {
    return (uint8_t)(
        ((y & 1)  ?  x                                                    : 0) ^
        ((y & 2)  ?  ph_gf_xtime(x)                                      : 0) ^
        ((y & 4)  ?  ph_gf_xtime(ph_gf_xtime(x))                         : 0) ^
        ((y & 8)  ?  ph_gf_xtime(ph_gf_xtime(ph_gf_xtime(x)))            : 0) ^
        ((y & 16) ?  ph_gf_xtime(ph_gf_xtime(ph_gf_xtime(ph_gf_xtime(x)))): 0));
}

// ════════════════════════════════════════════════════════════════════════════
// AES-256 key expansion + CBC decryption
// ════════════════════════════════════════════════════════════════════════════

typedef struct { uint8_t rk[240]; } PH_AES256;

static void ph_aes256_expand(PH_AES256 *a, const uint8_t *key) {
    memcpy(a->rk, key, 32);
    uint8_t *w = a->rk;
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, w + (i-1)*4, 4);
        if (i % 8 == 0) {
            uint8_t tmp = PH_SBOX[t[1]] ^ PH_RCON[i/8];
            t[1] = PH_SBOX[t[2]]; t[2] = PH_SBOX[t[3]]; t[3] = PH_SBOX[t[0]];
            t[0] = tmp;
        } else if (i % 8 == 4) {
            t[0]=PH_SBOX[t[0]]; t[1]=PH_SBOX[t[1]];
            t[2]=PH_SBOX[t[2]]; t[3]=PH_SBOX[t[3]];
        }
        uint8_t *dst = w + i*4, *src = w + (i-8)*4;
        dst[0]=src[0]^t[0]; dst[1]=src[1]^t[1];
        dst[2]=src[2]^t[2]; dst[3]=src[3]^t[3];
    }
}

static void ph_aes256_dec_block(const PH_AES256 *a, const uint8_t *in, uint8_t *out) {
    uint8_t s[16];
    const uint8_t *rk = a->rk + 224;
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int r = 13; r >= 0; r--) {
        rk -= 16;
        uint8_t t;
        t=s[13];s[13]=s[9];s[9]=s[5];s[5]=s[1];s[1]=t;
        t=s[10];s[10]=s[2];s[2]=t; t=s[14];s[14]=s[6];s[6]=t;
        t=s[3];s[3]=s[7];s[7]=s[11];s[11]=s[15];s[15]=t;
        for (int i = 0; i < 16; i++) s[i] = PH_RSBOX[s[i]] ^ rk[i];
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t *col = s + c*4;
                uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
                col[0]=ph_gf_mul(a0,0x0e)^ph_gf_mul(a1,0x0b)^ph_gf_mul(a2,0x0d)^ph_gf_mul(a3,0x09);
                col[1]=ph_gf_mul(a0,0x09)^ph_gf_mul(a1,0x0e)^ph_gf_mul(a2,0x0b)^ph_gf_mul(a3,0x0d);
                col[2]=ph_gf_mul(a0,0x0d)^ph_gf_mul(a1,0x09)^ph_gf_mul(a2,0x0e)^ph_gf_mul(a3,0x0b);
                col[3]=ph_gf_mul(a0,0x0b)^ph_gf_mul(a1,0x0d)^ph_gf_mul(a2,0x09)^ph_gf_mul(a3,0x0e);
            }
        }
    }
    memcpy(out, s, 16);
}

static int ph_aes256_cbc_dec(const uint8_t *key, const uint8_t *iv,
                              const uint8_t *in, int in_len, uint8_t *out) {
    if (in_len <= 0 || in_len % 16 != 0) return -1;
    PH_AES256 ctx; ph_aes256_expand(&ctx, key);
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (int i = 0; i < in_len; i += 16) {
        ph_aes256_dec_block(&ctx, in + i, out + i);
        for (int j = 0; j < 16; j++) out[i+j] ^= prev[j];
        memcpy(prev, in + i, 16);
    }
    memset(&ctx, 0, sizeof(ctx));
    int pad = out[in_len - 1];
    if (pad < 1 || pad > 16) return -1;
    return in_len - pad;
}

// ════════════════════════════════════════════════════════════════════════════
// Phantom master key — INDEPENDENT from guard.cpp
//
// guard.cpp uses: {D3,4A,7B,91,...} (KEY_HI^KEY_LO)
// phantom uses:   {4E,3D,2C,1B,...} — completely different key material.
//
// Each byte is split across two volatile arrays (HI ^ LO = actual byte)
// so no single MOVZ/MOV instruction ever holds the real key byte.
// amice's MBA pass additionally rewrites the combine arithmetic:
//   key[i] = (a|b)-(a&b)   ≡   a^b   but unrecognisable to IDA/Ghidra.
// ════════════════════════════════════════════════════════════════════════════

// PH_KEY_HI ^ PH_KEY_LO = {4E,3D,2C,1B,0A,F9,E8,D7,C6,B5,A4,93,82,71,60,5F}
static volatile const uint8_t PH_KEY_HI[16] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA
};
static volatile const uint8_t PH_KEY_LO[16] = {
    0xE4,0x97,0x86,0xB1,0xA0,0x53,0x42,0x7D,
    0x6C,0x1F,0x0E,0x39,0x28,0xDB,0xCA,0xF5
};
// PH_K2_HI ^ PH_K2_LO = {AB,9C,8D,7E,6F,50,41,32,23,14,05,F6,E7,D8,C9,BA}
static volatile const uint8_t PH_K2_HI[16] = {
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55
};
static volatile const uint8_t PH_K2_LO[16] = {
    0xFE,0xC9,0xD8,0x2B,0x3A,0x05,0x14,0x67,
    0x76,0x41,0x50,0xA3,0xB2,0x8D,0x9C,0xEF
};
// PH_IV_HI ^ PH_IV_LO = {11,33,55,77,99,BB,DD,FF,22,44,66,88,AA,CC,EE,00}
static volatile const uint8_t PH_IV_HI[16] = {
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};
static volatile const uint8_t PH_IV_LO[16] = {
    0x77,0x55,0x33,0x11,0xFF,0xDD,0xBB,0x99,
    0x44,0x22,0x00,0xEE,0xCC,0xAA,0x88,0x66
};

static __attribute__((noinline)) void ph_build_iv(uint8_t *iv) {
    // MBA: a^b = (a|b)-(a&b) — decompilers see arithmetic, not XOR
    for (int i = 0; i < 16; i++) {
        uint32_t a=(uint32_t)PH_IV_HI[i], b=(uint32_t)PH_IV_LO[i];
        iv[i] = (uint8_t)((a|b)-(a&b));
    }
}

static __attribute__((noinline)) void ph_build_key256(uint8_t *key) {
    for (int i = 0; i < 16; i++) {
        uint32_t a=(uint32_t)PH_KEY_HI[i], b=(uint32_t)PH_KEY_LO[i];
        key[i]    = (uint8_t)((a|b)-(a&b));
    }
    for (int i = 0; i < 16; i++) {
        uint32_t a=(uint32_t)PH_K2_HI[i], b=(uint32_t)PH_K2_LO[i];
        key[16+i] = (uint8_t)((a|b)-(a&b));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Per-string unique key derivation — FNV-1a32 mixing (same as guard.cpp)
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline)) uint32_t ph_ns_pstr_mix(uint32_t idx) {
    uint32_t h = 0x811c9dc5u;
    uint8_t b0=(uint8_t)(idx&0xFF),    b1=(uint8_t)((idx>>8)&0xFF);
    uint8_t b2=(uint8_t)(idx^0x5Au),   b3=(uint8_t)(idx^0xA3u);
    h=((h^(uint32_t)b0)*0x01000193u);
    h=((h^(uint32_t)b1)*0x01000193u);
    h=((h^(uint32_t)b2)*0x01000193u);
    h=((h^(uint32_t)b3)*0x01000193u);
    return h;
}

static __attribute__((noinline)) void ph_build_str_key(uint32_t idx, uint8_t *key) {
    ph_build_key256(key);
    uint32_t mix = ph_ns_pstr_mix(idx);
    for (int i = 0; i < 32; i++) {
        uint8_t m = (uint8_t)((mix >> (8*(i&3))) & 0xFFu);
        uint32_t a=(uint32_t)key[i], b=(uint32_t)m;
        key[i] = (uint8_t)((a|b)-(a&b));   // MBA XOR
        mix = (mix<<7)|(mix>>25);
    }
}

static __attribute__((noinline)) void ph_build_str_iv(uint32_t idx, uint8_t *iv) {
    ph_build_iv(iv);
    uint32_t mix = ph_ns_pstr_mix(idx + 100u);
    for (int i = 0; i < 16; i++) {
        uint8_t m = (uint8_t)((mix >> (8*(i&3))) & 0xFFu);
        uint32_t a=(uint32_t)iv[i], b=(uint32_t)m;
        iv[i] = (uint8_t)((a|b)-(a&b));
        mix = (mix<<7)|(mix>>25);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ph_reveal_ns — decrypt one string blob into buf.
// Annotate +vm_virtualize so the decrypt loop runs inside VMP bytecode.
// buf must be >= ct_len bytes; plaintext is always shorter (PKCS7 stripped).
// ════════════════════════════════════════════════════════════════════════════

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) const char *ph_reveal_ns(
        uint32_t idx, const uint8_t *ct, int ct_len, char *buf) {
    uint8_t key[32], iv[16];
    ph_build_str_key(idx, key);
    ph_build_str_iv(idx, iv);
    int plen = ph_aes256_cbc_dec(key, iv, ct, ct_len, (uint8_t *)buf);
    memset(key, 0, 32); memset(iv, 0, 16);
    if (plen < 0) { buf[0] = '\0'; return buf; }
    const uint8_t _mask = 0x5Au;   // amice MBA hides this literal
    for (int i = 0; i < plen; i++) buf[i] = (char)((uint8_t)buf[i] ^ _mask);
    buf[plen] = '\0';
    return buf;
}

// ════════════════════════════════════════════════════════════════════════════
// Convenience macro — declares stack buffer + decrypts in one line.
// ALWAYS follow with PH_ZERO(var, SP_BUF_SZ) when done.
// ════════════════════════════════════════════════════════════════════════════
#define PH_AES(var, name) \
    char var[SP_BUF_SZ]; \
    ph_reveal_ns(PH_IDX_##name, SP_##name, SP_##name##_LEN, (var))

#endif /* PHANTOM_CIPHER_H */
