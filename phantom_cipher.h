// phantom_cipher.h — XChaCha20-Poly1305 string protection for phantom_key.c
//
// Uses an INDEPENDENT phantom-specific master key and AAD domain so the
// Phantom and Guard .so files share no key material or payload contract.
//
// Two-tier protection (matches guard.cpp):
//   • Envelope in .rodata   — nonce, ciphertext, and authentication tag only
//   • Key derived at runtime — ph_build_key256() uses split volatile arrays
//     so no single MOVZ/MOV instruction holds the full key byte; amice's MBA
//     pass hides the combine arithmetic further
//   • Per-string unique key  — FNV-1a(idx) mixes the master key
//   • Per-string unique nonce — embedded in each authenticated envelope
//   • AAD binds the Phantom string domain and index
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
//   PH_XCHACHA(path, PROC_SELFSTATUS); // declares char path[SP_BUF_SZ], decrypts
//   // ... use path ...
//   PH_ZERO(path, SP_BUF_SZ);
//
// IMPORTANT: always PH_ZERO the buffer when done — the plaintext must not
// linger on the stack after the detection call returns.

#ifndef PHANTOM_CIPHER_H
#define PHANTOM_CIPHER_H

#include <stdint.h>
#include <string.h>
#include "phantom_chacha20poly1305.h"

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

// ════════════════════════════════════════════════════════════════════════════
// ph_reveal_ns — authenticate and decrypt one string envelope into buf.
// Annotate +vm_virtualize so the decrypt loop runs inside VMP bytecode.
// Envelope: [24-byte nonce][ciphertext][16-byte Poly1305 tag].
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline, noreturn)) void ph_pstring_auth_fail(void) {
    __builtin_trap();
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) const char *ph_reveal_ns(
        uint32_t idx, const uint8_t *envelope, int envelope_len, char *buf) {
    static const uint8_t aad_prefix[] = "PHANTOM-PSTRI";
    uint8_t key[32], aad[(sizeof(aad_prefix) - 1u) + 4u];
    int ciphertext_len;
    int authentic = 0;

    if (!envelope || !buf || envelope_len < 40) {
        if (buf) buf[0] = '\0';
        ph_pstring_auth_fail();
    }

    ciphertext_len = envelope_len - 40;
    ph_build_str_key(idx, key);
    memcpy(aad, aad_prefix, sizeof(aad_prefix) - 1u);
    aad[sizeof(aad_prefix) - 1u] = (uint8_t)idx;
    aad[sizeof(aad_prefix)] = (uint8_t)(idx >> 8);
    aad[sizeof(aad_prefix) + 1u] = (uint8_t)(idx >> 16);
    aad[sizeof(aad_prefix) + 2u] = (uint8_t)(idx >> 24);
    authentic = ph_xchacha20poly1305_decrypt(
            key, envelope, aad, sizeof(aad),
            envelope + 24, (size_t)ciphertext_len,
            envelope + 24 + ciphertext_len, (uint8_t *)buf);
    memset(key, 0, sizeof(key));
    memset(aad, 0, sizeof(aad));
    if (!authentic) {
        memset(buf, 0, (size_t)ciphertext_len);
        ph_pstring_auth_fail();
    }
    const uint8_t _mask = 0x5Au;   // amice MBA hides this literal
    for (int i = 0; i < ciphertext_len; i++) {
        buf[i] = (char)((uint8_t)buf[i] ^ _mask);
    }
    buf[ciphertext_len] = '\0';
    return buf;
}

// ════════════════════════════════════════════════════════════════════════════
// Convenience macro — declares stack buffer + decrypts in one line.
// ALWAYS follow with PH_ZERO(var, SP_BUF_SZ) when done.
// ════════════════════════════════════════════════════════════════════════════
#define PH_XCHACHA(var, name) \
    char var[SP_BUF_SZ]; \
    ph_reveal_ns(PH_IDX_##name, SP_##name, SP_##name##_LEN, (var))

#endif /* PHANTOM_CIPHER_H */
