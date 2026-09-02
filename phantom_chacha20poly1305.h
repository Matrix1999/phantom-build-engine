#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Portable ChaCha20/XChaCha20-Poly1305-IETF decryptor.
 *
 * This is deliberately self-contained so the runtime does not depend on
 * Android's private BoringSSL symbols or on the API-level-specific Java
 * ChaCha20 provider.  The envelope format is:
 *
 *   ChaCha20:  [12-byte nonce][ciphertext][16-byte Poly1305 tag]
 *   XChaCha20: [24-byte nonce][ciphertext][16-byte Poly1305 tag]
 *
 * XChaCha20-Poly1305 is used for the outer DEX envelope and Phantom's
 * authenticated native-string envelopes. The native-only DEX loading, key
 * reconstruction, anti-dumper checks, and wipe paths are unchanged.
 */

static uint32_t ph_chacha_load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void ph_chacha_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static __attribute__((always_inline)) inline void
ph_chacha_qr(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = (x[d] ^ x[a]); x[d] = (x[d] << 16) | (x[d] >> 16);
    x[c] += x[d]; x[b] = (x[b] ^ x[c]); x[b] = (x[b] << 12) | (x[b] >> 20);
    x[a] += x[b]; x[d] = (x[d] ^ x[a]); x[d] = (x[d] << 8)  | (x[d] >> 24);
    x[c] += x[d]; x[b] = (x[b] ^ x[c]); x[b] = (x[b] << 7)  | (x[b] >> 25);
}

/*
 * HChaCha20 subkey derivation from the XChaCha construction.
 *
 * always_inline is deliberate: when called from a +vm_virtualize function the
 * universal root key and intermediate state remain in that function's VM
 * bytecode instead of crossing a normal native call boundary.
 */
static __attribute__((always_inline)) inline void
ph_hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]) {
    uint32_t x[16];
    int i;

    x[0] = 0x61707865u;
    x[1] = 0x3320646eu;
    x[2] = 0x79622d32u;
    x[3] = 0x6b206574u;
    for (i = 0; i < 8; ++i) x[4 + i] = ph_chacha_load32_le(key + i * 4);
    for (i = 0; i < 4; ++i) x[12 + i] = ph_chacha_load32_le(nonce + i * 4);

    for (i = 0; i < 10; ++i) {
        ph_chacha_qr(x, 0, 4, 8, 12);
        ph_chacha_qr(x, 1, 5, 9, 13);
        ph_chacha_qr(x, 2, 6, 10, 14);
        ph_chacha_qr(x, 3, 7, 11, 15);
        ph_chacha_qr(x, 0, 5, 10, 15);
        ph_chacha_qr(x, 1, 6, 11, 12);
        ph_chacha_qr(x, 2, 7, 8, 13);
        ph_chacha_qr(x, 3, 4, 9, 14);
    }

    ph_chacha_store32_le(out + 0,  x[0]);
    ph_chacha_store32_le(out + 4,  x[1]);
    ph_chacha_store32_le(out + 8,  x[2]);
    ph_chacha_store32_le(out + 12, x[3]);
    ph_chacha_store32_le(out + 16, x[12]);
    ph_chacha_store32_le(out + 20, x[13]);
    ph_chacha_store32_le(out + 24, x[14]);
    ph_chacha_store32_le(out + 28, x[15]);
    memset(x, 0, sizeof(x));
}

static void ph_chacha_block(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12], uint8_t out[64]) {
    static const uint32_t constants[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t x[16];
    uint32_t original[16];
    int i;

    x[0] = constants[0];
    x[1] = constants[1];
    x[2] = constants[2];
    x[3] = constants[3];
    for (i = 0; i < 8; ++i) x[4 + i] = ph_chacha_load32_le(key + i * 4);
    x[12] = counter;
    x[13] = ph_chacha_load32_le(nonce);
    x[14] = ph_chacha_load32_le(nonce + 4);
    x[15] = ph_chacha_load32_le(nonce + 8);
    memcpy(original, x, sizeof(x));

    for (i = 0; i < 10; ++i) {
        ph_chacha_qr(x, 0, 4, 8, 12);
        ph_chacha_qr(x, 1, 5, 9, 13);
        ph_chacha_qr(x, 2, 6, 10, 14);
        ph_chacha_qr(x, 3, 7, 11, 15);
        ph_chacha_qr(x, 0, 5, 10, 15);
        ph_chacha_qr(x, 1, 6, 11, 12);
        ph_chacha_qr(x, 2, 7, 8, 13);
        ph_chacha_qr(x, 3, 4, 9, 14);
    }

    for (i = 0; i < 16; ++i) ph_chacha_store32_le(out + i * 4, x[i] + original[i]);
    memset(x, 0, sizeof(x));
    memset(original, 0, sizeof(original));
}

static void ph_chacha_xor(const uint8_t key[32], const uint8_t nonce[12],
                          uint32_t counter, const uint8_t *in, size_t len,
                          uint8_t *out) {
    uint8_t stream[64];
    size_t offset = 0;
    while (offset < len) {
        size_t block = len - offset;
        if (block > sizeof(stream)) block = sizeof(stream);
        ph_chacha_block(key, counter++, nonce, stream);
        for (size_t i = 0; i < block; ++i) out[offset + i] = in[offset + i] ^ stream[i];
        offset += block;
    }
    memset(stream, 0, sizeof(stream));
}

typedef struct {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t pad0, pad1, pad2, pad3;
    uint8_t buffer[16];
    size_t leftover;
} ph_poly1305_state_t;

static void ph_poly1305_blocks(ph_poly1305_state_t *st, const uint8_t *m,
                               size_t bytes, uint32_t hibit) {
    const uint32_t r0 = st->r0, r1 = st->r1, r2 = st->r2;
    const uint32_t r3 = st->r3, r4 = st->r4;
    const uint32_t s1 = st->s1, s2 = st->s2, s3 = st->s3, s4 = st->s4;
    uint32_t h0 = st->h0, h1 = st->h1, h2 = st->h2;
    uint32_t h3 = st->h3, h4 = st->h4;

    while (bytes >= 16) {
        uint32_t t0 = ph_chacha_load32_le(m + 0);
        uint32_t t1 = ph_chacha_load32_le(m + 4);
        uint32_t t2 = ph_chacha_load32_le(m + 8);
        uint32_t t3 = ph_chacha_load32_le(m + 12);
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += t0 & 0x3ffffffu;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffu;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffu;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffu;
        h4 += (t3 >> 8) | hibit;

        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) +
             ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) +
             ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) +
             ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) +
             ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) +
             ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffu; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffu; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffu; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffu; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffu;
        h0 += c * 5u;
        c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h0 = h0; st->h1 = h1; st->h2 = h2; st->h3 = h3; st->h4 = h4;
}

static void ph_poly1305_init(ph_poly1305_state_t *st, const uint8_t key[32]) {
    uint32_t t0 = ph_chacha_load32_le(key + 0);
    uint32_t t1 = ph_chacha_load32_le(key + 4);
    uint32_t t2 = ph_chacha_load32_le(key + 8);
    uint32_t t3 = ph_chacha_load32_le(key + 12);

    memset(st, 0, sizeof(*st));
    st->r0 = t0 & 0x3ffffffu;
    st->r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    st->r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    st->r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    st->r4 = (t3 >> 8) & 0x00fffffu;
    st->s1 = st->r1 * 5u;
    st->s2 = st->r2 * 5u;
    st->s3 = st->r3 * 5u;
    st->s4 = st->r4 * 5u;
    st->pad0 = ph_chacha_load32_le(key + 16);
    st->pad1 = ph_chacha_load32_le(key + 20);
    st->pad2 = ph_chacha_load32_le(key + 24);
    st->pad3 = ph_chacha_load32_le(key + 28);
}

static void ph_poly1305_update(ph_poly1305_state_t *st, const uint8_t *m, size_t bytes) {
    size_t want;
    if (bytes == 0) return;

    if (st->leftover) {
        want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16) return;
        ph_poly1305_blocks(st, st->buffer, 16, 1u << 24);
        st->leftover = 0;
    }

    if (bytes >= 16) {
        size_t full = bytes & ~(size_t)15;
        ph_poly1305_blocks(st, m, full, 1u << 24);
        m += full;
        bytes -= full;
    }
    if (bytes) {
        memcpy(st->buffer, m, bytes);
        st->leftover = bytes;
    }
}

static void ph_poly1305_finish(ph_poly1305_state_t *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4;
    uint32_t g0, g1, g2, g3, g4, mask;
    uint32_t c;
    uint32_t w0, w1, w2, w3;
    uint64_t f;

    if (st->leftover) {
        st->buffer[st->leftover] = 1;
        for (size_t i = st->leftover + 1; i < 16; ++i) st->buffer[i] = 0;
        ph_poly1305_blocks(st, st->buffer, 16, 0);
    }

    h0 = st->h0; h1 = st->h1; h2 = st->h2; h3 = st->h3; h4 = st->h4;
    c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

    g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3ffffffu;
    g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffu;
    g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffu;
    g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffu;
    g4 = h4 + c - (1u << 26);
    mask = (g4 >> 31) - 1u;
    g0 = (g0 & mask) | (h0 & ~mask);
    g1 = (g1 & mask) | (h1 & ~mask);
    g2 = (g2 & mask) | (h2 & ~mask);
    g3 = (g3 & mask) | (h3 & ~mask);
    g4 = (g4 & mask) | (h4 & ~mask);

    w0 = g0 | (g1 << 26);
    w1 = (g1 >> 6) | (g2 << 20);
    w2 = (g2 >> 12) | (g3 << 14);
    w3 = (g3 >> 18) | (g4 << 8);

    f = (uint64_t)w0 + st->pad0;
    ph_chacha_store32_le(mac + 0, (uint32_t)f);
    f = (uint64_t)w1 + st->pad1 + (f >> 32);
    ph_chacha_store32_le(mac + 4, (uint32_t)f);
    f = (uint64_t)w2 + st->pad2 + (f >> 32);
    ph_chacha_store32_le(mac + 8, (uint32_t)f);
    f = (uint64_t)w3 + st->pad3 + (f >> 32);
    ph_chacha_store32_le(mac + 12, (uint32_t)f);

    memset(st, 0, sizeof(*st));
}

static void ph_poly1305_pad16(ph_poly1305_state_t *st, size_t len) {
    static const uint8_t zeros[16] = {0};
    size_t rem = len & 15u;
    if (rem) ph_poly1305_update(st, zeros, 16u - rem);
}

static void ph_chacha_store64_le(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out[i] = (uint8_t)v;
        v >>= 8;
    }
}

static int ph_chacha_ct_equal(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static __attribute__((noinline)) int ph_chacha20poly1305_decrypt(
        const uint8_t key[32],
        const uint8_t nonce[12],
        const uint8_t *aad,
        size_t aad_len,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        const uint8_t tag[16],
        uint8_t *plaintext) {
    uint8_t first_block[64];
    uint8_t poly_key[32];
    uint8_t expected[16];
    uint8_t lengths[16];
    ph_poly1305_state_t poly;
    int authentic;

    if (!key || !nonce || !tag || (!ciphertext && ciphertext_len) ||
            (!plaintext && ciphertext_len)) return 0;

    ph_chacha_block(key, 0, nonce, first_block);
    memcpy(poly_key, first_block, sizeof(poly_key));
    ph_poly1305_init(&poly, poly_key);
    ph_poly1305_update(&poly, aad, aad_len);
    ph_poly1305_pad16(&poly, aad_len);
    ph_poly1305_update(&poly, ciphertext, ciphertext_len);
    ph_poly1305_pad16(&poly, ciphertext_len);
    memset(lengths, 0, sizeof(lengths));
    ph_chacha_store64_le(lengths, (uint64_t)aad_len);
    ph_chacha_store64_le(lengths + 8, (uint64_t)ciphertext_len);
    ph_poly1305_update(&poly, lengths, sizeof(lengths));
    ph_poly1305_finish(&poly, expected);

    authentic = ph_chacha_ct_equal(expected, tag);
    if (authentic) ph_chacha_xor(key, nonce, 1, ciphertext, ciphertext_len, plaintext);

    memset(first_block, 0, sizeof(first_block));
    memset(poly_key, 0, sizeof(poly_key));
    memset(expected, 0, sizeof(expected));
    memset(lengths, 0, sizeof(lengths));
    return authentic;
}

static __attribute__((noinline)) int ph_xchacha20poly1305_decrypt(
        const uint8_t key[32],
        const uint8_t nonce[24],
        const uint8_t *aad,
        size_t aad_len,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        const uint8_t tag[16],
        uint8_t *plaintext) {
    uint8_t subkey[32];
    uint8_t ietf_nonce[12] = {0};
    int authentic;

    if (!key || !nonce) return 0;
    ph_hchacha20(key, nonce, subkey);
    memcpy(ietf_nonce + 4, nonce + 16, 8);
    authentic = ph_chacha20poly1305_decrypt(
            subkey, ietf_nonce, aad, aad_len,
            ciphertext, ciphertext_len, tag, plaintext);
    memset(subkey, 0, sizeof(subkey));
    memset(ietf_nonce, 0, sizeof(ietf_nonce));
    return authentic;
}