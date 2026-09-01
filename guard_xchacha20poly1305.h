#pragma once

/*
 * Guard-specific XChaCha20-Poly1305 envelope support.
 *
 * The implementation is compiled with Guard-only symbol names even though the
 * primitive code is shared with the already audited, self-contained Phantom
 * implementation.  Guard and Phantom therefore do not share runtime symbols
 * or key domains.
 *
 * Envelope:
 *   [24-byte nonce][ciphertext][16-byte Poly1305 tag]
 *
 * AAD:
 *   "D2CG", version 1, domain, flags 0, object id (LE32), plaintext length
 */

#define ph_chacha_load32_le gd_chacha_load32_le
#define ph_chacha_store32_le gd_chacha_store32_le
#define ph_chacha_qr gd_chacha_qr
#define ph_hchacha20 gd_hchacha20
#define ph_chacha_block gd_chacha_block
#define ph_chacha_xor gd_chacha_xor
#define ph_poly1305_state_t gd_poly1305_state_t
#define ph_poly1305_init gd_poly1305_init
#define ph_poly1305_blocks gd_poly1305_blocks
#define ph_poly1305_update gd_poly1305_update
#define ph_poly1305_finish gd_poly1305_finish
#define ph_poly1305_pad16 gd_poly1305_pad16
#define ph_chacha_store64_le gd_chacha_store64_le
#define ph_chacha_ct_equal gd_chacha_ct_equal
#define ph_chacha20poly1305_decrypt gd_chacha20poly1305_decrypt
#define ph_xchacha20poly1305_decrypt gd_xchacha20poly1305_decrypt
#if defined(__has_include)
#  if __has_include("../phantom_source/phantom_chacha20poly1305.h")
#    include "../phantom_source/phantom_chacha20poly1305.h"
#  elif __has_include("phantom_chacha20poly1305.h")
#    include "phantom_chacha20poly1305.h"
#  else
#    error "Guard XChaCha20-Poly1305 primitive header is missing"
#  endif
#else
#  include "../phantom_source/phantom_chacha20poly1305.h"
#endif
#undef ph_chacha_load32_le
#undef ph_chacha_store32_le
#undef ph_chacha_qr
#undef ph_hchacha20
#undef ph_chacha_block
#undef ph_chacha_xor
#undef ph_poly1305_state_t
#undef ph_poly1305_init
#undef ph_poly1305_blocks
#undef ph_poly1305_update
#undef ph_poly1305_finish
#undef ph_poly1305_pad16
#undef ph_chacha_store64_le
#undef ph_chacha_ct_equal
#undef ph_chacha20poly1305_decrypt
#undef ph_xchacha20poly1305_decrypt

#define GD_XCHACHA_NONCE_BYTES 24u
#define GD_XCHACHA_TAG_BYTES 16u
#define GD_XCHACHA_OVERHEAD 40u
#define GD_GUARD_AAD_BYTES 16u

static inline void gd_guard_store32_le(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static inline void gd_guard_build_aad(uint8_t aad[GD_GUARD_AAD_BYTES],
                                      uint8_t domain,
                                      uint32_t object_id,
                                      uint32_t plaintext_len) {
    aad[0] = 'D'; aad[1] = '2'; aad[2] = 'C'; aad[3] = 'G';
    aad[4] = 1u;
    aad[5] = domain;
    aad[6] = 0u; aad[7] = 0u;
    gd_guard_store32_le(aad + 8, object_id);
    gd_guard_store32_le(aad + 12, plaintext_len);
}

/*
 * Authenticates before exposing plaintext.  On failure, plaintext is wiped
 * when a non-null output buffer and capacity are supplied.
 */
static __attribute__((noinline)) int gd_guard_decrypt_envelope(
        const uint8_t key[32],
        uint8_t domain,
        uint32_t object_id,
        const uint8_t *envelope,
        size_t envelope_len,
        uint8_t *plaintext,
        size_t plaintext_capacity) {
    uint8_t aad[GD_GUARD_AAD_BYTES];
    size_t ciphertext_len;
    int authentic;

    if (!key || !envelope || envelope_len < GD_XCHACHA_OVERHEAD) return 0;
    ciphertext_len = envelope_len - GD_XCHACHA_OVERHEAD;
    if (ciphertext_len > plaintext_capacity ||
            (ciphertext_len && !plaintext)) return 0;

    gd_guard_build_aad(aad, domain, object_id, (uint32_t)ciphertext_len);
    authentic = gd_xchacha20poly1305_decrypt(
            key,
            envelope,
            aad,
            sizeof(aad),
            envelope + GD_XCHACHA_NONCE_BYTES,
            ciphertext_len,
            envelope + GD_XCHACHA_NONCE_BYTES + ciphertext_len,
            plaintext);
    if (!authentic && plaintext && plaintext_capacity) {
        memset(plaintext, 0, plaintext_capacity);
    }
    memset(aad, 0, sizeof(aad));
    return authentic;
}