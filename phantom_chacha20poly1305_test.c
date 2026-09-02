#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "phantom_chacha20poly1305.h"

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int value;
        if (sscanf(hex + i * 2, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return hex[out_len * 2] == '\0';
}

static void print_hex(const char *label, const uint8_t *data, size_t length) {
    fputs(label, stderr);
    for (size_t i = 0; i < length; ++i) fprintf(stderr, "%02x", data[i]);
    fputc('\n', stderr);
}

static void compute_tag(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t tag[16]) {
    uint8_t first_block[64], poly_key[32], lengths[16] = {0};
    ph_poly1305_state_t poly;
    ph_chacha_block(key, 0, nonce, first_block);
    memcpy(poly_key, first_block, sizeof(poly_key));
    ph_poly1305_init(&poly, poly_key);
    ph_poly1305_update(&poly, aad, aad_len);
    ph_poly1305_pad16(&poly, aad_len);
    ph_poly1305_update(&poly, ciphertext, ciphertext_len);
    ph_poly1305_pad16(&poly, ciphertext_len);
    ph_chacha_store64_le(lengths, aad_len);
    ph_chacha_store64_le(lengths + 8, ciphertext_len);
    ph_poly1305_update(&poly, lengths, sizeof(lengths));
    ph_poly1305_finish(&poly, tag);
}

int main(void) {
    static const char h_key_hex[] =
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f";
    static const char h_nonce_hex[] = "000000090000004a0000000031415927";
    static const char h_expected_hex[] =
            "82413b4227b27bfed30e42508a877d73"
            "a0f9e4d58a74a853c12ec41326d3ecdc";
    static const char x_nonce_hex[] =
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            "b0b1b2b3b4b5b6b7";
    static const char x_aad_hex[] = "00000007";
    static const char x_ciphertext_hex[] =
            "35846b73c332c981190c45e81258c2ed"
            "51cbe94d8768abad7436eeca8ecd8a53"
            "a3e8da";
    static const char x_tag_hex[] = "817cebc1462a2debe99f1b71380c6f0f";
    static const uint8_t x_expected[] =
            "phantom-xchacha-java-native-interop";
    static const char key_hex[] =
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f";
    static const char nonce_hex[] = "070000004041424344454647";
    static const char aad_hex[] = "50515253c0c1c2c3c4c5c6c7";
    static const char ciphertext_hex[] =
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116";
    static const char tag_hex[] = "1ae10b594f09e26a7e902ecbd0600691";
    static const uint8_t expected[] =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one "
            "tip for the future, sunscreen would be it.";

    uint8_t h_key[32], h_nonce[16], h_expected[32], h_actual[32];
    uint8_t x_nonce[24], x_aad[4], x_ciphertext[35], x_tag[16], x_plaintext[35];
    uint8_t key[32], nonce[12], aad[12], ciphertext[114], tag[16], plaintext[114];
    uint8_t bad_tag[16];
    if (!hex_to_bytes(h_key_hex, h_key, sizeof(h_key)) ||
            !hex_to_bytes(h_nonce_hex, h_nonce, sizeof(h_nonce)) ||
            !hex_to_bytes(h_expected_hex, h_expected, sizeof(h_expected))) {
        fprintf(stderr, "HChaCha20 vector parsing failed\n");
        return 1;
    }
    ph_hchacha20(h_key, h_nonce, h_actual);
    if (memcmp(h_actual, h_expected, sizeof(h_actual)) != 0) {
        print_hex("expected: ", h_expected, sizeof(h_expected));
        print_hex("actual:   ", h_actual, sizeof(h_actual));
        fprintf(stderr, "HChaCha20 draft vector mismatch\n");
        return 1;
    }
    if (!hex_to_bytes(x_nonce_hex, x_nonce, sizeof(x_nonce)) ||
            !hex_to_bytes(x_aad_hex, x_aad, sizeof(x_aad)) ||
            !hex_to_bytes(x_ciphertext_hex, x_ciphertext, sizeof(x_ciphertext)) ||
            !hex_to_bytes(x_tag_hex, x_tag, sizeof(x_tag))) {
        fprintf(stderr, "XChaCha20-Poly1305 vector parsing failed\n");
        return 1;
    }
    if (!ph_xchacha20poly1305_decrypt(
            h_key, x_nonce, x_aad, sizeof(x_aad),
            x_ciphertext, sizeof(x_ciphertext), x_tag, x_plaintext)) {
        fprintf(stderr, "Java-generated XChaCha20-Poly1305 vector rejected\n");
        return 1;
    }
    if (memcmp(x_plaintext, x_expected, sizeof(x_plaintext)) != 0) {
        fprintf(stderr, "XChaCha20-Poly1305 plaintext mismatch\n");
        return 1;
    }
    if (!hex_to_bytes(key_hex, key, sizeof(key)) ||
            !hex_to_bytes(nonce_hex, nonce, sizeof(nonce)) ||
            !hex_to_bytes(aad_hex, aad, sizeof(aad)) ||
            !hex_to_bytes(ciphertext_hex, ciphertext, sizeof(ciphertext)) ||
            !hex_to_bytes(tag_hex, tag, sizeof(tag))) {
        fprintf(stderr, "vector parsing failed\n");
        return 1;
    }

    if (!ph_chacha20poly1305_decrypt(
            key, nonce, aad, sizeof(aad), ciphertext, sizeof(ciphertext),
            tag, plaintext)) {
        uint8_t calculated[16];
        compute_tag(key, nonce, aad, sizeof(aad), ciphertext, sizeof(ciphertext), calculated);
        print_hex("expected: ", tag, sizeof(tag));
        print_hex("actual:   ", calculated, sizeof(calculated));
        fprintf(stderr, "valid RFC 8439 tag rejected\n");
        return 1;
    }
    if (memcmp(plaintext, expected, sizeof(plaintext)) != 0) {
        fprintf(stderr, "RFC 8439 plaintext mismatch\n");
        return 1;
    }

    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[0] ^= 1;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (ph_chacha20poly1305_decrypt(
            key, nonce, aad, sizeof(aad), ciphertext, sizeof(ciphertext),
            bad_tag, plaintext)) {
        fprintf(stderr, "modified tag accepted\n");
        return 1;
    }
    for (size_t i = 0; i < sizeof(plaintext); ++i) {
        if (plaintext[i] != 0xa5) {
            fprintf(stderr, "plaintext written before authentication\n");
            return 1;
        }
    }

    puts("HChaCha20 draft vector: OK");
    puts("XChaCha20-Poly1305 Java/native vector: OK");
    puts("ChaCha20-Poly1305 RFC 8439 vector: OK");
    return 0;
}