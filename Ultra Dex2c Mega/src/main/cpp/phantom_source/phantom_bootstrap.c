// phantom_bootstrap.c -- first-stage loader for the encrypted Phantom library
//
// This library is intentionally separate from libphantom.so.  The latter cannot
// decrypt its own envelope before Android has loaded it.  The bootstrap contains
// only the authenticated outer-blob decrypt/write path and is loaded from an
// asset by the Java stub.

#include <jni.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include "phantom_chacha20poly1305.h"

#define PH_BLOB_MAGIC_BYTES 4u
#define PH_BLOB_HEADER_BYTES 32u
#define PH_BLOB_NONCE_BYTES 24u
#define PH_BLOB_TAG_BYTES 16u
#define PH_BLOB_MAX_OUTPUT (32u * 1024u * 1024u)

typedef struct {
    uint32_t word[8];
} ph_blob_key_state_t;

static __attribute__((noinline)) void ph_bootstrap_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    if (!p) return;
    while (len--) *p++ = 0;
    __asm__ volatile("" : : "r"(ptr) : "memory");
}

/*
 * K_blob = SHA-256("phantom-outer-xchacha-v1"), represented only as
 * independently encoded words.  The plaintext key is never stored as one
 * static array in this source or in the bootstrap's read-only data.
 */
#define PH_DEFINE_BLOB_STAGE(N, ENCODED)                                      \
    __attribute__((annotate("+vm_virtualize")))                              \
    static __attribute__((noinline)) void stage_blob_word##N##_vm(            \
            ph_blob_key_state_t *s) {                                         \
        const uint32_t i = (N);                                               \
        uint32_t v = (ENCODED);                                               \
        const uint32_t mix = 0xA5A5A5A5u ^ (i * 0x9E3779B9u);                \
        const uint32_t rot = (i % 5u) + 3u;                                  \
        const uint32_t add = 0x31415927u + (i * 0x01020304u);                \
        v ^= mix;                                                             \
        v = (v >> rot) | (v << (32u - rot));                                \
        s->word[i] = v - add;                                                 \
    }

PH_DEFINE_BLOB_STAGE(0, 0x8f56c7c2u)
PH_DEFINE_BLOB_STAGE(1, 0x76eeb17bu)
PH_DEFINE_BLOB_STAGE(2, 0x5de8395cu)
PH_DEFINE_BLOB_STAGE(3, 0x4ba2d4a7u)
PH_DEFINE_BLOB_STAGE(4, 0x1a7a754du)
PH_DEFINE_BLOB_STAGE(5, 0x9d775414u)
PH_DEFINE_BLOB_STAGE(6, 0xd3327f62u)
PH_DEFINE_BLOB_STAGE(7, 0x1d36bfd5u)
#undef PH_DEFINE_BLOB_STAGE

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_blob_group0_vm(
        ph_blob_key_state_t *s) {
    stage_blob_word0_vm(s);
    stage_blob_word1_vm(s);
    stage_blob_word2_vm(s);
    stage_blob_word3_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_blob_group1_vm(
        ph_blob_key_state_t *s) {
    stage_blob_word4_vm(s);
    stage_blob_word5_vm(s);
    stage_blob_word6_vm(s);
    stage_blob_word7_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_blob_key_vm(uint8_t key[32]) {
    ph_blob_key_state_t state = {{0}};
    stage_blob_group0_vm(&state);
    stage_blob_group1_vm(&state);
    for (uint32_t i = 0; i < 8u; ++i) {
        key[i * 4u] = (uint8_t)state.word[i];
        key[i * 4u + 1u] = (uint8_t)(state.word[i] >> 8);
        key[i * 4u + 2u] = (uint8_t)(state.word[i] >> 16);
        key[i * 4u + 3u] = (uint8_t)(state.word[i] >> 24);
    }
    ph_bootstrap_zero(&state, sizeof(state));
}

/*
 * Header format:
 *   [4-byte "PHX4"][4-byte big-endian ELF length][24-byte nonce]
 *   [XChaCha20 ciphertext of zlib-compressed ELF][16-byte Poly1305 tag]
 *
 * The 32-byte header is authenticated as AAD, binding the version and output
 * length to the ciphertext.  The key reconstruction and decrypt call are
 * isolated from file I/O so the sensitive path remains small for Amice.
 */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int stage_blob_decrypt_vm(
        const uint8_t *blob, size_t blob_len, uint8_t *compressed) {
    uint8_t key[32] = {0};
    const size_t ciphertext_len =
            blob_len - PH_BLOB_HEADER_BYTES - PH_BLOB_TAG_BYTES;
    const uint8_t *ciphertext = blob + PH_BLOB_HEADER_BYTES;
    const uint8_t *tag = blob + PH_BLOB_HEADER_BYTES + ciphertext_len;
    int ok;

    stage_blob_key_vm(key);
    ok = ph_xchacha20poly1305_decrypt(
            key, blob + PH_BLOB_MAGIC_BYTES, blob, PH_BLOB_HEADER_BYTES,
            ciphertext, ciphertext_len, tag, compressed);
    ph_bootstrap_zero(key, sizeof(key));
    return ok;
}

static uint32_t ph_bootstrap_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static int ph_bootstrap_write_all(int fd, const uint8_t *data, size_t len) {
    while (len) {
        ssize_t n = write(fd, data, len);
        if (n <= 0) return 0;
        data += (size_t)n;
        len -= (size_t)n;
    }
    return 1;
}

static int ph_bootstrap_decrypt_to_file(
        const uint8_t *blob, size_t blob_len, const char *output_path) {
    uint32_t output_len;
    size_t ciphertext_len;
    uint8_t *compressed = NULL;
    uint8_t *plain = NULL;
    uLongf decompressed_len;
    int fd = -1;
    int ok = 0;

    if (!blob || !output_path || blob_len < PH_BLOB_HEADER_BYTES + PH_BLOB_TAG_BYTES) {
        return 0;
    }
    if (memcmp(blob, "PHX4", PH_BLOB_MAGIC_BYTES) != 0) return 0;

    output_len = ph_bootstrap_be32(blob + PH_BLOB_MAGIC_BYTES);
    if (output_len == 0 || output_len > PH_BLOB_MAX_OUTPUT) return 0;
    ciphertext_len = blob_len - PH_BLOB_HEADER_BYTES - PH_BLOB_TAG_BYTES;
    if (ciphertext_len == 0) return 0;

    compressed = (uint8_t *)malloc(ciphertext_len);
    plain = (uint8_t *)malloc(output_len);
    if (!compressed || !plain) goto cleanup;

    if (!stage_blob_decrypt_vm(blob, blob_len, compressed)) goto cleanup;

    decompressed_len = (uLongf)output_len;
    if (uncompress(plain, &decompressed_len, compressed,
                   (uLong)ciphertext_len) != Z_OK ||
            decompressed_len != (uLongf)output_len) {
        goto cleanup;
    }

    fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (fd < 0) goto cleanup;
    if (!ph_bootstrap_write_all(fd, plain, output_len)) goto cleanup;
    if (fchmod(fd, 0500) != 0) goto cleanup;
    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    ok = 1;

cleanup:
    if (fd >= 0) close(fd);
    if (!ok) unlink(output_path);
    if (compressed) {
        ph_bootstrap_zero(compressed, ciphertext_len);
        free(compressed);
    }
    if (plain) {
        ph_bootstrap_zero(plain, output_len);
        free(plain);
    }
    return ok;
}

JNIEXPORT jboolean JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptBlob(
        JNIEnv *env, jclass clazz, jbyteArray blob_array, jstring output_path) {
    jbyte *blob = NULL;
    const char *path = NULL;
    jsize blob_len;
    int ok;

    (void)clazz;
    if (!env || !blob_array || !output_path) return JNI_FALSE;
    blob_len = (*env)->GetArrayLength(env, blob_array);
    if (blob_len <= 0) return JNI_FALSE;

    blob = (*env)->GetByteArrayElements(env, blob_array, NULL);
    path = (*env)->GetStringUTFChars(env, output_path, NULL);
    if (!blob || !path) {
        if (blob) (*env)->ReleaseByteArrayElements(env, blob_array, blob, JNI_ABORT);
        if (path) (*env)->ReleaseStringUTFChars(env, output_path, path);
        return JNI_FALSE;
    }

    ok = ph_bootstrap_decrypt_to_file(
            (const uint8_t *)blob, (size_t)blob_len, path);
    (*env)->ReleaseByteArrayElements(env, blob_array, blob, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, output_path, path);
    return ok ? JNI_TRUE : JNI_FALSE;
}