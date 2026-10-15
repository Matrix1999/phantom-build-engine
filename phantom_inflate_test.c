#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

static size_t wipe_calls;

static void test_secure_zero(void *memory, size_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    if (!bytes) return;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
    ++wipe_calls;
}

#define PHANTOM_INFLATE_SECURE_ZERO test_secure_zero
#include "phantom_inflate.h"
#undef PHANTOM_INFLATE_SECURE_ZERO

static uint8_t *compress_bytes(
        const uint8_t *input, size_t input_len, size_t *compressed_len) {
    uLongf capacity = compressBound((uLong)input_len);
    uint8_t *compressed = (uint8_t *)malloc((size_t)capacity);
    assert(compressed != NULL);
    int result = compress2(
            compressed, &capacity, input, (uLong)input_len, Z_BEST_COMPRESSION);
    assert(result == Z_OK);
    *compressed_len = (size_t)capacity;
    return compressed;
}

static void test_round_trip(size_t input_len) {
    uint8_t *input = (uint8_t *)malloc(input_len);
    assert(input != NULL);
    for (size_t i = 0; i < input_len; ++i)
        input[i] = (uint8_t)((i * 37u + i / 11u) & 0xffu);

    size_t compressed_len = 0u;
    uint8_t *compressed = compress_bytes(input, input_len, &compressed_len);
    size_t measured = 0u;
    assert(ph_inflate_measure_bounded(
            compressed, compressed_len, input_len, &measured));
    assert(measured == input_len);

    uint8_t *destination = (uint8_t *)malloc(measured);
    assert(destination != NULL);
    memset(destination, 0xa5, measured);
    size_t written = 0u;
    assert(ph_inflate_into_exact(
            compressed, compressed_len, destination, measured, &written));
    assert(written == measured);
    assert(memcmp(destination, input, input_len) == 0);

    size_t allocated_len = 0u;
    uint8_t *allocated = ph_inflate_alloc_bounded(
            compressed, compressed_len, input_len, &allocated_len);
    assert(allocated != NULL);
    assert(allocated_len == input_len);
    assert(memcmp(allocated, input, input_len) == 0);

    if (input_len > 1u) {
        assert(!ph_inflate_measure_bounded(
                compressed, compressed_len, input_len - 1u, &measured));
        assert(measured == 0u);
        uint8_t *too_small = (uint8_t *)malloc(input_len);
        assert(too_small != NULL);
        memset(too_small, 0xa5, input_len);
        assert(!ph_inflate_into_exact(
                compressed, compressed_len, too_small, input_len - 1u, &written));
        assert(written == 0u);
        assert(too_small[input_len - 1u] == 0xa5);
        free(too_small);
    }

    test_secure_zero(allocated, allocated_len);
    free(allocated);
    free(destination);
    free(compressed);
    free(input);
}

static void test_invalid_streams(void) {
    const uint8_t input[] = "bounded inflate rejects malformed streams";
    size_t compressed_len = 0u;
    uint8_t *compressed =
            compress_bytes(input, sizeof(input), &compressed_len);
    size_t output_len = 0u;

    assert(!ph_inflate_measure_bounded(
            compressed, compressed_len - 1u, sizeof(input), &output_len));
    assert(output_len == 0u);
    uint8_t *output = (uint8_t *)malloc(sizeof(input));
    assert(output != NULL);
    assert(!ph_inflate_into_exact(
            compressed, compressed_len - 1u, output, sizeof(input), &output_len));
    assert(output_len == 0u);
    assert(ph_inflate_alloc_bounded(
            compressed, compressed_len - 1u, sizeof(input), &output_len) == NULL);

    uint8_t *trailing = (uint8_t *)malloc(compressed_len + 1u);
    assert(trailing != NULL);
    memcpy(trailing, compressed, compressed_len);
    trailing[compressed_len] = 0x7fu;
    assert(!ph_inflate_measure_bounded(
            trailing, compressed_len + 1u, sizeof(input), &output_len));
    assert(output_len == 0u);
    assert(!ph_inflate_into_exact(
            trailing, compressed_len + 1u, output, sizeof(input), &output_len));
    assert(output_len == 0u);
    assert(ph_inflate_alloc_bounded(
            trailing, compressed_len + 1u, sizeof(input), &output_len) == NULL);

    const uint8_t invalid[] = {0x00, 0x01, 0x02, 0x03};
    assert(!ph_inflate_measure_bounded(
            invalid, sizeof(invalid), sizeof(input), &output_len));
    assert(ph_inflate_alloc_bounded(
            invalid, sizeof(invalid), sizeof(input), &output_len) == NULL);

    free(trailing);
    free(output);
    free(compressed);
}

static void test_expansion_limit(void) {
    const size_t input_len = 1024u * 1024u;
    uint8_t *input = (uint8_t *)calloc(1u, input_len);
    assert(input != NULL);
    size_t compressed_len = 0u;
    uint8_t *compressed = compress_bytes(input, input_len, &compressed_len);
    size_t output_len = 0u;

    assert(!ph_inflate_measure_bounded(
            compressed, compressed_len, 4096u, &output_len));
    assert(output_len == 0u);
    assert(ph_inflate_alloc_bounded(
            compressed, compressed_len, 4096u, &output_len) == NULL);

    uint8_t guarded[4097];
    memset(guarded, 0xa5, sizeof(guarded));
    assert(!ph_inflate_into_exact(
            compressed, compressed_len, guarded, 4096u, &output_len));
    assert(output_len == 0u);
    assert(guarded[4096] == 0xa5);

    free(compressed);
    free(input);
}

int main(void) {
    test_round_trip(112u);
    test_round_trip(4096u);
    test_round_trip(65536u);
    test_invalid_streams();
    test_expansion_limit();
    assert(wipe_calls > 0u);
    puts("Bounded zlib measurement, direct inflate, overflow and cleanup: PASS");
    return 0;
}
