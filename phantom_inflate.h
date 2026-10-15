#ifndef PHANTOM_INFLATE_H
#define PHANTOM_INFLATE_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifndef PHANTOM_INFLATE_SECURE_ZERO
#error "Define PHANTOM_INFLATE_SECURE_ZERO before including this header"
#endif

#if defined(__clang__)
#define PHANTOM_INFLATE_NATIVE \
    __attribute__((noinline, annotate("-vm_virtualize,-vm_flatten")))
#else
#define PHANTOM_INFLATE_NATIVE __attribute__((noinline))
#endif

typedef union {
    max_align_t alignment;
    size_t allocation_size;
} ph_inflate_allocation_header_t;

static PHANTOM_INFLATE_NATIVE voidpf ph_inflate_zalloc(
        voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    if (size != 0u &&
        (size_t)items >
            (SIZE_MAX - sizeof(ph_inflate_allocation_header_t)) / (size_t)size) {
        return Z_NULL;
    }

    size_t payload_size = (size_t)items * (size_t)size;
    if (payload_size == 0u) payload_size = 1u;
    if (payload_size >
        SIZE_MAX - sizeof(ph_inflate_allocation_header_t)) {
        return Z_NULL;
    }

    ph_inflate_allocation_header_t *header =
            (ph_inflate_allocation_header_t *)calloc(
                    1u, sizeof(*header) + payload_size);
    if (!header) return Z_NULL;
    header->allocation_size = payload_size;
    return (voidpf)(header + 1);
}

static PHANTOM_INFLATE_NATIVE void ph_inflate_zfree(
        voidpf opaque, voidpf address) {
    (void)opaque;
    if (!address) return;

    ph_inflate_allocation_header_t *header =
            ((ph_inflate_allocation_header_t *)address) - 1;
    size_t allocation_size = header->allocation_size;
    PHANTOM_INFLATE_SECURE_ZERO(address, allocation_size);
    PHANTOM_INFLATE_SECURE_ZERO(header, sizeof(*header));
    free(header);
}

static PHANTOM_INFLATE_NATIVE int ph_inflate_begin(z_stream *stream) {
    memset(stream, 0, sizeof(*stream));
    stream->zalloc = ph_inflate_zalloc;
    stream->zfree = ph_inflate_zfree;
    stream->opaque = Z_NULL;
    if (inflateInit(stream) != Z_OK) {
        PHANTOM_INFLATE_SECURE_ZERO(stream, sizeof(*stream));
        return 0;
    }
    return 1;
}

static PHANTOM_INFLATE_NATIVE int ph_inflate_end(z_stream *stream) {
    int result = inflateEnd(stream);
    PHANTOM_INFLATE_SECURE_ZERO(stream, sizeof(*stream));
    return result == Z_OK;
}

/*
 * Inflate a stream with an explicit output ceiling. Growth uses allocate-copy-
 * wipe-free rather than realloc, so a moved intermediate allocation is cleared.
 */
static PHANTOM_INFLATE_NATIVE uint8_t *ph_inflate_alloc_bounded(
        const uint8_t *input,
        size_t input_len,
        size_t max_output,
        size_t *output_len) {
    z_stream stream;
    uint8_t *buffer = NULL;
    size_t capacity = 0u;
    size_t produced = 0u;
    uint8_t overflow_probe = 0u;
    int started = 0;
    int success = 0;

    if (!output_len) return NULL;
    *output_len = 0u;
    if (!input || input_len == 0u || max_output == 0u ||
        input_len > (size_t)UINT_MAX || max_output > (size_t)UINT_MAX) {
        return NULL;
    }
    if (!ph_inflate_begin(&stream)) return NULL;
    started = 1;

    capacity = max_output < 4096u ? max_output : 4096u;
    buffer = (uint8_t *)malloc(capacity);
    if (!buffer) goto done;

    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)input_len;
    for (;;) {
        produced = (size_t)stream.total_out;
        if (produced > capacity) goto done;

        if (produced == capacity) {
            if (capacity < max_output) {
                size_t next_capacity =
                        capacity > max_output / 2u ? max_output : capacity * 2u;
                uint8_t *next_buffer = (uint8_t *)malloc(next_capacity);
                if (!next_buffer) goto done;
                memcpy(next_buffer, buffer, produced);
                PHANTOM_INFLATE_SECURE_ZERO(buffer, capacity);
                free(buffer);
                buffer = next_buffer;
                capacity = next_capacity;
                continue;
            }

            uLong before_in = stream.total_in;
            uLong before_out = stream.total_out;
            stream.next_out = &overflow_probe;
            stream.avail_out = 1u;
            int result = inflate(&stream, Z_NO_FLUSH);
            size_t overflow_bytes = 1u - (size_t)stream.avail_out;
            PHANTOM_INFLATE_SECURE_ZERO(&overflow_probe,
                                        sizeof(overflow_probe));
            if (overflow_bytes != 0u) goto done;
            if (result == Z_STREAM_END) {
                success = stream.avail_in == 0u;
                break;
            }
            if (result != Z_OK && result != Z_BUF_ERROR) goto done;
            if (before_in == stream.total_in && before_out == stream.total_out)
                goto done;
            continue;
        }

        stream.next_out = (Bytef *)(buffer + produced);
        stream.avail_out = (uInt)(capacity - produced);
        uLong before_in = stream.total_in;
        uLong before_out = stream.total_out;
        int result = inflate(&stream, Z_NO_FLUSH);
        produced = (size_t)stream.total_out;

        if (result == Z_STREAM_END) {
            success = stream.avail_in == 0u && produced <= max_output;
            break;
        }
        if (result != Z_OK && result != Z_BUF_ERROR) goto done;
        if (produced > capacity) goto done;
        if (before_in == stream.total_in && before_out == stream.total_out)
            goto done;
    }

done:
    if (started && !ph_inflate_end(&stream)) success = 0;
    PHANTOM_INFLATE_SECURE_ZERO(&overflow_probe, sizeof(overflow_probe));
    if (!success) {
        if (buffer) {
            PHANTOM_INFLATE_SECURE_ZERO(buffer, capacity);
            free(buffer);
        }
        return NULL;
    }

    *output_len = produced;
    return buffer;
}

/*
 * Count a bounded stream using only a small scratch buffer. The destination
 * pass can then allocate an exact page-rounded mapping without a full DEX heap
 * buffer. Trailing bytes and incomplete streams are rejected.
 */
static PHANTOM_INFLATE_NATIVE int ph_inflate_measure_bounded(
        const uint8_t *input,
        size_t input_len,
        size_t max_output,
        size_t *output_len) {
    z_stream stream;
    uint8_t scratch[4096] = {0};
    uint8_t overflow_probe = 0u;
    size_t produced_total = 0u;
    int started = 0;
    int success = 0;

    if (!output_len) return 0;
    *output_len = 0u;
    if (!input || input_len == 0u || max_output == 0u ||
        input_len > (size_t)UINT_MAX || max_output > (size_t)UINT_MAX) {
        return 0;
    }
    if (!ph_inflate_begin(&stream)) goto done;
    started = 1;

    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)input_len;
    for (;;) {
        size_t remaining = max_output - produced_total;
        uInt output_capacity = remaining > sizeof(scratch)
                ? (uInt)sizeof(scratch)
                : (uInt)remaining;
        int probing = output_capacity == 0u;
        if (probing) {
            stream.next_out = &overflow_probe;
            stream.avail_out = 1u;
            output_capacity = 1u;
        } else {
            stream.next_out = scratch;
            stream.avail_out = output_capacity;
        }

        uLong before_in = stream.total_in;
        uLong before_out = stream.total_out;
        int result = inflate(&stream, Z_NO_FLUSH);
        size_t produced = (size_t)(output_capacity - stream.avail_out);
        if (probing) {
            PHANTOM_INFLATE_SECURE_ZERO(&overflow_probe,
                                        sizeof(overflow_probe));
            if (produced != 0u) goto done;
        } else {
            produced_total += produced;
            PHANTOM_INFLATE_SECURE_ZERO(scratch, produced);
        }

        if (result == Z_STREAM_END) {
            success = stream.avail_in == 0u &&
                    produced_total <= max_output;
            break;
        }
        if (result != Z_OK && result != Z_BUF_ERROR) goto done;
        if (before_in == stream.total_in && before_out == stream.total_out)
            goto done;
    }

done:
    if (started && !ph_inflate_end(&stream)) success = 0;
    PHANTOM_INFLATE_SECURE_ZERO(scratch, sizeof(scratch));
    PHANTOM_INFLATE_SECURE_ZERO(&overflow_probe, sizeof(overflow_probe));
    if (success) *output_len = produced_total;
    return success;
}

/*
 * Inflate directly into a caller-owned exact-capacity destination. Output
 * overflow is detected through a one-byte stack probe, never by writing past
 * the destination. The caller must wipe the destination after any failure.
 */
static PHANTOM_INFLATE_NATIVE int ph_inflate_into_exact(
        const uint8_t *input,
        size_t input_len,
        uint8_t *output,
        size_t output_capacity,
        size_t *output_len) {
    z_stream stream;
    uint8_t overflow_probe = 0u;
    size_t produced_total = 0u;
    int started = 0;
    int success = 0;

    if (!output_len) return 0;
    *output_len = 0u;
    if (!input || input_len == 0u || !output || output_capacity == 0u ||
        input_len > (size_t)UINT_MAX ||
        output_capacity > (size_t)UINT_MAX) {
        return 0;
    }
    if (!ph_inflate_begin(&stream)) goto done;
    started = 1;

    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)input_len;
    for (;;) {
        size_t remaining = output_capacity - produced_total;
        uInt output_chunk = remaining > (size_t)UINT_MAX
                ? UINT_MAX
                : (uInt)remaining;
        int probing = output_chunk == 0u;
        if (probing) {
            stream.next_out = &overflow_probe;
            stream.avail_out = 1u;
            output_chunk = 1u;
        } else {
            stream.next_out = output + produced_total;
            stream.avail_out = output_chunk;
        }

        uLong before_in = stream.total_in;
        uLong before_out = stream.total_out;
        int result = inflate(&stream, Z_NO_FLUSH);
        size_t produced = (size_t)(output_chunk - stream.avail_out);
        if (probing) {
            PHANTOM_INFLATE_SECURE_ZERO(&overflow_probe,
                                        sizeof(overflow_probe));
            if (produced != 0u) goto done;
        } else {
            produced_total += produced;
        }

        if (result == Z_STREAM_END) {
            success = stream.avail_in == 0u &&
                    produced_total == output_capacity;
            break;
        }
        if (result != Z_OK && result != Z_BUF_ERROR) goto done;
        if (before_in == stream.total_in && before_out == stream.total_out)
            goto done;
    }

done:
    if (started && !ph_inflate_end(&stream)) success = 0;
    PHANTOM_INFLATE_SECURE_ZERO(&overflow_probe, sizeof(overflow_probe));
    if (success) *output_len = produced_total;
    return success;
}

#endif

#undef PHANTOM_INFLATE_NATIVE
