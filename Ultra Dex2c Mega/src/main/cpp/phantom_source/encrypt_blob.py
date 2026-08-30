#!/usr/bin/env python3
"""Create and verify the authenticated outer Phantom library envelope.

Blob v4 layout:
    [4-byte magic "PHX4"][4-byte big-endian ELF length][24-byte nonce]
    [XChaCha20 ciphertext of zlib-compressed ELF][16-byte Poly1305 tag]

The 32-byte header is authenticated as associated data.  The runtime key is
not emitted as one static byte array: phantom_bootstrap.c reconstructs it from
fixed-index VM stages.  This host-side copy is only used while producing the
release blob.
"""

import hashlib
import hmac
import secrets
import struct
import sys
import zlib


BLOB_MAGIC = b"PHX4"
BLOB_HEADER_BYTES = 32
BLOB_NONCE_BYTES = 24
BLOB_TAG_BYTES = 16
BLOB_MAX_OUTPUT = 32 * 1024 * 1024
BLOB_KEY = hashlib.sha256(b"phantom-outer-xchacha-v1").digest()


def _u32(value):
    return value & 0xFFFFFFFF


def _rol32(value, shift):
    return _u32((_u32(value) << shift) | (_u32(value) >> (32 - shift)))


def _quarter_round(x, a, b, c, d):
    x[a] = _u32(x[a] + x[b])
    x[d] = _rol32(x[d] ^ x[a], 16)
    x[c] = _u32(x[c] + x[d])
    x[b] = _rol32(x[b] ^ x[c], 12)
    x[a] = _u32(x[a] + x[b])
    x[d] = _rol32(x[d] ^ x[a], 8)
    x[c] = _u32(x[c] + x[d])
    x[b] = _rol32(x[b] ^ x[c], 7)


def _chacha20_block(key, nonce, counter):
    constants = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    state = list(constants)
    state.extend(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state.extend(struct.unpack("<3I", nonce))
    original = state[:]

    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    return struct.pack("<16I", *(_u32(a + b) for a, b in zip(state, original)))


def _chacha20_xor(key, nonce, counter, data):
    result = bytearray(len(data))
    for offset in range(0, len(data), 64):
        stream = _chacha20_block(key, nonce, counter)
        counter += 1
        count = min(64, len(data) - offset)
        for i in range(count):
            result[offset + i] = data[offset + i] ^ stream[i]
    return bytes(result)


def _hchacha20(key, nonce16):
    state = list((0x61707865, 0x3320646E, 0x79622D32, 0x6B206574))
    state.extend(struct.unpack("<8I", key))
    state.extend(struct.unpack("<4I", nonce16))

    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    return struct.pack(
        "<8I", state[0], state[1], state[2], state[3],
        state[12], state[13], state[14], state[15]
    )


def _poly1305_input(aad, ciphertext):
    return (
        aad
        + b"\x00" * ((16 - len(aad) % 16) % 16)
        + ciphertext
        + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )


def _poly1305_mac(one_time_key, data):
    r = int.from_bytes(one_time_key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], "little")
    modulus = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + n) * r) % modulus
    return ((accumulator + s) % (1 << 128)).to_bytes(16, "little")


def _xchacha20_poly1305_encrypt(key, nonce, aad, plaintext):
    subkey = _hchacha20(key, nonce[:16])
    ietf_nonce = b"\x00\x00\x00\x00" + nonce[16:]
    first_block = _chacha20_block(subkey, ietf_nonce, 0)
    ciphertext = _chacha20_xor(subkey, ietf_nonce, 1, plaintext)
    tag = _poly1305_mac(first_block[:32], _poly1305_input(aad, ciphertext))
    return ciphertext + tag


def _xchacha20_poly1305_decrypt(key, nonce, aad, ciphertext_and_tag):
    if len(ciphertext_and_tag) < BLOB_TAG_BYTES:
        raise ValueError("blob ciphertext is truncated")
    ciphertext = ciphertext_and_tag[:-BLOB_TAG_BYTES]
    supplied = ciphertext_and_tag[-BLOB_TAG_BYTES:]
    subkey = _hchacha20(key, nonce[:16])
    ietf_nonce = b"\x00\x00\x00\x00" + nonce[16:]
    first_block = _chacha20_block(subkey, ietf_nonce, 0)
    expected = _poly1305_mac(first_block[:32], _poly1305_input(aad, ciphertext))
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("blob authentication failed")
    return _chacha20_xor(subkey, ietf_nonce, 1, ciphertext)


def encrypt_blob(src_path, dst_path):
    with open(src_path, "rb") as source:
        raw = source.read()
    if not raw or len(raw) > BLOB_MAX_OUTPUT:
        raise ValueError("ELF length is outside the supported range")

    nonce = secrets.token_bytes(BLOB_NONCE_BYTES)
    header = BLOB_MAGIC + struct.pack(">I", len(raw)) + nonce
    compressed = zlib.compress(raw, level=9)
    ciphertext_and_tag = _xchacha20_poly1305_encrypt(
        BLOB_KEY, nonce, header, compressed
    )
    with open(dst_path, "wb") as output:
        output.write(header)
        output.write(ciphertext_and_tag)

    print(
        f"[encrypt_blob] {src_path} ({len(raw):,} B) -> "
        f"{dst_path} ({BLOB_HEADER_BYTES + len(ciphertext_and_tag):,} B XChaCha20-Poly1305)"
    )


def verify_roundtrip(src_path, blob_path):
    with open(src_path, "rb") as source:
        original = source.read()
    with open(blob_path, "rb") as blob_file:
        envelope = blob_file.read()

    if len(envelope) < BLOB_HEADER_BYTES + BLOB_TAG_BYTES:
        raise ValueError("blob is truncated")
    header = envelope[:BLOB_HEADER_BYTES]
    if header[:4] != BLOB_MAGIC:
        raise ValueError("unsupported blob version")
    output_len = struct.unpack(">I", header[4:8])[0]
    nonce = header[8:32]
    compressed = _xchacha20_poly1305_decrypt(
        BLOB_KEY, nonce, header, envelope[BLOB_HEADER_BYTES:]
    )
    recovered = zlib.decompress(compressed)
    if len(recovered) != output_len or recovered != original:
        raise ValueError("blob round-trip mismatch")
    print("[verify] Round-trip OK.")

    tampered = bytearray(envelope)
    tampered[BLOB_HEADER_BYTES] ^= 0x01
    try:
        _xchacha20_poly1305_decrypt(
            BLOB_KEY, nonce, header, bytes(tampered[BLOB_HEADER_BYTES:])
        )
    except ValueError:
        print("[verify] Tamper rejection OK.")
    else:
        raise ValueError("tamper check failed")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} INPUT_SO OUTPUT_BLOB")
        sys.exit(2)
    encrypt_blob(sys.argv[1], sys.argv[2])
    verify_roundtrip(sys.argv[1], sys.argv[2])