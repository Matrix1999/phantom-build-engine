#!/usr/bin/env python3
"""
encrypt_blob.py — Authenticated wrapper for a compiled libphantom.so.

Blob v3 layout:
  [4-byte magic "PHB3"][16-byte nonce]
  [compress(ARX(compress(ELF)))][32-byte HMAC-SHA256]

The 16-byte ARX key is derived as SHA-256(root || nonce || "stream")[:16].
The HMAC covers magic, nonce, and ciphertext. The universal root is not emitted
verbatim into protected APKs; the stub reconstructs it from two distributed
32-byte shares and wipes it immediately after verification.

Usage:
    python3 docs/encrypt_blob.py <input.so> <output.blob>

Example (after NDK + OLLVM build):
    python3 docs/encrypt_blob.py build-arm64/libphantom.so libphantom_arm64.blob
    python3 docs/encrypt_blob.py build-arm/libphantom.so   libphantom_arm.blob

Then place the blobs in the MAIN APP assets (not stub-loader):
    cp libphantom_arm64.blob src/main/assets/phantom/libphantom_arm64.blob
    cp libphantom_arm.blob   src/main/assets/phantom/libphantom_arm.blob

IMPORTANT: BLOB_ROOT must equal maskedBundleHeader XOR ASSET_KEY_MASK in the
packer/stub. Any change requires regenerating both blobs.
"""

import hashlib
import hmac
import secrets
import sys
import struct
import zlib

BLOB_MAGIC = b"PHB3"
BLOB_NONCE_BYTES = 16
BLOB_TAG_BYTES = 32
BLOB_ROOT = bytes.fromhex(
    "6e2c4fb192a7d03c55f17a8b0ce39d74"
    "2d9817e643b5ca109f26d84ab7c351ee"
)
assert len(BLOB_ROOT) == 32


# ── ARX cipher helpers — must match DexCrypto.exfr() / FxIjsF() / nDnv() ────

def _u32(v):
    return v & 0xFFFFFFFF

def _le32(b, off):
    return struct.unpack_from('<I', b, off)[0]

def _rol32(v, n):
    v = _u32(v)
    return _u32((v << n) | (v >> (32 - n)))

def _expand_key(key: bytes):
    """FxIjsF — expand 16-byte key into 27-word subkey schedule."""
    iArr = [_le32(key, i * 4) for i in range(4)]
    sched = [iArr[0]]
    t = list(iArr[1:])  # [iArr[1], iArr[2], iArr[3]]
    for i2 in range(26):
        t[i2 % 3] = _u32((_u32(_rol32(t[i2 % 3], 24) + sched[-1])) ^ i2)
        sched.append(_u32(_rol32(sched[-1], 3) ^ t[i2 % 3]))
    return sched

def _step(state: list, sched: list):
    """nDnv — advance cipher state by one 8-byte block using the schedule."""
    i, i2 = state
    for k in sched:
        i2 = _u32((_u32(_rol32(i2, 24) + i)) ^ k)
        i  = _u32(_rol32(i, 3) ^ i2)
    state[0] = i
    state[1] = i2

def arx_cipher(data: bytes, key: bytes) -> bytes:
    """Encrypt-or-decrypt data with key (the cipher is its own inverse)."""
    sched  = _expand_key(key)
    state  = [_u32(_le32(key, 0) ^ _le32(key, 8)),
               _u32(_le32(key, 4) ^ _le32(key, 12))]
    out    = bytearray(data)
    pos    = 0
    length = len(out)

    while pos < length:
        if pos % 8 == 0:
            _step(state, sched)
        word     = state[(pos % 8) // 4]
        shift    = (pos % 4) * 8
        out[pos] ^= (word >> shift) & 0xFF
        pos += 1

    return bytes(out)


def _stream_key(nonce: bytes) -> bytes:
    return hashlib.sha256(BLOB_ROOT + nonce + b"stream").digest()[:16]


def encrypt_blob(src_path: str, dst_path: str) -> None:
    """
    Compress the ELF, encrypt it with a nonce-derived ARX stream, and authenticate
    the complete envelope before it reaches the stub loader.
    """
    with open(src_path, 'rb') as f:
        raw = f.read()

    nonce = secrets.token_bytes(BLOB_NONCE_BYTES)
    compressed = zlib.compress(raw, level=9)
    ciphertext = zlib.compress(
        arx_cipher(compressed, _stream_key(nonce)), level=9)
    authenticated = BLOB_MAGIC + nonce + ciphertext
    tag = hmac.new(BLOB_ROOT, authenticated, hashlib.sha256).digest()
    envelope = authenticated + tag

    with open(dst_path, 'wb') as f:
        f.write(envelope)

    print(f"[encrypt_blob] {src_path} ({len(raw):,} B)"
          f"  →  {dst_path} ({len(envelope):,} B authenticated)")


def verify_roundtrip(src_path: str, blob_path: str) -> None:
    """
    Sanity-check: simulate DexCrypto.decrypt() and compare with original bytes.

    Verify the HMAC, derive the nonce-bound stream key, decrypt, and inflate.
    """
    with open(src_path,  'rb') as f: original  = f.read()
    with open(blob_path, 'rb') as f: encrypted = f.read()

    if len(encrypted) < len(BLOB_MAGIC) + BLOB_NONCE_BYTES + BLOB_TAG_BYTES:
        raise ValueError("blob is truncated")
    authenticated, tag = encrypted[:-BLOB_TAG_BYTES], encrypted[-BLOB_TAG_BYTES:]
    expected = hmac.new(BLOB_ROOT, authenticated, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("blob authentication failed")
    if authenticated[:4] != BLOB_MAGIC:
        raise ValueError("unsupported blob version")
    nonce = authenticated[4:4 + BLOB_NONCE_BYTES]
    ciphertext = authenticated[4 + BLOB_NONCE_BYTES:]
    recovered = zlib.decompress(
        arx_cipher(zlib.decompress(ciphertext), _stream_key(nonce)))

    if recovered == original:
        print("[verify] Round-trip OK — blob decrypts to original bytes.")
    else:
        print("[verify] MISMATCH — blob does NOT decrypt to original bytes!", file=sys.stderr)
        sys.exit(1)

    tampered = bytearray(encrypted)
    tampered[len(BLOB_MAGIC) + BLOB_NONCE_BYTES] ^= 0x01
    authenticated, tag = bytes(tampered[:-BLOB_TAG_BYTES]), bytes(tampered[-BLOB_TAG_BYTES:])
    if hmac.compare_digest(tag, hmac.new(BLOB_ROOT, authenticated, hashlib.sha256).digest()):
        print("[verify] TAMPER CHECK FAILED!", file=sys.stderr)
        sys.exit(1)
    print("[verify] Tamper rejection OK.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    src, dst = sys.argv[1], sys.argv[2]
    encrypt_blob(src, dst)
    verify_roundtrip(src, dst)
