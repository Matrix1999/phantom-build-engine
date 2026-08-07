#!/usr/bin/env python3
"""
encrypt_blob.py — Encrypt a compiled libphantom.so into a .blob file.

The stub-loader's DexCrypto.loadPhantomLib() decrypts each blob using the same
ARX stream cipher and zlib pipeline as DexCrypto.decrypt() / DexCrypto.encrypt().

Java cipher pipeline (DexCrypto.encrypt):
  - DeflaterInputStream  wraps the input  → reads give COMPRESSED plaintext
  - exfr XORs compressed plaintext with keystream
  - DeflaterOutputStream wraps the output → COMPRESSES the XORed bytes again
  Final layout on disk: compress(XOR(compress(plaintext)))

Python must match:
  step1 = zlib.compress(plaintext)        # inner compress (DeflaterInputStream)
  step2 = arx_cipher(step1, key)          # XOR keystream (exfr)
  output = zlib.compress(step2)           # outer compress (DeflaterOutputStream)

Usage:
    python3 docs/encrypt_blob.py <input.so> <output.blob>

Example (after NDK + OLLVM build):
    python3 docs/encrypt_blob.py build-arm64/libphantom.so libphantom_arm64.blob
    python3 docs/encrypt_blob.py build-arm/libphantom.so   libphantom_arm.blob

Then place the blobs in the MAIN APP assets (not stub-loader):
    cp libphantom_arm64.blob src/main/assets/phantom/libphantom_arm64.blob
    cp libphantom_arm.blob   src/main/assets/phantom/libphantom_arm.blob

IMPORTANT: The BLOB_KEY here must match DexCrypto.blobKey() exactly.
If you change the key in DexCrypto.blobKey(), update BLOB_KEY below and re-encrypt
all existing blobs.
"""

import sys
import struct
import zlib

# Must match DexCrypto.blobKey() in the stub-loader exactly (16 bytes, ASCII).
BLOB_KEY = b"Ph4nt0mBl0bK3y!!"
assert len(BLOB_KEY) == 16, "blob key must be exactly 16 bytes"


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


def encrypt_blob(src_path: str, dst_path: str) -> None:
    """
    Produce a blob that DexCrypto.decrypt() can recover.

    Java decrypt pipeline (InflaterInputStream → exfr → InflaterOutputStream):
      1. InflaterInputStream reads from blob → decompresses outer layer
      2. exfr XORs the decompressed bytes with keystream
      3. InflaterOutputStream decompresses the XORed result → plaintext

    So the blob on disk must be: compress(XOR(compress(plaintext)))
    """
    with open(src_path, 'rb') as f:
        raw = f.read()

    inner_compressed = zlib.compress(raw, level=9)       # step 1 — DeflaterInputStream side
    xored            = arx_cipher(inner_compressed, BLOB_KEY)  # step 2 — XOR keystream
    outer_compressed = zlib.compress(xored, level=9)     # step 3 — DeflaterOutputStream side

    with open(dst_path, 'wb') as f:
        f.write(outer_compressed)

    print(f"[encrypt_blob] {src_path} ({len(raw):,} B)"
          f"  →  {dst_path} ({len(outer_compressed):,} B encrypted)")


def verify_roundtrip(src_path: str, blob_path: str) -> None:
    """
    Sanity-check: simulate DexCrypto.decrypt() and compare with original bytes.

    Mirrors InflaterInputStream → exfr → InflaterOutputStream:
      1. Decompress outer layer   (InflaterInputStream)
      2. XOR with keystream       (exfr — cipher is self-inverse)
      3. Decompress inner layer   (InflaterOutputStream)
    """
    with open(src_path,  'rb') as f: original  = f.read()
    with open(blob_path, 'rb') as f: encrypted = f.read()

    step1     = zlib.decompress(encrypted)        # undo outer compress
    step2     = arx_cipher(step1, BLOB_KEY)       # undo XOR
    recovered = zlib.decompress(step2)            # undo inner compress

    if recovered == original:
        print("[verify] Round-trip OK — blob decrypts to original bytes.")
    else:
        print("[verify] MISMATCH — blob does NOT decrypt to original bytes!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    src, dst = sys.argv[1], sys.argv[2]
    encrypt_blob(src, dst)
    verify_roundtrip(src, dst)
