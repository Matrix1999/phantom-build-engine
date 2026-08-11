# encoding=utf-8
"""
vm_encryptor.py — AES-256-CBC split-key encryption for lvm_method_exec programs.

Produces the same KHI/KLO/IHI/ILO split-key format used by guard.cpp's
existing lvm_exec programs so both share the same interpreter infrastructure.

AES backend priority:
  1. pycryptodome  (Crypto.Cipher.AES)
  2. cryptography  (cryptography.hazmat)
  3. OpenSSL subprocess  (openssl enc -aes-256-cbc)
  4. Pure-Python AES-256-CBC (built-in, no dependencies)
"""
import os
import struct
import subprocess
import tempfile

# ── Try fast native AES libraries first ───────────────────────────────────
_AES_BACKEND = None

try:
    from Crypto.Cipher import AES as _AES_CRYPTO
    _AES_BACKEND = 'pycryptodome'
except ImportError:
    pass

if _AES_BACKEND is None:
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher as _Cipher, algorithms as _algorithms, modes as _modes)
        from cryptography.hazmat.backends import default_backend as _default_backend
        _AES_BACKEND = 'cryptography'
    except ImportError:
        pass

# ── Pure-Python AES-256-CBC fallback (RFC 3602) ───────────────────────────
# Only used when neither pycryptodome nor cryptography is available.
# Tested against OpenSSL reference vectors.

def _pure_aes_key_schedule(key: bytes):
    """Expand 256-bit key into 15×4-word round-key array."""
    Nk, Nr = 8, 14
    SBOX = (
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    )
    RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36)

    def sub_word(w):
        return (SBOX[(w>>24)&0xff]<<24)|(SBOX[(w>>16)&0xff]<<16)|(SBOX[(w>>8)&0xff]<<8)|SBOX[w&0xff]
    def rot_word(w):
        return ((w<<8)|(w>>24))&0xFFFFFFFF

    W = []
    for i in range(Nk):
        W.append(struct.unpack('>I', key[4*i:4*i+4])[0])
    for i in range(Nk, 4*(Nr+1)):
        temp = W[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ (RCON[i//Nk-1] << 24)
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        W.append(W[i-Nk] ^ temp)
    # Pack into round keys: list of 15 × (4 ints)
    return [W[i*4:(i+1)*4] for i in range(Nr+1)]


def _pure_aes_encrypt_block(state_bytes: bytes, round_keys) -> bytes:
    """AES-256 encrypt a single 16-byte block."""
    SBOX = (
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    )
    MUL2 = bytes(((x<<1)^(0x1b if x&0x80 else 0))&0xFF for x in range(256))
    MUL3 = bytes(MUL2[x]^x for x in range(256))

    def xor_rk(s, rk):
        ws = [struct.unpack('>I',bytes(s[4*i:4*i+4]))[0] for i in range(4)]
        return bytearray(struct.pack('>IIII',ws[0]^rk[0],ws[1]^rk[1],ws[2]^rk[2],ws[3]^rk[3]))

    def sub_bytes(s):
        return bytearray(SBOX[b] for b in s)

    def shift_rows(s):
        return bytearray([s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],
                          s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]])

    def mix_col(a,b,c,d):
        return (MUL2[a]^MUL3[b]^c^d,
                a^MUL2[b]^MUL3[c]^d,
                a^b^MUL2[c]^MUL3[d],
                MUL3[a]^b^c^MUL2[d])

    def mix_columns(s):
        r = bytearray(16)
        for i in range(4):
            col = s[i],s[i+4],s[i+8],s[i+12]
            mc  = mix_col(*col)
            r[i],r[i+4],r[i+8],r[i+12] = mc
        return r

    Nr = 14
    s = xor_rk(bytearray(state_bytes), round_keys[0])
    for rnd in range(1, Nr):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = xor_rk(s, round_keys[rnd])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = xor_rk(s, round_keys[Nr])
    return bytes(s)


def _pure_aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Pure-Python AES-256-CBC encrypt with PKCS#7 padding."""
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad] * pad)
    rk = _pure_aes_key_schedule(key)
    prev = bytearray(iv)
    out  = bytearray()
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc   = _pure_aes_encrypt_block(block, rk)
        out.extend(enc)
        prev = bytearray(enc)
    return bytes(out)


def _aes_cbc_encrypt_openssl(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC encrypt via openssl subprocess. PKCS#7 padding applied here."""
    import tempfile, subprocess, os
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(padded)
        fname = f.name
    try:
        r = subprocess.run(
            ['openssl', 'enc', '-aes-256-cbc',
             '-K', key.hex(), '-iv', iv.hex(),
             '-nosalt', '-nopad', '-in', fname],
            capture_output=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError('openssl enc failed: ' + r.stderr.decode())
        return r.stdout
    finally:
        os.unlink(fname)


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC encrypt. Uses the best available backend."""
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    if _AES_BACKEND == 'pycryptodome':
        cipher = _AES_CRYPTO.new(key, _AES_CRYPTO.MODE_CBC, iv)
        return cipher.encrypt(padded)

    if _AES_BACKEND == 'cryptography':
        cipher = _Cipher(_algorithms.AES(key), _modes.CBC(iv), backend=_default_backend())
        enc = cipher.encryptor()
        return enc.update(padded) + enc.finalize()

    # OpenSSL subprocess fallback (reliable, no Python deps required)
    return _aes_cbc_encrypt_openssl(key, iv, plaintext)


def _xor_checksum(data: bytes) -> int:
    """XOR of all plaintext bytes — matches guard.cpp integrity check."""
    cs = 0
    for b in data:
        cs ^= b
    return cs & 0xFF


class VmEncryptor:
    """
    Encrypt a VM bytecode program with a unique random AES-256-CBC split key.

    The split-key scheme (KHI^KLO = actual key, IHI^ILO = actual IV) matches
    exactly what guard.cpp's lvm_exec programs use, so lvm_method_exec can use
    the same decryption logic.
    """

    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt plaintext and return a dict:
          khi, klo : 32-byte split halves for the key
          ihi, ilo : 16-byte split halves for the IV
          enc      : ciphertext bytes
          cs       : XOR checksum of plaintext (uint8)
        """
        khi = os.urandom(32)
        klo = os.urandom(32)
        ihi = os.urandom(16)
        ilo = os.urandom(16)

        key = bytes(a ^ b for a, b in zip(khi, klo))
        iv  = bytes(a ^ b for a, b in zip(ihi, ilo))

        enc = _aes_cbc_encrypt(key, iv, plaintext)
        cs  = _xor_checksum(plaintext)

        return {
            'khi': khi, 'klo': klo,
            'ihi': ihi, 'ilo': ilo,
            'enc': enc,
            'cs':  cs,
        }

    @staticmethod
    def to_c_array(data: bytes, name: str) -> str:
        """Format bytes as a C static volatile uint8_t array declaration."""
        hex_bytes = ','.join('0x%02x' % b for b in data)
        return 'static volatile const uint8_t %s[] = {%s};\n' % (name, hex_bytes)

    def generate_c_blobs(self, plaintext: bytes, sym_prefix: str) -> tuple:
        """
        Encrypt plaintext and return (c_declarations: str, cs: int, enc_len: int).

        c_declarations includes:
          - KHI/KLO/IHI/ILO/ENC array definitions
          - #define SYM_LEN  N
          - #define SYM_CS   0xXXu
        """
        d = self.encrypt(plaintext)
        lines = []
        lines.append(self.to_c_array(d['khi'], '%s_KHI' % sym_prefix))
        lines.append(self.to_c_array(d['klo'], '%s_KLO' % sym_prefix))
        lines.append(self.to_c_array(d['ihi'], '%s_IHI' % sym_prefix))
        lines.append(self.to_c_array(d['ilo'], '%s_ILO' % sym_prefix))
        lines.append(self.to_c_array(d['enc'], '%s_ENC' % sym_prefix))
        lines.append('#define %s_LEN %d\n' % (sym_prefix, len(d['enc'])))
        lines.append('#define %s_CS  0x%02xu\n' % (sym_prefix, d['cs']))
        return ''.join(lines), d['cs'], len(d['enc'])
