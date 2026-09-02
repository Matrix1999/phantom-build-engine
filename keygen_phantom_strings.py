#!/usr/bin/env python3
# keygen_phantom_strings.py
#
# Generates phantom_pstrings.inc — authenticated XChaCha20-Poly1305 + XOR 0x5A
# string envelopes for phantom_key.c.
#
# Per-string unique key: master key mixed with FNV-1a(idx) via MBA XOR.
# Plaintext XOR'd with 0x5A before authenticated encryption.
# Runtime path (in phantom_cipher.h):
#   authenticate → XChaCha20 decrypt → XOR 0x5A → plaintext on stack.
#
# Run:  python3 keygen_phantom_strings.py > phantom_pstrings.inc

# ── Phantom master key (DISTINCT from guard.cpp constants) ────────────────────
MASTER_KEY = bytes([
    0x4E,0x3D,0x2C,0x1B,0x0A,0xF9,0xE8,0xD7,
    0xC6,0xB5,0xA4,0x93,0x82,0x71,0x60,0x5F,
    0xAB,0x9C,0x8D,0x7E,0x6F,0x50,0x41,0x32,
    0x23,0x14,0x05,0xF6,0xE7,0xD8,0xC9,0xBA,
])
NONCE_DOMAIN = bytes([
    0x91,0x2E,0x74,0xC3,0x5A,0x08,0xD9,0x67,
    0x43,0xB1,0x0F,0xE8,0x26,0x5D,0xA4,0x7B,
])
AAD_PREFIX = b'PHANTOM-PSTRI'  # 13 bytes; final four AAD bytes are the index
XOR_MASK = 0x5A

# ── Pure-Python XChaCha20-Poly1305-IETF ──────────────────────────────────────
def _rotl32(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)

def _rounds(state):
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

def _words(data):
    return [int.from_bytes(data[i:i + 4], 'little') for i in range(0, len(data), 4)]

def _hchacha20(key, nonce16):
    state = _words(b'expand 32-byte k' + key + nonce16)
    _rounds(state)
    return b''.join(state[i].to_bytes(4, 'little') for i in (0, 1, 2, 3, 12, 13, 14, 15))

def _chacha20_block(key, counter, nonce12):
    initial = _words(b'expand 32-byte k' + key + counter.to_bytes(4, 'little') + nonce12)
    state = initial.copy()
    _rounds(state)
    return b''.join(((state[i] + initial[i]) & 0xFFFFFFFF).to_bytes(4, 'little')
                    for i in range(16))

def _chacha20_xor(key, nonce12, counter, data):
    out = bytearray(len(data))
    for offset in range(0, len(data), 64):
        stream = _chacha20_block(key, counter, nonce12)
        block = data[offset:offset + 64]
        out[offset:offset + len(block)] = bytes(a ^ b for a, b in zip(block, stream))
        counter += 1
    return bytes(out)

def _poly1305_mac(message, one_time_key):
    r = int.from_bytes(one_time_key[:16], 'little')
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], 'little')
    accumulator = 0
    modulus = (1 << 130) - 5
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        number = int.from_bytes(block + b'\x01', 'little')
        accumulator = ((accumulator + number) * r) % modulus
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, 'little')

def _pad16(data):
    return b'' if len(data) % 16 == 0 else b'\x00' * (16 - len(data) % 16)

def xchacha20poly1305_encrypt(key, nonce24, aad, plaintext):
    subkey = _hchacha20(key, nonce24[:16])
    ietf_nonce = b'\x00\x00\x00\x00' + nonce24[16:]
    poly_key = _chacha20_block(subkey, 0, ietf_nonce)[:32]
    ciphertext = _chacha20_xor(subkey, ietf_nonce, 1, plaintext)
    mac_data = (aad + _pad16(aad) + ciphertext + _pad16(ciphertext) +
                len(aad).to_bytes(8, 'little') +
                len(ciphertext).to_bytes(8, 'little'))
    return ciphertext, _poly1305_mac(mac_data, poly_key)

# ── Per-string key derivation — FNV-1a mixing (MUST match phantom_cipher.h) ──
def _mix(idx):
    h=0x811c9dc5
    for b in [idx&0xFF,(idx>>8)&0xFF,idx^0x5A,idx^0xA3]:
        h=((h^b)*0x01000193)&0xFFFFFFFF
    return h

def _rot32(v,n): return((v<<n)|(v>>(32-n)))&0xFFFFFFFF

def str_key(idx):
    key=bytearray(MASTER_KEY); mix=_mix(idx)
    for i in range(32):
        m=(mix>>(8*(i&3)))&0xFF; a,b=key[i],m
        key[i]=(a|b)-(a&b); mix=_rot32(mix,7)
    return bytes(key)

def str_nonce(idx):
    return (NONCE_DOMAIN + idx.to_bytes(4, 'little') +
            bytes((idx ^ 0x5A, (idx >> 8) ^ 0xA3,
                   (idx >> 16) ^ 0x5A, (idx >> 24) ^ 0xA3)))

def str_aad(idx):
    return AAD_PREFIX + idx.to_bytes(4, 'little')

def enc(idx, s):
    pt=s if isinstance(s,bytes) else s.encode('latin-1')
    masked=bytes([b^XOR_MASK for b in pt])
    nonce = str_nonce(idx)
    ciphertext, tag = xchacha20poly1305_encrypt(
        str_key(idx), nonce, str_aad(idx), masked)
    return nonce + ciphertext + tag

# ── All detection strings (hardcoded plaintext — verified from source) ────────
# Index → (C_name, plaintext)
STRINGS = {
    1:  ('PROC_SELFSTATUS',   '/proc/self/status'),
    2:  ('TRACER_PID',        'TracerPid:'),
    3:  ('PROC_TASK',         '/proc/self/task'),
    4:  ('JDWP',              'jdwp'),
    5:  ('GUM_JS_LOOP',       'gum-js-loop'),
    6:  ('GMAIN',             'gmain'),
    7:  ('FRIDA_WS',          'tyZql/Y8dNFFyopTrHadWzvbvRs='),
    8:  ('FRIDA_WS_REQ',
         'GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
         'Sec-WebSocket-Key: CpxD2C5REVLHvsUC9YAoqg==\r\n'
         'Sec-WebSocket-Version: 13\r\nHost: 127.0.0.1\r\n'
         'User-Agent: Frida/16.1.7\r\n\r\n'),
    9:  ('PROC_FD',           '/proc/self/fd'),
    10: ('LINJECTOR',         'linjector'),
    11: ('PATH_UPROBE_DBG',   '/sys/kernel/debug/tracing/uprobe_events'),
    12: ('PATH_UPROBE',       '/sys/kernel/tracing/uprobe_events'),
    13: ('STR_LIBART',        'libart'),
    14: ('STR_DEX_DUMP',      'dex_dump'),
    15: ('HOOK_RIRU',         'riru'),
    16: ('HOOK_ZYGISK',       'zygisk'),
    17: ('HOOK_XPOSED',       'xposed'),
    18: ('HOOK_LSPD',         'lspd'),
    19: ('HOOK_EDXPOSED',     'edxposed'),
    20: ('HOOK_FRIDA',        'frida'),
    21: ('PROC_MAPS',         '/proc/self/maps'),
    22: ('PATH_PROC_MOUNTS',  '/proc/self/mounts'),
    23: ('STR_MAGISK',        'magisk'),
    24: ('STR_CORE_MIRROR',   'core/mirror'),
    25: ('STR_CORE_IMG',      'core/img'),
    26: ('PATH_SELINUX1',     '/sys/fs/selinux/enforce'),
    27: ('PATH_SELINUX2',     '/sys/kernel/security/selinux/enforce'),
    28: ('PATH_MAGISK',       '/data/adb/magisk'),
    29: ('PATH_KSU',          '/data/adb/ksu'),
    30: ('PATH_APD',          '/data/adb/apd'),
    31: ('PATH_LSPD_DIR',     '/data/adb/lspd'),
    32: ('PATH_MAGISK_SBIN',  '/sbin/.magisk'),
    33: ('PATH_MAGISK_DEV',   '/dev/.magisk'),
    34: ('PATH_XPOSED_PROP',  '/system/xposed.prop'),
    35: ('PATH_BUILD_PROP',   '/system/build.prop'),
    36: ('STR_CAPEFF',        'CapEff:'),
    37: ('STR_TEST_KEYS',     'test-keys'),
    38: ('STR_DEV_KEYS',      'dev-keys'),
    39: ('STR_NAME_FIELD',    'Name:'),
    40: ('PATH_RIRU',         '/data/adb/riru'),
    41: ('PATH_RIRU_MOD',     '/data/adb/modules/riru'),
    42: ('PATH_ZYGISK_MOD',   '/data/adb/modules/zygisk'),
    43: ('PATH_RIRU_MISC',    '/data/misc/riru'),
    44: ('PATH_XPOSED_LIB',   '/system/lib/libxposed_art.so'),
    45: ('PATH_XPOSED_LIB64', '/system/lib64/libxposed_art.so'),
    46: ('PATH_XPOSED_JAR',   '/system/framework/XposedBridge.jar'),
    47: ('PATH_SU_LOCAL',     '/data/local/su'),
    48: ('PATH_SU_LOCAL_BIN', '/data/local/bin/su'),
    49: ('PATH_SU_LOCAL_XBIN','/data/local/xbin/su'),
    50: ('PATH_SU_SBIN',      '/sbin/su'),
    51: ('PATH_SU_SU_BIN',    '/su/bin/su'),
    52: ('PATH_SU_SYS_BIN',   '/system/bin/su'),
    53: ('PATH_SU_SYS_XBIN',  '/system/xbin/su'),
    54: ('PATH_SU_EXT',       '/system/bin/.ext/su'),
    55: ('PATH_SU_FAILSAFE',  '/system/bin/failsafe/su'),
    56: ('PATH_SU_SD',        '/system/sd/xbin/su'),
    57: ('PATH_SU_USR',       '/system/usr/we-need-root/su'),
    58: ('PATH_SU_CACHE',     '/cache/su'),
    59: ('PATH_SU_DATA',      '/data/su'),
    60: ('PATH_SU_DEV',       '/dev/su'),
    61: ('APPNAME',           'PhantomGuard'),
    62: ('PROC_STATUS',       '/proc/self/task/%s/status'),
    63: ('LIBC',              'libc.so'),
    64: ('LIBPHANTOM',        'libphantom.so'),
    65: ('PATH_SU_SYS_XBIN2', '/system/bin/failsafe/su'),  # alias
    66: ('COMM_SUFFIX',       '/comm'),
    67: ('STATUS_SUFFIX',     '/status'),
    68: ('PROC_CMDLINE',      '/proc/self/cmdline'),
    69: ('BLACKDEX_LIB',      'libblackdex.so'),
    70: ('BLACKDEX_D_LIB',    'libblackdex_d.so'),
    71: ('BLACKDEX_HOST',     'top.niunaijun.blackdex'),
    72: ('BLACKBOX_CORE',     'top.niunaijun.blackbox'),
    73: ('PROC_MEM_SUFFIX',     '/mem'),
    74: ('PROC_PAGEMAP_SUFFIX', '/pagemap'),
    75: ('PROC_KCORE_SUFFIX',   '/kcore'),
    76: ('PROC_KMEM_SUFFIX',    '/kmem'),
    77: ('PATH_KPROBE_DBG',     '/sys/kernel/debug/tracing/kprobe_events'),
    78: ('PATH_KPROBE',         '/sys/kernel/tracing/kprobe_events'),
    79: ('JAVA_XPOSED_BRIDGE', 'de.robv.android.xposed.XposedBridge'),
    80: ('JAVA_CNFE',         'java/lang/ClassNotFoundException'),
}

def c_arr(name, data):
    escaped=''.join(f'\\x{b:02x}' for b in data)
    return (f'static const uint8_t SP_{name}[]="{escaped}";\n'
            f'#define SP_{name}_LEN (sizeof(SP_{name}) - 1u)')

def main():
    print('// phantom_pstrings.inc — XChaCha20-Poly1305 + XOR 0x5A protected strings.')
    print('// Generated by keygen_phantom_strings.py — DO NOT EDIT by hand.')
    print('// Re-run if any plaintext changes. Index assignment must match PH_IDX_* below.')
    print('//')
    print('// Decrypt at runtime: ph_reveal_ns(PH_IDX_X, SP_X, SP_X_LEN, buf)')
    print('// or:                 PH_XCHACHA(varname, X); (declares buf + decrypts)')
    print()
    print('// ── Index constants ─────────────────────────────────────────────────────────')
    for idx,(name,_) in sorted(STRINGS.items()):
        print(f'#define PH_IDX_{name} {idx}u')
    print()
    print('// ── XChaCha20-Poly1305 envelopes: nonce || ciphertext || tag ────────────────')
    max_pt = 0
    for idx,(name,pt) in sorted(STRINGS.items()):
        pt_bytes = pt if isinstance(pt,bytes) else pt.encode('latin-1')
        max_pt = max(max_pt, len(pt_bytes))
        ct = enc(idx, pt_bytes)
        print(c_arr(name, ct))
    # Plaintext length equals ciphertext length. Keep a small wipe/safety margin.
    buf_sz = max_pt + 8
    print(f'// Longest plaintext: {max_pt} bytes → SP_BUF_SZ = {buf_sz}')
    print(f'#define SP_BUF_SZ {buf_sz}')

if __name__ == '__main__':
    main()
