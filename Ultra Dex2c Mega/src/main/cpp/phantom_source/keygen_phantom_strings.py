#!/usr/bin/env python3
# keygen_phantom_strings.py
#
# Generates phantom_pstrings.inc — AES-256-CBC + XOR 0x5A protected string
# blobs for phantom_key.c, matching the guard.cpp / guard_pstrings.inc pattern.
#
# Per-string unique key: master key mixed with FNV-1a(idx) via MBA XOR.
# Plaintext XOR'd with 0x5A before PKCS7 + AES-256-CBC encryption.
# Runtime path (in phantom_cipher.h):
#   AES-CBC-dec → strip PKCS7 → XOR 0x5A → plaintext on stack.
#
# Run:  python3 keygen_phantom_strings.py > phantom_pstrings.inc

# ── Phantom master key (DISTINCT from guard.cpp constants) ────────────────────
MASTER_KEY = bytes([
    0x4E,0x3D,0x2C,0x1B,0x0A,0xF9,0xE8,0xD7,
    0xC6,0xB5,0xA4,0x93,0x82,0x71,0x60,0x5F,
    0xAB,0x9C,0x8D,0x7E,0x6F,0x50,0x41,0x32,
    0x23,0x14,0x05,0xF6,0xE7,0xD8,0xC9,0xBA,
])
MASTER_IV = bytes([
    0x11,0x33,0x55,0x77,0x99,0xBB,0xDD,0xFF,
    0x22,0x44,0x66,0x88,0xAA,0xCC,0xEE,0x00,
])
XOR_MASK = 0x5A

# ── Pure-Python AES-256-CBC (same S-box as guard.cpp / FIPS 197) ──────────────
SBOX = [
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
]
RCON = [0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(x): return ((x<<1)^0x1b)&0xFF if(x&0x80) else(x<<1)&0xFF

def _expand(key):
    w = list(key)
    for i in range(8, 60):
        t = w[(i-1)*4:(i-1)*4+4]
        if i%8==0:
            t=[SBOX[t[1]]^RCON[i//8],SBOX[t[2]],SBOX[t[3]],SBOX[t[0]]]
        elif i%8==4:
            t=[SBOX[b] for b in t]
        src=w[(i-8)*4:(i-8)*4+4]
        w+=[src[j]^t[j] for j in range(4)]
    return bytes(w)

def _enc_block(rk, block):
    s=bytearray(block)
    for i in range(16): s[i]^=rk[i]
    for r in range(1,15):
        for i in range(16): s[i]=SBOX[s[i]]
        s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1]
        s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6]
        s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]
        if r<14:
            for c in range(4):
                col=s[c*4:c*4+4]; a0,a1,a2,a3=col
                s[c*4+0]=_xtime(a0)^_xtime(a1)^a1^a2^a3
                s[c*4+1]=a0^_xtime(a1)^_xtime(a2)^a2^a3
                s[c*4+2]=a0^a1^_xtime(a2)^_xtime(a3)^a3
                s[c*4+3]=_xtime(a0)^a0^a1^a2^_xtime(a3)
        off=r*16
        for i in range(16): s[i]^=rk[off+i]
    return bytes(s)

def aes256_cbc_enc(key, iv, pt):
    rk=_expand(key)
    pad=16-(len(pt)%16); pt=pt+bytes([pad]*pad)
    ct=b''; prev=bytearray(iv)
    for i in range(0,len(pt),16):
        block=bytes(a^b for a,b in zip(pt[i:i+16],prev))
        enc=_enc_block(rk,block); ct+=enc; prev=bytearray(enc)
    return ct

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

def str_iv(idx):
    iv=bytearray(MASTER_IV); mix=_mix(idx+100)
    for i in range(16):
        m=(mix>>(8*(i&3)))&0xFF; a,b=iv[i],m
        iv[i]=(a|b)-(a&b); mix=_rot32(mix,7)
    return bytes(iv)

def enc(idx, s):
    pt=s if isinstance(s,bytes) else s.encode('latin-1')
    masked=bytes([b^XOR_MASK for b in pt])
    return aes256_cbc_enc(str_key(idx),str_iv(idx),masked)

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
}

def c_arr(name, data):
    vals=','.join(f'0x{b:02x}' for b in data)
    return (f'static const uint8_t SP_{name}[]={{{vals}}};\n'
            f'#define SP_{name}_LEN {len(data)}')

def main():
    print('// phantom_pstrings.inc — AES-256-CBC + XOR 0x5A protected detection strings.')
    print('// Generated by keygen_phantom_strings.py — DO NOT EDIT by hand.')
    print('// Re-run if any plaintext changes. Index assignment must match PH_IDX_* below.')
    print('//')
    print('// Decrypt at runtime: ph_reveal_ns(PH_IDX_X, SP_X, SP_X_LEN, buf)')
    print('// or:                 PH_AES(varname, X);   (declares buf + decrypts)')
    print()
    print('// ── Index constants ─────────────────────────────────────────────────────────')
    for idx,(name,_) in sorted(STRINGS.items()):
        print(f'#define PH_IDX_{name} {idx}u')
    print()
    print('// ── AES-256-CBC ciphertext blobs ────────────────────────────────────────────')
    max_pt = 0
    for idx,(name,pt) in sorted(STRINGS.items()):
        pt_bytes = pt if isinstance(pt,bytes) else pt.encode('latin-1')
        max_pt = max(max_pt, len(pt_bytes))
        ct = enc(idx, pt_bytes)
        preview = pt_bytes[:60].decode('latin-1').replace('\r', '\\r').replace('\n', '\\n')
        if len(pt_bytes) > 60: preview += '...'
        print(f'// "{preview}" idx={idx}')
        print(c_arr(name, ct))
        print()
    # SP_BUF_SZ: round max plaintext up to next 16-byte boundary, add 8 for NUL + safety
    buf_sz = ((max_pt + 16) & ~15) + 8
    print(f'// Longest plaintext: {max_pt} bytes → SP_BUF_SZ = {buf_sz}')
    print(f'#define SP_BUF_SZ {buf_sz}')

if __name__ == '__main__':
    main()
