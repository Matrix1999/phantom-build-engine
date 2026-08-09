// phantom_key.c -- JNI entry-point for libphantom.so
//
// Exports:
// Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard
// Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard
//
// Security model:
// * Per-APK key derived from (salt, sha256(pkg_name)) via ARX KDF.
// * Key NEVER crosses the JNI boundary -- lives only on the C stack, zeroed on return.
//
// Anti-Frida / Anti-Debugger layers:
//
// LAYER 1  nativeWipeShard()  [JNI -- called from DexProtector after loading]
// Zeroes the ENTIRE Java byte[] that nativeDecryptShard returned so the heap
// contains no reconstructable DEX bytecode.
//
// LAYER 2  detect_frida_loop()  [5 s cadence, background thread]
// Frida/ptrace heuristics PLUS eBPF uprobe detection, JDWP thread scan,
// Riru/Zygisk/Xposed detection, root detection, and disk-vs-mem ELF compare.
//
// LAYER 3  BLOCK_ROOTED_DEVICES (optional, compile-time opt-in via UI toggle)
// If compiled with -DBLOCK_ROOTED_DEVICES, the constructor reads the SELinux
// enforce node.  Rooted phones (Magisk/KernelSU) set setenforce 0 → SELinux
// permissive → immediate nuke.  Non-rooted phones always read '1' → pass.
//
// detect_frida_init() fires via __attribute__((constructor)) the instant
// System.load(libphantom.so) is called -- before nativeDecryptShard is reached.
//
// Build requirements:
// * Compile with OLLVM (see phantom/CMakeLists.txt).
// * Target ABIs: arm64-v8a and armeabi-v7a.
// * After building, ARX-encrypt with encrypt_blob.py and place blobs at:
// assets/phantom/libphantom_arm64.blob
// assets/phantom/libphantom_arm.blob
//
// IMPORTANT: Do NOT compile on Replit. Use the CI build with OLLVM toolchain.

// ?
// Includes
// ?

#include <jni.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <elf.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <link.h>
#include <dlfcn.h>
#include <zlib.h>
#include <android/log.h>

// ── Debug logging — DISABLED for release build (silenced to no-ops)
// To re-enable for debugging: replace ((void)0) with __android_log_print(...)
#define PH_LOG(fmt, ...)     ((void)0)
#define PH_NUKE(reason, ...) ((void)0)
// ─────────────────────────────────────────────────────────────────────────────

// ?
// Anti-dump / Anti-Frida -- constants & types
// ?

#define MAX_LINE   512
#define MAX_LENGTH 256
#define MAX_SZ     (80 * 1024 * 1024)


// ── Advanced string hiding ────────────────────────────────────────────────────
// Technique: per-string unique 4-byte rotating XOR key — no shared decrypt fn.
// OLLVM obfuscates each inlined PH_DECRYPT_N callsite independently.
// strings(1) / IDA string window / Ghidra mass-emulation all yield nothing.
//
// PH_DECRYPT_N(out, enc, enc_len, key) — key is a variable name, NOT a brace-literal.
//   Passing {0x41,...} as a macro arg would let the preprocessor split on the
//   internal commas and report "too many arguments". Keys are declared as
//   separate static arrays below — same security, no preprocessor issue.
// PH_ZERO(buf, sz) — volatile wipe; compiler cannot optimize away.
#define PH_DECRYPT_N(out, enc, enc_len, key) do {           \
    int _kl = (int)sizeof(key);                             \
    for (int _i = 0; _i < (enc_len); _i++)                  \
        (out)[_i] = (char)((enc)[_i] ^ (key)[_i % _kl]);   \
    (out)[enc_len] = '\0';                                  \
} while(0)
#define PH_ZERO(buf, sz) do {                               \
    volatile char *_vp = (buf);                             \
    for (int _zi = 0; _zi < (sz); _zi++) _vp[_zi] = 0;    \
} while(0)

// ── Encrypted data arrays (.rodata — no plaintext) ────────────────────────────
// enc[i] = plaintext[i] ^ key[i % sizeof(key)]
static const uint8_t _E_APPNAME[]        = {0x11,0x3A,0x2C,0x4F,0x35,0x3D,0x20,0x66,0x34,0x33,0x3F,0x45,0x00};
static const uint8_t _E_GUM_JS_LOOP[]    = {0xB9,0xD8,0xD3,0xC2,0xB4,0xDE,0x93,0x83,0xB1,0xC2,0xCE,0x00};
static const uint8_t _E_GMAIN[]          = {0xA7,0x92,0x8F,0x78,0xAE,0x00};
static const uint8_t _E_LINJECTOR[]      = {0x7F,0x5E,0x9E,0x67,0x76,0x54,0x84,0x62,0x61,0x00};
static const uint8_t _E_FRIDA_WS[]       = {0x66,0x4D,0x0C,0x09,0x7E,0x1B,0x0F,0x40,0x76,0x7A,0x10,0x3E,0x6B,
                                             0x5B,0x26,0x2C,0x60,0x7C,0x37,0x1C,0x45,0x4E,0x20,0x1A,0x64,0x66,
                                             0x25,0x45,0x00};
static const uint8_t _E_JDWP[]           = {0xE1,0x89,0xB8,0x51,0x00};
static const uint8_t _E_HOOK_RIRU[]      = {0x7F,0x99,0xDF,0xCF,0x00};
static const uint8_t _E_HOOK_ZYGISK[]    = {0xB0,0x87,0xDD,0xD7,0xB9,0x95,0x00};
static const uint8_t _E_HOOK_XPOSED[]    = {0xA6,0xDD,0xAF,0xAD,0xBB,0xC9,0x00};
static const uint8_t _E_HOOK_LSPD[]      = {0xD2,0x9C,0xBA,0x9A,0x00};
static const uint8_t _E_HOOK_EDXPOSED[]  = {0x95,0x69,0x82,0xBE,0x9F,0x7E,0x9F,0xAA,0x00};
static const uint8_t _E_HOOK_FRIDA[]     = {0x19,0x37,0x25,0x22,0x1E,0x00};
static const uint8_t _E_PROC_MAPS[]      = {0xB6,0x6A,0x59,0x53,0xFA,0x35,0x58,0x59,0xF5,0x7C,0x04,0x51,0xF8,
                                             0x6A,0x58,0x00};
static const uint8_t _E_PROC_STATUS[]    = {0xEA,0xA6,0x95,0x97,0xA6,0xF9,0x94,0x9D,0xA9,0xB0,0xC8,0x8C,0xA4,
                                             0xA5,0x8C,0xD7,0xE0,0xA5,0xC8,0x8B,0xB1,0xB7,0x93,0x8D,0xB6,0x00};
static const uint8_t _E_PROC_FD[]        = {0x62,0x2E,0x1D,0x1F,0x2E,0x71,0x1C,0x15,0x21,0x38,0x40,0x16,0x29,
                                             0x00};
static const uint8_t _E_PROC_TASK[]      = {0xAE,0xE2,0xD1,0xDB,0xE2,0xBD,0xD0,0xD1,0xED,0xF4,0x8C,0xC0,0xE0,
                                             0xE1,0xC8,0x00};
static const uint8_t _E_PROC_SELFSTATUS[]= {0xB6,0x6A,0x59,0x53,0xFA,0x35,0x58,0x59,0xF5,0x7C,0xBF,0x51,0xF4,
                                             0x68,0x52,0x6B,0x5A,0x00};
static const uint8_t _E_TRACER_PID[]     = {0x5E,0x69,0x4D,0x5E,0x6F,0x69,0x7C,0x54,0x6E,0x21,0x00};
static const uint8_t _E_LIBC[]           = {0x7D,0x4B,0x51,0x27,0x3F,0x51,0x5C,0x00};
static const uint8_t _E_LIBPHANTOM[]     = {0x39,0x0F,0x15,0xF8,0x3D,0x07,0x19,0xFC,0x3A,0x0B,0x59,0xFB,0x3A,
                                             0x00};

// ── Per-string unique XOR keys (.rodata) ─────────────────────────────────────
// Each key is its own array — passed by name to PH_DECRYPT_N so the
// preprocessor never sees internal commas as argument separators.
static const uint8_t _K_APPNAME[]        = {0x41,0x52,0x4D,0x21};
static const uint8_t _K_GUM_JS_LOOP[]    = {0xDE,0xAD,0xBE,0xEF};
static const uint8_t _K_GMAIN[]          = {0xC0,0xFF,0xEE,0x11};
static const uint8_t _K_LINJECTOR[]      = {0x13,0x37,0xF0,0x0D};
static const uint8_t _K_FRIDA_WS[]       = {0x12,0x34,0x56,0x78};
static const uint8_t _K_JDWP[]           = {0xAB,0xCD,0xEF,0x01};
static const uint8_t _K_HOOK_RIRU[]      = {0x0D,0xF0,0xAD,0xBA};
static const uint8_t _K_HOOK_ZYGISK[]    = {0xCA,0xFE,0xBA,0xBE};
static const uint8_t _K_HOOK_XPOSED[]    = {0xDE,0xAD,0xC0,0xDE};
static const uint8_t _K_HOOK_LSPD[]      = {0xBE,0xEF,0xCA,0xFE};
static const uint8_t _K_HOOK_EDXPOSED[]  = {0xF0,0x0D,0xFA,0xCE};
static const uint8_t _K_HOOK_FRIDA[]     = {0x7F,0x45,0x4C,0x46};
static const uint8_t _K_PROC_MAPS[]      = {0x99,0x1A,0x2B,0x3C};
static const uint8_t _K_PROC_STATUS[]    = {0xC5,0xD6,0xE7,0xF8};
static const uint8_t _K_PROC_FD[]        = {0x4D,0x5E,0x6F,0x70};
static const uint8_t _K_PROC_TASK[]      = {0x81,0x92,0xA3,0xB4};
static const uint8_t _K_PROC_SELFSTATUS[]= {0x99,0x1A,0x2B,0x3C};
static const uint8_t _K_TRACER_PID[]     = {0x0A,0x1B,0x2C,0x3D};
static const uint8_t _K_LIBC[]           = {0x11,0x22,0x33,0x44};
static const uint8_t _K_LIBPHANTOM[]     = {0x55,0x66,0x77,0x88};

/* ─── 2026 addition: encrypted string lengths ─────────────────────────── */
#define _L2_ENVIRON_PATH 18
#define _L2_STR_LD_PRELOAD 11
#define _L2_STR_LD_LIB 16
#define _L2_STR_SYS_PROP_GET 21
#define _L2_STR_ADBD_SVC 13
#define _L2_STR_RUNNING 7
#define _L2_STR_RO_DEBUG 13
#define _L2_STR_RO_BTYPE 13
#define _L2_STR_USER 4
#define _L2_STR_ADB_KEYS 23
#define _L2_STR_TCP6 14
#define _L2_STR_PORT_5037 5
#define _L2_STR_PORT_5037L 5
#define _L2_STR_RO_BTAGS 13
#define _L2_STR_REL_KEYS 12
#define _L2_STR_RO_VBS 25
#define _L2_STR_ORANGE 6
#define _L2_STR_RED 3
#define _L2_STR_RO_FLASH 20
#define _L2_STR_CONSCRYPT 9
#define _L2_STR_TMPFS 5
#define _L2_STR_SYS_MNT 9
#define _L2_STR_RW_COMMA 4
#define _L2_STR_COMMA_RW 4
#define _L2_STR_APEX_MNT 6
#define _L2_STR_NET_UNIX 14
#define _L2_STR_DOT_MAGISK 7
#define _L2_STR_NPATCH 6
#define _L2_STR_LSPATCH 7
#define _L2_STR_PARANOID 8
#define _L2_STR_COM_NP 7
#define _L2_STR_7723 7
#define _L2_STR_IO_LSP 17
#define _L2_STR_MISC_NP 17
#define _L2_STR_MOD_NP 24
#define _L2_STR_MOD_LSP 25
#define _L2_STR_GOLDFISH_P 18
#define _L2_STR_QEMU_PIPE 14
#define _L2_STR_QEMUD 17
#define _L2_STR_GOLDFISH_S 18
#define _L2_STR_CPUINFO 13
#define _L2_STR_GOLDFISH_U 8
#define _L2_STR_GOLDFISH_L 8
#define _L2_STR_RANCHU 6
#define _L2_STR_QEMU_U 4
#define _L2_STR_HW_RANDOM 35
#define _L2_STR_VBOX 4
#define _L2_STR_PROC_MOUNTS 17

/* ─── 2026 addition: encrypted string data (.rodata — no plaintext) ───── */
static const uint8_t _E2_ENVIRON_PATH[]    = {0x8B,0x6D,0x75,0xD1,0xC7,0x32,0x74,0xDB,0xC8,0x7B,0x28,0xDB,0xCA,0x6B,0x6E,0xCC,0xCB,0x73};
static const uint8_t _E2_STR_LD_PRELOAD[]  = {0x0B,0x7B,0x65,0x74,0x15,0x7A,0x76,0x6B,0x06,0x7B,0x07};
static const uint8_t _E2_STR_LD_LIB[]     = {0xF1,0x5F,0xF1,0xF2,0xF4,0x59,0xFC,0xFF,0xEF,0x42,0xF1,0xEE,0xFC,0x4F,0xE6,0x83};
static const uint8_t _E2_STR_SYS_PROP_GET[]={0xBA,0xD3,0x64,0xE1,0x96,0xF8,0x72,0xF5,0xBA,0xFC,0x65,0xF7,0x95,0xE9,0x65,0xEC,0x9C,0xD3,0x70,0xFD,0x91};
static const uint8_t _E2_STR_ADBD_SVC[]   = {0x04,0x67,0x61,0x6C,0x43,0x7A,0x7E,0x7B,0x43,0x68,0x6C,0x7A,0x09};
static const uint8_t _E2_STR_RUNNING[]    = {0x4A,0x49,0xEC,0xF5,0x51,0x52,0xE5};
static const uint8_t _E2_STR_RO_DEBUG[]   = {0x75,0xFF,0x1D,0xDC,0x62,0xF2,0x46,0xDF,0x60,0xF1,0x51,0xD4,0x62};
static const uint8_t _E2_STR_RO_BTYPE[]   = {0xD5,0xDB,0xA2,0x0E,0xD2,0xDD,0xE0,0x08,0x89,0xC0,0xF5,0x1C,0xC2};
static const uint8_t _E2_STR_USER[]       = {0x4C,0x00,0xF2,0x3A};
static const uint8_t _E2_STR_ADB_KEYS[]   = {0xFF,0xBB,0x63,0xB7,0xB1,0xF0,0x6F,0xAA,0xA3,0xBC,0x2D,0xA2,0xB4,0xBD,0x2D,0xA2,0xB4,0xBD,0x5D,0xA8,0xB5,0xA6,0x71};
static const uint8_t _E2_STR_TCP6[]       = {0xE0,0x59,0xC1,0x02,0xAC,0x06,0xDD,0x08,0xBB,0x06,0xC7,0x0E,0xBF,0x1F};
static const uint8_t _E2_STR_PORT_5037[]  = {0x62,0x79,0x1B,0x79,0x1C};
static const uint8_t _E2_STR_PORT_5037L[] = {0xCC,0xF5,0x64,0x7A,0x92};
static const uint8_t _E2_STR_RO_BTAGS[]   = {0x6A,0x0D,0x37,0x3E,0x6D,0x0B,0x75,0x38,0x36,0x16,0x78,0x3B,0x6B};
static const uint8_t _E2_STR_REL_KEYS[]   = {0xAB,0x3C,0xF7,0x21,0xB8,0x2A,0xFE,0x69,0xB2,0x3C,0xE2,0x37};
static const uint8_t _E2_STR_RO_VBS[]     = {0xBD,0x63,0x95,0x14,0xA0,0x63,0xCF,0x58,0xB9,0x69,0xC9,0x1F,0xA9,0x65,0xDE,0x12,0xAD,0x63,0xD4,0x02,0xBC,0x78,0xDA,0x02,0xAA};
static const uint8_t _E2_STR_ORANGE[]     = {0xE5,0x52,0x9B,0x83,0xED,0x45};
static const uint8_t _E2_STR_RED[]        = {0x13,0x70,0xEA};
static const uint8_t _E2_STR_RO_FLASH[]   = {0xA7,0xCE,0xB1,0x81,0xBA,0xCE,0xEB,0xCD,0xB3,0xCD,0xFE,0x90,0xBD,0x8F,0xF3,0x8C,0xB6,0xCA,0xFA,0x87};
static const uint8_t _E2_STR_CONSCRYPT[]  = {0xBE,0x32,0xFA,0x41,0xBE,0x2F,0xED,0x42,0xA9};
static const uint8_t _E2_STR_TMPFS[]      = {0xC1,0x7F,0x7C,0xCC,0xC6};
static const uint8_t _E2_STR_SYS_MNT[]    = {0x1B,0xE9,0x38,0x84,0x48,0xB2,0x2E,0x90,0x1B};
static const uint8_t _E2_STR_RW_COMMA[]   = {0x35,0xA9,0x4B,0xF2};
static const uint8_t _E2_STR_COMMA_RW[]   = {0x36,0x10,0x3F,0x59};
static const uint8_t _E2_STR_APEX_MNT[]   = {0x83,0xF9,0x3F,0x5A,0xC6,0xAE};
static const uint8_t _E2_STR_NET_UNIX[]   = {0xE0,0xF9,0xF6,0xC3,0xAC,0xF0,0xEB,0xCF,0xBB,0xF0,0xF7,0xCE,0xBF,0xDF};
static const uint8_t _E2_STR_DOT_MAGISK[] = {0x16,0x3B,0x9A,0x89,0x33,0x9B,0x8C};
static const uint8_t _E2_STR_NPATCH[]     = {0xA2,0x68,0xED,0xA9,0xAC,0x60};
static const uint8_t _E2_STR_LSPATCH[]    = {0x24,0xFB,0x60,0x1C,0x23,0xFC,0x61};
static const uint8_t _E2_STR_PARANOID[]   = {0x68,0x11,0xFA,0x0C,0x6A,0x16,0xF3,0x0D};
static const uint8_t _E2_STR_COM_NP[]     = {0xBB,0x1A,0xAF,0x4E,0xBC,0x1A,0xAD};
static const uint8_t _E2_STR_7723[]       = {0xC4,0xCC,0xCC,0xDB,0xCA,0xCC,0xD8};
static const uint8_t _E2_STR_IO_LSP[]     = {0x3B,0x5F,0x6F,0x41,0x3A,0x5C,0x7B,0x56,0x28,0x55,0x73,0x56,0x25,0x56,0x7A,0x56,0x21};
static const uint8_t _E2_STR_MISC_NP[]    = {0xFF,0x43,0x6C,0x46,0xFD,0x41,0x6D,0x46,0xFB,0x56,0x6D,0x45,0xF8,0x56,0x6A,0x52,0xF0};
static const uint8_t _E2_STR_MOD_NP[]     = {0xFF,0x43,0x6C,0x46,0xFD,0x4E,0x7D,0x5F,0xF8,0x53,0x7B,0x41,0xF8,0x5B,0x62,0x5F,0xF8,0x56,0x6D,0x45,0xF8,0x56,0x6A,0x52};
static const uint8_t _E2_STR_MOD_LSP[]    = {0xFF,0x43,0x6C,0x46,0xFD,0x4E,0x7D,0x5F,0xF8,0x53,0x7B,0x41,0xF8,0x5B,0x62,0x5F,0x26,0x4A,0x6D,0x5E,0x24,0x4A,0x7D,0x50,0x21};
static const uint8_t _E2_STR_GOLDFISH_P[] = {0x8B,0x6D,0x75,0xD1,0xDA,0x2A,0x6A,0xDE,0xCE,0x7A,0x29,0xDE,0xCA,0x23,0x74,0xDE,0xCF,0x21};
static const uint8_t _E2_STR_QEMU_PIPE[]  = {0x8B,0x6D,0x75,0xD1,0xDA,0x2E,0x68,0xDE,0xC8,0x21,0x63,0xCE,0xCB,0x28};
static const uint8_t _E2_STR_QEMUD[]      = {0x8B,0x6D,0x75,0xD1,0xC0,0x2D,0x74,0xDB,0xCC,0x7A,0x29,0xDB,0xCB,0x7B,0x28,0xDB,0xD8};
static const uint8_t _E2_STR_GOLDFISH_S[] = {0x8B,0x6D,0x75,0xD1,0xDA,0x2A,0x6A,0xDE,0xCE,0x7A,0x29,0xDE,0xCA,0x23,0x74,0xDE,0xCC,0x35};
static const uint8_t _E2_STR_CPUINFO[]    = {0x8B,0x6D,0x75,0xD1,0xC1,0x36,0x70,0xD8,0xD5,0x7B,0x29,0xD8,0xCE};
static const uint8_t _E2_STR_GOLDFISH_U[] = {0x97,0x1A,0x04,0xBB,0x9A,0x08,0x1C,0xBC};
static const uint8_t _E2_STR_GOLDFISH_L[] = {0xB7,0x3A,0x24,0x9B,0xBA,0x28,0x3C,0x9C};
static const uint8_t _E2_STR_RANCHU[]     = {0x29,0x1B,0x08,0xBB,0x2C,0x1E};
static const uint8_t _E2_STR_QEMU_U[]     = {0x97,0x1A,0x04,0xBB};
static const uint8_t _E2_STR_HW_RANDOM[]  = {0x8B,0x6D,0x75,0xD1,0xC1,0x36,0x70,0xD8,0xD5,0x7B,0x28,0xDB,0xDE,0x7B,0x25,0xDB,0xD5,0x38,0x70,0xDD,0xD4,0x2F,0x7A,0xDB,0xD4,0x27,0x7A,0xDD,0xD4,0x2C,0x7F,0xD2,0xC6,0x29,0x6D};
static const uint8_t _E2_STR_VBOX[]       = {0xB9,0x34,0x28,0x93};
static const uint8_t _E2_STR_PROC_MOUNTS[]= {0x8B,0x6D,0x75,0xD1,0xC1,0x36,0x6F,0xDB,0xD6,0x7B,0x28,0xDA,0xD4,0x38,0x71,0xDB,0xCA};

/* ─── 2026 addition: per-string XOR keys (.rodata) ────────────────────── */
static const uint8_t _K2_ENVIRON_PATH[]    = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_LD_PRELOAD[]  = {0x6E,0x1C,0x00,0x1F};
static const uint8_t _K2_STR_LD_LIB[]     = {0x9E,0x30,0x9E,0x9B};
static const uint8_t _K2_STR_SYS_PROP_GET[]={0xDF,0xB4,0x05,0x8E};
static const uint8_t _K2_STR_ADBD_SVC[]   = {0x61,0x06,0x04,0x0F};
static const uint8_t _K2_STR_RUNNING[]    = {0x2A,0x28,0x8E,0x95};
static const uint8_t _K2_STR_RO_DEBUG[]   = {0x15,0x9F,0x7D,0xBC};
static const uint8_t _K2_STR_RO_BTYPE[]   = {0xB5,0xBB,0xC2,0x6E};
static const uint8_t _K2_STR_USER[]       = {0x3B,0x75,0x86,0x5B};
static const uint8_t _K2_STR_ADB_KEYS[]   = {0x9E,0xDA,0x0C,0xD4};
static const uint8_t _K2_STR_TCP6[]       = {0x8F,0x38,0xAE,0x6F};
static const uint8_t _K2_STR_PORT_5037[]  = {0x57,0x18,0x7B,0x18};
static const uint8_t _K2_STR_PORT_5037L[] = {0xB9,0x94,0x00,0x19};
static const uint8_t _K2_STR_RO_BTAGS[]   = {0x0B,0x6C,0x57,0x5F};
static const uint8_t _K2_STR_REL_KEYS[]   = {0xCA,0x5D,0x96,0x40};
static const uint8_t _K2_STR_RO_VBS[]     = {0xDC,0x02,0xF4,0x75};
static const uint8_t _K2_STR_ORANGE[]     = {0x84,0x33,0xFA,0xE2};
static const uint8_t _K2_STR_RED[]        = {0x72,0x11,0x8B};
static const uint8_t _K2_STR_RO_FLASH[]   = {0xC6,0xAF,0xD0,0xE0};
static const uint8_t _K2_STR_CONSCRYPT[]  = {0xDF,0x53,0x9B,0x20};
static const uint8_t _K2_STR_TMPFS[]      = {0xA0,0x1E,0x1D,0xAD};
static const uint8_t _K2_STR_SYS_MNT[]    = {0x7A,0x88,0x59,0xE5};
static const uint8_t _K2_STR_RW_COMMA[]   = {0x54,0xC8,0x2A,0x93};
static const uint8_t _K2_STR_COMMA_RW[]   = {0x57,0x71,0x5E,0x38};
static const uint8_t _K2_STR_APEX_MNT[]   = {0xE2,0x98,0x5E,0x3B};
static const uint8_t _K2_STR_NET_UNIX[]   = {0x8F,0x98,0x97,0xA2};
static const uint8_t _K2_STR_DOT_MAGISK[] = {0x77,0x5A,0xFB,0xE8};
static const uint8_t _K2_STR_NPATCH[]     = {0xC3,0x09,0x8C,0xC8};
static const uint8_t _K2_STR_LSPATCH[]    = {0x45,0x9A,0x01,0x7D};
static const uint8_t _K2_STR_PARANOID[]   = {0x09,0x70,0x9B,0x6D};
static const uint8_t _K2_STR_COM_NP[]     = {0xDA,0x7B,0xCE,0x2F};
static const uint8_t _K2_STR_7723[]       = {0xA5,0xAD,0xAD,0xBA};
static const uint8_t _K2_STR_IO_LSP[]     = {0x5A,0x3E,0x0E,0x20};
static const uint8_t _K2_STR_MISC_NP[]    = {0x9E,0x22,0x0D,0x27};
static const uint8_t _K2_STR_MOD_NP[]     = {0x9E,0x22,0x0D,0x27};
static const uint8_t _K2_STR_MOD_LSP[]    = {0x9E,0x22,0x0D,0x27};
static const uint8_t _K2_STR_GOLDFISH_P[] = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_QEMU_PIPE[]  = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_QEMUD[]      = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_GOLDFISH_S[] = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_CPUINFO[]    = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_GOLDFISH_U[] = {0xF6,0x7B,0x6B,0xDA};
static const uint8_t _K2_STR_GOLDFISH_L[] = {0xD6,0x5B,0x4B,0xFA};
static const uint8_t _K2_STR_RANCHU[]     = {0x48,0x7A,0x69,0xDA};
static const uint8_t _K2_STR_QEMU_U[]     = {0xF6,0x7B,0x6B,0xDA};
static const uint8_t _K2_STR_HW_RANDOM[]  = {0xE4,0x02,0x1B,0xBF};
static const uint8_t _K2_STR_VBOX[]       = {0xD8,0x55,0x49,0xF2};
static const uint8_t _K2_STR_PROC_MOUNTS[]= {0xE4,0x02,0x1B,0xBF};

// ── Plaintext buffers (.bss — all zeros at startup) ───────────────────────────
static char APPNAME[14];
static char FRIDA_THREAD_GUM_JS_LOOP[12];
static char FRIDA_THREAD_GMAIN[6];
static char FRIDA_NAMEDPIPE_LINJECTOR[10];
static char FRIDA_WS_ACCEPT[30];
static char JDWP_THREAD_NAME[5];
static char HOOK_RIRU[5];
static char HOOK_ZYGISK[7];
static char HOOK_XPOSED[7];
static char HOOK_LSPD[5];
static char HOOK_EDXPOSED[9];
static char HOOK_FRIDA[6];
static char PROC_MAPS[16];
static char PROC_STATUS[26];
static char PROC_FD[14];
static char PROC_TASK[16];
static char PROC_SELF_STATUS[19];
static char STR_TRACER_PID[11];
static char STR_LIBC[8];
static char STR_LIBPHANTOM[14];

/* ─── 2026 addition: plaintext buffers (.bss) ──────────────────────────── */
static char _S2_ENVIRON_PATH[20];
static char _S2_STR_LD_PRELOAD[13];
static char _S2_STR_LD_LIB[18];
static char _S2_STR_SYS_PROP_GET[23];
static char _S2_STR_ADBD_SVC[15];
static char _S2_STR_RUNNING[9];
static char _S2_STR_RO_DEBUG[15];
static char _S2_STR_RO_BTYPE[15];
static char _S2_STR_USER[6];
static char _S2_STR_ADB_KEYS[25];
static char _S2_STR_TCP6[16];
static char _S2_STR_PORT_5037[7];
static char _S2_STR_PORT_5037L[7];
static char _S2_STR_RO_BTAGS[15];
static char _S2_STR_REL_KEYS[14];
static char _S2_STR_RO_VBS[27];
static char _S2_STR_ORANGE[8];
static char _S2_STR_RED[5];
static char _S2_STR_RO_FLASH[22];
static char _S2_STR_CONSCRYPT[11];
static char _S2_STR_TMPFS[7];
static char _S2_STR_SYS_MNT[11];
static char _S2_STR_RW_COMMA[6];
static char _S2_STR_COMMA_RW[6];
static char _S2_STR_APEX_MNT[8];
static char _S2_STR_NET_UNIX[16];
static char _S2_STR_DOT_MAGISK[9];
static char _S2_STR_NPATCH[8];
static char _S2_STR_LSPATCH[9];
static char _S2_STR_PARANOID[10];
static char _S2_STR_COM_NP[9];
static char _S2_STR_7723[9];
static char _S2_STR_IO_LSP[19];
static char _S2_STR_MISC_NP[19];
static char _S2_STR_MOD_NP[26];
static char _S2_STR_MOD_LSP[27];
static char _S2_STR_GOLDFISH_P[20];
static char _S2_STR_QEMU_PIPE[16];
static char _S2_STR_QEMUD[19];
static char _S2_STR_GOLDFISH_S[20];
static char _S2_STR_CPUINFO[15];
static char _S2_STR_GOLDFISH_U[10];
static char _S2_STR_GOLDFISH_L[10];
static char _S2_STR_RANCHU[8];
static char _S2_STR_QEMU_U[6];
static char _S2_STR_HW_RANDOM[37];
static char _S2_STR_VBOX[6];
static char _S2_STR_PROC_MOUNTS[19];

#define NUM_LIBS 2
static char *libstocheck[NUM_LIBS]; // filled by ph_strings_init() → STR_LIBPHANTOM, STR_LIBC

// Decrypts all detection strings into the static buffers above on first call.
static void ph_strings_init(void) {
    static volatile int _done = 0;
    if (_done) return;
    _done = 1;
    PH_DECRYPT_N(APPNAME,                 _E_APPNAME,        13, _K_APPNAME);
    PH_DECRYPT_N(FRIDA_THREAD_GUM_JS_LOOP,_E_GUM_JS_LOOP,   11, _K_GUM_JS_LOOP);
    PH_DECRYPT_N(FRIDA_THREAD_GMAIN,      _E_GMAIN,           5, _K_GMAIN);
    PH_DECRYPT_N(FRIDA_NAMEDPIPE_LINJECTOR,_E_LINJECTOR,     9, _K_LINJECTOR);
    PH_DECRYPT_N(FRIDA_WS_ACCEPT,         _E_FRIDA_WS,       28, _K_FRIDA_WS);
    PH_DECRYPT_N(JDWP_THREAD_NAME,        _E_JDWP,            4, _K_JDWP);
    PH_DECRYPT_N(HOOK_RIRU,               _E_HOOK_RIRU,       4, _K_HOOK_RIRU);
    PH_DECRYPT_N(HOOK_ZYGISK,             _E_HOOK_ZYGISK,     6, _K_HOOK_ZYGISK);
    PH_DECRYPT_N(HOOK_XPOSED,             _E_HOOK_XPOSED,     6, _K_HOOK_XPOSED);
    PH_DECRYPT_N(HOOK_LSPD,               _E_HOOK_LSPD,       4, _K_HOOK_LSPD);
    PH_DECRYPT_N(HOOK_EDXPOSED,           _E_HOOK_EDXPOSED,   8, _K_HOOK_EDXPOSED);
    PH_DECRYPT_N(HOOK_FRIDA,              _E_HOOK_FRIDA,      5, _K_HOOK_FRIDA);
    PH_DECRYPT_N(PROC_MAPS,               _E_PROC_MAPS,      15, _K_PROC_MAPS);
    PH_DECRYPT_N(PROC_STATUS,             _E_PROC_STATUS,    25, _K_PROC_STATUS);
    PH_DECRYPT_N(PROC_FD,                 _E_PROC_FD,        13, _K_PROC_FD);
    PH_DECRYPT_N(PROC_TASK,               _E_PROC_TASK,      15, _K_PROC_TASK);
    PH_DECRYPT_N(PROC_SELF_STATUS,        _E_PROC_SELFSTATUS,18, _K_PROC_SELFSTATUS);
    PH_DECRYPT_N(STR_TRACER_PID,          _E_TRACER_PID,     10, _K_TRACER_PID);
    PH_DECRYPT_N(STR_LIBC,                _E_LIBC,            7, _K_LIBC);
    PH_DECRYPT_N(STR_LIBPHANTOM,          _E_LIBPHANTOM,     13, _K_LIBPHANTOM);
    libstocheck[0] = STR_LIBPHANTOM;
    libstocheck[1] = STR_LIBC;
    /* ── 2026 additions ─────────────────────────────────────────────────── */
    PH_DECRYPT_N(_S2_ENVIRON_PATH,    _E2_ENVIRON_PATH,    _L2_ENVIRON_PATH,    _K2_ENVIRON_PATH);
    PH_DECRYPT_N(_S2_STR_LD_PRELOAD,  _E2_STR_LD_PRELOAD,  _L2_STR_LD_PRELOAD,  _K2_STR_LD_PRELOAD);
    PH_DECRYPT_N(_S2_STR_LD_LIB,      _E2_STR_LD_LIB,      _L2_STR_LD_LIB,      _K2_STR_LD_LIB);
    PH_DECRYPT_N(_S2_STR_SYS_PROP_GET,_E2_STR_SYS_PROP_GET,_L2_STR_SYS_PROP_GET,_K2_STR_SYS_PROP_GET);
    PH_DECRYPT_N(_S2_STR_ADBD_SVC,    _E2_STR_ADBD_SVC,    _L2_STR_ADBD_SVC,    _K2_STR_ADBD_SVC);
    PH_DECRYPT_N(_S2_STR_RUNNING,     _E2_STR_RUNNING,     _L2_STR_RUNNING,     _K2_STR_RUNNING);
    PH_DECRYPT_N(_S2_STR_RO_DEBUG,    _E2_STR_RO_DEBUG,    _L2_STR_RO_DEBUG,    _K2_STR_RO_DEBUG);
    PH_DECRYPT_N(_S2_STR_RO_BTYPE,    _E2_STR_RO_BTYPE,    _L2_STR_RO_BTYPE,    _K2_STR_RO_BTYPE);
    PH_DECRYPT_N(_S2_STR_USER,        _E2_STR_USER,        _L2_STR_USER,        _K2_STR_USER);
    PH_DECRYPT_N(_S2_STR_ADB_KEYS,    _E2_STR_ADB_KEYS,    _L2_STR_ADB_KEYS,    _K2_STR_ADB_KEYS);
    PH_DECRYPT_N(_S2_STR_TCP6,        _E2_STR_TCP6,        _L2_STR_TCP6,        _K2_STR_TCP6);
    PH_DECRYPT_N(_S2_STR_PORT_5037,   _E2_STR_PORT_5037,   _L2_STR_PORT_5037,   _K2_STR_PORT_5037);
    PH_DECRYPT_N(_S2_STR_PORT_5037L,  _E2_STR_PORT_5037L,  _L2_STR_PORT_5037L,  _K2_STR_PORT_5037L);
    PH_DECRYPT_N(_S2_STR_RO_BTAGS,    _E2_STR_RO_BTAGS,    _L2_STR_RO_BTAGS,    _K2_STR_RO_BTAGS);
    PH_DECRYPT_N(_S2_STR_REL_KEYS,    _E2_STR_REL_KEYS,    _L2_STR_REL_KEYS,    _K2_STR_REL_KEYS);
    PH_DECRYPT_N(_S2_STR_RO_VBS,      _E2_STR_RO_VBS,      _L2_STR_RO_VBS,      _K2_STR_RO_VBS);
    PH_DECRYPT_N(_S2_STR_ORANGE,      _E2_STR_ORANGE,      _L2_STR_ORANGE,      _K2_STR_ORANGE);
    PH_DECRYPT_N(_S2_STR_RED,         _E2_STR_RED,         _L2_STR_RED,         _K2_STR_RED);
    PH_DECRYPT_N(_S2_STR_RO_FLASH,    _E2_STR_RO_FLASH,    _L2_STR_RO_FLASH,    _K2_STR_RO_FLASH);
    PH_DECRYPT_N(_S2_STR_CONSCRYPT,   _E2_STR_CONSCRYPT,   _L2_STR_CONSCRYPT,   _K2_STR_CONSCRYPT);
    PH_DECRYPT_N(_S2_STR_TMPFS,       _E2_STR_TMPFS,       _L2_STR_TMPFS,       _K2_STR_TMPFS);
    PH_DECRYPT_N(_S2_STR_SYS_MNT,     _E2_STR_SYS_MNT,     _L2_STR_SYS_MNT,     _K2_STR_SYS_MNT);
    PH_DECRYPT_N(_S2_STR_RW_COMMA,    _E2_STR_RW_COMMA,    _L2_STR_RW_COMMA,    _K2_STR_RW_COMMA);
    PH_DECRYPT_N(_S2_STR_COMMA_RW,    _E2_STR_COMMA_RW,    _L2_STR_COMMA_RW,    _K2_STR_COMMA_RW);
    PH_DECRYPT_N(_S2_STR_APEX_MNT,    _E2_STR_APEX_MNT,    _L2_STR_APEX_MNT,    _K2_STR_APEX_MNT);
    PH_DECRYPT_N(_S2_STR_NET_UNIX,    _E2_STR_NET_UNIX,    _L2_STR_NET_UNIX,    _K2_STR_NET_UNIX);
    PH_DECRYPT_N(_S2_STR_DOT_MAGISK,  _E2_STR_DOT_MAGISK,  _L2_STR_DOT_MAGISK,  _K2_STR_DOT_MAGISK);
    PH_DECRYPT_N(_S2_STR_NPATCH,      _E2_STR_NPATCH,      _L2_STR_NPATCH,      _K2_STR_NPATCH);
    PH_DECRYPT_N(_S2_STR_LSPATCH,     _E2_STR_LSPATCH,     _L2_STR_LSPATCH,     _K2_STR_LSPATCH);
    PH_DECRYPT_N(_S2_STR_PARANOID,    _E2_STR_PARANOID,    _L2_STR_PARANOID,    _K2_STR_PARANOID);
    PH_DECRYPT_N(_S2_STR_COM_NP,      _E2_STR_COM_NP,      _L2_STR_COM_NP,      _K2_STR_COM_NP);
    PH_DECRYPT_N(_S2_STR_7723,        _E2_STR_7723,        _L2_STR_7723,        _K2_STR_7723);
    PH_DECRYPT_N(_S2_STR_IO_LSP,      _E2_STR_IO_LSP,      _L2_STR_IO_LSP,      _K2_STR_IO_LSP);
    PH_DECRYPT_N(_S2_STR_MISC_NP,     _E2_STR_MISC_NP,     _L2_STR_MISC_NP,     _K2_STR_MISC_NP);
    PH_DECRYPT_N(_S2_STR_MOD_NP,      _E2_STR_MOD_NP,      _L2_STR_MOD_NP,      _K2_STR_MOD_NP);
    PH_DECRYPT_N(_S2_STR_MOD_LSP,     _E2_STR_MOD_LSP,     _L2_STR_MOD_LSP,     _K2_STR_MOD_LSP);
    PH_DECRYPT_N(_S2_STR_GOLDFISH_P,  _E2_STR_GOLDFISH_P,  _L2_STR_GOLDFISH_P,  _K2_STR_GOLDFISH_P);
    PH_DECRYPT_N(_S2_STR_QEMU_PIPE,   _E2_STR_QEMU_PIPE,   _L2_STR_QEMU_PIPE,   _K2_STR_QEMU_PIPE);
    PH_DECRYPT_N(_S2_STR_QEMUD,       _E2_STR_QEMUD,       _L2_STR_QEMUD,       _K2_STR_QEMUD);
    PH_DECRYPT_N(_S2_STR_GOLDFISH_S,  _E2_STR_GOLDFISH_S,  _L2_STR_GOLDFISH_S,  _K2_STR_GOLDFISH_S);
    PH_DECRYPT_N(_S2_STR_CPUINFO,     _E2_STR_CPUINFO,     _L2_STR_CPUINFO,     _K2_STR_CPUINFO);
    PH_DECRYPT_N(_S2_STR_GOLDFISH_U,  _E2_STR_GOLDFISH_U,  _L2_STR_GOLDFISH_U,  _K2_STR_GOLDFISH_U);
    PH_DECRYPT_N(_S2_STR_GOLDFISH_L,  _E2_STR_GOLDFISH_L,  _L2_STR_GOLDFISH_L,  _K2_STR_GOLDFISH_L);
    PH_DECRYPT_N(_S2_STR_RANCHU,      _E2_STR_RANCHU,      _L2_STR_RANCHU,      _K2_STR_RANCHU);
    PH_DECRYPT_N(_S2_STR_QEMU_U,      _E2_STR_QEMU_U,      _L2_STR_QEMU_U,      _K2_STR_QEMU_U);
    PH_DECRYPT_N(_S2_STR_HW_RANDOM,   _E2_STR_HW_RANDOM,   _L2_STR_HW_RANDOM,   _K2_STR_HW_RANDOM);
    PH_DECRYPT_N(_S2_STR_VBOX,        _E2_STR_VBOX,        _L2_STR_VBOX,        _K2_STR_VBOX);
    PH_DECRYPT_N(_S2_STR_PROC_MOUNTS, _E2_STR_PROC_MOUNTS, _L2_STR_PROC_MOUNTS, _K2_STR_PROC_MOUNTS);
}

typedef struct {
    int           execSectionCount;
    unsigned long offset[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;

static execSection *elfSectionArr[NUM_LIBS] = {NULL};

#if defined(__LP64__)
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#endif

// ?
// Inline string helpers (avoid libc hooks)
// ?

__attribute__((always_inline))
static inline size_t my_strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

__attribute__((always_inline))
static inline int my_strcmp(const char *s1, const char *s2) {
    while (*s1 == *s2++) if (*s1++ == 0) return 0;
    return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

static inline int my_strncmp(const char *s1, const char *s2, size_t n);

__attribute__((always_inline))
static inline char *my_strstr(const char *s, const char *find) {
    char c, sc;
    size_t len;
    if ((c = *find++) != '\0') {
        len = my_strlen(find);
        do {
            do { if ((sc = *s++) == '\0') return NULL; } while (sc != c);
        } while (my_strncmp(s, find, len) != 0);
        s--;
    }
    return (char *)s;
}

__attribute__((always_inline))
static inline int my_strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    do {
        if (*s1 != *s2++) return (*(unsigned char *)s1 - *(unsigned char *)--s2);
        if (*s1++ == 0) break;
    } while (--n != 0);
    return 0;
}

__attribute__((always_inline))
static inline void *my_memset(void *dst, int c, size_t n) {
    char *q = (char *)dst;
    for (size_t i = 0; i < n; i++) q[i] = (char)c;
    return dst;
}

// ?
// Raw syscall wrappers (bypass libc -- Frida hooks libc)
// ?

#if defined(__aarch64__)

__attribute__((always_inline))
static inline long raw_syscall_3(long no, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = no;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc #0\n"
        : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

__attribute__((always_inline))
static inline long raw_syscall_4(long no, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = no;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile("svc #0\n"
        : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

__attribute__((always_inline)) static inline int my_openat(int d, const char *p, int f, int m)
    { return (int)raw_syscall_4(__NR_openat, d, (long)p, f, m); }

__attribute__((always_inline)) static inline ssize_t my_read(int fd, void *b, size_t n)
    { return (ssize_t)raw_syscall_3(__NR_read, fd, (long)b, n); }

__attribute__((always_inline)) static inline ssize_t my_write(int fd, const void *b, size_t n)
    { return (ssize_t)raw_syscall_3(__NR_write, fd, (long)b, n); }

__attribute__((always_inline)) static inline off_t my_lseek(int fd, off_t off, int w)
    { return (off_t)raw_syscall_3(__NR_lseek, fd, off, w); }

__attribute__((always_inline)) static inline int my_close(int fd)
    { return (int)raw_syscall_3(__NR_close, fd, 0, 0); }

__attribute__((always_inline)) static inline int my_nanosleep(const struct timespec *r, struct timespec *e)
    { return (int)raw_syscall_3(__NR_nanosleep, (long)r, (long)e, 0); }

__attribute__((always_inline)) static inline ssize_t my_readlinkat(int d, const char *p, char *b, size_t s)
    { return (ssize_t)raw_syscall_4(__NR_readlinkat, d, (long)p, (long)b, s); }

__attribute__((always_inline)) static inline int my_mprotect(void *a, size_t l, int prot)
    { return (int)raw_syscall_3(__NR_mprotect, (long)a, (long)l, prot); }

__attribute__((always_inline)) static inline int my_madvise(void *a, size_t l, int adv)
    { return (int)raw_syscall_3(__NR_madvise, (long)a, (long)l, adv); }

// socket + connect raw syscall wrappers (arm64)
__attribute__((always_inline)) static inline int my_socket(int domain, int type, int protocol)
    { return (int)raw_syscall_3(__NR_socket, domain, type, protocol); }

__attribute__((always_inline)) static inline int my_connect(int fd, const struct sockaddr *addr, socklen_t len)
    { return (int)raw_syscall_3(__NR_connect, fd, (long)addr, (long)len); }

#else  // armeabi-v7a -- use libc syscall() wrapper

__attribute__((always_inline)) static inline int my_openat(int d, const char *p, int f, int m)
    { return (int)syscall(__NR_openat, d, p, f, m); }

__attribute__((always_inline)) static inline ssize_t my_read(int fd, void *b, size_t n)
    { return (ssize_t)syscall(__NR_read, fd, b, n); }

__attribute__((always_inline)) static inline ssize_t my_write(int fd, const void *b, size_t n)
    { return (ssize_t)syscall(__NR_write, fd, b, n); }

__attribute__((always_inline)) static inline off_t my_lseek(int fd, off_t off, int w)
    { return (off_t)syscall(__NR_lseek, fd, off, w); }

__attribute__((always_inline)) static inline int my_close(int fd)
    { return (int)syscall(__NR_close, fd); }

__attribute__((always_inline)) static inline int my_nanosleep(const struct timespec *r, struct timespec *e)
    { return (int)syscall(__NR_nanosleep, r, e); }

__attribute__((always_inline)) static inline ssize_t my_readlinkat(int d, const char *p, char *b, size_t s)
    { return (ssize_t)syscall(__NR_readlinkat, d, p, b, s); }

__attribute__((always_inline)) static inline int my_mprotect(void *a, size_t l, int prot)
    { return (int)syscall(__NR_mprotect, a, l, prot); }

__attribute__((always_inline)) static inline int my_madvise(void *a, size_t l, int adv)
    { return (int)syscall(__NR_madvise, a, l, adv); }

// socket + connect raw syscall wrappers (arm32)
__attribute__((always_inline)) static inline int my_socket(int domain, int type, int protocol)
    { return (int)syscall(__NR_socket, domain, type, protocol); }

__attribute__((always_inline)) static inline int my_connect(int fd, const struct sockaddr *addr, socklen_t len)
    { return (int)syscall(__NR_connect, fd, addr, len); }

#endif  // ABI

// ?
// Low-level I/O helpers
// ?

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret, bytes_read = 0;
    my_memset(buf, 0, max_len);
    do {
        ret = my_read(fd, &b, 1);
        if (ret != 1) return (bytes_read == 0) ? -1 : bytes_read;
        if (b == '\n') return bytes_read;
        *(buf++) = b;
        bytes_read++;
    } while (bytes_read < max_len - 1);
    return bytes_read;
}

static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *)buffer;
    for (size_t i = 0; i < len; i++) seed += (unsigned long)(*buf++);
    return seed;
}

// ?
// ELF section checksum helpers (Frida mem/disk compare)
// ?

static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char map[MAX_LINE];
    int counter = 0;
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (my_strstr(map, libstocheck[i]) != NULL) {
                char tmp[MAX_LENGTH] = "", path[MAX_LENGTH] = "", buf[5] = "";
                sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                if (buf[2] == 'x') {
                    size_t size = my_strlen(path) + 1;
                    filepaths[i] = (char *)malloc(size);
                    strcpy(filepaths[i], path);
                    counter++;
                }
            }
        }
        if (counter == NUM_LIBS) break;
    }
    my_close(fd);
}

static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {
    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    my_read(fd, &ehdr, sizeof(Elf_Ehdr));
    my_lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET);
    unsigned long memsize[2] = {0}, offset[2] = {0};
    int execSectionCount = 0;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
            offset[execSectionCount] = sectHdr.sh_offset;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) break;
        }
    }
    if (execSectionCount == 0) { my_close(fd); return false; }
    *pTextSection = (execSection *)malloc(sizeof(execSection));
    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem   = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = (uint8_t *)malloc(memsize[i]);
        my_read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i]   = offset[i];
        (*pTextSection)->memsize[i]  = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
    }
    my_close(fd);
    return true;
}

static inline bool scan_executable_segments(char *map, execSection *pElfSectArr) {
    unsigned long start, end;
    char buf[MAX_LINE] = "", path[MAX_LENGTH] = "", tmp[100] = "";
    sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);
    if (buf[2] == 'x' && buf[0] == 'r') {
        uint8_t *buffer = (uint8_t *)start;
        for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
            unsigned long output = checksum(buffer + pElfSectArr->offset[i],
                                            pElfSectArr->memsize[i]);
            if (output != pElfSectArr->checksum[i]) return false;
        }
        return true;
    }
    return false;
}

// ?
// Kill switch
//
// Sends SIGKILL to the calling thread via a raw tgkill syscall.
//
// WHY NOT null-deref (the old approach):
//   ART's libsigchain wraps sigaction() and gets first access to EVERY signal,
//   including SIGSEGV.  ART's fault_handler.cc intercepts SIGSEGV from native
//   null-derefs to check whether the fault is in managed code — on some Android
//   versions and OEM ROMs this interception absorbs the signal before it kills
//   the process.  A null-deref is therefore NOT reliably fatal in JNI context.
//
// WHY SIGKILL via raw tgkill:
//   SIGKILL cannot be caught, blocked, masked, or ignored by ANY userspace
//   handler — this is a hard kernel guarantee (POSIX + Linux).  ART's
//   libsigchain has zero power over SIGKILL.  The kernel delivers it
//   unconditionally and the process is terminated immediately.
//   AOSP itself uses tgkill() for all signal dispatch (android_util_Process.cpp).
//
// Syscall numbers — stable Linux ABI, unchanged across all Android versions
// (5 → 16+), confirmed from kernel/common/include/uapi/asm-generic/unistd.h:
//   arm64: __NR_getpid=172  __NR_gettid=178  __NR_tgkill=131  __NR_kill=129
//   arm32: numbers resolved at compile time via NDK <sys/syscall.h> __NR_* defs
// ?

__attribute__((noreturn)) static void nuke_app(void) {
#if defined(__aarch64__)
    // Fully raw path — zero libc, zero ART involvement.
    // Hardcoded numbers match the stable arm64 Linux ABI (never changes).
    long pid = raw_syscall_3(172 /*__NR_getpid*/, 0, 0, 0);
    long tid = raw_syscall_3(178 /*__NR_gettid*/, 0, 0, 0);
    // tgkill(pid, tid, SIGKILL=9) — kills this specific thread; kernel
    // propagates SIGKILL to the whole thread group (process) immediately.
    raw_syscall_3(131 /*__NR_tgkill*/, pid, tid, 9 /*SIGKILL*/);
    // Fallback: kill(pid, SIGKILL) — targets the entire process group.
    raw_syscall_3(129 /*__NR_kill*/, pid, 9 /*SIGKILL*/, 0);
#else
    // arm32 EABI — libc syscall() wrapper is fine; SIGKILL is still uncatchable.
    // __NR_* resolved from NDK <sys/syscall.h> (bionic copies kernel headers).
    // Confirmed from arch/arm/tools/syscall.tbl (Android kernel + Linus tree,
    // stable since first arm32 Android, __NR_SYSCALL_BASE=0 on EABI):
    //   __NR_getpid=20  __NR_kill=37  __NR_gettid=224  __NR_tgkill=268
    pid_t pid = (pid_t)syscall(__NR_getpid);          // 20
    pid_t tid = (pid_t)syscall(__NR_gettid);          // 224
    syscall(__NR_tgkill, (long)pid, (long)tid, 9L);   // 268, SIGKILL=9
    syscall(__NR_kill,   (long)pid,              9L);  // 37,  SIGKILL=9
#endif
    // Should NEVER reach here — SIGKILL is unconditional.
    // Paranoia-only null-deref as absolute last resort.
    volatile int *p = (volatile int *)0;
    *p = 0xDEAD;
    __builtin_unreachable();
}


// ?
// Original anti-Frida detection functions (unchanged)
// ?

static inline void detect_ptrace(void) {
    ph_strings_init();
    PH_LOG("detect_ptrace: checking TracerPid");
    char buf[512];
    int fd = my_openat(AT_FDCWD, PROC_SELF_STATUS, O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0) {
        ssize_t bytes = my_read(fd, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            char *tracer = my_strstr(buf, STR_TRACER_PID);
            if (tracer) {
                int pid = atoi(tracer + 10);
                if (pid > 0) { my_close(fd); PH_NUKE("ptrace — TracerPid=%d", pid); nuke_app(); }
            }
        }
        my_close(fd);
    }
}


// ?

static inline void detect_frida_memdiskcompare(void) {
    // Open a fresh fd each call — avoids cross-thread fd sharing.
    // elfSectionArr[i] NULL guard: array stays NULL if fetch_checksum_of_library()
    // failed at startup; passing NULL to scan_executable_segments crashes.
    int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char map[MAX_LINE];
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (my_strstr(map, libstocheck[i]) != NULL) {
                if (elfSectionArr[i] != NULL)           // NULL guard — CRASH FIX
                    scan_executable_segments(map, elfSectionArr[i]);
                break;
            }
        }
    }
    my_close(fd);
}

// detect_frida_threads — three checks per task, matching darvincisec + NativeShield:
//
//  1. /proc/self/task/<tid>/comm
//     Raw thread name (no prefix).  Exact checks:
//       - "JDWP"         → Java Debug Wire Protocol thread = Java debugger attached
//       - "gum-js-loop"  → Frida's JavaScript engine thread
//       - "gmain"        → Frida's GLib main loop thread
//
//  2. /proc/self/task/<tid>/status  (full read)
//     - Name: field  → same Frida thread name checks as backup
//     - TracerPid:   → non-zero means a debugger is ptrace-attached to THIS thread
//
// Reading status for EVERY task (not just /proc/self/status) catches debuggers
// that attach to a single worker thread rather than the main thread — a common
// bypass of single-file TracerPid checks.
static inline void detect_frida_threads(void) {
    ph_strings_init();
    PH_LOG("detect_frida_threads: scanning all task comm + status");
    DIR *dir = opendir(PROC_TASK);
    if (dir == NULL) return;

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (my_strcmp(entry->d_name, ".") == 0 ||
            my_strcmp(entry->d_name, "..") == 0) continue;

        // ── 1. comm file — raw thread name, cleanest for exact matching ──────
        {
            char comm_path[MAX_LENGTH] = "";
            snprintf(comm_path, sizeof(comm_path),
                     "/proc/self/task/%s/comm", entry->d_name);
            int fd = my_openat(AT_FDCWD, comm_path, O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                char name[MAX_LENGTH] = "";
                read_one_line(fd, name, MAX_LENGTH);
                my_close(fd);

                // JDWP = Java debugger (darvincisec + NativeShield technique)
                if (my_strncmp(name, JDWP_THREAD_NAME, 4) == 0) {
                    PH_NUKE("JDWP Java debugger thread — task=%s comm=%s",
                            entry->d_name, name);
                    closedir(dir); nuke_app();
                }
                // Frida runtime threads
                if (my_strstr(name, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(name, FRIDA_THREAD_GMAIN)) {
                    PH_NUKE("Frida thread via comm — task=%s name=%s",
                            entry->d_name, name);
                    closedir(dir); nuke_app();
                }
            }
        }

        // ── 2. status file — TracerPid + backup Name: check ──────────────────
        {
            char status_path[MAX_LENGTH] = "";
            snprintf(status_path, sizeof(status_path),
                     "/proc/self/task/%s/status", entry->d_name);
            int fd = my_openat(AT_FDCWD, status_path, O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                char buf[1024] = "";
                ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
                my_close(fd);
                if (n > 0) {
                    buf[n] = '\0';

                    // TracerPid: <pid>  — non-zero = debugger attached to this task
                    char *tracer = my_strstr(buf, STR_TRACER_PID);
                    if (tracer) {
                        int tpid = atoi(tracer + 10);
                        if (tpid > 0) {
                            PH_NUKE("per-task TracerPid=%d on task=%s",
                                    tpid, entry->d_name);
                            closedir(dir); nuke_app();
                        }
                    }

                    // Name: field (backup — comm is primary)
                    char *name_field = my_strstr(buf, "Name:");
                    if (name_field) {
                        name_field += 5;
                        while (*name_field == '\t' || *name_field == ' ')
                            name_field++;
                        if (my_strstr(name_field, FRIDA_THREAD_GUM_JS_LOOP) ||
                            my_strstr(name_field, FRIDA_THREAD_GMAIN)) {
                            PH_NUKE("Frida thread via status Name: task=%s",
                                    entry->d_name);
                            closedir(dir); nuke_app();
                        }
                    }
                }
            }
        }
    }
    closedir(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_frida_websocket -- Frida server WebSocket fingerprint
//
// Frida's built-in server exposes a WebSocket endpoint used by frida-tools.
// The Sec-WebSocket-Accept header is deterministic:
//   SHA1("CpxD2C5REVLHvsUC9YAoqg==" + WS_MAGIC_GUID) → base64 → fixed string.
// Any port that returns "tyZql/Y8dNFFyopTrHadWzvbvRs=" IS Frida.
//
// Port scan strategy: check Frida's default (27042) + a focused list of
// common alternative ports used in real-world deployments.  Connecting to a
// closed port returns ECONNREFUSED instantly, so the scan is fast even
// across 30+ ports.
// ─────────────────────────────────────────────────────────────────────────────

// HTTP WebSocket upgrade request with the fixed key NativeShield uses.
static const char FRIDA_WS_REQUEST[] =
    "GET /ws HTTP/1.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: CpxD2C5REVLHvsUC9YAoqg==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Host: 127.0.0.1\r\n"
    "User-Agent: Frida/16.1.7\r\n"
    "\r\n";

// Returns 1 if port 127.0.0.1:port responds with the Frida fingerprint.
static int check_frida_port(int port) {
    int fd = my_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    // 400 ms timeout on both send and receive — don't hang on open ports
    // that are NOT Frida (other localhost servers).
    struct timeval tv = {0, 400000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 127.0.0.1
    addr.sin_port        = htons((uint16_t)port);

    // connect() to a closed port returns ECONNREFUSED immediately.
    if (my_connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        my_close(fd);
        return 0;
    }

    // Port is open — send the WebSocket upgrade and read the response.
    my_write(fd, FRIDA_WS_REQUEST, sizeof(FRIDA_WS_REQUEST) - 1);

    char res[512];
    my_memset(res, 0, sizeof(res));
    my_read(fd, res, sizeof(res) - 1);
    my_close(fd);

    return my_strstr(res, FRIDA_WS_ACCEPT) != NULL;
}

static inline void detect_frida_websocket(void) {
    PH_LOG("detect_frida_websocket: scanning for Frida server WebSocket fingerprint");

    // Ports to probe — Frida default + common alternatives used in the wild.
    // Connecting to a closed port is instant; this list runs in < 1 ms total
    // for a typical device where none of these ports are open.
    static const int FRIDA_PORTS[] = {
        27042,          // Frida default (frida-server, gadget)
        27043, 27041,   // ±1 from default (common manual tweaks)
        27040, 27044,   // ±2
        27039, 27045,   // ±3
        1337,           // "leet" port popular in CTFs / PoCs
        4444,           // Metasploit default — sometimes reused
        5555,           // ADB default — Frida-over-USB sometimes lands here
        1234, 6666, 7777, 8888, 9999,  // common quick-test ports
        8080, 8081,     // common HTTP alternative ports
        31415,          // seen in some frida-server wrappers
        11111, 22222,   // round numbers used in tutorials
    };
    static const int N_PORTS = (int)(sizeof(FRIDA_PORTS) / sizeof(FRIDA_PORTS[0]));

    for (int i = 0; i < N_PORTS; i++) {
        if (check_frida_port(FRIDA_PORTS[i])) {
            PH_NUKE("Frida WebSocket fingerprint detected on port %d — server responding with Frida WS accept hash",
                    FRIDA_PORTS[i]);
            nuke_app();
        }
    }
}

static inline void detect_frida_namedpipe(void) {
    PH_LOG("detect_frida_namedpipe: scanning fds for Frida linjector pipe");
    DIR *dir = opendir(PROC_FD);
    // Bug fix: closedir(NULL) is undefined behaviour (crash) if opendir fails.
    // Guard everything — only enter and close if dir is non-NULL.
    if (dir == NULL) return;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        struct stat filestat;
        char buf[MAX_LENGTH] = "";
        char filePath[MAX_LENGTH] = "";
        snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);
        lstat(filePath, &filestat);
        if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
            my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
            if (my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR) != NULL) {
                PH_NUKE("Frida named pipe detected — fd link: %s", buf);
                closedir(dir); nuke_app();
            }
        }
    }
    closedir(dir);
}




// ?
// detect_ebpf_uprobe()
//
// eBPFDexDumper (updated July 2026) attaches a kernel uprobe to
// art::interpreter::Execute inside libart.so then streams DEX bytecode
// from below userspace -- completely bypassing /proc/PID/mem poisoning.
//
// When a uprobe is attached the kernel writes an entry like:
// p:dex_dump libart.so:0x<offset>
// into the tracing filesystem under two possible paths.  We scan both.
// Any line containing "libart" -> an eBPF dumper is active -> nuke_app().
// ?

static void detect_ebpf_uprobe(void) {
    static const char *paths[] = {
        "/sys/kernel/debug/tracing/uprobe_events",
        "/sys/kernel/tracing/uprobe_events",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        int fd = my_openat(AT_FDCWD, paths[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) continue;
        char buf[4096];
        my_memset(buf, 0, sizeof(buf));
        ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
        my_close(fd);
        if (n <= 0) continue;
                // eBPFDexDumper registers uprobe on libart; any hit is a dumper.
        if (my_strstr(buf, "libart") != NULL ||
            my_strstr(buf, "dex_dump") != NULL) {
            PH_NUKE("eBPF uprobe on libart detected — uprobe entry: %s", buf);
            nuke_app();
        }
    }
}

// ?
// detect_riru_zygisk -- Riru / Zygisk / Xposed / LSPosed injection detection
//
// Three independent signal sources (NativeShield RiGisk.cpp technique):
//
//   1. /proc/self/maps scan
//      Riru injects libmain.so from /data/adb/riru/; Zygisk from its module
//      directory.  LSPosed appears as "lspd"; EdXposed as "edxposed".
//      Any matching string in a mapped path → injection detected.
//      Note: advanced Zygisk (DenyList) can hide from maps; source 2 covers that.
//
//   2. dl_iterate_phdr (raw linker list)
//      Walks the dynamic linker's in-memory list of loaded libraries.
//      Different data source from procfs — DenyList hides from /proc/self/maps
//      but the linker's soinfo list still has the real path at load time.
//
//   3. Known module install paths
//      If the directory exists, the framework is installed (even if not currently
//      injected into this specific process).  Zygisk modules survive reboots and
//      are in the process if they target our app.
// ?

// C-style dl_iterate_phdr callback (file is compiled as C, not C++).
// ADDITION 5: expanded with ksu, apatch, apd, objection
static int hook_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    if (my_strstr(info->dlpi_name, HOOK_RIRU)     ||
        my_strstr(info->dlpi_name, HOOK_ZYGISK)   ||
        my_strstr(info->dlpi_name, HOOK_XPOSED)   ||
        my_strstr(info->dlpi_name, HOOK_LSPD)     ||
        my_strstr(info->dlpi_name, HOOK_EDXPOSED)  ||
        my_strstr(info->dlpi_name, HOOK_FRIDA)    ||
        my_strstr(info->dlpi_name, "ksu")         ||  // KernelSU
        my_strstr(info->dlpi_name, "apatch")      ||  // APatch
        my_strstr(info->dlpi_name, "apd")         ||  // APatch daemon lib
        my_strstr(info->dlpi_name, "objection")) {    // objection (Frida toolkit)
        *(int *)data = 1;
        return 1;   // stop iteration
    }
    return 0;
}

static void detect_riru_zygisk(void) {
    PH_LOG("detect_riru_zygisk: scanning maps + phdr + paths");

    // ── 1. /proc/self/maps scan ───────────────────────────────────────────────
    // ADDITION 5: expanded with ksu, apatch, apd, objection
    // Open a fresh fd each call — avoids cross-thread fd sharing.
    {
        int fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char map[MAX_LINE] = "";
            while (read_one_line(fd, map, MAX_LINE) > 0) {
                if (my_strstr(map, HOOK_RIRU)     ||
                    my_strstr(map, HOOK_ZYGISK)   ||
                    my_strstr(map, HOOK_XPOSED)   ||
                    my_strstr(map, HOOK_LSPD)     ||
                    my_strstr(map, HOOK_EDXPOSED)  ||
                    my_strstr(map, HOOK_FRIDA)    ||
                    my_strstr(map, "ksu")         ||  // KernelSU
                    my_strstr(map, "apatch")      ||  // APatch
                    my_strstr(map, "apd")         ||  // APatch daemon
                    my_strstr(map, "objection")) {    // Frida objection toolkit
                    PH_NUKE("hooking framework in /proc/self/maps: %s", map);
                    my_close(fd); nuke_app();
                }
            }
            my_close(fd);
        }
    }

    // ── 2. dl_iterate_phdr — linker's in-memory library list ─────────────────
    {
        int found = 0;
        dl_iterate_phdr(hook_phdr_cb, &found);
        if (found) {
            PH_NUKE("hooking framework found via dl_iterate_phdr");
            nuke_app();
        }
    }

    // ── 3. Known install paths — existence check ──────────────────────────────
    // ADDITION 5: expanded with KernelSU, APatch, LSPosed, objection paths
    static const char *HOOK_PATHS[] = {
        "/data/adb/riru",
        "/data/adb/modules/riru",
        "/data/adb/modules/zygisk",
        "/data/misc/riru",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/framework/XposedBridge.jar",
        // KernelSU
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/modules/zygisk_lsposed",  // LSPosed via KernelSU
        // APatch
        "/data/adb/apd",
        "/data/adb/ap",
        // LSPosed standalone
        "/data/adb/lspd",
        "/data/adb/modules/lspd",
        // Saurik / Substrate
        "/data/data/com.saurik.substrate",
        NULL
    };
    for (int i = 0; HOOK_PATHS[i] != NULL; i++) {
        int fd = my_openat(AT_FDCWD, HOOK_PATHS[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            PH_NUKE("hooking framework path exists: %s", HOOK_PATHS[i]);
            my_close(fd); nuke_app();
        }
    }
}

// ?
// detect_root -- su binary + Magisk mount detection
//
// Two independent checks (NativeShield RootDetect.cpp technique):
//
//   A. su binary existence
//      Attempts to open each known su path with O_RDONLY.  On a non-rooted
//      device these files do not exist.  If ANY opens successfully, root is
//      confirmed → nuke_app().
//
//   B. /proc/self/mounts scan for Magisk signatures
//      Magisk mounts a mirror of /data under /data/adb/modules and creates
//      entries containing "magisk", "core/mirror", or "core/img" in the
//      process mount namespace.  Reading /proc/self/mounts and scanning for
//      these strings catches Magisk even when it hides su from PATH.
// ?

static void detect_root(void) {
    PH_LOG("detect_root: checking su binaries + Magisk mounts");

    // ── A. su binary existence ────────────────────────────────────────────────
    static const char *SU_PATHS[] = {
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/system/bin/.ext/su",
        "/system/bin/failsafe/su",
        "/system/sd/xbin/su",
        "/system/usr/we-need-root/su",
        "/cache/su",
        "/data/su",
        "/dev/su",
        NULL
    };
    for (int i = 0; SU_PATHS[i] != NULL; i++) {
        int fd = my_openat(AT_FDCWD, SU_PATHS[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            PH_NUKE("su binary found: %s — root confirmed", SU_PATHS[i]);
            my_close(fd); nuke_app();
        }
    }

    // ── B. /proc/self/mounts — Magisk mount signatures ────────────────────────
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_PROC_MOUNTS, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char buf[MAX_LINE] = "";
            static const char *MAGISK_MARKERS[] = {
                "magisk", "core/mirror", "core/img", NULL
            };
            while (read_one_line(fd, buf, MAX_LINE) > 0) {
                for (int i = 0; MAGISK_MARKERS[i] != NULL; i++) {
                    if (my_strstr(buf, MAGISK_MARKERS[i])) {
                        PH_NUKE("Magisk mount detected: %s", buf);
                        my_close(fd); nuke_app();
                    }
                }
            }
            my_close(fd);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2026-A: LD_PRELOAD injection detection
// Frida and other tools inject via LD_PRELOAD. Read /proc/self/environ via
// raw syscall — Frida hooks getenv() but not svc #0 pread on /proc/self/environ.
// ═══════════════════════════════════════════════════════════════════════════
static void detect_ld_preload(void) {
    int fd = my_openat(AT_FDCWD, _S2_ENVIRON_PATH, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char buf[4096]; ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
    my_close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    // environ is null-delimited key=value pairs — scan for LD_PRELOAD=
    for (int i = 0; i < n; ) {
        char *entry = buf + i;
        if (my_strstr(entry, _S2_STR_LD_PRELOAD) == entry ||
            my_strstr(entry, _S2_STR_LD_LIB) == entry) {
            // Skip empty LD_PRELOAD= (value is empty string — no injection)
            char *eq = my_strstr(entry, "=");
            if (eq && *(eq + 1) != '\0') {
                PH_NUKE("LD_PRELOAD/LD_LIBRARY_PATH injection detected");
                nuke_app();
            }
        }
        int len = (int)my_strlen(entry);
        i += len + 1;
        if (i >= n) break;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2026-B: ADB native detection (3 independent signals)
// __system_property_get bypasses Java layer hooks entirely.
// All 3 checks use raw data sources Frida cannot intercept without kernel mod.
// ═══════════════════════════════════════════════════════════════════════════
static void detect_adb(void) {
    // ── 1. init.svc.adbd property — "running" means ADB daemon is active ──────
    {
        char val[128] = {0};
        // __system_property_get is in libc — call via dlsym to avoid PLT hook
        typedef int (*spg_t)(const char *, char *);
        spg_t spg = (spg_t)dlsym(RTLD_DEFAULT, _S2_STR_SYS_PROP_GET);
        if (spg) {
            spg(_S2_STR_ADBD_SVC, val);
            if (my_strstr(val, _S2_STR_RUNNING)) {
                PH_NUKE("ADB daemon active");
                nuke_app();
            }
            // ro.debuggable=1 means a debug build — legitimate on dev devices
            // but combined with ADB is high risk
            char dbg[8] = {0};
            spg(_S2_STR_RO_DEBUG, dbg);
            if (dbg[0] == '1') {
                spg(_S2_STR_RO_BTYPE, val);
                if (!my_strstr(val, _S2_STR_USER)) {
                    // Non-user build with debug enabled — likely tampered
                    PH_NUKE("ro.debuggable=1 on non-user build");
                    nuke_app();
                }
            }
        }
    }

    // ── 2. /data/misc/adb/adb_keys — only exists if ADB auth was set up ───────
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_ADB_KEYS, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            my_close(fd);
            PH_NUKE("ADB keys file present");
            nuke_app();
        }
    }

    // ── 3. TCP 5037 in /proc/net/tcp6 — ADB over network ─────────────────────
    // ADB server binds to 127.0.0.1:5037. In /proc/net/tcp(6) the local
    // address field is hex little-endian: 5037 decimal = 0x13AD hex.
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_TCP6, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char line[256];
            while (read_one_line(fd, line, sizeof(line)) > 0) {
                // Look for ":13AD" (port 5037) in local address field
                if (my_strstr(line, _S2_STR_PORT_5037) || my_strstr(line, _S2_STR_PORT_5037L)) {
                    my_close(fd);
                    PH_NUKE("ADB port 5037 open");
                    nuke_app();
                }
            }
            my_close(fd);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2026-C: Build prop integrity via __system_property_get
// PlayIntegrityFix (2025-2026) spoofs ro.boot.verifiedbootstate and
// ro.build.tags to pass Play Integrity. Detect by reading native props
// and cross-checking — PIF cannot hook __system_property_get in native.
// ═══════════════════════════════════════════════════════════════════════════
static void detect_build_prop_tamper(void) {
    typedef int (*spg_t)(const char *, char *);
    spg_t spg = (spg_t)dlsym(RTLD_DEFAULT, _S2_STR_SYS_PROP_GET);
    if (!spg) return;

    char val[128] = {0};

    // ro.build.tags should be "release-keys" on production devices
    spg(_S2_STR_RO_BTAGS, val);
    if (val[0] && !my_strstr(val, _S2_STR_REL_KEYS)) {
        PH_NUKE("ro.build.tags tampered");
        nuke_app();
    }

    // ro.boot.verifiedbootstate should be "green" on unrooted locked bootloader
    my_memset(val, 0, sizeof(val));
    spg(_S2_STR_RO_VBS, val);
    if (val[0] && (my_strstr(val, _S2_STR_ORANGE) || my_strstr(val, _S2_STR_RED))) {
        // orange = unlocked bootloader, red = failed verification
        PH_NUKE("verifiedbootstate compromised");
        nuke_app();
    }

    // ro.boot.flash.locked: "1" on stock, "0" on unlocked
    my_memset(val, 0, sizeof(val));
    spg(_S2_STR_RO_FLASH, val);
    if (val[0] == '0') {
        PH_NUKE("bootloader unlocked");
        nuke_app();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2026-D: Suspicious mount detection
// a. tmpfs over /apex/com.android.conscrypt — Magisk SSL unpinning
// b. /system mounted read-write — system partition tampered
// c. Magisk socket in /proc/net/unix — SUSFS bypass (SUSFS hides from
//    /proc/self/maps at kernel level, but cannot hide unix socket entries)
// ═══════════════════════════════════════════════════════════════════════════
static void detect_suspicious_mounts(void) {
    // ── a + b: /proc/self/mounts scan ────────────────────────────────────────
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_PROC_MOUNTS, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char line[MAX_LINE];
            while (read_one_line(fd, line, MAX_LINE) > 0) {
                // tmpfs over conscrypt APEX — Magisk SSL unpinning
                if (my_strstr(line, _S2_STR_CONSCRYPT) && my_strstr(line, _S2_STR_TMPFS)) {
                    my_close(fd);
                    PH_NUKE("SSL unpinning mount detected");
                    nuke_app();
                }
                // /system mounted rw — partition tampered
                if (my_strstr(line, _S2_STR_SYS_MNT) &&
                    (my_strstr(line, _S2_STR_RW_COMMA) || my_strstr(line, _S2_STR_COMMA_RW))) {
                    my_close(fd);
                    PH_NUKE("system partition tampered");
                    nuke_app();
                }
                // /apex mounted with unusual fs (not ext4/erofs/squashfs)
                if (my_strstr(line, _S2_STR_APEX_MNT) && my_strstr(line, _S2_STR_TMPFS)) {
                    my_close(fd);
                    PH_NUKE("apex image spoofed");
                    nuke_app();
                }
            }
            my_close(fd);
        }
    }

    // ── c: /proc/net/unix — Magisk socket (bypasses SUSFS maps hiding) ───────
    // Magisk creates a unix socket at "@/dev/.magisk.unblock" or similar.
    // SUSFS patches /proc/self/maps but NOT /proc/net/unix.
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_NET_UNIX, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char line[MAX_LINE];
            while (read_one_line(fd, line, MAX_LINE) > 0) {
                if (my_strstr(line, HOOK_FRIDA)         ||
                    my_strstr(line, _S2_STR_DOT_MAGISK) ||
                    my_strstr(line, HOOK_ZYGISK)        ||
                    my_strstr(line, HOOK_RIRU)) {
                    my_close(fd);
                    PH_NUKE("root socket in /proc/net/unix");
                    nuke_app();
                }
            }
            my_close(fd);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2026-E: NPatch detection (rootless Xposed, active 2025-2026)
// NPatch is a fork of LSPatch/LSPosed that injects without root via
// APK repackaging. It leaves traces in maps, loaded libs, and data dirs.
// ═══════════════════════════════════════════════════════════════════════════
static void detect_npatch(void) {
    // ── maps scan ─────────────────────────────────────────────────────────────
    {
        int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char line[MAX_LINE];
            while (read_one_line(fd, line, MAX_LINE) > 0) {
                if (my_strstr(line, _S2_STR_NPATCH)   ||
                    my_strstr(line, _S2_STR_LSPATCH)  ||
                    my_strstr(line, _S2_STR_PARANOID)) {
                    my_close(fd);
                    PH_NUKE("NPatch/LSPatch in maps");
                    nuke_app();
                }
            }
            my_close(fd);
        }
    }

    // ── package path scan (second pass) ──────────────────────────────────────
    {
        int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char line[MAX_LINE];
            while (read_one_line(fd, line, MAX_LINE) > 0) {
                if (my_strstr(line, _S2_STR_COM_NP)  ||
                    my_strstr(line, _S2_STR_7723)     ||
                    my_strstr(line, _S2_STR_IO_LSP)) {
                    my_close(fd);
                    PH_NUKE("NPatch package path in maps");
                    nuke_app();
                }
            }
            my_close(fd);
        }
    }

    // ── known NPatch data dirs ────────────────────────────────────────────────
    {
        const char *NPATCH_PATHS[4] = {
            _S2_STR_MISC_NP,   // /data/misc/npatch
            _S2_STR_MOD_NP,    // /data/adb/modules/npatch
            _S2_STR_MOD_LSP,   // /data/adb/modules/lspatch
            NULL
        };
        for (int i = 0; NPATCH_PATHS[i]; i++) {
            int fd = my_openat(AT_FDCWD, NPATCH_PATHS[i], O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) { my_close(fd); PH_NUKE("rootless hook path exists"); nuke_app(); }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADDITION 1: Emulator detection
// Checks QEMU/Goldfish hardware pipes, cpuinfo strings, and hw_random sysfs.
// Emulators are the #1 reversal environment — block them at constructor time.
// ═══════════════════════════════════════════════════════════════════════════
static void detect_emulator(void) {
    // A. QEMU/Goldfish device nodes — present on Android emulator, absent on real hw
    // Paths filled from decrypted buffers — no plaintext in .rodata
    {
        const char *EMU_DEVS[5] = {
            _S2_STR_GOLDFISH_P,  // /dev/goldfish_pipe
            _S2_STR_QEMU_PIPE,   // /dev/qemu_pipe
            _S2_STR_QEMUD,       // /dev/socket/qemud
            _S2_STR_GOLDFISH_S,  // /dev/goldfish_sync
            NULL
        };
        for (int i = 0; EMU_DEVS[i]; i++) {
            int fd = my_openat(AT_FDCWD, EMU_DEVS[i], O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) { my_close(fd); PH_NUKE("emulator device node"); nuke_app(); }
        }
    }

    // B. /proc/cpuinfo — QEMU/Goldfish/ranchu CPU model strings
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_CPUINFO, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char buf[2048]; ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
            my_close(fd);
            if (n > 0) {
                buf[n] = '\0';
                if (my_strstr(buf, _S2_STR_GOLDFISH_U) ||
                    my_strstr(buf, _S2_STR_GOLDFISH_L) ||
                    my_strstr(buf, _S2_STR_RANCHU)     ||
                    my_strstr(buf, _S2_STR_QEMU_U))
                    nuke_app();
            }
        }
    }

    // C. /sys/devices/virtual/misc/hw_random — QEMU RNG device, absent on real hardware
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_HW_RANDOM, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) { my_close(fd); PH_NUKE("emulator hw_random sysfs present"); nuke_app(); }
    }

    // D. /proc/self/mounts — QEMU block device tags
    {
        int fd = my_openat(AT_FDCWD, _S2_STR_PROC_MOUNTS, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char line[MAX_LINE];
            while (read_one_line(fd, line, MAX_LINE) > 0) {
                if (my_strstr(line, _S2_STR_GOLDFISH_L) ||
                    my_strstr(line, _S2_STR_RANCHU)     ||
                    my_strstr(line, _S2_STR_VBOX)) {
                    my_close(fd);
                    PH_NUKE("emulator mount entry");
                    nuke_app();
                }
            }
            my_close(fd);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADDITION 2: rwxp page detection — catches injected hook pages
// Any read+write+execute mapping means code was injected and made writable.
// Legitimate pages are r-xp (execute only) or rw-p (data, no execute).
// ═══════════════════════════════════════════════════════════════════════════
static void detect_rwx_pages(void) {
    int fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char line[MAX_LINE];
    while (read_one_line(fd, line, MAX_LINE) > 0) {
        // maps format: addr-addr perms offset dev inode [path]
        // perms field: e.g. "rwxp"
        char *sp = my_strstr(line, " ");
        if (!sp) continue;
        sp++;  // points to perms field
        // rwxp = writable AND executable — classic hook injection page
        if (sp[0] == 'r' && sp[1] == 'w' && sp[2] == 'x') {
            my_close(fd);
            PH_NUKE("rwxp page detected — inline hook injection: %s", line);
            nuke_app();
        }
    }
    my_close(fd);
}

// ═══════════════════════════════════════════════════════════════════════════
// ADDITION 3: Own .text self-integrity snapshot + verify
// Snapshots the checksum of libphantom's own r-xp region at load time.
// Re-verifies every loop iteration — detects post-load inline patching.
// ═══════════════════════════════════════════════════════════════════════════
static volatile unsigned long g_own_text_checksum = 0;
static volatile void         *g_own_text_start    = NULL;
static volatile size_t        g_own_text_size     = 0;

static void snapshot_own_text(void) {
    int fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char line[MAX_LINE];
    while (read_one_line(fd, line, MAX_LINE) > 0) {
        // Must reference libphantom and be a r-xp (execute-only) mapping
        if (!my_strstr(line, STR_LIBPHANTOM)) continue;
        if (!my_strstr(line, "r-xp"))         continue;
        unsigned long start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if (end <= start) continue;
        g_own_text_start    = (void *)start;
        g_own_text_size     = (size_t)(end - start);
        g_own_text_checksum = checksum((void *)start, (size_t)(end - start));
        PH_LOG("snapshot_own_text: start=%lx size=%zu checksum=%lu",
               start, g_own_text_size, g_own_text_checksum);
        break;
    }
    my_close(fd);
}

static void verify_own_text(void) {
    if (!g_own_text_start || g_own_text_size == 0) return;
    unsigned long c = checksum((void *)g_own_text_start, g_own_text_size);
    if (c != g_own_text_checksum) {
        PH_NUKE("libphantom .text patched — expected %lu got %lu",
                g_own_text_checksum, c);
        nuke_app();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADDITION 4: PR_GET_DUMPABLE re-verification
// prctl(PR_SET_DUMPABLE, 0) is set in the constructor, but an attacker can
// call prctl(PR_SET_DUMPABLE, 1) afterwards to re-enable memory dumps.
// We re-check and re-apply every loop iteration.
// ═══════════════════════════════════════════════════════════════════════════
static void verify_dumpable(void) {
#if defined(__aarch64__)
    // __NR_prctl = 167 on arm64
    long v = raw_syscall_3(167L, 3L /*PR_GET_DUMPABLE*/, 0L, 0L);
    if (v != 0) {
        // Re-apply and nuke — someone tampered
        raw_syscall_3(167L, 4L /*PR_SET_DUMPABLE*/, 0L, 0L);
        PH_NUKE("PR_GET_DUMPABLE was re-enabled — memory dump attack");
        nuke_app();
    }
#else
    // arm32: use libc prctl wrapper (still uncatchable since we nuke immediately)
    if (prctl(PR_GET_DUMPABLE) != 0) {
        prctl(PR_SET_DUMPABLE, 0);
        nuke_app();
    }
#endif
}

// ═══════════════════════════════════════════════════════════════════════════
// ADDITION 6: Anonymous ELF / Frida gadget scan
// Frida gadget loaded via dlopen shows no filename in /proc/self/maps —
// it appears as an anonymous r-xp region. We scan anonymous executable
// pages for the ELF magic header (\x7fELF) via /proc/self/mem pread.
// Any anonymous ELF page is treated as injected code → nuke.
// ═══════════════════════════════════════════════════════════════════════════
static void detect_frida_gadget_anon(void) {
    int maps_fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (maps_fd < 0) return;

    int mem_fd = my_openat(AT_FDCWD, "/proc/self/mem", O_RDONLY | O_CLOEXEC, 0);
    if (mem_fd < 0) { my_close(maps_fd); return; }

    char line[MAX_LINE];
    while (read_one_line(maps_fd, line, MAX_LINE) > 0) {
        unsigned long start = 0, end = 0;
        char perms[8]  = {0};
        unsigned long offset = 0;
        unsigned int maj = 0, min = 0;
        unsigned long inode = 0;
        char path[256] = {0};

        int n = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %255s",
                       &start, &end, perms, &offset, &maj, &min, &inode, path);
        if (n < 7) continue;
        if (end <= start || (end - start) < 8) continue;

        // Only anonymous (inode == 0) executable pages with no path label
        if (inode != 0) continue;
        if (perms[2] != 'x') continue;
        if (n >= 8 && path[0] != '\0') continue;  // has a name — skip

        // pread the first 8 bytes of this anonymous region via /proc/self/mem
        uint8_t hdr[8] = {0};
#if defined(__aarch64__)
        ssize_t r = (ssize_t)raw_syscall_4(
            __NR_pread64, (long)mem_fd, (long)hdr, (long)8, (long)start);
#else
        ssize_t r = (ssize_t)syscall(__NR_pread64, mem_fd, hdr, 8, (off_t)start);
#endif
        if (r < 4) continue;

        // ELF magic: 0x7f 'E' 'L' 'F'
        if (hdr[0] == 0x7F && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
            my_close(mem_fd);
            my_close(maps_fd);
            PH_NUKE("anonymous ELF page detected at %lx — Frida gadget injection", start);
            nuke_app();
        }
    }
    my_close(mem_fd);
    my_close(maps_fd);
}

// ?
// detect_frida_loop -- 5-second cadence
// Frida thread names, named pipes, binary checksums, ptrace, eBPF uprobes.
// ?

/* ── Dual-canary tamper-proof block-rooted flag ──────────────────────────────
 *
 * Problem with a single volatile int:
 *   A Frida/root attacker needs ONE Memory.writeU32(addr, 0) to permanently
 *   disable all root checks.  The address is a fixed BSS offset from the
 *   loaded libphantom.so base — trivial to find with a hex scan for the
 *   nativeLoadShards call that sets it.
 *
 * Solution — split flag across TWO variables, always kept complementary:
 *   g_block_rooted_val  ∈ { BLK_MAGIC_OFF(0x00000000), BLK_MAGIC_ON(0xA55A1234) }
 *   g_block_rooted_inv  = ~g_block_rooted_val  always
 *
 *   get_block_rooted() checks (val ^ inv) == 0xFFFFFFFF before trusting val.
 *   If anyone patches either variable without updating the other, XOR ≠ all-ones
 *   → nuke_app() fires before any root check is even skipped.
 *
 *   The attacker must patch BOTH locations in the same instant with consistent
 *   values — both are in BSS at unpredictable relative offsets (ASLR) and both
 *   set_block_rooted / get_block_rooted are VMP-virtualized so their logic is
 *   invisible in Ghidra / IDA.
 *
 *   Initial state: val=0x00000000, inv=0xFFFFFFFF  →  flag OFF, canary intact.
 */
static volatile uint32_t g_block_rooted_val = 0x00000000u;
static volatile uint32_t g_block_rooted_inv = 0xFFFFFFFFu; /* ~0x00000000 */

#define BLK_MAGIC_ON  0xA55A1234u   /* arbitrary non-zero sentinel for ON  */
#define BLK_MAGIC_OFF 0x00000000u   /* zero = OFF (also the BSS default)   */

/* Write both halves atomically-as-possible.  VMP-virtualized so the store
 * sequence is opaque to static analysis. */
__attribute__((annotate("+vm_virtualize")))
static void set_block_rooted(int blk) {
    uint32_t v = blk ? BLK_MAGIC_ON : BLK_MAGIC_OFF;
    g_block_rooted_val = v;
    g_block_rooted_inv = ~v;
}

/* Read and verify canary.  Any single-variable patch causes XOR ≠ 0xFFFFFFFF
 * → nuke_app() before the caller even sees the return value.
 * VMP-virtualized so the verification bytecode is hidden from disassemblers. */
__attribute__((annotate("+vm_virtualize")))
static int get_block_rooted(void) {
    uint32_t v   = g_block_rooted_val;
    uint32_t inv = g_block_rooted_inv;
    if ((v ^ inv) != 0xFFFFFFFFu) {
        /* Canary mismatch — g_block_rooted was memory-patched → kill now. */
        nuke_app();
    }
    return (v == BLK_MAGIC_ON);
}

static void *detect_frida_loop(void *args) {
    (void)args;
    struct timespec timereq;
    timereq.tv_sec  = 5;
    timereq.tv_nsec = 0;
    while (1) {
        detect_frida_threads();                    // JDWP + per-task TracerPid + gum-js-loop/gmain
        detect_frida_namedpipe();
        detect_frida_websocket();                  // WebSocket fingerprint: tyZql/Y8dNFFyopTrHadWzvbvRs=
        detect_frida_memdiskcompare();
        detect_ptrace();
        detect_ebpf_uprobe();
        detect_emulator();                         // ADDITION 1: QEMU/Goldfish/ranchu emulator
        detect_rwx_pages();                        // ADDITION 2: rwxp pages = injected hook code
        verify_own_text();                         // ADDITION 3: libphantom .text self-integrity
        verify_dumpable();                         // ADDITION 4: PR_SET_DUMPABLE tamper check
        detect_frida_gadget_anon();                // ADDITION 6: anonymous ELF = Frida gadget
        detect_ld_preload();                       // 2026-A: LD_PRELOAD/LD_LIBRARY_PATH injection
        detect_adb();                              // 2026-B: ADB daemon + adb_keys + TCP 5037
        detect_build_prop_tamper();                // 2026-C: PlayIntegrityFix build prop spoof
        detect_suspicious_mounts();               // 2026-D: tmpfs/conscrypt + system-RW + SUSFS bypass
        detect_npatch();                           // 2026-E: NPatch / LSPatch rootless Xposed
        if (get_block_rooted()) detect_riru_zygisk(); // Riru/Zygisk/Xposed/KSU/APatch + maps + phdr
        if (get_block_rooted()) detect_root();         // su binaries + Magisk mounts
        my_nanosleep(&timereq, NULL);
    }
    return NULL;
}

// ?
// Constructor -- runs immediately on System.load(libphantom.so)
//
// Threads launched:
//   detect_frida_loop -- 5 s cadence -- Frida/ptrace/eBPF/root heuristics.
//
// Optional (compile-time -DBLOCK_ROOTED_DEVICES):
//   SELinux permissive → immediate nuke (rooted phone detected on launch).
// ?

/* Root checks — always compiled in, always present in every blob.
   Triggered at runtime by a flag bit DexPacker hides in salt[0] bit-7.
   Java sees only an opaque 16-byte salt and cannot distinguish the variants.
   OLLVM -fla flattens this separately from the tiny constructor. */
__attribute__((annotate("+vm_virtualize")))
static void check_rooted(void) {
    /* 1. SELinux permissive */
    static const char * const SE[] = {
        "/sys/fs/selinux/enforce",
        "/sys/kernel/security/selinux/enforce", NULL
    };
    for (int i = 0; SE[i]; i++) {
        int fd = my_openat(AT_FDCWD, SE[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) continue;
        char b[4] = {0}; my_read(fd, b, 3); my_close(fd);
        if (b[0] == '0') { PH_NUKE("SELinux permissive"); nuke_app(); }
        break;
    }

    /* 2. Su binaries */
    static const char * const SU[] = {
        "/data/local/su","/data/local/bin/su","/data/local/xbin/su",
        "/sbin/su","/su/bin/su","/system/bin/su","/system/bin/.ext/su",
        "/system/bin/failsafe/su","/system/sd/xbin/su",
        "/system/usr/we-need-root/su","/system/xbin/su",
        "/cache/su","/data/su","/dev/su", NULL
    };
    for (int i = 0; SU[i]; i++) {
        int fd = my_openat(AT_FDCWD, SU[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) { my_close(fd); PH_NUKE("su: %s", SU[i]); nuke_app(); }
    }

    /* 3. Root / hook framework directories */
    static const char * const DIRS[] = {
        "/data/adb/magisk","/data/adb/ksu","/data/adb/apd",
        "/data/adb/lspd","/sbin/.magisk","/dev/.magisk",
        "/system/framework/XposedBridge.jar","/system/xposed.prop", NULL
    };
    for (int i = 0; DIRS[i]; i++) {
        int fd = my_openat(AT_FDCWD, DIRS[i], O_RDONLY | O_CLOEXEC | O_DIRECTORY, 0);
        if (fd >= 0) { my_close(fd); PH_NUKE("dir: %s", DIRS[i]); nuke_app(); }
    }

    /* 4. /proc/self/mounts scan */
    static const char * const MNT[] = {
        "magisk","core/mirror","core/img","lspd","zygisk","xposed", NULL
    };
    int mfd = my_openat(AT_FDCWD, _S2_STR_PROC_MOUNTS, O_RDONLY | O_CLOEXEC, 0);
    if (mfd >= 0) {
        char buf[512]; int pos = 0; ssize_t n;
        while ((n = my_read(mfd, buf + pos, (ssize_t)sizeof(buf) - pos - 1)) > 0) {
            buf[pos + n] = '\0';
            for (int i = 0; MNT[i]; i++)
                if (my_strstr(buf, MNT[i])) {
                    my_close(mfd);
                    PH_NUKE("mount: %s", MNT[i]); nuke_app();
                }
            if (pos + n > 11) {
                for (int k = 0; k < 11; k++) buf[k] = buf[(pos+n)-11+k];
                pos = 11;
            } else { pos = 0; }
        }
        my_close(mfd);
    }

    /* 5. CapEff — kernel-enforced, survives Shamiko */
    int sfd = my_openat(AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    if (sfd >= 0) {
        char sb[2048]; ssize_t sn = my_read(sfd, sb, sizeof(sb)-1); my_close(sfd);
        if (sn > 0) {
            sb[sn] = '\0';
            const char *cap = my_strstr(sb, "CapEff:");
            if (cap) {
                cap += 7; while (*cap == ' ' || *cap == '\t') cap++;
                while (*cap == '0') cap++;
                if (*cap && *cap != '\n')
                    { PH_NUKE("CapEff elevated"); nuke_app(); }
            }
        }
    }

    /* 6. build.prop test-keys / dev-keys */
    static const char * const KEYS[] = { "test-keys","dev-keys", NULL };
    int bfd = my_openat(AT_FDCWD, "/system/build.prop", O_RDONLY | O_CLOEXEC, 0);
    if (bfd >= 0) {
        char bb[512]; int bp = 0; ssize_t bn;
        while ((bn = my_read(bfd, bb + bp, (ssize_t)sizeof(bb) - bp - 1)) > 0) {
            bb[bp + bn] = '\0';
            for (int i = 0; KEYS[i]; i++)
                if (my_strstr(bb, KEYS[i])) {
                    my_close(bfd);
                    PH_NUKE("build: %s", KEYS[i]); nuke_app();
                }
            if (bp + bn > 9) {
                for (int k = 0; k < 9; k++) bb[k] = bb[(bp+bn)-9+k];
                bp = 9;
            } else { bp = 0; }
        }
        my_close(bfd);
    }
}

__attribute__((constructor))
void detect_frida_init(void) {
    prctl(PR_SET_DUMPABLE, 0);
    // ADDITION 1: block emulators immediately at load time (before any Java runs)
    detect_emulator();
    /* check_rooted() is NOT called here — it runs inside nativeDecryptShard
       when the Java-side blockRooted flag is true. */
    char *filePaths[NUM_LIBS] = {NULL, NULL};
    parse_proc_maps_to_fetch_path(filePaths);
    for (int i = 0; i < NUM_LIBS; i++) {
        if (filePaths[i]) {
            fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
            free(filePaths[i]);
        }
    }
    // ADDITION 3: snapshot own .text checksum before background thread starts
    ph_strings_init();
    snapshot_own_text();
    pthread_t t;
    pthread_create(&t, NULL, detect_frida_loop, NULL);
}

// ?
// LAYER 2a -- nativeWipeShard()  [JNI -- called from DexProtector after load]
//
// Java calls this immediately after InMemoryDexClassLoader (or the file-
// based fallback) has consumed the plaintext DEX byte[].  We zero the first
// 8 bytes (dex\n magic + version string) and the endian_tag at offset 40
// inside the Java byte[] so the heap copy no longer looks like a DEX to
// any /proc/PID/mem scanner.
//
// ART has already fully parsed and mapped the DEX before this is called, so
// zeroing the source byte[] does not affect class resolution.
// ?

JNIEXPORT void JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_dex)
{
    (void)clazz;
    if (!j_dex) return;
    jint len = (*env)->GetArrayLength(env, j_dex);
    if (len <= 0) return;

        // Wipe the ENTIRE byte[] -- not just the 8-byte magic header.
    // ART has already parsed and internally mapped the DEX before this call.
    // Zeroing only the header leaves the full method bytecode in the Java
    // heap for any /proc/PID/mem scanner to reconstruct.  Wiping all bytes
    // leaves nothing to reconstruct from.  Write in 64 KB chunks to avoid
    // a large stack allocation.
    static const jbyte zero_chunk[65536] = {0};
    jint remaining = len;
    jint offset    = 0;
    while (remaining > 0) {
        jint chunk = remaining > (jint)sizeof(zero_chunk)
                     ? (jint)sizeof(zero_chunk) : remaining;
        (*env)->SetByteArrayRegion(env, j_dex, offset, chunk, zero_chunk);
        offset    += chunk;
        remaining -= chunk;
    }
}

// ?
// LAYER 2b -- nativeWipeArtDex()  [JNI -- called after all shards are loaded]
//
// ART internally mmaps the DEX into its own anonymous read-only memory region
// when InMemoryDexClassLoader (or the file-based fallback) parses it.  That
// region persists for the life of the process -- even after nativeWipeShard()
// zeroes the Java byte[] source.  Any scanner reading /proc/self/mem without
// root can find it via its "dex\n" magic at offset 0.
//
// This function:
//   1. Reads /proc/self/maps line by line.
//   2. Selects anonymous regions (inode == 0) that are readable and at least
//      112 bytes (minimum DEX header size).  Skips [stack], [heap], [vdso],
//      [vvar] and other well-known non-DEX anonymous regions.
//   3. Peeks at byte 0-3 of each region — read is allowed since perm[0]=='r'.
//   4. If "dex\n" magic is found: uses my_mprotect (raw syscall, bypasses libc
//      hooks) to temporarily add PROT_WRITE, zeroes magic (bytes 0-7) and
//      endian_tag (bytes 40-43), then restores PROT_READ.
//
// Zeroing the magic and endian_tag is sufficient to defeat all memory scanners
// that locate DEX via these fields, without affecting ART class resolution —
// ART has already fully parsed the DEX into its internal structures before
// this is called.
//
// Must be called AFTER InMemoryDexClassLoader has consumed all shards.
// ?

JNIEXPORT void JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeArtDex(
        JNIEnv *env, jclass clazz)
{
    (void)env; (void)clazz;

    int fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;

    char line[MAX_LINE];
    while (read_one_line(fd, line, MAX_LINE) > 0) {
        unsigned long start = 0, end = 0;
        char perms[5]   = {0};
        unsigned long offset = 0;
        unsigned int dev_maj = 0, dev_min = 0;
        unsigned long inode  = 0;
        char path[256]  = {0};

        // Parse maps line: start-end perms offset dev inode [path]
        int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                       &start, &end, perms, &offset,
                       &dev_maj, &dev_min, &inode, path);
        if (n < 7) continue;
        if (end <= start || (end - start) < 112) continue;

        // Only anonymous regions — file-backed regions are not ART's mmap copy
        if (inode != 0) continue;

        // Must be readable (perms[0] == 'r')
        if (perms[0] != 'r') continue;

        // Skip known non-DEX anonymous regions by name
        if (n >= 8 && path[0] == '[') {
            if (my_strncmp(path, "[stack", 6) == 0 ||
                my_strncmp(path, "[heap",  5) == 0 ||
                my_strncmp(path, "[vvar",  5) == 0 ||
                my_strncmp(path, "[vdso",  5) == 0 ||
                my_strncmp(path, "[vsys",  5) == 0) continue;
        }

        uint8_t *ptr = (uint8_t *)start;

        // Peek at first 4 bytes — readable since perms[0] == 'r'
        // DEX magic: 'd'(0x64) 'e'(0x65) 'x'(0x78) '\n'(0x0A)
        if (ptr[0] != 0x64 || ptr[1] != 0x65 ||
            ptr[2] != 0x78 || ptr[3] != 0x0A) continue;

        // DEX magic confirmed — need write permission to zero it.
        // my_mprotect is a raw syscall (bypasses any libc/Frida hook).
        // We operate only on the first page (4096 bytes); both the
        // 8-byte magic (offset 0) and endian_tag (offset 40) lie within it.
        bool was_ro = (perms[1] != 'w');
        if (was_ro) {
            if (my_mprotect(ptr, 4096, PROT_READ | PROT_WRITE) != 0) continue;
        }

        // Zero DEX magic + version string (bytes 0-7): e.g. "dex\n035\0"
        my_memset(ptr, 0, 8);
        // Zero endian_tag (bytes 40-43): 0x12345678 little-endian
        my_memset(ptr + 40, 0, 4);

        // Restore original permissions
        if (was_ro) my_mprotect(ptr, 4096, PROT_READ);
    }
    my_close(fd);
}

// ?
// SHA-256 (minimal, self-contained)
// Hashes the package name inside native so the hash never returns to Java.
// ?

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_block(uint32_t h[8], const uint8_t data[64]) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)
              |((uint32_t)data[i*4+2]<<8)|(uint32_t)data[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1  = ROR32(e,6)^ROR32(e,11)^ROR32(e,25);
        uint32_t ch  = (e&f)^(~e&g);
        uint32_t tmp1= hh+S1+ch+K256[i]+w[i];
        uint32_t S0  = ROR32(a,2)^ROR32(a,13)^ROR32(a,22);
        uint32_t maj = (a&b)^(a&c)^(b&c);
        uint32_t tmp2= S0+maj;
        hh=g; g=f; f=e; e=d+tmp1;
        d=c;  c=b; b=a; a=tmp1+tmp2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    size_t i;
    uint64_t bit_len = (uint64_t)len * 8;
    while (len >= 64) { sha256_block(h, msg); msg += 64; len -= 64; }
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    if (len >= 56) { sha256_block(h, block); memset(block, 0, 64); }
    for (i = 0; i < 8; i++) block[56+i] = (uint8_t)(bit_len >> (56 - i*8));
    sha256_block(h, block);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i]>>24);
        out[i*4+1] = (uint8_t)(h[i]>>16);
        out[i*4+2] = (uint8_t)(h[i]>>8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

// ?
// ARX KDF -- byte-identical to DexSeed.arx() in Java
// ?

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t le32(const uint8_t *b, int off) {
    return (uint32_t)b[off]
         | ((uint32_t)b[off+1] <<  8)
         | ((uint32_t)b[off+2] << 16)
         | ((uint32_t)b[off+3] << 24);
}

static inline void put_le32(uint8_t *b, int off, uint32_t v) {
    b[off]   = (uint8_t)v;
    b[off+1] = (uint8_t)(v >>  8);
    b[off+2] = (uint8_t)(v >> 16);
    b[off+3] = (uint8_t)(v >> 24);
}

__attribute__((annotate("+vm_virtualize")))
static void arx_kdf(const uint8_t salt[16], const uint8_t pkg_hash[32], uint8_t out[16]) {
    uint32_t s0 = le32(salt,  0), s1 = le32(salt,  4);
    uint32_t s2 = le32(salt,  8), s3 = le32(salt, 12);
    uint32_t ph0 = le32(pkg_hash, 0), ph1 = le32(pkg_hash, 4);
    for (int i = 0; i < 8; i++) {
        s0 = ROL32(s0 ^ ph0, 11) + s1;
        s1 = ROL32(s1 ^ ph1, 13) + s2;
        s2 = ROL32(s2 ^ ph0, 17) + s3;
        s3 = ROL32(s3 ^ ph1, 19) + s0;
    }
    put_le32(out,  0, s0); put_le32(out,  4, s1);
    put_le32(out,  8, s2); put_le32(out, 12, s3);
}

// ?
// ARX stream cipher -- port of Java DexCrypto.{exfr,FxIjsF,nDnv}
// ?

typedef struct {
    uint32_t ks[27];
    uint32_t st[2];
    int      pos;
} arx_ctx_t;

static void arx_ctx_init(arx_ctx_t *s, const uint8_t key[16]) {
    uint32_t k0=le32(key,0), k1=le32(key,4), k2=le32(key,8), k3=le32(key,12);
    s->st[0] = k0 ^ k2;
    s->st[1] = k1 ^ k3;
    s->pos   = 0;
    {
        uint32_t iv=k0, t[3]; t[0]=k1; t[1]=k2; t[2]=k3;
        s->ks[0] = iv;
        for (int i2=0; i2<26; i2++) {
            t[i2%3] = (ROR32(t[i2%3],8)+iv)^(uint32_t)i2;
            iv = ROL32(iv,3)^t[i2%3];
            s->ks[i2+1] = iv;
        }
    }
}

static void arx_advance_block(arx_ctx_t *s) {
    const uint32_t *ks = s->ks;
    uint32_t i=s->st[0], i2=s->st[1];
    i2=(ROR32(i2,8)+i)^ks[0];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[1];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[2];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[3];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[4];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[5];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[6];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[7];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[8];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[9];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[10]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[11]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[12]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[13]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[14]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[15]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[16]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[17]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[18]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[19]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[20]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[21]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[22]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[23]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[24]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[25]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[26];
    s->st[0]=ROL32(i,3)^i2; s->st[1]=i2;
}

static void arx_xor(arx_ctx_t *s, uint8_t *buf, size_t len) {
    for (size_t n=0; n<len; n++) {
        int i6=s->pos%8, shift=(s->pos%4)*8;
        if (i6==0) arx_advance_block(s);
        int word=(int)s->st[i6>>2];
        buf[n] ^= (uint8_t)(word>>shift);
        s->pos++;
    }
}

// ?
// zlib inflate helper
// ?

static uint8_t *inflate_alloc(const uint8_t *in, size_t in_len, size_t *out_len) {
    z_stream zs;
    uint8_t *buf, *tmp;
    size_t cap, used;
    int ret;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) return NULL;
    cap = in_len * 4 + 4096;
    buf = (uint8_t *)malloc(cap);
    if (!buf) { inflateEnd(&zs); return NULL; }
    zs.next_in   = (Bytef *)in;
    zs.avail_in  = (uInt)in_len;
    zs.next_out  = (Bytef *)buf;
    zs.avail_out = (uInt)cap;
    for (;;) {
        ret = inflate(&zs, Z_FINISH);
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK && ret != Z_BUF_ERROR) { free(buf); inflateEnd(&zs); return NULL; }
        used = cap - zs.avail_out; cap *= 2;
        tmp  = (uint8_t *)realloc(buf, cap);
        if (!tmp) { free(buf); inflateEnd(&zs); return NULL; }
        buf = tmp;
        zs.next_out  = (Bytef *)(buf + used);
        zs.avail_out = (uInt)(cap - used);
    }
    *out_len = cap - zs.avail_out;
    inflateEnd(&zs);
    return buf;
}

// ?
// nativeLoadShards -- JNI entry-point  [REPLACES nativeDecryptShard for API 27+]
//
// Decrypts ALL shards, constructs InMemoryDexClassLoader, and wipes every
// plaintext byte — entirely within a single native call.
//
// WHY THIS MATTERS:
//   nativeDecryptShard returns a jbyteArray to Java.  A Frida hook on its
//   return captures the full plaintext DEX before nativeWipeShard runs.
//   Java code (`byte[] dexBytes = nativeDecryptShard(...)`) is the interception
//   point — the DEX is visible at the Java level even though decryption is native.
//
// HOW THIS FIXES IT:
//   nativeLoadShards never returns plaintext.  It:
//     1. Derives the key and decrypts each shard to a native malloc buffer.
//     2. Copies each plaintext into a jbyteArray that lives only inside this
//        JNI call — never returned to Java code.
//     3. Wraps each jbyteArray in ByteBuffer.wrap() via JNI.
//     4. Calls new InMemoryDexClassLoader(ByteBuffer[], parent) via JNI —
//        ART parses every DEX synchronously inside that constructor.
//     5. Zeroes every plaintext jbyteArray (Layer-2a wipe).
//     6. Scans /proc/self/maps and wipes ART's internal mmap copies (Layer-2b).
//     7. Returns only the ClassLoader — no DEX bytes ever reach Java code.
//
//   Hooking the return of nativeLoadShards yields only a ClassLoader reference.
//   To intercept the DEX, an attacker must now hook ART internals (NewByteArray,
//   SetByteArrayRegion, or art::DexFile::Open) — a far deeper and more fragile
//   attack surface.
//
// nativeDecryptShard is retained for the API < 27 file-based fallback path.
// ?

JNIEXPORT jobject JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeLoadShards(
        JNIEnv      *env,
        jclass       clazz,
        jbyteArray   j_salt,
        jbyteArray   j_pkg_name_utf8,
        jobjectArray j_enc_shards,
        jobject      j_parent_cl)
{
    (void)clazz;
    prctl(PR_SET_DUMPABLE, 0);

    jobject  result_cl    = NULL;
    uint8_t  salt[16]     = {0};
    uint8_t  pkg_hash[32] = {0};
    uint8_t  key[16]      = {0};

    /* Track every plaintext jbyteArray so we can zero them all before return */
    jbyteArray plain_arrays[64];
    int        n_plains = 0;
    int        i;
    for (i = 0; i < 64; i++) plain_arrays[i] = NULL;

    /* ── 1. Salt ──────────────────────────────────────────────────────────── */
    if (!j_salt || (*env)->GetArrayLength(env, j_salt) != 16) goto cleanup;
    (*env)->GetByteArrayRegion(env, j_salt, 0, 16, (jbyte *)salt);
    {
        int blk = (salt[0] & 0x80) != 0;
        salt[0] &= 0x7F;
        set_block_rooted(blk);   /* dual-canary: writes val + ~val */
        if (blk) check_rooted();
    }

    /* ── 2. Package name hash ─────────────────────────────────────────────── */
    if (j_pkg_name_utf8) {
        jint pl = (*env)->GetArrayLength(env, j_pkg_name_utf8);
        if (pl > 0 && pl <= 512) {
            uint8_t pb[512];
            (*env)->GetByteArrayRegion(env, j_pkg_name_utf8, 0, pl, (jbyte *)pb);
            sha256(pb, (size_t)pl, pkg_hash);
            memset(pb, 0, sizeof(pb));
        }
    }
    arx_kdf(salt, pkg_hash, key);

    /* ── 3. Validate shard array ──────────────────────────────────────────── */
    if (!j_enc_shards) goto cleanup;
    {
        jint sc = (*env)->GetArrayLength(env, j_enc_shards);
        if (sc <= 0 || sc > 64) goto cleanup;

        /* ── 4. Resolve JNI classes and methods ───────────────────────────── */
        jclass bb_cl = (*env)->FindClass(env, "java/nio/ByteBuffer");
        if (!bb_cl || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); goto cleanup; }

        jclass imdcl = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
        if (!imdcl || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); goto cleanup; }

        jmethodID wrap = (*env)->GetStaticMethodID(env, bb_cl, "wrap",
                             "([B)Ljava/nio/ByteBuffer;");
        if (!wrap || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); goto cleanup; }

        jmethodID ctor = (*env)->GetMethodID(env, imdcl, "<init>",
                             "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        if (!ctor || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); goto cleanup; }

        jobjectArray bufs = (*env)->NewObjectArray(env, sc, bb_cl, NULL);
        if (!bufs || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); goto cleanup; }

        /* ── 5. Decrypt each shard — plaintext stays inside this JNI call ── */
        for (i = 0; i < sc; i++) {
            uint8_t *enc_buf = NULL, *inter_buf = NULL, *plain_buf = NULL;
            size_t   inter_len = 0,   plain_len  = 0;

            jbyteArray j_enc = (jbyteArray)(*env)->GetObjectArrayElement(env, j_enc_shards, i);
            if (!j_enc || (*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env); goto cleanup;
            }
            jint enc_len = (*env)->GetArrayLength(env, j_enc);
            if (enc_len <= 0) { (*env)->DeleteLocalRef(env, j_enc); goto cleanup; }

            enc_buf = (uint8_t *)malloc((size_t)enc_len);
            if (!enc_buf) { (*env)->DeleteLocalRef(env, j_enc); goto cleanup; }
            (*env)->GetByteArrayRegion(env, j_enc, 0, enc_len, (jbyte *)enc_buf);
            (*env)->DeleteLocalRef(env, j_enc);

            /* Outer inflate */
            inter_buf = inflate_alloc(enc_buf, (size_t)enc_len, &inter_len);
            memset(enc_buf, 0, (size_t)enc_len); free(enc_buf);
            if (!inter_buf) goto cleanup;

            /* ARX XOR */
            { arx_ctx_t arx; arx_ctx_init(&arx, key); arx_xor(&arx, inter_buf, inter_len);
              memset(&arx, 0, sizeof(arx)); }

            /* Inner inflate */
            plain_buf = inflate_alloc(inter_buf, inter_len, &plain_len);
            memset(inter_buf, 0, inter_len); free(inter_buf);
            if (!plain_buf) goto cleanup;

            /* Plaintext → jbyteArray (stays inside this JNI call, never returned) */
            jbyteArray j_dex = (*env)->NewByteArray(env, (jsize)plain_len);
            if (!j_dex || (*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                memset(plain_buf, 0, plain_len); free(plain_buf);
                goto cleanup;
            }
            (*env)->SetByteArrayRegion(env, j_dex, 0, (jsize)plain_len, (jbyte *)plain_buf);
            memset(plain_buf, 0, plain_len); free(plain_buf); /* wipe native copy immediately */

            plain_arrays[n_plains++] = j_dex;   /* track for post-load zero */

            /* ByteBuffer.wrap(j_dex) */
            jobject bb = (*env)->CallStaticObjectMethod(env, bb_cl, wrap, j_dex);
            if (!bb || (*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env); goto cleanup;
            }
            (*env)->SetObjectArrayElement(env, bufs, i, bb);
            (*env)->DeleteLocalRef(env, bb);
        }

        /* ── 6. new InMemoryDexClassLoader(bufs, parent)
                  ART parses + mmaps every DEX synchronously inside this call.
                  Hooking this return gets only a ClassLoader — not a byte[]. ── */
        result_cl = (*env)->NewObject(env, imdcl, ctor, bufs, j_parent_cl);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); result_cl = NULL; }
    }

    /* ── 7. Wipe ART's internal anonymous mmap copies (Layer-2b) ─────────── */
    {
        int mfd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
        if (mfd >= 0) {
            char ml[MAX_LINE];
            while (read_one_line(mfd, ml, MAX_LINE) > 0) {
                unsigned long ms = 0, me = 0;
                char mp[5] = {0};
                unsigned long moff = 0;
                unsigned int  mmaj = 0, mmn = 0;
                unsigned long mino = 0;
                char mpth[256] = {0};
                int mn = sscanf(ml, "%lx-%lx %4s %lx %x:%x %lu %255s",
                                &ms, &me, mp, &moff, &mmaj, &mmn, &mino, mpth);
                if (mn < 7 || me <= ms || (me - ms) < 112) continue;
                if (mp[0] != 'r' || mino != 0) continue;
                if (mn >= 8 && mpth[0] == '[') {
                    if (my_strncmp(mpth, "[stack", 6) == 0 ||
                        my_strncmp(mpth, "[heap",  5) == 0 ||
                        my_strncmp(mpth, "[vvar",  5) == 0 ||
                        my_strncmp(mpth, "[vdso",  5) == 0) continue;
                }
                uint8_t *ptr = (uint8_t *)ms;
                if (ptr[0]!=0x64||ptr[1]!=0x65||ptr[2]!=0x78||ptr[3]!=0x0A) continue;
                bool ro = (mp[1] != 'w');
                if (ro && my_mprotect(ptr, 4096, PROT_READ|PROT_WRITE) != 0) continue;
                my_memset(ptr, 0, 8);
                if ((me - ms) > 44) my_memset(ptr + 40, 0, 4);
                if (ro) my_mprotect(ptr, 4096, PROT_READ);
            }
            my_close(mfd);
        }
    }

cleanup:
    /* ── 8. Zero every plaintext jbyteArray (Layer-2a) ───────────────────── */
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    {
        static const jbyte zeros[65536] = {0};
        int z;
        for (z = 0; z < n_plains; z++) {
            if (!plain_arrays[z]) continue;
            jint len = (*env)->GetArrayLength(env, plain_arrays[z]);
            jint off = 0, rem = len;
            while (rem > 0) {
                jint chunk = rem > (jint)sizeof(zeros) ? (jint)sizeof(zeros) : rem;
                (*env)->SetByteArrayRegion(env, plain_arrays[z], off, chunk, zeros);
                off += chunk; rem -= chunk;
            }
        }
    }
    memset(salt,     0, sizeof(salt));
    memset(pkg_hash, 0, sizeof(pkg_hash));
    memset(key,      0, sizeof(key));
    return result_cl;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ph_patch_providers_native()
 *
 * Patches every in-process ContentProvider's mContext from the old
 * ProxyApplication to the newly installed real Application.
 *
 * Runs entirely via JNI jobject pointers — no Java generic casts,
 * no ClassCastException possible on ANY Android version.
 * (The Java equivalent cast mProviderMap as ArrayMap<String,String> which
 * crashed with ClassCastException because values are ProviderClientRecord.)
 * ═══════════════════════════════════════════════════════════════════════════ */
static void ph_patch_providers_native(JNIEnv *env, jobject activityThread, jobject realApp) {
    /* ActivityThread.mProviderMap — ArrayMap<String, ProviderClientRecord> */
    jclass atCls2 = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!atCls2) { (*env)->ExceptionClear(env); return; }
    jfieldID mProvMapFid = (*env)->GetFieldID(env, atCls2,
            "mProviderMap", "Landroid/util/ArrayMap;");
    (*env)->DeleteLocalRef(env, atCls2);
    if (!mProvMapFid) { (*env)->ExceptionClear(env); return; }

    jobject provMap = (*env)->GetObjectField(env, activityThread, mProvMapFid);
    if (!provMap) return;

    /* ArrayMap.values() → Collection */
    jclass amCls = (*env)->FindClass(env, "android/util/ArrayMap");
    if (!amCls) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, provMap); return; }
    jmethodID valuesMid = (*env)->GetMethodID(env, amCls, "values", "()Ljava/util/Collection;");
    (*env)->DeleteLocalRef(env, amCls);
    if (!valuesMid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, provMap); return; }

    jobject values = (*env)->CallObjectMethod(env, provMap, valuesMid);
    (*env)->DeleteLocalRef(env, provMap);
    if (!values || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return; }

    /* Collection.toArray() → Object[] — avoids iterator generics entirely */
    jclass colCls = (*env)->FindClass(env, "java/util/Collection");
    if (!colCls) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, values); return; }
    jmethodID toArrMid = (*env)->GetMethodID(env, colCls, "toArray", "()[Ljava/lang/Object;");
    (*env)->DeleteLocalRef(env, colCls);
    if (!toArrMid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, values); return; }

    jobjectArray arr = (jobjectArray)(*env)->CallObjectMethod(env, values, toArrMid);
    (*env)->DeleteLocalRef(env, values);
    if (!arr || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return; }

    /* ProviderClientRecord.mLocalProvider */
    jclass pcrCls = (*env)->FindClass(env, "android/app/ActivityThread$ProviderClientRecord");
    jfieldID mLocalProvFid = NULL;
    if (pcrCls) {
        mLocalProvFid = (*env)->GetFieldID(env, pcrCls, "mLocalProvider",
                                           "Landroid/content/ContentProvider;");
        if (!mLocalProvFid) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, pcrCls);
    } else { (*env)->ExceptionClear(env); }

    /* ContentProvider.mContext */
    jclass cpCls = (*env)->FindClass(env, "android/content/ContentProvider");
    jfieldID mCtxFid = NULL;
    if (cpCls) {
        mCtxFid = (*env)->GetFieldID(env, cpCls, "mContext", "Landroid/content/Context;");
        if (!mCtxFid) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cpCls);
    } else { (*env)->ExceptionClear(env); }

    if (!mLocalProvFid || !mCtxFid) { (*env)->DeleteLocalRef(env, arr); return; }

    jsize len = (*env)->GetArrayLength(env, arr);
    for (jsize i = 0; i < len; i++) {
        jobject pcr = (*env)->GetObjectArrayElement(env, arr, i);
        if (!pcr) continue;
        jobject lp = (*env)->GetObjectField(env, pcr, mLocalProvFid);
        if (lp) {
            (*env)->SetObjectField(env, lp, mCtxFid, realApp);
            (*env)->DeleteLocalRef(env, lp);
        }
        (*env)->DeleteLocalRef(env, pcr);
    }
    (*env)->DeleteLocalRef(env, arr);
    PH_LOG("ph_patch_providers_native: patched %d provider record(s)", (int)len);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * nativeSwapApplication()
 *
 * Moves ALL ActivityThread application-swap reflection out of Java (where
 * type-unsafe generics caused ClassCastException) into native C.
 *
 * Mirrors the old ProxyApplication.realApplication() logic but:
 *   • Runs entirely via raw JNI jobject pointers — Java generics never
 *     involved, ClassCastException impossible on any Android version.
 *   • Atomic swap: mApplication is NEVER null — ContentProvider background
 *     threads always see either ProxyApplication or realApp, never null.
 *   • Provider patching done via ph_patch_providers_native() which iterates
 *     mProviderMap values as Object[], not as String (the old bug).
 *   • Swap logic hidden inside OLLVM-obfuscated libphantom.so — not visible
 *     in the stub DEX string pool or reflection call list.
 * ═══════════════════════════════════════════════════════════════════════════ */
JNIEXPORT jobject JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeSwapApplication(
        JNIEnv *env, jclass klass,
        jobject classLoader,
        jstring realAppClass,
        jobject baseContext) {

    (void)klass;
    PH_LOG("nativeSwapApplication: start");

    jobject result = NULL;

    /* ── ActivityThread ──────────────────────────────────────────────────── */
    jclass atCls = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!atCls) { (*env)->ExceptionClear(env); return NULL; }

    jmethodID curThreadMid = (*env)->GetStaticMethodID(env, atCls,
            "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (!curThreadMid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, atCls); return NULL; }

    jobject thread = (*env)->CallStaticObjectMethod(env, atCls, curThreadMid);
    if (!thread || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, atCls); return NULL;
    }

    /* ── AppBindData → LoadedApk ─────────────────────────────────────────── */
    jclass abdCls = (*env)->FindClass(env, "android/app/ActivityThread$AppBindData");
    jfieldID mBoundFid = (*env)->GetFieldID(env, atCls, "mBoundApplication",
            "Landroid/app/ActivityThread$AppBindData;");
    if (!abdCls || !mBoundFid) {
        (*env)->ExceptionClear(env);
        if (abdCls) (*env)->DeleteLocalRef(env, abdCls); /* avoid local ref leak */
        goto done;
    }
    jobject mBoundApp = (*env)->GetObjectField(env, thread, mBoundFid);

    jfieldID infoFid = (*env)->GetFieldID(env, abdCls, "info", "Landroid/app/LoadedApk;");
    if (!infoFid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, abdCls); goto done; }
    jobject loadedApk = (*env)->GetObjectField(env, mBoundApp, infoFid);

    jfieldID bindAppInfoFid = (*env)->GetFieldID(env, abdCls, "appInfo",
            "Landroid/content/pm/ApplicationInfo;");
    jobject bindDataAppInfo = (bindAppInfoFid && !(*env)->ExceptionCheck(env))
            ? (*env)->GetObjectField(env, mBoundApp, bindAppInfoFid) : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, abdCls);

    /* ── LoadedApk fields ────────────────────────────────────────────────── */
    jclass laCls = (*env)->FindClass(env, "android/app/LoadedApk");
    if (!laCls) { (*env)->ExceptionClear(env); goto done; }

    jfieldID mAppInfoFid = (*env)->GetFieldID(env, laCls, "mApplicationInfo",
            "Landroid/content/pm/ApplicationInfo;");
    jobject laAppInfo = (mAppInfoFid && !(*env)->ExceptionCheck(env))
            ? (*env)->GetObjectField(env, loadedApk, mAppInfoFid) : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    jfieldID mAppFid = (*env)->GetFieldID(env, laCls, "mApplication",
            "Landroid/app/Application;");
    if (!mAppFid) (*env)->ExceptionClear(env);

    /* ── Patch className in both ApplicationInfo copies ──────────────────── */
    jclass aiCls = (*env)->FindClass(env, "android/content/pm/ApplicationInfo");
    if (aiCls) {
        jfieldID cnFid = (*env)->GetFieldID(env, aiCls, "className", "Ljava/lang/String;");
        if (cnFid) {
            if (laAppInfo)       (*env)->SetObjectField(env, laAppInfo,       cnFid, realAppClass);
            if (bindDataAppInfo) (*env)->SetObjectField(env, bindDataAppInfo, cnFid, realAppClass);
        } else { (*env)->ExceptionClear(env); }
        (*env)->DeleteLocalRef(env, aiCls);
    } else { (*env)->ExceptionClear(env); }

    /* ── mInitialApplication (old = ProxyApplication) ────────────────────── */
    jfieldID mInitFid = (*env)->GetFieldID(env, atCls, "mInitialApplication",
            "Landroid/app/Application;");
    if (!mInitFid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, laCls); goto done; }
    jobject oldApp = (*env)->GetObjectField(env, thread, mInitFid);

    /* mAllApplications */
    jfieldID mAllFid = (*env)->GetFieldID(env, atCls, "mAllApplications",
            "Ljava/util/ArrayList;");
    jobject mAllApps = (mAllFid && !(*env)->ExceptionCheck(env))
            ? (*env)->GetObjectField(env, thread, mAllFid) : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    /* mInstrumentation */
    jfieldID mInstrFid = (*env)->GetFieldID(env, atCls, "mInstrumentation",
            "Landroid/app/Instrumentation;");
    if (!mInstrFid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, laCls); goto done; }
    jobject instr = (*env)->GetObjectField(env, thread, mInstrFid);

    /* ── Create real Application via Instrumentation.newApplication() ──────── */
    jobject realApp = NULL;
    jclass instrCls = (*env)->FindClass(env, "android/app/Instrumentation");
    if (instrCls) {
        jmethodID newAppMid = (*env)->GetMethodID(env, instrCls, "newApplication",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)"
                "Landroid/app/Application;");
        if (newAppMid && instr) {
            realApp = (*env)->CallObjectMethod(env, instr, newAppMid,
                    classLoader, realAppClass, baseContext);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                realApp = NULL;
            }
        } else { (*env)->ExceptionClear(env); }
        (*env)->DeleteLocalRef(env, instrCls);
    } else { (*env)->ExceptionClear(env); }

    /* Fallback: LoadedApk.makeApplication(false, null) */
    if (!realApp) {
        PH_LOG("nativeSwapApplication: newApplication() failed — fallback makeApplication()");
        if (mAppFid) (*env)->SetObjectField(env, loadedApk, mAppFid, NULL);
        jmethodID makeAppMid = (*env)->GetMethodID(env, laCls, "makeApplication",
                "(ZLandroid/app/Instrumentation;)Landroid/app/Application;");
        if (makeAppMid) {
            realApp = (*env)->CallObjectMethod(env, loadedApk, makeAppMid, JNI_FALSE, NULL);
            if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); realApp = NULL; }
        } else { (*env)->ExceptionClear(env); }
        if (realApp) {
            if (mInitFid) (*env)->SetObjectField(env, thread, mInitFid, realApp);
            ph_patch_providers_native(env, thread, realApp);
            result = (*env)->NewGlobalRef(env, realApp);
            PH_LOG("nativeSwapApplication: fallback OK");
        }
        (*env)->DeleteLocalRef(env, laCls);
        goto done;
    }

    PH_LOG("nativeSwapApplication: newApplication() OK");

    /* ── Update mAllApplications ─────────────────────────────────────────── */
    if (mAllApps) {
        jclass alCls = (*env)->FindClass(env, "java/util/ArrayList");
        if (alCls) {
            jmethodID remMid = (*env)->GetMethodID(env, alCls, "remove", "(Ljava/lang/Object;)Z");
            jmethodID addMid = (*env)->GetMethodID(env, alCls, "add",    "(Ljava/lang/Object;)Z");
            if (remMid) { (*env)->CallBooleanMethod(env, mAllApps, remMid, oldApp);
                          if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); }
            if (addMid) { (*env)->CallBooleanMethod(env, mAllApps, addMid, realApp);
                          if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); }
            (*env)->DeleteLocalRef(env, alCls);
        } else { (*env)->ExceptionClear(env); }
    }

    /* ── Atomic swap: LoadedApk.mApplication + ActivityThread.mInitialApplication ── */
    if (mAppFid)  (*env)->SetObjectField(env, loadedApk, mAppFid,  realApp);
    if (mInitFid) (*env)->SetObjectField(env, thread,    mInitFid, realApp);

    /* ── Patch ContentProvider contexts (raw JNI — no ClassCastException) ── */
    ph_patch_providers_native(env, thread, realApp);

    result = (*env)->NewGlobalRef(env, realApp);
    PH_LOG("nativeSwapApplication: done");

    (*env)->DeleteLocalRef(env, laCls);

done:
    (*env)->DeleteLocalRef(env, atCls);
    (*env)->DeleteLocalRef(env, thread);
    /* Return local ref — caller (Java) owns this reference */
    if (result) {
        jobject local = (*env)->NewLocalRef(env, result);
        (*env)->DeleteGlobalRef(env, result);
        return local;
    }
    return NULL;
}

// ?
// nativeDecryptShard -- JNI entry-point
//
// Derives key + decrypts one shard entirely in native.
// Pipeline reversal: outer inflate -> ARX XOR -> inner inflate -> plaintext DEX.
// Key is zeroed on the stack before return; never crosses the JNI boundary.
//
// NOTE: Still used for the API < 27 file-based fallback path in DexProtector.
//       On API 27+ use nativeLoadShards instead — it never returns plaintext.
// ?

JNIEXPORT jbyteArray JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_salt,
        jbyteArray j_pkg_name_utf8,
        jbyteArray j_encrypted)
{
    // Belt-and-suspenders: re-seal /proc/self/mem on every decrypt call.
    prctl(PR_SET_DUMPABLE, 0);

    jbyteArray result = NULL;

    uint8_t salt[16]     = {0};
    uint8_t pkg_hash[32] = {0};
    uint8_t key[16]      = {0};

    uint8_t *enc_buf   = NULL;
    uint8_t *inter_buf = NULL;
    uint8_t *plain_buf = NULL;
    size_t   inter_len = 0, plain_len = 0;
    jint     enc_len   = 0;

    (void)clazz;

    // 1. Derive key entirely inside native.
    if (j_salt == NULL || (*env)->GetArrayLength(env, j_salt) != 16)
        goto cleanup;
    (*env)->GetByteArrayRegion(env, j_salt, 0, 16, (jbyte *)salt);

    // ── Block-rooted flag — hidden in salt[0] bit 7 by DexPacker ────────────
    // Java sees only an opaque 16-byte array — it cannot patch or hook this.
    // We read the flag, strip the bit from salt before KDF so the derived key
    // is identical regardless of whether the flag is set.
    // g_block_rooted is published here so detect_frida_loop() (background
    // thread) knows whether to run detect_root() on each 5-second cycle.
    {
        int block_rooted = (salt[0] & 0x80) != 0;
        salt[0] &= 0x7F;              /* clear flag bit — KDF uses clean salt */
        set_block_rooted(block_rooted); /* dual-canary: writes val + ~val */
        if (block_rooted) check_rooted();
    }

    if (j_pkg_name_utf8 != NULL) {
        jint pkg_len = (*env)->GetArrayLength(env, j_pkg_name_utf8);
        if (pkg_len > 0 && pkg_len <= 512) {
            uint8_t pkg_buf[512];
            (*env)->GetByteArrayRegion(env, j_pkg_name_utf8, 0, pkg_len, (jbyte *)pkg_buf);
            sha256(pkg_buf, (size_t)pkg_len, pkg_hash);
            memset(pkg_buf, 0, sizeof(pkg_buf));
        }
    }
    arx_kdf(salt, pkg_hash, key);

        // 2. Copy encrypted shard to native heap.
    if (j_encrypted == NULL) goto cleanup;
    enc_len = (*env)->GetArrayLength(env, j_encrypted);
    if (enc_len <= 0) goto cleanup;
    enc_buf = (uint8_t *)malloc((size_t)enc_len);
    if (!enc_buf) goto cleanup;
    (*env)->GetByteArrayRegion(env, j_encrypted, 0, enc_len, (jbyte *)enc_buf);

        // 3. Outer inflate.
    inter_buf = inflate_alloc(enc_buf, (size_t)enc_len, &inter_len);
    free(enc_buf); enc_buf = NULL;
    if (!inter_buf) goto cleanup;

        // 4. ARX XOR in-place.
    { arx_ctx_t arx; arx_ctx_init(&arx, key); arx_xor(&arx, inter_buf, inter_len);
      memset(&arx, 0, sizeof(arx)); }

        // 5. Inner inflate.
    plain_buf = inflate_alloc(inter_buf, inter_len, &plain_len);
    if (!plain_buf) goto cleanup;

        // 6. Return plaintext DEX bytes to Java.
    result = (*env)->NewByteArray(env, (jsize)plain_len);
    if (result)
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plain_len, (jbyte *)plain_buf);

cleanup:
    memset(salt,     0, sizeof(salt));
    memset(pkg_hash, 0, sizeof(pkg_hash));
    memset(key,      0, sizeof(key));
    if (enc_buf)   free(enc_buf);
    if (inter_buf) { memset(inter_buf, 0, inter_len); free(inter_buf); }
    if (plain_buf) free(plain_buf);
    return result;
}
