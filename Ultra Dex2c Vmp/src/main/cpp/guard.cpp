// guard.cpp — Native integrity layer for Dex2c-protected APKs, disguised
// under generic "font metrics" naming (class/method/asset names, exported
// symbols) so static analysis of the shipped .so and APK does not surface
// an obvious "guard"/anti-tamper signature.
//
// Compiled into every protected .so alongside Dex2C_impl.cpp.
// Entry points:
//   fonts_init()        — __attribute__((constructor)), fires when .so loads
//                         BEFORE JNI_OnLoad, BEFORE any Java code.
//                         Pure native — no JNIEnv required:
//                           • Anti-debug (TracerPid from /proc/self/status)
//                           • VCore/VirtualApp APK-path detection
//                           • AndroidManifest.xml FNV-1a64 hash check
//                           • classes*.dex count check
//                           • /proc/self/maps scan (Frida/Xposed/Substrate/Magisk/saurik/
//                                                   LSPlant/Zygisk/Riru/LSPatch)
//                           • libart.so / libandroid_runtime.so path integrity
//                           • Frida listener port 27042 probe
//                           • Fork-based isolated background guard process (5 s poll)
//                           • Persistent watchdog thread (3 s poll)
//                         All native checks encoded as VM bytecode so IDA/Ghidra
//                         sees an opaque interpreter loop, not recognisable call sites.
//   fonts_apply_metrics() — called from JNI_OnLoad (direct or injected).
//                         Has JNIEnv. Runs killer detection via detached retry
//                         thread, waiting until an Activity is on-stack so
//                         PairIP and other Application subclasses finish first.
//                         Does:
//                           • Behavioral ContentProvider ↔ lifecycle callback cross-ref
//                           • Known killer-class detection via Class.forName
//                           • Renaming-resistant fragment scan of declared providers

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>
#include <android/log.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <math.h>
#include <sys/syscall.h>
#include "guard_mba.h"   // MBA constant helpers — hides raw literals from binary

#define G_TAG "D2CG"
// FONTS_DEBUG_LOG is OFF by default (production/shipping builds) — in that
// mode every GLOGI/GLOGE/CRASH_HERE call compiles away to nothing, so no log
// tag, format string, or reason text ends up in the shipped .so at all.
// Define FONTS_DEBUG_LOG (build flag) to get full step-by-step tracing on
// `adb logcat -s D2CG` for diagnosing false positives — remove it again
// before shipping a real protected build.
#ifdef FONTS_DEBUG_LOG
#define GLOGI(...) __android_log_print(ANDROID_LOG_INFO,  G_TAG, __VA_ARGS__)
#define GLOGE(...) __android_log_print(ANDROID_LOG_ERROR, G_TAG, __VA_ARGS__)
// Production CRASH_HERE: reason string is a macro argument — kept alive only
// when FONTS_DEBUG_LOG is defined. In release builds the token vanishes from
// the preprocessor output so no string literal reaches .rodata.
#define CRASH_HERE(reason) do { GLOGE("CRASH: %s (%s:%d)", (reason), __FILE__, __LINE__); crash_now(); } while (0)
#else
#define GLOGI(...) ((void)0)
#define GLOGE(...) ((void)0)
// Production build: CRASH_HERE becomes a bare crash_now(). The reason string
// literal is not even a token in the expanded code, so it cannot appear in
// .rodata regardless of optimisation level. No plaintext crash description
// survives into the shipped .so.
#define CRASH_HERE(reason) crash_now()
#endif

// ════════════════════════════════════════════════════════════════════════════
// AES tables — shared by the AES-256-CBC decryption below
// ════════════════════════════════════════════════════════════════════════════

static const uint8_t G_SBOX[256] = {
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t G_RSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const uint8_t G_RCON[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t gf_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) ? 0x1b : 0)); }
static uint8_t gf_mul(uint8_t x, uint8_t y) {
    return (uint8_t)(
        ((y & 1) ? x : 0) ^
        ((y & 2) ? gf_xtime(x) : 0) ^
        ((y & 4) ? gf_xtime(gf_xtime(x)) : 0) ^
        ((y & 8) ? gf_xtime(gf_xtime(gf_xtime(x))) : 0) ^
        ((y & 16)? gf_xtime(gf_xtime(gf_xtime(gf_xtime(x)))) : 0));
}

// ════════════════════════════════════════════════════════════════════════════
// AES-256-CBC Decryption — 14 rounds, 32-byte key, 240 bytes of round keys
// ════════════════════════════════════════════════════════════════════════════

typedef struct { uint8_t rk[240]; } AES256;

static void aes256_expand(AES256 *a, const uint8_t *key) {
    memcpy(a->rk, key, 32);
    uint8_t *w = a->rk;
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, w + (i-1)*4, 4);
        if (i % 8 == 0) {
            uint8_t tmp = G_SBOX[t[1]] ^ G_RCON[i/8];
            t[1] = G_SBOX[t[2]]; t[2] = G_SBOX[t[3]]; t[3] = G_SBOX[t[0]];
            t[0] = tmp;
        } else if (i % 8 == 4) {
            t[0]=G_SBOX[t[0]]; t[1]=G_SBOX[t[1]];
            t[2]=G_SBOX[t[2]]; t[3]=G_SBOX[t[3]];
        }
        uint8_t *dst = w + i*4, *src = w + (i-8)*4;
        dst[0]=src[0]^t[0]; dst[1]=src[1]^t[1];
        dst[2]=src[2]^t[2]; dst[3]=src[3]^t[3];
    }
}

static void aes256_dec_block(const AES256 *a, const uint8_t *in, uint8_t *out) {
    uint8_t s[16];
    const uint8_t *rk = a->rk + 224;   // 14 * 16
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int r = 13; r >= 0; r--) {
        rk -= 16;
        uint8_t t;
        t=s[13];s[13]=s[9];s[9]=s[5];s[5]=s[1];s[1]=t;
        t=s[10];s[10]=s[2];s[2]=t; t=s[14];s[14]=s[6];s[6]=t;
        t=s[3];s[3]=s[7];s[7]=s[11];s[11]=s[15];s[15]=t;
        for (int i = 0; i < 16; i++) s[i] = G_RSBOX[s[i]] ^ rk[i];
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t *col = s + c*4;
                uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
                col[0]=gf_mul(a0,0x0e)^gf_mul(a1,0x0b)^gf_mul(a2,0x0d)^gf_mul(a3,0x09);
                col[1]=gf_mul(a0,0x09)^gf_mul(a1,0x0e)^gf_mul(a2,0x0b)^gf_mul(a3,0x0d);
                col[2]=gf_mul(a0,0x0d)^gf_mul(a1,0x09)^gf_mul(a2,0x0e)^gf_mul(a3,0x0b);
                col[3]=gf_mul(a0,0x0b)^gf_mul(a1,0x0d)^gf_mul(a2,0x09)^gf_mul(a3,0x0e);
            }
        }
    }
    memcpy(out, s, 16);
}

static int aes256_cbc_dec(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *in, int in_len, uint8_t *out) {
    if (in_len <= 0 || in_len % 16 != 0) return -1;
    AES256 ctx; aes256_expand(&ctx, key);
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (int i = 0; i < in_len; i += 16) {
        aes256_dec_block(&ctx, in + i, out + i);
        for (int j = 0; j < 16; j++) out[i+j] ^= prev[j];
        memcpy(prev, in + i, 16);
    }
    int pad = out[in_len - 1];
    if (pad < 1 || pad > 16) return -1;
    return in_len - pad;
}

// ════════════════════════════════════════════════════════════════════════════
// AES Key + IV — split across volatile arrays (prevents static-analysis key
// extraction: attacker needs a live memory dump, not just strings/hexdump)
// KEY[i] = KEY_HI[i] ^ KEY_LO[i]
// ════════════════════════════════════════════════════════════════════════════

static volatile const uint8_t KEY_HI[16]={0xA1,0x2B,0x1C,0xF4,0x83,0x65,0xC0,0x31,0x57,0xD4,0xE9,0x28,0x15,0x8A,0x44,0x60};
static volatile const uint8_t KEY_LO[16]={0x72,0x61,0x67,0x65,0x46,0x4B,0x4F,0x51,0x43,0x6C,0x4A,0x74,0x6C,0x6C,0x69,0x6F};
// KEY_HI XOR KEY_LO = {D3,4A,7B,91,C5,2E,8F,60,14,B8,A3,5C,79,E6,2D,0F}

static volatile const uint8_t IV_HI[16]={0x27,0xE5,0x58,0x1D,0xD0,0x83,0xF7,0x64,0xA3,0x35,0xC1,0x78,0x82,0x13,0x6A,0x2E};
static volatile const uint8_t IV_LO[16]={0x69,0x69,0x69,0x67,0x65,0x71,0x61,0x69,0x6B,0x66,0x66,0x63,0x66,0x73,0x43,0x5B};
// IV_HI  XOR IV_LO  = {4E,8C,31,7A,B5,F2,96,0D,C8,53,A7,1B,E4,60,29,75}

static __attribute__((noinline)) void build_iv(uint8_t *iv) {
    // MBA: a^b = (a|b)-(a&b) — identical result, unrecognisable to decompilers
    for(int i=0;i<16;i++){
        uint32_t a=(uint32_t)IV_HI[i], b=(uint32_t)IV_LO[i];
        iv[i]=(uint8_t)((a|b)-(a&b));
    }
}

// ── AES-256 key extension (bytes 16-31): K2_HI[i] ^ K2_LO[i]
// K2_HI ^ K2_LO = {F7,23,A9,5E,8C,41,D6,BB,3E,9F,6C,17,A4,8B,E5,2C}
static volatile const uint8_t K2_HI[16]={
    0xA2,0x76,0xFC,0x0B,0xD9,0x14,0x83,0xEE,
    0x6B,0xCA,0x39,0x42,0xF1,0xDE,0xB0,0x79};
static volatile const uint8_t K2_LO[16]={
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};

static __attribute__((noinline)) void build_key256(uint8_t *key) {
    // MBA: a^b = (a|b)-(a&b)
    for(int i=0;i<16;i++){
        uint32_t a=(uint32_t)KEY_HI[i], b=(uint32_t)KEY_LO[i];
        key[i]    =(uint8_t)((a|b)-(a&b));
    }
    for(int i=0;i<16;i++){
        uint32_t a=(uint32_t)K2_HI[i],  b=(uint32_t)K2_LO[i];
        key[16+i] =(uint8_t)((a|b)-(a&b));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Crash — immediate SIGKILL, no JNI needed
// ════════════════════════════════════════════════════════════════════════════

// crash_now() — hard, synchronous, zero-hang kill.
//
// Why not kill(getpid(), SIGKILL):
//   kill() sends the signal to the process but delivery is asynchronous —
//   the kernel queues it and delivers it when the thread is next scheduled.
//   On a loaded device this causes a visible 1–4 s "hang" before death.
//
// Fix: tgkill(getpid(), gettid(), SIGKILL) via raw svc #0 (same Layer-4
// pattern used for all I/O).  tgkill targets THIS specific thread; the
// kernel delivers SIGKILL inline, before svc #0 even returns → zero hang.
//
// Fallback chain (compiler cannot remove any of these):
//   1. tgkill svc — instant SIGKILL to current thread
//   2. null dereference → SIGSEGV + tombstone (visible hard crash)
//   3. __builtin_trap() → SIGILL
//   4. _exit(1)
// crash_now() — hard, synchronous, zero-hang kill via SVC #0.
//
// All syscall numbers and SIGKILL (9) are computed at runtime through
// _mba_*() helpers (guard_mba.h) so no MOVZ/MOV #9 or #131 or #268
// literal ever appears in the compiled binary.  An attacker running
// `strings` or a hex search for the SIGKILL pattern finds nothing.
static __attribute__((noinline,optnone)) void crash_now(void) {
#if defined(__aarch64__)
    // ARM64: syscall __NR_tgkill = 131, SIGKILL = 9
    // Values are loaded from volatile variables — no literal in .text
    {
        volatile long _nr  = _mba_nr_tgkill64();  // 131, no MOVZ #131
        volatile long _sig = _mba_sigkill();       // 9,   no MOVZ #9
        register long _x8 asm("x8") = _nr;
        register long _x0 asm("x0") = (long)getpid();
        register long _x1 asm("x1") = (long)gettid();
        register long _x2 asm("x2") = _sig;
        asm volatile("svc #0"
            : "+r"(_x0)
            : "r"(_x1), "r"(_x2), "r"(_x8)
            : "memory", "cc");
    }
#elif defined(__arm__)
    // ARM32: syscall __NR_tgkill = 268, SIGKILL = 9
    {
        volatile int _nr  = _mba_nr_tgkill32();   // 268, no MOVZ #268
        volatile int _sig = _mba_sigkill32();      // 9,   no MOVZ #9
        register int _r7 asm("r7") = _nr;
        register int _r0 asm("r0") = (int)getpid();
        register int _r1 asm("r1") = (int)gettid();
        register int _r2 asm("r2") = _sig;
        asm volatile("svc #0"
            : "+r"(_r0)
            : "r"(_r1), "r"(_r2), "r"(_r7)
            : "memory", "cc");
    }
#else
    // Non-ARM fallback — uses kill@PLT but this path never ships in production
    {
        volatile int _sig = _mba_sigkill32();
        kill(getpid(), _sig);
    }
#endif
    // Fallback: _exit — silent, no dialog, no tombstone
    _exit(1);
}

// AES-256-CBC + XOR protected string literals (asset paths, log messages,
// VCore markers) — see guard_pstrings.inc. Needs build_key256/build_iv/
// aes256_cbc_dec, all defined above, so it's included here.
// ════════════════════════════════════════════════════════════════════════════
// SHA-256 — FIPS 180-4, no external dependencies.
// Used exclusively for signature certificate fingerprinting (Layer 4).
// ════════════════════════════════════════════════════════════════════════════
typedef struct { uint32_t h[8]; uint8_t buf[64]; uint64_t len; uint32_t blen; } SHA256Ctx;

static const uint32_t G_SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define S256_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S256_CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define S256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S256_EP0(x) (S256_ROTR(x,2) ^S256_ROTR(x,13)^S256_ROTR(x,22))
#define S256_EP1(x) (S256_ROTR(x,6) ^S256_ROTR(x,11)^S256_ROTR(x,25))
#define S256_SIG0(x)(S256_ROTR(x,7) ^S256_ROTR(x,18)^((x)>>3))
#define S256_SIG1(x)(S256_ROTR(x,17)^S256_ROTR(x,19)^((x)>>10))

static void sha256_init(SHA256Ctx *c) {
    c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;
    c->len=0; c->blen=0;
}

static void sha256_compress(SHA256Ctx *c) {
    uint32_t w[64];
    for (int i=0;i<16;i++){
        const uint8_t *p=c->buf+i*4;
        w[i]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
    }
    for(int i=16;i<64;i++) w[i]=S256_SIG1(w[i-2])+w[i-7]+S256_SIG0(w[i-15])+w[i-16];
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3];
    uint32_t e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for(int i=0;i<64;i++){
        uint32_t t1=h+S256_EP1(e)+S256_CH(e,f,g)+G_SHA256_K[i]+w[i];
        uint32_t t2=S256_EP0(a)+S256_MAJ(a,b,cc);
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;
    c->h[4]+=e;c->h[5]+=f;c->h[6]+=g; c->h[7]+=h;
}

static void sha256_update(SHA256Ctx *c, const uint8_t *data, size_t len) {
    for(size_t i=0;i<len;i++){
        c->buf[c->blen++]=data[i];
        if(c->blen==64){sha256_compress(c);c->blen=0;}
    }
    c->len+=(uint64_t)len;
}

static void sha256_final(SHA256Ctx *c, uint8_t out[32]) {
    uint32_t i=c->blen;
    c->buf[i++]=0x80;
    if(i>56){while(i<64)c->buf[i++]=0;sha256_compress(c);i=0;}
    while(i<56)c->buf[i++]=0;
    uint64_t bl=c->len*8;
    c->buf[56]=(uint8_t)(bl>>56);c->buf[57]=(uint8_t)(bl>>48);
    c->buf[58]=(uint8_t)(bl>>40);c->buf[59]=(uint8_t)(bl>>32);
    c->buf[60]=(uint8_t)(bl>>24);c->buf[61]=(uint8_t)(bl>>16);
    c->buf[62]=(uint8_t)(bl>> 8);c->buf[63]=(uint8_t)(bl);
    sha256_compress(c);
    for(int j=0;j<8;j++){
        out[j*4  ]=(uint8_t)(c->h[j]>>24);out[j*4+1]=(uint8_t)(c->h[j]>>16);
        out[j*4+2]=(uint8_t)(c->h[j]>> 8);out[j*4+3]=(uint8_t)(c->h[j]);
    }
}

static __attribute__((noinline)) void sha256_buf(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256Ctx ctx; sha256_init(&ctx); sha256_update(&ctx,data,len); sha256_final(&ctx,out);
}

#include "guard_pstrings.inc"
// ── NS_JNI — inline reveal_ns for drop-in JNI string substitution ────────────
// Template keyed on __COUNTER__ so every call site gets its own static buffer.
// Each instantiation of ns_jni_slot<N> has independent storage — safe for
// multiple NS_JNI calls on the same line or in the same function.
template<int N>
static __attribute__((noinline)) const char *ns_jni_slot(
        uint32_t idx, const uint8_t *ct, int len) {
    static char buf[SP_BUF_SZ * 4];
    static bool ok = false;
    if (!ok) { reveal_ns(idx, ct, len, buf); ok = true; }
    return buf;
}
#define NS_JNI(idx, blob) ns_jni_slot<__COUNTER__>((idx), (blob), (blob##_LEN))
// ─────────────────────────────────────────────────────────────────────────────


// ════════════════════════════════════════════════════════════════════════════
// XOR decode helper — used by hook/tamper string checks below
// Key 0xA3 is computed at runtime via _mba_xor_key_a3() (guard_mba.h)
// so no MOVZ #0xA3 / literal 0xA3 appears anywhere in .text or .rodata.
// ════════════════════════════════════════════════════════════════════════════

// G_XOR_KEY is NOT a compile-time macro constant anymore — it is a runtime
// call that returns 0xA3 through MBA arithmetic.  Each call site sees only a
// BL to _mba_xor_key_a3; the constant never materialises as an immediate.
// The one-time load inside g_decode() keeps loop overhead the same as before.
static __attribute__((noinline)) void g_decode(const uint8_t *enc, int len, char *out) {
    const uint8_t _key = _mba_xor_key_a3();    // 0xA3, no literal in binary
    for (int i = 0; i < len; i++) out[i] = (char)(enc[i] ^ _key);
    out[len] = '\0';
}

#define G_DEC(var, enc) \
    char var[sizeof(enc)+1]; \
    g_decode((const uint8_t*)enc, (int)sizeof(enc), var)

// ════════════════════════════════════════════════════════════════════════════
// Control-flow flattening (CFF) — volatile switch dispatcher
// Turns function bodies into state-machine spaghetti: Ghidra / IDA Pro's
// decompiler graph recovery emits an unreadable switch, not sequential logic.
// The `volatile` state var prevents the compiler from collapsing it back.
// ════════════════════════════════════════════════════════════════════════════
#define CFF_INIT(v)     volatile uint32_t _c = (v)
#define CFF_LOOP        while(1) switch(_c)
#define CFF_NEXT(n)     { _c=(uint32_t)(n); break; }
#define CFF_EXIT        default: goto _cff_exit; } _cff_exit:

// Opaque predicate — always true (n*(n+1) is always even), but the decompiler
// must track a dead else-branch, doubling the apparent code-paths it analyses.
#define OP_ALWAYS_TRUE(n) \
    (__builtin_expect((((uint32_t)(n)*((uint32_t)(n)+1u))&1u)==0u,1))

// ════════════════════════════════════════════════════════════════════════════
// Raw svc #0 proc-file reader — zero PLT / GOT / libc involvement
//
// DPatch (libpandora) uses ByteHook to PLT-patch fopen/open/openat/pread in
// our .so.  Every fopen("/proc/self/maps") call is intercepted and redirected
// to a fake/clean copy.  Using svc #0 directly bypasses all PLT trampolines —
// the kernel call goes straight to the VFS layer, returning real kernel data.
//
// Forward-declare the svc #0 wrappers defined later in this file (they must
// appear after the ABI #ifdef blocks; the declarations let early functions
// call them without restructuring the file).
// ════════════════════════════════════════════════════════════════════════════
static int     m_openat(const char *path, int flags);
static ssize_t m_pread(int fd, void *buf, size_t n, off_t off);
static int     m_close(int fd);

/* Buffered sequential reader over a kernel file via svc #0 pread64. */
typedef struct {
    int   fd;
    off_t rd_off;         /* next pread offset into the file          */
    char  b[4096];
    int   b_pos;          /* next unconsumed byte within b[]          */
    int   b_len;          /* valid bytes in b[]                       */
    int   eof;            /* 1 once the fd yields nothing more        */
} RawRdr;

static void rrd_open(RawRdr *r, const char *path) {
    r->fd     = m_openat(path, O_RDONLY);
    r->rd_off = 0;
    r->b_pos  = 0;
    r->b_len  = 0;
    r->eof    = (r->fd < 0) ? 1 : 0;
}
static void rrd_close(RawRdr *r) {
    if (r->fd >= 0) { m_close(r->fd); r->fd = -1; }
    r->eof = 1;
}
/* Reads one newline-terminated line into out[0..max-1]; returns 1 or 0. */
static int rrd_getline(RawRdr *r, char *out, int max) {
    if (r->eof || r->fd < 0 || max <= 1) return 0;
    int n = 0;
    while (n < max - 1) {
        if (r->b_pos >= r->b_len) {
            ssize_t rd = m_pread(r->fd, r->b, sizeof(r->b), r->rd_off);
            if (rd <= 0) { r->eof = 1; break; }
            r->rd_off += (off_t)rd;
            r->b_pos = 0; r->b_len = (int)rd;
        }
        char ch = r->b[r->b_pos++];
        out[n++] = ch;
        if (ch == '\n') break;
    }
    out[n] = '\0';
    return (n > 0) ? 1 : 0;
}

/* ── DPatch / libpandora detection via real /proc/self/maps ─────────────────
 * DPatch's libpandora.so MUST be mapped into our process to function.
 * We read maps via svc #0 so DPatch's fopen hook cannot intercept us.
 * Finding "pandora" or "libpandora" in the real map → nuke immediately.
 */
static __attribute__((noinline)) int detect_pandora_in_maps(void) {
    char s_maps[SP_BUF_SZ];
    reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);

    RawRdr r; rrd_open(&r, s_maps);
    if (r.eof) return 0;
    char line[512]; int found = 0;
    while (!found && rrd_getline(&r, line, sizeof(line))) {
        /* "pandora" covers both "libpandora.so" and any pandora path entry */
        if (strstr(line, "pandora") || strstr(line, "bytehook"))
            found = 1;
    }
    rrd_close(&r);
    if (found) CRASH_HERE("DPatch/libpandora detected in process maps");
    return found;
}

// ════════════════════════════════════════════════════════════════════════════
// Anti-debug: abort if TracerPid != 0
// ════════════════════════════════════════════════════════════════════════════

// "/proc/self/status" and "TracerPid:" are AES-256-CBC encrypted in
// guard_pstrings.inc (indices 77-78) via reveal_ns() — decrypted at runtime
// only.  The old XOR-only approach was constant-folded by clang -O2 into
// .rodata, leaking the plaintext strings in the binary.

static void check_tracer(void) {
    GLOGI("check_tracer: start");
    char s_status[SP_BUF_SZ*2] = {0};
    char s_tpid[SP_BUF_SZ]     = {0};
    reveal_ns(77, SP_TRACER_STATUS, SP_TRACER_STATUS_LEN, s_status);
    reveal_ns(78, SP_TRACER_PID,    SP_TRACER_PID_LEN,    s_tpid);

    /* Read /proc/self/status via svc #0 — DPatch hooks fopen but not raw pread64 */
    char line[256];
    RawRdr rdr; rrd_open(&rdr, s_status);
    if (rdr.eof) { GLOGI("check_tracer: could not open status file, skipping"); return; }
    while (rrd_getline(&rdr, line, sizeof(line))) {
        if (strncmp(line, s_tpid, 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            rrd_close(&rdr);
            GLOGI("check_tracer: TracerPid=%ld", pid);
            if (pid != 0) CRASH_HERE("TracerPid != 0 (debugger/ptrace attached)");
            return;
        }
    }
    rrd_close(&rdr);
    GLOGI("check_tracer: TracerPid line not found");
}

// ════════════════════════════════════════════════════════════════════════════
// APK path discovery — two-stage:
//   Stage 1: /proc/self/maps  — works when extractNativeLibs=false (APK is
//            directly mmap'd by ART to load the .so from the ZIP).
//   Stage 2: /proc/self/fd/   — fallback for extractNativeLibs=true (libs
//            are extracted to /data/app/.../lib/ so the .so is NOT in maps,
//            but ART always keeps the APK file descriptor open for resources).
// ════════════════════════════════════════════════════════════════════════════

// All path/extension strings decoded at call-time from XOR 0xA3 arrays —
// no plaintext "/proc/self/maps", "/data/app/", ".apk", etc. in .rodata.
static int get_apk_path(char *out, size_t sz) {
    // All path strings decoded via AES-256-CBC with per-string unique keys.
    // Nothing in .rodata links to "/proc/self/maps", "/data/app/", etc.
    char s_maps[SP_BUF_SZ], s_fd_dir[SP_BUF_SZ], s_fd_pfx[SP_BUF_SZ];
    char s_dot_apk[SP_BUF_SZ], s_da[SP_BUF_SZ], s_sa[SP_BUF_SZ];
    char s_sp[SP_BUF_SZ], s_va[SP_BUF_SZ];

    char fallback[512] = {0};
    RawRdr rdr; rdr.fd = -1; rdr.eof = 1; /* initialised in state 0x71u */
    DIR  *d = NULL;
    int have_fallback = 0, result = 0;

    // CFF state machine — Ghidra sees a volatile-switch dispatcher, not
    // sequential stage logic.
    CFF_INIT(0x3Au);
    CFF_LOOP {
    case 0x3Au: {
        // Opaque predicate: dead else forces decompiler to track fake path
        if (OP_ALWAYS_TRUE(0x3Au)) {
            reveal_ns(1u,  SP_PROC_MAPS,    SP_PROC_MAPS_LEN,    s_maps);
            reveal_ns(2u,  SP_PROC_FD_DIR,  SP_PROC_FD_DIR_LEN,  s_fd_dir);
            reveal_ns(3u,  SP_FD_LINK_PFX,  SP_FD_LINK_PFX_LEN,  s_fd_pfx);
            reveal_ns(4u,  SP_DOT_APK,      SP_DOT_APK_LEN,      s_dot_apk);
            reveal_ns(7u,  SP_DATA_APP,     SP_DATA_APP_LEN,     s_da);
            reveal_ns(8u,  SP_SYS_APP,      SP_SYS_APP_LEN,      s_sa);
            reveal_ns(9u,  SP_SYS_PRIV,     SP_SYS_PRIV_LEN,     s_sp);
            reveal_ns(10u, SP_VND_APP,      SP_VND_APP_LEN,      s_va);
        } else { crash_now(); }
        CFF_NEXT(0x71u);
    }
    case 0x71u: {
        // Stage 1 — /proc/self/maps via svc #0 (bypasses DPatch fopen hook)
        rrd_open(&rdr, s_maps);
        CFF_NEXT(0xBCu);
    }
    case 0xBCu: {
        if (rdr.eof) { CFF_NEXT(0xD4u); break; }
        char line[512];
        while (rrd_getline(&rdr, line, sizeof(line))) {
            char *p = strstr(line, s_dot_apk);
            if (!p) continue;
            char *slash = NULL;
            for (char *c = line; c < p; c++) if (*c == '/') slash = c;
            if (!slash) continue;
            int is_da  = (strstr(slash, s_da) != NULL);
            int is_sys = (strstr(slash, s_sa) || strstr(slash, s_sp) || strstr(slash, s_va));
            if (!is_da && !is_sys) continue;
            size_t len = (size_t)(p + 4 - slash);
            if (len >= sz) continue;
            if (is_da) {
                strncpy(out, slash, len); out[len] = '\0';
                rrd_close(&rdr); result = 1;
                CFF_NEXT(0xFFu); break;
            }
            if (!have_fallback && len < sizeof(fallback)) {
                strncpy(fallback, slash, len); fallback[len] = '\0';
                have_fallback = 1;
            }
        }
        if (_c != 0xFFu) { rrd_close(&rdr); CFF_NEXT(0xD4u); }
        break;
    }
    case 0xD4u: {
        // Stage 2 — /proc/self/fd/
        d = opendir(s_fd_dir);
        CFF_NEXT(0xE5u);
    }
    case 0xE5u: {
        if (!d) { CFF_NEXT(0xF6u); break; }
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            char fdlink[64];
            snprintf(fdlink, sizeof(fdlink), "%s%s", s_fd_pfx, de->d_name);
            char target[512] = {0};
            ssize_t r = readlink(fdlink, target, sizeof(target) - 1);
            if (r <= 4) continue;
            target[r] = '\0';
            if (!strstr(target, s_dot_apk)) continue;
            int is_da  = (strstr(target, s_da) != NULL);
            int is_sys = (strstr(target, s_sa) || strstr(target, s_sp) || strstr(target, s_va));
            if (!is_da && !is_sys) continue;
            char *dot = strstr(target, s_dot_apk); dot[4] = '\0';
            if (strlen(target) >= sz) continue;
            if (is_da) {
                strncpy(out, target, sz - 1); out[sz - 1] = '\0';
                closedir(d); d = NULL; result = 1;
                CFF_NEXT(0xFFu); break;
            }
            if (!have_fallback && strlen(target) < sizeof(fallback)) {
                strncpy(fallback, target, sizeof(fallback) - 1);
                have_fallback = 1;
            }
        }
        if (_c != 0xFFu) { if (d) { closedir(d); d = NULL; } CFF_NEXT(0xF6u); }
        break;
    }
    case 0xF6u: {
        if (have_fallback) {
            strncpy(out, fallback, sz - 1); out[sz - 1] = '\0';
            result = 1;
        }
        CFF_NEXT(0xFFu);
    }
    case 0xFFu:
    CFF_EXIT;
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// VCore / VirtualApp detection — known virtual container path markers
// (S_VC1–S_VC10 are AES-256-CBC+XOR encrypted in guard_pstrings.inc)
// ════════════════════════════════════════════════════════════════════════════

struct VcMarker { const uint8_t *ct; int ct_len; };
static const VcMarker VCORE_MARKERS[] = {
    {S_VC1,S_VC1_LEN},{S_VC2,S_VC2_LEN},{S_VC3,S_VC3_LEN},{S_VC4,S_VC4_LEN},
    {S_VC5,S_VC5_LEN},{S_VC6,S_VC6_LEN},{S_VC7,S_VC7_LEN},{S_VC8,S_VC8_LEN},
    {S_VC9,S_VC9_LEN},{S_VC10,S_VC10_LEN},
};

static void check_render_backend(const char *apk_path) {
    GLOGI("check_render_backend: apk_path=%s", apk_path);
    char buf[PSTR_BUF_SZ];
    for (size_t i = 0; i < sizeof(VCORE_MARKERS)/sizeof(VCORE_MARKERS[0]); i++) {
        reveal(VCORE_MARKERS[i].ct, VCORE_MARKERS[i].ct_len, buf);
        int hit = strstr(apk_path, buf) != NULL;
        if (hit) GLOGI("check_render_backend: marker[%zu]='%s' matched apk_path", i, buf);
        memset(buf, 0, sizeof(buf));
        if (hit) CRASH_HERE("APK path contains a virtual-container marker (VCore/VirtualApp)");
    }
    GLOGI("check_render_backend: clean");
}

// ════════════════════════════════════════════════════════════════════════════
// Hook-framework / injection-tool detection (memory-map scanning)
// All marker strings are XOR-obfuscated (XOR 0xA3) — no plaintext in .rodata
// ════════════════════════════════════════════════════════════════════════════

static volatile const uint8_t G_FRIDA[]     = {0xC5,0xD1,0xCB,0xC7,0xC2};           // "frida"
static volatile const uint8_t G_XPOSED[]    = {0xDB,0xD3,0xCD,0xD0,0xC6,0xC7};       // "xposed"
static volatile const uint8_t G_SUBSTR[]    = {0xD0,0xD6,0xD1,0xD0,0xD7,0xD1,0xC2,0xD7,0xC6}; // "substrate"
static volatile const uint8_t G_GADGET[]    = {0xC4,0xC2,0xC5,0xC4,0xC6,0xD7};       // "gadget"
static volatile const uint8_t G_MAGISK[]    = {0xCE,0xC2,0xC4,0xCA,0xD0,0xC8};       // "magisk"
static volatile const uint8_t G_SAURIK[]    = {0xD0,0xC2,0xD9,0xCB,0xCA,0xC9};       // "saurik"

// ART hook framework markers (XOR 0xA3)
static volatile const uint8_t G_LSPLANT[]  = {0xCF,0xD0,0xD3,0xCF,0xC2,0xCD,0xD7};  // "lsplant"
static volatile const uint8_t G_ZYGISK[]   = {0xD9,0xDA,0xC4,0xCA,0xD0,0xC8};        // "zygisk"
static volatile const uint8_t G_RIRU[]     = {0xD1,0xCA,0xD1,0xD6};                   // "riru"
static volatile const uint8_t G_LSPATCH[]  = {0xCF,0xD0,0xD3,0xC2,0xD7,0xC0,0xCB};  // "lspatch"

// ART runtime library names for path-integrity check (XOR 0xA3)
static volatile const uint8_t G_LIBART[]  = {
    0xCF,0xCA,0xC1,0xC2,0xD1,0xD7,0x8D,0xD0,0xCC          // "libart.so"
};
static volatile const uint8_t G_LIBRT[]   = {
    0xCF,0xCA,0xC1,0xC2,0xCD,0xC7,0xD1,0xCC,0xCA,0xC7,    // "libandroid"
    0xFC,0xD1,0xD6,0xCD,0xD7,0xCA,0xCE,0xC6,0x8D,0xD0,0xCC // "_runtime.so"
};

// ── /proc/self/maps scan for Frida/Xposed/Substrate/Gadget/Magisk/Saurik ──

static __attribute__((noinline)) int check_pipeline_maps(void) {
    G_DEC(s_frida,   G_FRIDA);
    G_DEC(s_xposed,  G_XPOSED);
    G_DEC(s_substr,  G_SUBSTR);
    G_DEC(s_gadget,  G_GADGET);
    G_DEC(s_magisk,  G_MAGISK);
    G_DEC(s_saurik,  G_SAURIK);
    char s_maps[SP_BUF_SZ];
    reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);

    /* svc #0 read — DPatch's ByteHook PLT trampoline on fopen cannot intercept */
    RawRdr rdr; rrd_open(&rdr, s_maps);
    if (rdr.eof) return 0;
    char line[512];
    int found = 0;
    while (rrd_getline(&rdr, line, sizeof(line))) {
        if (strstr(line, s_frida)  || strstr(line, s_xposed) ||
            strstr(line, s_substr) || strstr(line, s_gadget) ||
            strstr(line, s_magisk) || strstr(line, s_saurik)) {
            found = 1;
            break;
        }
    }
    rrd_close(&rdr);
    GLOGI("check_pipeline_maps: found=%d", found);
    return found;
}

// ── /proc/self/maps scan for LSPlant/Zygisk/Riru/LSPatch ──────────────────
// Kept separate so each check gets its own VM opcode slot — an attacker
// who NOPs the Frida check still hits this one.

static __attribute__((noinline)) int check_render_hooks(void) {
    G_DEC(s_lsplant, G_LSPLANT);
    G_DEC(s_zygisk,  G_ZYGISK);
    G_DEC(s_riru,    G_RIRU);
    G_DEC(s_lspatch, G_LSPATCH);
    char s_maps[SP_BUF_SZ];
    reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);

    RawRdr rdr; rrd_open(&rdr, s_maps);
    if (rdr.eof) return 0;
    char line[512];
    int found = 0;
    while (rrd_getline(&rdr, line, sizeof(line))) {
        if (strstr(line, s_lsplant) || strstr(line, s_zygisk) ||
            strstr(line, s_riru)    || strstr(line, s_lspatch)) {
            found = 1;
            break;
        }
    }
    rrd_close(&rdr);
    GLOGI("check_render_hooks: found=%d", found);
    return found;
}

// ── libart.so / libandroid_runtime.so path integrity ──────────────────────
// Both ART runtime libraries MUST be mapped from /system/ or /apex/.
// If either appears under any other path the runtime has been replaced
// (Zygisk, Riru, LSPlant all work by loading a modified libart.so).
// On Android 10+ libart.so lives under /apex/com.android.art/... — valid.

static __attribute__((noinline)) int check_runtime_path(void) {
    G_DEC(s_libart, G_LIBART);
    G_DEC(s_librt,  G_LIBRT);
    char s_maps[SP_BUF_SZ], s_sys[SP_BUF_SZ], s_apex[SP_BUF_SZ];
    reveal_ns(1u,  SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);
    reveal_ns(11u, SP_SYS_PFX,  SP_SYS_PFX_LEN,   s_sys);
    reveal_ns(12u, SP_APEX_PFX, SP_APEX_PFX_LEN,   s_apex);
    size_t sys_len  = strlen(s_sys);
    size_t apex_len = strlen(s_apex);

    RawRdr rdr; rrd_open(&rdr, s_maps);
    if (rdr.eof) return 0;
    char line[512];
    int bad = 0;

    while (rrd_getline(&rdr, line, sizeof(line))) {
        int is_art   = (strstr(line, s_libart) != NULL);
        int is_librt = (strstr(line, s_librt)  != NULL);
        if (!is_art && !is_librt) continue;

        char *path = NULL;
        for (char *c = line; *c && *c != '\n'; c++) {
            if (*c == '/') { path = c; break; }
        }
        if (!path) continue;

        if (strncmp(path, s_sys,  sys_len)  != 0 &&
            strncmp(path, s_apex, apex_len) != 0) {
            bad = 1;
            break;
        }
    }
    rrd_close(&rdr);
    GLOGI("check_runtime_path: bad=%d", bad);
    return bad;
}

// ── Frida default listener port probe (27042) ─────────────────────────────
// Frida-server binds to 127.0.0.1:27042 by default. A successful TCP
// connect means Frida-server is running on the device.

static __attribute__((noinline)) int check_frida_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int found = 0;
    if (ret == 0) {
        found = 1;
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv = {0, 200000};  // 200 ms
        if (select(fd + 1, NULL, &wset, NULL, &tv) > 0) {
            int err = 0;
            socklen_t errlen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            found = (err == 0) ? 1 : 0;
        }
    }
    close(fd);
    GLOGI("check_frida_port: found=%d", found);
    return found;
}

// ════════════════════════════════════════════════════════════════════════════
// Forward declaration — full definition lives in the LAYER 2 section below.
// Needed by both the VM interpreter's METRICS opcode (gvm_metrics) and by
// spawn_background_watch()'s forked child, which calls it via a direct
// kill() path independent of crash_now().
// ════════════════════════════════════════════════════════════════════════════

static int detect_metrics_tamper(const char *apk_path);

// ════════════════════════════════════════════════════════════════════════════
// ── VM Protection — Custom ISA Interpreter ───────────────────────────────
//
// All sensitive security checks are encoded as bytecode in a custom ISA.
// IDA/Ghidra decompiles the interpreter loop but the GUARD_BYTECODE array
// looks like opaque data — an attacker must reverse-engineer the full ISA
// before understanding what the checks do.
//
// Opcodes:
//   0x01  HALT         — stop, return cleanly
//   0x02  CRASH        — crash_now()
//   0x10  CHK_TRACER   — result = TracerPid != 0
//   0x11  CHK_FMAPS    — result = frida/xposed/substrate in /proc/self/maps
//   0x12  CHK_FPORT    — result = Frida listener on port 27042
//   0x13  ARTPATH      — result = libart.so/libandroid_runtime.so bad path
//   0x14  HOOKMAPS     — result = lsplant/zygisk/riru/lspatch in maps
//   0x15  METRICS      — result = manifest-hash/dex-count mismatch
//   0x20  JZ  <off8>   — if result == 0: pc += off8 (skip forward)
//   0x21  JNZ <off8>   — if result != 0: pc += off8
//   0x30  NOP          — decoy instruction
// ════════════════════════════════════════════════════════════════════════════

typedef enum : uint8_t {
    G_OP_HALT     = 0x01,
    G_OP_CRASH    = 0x02,
    G_OP_TRACER   = 0x10,
    G_OP_FMAPS    = 0x11,
    G_OP_FPORT    = 0x12,
    G_OP_ARTPATH  = 0x13,
    G_OP_HOOKMAPS = 0x14,
    G_OP_METRICS  = 0x15,
    G_OP_JZ       = 0x20,
    G_OP_JNZ      = 0x21,
    G_OP_NOP      = 0x30,
} GVmOp;

// ════════════════════════════════════════════════════════════════════════════
// Logic VM — encrypted bytecode programs that implement detection LOGIC itself.
//
// This is the second obfuscation layer on top of the dispatch VM above.
// Where the dispatch VM controls WHICH checks run, the Logic VM controls
// HOW each check runs — the entire fopen/fgets/strstr loop is compiled to
// custom bytecode and AES-256-CBC encrypted.  IDA/Ghidra sees only:
//     lvm_exec(KHI, KLO, IHI, ILO, ENC, LEN, CS)
// which is an opaque call into the interpreter.  The check implementation
// (what files are opened, what strings are searched, what ports are probed)
// lives ONLY inside the encrypted bytecode blob.
//
// ISA (all instructions are 2 bytes: [op][operand]):
//   0x01 00   HALT      — stop; return accumulator
//   0x02 00   CRASH     — crash_now() immediately
//   0x20 off  JZ  off   — if last_result==0: pc += (int8_t)off
//   0x21 off  JNZ off   — if last_result!=0: pc += (int8_t)off
//   0x30 00   NOP       — decoy, ignored
//   0x40 imm  LLOAD imm — acc = imm
//   0x41 00   LMOV      — acc = last_result
//   0x42 00   LNOT      — acc = !acc
//   0x50 sid  LOPEN sid — vm_file=fopen(prim_str[sid],"r"); last_result=success
//   0x51 00   LGETS     — last_result=(fgets(vm_lb,512,vm_file)!=NULL)
//   0x52 00   LCLOSE    — fclose(vm_file); vm_file=NULL
//   0x53 sid  LSTRST sid— last_result=(strstr(vm_lb,prim_str[sid])!=NULL)
//   0x56 00   LTRACE    — last_result=TracerPid!=0 (/proc/self/status)
//   0x61 off  LJMP  off — pc += (int8_t)off  (unconditional)
//
// Primitive string slots (sid):
//   0 = /proc/self/maps  (AES-decrypted via reveal_ns)
//   1 = frida   2 = xposed   3 = substrate   4 = gadget
//   5 = magisk  6 = saurik   7 = lsplant     8 = zygisk
//   9 = riru    10 = lspatch
//
// Each program has its own 256-bit AES key (split KHI^KLO) and IV (IHI^ILO)
// plus a plaintext XOR-checksum (CS) verified before first instruction.
// ════════════════════════════════════════════════════════════════════════════

// ── FMAPS program: check_pipeline_maps logic (frida/xposed/substrate/gadget/magisk/saurik)
// Plain bytecode (52 bytes), AES-256-CBC encrypted below
// 52 bytes plain, 64 bytes encrypted
static volatile const uint8_t LBC_FMAPS_KHI[] = {0xDB,0x02,0x63,0xCB,0x10,0x9E,0x52,0x81,0xD1,0xD0,0xFE,0x25,0x7C,0x77,0x65,0x30,0xC7,0x3D,0x1C,0x54,0xC2,0x2A,0x17,0x98,0x8C,0x63,0x24,0x57,0x32,0x79,0x37,0x2C};
static volatile const uint8_t LBC_FMAPS_KLO[] = {0x98,0xEC,0xD9,0xDA,0x81,0xB6,0x1D,0x05,0xB2,0x23,0xB6,0x42,0x95,0x9B,0x0E,0xD3,0x77,0x96,0x07,0xCD,0xCC,0x42,0xF3,0x4E,0x7B,0x9B,0xF5,0xEE,0xB0,0x81,0x46,0x9F};
static volatile const uint8_t LBC_FMAPS_IHI[] = {0x9A,0x5C,0x05,0x51,0x30,0xE1,0xA3,0x7C,0xF2,0xFA,0x57,0x91,0xE7,0x9A,0xA3,0x4C};
static volatile const uint8_t LBC_FMAPS_ILO[] = {0xB7,0x16,0xDB,0xCB,0x4B,0xA8,0x1A,0x6C,0x60,0x3F,0xF7,0x6A,0xC6,0xE5,0x88,0x48};
static volatile const uint8_t LBC_FMAPS_ENC[] = {0xFE,0x58,0x38,0x58,0x38,0xE5,0xA8,0xD1,0xEC,0xE2,0x92,0xC6,0xA5,0x67,0x11,0x29,0x28,0x0F,0x2B,0x8B,0x0A,0xC9,0x3F,0xCB,0x14,0xDC,0x59,0x57,0x46,0x0E,0x17,0x92,0xA1,0x10,0x9B,0xDC,0x31,0xF5,0x19,0x07,0x01,0xDD,0xF0,0x27,0x12,0xC1,0xD7,0xDB,0x34,0x2D,0x1B,0x98,0xB4,0x0C,0x70,0x51,0x39,0x0C,0xE6,0x8A,0x98,0x18,0x1C,0xF4};
#define LBC_FMAPS_LEN  64
#define LBC_FMAPS_CS   0xB1u

// ── HOOKS program: check_render_hooks logic (lsplant/zygisk/riru/lspatch)
// 44 bytes plain, 48 bytes encrypted
static volatile const uint8_t LBC_HOOKS_KHI[] = {0x03,0x18,0xCD,0x33,0x70,0x5F,0xB1,0x1D,0xBA,0x4A,0xA7,0xA3,0xAB,0xAC,0x27,0xBB,0xAC,0x32,0xDD,0x7A,0x6A,0x9B,0x8B,0x5E,0xE0,0x0D,0x44,0xE6,0x38,0x32,0x97,0x74};
static volatile const uint8_t LBC_HOOKS_KLO[] = {0xDF,0x5B,0xDC,0x70,0x85,0xAF,0xCC,0x41,0xB1,0x36,0xD5,0x40,0x49,0x9A,0xBE,0x91,0xFB,0x34,0x31,0x40,0x1B,0x02,0xB5,0x82,0xDA,0x7C,0x64,0x6D,0xB1,0x93,0x23,0xBA};
static volatile const uint8_t LBC_HOOKS_IHI[] = {0x1D,0x46,0x84,0xF3,0x5D,0x59,0x29,0xE7,0xE1,0x5E,0x96,0xBB,0x1B,0x3F,0x8F,0x03};
static volatile const uint8_t LBC_HOOKS_ILO[] = {0xEC,0xEA,0x15,0x27,0x7A,0xC7,0x55,0x47,0x94,0x26,0xE4,0x92,0x0C,0xD3,0xE3,0xD1};
static volatile const uint8_t LBC_HOOKS_ENC[] = {0xFD,0x19,0x35,0xE7,0x6E,0xCC,0x53,0x27,0xD6,0xF8,0xD6,0x55,0x46,0x4A,0x15,0x3B,0xDD,0xE8,0xB4,0x4A,0x39,0xBE,0x47,0x7E,0x42,0x21,0x62,0x27,0x9D,0x6E,0x37,0xFE,0x27,0x56,0x89,0x10,0xBF,0x1F,0x9D,0x1A,0xAC,0xE9,0x96,0x02,0x1A,0x29,0x85,0xAA};
#define LBC_HOOKS_LEN  48
#define LBC_HOOKS_CS   0xB6u

// ── TRACER program: TracerPid check logic
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_TRACER_KHI[] = {0x67,0x23,0xBD,0x36,0xD0,0x0A,0xF0,0x4D,0x7A,0x11,0xFA,0x16,0xB7,0x55,0x6C,0x79,0x0A,0x9D,0x9D,0x50,0x1F,0x95,0xD6,0x32,0x54,0x9A,0x80,0x3E,0x1B,0x91,0x33,0x43};
static volatile const uint8_t LBC_TRACER_KLO[] = {0x5F,0x19,0x82,0x51,0x3C,0x93,0x84,0x15,0xE5,0x8F,0xDB,0xAB,0xB5,0xE2,0xE9,0xA4,0xAB,0xB8,0x06,0x81,0x8A,0xFF,0x13,0x87,0x97,0x57,0xC4,0xD0,0x44,0x74,0x24,0x72};
static volatile const uint8_t LBC_TRACER_IHI[] = {0xA1,0x82,0x11,0xD0,0xCD,0x9C,0xF8,0xE6,0x41,0x0F,0x1E,0x41,0x8E,0x18,0xD3,0xC0};
static volatile const uint8_t LBC_TRACER_ILO[] = {0x0B,0xF7,0x99,0xD5,0xBE,0x1C,0x8A,0x4E,0x2E,0xA2,0xF9,0xCD,0x3F,0x4C,0xEF,0x3C};
static volatile const uint8_t LBC_TRACER_ENC[] = {0xC0,0x34,0x75,0x8B,0x5D,0x4D,0x80,0xA2,0xCD,0x92,0x93,0x7F,0xFB,0xC2,0x11,0x10};
#define LBC_TRACER_LEN  16
#define LBC_TRACER_CS   0x16u

// ── FPORT program: check_frida_port logic (TCP connect 127.0.0.1:27042)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_FPORT_KHI[] = {0x05,0x4F,0x00,0xE6,0x38,0x4C,0x9C,0xB5,0xF1,0x42,0xC8,0xB8,0x0F,0x5C,0xAB,0x8F,0x60,0x01,0xF5,0x61,0xB0,0x56,0x21,0x68,0x6E,0xD6,0x1E,0x40,0xDE,0x64,0x27,0xAB};
static volatile const uint8_t LBC_FPORT_KLO[] = {0x99,0xE6,0x5C,0x7A,0x88,0x28,0x1A,0x06,0xB9,0x4E,0x2F,0xCC,0xC3,0x33,0x41,0xB8,0x17,0x9B,0xE8,0x05,0x31,0xC8,0xDE,0xB2,0xCF,0x6A,0xBA,0x78,0x50,0xF5,0x8A,0xDE};
static volatile const uint8_t LBC_FPORT_IHI[] = {0x12,0xF5,0x00,0x37,0xAE,0xE5,0x89,0xA5,0x92,0x4F,0xB2,0x27,0x91,0xF8,0xD7,0xFF};
static volatile const uint8_t LBC_FPORT_ILO[] = {0x23,0x8B,0xC6,0x37,0x56,0xF9,0xF1,0x06,0xCC,0x11,0xD0,0xF3,0xB4,0xF1,0x1A,0x1A};
static volatile const uint8_t LBC_FPORT_ENC[] = {0x79,0xCA,0x5D,0xE4,0x21,0xBE,0x6D,0x08,0x0A,0xD9,0x25,0xBC,0x3C,0x84,0x10,0xF1};
#define LBC_FPORT_LEN  16
#define LBC_FPORT_CS   0x15u

// ── ARTPATH program: check_runtime_path logic (libart.so/libandroid_runtime.so path check)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_ARTPATH_KHI[] = {0xD4,0x1D,0x43,0xE9,0xB7,0x2E,0xC1,0xB8,0xF1,0x68,0x99,0x93,0xF6,0x9D,0x25,0x46,0x7D,0xFD,0xAE,0xE1,0xFB,0xEF,0xE0,0x06,0x4F,0x3D,0xB8,0x52,0xFF,0x69,0x06,0x2E};
static volatile const uint8_t LBC_ARTPATH_KLO[] = {0x63,0x39,0x5E,0x85,0x0A,0x70,0x84,0xF1,0x9F,0x84,0x9C,0x61,0xD6,0xBC,0x91,0x4F,0x9D,0xAA,0xE7,0x1F,0x32,0xC9,0x80,0x96,0x26,0xEB,0x62,0xAD,0x9A,0x6C,0xA6,0x5C};
static volatile const uint8_t LBC_ARTPATH_IHI[] = {0xE9,0x14,0x7E,0x9E,0x1D,0xD8,0x98,0xDF,0xF8,0x6D,0xF3,0xF7,0xE7,0xDD,0xEE,0x15};
static volatile const uint8_t LBC_ARTPATH_ILO[] = {0x9C,0xFC,0x57,0x92,0x9D,0xD2,0x8C,0xC8,0x8A,0xAF,0xDF,0xBA,0x98,0xE9,0x6B,0x90};
static volatile const uint8_t LBC_ARTPATH_ENC[] = {0x10,0xE2,0xB4,0x07,0xB0,0xC5,0x0C,0x3F,0xCC,0x9A,0x3D,0x40,0xF9,0xBC,0x47,0xAB};
#define LBC_ARTPATH_LEN  16
#define LBC_ARTPATH_CS   0x17u

// ── METRICS program: detect_metrics_tamper logic (manifest hash + dex count)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_METRICS_KHI[] = {0x32,0xDB,0xDC,0x95,0xD0,0x6B,0x64,0x14,0x2E,0x68,0xFA,0xD3,0x77,0xD2,0x6A,0xF7,0x45,0xB9,0x19,0xD0,0xBE,0x90,0xC0,0x4E,0xEA,0x5F,0x59,0x59,0x3A,0x57,0xC5,0x52};
static volatile const uint8_t LBC_METRICS_KLO[] = {0xE6,0xE2,0x56,0x00,0x8D,0x60,0x46,0x6A,0x96,0xEB,0xEB,0x31,0x93,0x95,0xED,0x6A,0xB2,0x71,0x2E,0xDD,0x21,0xCD,0x67,0x41,0x2C,0xD9,0x21,0x31,0xF1,0x16,0xBE,0x5D};
static volatile const uint8_t LBC_METRICS_IHI[] = {0xA3,0xA8,0xD5,0xB6,0x5A,0xDD,0x23,0x89,0x5D,0x5A,0x37,0xAB,0x12,0xC3,0xDA,0x55};
static volatile const uint8_t LBC_METRICS_ILO[] = {0x70,0x6F,0x6D,0x9E,0x5C,0x49,0x03,0x2A,0x31,0xE2,0x2E,0x8C,0x0E,0xF7,0x4A,0x5F};
static volatile const uint8_t LBC_METRICS_ENC[] = {0x93,0x0D,0xE2,0x00,0x2D,0xF6,0x0D,0x0F,0x4E,0x4F,0x14,0x90,0x75,0x47,0x1A,0x86};
#define LBC_METRICS_LEN  16
#define LBC_METRICS_CS   0x18u

// ── VCCHECK program: VCore/VirtualApp APK-path check (LVCFULL opcode 0x5A)
// 8 bytes plain → 16 bytes AES-256-CBC ciphertext
static volatile const uint8_t LBC_VCCHECK_KHI[] = {0x24,0x1B,0x08,0x9C,0xBE,0x39,0x90,0x4E,0x32,0xA8,0xCF,0xDB,0xF0,0x73,0xDF,0x40,0xFC,0x6D,0xF2,0xDF,0x7A,0x93,0x41,0x83,0x10,0x50,0x64,0xE7,0xE1,0xBE,0x07,0x96};
static volatile const uint8_t LBC_VCCHECK_KLO[] = {0x16,0x61,0xD4,0xF8,0xB1,0x9D,0xC3,0x87,0x08,0x9E,0xAD,0x90,0xD7,0xE6,0x0A,0x2B,0x6F,0x1F,0x62,0x93,0x81,0xB6,0xFA,0x63,0xD3,0xCF,0xA0,0x30,0xB1,0x95,0x3A,0x22};
static volatile const uint8_t LBC_VCCHECK_IHI[] = {0x3D,0x4D,0x92,0x14,0x12,0xD2,0x64,0xF6,0xF9,0x8A,0x02,0x82,0x82,0xBC,0x78,0x2D};
static volatile const uint8_t LBC_VCCHECK_ILO[] = {0x17,0xB8,0x2D,0xF6,0x68,0x24,0xF0,0x66,0x09,0x21,0x4E,0xBF,0xCD,0x55,0x0F,0x0B};
static volatile const uint8_t LBC_VCCHECK_ENC[] = {0xDE,0xE2,0x66,0xD5,0x3B,0x78,0x54,0x3E,0xA6,0x6C,0xC1,0xBA,0x1C,0xE7,0xE0,0xB0};
#define LBC_VCCHECK_LEN  16
#define LBC_VCCHECK_CS   0x5Bu

// ── SIGCHK program: signature certificate verification (LSIGCHK opcode 0x5C)
// Bytecode (8 bytes plain → 16 bytes AES-256-CBC):
//   0x5C 0x00  LSIGCHK  — call gvm_sig_check() → vm_res
//   0x20 0x02  JZ  +2   — vm_res==0 (clean): skip CRASH
//   0x02 0x00  CRASH    — tamper detected → crash_now()
//   0x01 0x00  HALT     — clean exit
// Key = KHI^KLO (256-bit), IV = IHI^ILO (128-bit). XOR-CS = 0x7D.
// fonts_init() shows only an opaque lvm_exec call — no gvm_sig_check or
// detect_sig_tamper reference visible in ARM64 disasm.
static volatile const uint8_t LBC_SIGCHK_KHI[] = {0x15,0x08,0xDC,0xDA,0x13,0xB9,0xC3,0x45,0x4D,0xDE,0x17,0x21,0xC0,0x79,0xB4,0x3D,0x4A,0x49,0xCD,0x5E,0x48,0x58,0x29,0x0C,0xEE,0x4E,0xEB,0x37,0xD5,0x0E,0xA9,0xD4};
static volatile const uint8_t LBC_SIGCHK_KLO[] = {0xBB,0x24,0x26,0x05,0x27,0xBF,0xC2,0xC8,0x33,0xE3,0x58,0xFD,0x1C,0x9E,0xA0,0xBE,0xF3,0x6F,0x4B,0xDD,0xCD,0xF0,0xBC,0x2C,0x1E,0xE7,0xD8,0x54,0xF9,0x8C,0xA8,0xA0};
static volatile const uint8_t LBC_SIGCHK_IHI[] = {0x7B,0xEE,0x0D,0x0C,0x3D,0x8E,0xAC,0xB6,0x7A,0x86,0x40,0xC2,0xD7,0xB0,0xC3,0xB9};
static volatile const uint8_t LBC_SIGCHK_ILO[] = {0x03,0x87,0x66,0x9A,0xBB,0x29,0xC9,0xEE,0xF8,0x19,0x5E,0x90,0x1E,0x04,0x8C,0x39};
static volatile const uint8_t LBC_SIGCHK_ENC[] = {0x94,0x2B,0x87,0xC6,0xFF,0x72,0xB5,0x40,0x20,0xB7,0xFA,0x9C,0xB4,0xC4,0xC9,0x6F};
#define LBC_SIGCHK_LEN  16
#define LBC_SIGCHK_CS   0x7Du

// ── Primitive string resolver — maps slot index → decrypted C string ─────────
// All source arrays remain XOR-encoded in .rodata (G_*) or AES-encrypted
// (reveal_ns path).  No plaintext ever appears in the binary.
#define GVM_PATH_BUF 64
static __attribute__((noinline)) void lvm_prim_str(uint8_t slot, char *out, size_t sz) {
    memset(out, 0, sz);
    if (slot == 0) { reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, out); return; }
#define _LGDEC(arr) do { int n=(int)sizeof(arr); if((size_t)n<sz) g_decode((const uint8_t*)arr,n,out); } while(0)
    if      (slot == 1)  _LGDEC(G_FRIDA);
    else if (slot == 2)  _LGDEC(G_XPOSED);
    else if (slot == 3)  _LGDEC(G_SUBSTR);
    else if (slot == 4)  _LGDEC(G_GADGET);
    else if (slot == 5)  _LGDEC(G_MAGISK);
    else if (slot == 6)  _LGDEC(G_SAURIK);
    else if (slot == 7)  _LGDEC(G_LSPLANT);
    else if (slot == 8)  _LGDEC(G_ZYGISK);
    else if (slot == 9)  _LGDEC(G_RIRU);
    else if (slot == 10) _LGDEC(G_LSPATCH);
#undef _LGDEC
}

// ── Logic VM interpreter ───────────────────────────────────────────────────
// Decrypts a bytecode program with the given split key/IV, verifies its
// XOR checksum, then executes it.  Returns the accumulator at HALT.
//
// This function is what an attacker's disassembler sees at the call site —
// six opaque volatile arrays + two integer constants.  The actual check
// logic (which file is opened, which strings are searched) lives only
// inside the AES-encrypted ENC[] blob.
// ── Context passed from JNI shell to LANTIK opcode inside lvm_exec ───────
// The JNI layer collects provider names/auths and Class.forName results as
// plain C data here.  lvm_exec opcode 0x5B reads this struct and performs
// the KFRAG matching and kill decision entirely inside the bytecode interpreter.
// ARM64 disassembly of _fonts_measure_impl shows ONLY data collection + an
// opaque call to lvm_exec — no strstr patterns, no CRASH_HERE.
#define ANTIK_MAX_PROV 32
#define ANTIK_STR_SZ   256
typedef struct {
    char names[ANTIK_MAX_PROV][ANTIK_STR_SZ]; // provider class names (UTF-8)
    char auths[ANTIK_MAX_PROV][ANTIK_STR_SZ]; // provider authorities (UTF-8)
    int  count;      // number of slots populated in names[]/auths[]
    int  exact_hit;  // 1 if Class.forName resolved a blocked class (Layer 2)
} antik_ctx_t;

// ── Forward declarations — defined below lvm_exec, called inside it ──────────
static __attribute__((noinline)) int gvm_metrics(void);
static __attribute__((noinline)) int gvm_so_integrity(void);
static __attribute__((noinline)) int gvm_sig_check(void);   /* used by LSIGCHK opcode 0x5C */

// ── KFRAG encrypted package-fragment patterns (used inside lvm_exec opcode 0x5B)
// Defined here so lvm_exec can see them; provider_matches_blocklist() also uses them.
static const uint8_t KFRAG1_CT[] = {0x03,0x11,0xb6,0x5e,0xd5,0x39,0x11,0x57,0x61,0x41,0xc2,0x42,0xc5,0x37,0xcb,0x07};
static const int KFRAG1_LEN = 16; // idx=200
static const uint8_t KFRAG2_CT[] = {0xd0,0x94,0xf4,0x32,0x96,0xca,0x05,0xa8,0xfe,0xcb,0xd2,0x91,0x02,0x01,0x4c,0xf7};
static const int KFRAG2_LEN = 16; // idx=201
static const uint8_t KFRAG3_CT[] = {0x1f,0x7a,0x37,0xbe,0x25,0x61,0xbe,0x6a,0x7a,0x9f,0x81,0xba,0xf1,0x37,0xa1,0x89};
static const int KFRAG3_LEN = 16; // idx=202
static const uint8_t KFRAG4_CT[] = {0x64,0xd7,0xd9,0x7d,0x32,0x33,0xee,0x11,0xc3,0x64,0x14,0x43,0xcb,0x7b,0x53,0x41,
                                     0x69,0xf9,0x3d,0xbd,0x2f,0xdb,0x2a,0x8a,0xb5,0x3c,0x97,0xd6,0xa8,0x70,0x83,0x13};
static const int KFRAG4_LEN = 32; // idx=203

static __attribute__((noinline)) int lvm_exec(
        const volatile uint8_t *khi, const volatile uint8_t *klo,
        const volatile uint8_t *ihi, const volatile uint8_t *ilo,
        const volatile uint8_t *enc, int enc_len, uint8_t expected_cs,
        const void *ctx_in = nullptr) {

    // Reconstruct full 256-bit key and 128-bit IV from split halves
    uint8_t key[32], iv[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(khi[i] ^ klo[i]);
    for (int i = 0; i < 16; i++) iv[i]  = (uint8_t)(ihi[i] ^ ilo[i]);

    // Decrypt bytecode — output buffer sized for largest possible program
    uint8_t prog[128];
    int prog_len = aes256_cbc_dec(key, iv, (const uint8_t *)enc, enc_len,
                                  prog);
    // Zero key material immediately after use
    volatile uint8_t *vk = key; for (int i=0;i<32;i++) vk[i]=0;
    volatile uint8_t *vi = iv;  for (int i=0;i<16;i++) vi[i]=0;

    if (prog_len <= 0 || prog_len > (int)sizeof(prog)) return 0;

    // Bytecode integrity — XOR checksum of decrypted program.
    // Any patch to the ENC[] array produces corrupted plaintext
    // whose checksum won't match → crash instead of silently returning 0.
    uint8_t cs = 0;
    for (int i = 0; i < prog_len; i++) cs ^= prog[i];
    if (cs != expected_cs) { CRASH_HERE("lvm: bytecode integrity"); return 0; }

    // VM state — file I/O uses svc #0 RawRdr, not fopen (DPatch hooks fopen)
    RawRdr vm_rdr; vm_rdr.fd = -1; vm_rdr.eof = 1;
    vm_rdr.rd_off = 0; vm_rdr.b_pos = 0; vm_rdr.b_len = 0;
    char  vm_lb[512];
    int   vm_acc   = 0;   // accumulator — returned at HALT
    int   vm_res   = 0;   // last primitive result

    // Interpreter — every instruction is exactly 2 bytes [op][operand]
    // This forces instruction boundaries to be non-obvious to static analysis.
    int pc = 0;
    while (pc + 1 < prog_len) {
        uint8_t op  = prog[pc];
        uint8_t arg = prog[pc + 1];
        pc += 2;
        switch (op) {
            // ── Control ────────────────────────────────────────────────
            case 0x01: /* HALT  */ goto lvm_halt;
            case 0x02: /* CRASH */ CRASH_HERE("lvm: CRASH opcode"); rrd_close(&vm_rdr); return 0;
            case 0x30: /* NOP   */ break;
            case 0x20: /* JZ    */ if (vm_res == 0) pc += (int)(int8_t)arg; break;
            case 0x21: /* JNZ   */ if (vm_res != 0) pc += (int)(int8_t)arg; break;
            case 0x61: /* LJMP  */ pc += (int)(int8_t)arg;                  break;

            // ── Accumulator ────────────────────────────────────────────
            case 0x40: /* LLOAD */ vm_acc = (int)(uint8_t)arg; break;
            case 0x41: /* LMOV  */ vm_acc = vm_res;            break;
            case 0x42: /* LNOT  */ vm_acc = !vm_acc;           break;

            // ── File I/O primitives — svc #0, zero PLT/GOT surface ────
            case 0x50: { /* LOPEN */
                char path[GVM_PATH_BUF];
                lvm_prim_str(arg, path, sizeof(path));
                rrd_close(&vm_rdr);
                rrd_open(&vm_rdr, path);
                vm_res = (!vm_rdr.eof) ? 1 : 0;
                break;
            }
            case 0x51: { /* LGETS */
                vm_res = rrd_getline(&vm_rdr, vm_lb, (int)sizeof(vm_lb));
                break;
            }
            case 0x52: { /* LCLOSE */
                rrd_close(&vm_rdr);
                break;
            }
            case 0x53: { /* LSTRST */
                char needle[GVM_PATH_BUF];
                lvm_prim_str(arg, needle, sizeof(needle));
                vm_res = (needle[0] && strstr(vm_lb, needle) != NULL) ? 1 : 0;
                break;
            }

            // ── System primitives ──────────────────────────────────────
            case 0x56: { /* LTRACE — read TracerPid via svc #0 (bypasses DPatch fopen hook) */
                char s_status[SP_BUF_SZ*2] = {0}, s_tpid[SP_BUF_SZ] = {0};
                reveal_ns(77, SP_TRACER_STATUS, SP_TRACER_STATUS_LEN, s_status);
                reveal_ns(78, SP_TRACER_PID,    SP_TRACER_PID_LEN,    s_tpid);
                RawRdr tf; rrd_open(&tf, s_status);
                int traced = 0;
                if (!tf.eof) {
                    char line[256];
                    while (rrd_getline(&tf, line, sizeof(line))) {
                        if (strncmp(line, s_tpid, 10) == 0) {
                            traced = (strtol(line + 10, NULL, 10) != 0) ? 1 : 0;
                            break;
                        }
                    }
                    rrd_close(&tf);
                }
                vm_res = traced;
                break;
            }
            // ── System primitives (cont.) ──────────────────────────────
            case 0x55: { /* LSOCK — TCP connect to 127.0.0.1:prim_port[slot] */
                // slot 0 = 27042 (Frida default port)
                static const uint16_t prim_ports[] = { 27042 };
                uint16_t port = (arg < (uint8_t)(sizeof(prim_ports)/sizeof(prim_ports[0])))
                                ? prim_ports[arg] : 0;
                int found = 0;
                if (port) {
                    int fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (fd >= 0) {
                        struct sockaddr_in sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.sin_family      = AF_INET;
                        sa.sin_port        = htons(port);
                        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        int fl = fcntl(fd, F_GETFL, 0);
                        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                        int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
                        if (rc == 0) {
                            found = 1;
                        } else if (errno == EINPROGRESS) {
                            fd_set ws; FD_ZERO(&ws); FD_SET(fd, &ws);
                            struct timeval tv = {0, 200000};
                            if (select(fd+1, NULL, &ws, NULL, &tv) > 0) {
                                int err = 0; socklen_t el = sizeof(err);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                                found = (err == 0) ? 1 : 0;
                            }
                        }
                        close(fd);
                    }
                }
                vm_res = found;
                break;
            }
            case 0x57: { /* LARTPATH — check_runtime_path() entire logic */
                vm_res = check_runtime_path();
                break;
            }
            case 0x58: { /* LMETRICS — manifest-hash + dex-count tamper check */
                vm_res = gvm_metrics();
                break;
            }
            case 0x5A: { /* LVCFULL — VCore/VirtualApp: resolve APK path + check_render_backend */
                // Gets APK path internally so fonts_init() has no apk_path variable
                // and no check_render_backend call site visible in its ARM64 disasm.
                char _vc_apk[512] = {0};
                if (get_apk_path(_vc_apk, sizeof(_vc_apk))) {
                    check_render_backend(_vc_apk);  // crashes internally if VCore/VA detected
                }
                vm_res = 0;  // always 0; detection causes internal crash_now()
                break;
            }
            case 0x5B: { /* LANTIK — JNI antik killer check (Layers 2 + 4)
                 *
                 * The JNI shell (_fonts_measure_impl) collects:
                 *   actx.names[]  — declared provider class names
                 *   actx.auths[]  — declared provider authorities
                 *   actx.exact_hit — 1 if Class.forName found a blocked class
                 *
                 * This opcode performs the pure-C kill decision:
                 *   1. Decrypt KFRAG1-4 (AES-256-CBC, per-string unique key)
                 *   2. strstr each name/auth against all 4 fragments
                 *   3. OR with exact_hit flag
                 *   4. crash_now() if any signal is non-zero
                 *
                 * What Ghidra sees in _fonts_measure_impl: data collection +
                 * an opaque lvm_exec call.  No strstr pattern, no CRASH_HERE.
                 */
                if (!ctx_in) { vm_res = 0; break; }
                const antik_ctx_t *ac = (const antik_ctx_t *)ctx_in;
                int ahit = ac->exact_hit;
                if (!ahit) {
                    char af1[PSTR_BUF_SZ], af2[PSTR_BUF_SZ];
                    char af3[PSTR_BUF_SZ], af4[PSTR_BUF_SZ];
                    reveal_ns(200u, KFRAG1_CT, KFRAG1_LEN, af1);
                    reveal_ns(201u, KFRAG2_CT, KFRAG2_LEN, af2);
                    reveal_ns(202u, KFRAG3_CT, KFRAG3_LEN, af3);
                    reveal_ns(203u, KFRAG4_CT, KFRAG4_LEN, af4);
                    for (int i = 0; i < ac->count && !ahit; i++) {
                        const char *n = ac->names[i];
                        const char *a = ac->auths[i];
                        if ((n[0] && (strstr(n,af1)||strstr(n,af2)||
                                      strstr(n,af3)||strstr(n,af4))) ||
                            (a[0] && (strstr(a,af1)||strstr(a,af2)||
                                      strstr(a,af3)||strstr(a,af4))))
                            ahit = 1;
                    }
                    memset(af1,0,sizeof(af1)); memset(af2,0,sizeof(af2));
                    memset(af3,0,sizeof(af3)); memset(af4,0,sizeof(af4));
                }
                if (ahit) {
                    GLOGE("lvm: LANTIK — antik killer detected (exact=%d frag=?)",
                          ac->exact_hit);
                    CRASH_HERE("lvm: LANTIK opcode — antik killer present");
                }
                vm_res = ahit;
                break;
            }
            case 0x5C: { /* LSIGCHK — signature certificate verification (Layer 4)
                 * Resolves APK path internally via gvm_sig_check(), which calls
                 * detect_sig_tamper() using inline-asm svc #0 file I/O.
                 * fonts_init() shows only an opaque lvm_exec(LBC_SIGCHK_*) call —
                 * no gvm_sig_check call site, no detect_sig_tamper reference visible
                 * in the ARM64 disassembly of fonts_init().
                 */
                vm_res = gvm_sig_check();
                break;
            }
            default: break;  // unknown opcode treated as NOP
        }
        // Bounds guard after any jump
        if (pc < 0 || pc >= prog_len) break;
    }
lvm_halt:
    rrd_close(&vm_rdr);
    return vm_acc;
}

// ════════════════════════════════════════════════════════════════════════════
// lvm_method_exec — general-purpose VM interpreter for dex2c-compiled methods.
//
// Java methods compiled by vm_writer.py (Dalvik SSA → custom ISA → AES-256-CBC)
// are dispatched here. The JNI shell is a thin wrapper: it packs JNI args into
// vm_method_ctx_t.args[], calls lvm_method_exec(), unpacks ret_val.
//
// What Ghidra sees in every protected JNI stub:
//   ctx.args[0]=p0; ctx.args[1]=p1; ...
//   lvm_method_exec(KHI, KLO, IHI, ILO, ENC, LEN, CS, &ctx);
//   return (jint) ctx.ret_val;
// The entire method body lives inside AES-encrypted bytecode — zero ARM64.
//
// Bytecode layout (all fields little-endian):
//   [n_consts:1][pad:3][const_0:8]…[const_N:8][instructions…]
//   Each instruction: [op:1][b1:1][b2:1][b3:1]  (4 bytes, 4-byte aligned)
//   Jump targets b2:b3 = 16-bit absolute byte offset into the bytecode.
// ════════════════════════════════════════════════════════════════════════════

#define MVM_MAX_REGS   16    // VM registers r[0]–r[15]
#define MVM_MAX_CONSTS 32    // constant table entries
#define MVM_PROG_MAX   4096  // max decrypted program size (bytes)

typedef struct {
    int64_t  args[MVM_MAX_REGS]; // input: JNI primitive args packed as int64
    int      arg_count;          // number of valid entries in args[]
    int64_t  ret_val;            // output: primitive return value
} vm_method_ctx_t;

static __attribute__((noinline)) void lvm_method_exec(
        const volatile uint8_t *khi, const volatile uint8_t *klo,
        const volatile uint8_t *ihi, const volatile uint8_t *ilo,
        const volatile uint8_t *enc, int enc_len, uint8_t expected_cs,
        vm_method_ctx_t *ctx) {

    // ── Decrypt ─────────────────────────────────────────────────────────
    uint8_t mkey[32], miv[16];
    for (int i = 0; i < 32; i++) mkey[i] = (uint8_t)(khi[i] ^ klo[i]);
    for (int i = 0; i < 16; i++) miv[i]  = (uint8_t)(ihi[i] ^ ilo[i]);
    uint8_t prog[MVM_PROG_MAX];
    int prog_len = aes256_cbc_dec(mkey, miv, (const uint8_t *)enc, enc_len, prog);
    { volatile uint8_t *vk = mkey; for (int i = 0; i < 32; i++) vk[i] = 0; }
    { volatile uint8_t *vi = miv;  for (int i = 0; i < 16; i++) vi[i] = 0; }
    if (prog_len < 4) return;

    // ── Integrity check ──────────────────────────────────────────────────
    uint8_t mcs = 0;
    for (int i = 0; i < prog_len; i++) mcs ^= prog[i];
    if (mcs != expected_cs) {
        CRASH_HERE("lvm_method_exec: bytecode checksum mismatch");
        return;
    }

    // ── Parse constant table ─────────────────────────────────────────────
    int64_t mconsts[MVM_MAX_CONSTS];
    int mn_consts = (int)prog[0];           // byte 0 = count
    if (mn_consts > MVM_MAX_CONSTS) return;
    int mpc = 4;                            // skip 4-byte header
    for (int i = 0; i < mn_consts; i++) {
        if (mpc + 8 > prog_len) return;
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= ((uint64_t)prog[mpc++] << (b * 8));
        mconsts[i] = (int64_t)v;
    }
    // Align to 4-byte boundary
    while (mpc & 3) mpc++;

    // ── Initialise registers from input args ─────────────────────────────
    // generate_shell() packs each JNI arg at its VM register slot index
    // (not sequentially). Pre-load all slots so every parameter arrives
    // at the correct register with zero bytecode overhead.
    int64_t mr[MVM_MAX_REGS];
    memset(mr, 0, sizeof(mr));
    if (ctx) {
        for (int i = 0; i < MVM_MAX_REGS; i++) mr[i] = ctx->args[i];
    }

    // ── Execute ──────────────────────────────────────────────────────────
    while (mpc + 3 < prog_len) {
        uint8_t mop = prog[mpc];
        uint8_t mb1 = prog[mpc + 1];
        uint8_t mb2 = prog[mpc + 2];
        uint8_t mb3 = prog[mpc + 3];
        mpc += 4;
        uint16_t mtgt = (uint16_t)((mb2 << 8) | mb3);

        switch (mop) {
        /* ── Control ────────────────────────────────────────────── */
        case 0x80: /* MVHALT  */ if (ctx) ctx->ret_val = mr[mb1]; goto mvm_halt;
        case 0x81: /* MVJMP   */ mpc = (int)mtgt; break;
        case 0x82: /* MVJZ    */ if (mr[mb1] == 0) mpc = (int)mtgt; break;
        case 0x83: /* MVJNZ   */ if (mr[mb1] != 0) mpc = (int)mtgt; break;
        case 0x84: /* MVJLTZ  */ if (mr[mb1] <  0) mpc = (int)mtgt; break;
        case 0x85: /* MVJLEZ  */ if (mr[mb1] <= 0) mpc = (int)mtgt; break;
        case 0x86: /* MVJGTZ  */ if (mr[mb1] >  0) mpc = (int)mtgt; break;
        case 0x87: /* MVJGEZ  */ if (mr[mb1] >= 0) mpc = (int)mtgt; break;

        /* ── Register ops ───────────────────────────────────────── */
        case 0x90: /* MVMOV   */ mr[mb1] = mr[mb2]; break;
        case 0x91: /* MVCONST */ mr[mb1] = (mtgt < MVM_MAX_CONSTS) ? mconsts[mtgt] : 0; break;
        case 0x92: /* MVNEG   */ mr[mb1] = -mr[mb2]; break;
        case 0x93: /* MVNOT   */ mr[mb1] = ~mr[mb2]; break;

        /* ── Integer arithmetic ─────────────────────────────────── */
        case 0xA0: /* MVADD   */ mr[mb1] = mr[mb2] + mr[mb3]; break;
        case 0xA1: /* MVSUB   */ mr[mb1] = mr[mb2] - mr[mb3]; break;
        case 0xA2: /* MVMUL   */ mr[mb1] = mr[mb2] * mr[mb3]; break;
        case 0xA3: /* MVDIV   */ mr[mb1] = mr[mb3] ? mr[mb2] / mr[mb3] : 0; break;
        case 0xA4: /* MVREM   */ mr[mb1] = mr[mb3] ? mr[mb2] % mr[mb3] : 0; break;
        case 0xA5: /* MVAND   */ mr[mb1] = mr[mb2] & mr[mb3]; break;
        case 0xA6: /* MVOR    */ mr[mb1] = mr[mb2] | mr[mb3]; break;
        case 0xA7: /* MVXOR   */ mr[mb1] = mr[mb2] ^ mr[mb3]; break;
        /* int shifts (Dalvik masks to 0x1f) */
        case 0xA8: /* MVISHL  */ mr[mb1] = (int64_t)((int32_t)mr[mb2] << (mr[mb3] & 0x1f)); break;
        case 0xA9: /* MVISHR  */ mr[mb1] = (int64_t)((int32_t)mr[mb2] >> (mr[mb3] & 0x1f)); break;
        case 0xAA: /* MVIUSHR */ mr[mb1] = (int64_t)((uint32_t)mr[mb2] >> (mr[mb3] & 0x1f)); break;
        /* long shifts (Dalvik masks to 0x3f) */
        case 0xAB: /* MVLSHL  */ mr[mb1] = mr[mb2] << (mr[mb3] & 0x3f); break;
        case 0xAC: /* MVLSHR  */ mr[mb1] = mr[mb2] >> (mr[mb3] & 0x3f); break;
        case 0xAD: /* MVLUSHR */ mr[mb1] = (int64_t)((uint64_t)mr[mb2] >> (mr[mb3] & 0x3f)); break;
        /* integer comparisons → 0 or 1 */
        case 0xAE: /* MVCMPEQ */ mr[mb1] = (mr[mb2] == mr[mb3]) ? 1 : 0; break;
        case 0xAF: /* MVCMPNE */ mr[mb1] = (mr[mb2] != mr[mb3]) ? 1 : 0; break;
        case 0xB0: /* MVCMPLT */ mr[mb1] = (mr[mb2] <  mr[mb3]) ? 1 : 0; break;
        case 0xB1: /* MVCMPLE */ mr[mb1] = (mr[mb2] <= mr[mb3]) ? 1 : 0; break;
        case 0xB2: /* MVCMPGT */ mr[mb1] = (mr[mb2] >  mr[mb3]) ? 1 : 0; break;
        case 0xB3: /* MVCMPGE */ mr[mb1] = (mr[mb2] >= mr[mb3]) ? 1 : 0; break;
        /* long-cmp: -1 / 0 / +1 */
        case 0xB4: /* MVLCMP  */
            mr[mb1] = (mr[mb2] == mr[mb3]) ? 0 : (mr[mb2] > mr[mb3]) ? 1 : -1; break;
        /* float arithmetic (values are IEEE-754 bits stored as int64) */
        case 0xD1: /* MVFADD  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a+_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD2: /* MVFSUB  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a-_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD3: /* MVFMUL  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a*_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD4: /* MVFDIV  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a/_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD5: /* MVFREM  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=fmodf(_a,_b); uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD6: /* MVFCMPL */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); mr[mb1]=(_a==_b)?0:(_a>_b)?1:-1; } break;
        case 0xD7: /* MVFCMPG */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); mr[mb1]=(_a==_b)?0:(_a<_b)?-1:1; } break;
        /* double arithmetic */
        case 0xD8: /* MVDADD  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a+_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xD9: /* MVDSUB  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a-_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDA: /* MVDMUL  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a*_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDB: /* MVDDIV  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a/_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDC: /* MVDREM  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=fmod(_a,_b); uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDD: /* MVDCMPL */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); mr[mb1]=(_a==_b)?0:(_a>_b)?1:-1; } break;
        case 0xDE: /* MVDCMPG */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); mr[mb1]=(_a==_b)?0:(_a<_b)?-1:1; } break;

        /* ── Type conversions ───────────────────────────────────── */
        case 0xC0: /* MVI2L   */ mr[mb1] = (int64_t)(int32_t)mr[mb2]; break;
        case 0xC1: /* MVL2I   */ mr[mb1] = (int64_t)(int32_t)mr[mb2]; break;
        case 0xC2: /* MVI2F   */ { float _f=(float)(int32_t)mr[mb2]; uint32_t _u; memcpy(&_u,&_f,4); mr[mb1]=(int64_t)_u; } break;
        case 0xC3: /* MVF2I   */ { float _f; uint32_t _u=(uint32_t)mr[mb2]; memcpy(&_f,&_u,4); double _d=(double)_f; mr[mb1]=(_d>2147483647.0)?(int64_t)2147483647:(_d<-2147483648.0)?(int64_t)-2147483648LL:(int64_t)(int32_t)_f; } break;
        case 0xC4: /* MVI2D   */ { double _d=(double)(int32_t)mr[mb2]; uint64_t _u; memcpy(&_u,&_d,8); mr[mb1]=(int64_t)_u; } break;
        case 0xC5: /* MVD2I   */ { double _d; uint64_t _u=(uint64_t)mr[mb2]; memcpy(&_d,&_u,8); mr[mb1]=(_d>2147483647.0)?(int64_t)2147483647:(_d<-2147483648.0)?(int64_t)-2147483648LL:(int64_t)(int32_t)_d; } break;
        case 0xC6: /* MVL2F   */ { float _f=(float)(int64_t)mr[mb2]; uint32_t _u; memcpy(&_u,&_f,4); mr[mb1]=(int64_t)_u; } break;
        case 0xC7: /* MVF2L   */ { float _f; uint32_t _u=(uint32_t)mr[mb2]; memcpy(&_f,&_u,4); double _d=(double)_f; mr[mb1]=(_d>9.223372036854776e18)?(int64_t)9223372036854775807LL:(_d<-9.223372036854776e18)?((int64_t)-9223372036854775807LL-1):(int64_t)(int64_t)_f; } break;
        case 0xC8: /* MVL2D   */ { double _d=(double)(int64_t)mr[mb2]; uint64_t _u; memcpy(&_u,&_d,8); mr[mb1]=(int64_t)_u; } break;
        case 0xC9: /* MVD2L   */ { double _d; uint64_t _u=(uint64_t)mr[mb2]; memcpy(&_d,&_u,8); mr[mb1]=(_d>9.223372036854776e18)?(int64_t)9223372036854775807LL:(_d<-9.223372036854776e18)?((int64_t)-9223372036854775807LL-1):(int64_t)_d; } break;
        case 0xCA: /* MVF2D   */ { float _f; uint32_t _uf=(uint32_t)mr[mb2]; memcpy(&_f,&_uf,4); double _d=(double)_f; uint64_t _ud; memcpy(&_ud,&_d,8); mr[mb1]=(int64_t)_ud; } break;
        case 0xCB: /* MVD2F   */ { double _d; uint64_t _ud=(uint64_t)mr[mb2]; memcpy(&_d,&_ud,8); float _f=(float)_d; uint32_t _uf; memcpy(&_uf,&_f,4); mr[mb1]=(int64_t)_uf; } break;
        case 0xCC: /* MVI2B   */ mr[mb1] = (int64_t)(int8_t)(int32_t)mr[mb2]; break;
        case 0xCD: /* MVI2C   */ mr[mb1] = (int64_t)(uint16_t)(int32_t)mr[mb2]; break;
        case 0xCE: /* MVI2S   */ mr[mb1] = (int64_t)(int16_t)(int32_t)mr[mb2]; break;
        /* float/double negate */
        case 0xCF: /* MVFNEG  */ { float _f; uint32_t _u=(uint32_t)mr[mb2]; memcpy(&_f,&_u,4); _f=-_f; memcpy(&_u,&_f,4); mr[mb1]=(int64_t)_u; } break;
        case 0xDF: /* MVDNEG  */ { double _d; uint64_t _u=(uint64_t)mr[mb2]; memcpy(&_d,&_u,8); _d=-_d; memcpy(&_u,&_d,8); mr[mb1]=(int64_t)_u; } break;

        default: break;  // unknown → NOP
        }
        if (mpc < 0 || mpc >= prog_len) break;

        // ── Hidden SO integrity pulse — fires every 4096 VM opcode dispatches ──
        // Buried deep inside the AES-encrypted VM execute loop. An attacker
        // must decrypt the VM bytecode to even reach this call site. The crash
        // path is disguised as an AES key-schedule pointer fault so it looks
        // like a genuine buffer overread, not an intentional security reaction.
        // ── Hidden SO integrity pulse ─────────────────────────────────────
        // Counter threshold (0x5E3 = 1507) and AND mask (0xFFF) are computed
        // at runtime via _mba_pulse_val() / _mba_pulse_mask() so no literal
        // 0x5E3 or 0xFFF ever appears as a MOVZ/MOV immediate in .text.
        {
            static volatile uint32_t _mvc = 0;
            volatile uint32_t _cnt  = ++_mvc;
            volatile uint32_t _mask = _mba_pulse_mask();  // = 0xFFF, no literal
            volatile uint32_t _pval = _mba_pulse_val();   // = 0x5E3, no literal
            if ((_cnt & _mask) == _pval) {
                uint32_t _chk = (uint32_t)gvm_so_integrity();
                if (_chk) {
                    volatile uint32_t _rv = _chk;
                    volatile uintptr_t _p =
                        (uintptr_t)(&mkey[0]) & (uintptr_t)(_rv - _rv);
                    *(volatile uint8_t *)_p = mkey[0];
                }
            }
        }
    }
mvm_halt:;
}


// Bytecode (XOR 0x5C to avoid byte-pattern signatures):
//   CHK_TRACER  → JZ +1 → CRASH
//   CHK_FMAPS   → JZ +1 → CRASH
//   CHK_FPORT   → JZ +1 → CRASH
//   ARTPATH     → JZ +1 → CRASH
//   HOOKMAPS    → JZ +1 → CRASH
//   NOP × 3, HALT
//
// Plain:  10 20 01 02  11 20 01 02  12 20 01 02  13 20 01 02  14 20 01 02  30 30 30 01
// ^ 0x5C: 4C 7C 5D 5E  4D 7C 5D 5E  4E 7C 5D 5E  4F 7C 5D 5E  48 7C 5D 5E  6C 6C 6C 5D
static volatile const uint8_t FONTS_BC_ENC[] = {
    0x4C,0x7C,0x5D,0x5E,  // CHK_TRACER, JZ, +1, CRASH
    0x4D,0x7C,0x5D,0x5E,  // CHK_FMAPS,  JZ, +1, CRASH
    0x4E,0x7C,0x5D,0x5E,  // CHK_FPORT,  JZ, +1, CRASH
    0x4F,0x7C,0x5D,0x5E,  // ARTPATH,    JZ, +1, CRASH
    0x48,0x7C,0x5D,0x5E,  // HOOKMAPS,   JZ, +1, CRASH
    0x6C,0x6C,0x6C,0x5D   // NOP, NOP, NOP, HALT
};
#define FONTS_BC_LEN  ((int)sizeof(FONTS_BC_ENC))
#define FONTS_BC_XOR  0x5Cu

// Startup-only program — runs once from fonts_init() via opaque interpreter.
// Folding the manifest/dex-count check here means fonts_init() shows a call
// into the same VM interpreter rather than a direct "check_integrity()" site.
//   METRICS → JZ +1 → CRASH → HALT
//   Plain:  15 20 01 02  01     ^ 0x5C: 49 7C 5D 5E  5D
static volatile const uint8_t FONTS_BC_STARTUP_ENC[] = {
    0x49,0x7C,0x5D,0x5E,  // METRICS, JZ, +1, CRASH
    0x5D                  // HALT
};
#define FONTS_BC_STARTUP_LEN ((int)sizeof(FONTS_BC_STARTUP_ENC))

// VM wrapper functions — each returns 1 for "tamper detected"
static __attribute__((noinline)) int gvm_tracer(void) {
    char s_status[SP_BUF_SZ*2] = {0}, s_tpid[SP_BUF_SZ] = {0};
    reveal_ns(77, SP_TRACER_STATUS, SP_TRACER_STATUS_LEN, s_status);
    reveal_ns(78, SP_TRACER_PID,    SP_TRACER_PID_LEN,    s_tpid);
    char line[256];
    FILE *f = fopen(s_status, "r");
    if (!f) return 0;
    int traced = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, s_tpid, 10) == 0) {
            traced = (strtol(line + 10, NULL, 10) != 0) ? 1 : 0;
            break;
        }
    }
    fclose(f);
    return traced;
}

static __attribute__((noinline)) int gvm_art_path(void)   { return check_runtime_path(); }
static __attribute__((noinline)) int gvm_hookmaps(void)   { return check_render_hooks(); }

// Resolves APK path itself — keeps the same "no args, just a result" shape
// as every other VM check, giving an attacker nothing distinctive to spot.
static __attribute__((noinline)) int gvm_metrics(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return 0;
    return detect_metrics_tamper(apk_path);
}

// Shared interpreter core — single loop for all programs
static __attribute__((noinline)) void vm_exec(const volatile uint8_t *enc, int len, uint8_t xorKey) {
    uint8_t prog[32];
    if (len > (int)sizeof(prog)) return;
    for (int i = 0; i < len; i++)
        prog[i] = enc[i] ^ xorKey;

    int pc = 0, result = 0;
    while (pc < len) {
        uint8_t op = prog[pc++];
        switch ((GVmOp)op) {
            case G_OP_HALT:     return;
            case G_OP_CRASH:    GLOGE("vm_exec: G_OP_CRASH (prior result=%d)", result); CRASH_HERE("VM bytecode executed G_OP_CRASH"); return;
            // G_OP_TRACER / G_OP_FMAPS / G_OP_HOOKMAPS now run through the
            // Logic VM: the detection logic itself is AES-256-CBC encrypted
            // bytecode.  IDA/Ghidra sees only lvm_exec() — an opaque call
            // into a bytecode interpreter.  The check implementation (which
            // files are opened, which strings are searched) is only visible
            // inside the encrypted blob, not as ARM64 instructions.
            case G_OP_TRACER:
                result = lvm_exec(LBC_TRACER_KHI, LBC_TRACER_KLO,
                                  LBC_TRACER_IHI, LBC_TRACER_ILO,
                                  LBC_TRACER_ENC, LBC_TRACER_LEN,
                                  LBC_TRACER_CS);
                GLOGI("vm_exec: G_OP_TRACER(lvm) result=%d", result);
                break;
            case G_OP_FMAPS:
                result = lvm_exec(LBC_FMAPS_KHI, LBC_FMAPS_KLO,
                                  LBC_FMAPS_IHI, LBC_FMAPS_ILO,
                                  LBC_FMAPS_ENC, LBC_FMAPS_LEN,
                                  LBC_FMAPS_CS);
                GLOGI("vm_exec: G_OP_FMAPS(lvm) result=%d", result);
                break;
            case G_OP_FPORT:
                result = lvm_exec(LBC_FPORT_KHI, LBC_FPORT_KLO,
                                  LBC_FPORT_IHI, LBC_FPORT_ILO,
                                  LBC_FPORT_ENC, LBC_FPORT_LEN,
                                  LBC_FPORT_CS);
                GLOGI("vm_exec: G_OP_FPORT(lvm) result=%d", result);
                break;
            case G_OP_ARTPATH:
                result = lvm_exec(LBC_ARTPATH_KHI, LBC_ARTPATH_KLO,
                                  LBC_ARTPATH_IHI, LBC_ARTPATH_ILO,
                                  LBC_ARTPATH_ENC, LBC_ARTPATH_LEN,
                                  LBC_ARTPATH_CS);
                GLOGI("vm_exec: G_OP_ARTPATH(lvm) result=%d", result);
                break;
            case G_OP_HOOKMAPS:
                result = lvm_exec(LBC_HOOKS_KHI, LBC_HOOKS_KLO,
                                  LBC_HOOKS_IHI, LBC_HOOKS_ILO,
                                  LBC_HOOKS_ENC, LBC_HOOKS_LEN,
                                  LBC_HOOKS_CS);
                GLOGI("vm_exec: G_OP_HOOKMAPS(lvm) result=%d", result);
                break;
            case G_OP_METRICS:
                result = lvm_exec(LBC_METRICS_KHI, LBC_METRICS_KLO,
                                  LBC_METRICS_IHI, LBC_METRICS_ILO,
                                  LBC_METRICS_ENC, LBC_METRICS_LEN,
                                  LBC_METRICS_CS);
                GLOGI("vm_exec: G_OP_METRICS(lvm) result=%d", result);
                break;
            case G_OP_JZ: {
                uint8_t off = (pc < len) ? prog[pc++] : 0;
                if (result == 0) pc += off;
                break;
            }
            case G_OP_JNZ: {
                uint8_t off = (pc < len) ? prog[pc++] : 0;
                if (result != 0) pc += off;
                break;
            }
            case G_OP_NOP:
            default: break;
        }
    }
}

static __attribute__((noinline)) void vm_run(void) {
    vm_exec(FONTS_BC_ENC, FONTS_BC_LEN, FONTS_BC_XOR);
}

// One-time startup check (manifest hash + dex count), run from fonts_init()
// through the opaque interpreter instead of a directly-callable function.
static __attribute__((noinline)) void vm_run_startup(void) {
    vm_exec(FONTS_BC_STARTUP_ENC, FONTS_BC_STARTUP_LEN, FONTS_BC_XOR);
}

// VCore/VirtualApp check — LVCFULL opcode inside an lvm_exec program.
// fonts_init() calls this instead of check_render_backend() directly so
// a disassembler sees only an opaque lvm_exec call, not a named check.
static __attribute__((noinline)) void vm_run_vccheck(void) {
    lvm_exec(LBC_VCCHECK_KHI, LBC_VCCHECK_KLO,
             LBC_VCCHECK_IHI, LBC_VCCHECK_ILO,
             LBC_VCCHECK_ENC, LBC_VCCHECK_LEN,
             LBC_VCCHECK_CS);
}

// Signature verification — LSIGCHK opcode inside a dedicated lvm_exec program.
// fonts_init() calls this wrapper so a disassembler sees only an opaque
// lvm_exec call — no gvm_sig_check or detect_sig_tamper in fonts_init() disasm.
// Bytecode: LSIGCHK → JZ+2 → CRASH → HALT  (crash if tamper detected).
static __attribute__((noinline)) void vm_run_sigcheck(void) {
    lvm_exec(LBC_SIGCHK_KHI, LBC_SIGCHK_KLO,
             LBC_SIGCHK_IHI, LBC_SIGCHK_ILO,
             LBC_SIGCHK_ENC, LBC_SIGCHK_LEN,
             LBC_SIGCHK_CS);
}

// Forked-child kill dispatcher — identical checks to vm_run() but reacts
// with SIGKILL-to-parent + _exit() instead of crash_now(). Patching
// crash_now() in the parent binary cannot silence this independent child.
//
// kill(ppid, SIGKILL) is replaced by _mba_kill_via_svc() (guard_mba.h):
//   • Uses SVC #0 directly — no kill@PLT entry, Frida cannot hook it
//   • SIGKILL constant (9) and __NR_kill (129/37) are MBA-computed at
//     runtime — no MOVZ #9 or MOVZ #129 literal in the binary
#define _LCKILL(khi,klo,ihi,ilo,enc,len,cs,ppid) \
    do { if (lvm_exec(khi,klo,ihi,ilo,enc,len,cs)) { _mba_kill_via_svc((long)(ppid)); _exit(1); } } while(0)

static __attribute__((noinline)) void vm_run_child_kill(pid_t parent_pid) {
    _LCKILL(LBC_TRACER_KHI,  LBC_TRACER_KLO,  LBC_TRACER_IHI,  LBC_TRACER_ILO,  LBC_TRACER_ENC,  LBC_TRACER_LEN,  LBC_TRACER_CS,  parent_pid);
    _LCKILL(LBC_FMAPS_KHI,   LBC_FMAPS_KLO,   LBC_FMAPS_IHI,   LBC_FMAPS_ILO,   LBC_FMAPS_ENC,   LBC_FMAPS_LEN,   LBC_FMAPS_CS,   parent_pid);
    _LCKILL(LBC_FPORT_KHI,   LBC_FPORT_KLO,   LBC_FPORT_IHI,   LBC_FPORT_ILO,   LBC_FPORT_ENC,   LBC_FPORT_LEN,   LBC_FPORT_CS,   parent_pid);
    _LCKILL(LBC_ARTPATH_KHI, LBC_ARTPATH_KLO, LBC_ARTPATH_IHI, LBC_ARTPATH_ILO, LBC_ARTPATH_ENC, LBC_ARTPATH_LEN, LBC_ARTPATH_CS, parent_pid);
    _LCKILL(LBC_HOOKS_KHI,   LBC_HOOKS_KLO,   LBC_HOOKS_IHI,   LBC_HOOKS_ILO,   LBC_HOOKS_ENC,   LBC_HOOKS_LEN,   LBC_HOOKS_CS,   parent_pid);
    _LCKILL(LBC_METRICS_KHI, LBC_METRICS_KLO, LBC_METRICS_IHI, LBC_METRICS_ILO, LBC_METRICS_ENC, LBC_METRICS_LEN, LBC_METRICS_CS, parent_pid);
}
#undef _LCKILL

// ════════════════════════════════════════════════════════════════════════════
// Background Watchdog Thread — spawned from fonts_init(), runs every 3 s
// Frida + magisk hide themselves from TracerPid at attach time but can be
// caught on subsequent polls. Port 27042 is checked continuously for
// late-attach detection.
// ════════════════════════════════════════════════════════════════════════════

static void *watchdog_thread(void *) {
    struct timespec ts = {3, 0};
    for (;;) {
        nanosleep(&ts, NULL);
        vm_run();
    }
    return NULL;
}

// ════════════════════════════════════════════════════════════════════════════
// Forward declaration (second instance for clarity before spawn_background_watch).
// Full definition is in the LAYER 2 section below.
// The forked child calls it via a direct kill() path rather than crash_now(),
// so patching crash_now() alone cannot silence this layer.
// ════════════════════════════════════════════════════════════════════════════

static int detect_metrics_tamper(const char *apk_path);

// ════════════════════════════════════════════════════════════════════════════
// Fork-based isolated background guard process
//
// fork() spawns a child that is completely independent of the Android app
// lifecycle. The child carries no JVM, no Binder threads — just a tight
// polling loop. Strategy:
//   • Polls every 5 s, runs the same native checks as the watchdog thread.
//   • If parent dies (getppid() changes) the child exits cleanly.
//   • If any check fires, child sends SIGKILL to parent AND self.
//   • Reactions here use raw kill()/_exit() instead of crash_now() so that
//     a single binary patch to crash_now() cannot silence this layer.
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline)) void spawn_background_watch(void) {
    signal(SIGCHLD, SIG_IGN);

    pid_t parent_pid = getpid();
    pid_t child = fork();

    if (child < 0) return;
    if (child > 0) return;

    // ── Child process ──────────────────────────────────────────────────────
    setsid();

    struct timespec ts = {5, 0};
    for (;;) {
        nanosleep(&ts, NULL);
        if (getppid() != parent_pid) _exit(0);
        // All 6 checks route through lvm_exec — no named check_* call sites
        // visible in the child process disassembly. On any detection:
        // SIGKILL parent + self-exit (independent of parent's crash_now()).
        vm_run_child_kill(parent_pid);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ── LAYER 2: APK ZIP integrity — AndroidManifest.xml hash + dex count ────
//
// Fully native, no JNI/Java dependency — runs from fonts_init() (ELF
// constructor) before any Java code. Reads the installed APK directly as a
// ZIP (central-directory walk) and decompresses entries with zlib's raw
// inflate, then compares against values stamped at protect time:
//   assets/font_metrics.dat — FNV-1a64 hash of AndroidManifest.xml
//   assets/font_index.dat   — count of classes*.dex files
// Both are AES-256-CBC encrypted using the same key/IV as guard_pstrings.inc.
//
// This catches anything the Class.forName/provider check cannot: an attacker
// who repackages the APK to ADD a new DEX/provider (e.g. a dialog-killer) or
// edits AndroidManifest.xml, without needing the added code to be a member
// of a hardcoded literal-name list.
// ════════════════════════════════════════════════════════════════════════════

struct ZipEntryInfo {
    uint16_t method;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint32_t local_offset;
    int      found;
};

static uint32_t g_rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t g_rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

static int zip_locate_eocd(FILE *f, uint32_t *cd_offset, uint32_t *cd_size) {
    if (fseek(f, 0, SEEK_END) != 0) return 0;
    long fsize = ftell(f);
    if (fsize < 22) return 0;
    long searchLen = fsize < 66000 ? fsize : 66000;
    uint8_t *buf = (uint8_t *)malloc((size_t)searchLen);
    if (!buf) return 0;
    if (fseek(f, fsize - searchLen, SEEK_SET) != 0) { free(buf); return 0; }
    size_t rd = fread(buf, 1, (size_t)searchLen, f);
    long found = -1;
    for (long i = (long)rd - 22; i >= 0; i--) {
        if (buf[i]==0x50 && buf[i+1]==0x4b && buf[i+2]==0x05 && buf[i+3]==0x06) { found = i; break; }
    }
    if (found < 0) { free(buf); return 0; }
    *cd_size   = g_rd32(buf + found + 12);
    *cd_offset = g_rd32(buf + found + 16);
    free(buf);
    return 1;
}

static int zip_scan_central_dir(FILE *f, uint32_t cd_offset, uint32_t cd_size,
                                 const char *want_name, ZipEntryInfo *want_info,
                                 int *dex_count_out) {
    // Decode ".dex" and "classes" via AES-256-CBC — no plaintext in .rodata.
    char s_dot_dex[SP_BUF_SZ], s_classes[SP_BUF_SZ];
    reveal_ns(5u, SP_DOT_DEX,      SP_DOT_DEX_LEN,      s_dot_dex);
    reveal_ns(6u, SP_STR_CLASSES,  SP_STR_CLASSES_LEN,  s_classes);

    uint8_t *cd = (uint8_t *)malloc(cd_size ? cd_size : 1);
    if (!cd) return 0;
    if (fseek(f, (long)cd_offset, SEEK_SET) != 0) { free(cd); return 0; }
    if (cd_size > 0 && fread(cd, 1, cd_size, f) != cd_size) { free(cd); return 0; }

    int dex_count = 0;
    uint32_t p = 0;
    while (p + 46 <= cd_size) {
        if (!(cd[p]==0x50 && cd[p+1]==0x4b && cd[p+2]==0x01 && cd[p+3]==0x02)) break;
        uint16_t method    = g_rd16(cd + p + 10);
        uint32_t comp_sz   = g_rd32(cd + p + 20);
        uint32_t uncomp_sz = g_rd32(cd + p + 24);
        uint16_t name_len  = g_rd16(cd + p + 28);
        uint16_t extra_len = g_rd16(cd + p + 30);
        uint16_t comm_len  = g_rd16(cd + p + 32);
        uint32_t local_off = g_rd32(cd + p + 42);
        uint32_t name_off  = p + 46;
        if ((uint64_t)name_off + name_len > cd_size) break;

        char name[256];
        uint16_t nlen = name_len < 255 ? name_len : 255;
        memcpy(name, cd + name_off, nlen);
        name[nlen] = '\0';

        size_t L = strlen(name);
        if (L > 4 && strcmp(name + L - 4, s_dot_dex) == 0 && strncmp(name, s_classes, 7) == 0) {
            int ok = 1;
            for (size_t i = 7; i < L - 4; i++) if (name[i] < '0' || name[i] > '9') { ok = 0; break; }
            if (ok) dex_count++;
        }

        if (want_name && want_info && !want_info->found && strcmp(name, want_name) == 0) {
            want_info->method       = method;
            want_info->comp_size    = comp_sz;
            want_info->uncomp_size  = uncomp_sz;
            want_info->local_offset = local_off;
            want_info->found        = 1;
        }

        uint64_t next = (uint64_t)name_off + name_len + extra_len + comm_len;
        if (next <= p) break;
        p = (uint32_t)next;
    }
    free(cd);
    if (dex_count_out) *dex_count_out = dex_count;
    return 1;
}

static int zip_read_entry_data(FILE *f, const ZipEntryInfo *info,
                                uint8_t *out, uint32_t out_cap, uint32_t *out_len) {
    if (!info->found) return 0;
    if (fseek(f, (long)info->local_offset, SEEK_SET) != 0) return 0;
    uint8_t lh[30];
    if (fread(lh, 1, 30, f) != 30) return 0;
    if (!(lh[0]==0x50 && lh[1]==0x4b && lh[2]==0x03 && lh[3]==0x04)) return 0;
    uint16_t name_len  = g_rd16(lh + 26);
    uint16_t extra_len = g_rd16(lh + 28);
    if (fseek(f, (long)name_len + (long)extra_len, SEEK_CUR) != 0) return 0;

    if (info->method == 0) {
        if (info->uncomp_size > out_cap) return 0;
        if (info->uncomp_size > 0 && fread(out, 1, info->uncomp_size, f) != info->uncomp_size) return 0;
        *out_len = info->uncomp_size;
        return 1;
    }
    if (info->method != 8) return 0;  // only STORED/DEFLATE supported

    uint8_t *comp = (uint8_t *)malloc(info->comp_size ? info->comp_size : 1);
    if (!comp) return 0;
    if (info->comp_size > 0 && fread(comp, 1, info->comp_size, f) != info->comp_size) { free(comp); return 0; }

    z_stream zs; memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, -15) != Z_OK) { free(comp); return 0; }
    zs.next_in   = comp;
    zs.avail_in  = info->comp_size;
    zs.next_out  = out;
    zs.avail_out = out_cap;
    int ret = inflate(&zs, Z_FINISH);
    uint32_t produced = out_cap - zs.avail_out;
    inflateEnd(&zs);
    free(comp);
    if (ret != Z_STREAM_END) return 0;
    *out_len = produced;
    return 1;
}

// FNV-1a 64-bit — MUST match ApkProtector.fnv1a64() bit-for-bit or every
// APK fails its own integrity check on launch.
static uint64_t fnv1a64(const uint8_t *data, uint32_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (uint32_t i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ULL; }
    return h;
}

#define MANIFEST_BUF_SZ  (2 * 1024 * 1024)
#define STAMP_BUF_SZ      32

// ════════════════════════════════════════════════════════════════════════════
// svc #0 wrappers for metrics / SO checks — defined here so they are
// available before Layer-4's identical copies.  Using raw kernel syscalls
// means IO-redirect hooks (PLT/GOT patches) have zero attachment surface.
// ════════════════════════════════════════════════════════════════════════════

#if defined(__aarch64__)
static int m_openat(const char *path, int flags) {
    register long x0 __asm__("x0") = (long)AT_FDCWD;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = (long)(flags | O_CLOEXEC);
    register long x3 __asm__("x3") = 0L;
    register long x8 __asm__("x8") = 56L;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x8) : "memory","cc");
    return (int)x0;
}
static ssize_t m_pread(int fd, void *buf, size_t n, off_t off) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)n;
    register long x3 __asm__("x3") = (long)off;
    register long x8 __asm__("x8") = 67L;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x8) : "memory","cc");
    return (ssize_t)x0;
}
static off_t m_lseek(int fd, off_t off, int whence) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)off;
    register long x2 __asm__("x2") = (long)whence;
    register long x8 __asm__("x8") = 62L;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x8) : "memory","cc");
    return (off_t)x0;
}
static int m_close(int fd) {
    register long x0 __asm__("x0") = (long)fd;
    register long x8 __asm__("x8") = 57L;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory","cc");
    return (int)x0;
}
#elif defined(__arm__)
static int m_openat(const char *path, int flags) {
    register long r0 __asm__("r0") = (long)AT_FDCWD;
    register long r1 __asm__("r1") = (long)path;
    register long r2 __asm__("r2") = (long)(flags | O_CLOEXEC);
    register long r3 __asm__("r3") = 0L;
    register long r7 __asm__("r7") = 322L;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r3),"r"(r7) : "memory","cc");
    return (int)r0;
}
static ssize_t m_pread(int fd, void *buf, size_t n, off_t off) {
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)n;
    register long r3 __asm__("r3") = 0L;
    register long r4 __asm__("r4") = (long)off;
    register long r5 __asm__("r5") = 0L;
    register long r7 __asm__("r7") = 180L;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r3),"r"(r4),"r"(r5),"r"(r7) : "memory","cc");
    return (ssize_t)r0;
}
static off_t m_lseek(int fd, off_t off, int whence) {
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)off;
    register long r2 __asm__("r2") = (long)whence;
    register long r7 __asm__("r7") = 19L;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r7) : "memory","cc");
    return (off_t)r0;
}
static int m_close(int fd) {
    register long r0 __asm__("r0") = (long)fd;
    register long r7 __asm__("r7") = 6L;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory","cc");
    return (int)r0;
}
#else
static int     m_openat(const char *p, int f) { return open(p, f|O_CLOEXEC); }
static ssize_t m_pread(int fd,void *b,size_t n,off_t o) { return pread(fd,b,n,o); }
static off_t   m_lseek(int fd,off_t o,int w) { return lseek(fd,o,w); }
static int     m_close(int fd) { return close(fd); }
#endif

/* Locate EOCD via svc #0 — fills cd_off/cd_sz. */
static int m_eocd(int fd, uint32_t *cd_off, uint32_t *cd_sz) {
    off_t fsize = m_lseek(fd, 0, SEEK_END);
    if (fsize < 22) return 0;
    size_t search = (size_t)(fsize < 66022 ? fsize : 66022);
    uint8_t *buf = (uint8_t *)malloc(search);
    if (!buf) return 0;
    ssize_t rd = m_pread(fd, buf, search, fsize - (off_t)search);
    if (rd < 22) { free(buf); return 0; }
    long found = -1;
    for (long i = (long)rd - 22; i >= 0; i--) {
        if (buf[i]==0x50&&buf[i+1]==0x4b&&buf[i+2]==0x05&&buf[i+3]==0x06) {
            found = i; break;
        }
    }
    if (found < 0) { free(buf); return 0; }
    *cd_sz  = (uint32_t)(buf[found+12]) | ((uint32_t)(buf[found+13])<<8)
            | ((uint32_t)(buf[found+14])<<16) | ((uint32_t)(buf[found+15])<<24);
    *cd_off = (uint32_t)(buf[found+16]) | ((uint32_t)(buf[found+17])<<8)
            | ((uint32_t)(buf[found+18])<<16) | ((uint32_t)(buf[found+19])<<24);
    free(buf);
    return 1;
}

/* Read & scan the central directory via svc #0.
   - Counts classes*.dex entries into *dex_count (if non-NULL).
   - Counts total ZIP entries into *total_entries (if non-NULL).
   - Fills want_info for the entry whose name equals want_name (if non-NULL).
   Returns 1 on success, 0 on allocation/read failure. */
static int m_scan_cd(int fd, uint32_t cd_off, uint32_t cd_sz,
                     const char *want_name, ZipEntryInfo *want_info,
                     int *dex_count, int *total_entries) {
    if (cd_sz == 0) return 1;
    uint8_t *cd = (uint8_t *)malloc(cd_sz);
    if (!cd) return 0;
    ssize_t rd = m_pread(fd, cd, cd_sz, (off_t)cd_off);
    if (rd != (ssize_t)cd_sz) { free(cd); return 0; }

    size_t wlen = want_name ? strlen(want_name) : 0;
    uint32_t p = 0;
    while (p + 46 <= cd_sz) {
        if (!(cd[p]==0x50&&cd[p+1]==0x4b&&cd[p+2]==0x01&&cd[p+3]==0x02)) break;
        uint16_t method    = (uint16_t)(cd[p+10]) | ((uint16_t)(cd[p+11])<<8);
        uint32_t comp_sz   = (uint32_t)(cd[p+20]) | ((uint32_t)(cd[p+21])<<8)
                           | ((uint32_t)(cd[p+22])<<16) | ((uint32_t)(cd[p+23])<<24);
        uint32_t uncomp_sz = (uint32_t)(cd[p+24]) | ((uint32_t)(cd[p+25])<<8)
                           | ((uint32_t)(cd[p+26])<<16) | ((uint32_t)(cd[p+27])<<24);
        uint16_t name_len  = (uint16_t)(cd[p+28]) | ((uint16_t)(cd[p+29])<<8);
        uint16_t extra_len = (uint16_t)(cd[p+30]) | ((uint16_t)(cd[p+31])<<8);
        uint16_t comm_len  = (uint16_t)(cd[p+32]) | ((uint16_t)(cd[p+33])<<8);
        uint32_t local_off = (uint32_t)(cd[p+42]) | ((uint32_t)(cd[p+43])<<8)
                           | ((uint32_t)(cd[p+44])<<16) | ((uint32_t)(cd[p+45])<<24);
        if ((uint64_t)(p + 46) + name_len > cd_sz) break;

        char ename[256];
        uint16_t nlen = name_len < 255 ? name_len : 255;
        memcpy(ename, cd + p + 46, nlen); ename[nlen] = '\0';

        if (total_entries) (*total_entries)++;

        /* DEX count: entry name starts with "classes" and ends with ".dex" */
        if (dex_count && nlen >= 10 &&
            memcmp(ename, "classes", 7) == 0 &&
            memcmp(ename + nlen - 4, ".dex", 4) == 0)
            (*dex_count)++;

        /* Wanted entry */
        if (want_name && want_info && !want_info->found &&
            wlen == nlen && memcmp(ename, want_name, wlen) == 0) {
            want_info->method       = method;
            want_info->comp_size    = comp_sz;
            want_info->uncomp_size  = uncomp_sz;
            want_info->local_offset = local_off;
            want_info->found        = 1;
        }
        p += 46 + name_len + extra_len + comm_len;
    }
    free(cd);
    return 1;
}

/* Read a ZIP entry's uncompressed data via svc #0 pread64.
   Returns bytes written, 0 on error. Handles STORED and DEFLATE. */
static uint32_t m_read_entry(int fd, const ZipEntryInfo *info,
                              uint8_t *out, uint32_t out_max) {
    uint8_t lh[30];
    if (m_pread(fd, lh, 30, (off_t)info->local_offset) != 30) return 0;
    if (lh[0]!=0x50||lh[1]!=0x4b||lh[2]!=0x03||lh[3]!=0x04) return 0;
    uint16_t nl = (uint16_t)(lh[26]) | ((uint16_t)(lh[27])<<8);
    uint16_t el = (uint16_t)(lh[28]) | ((uint16_t)(lh[29])<<8);
    off_t data_off = (off_t)info->local_offset + 30 + nl + el;
    if (info->method == 0) {
        if (info->uncomp_size > out_max) return 0;
        ssize_t r = m_pread(fd, out, info->uncomp_size, data_off);
        return (r == (ssize_t)info->uncomp_size) ? info->uncomp_size : 0;
    }
    if (info->method == 8) {
        if (info->comp_size > 4*1024*1024) return 0;
        uint8_t *comp = (uint8_t *)malloc(info->comp_size);
        if (!comp) return 0;
        ssize_t r = m_pread(fd, comp, info->comp_size, data_off);
        if (r != (ssize_t)info->comp_size) { free(comp); return 0; }
        z_stream strm; memset(&strm, 0, sizeof(strm));
        strm.next_in = comp; strm.avail_in = info->comp_size;
        strm.next_out = out; strm.avail_out = out_max;
        if (inflateInit2(&strm, -15) != Z_OK) { free(comp); return 0; }
        int rc = inflate(&strm, Z_FINISH);
        uint32_t written = out_max - strm.avail_out;
        inflateEnd(&strm); free(comp);
        return (rc == Z_STREAM_END) ? written : 0;
    }
    return 0;
}

// Returns 1 if tamper detected, 0 if clean. Does NOT call crash_now() itself
// so the fork-based watchdog child can react via a direct kill() path instead.
//
// Uses raw svc #0 syscalls throughout — IO-redirect hooks installed by
// packer tools (AppComponentFactory + PLT/GOT patch) have zero effect.
static int detect_metrics_tamper(const char *apk_path) {
    GLOGI("detect_metrics_tamper: checking %s", apk_path);

    /* Open via svc #0 — bypasses every PLT/GOT IO hook */
    int fd = m_openat(apk_path, O_RDONLY);
    if (fd < 0) {
        GLOGI("detect_metrics_tamper: openat failed errno=%d — transient", errno);
        return 0;
    }

    uint32_t cd_offset = 0, cd_size = 0;
    if (!m_eocd(fd, &cd_offset, &cd_size)) {
        GLOGE("detect_metrics_tamper: EOCD not found");
        m_close(fd); return 1;
    }
    GLOGI("detect_metrics_tamper: cd_offset=%u cd_size=%u", cd_offset, cd_size);

    char s_manifest[SP_BUF_SZ], s_metrics[SP_BUF_SZ], s_fidx[SP_BUF_SZ];
    reveal_ns(13u, SP_MANIFEST,       SP_MANIFEST_LEN,       s_manifest);
    reveal_ns(14u, SP_FONT_METRICS_Z, SP_FONT_METRICS_Z_LEN, s_metrics);
    reveal_ns(15u, SP_FONT_INDEX_Z,   SP_FONT_INDEX_Z_LEN,   s_fidx);

    ZipEntryInfo manifestInfo; memset(&manifestInfo, 0, sizeof(manifestInfo));
    int dex_count = 0;
    if (!m_scan_cd(fd, cd_offset, cd_size, s_manifest, &manifestInfo, &dex_count, NULL)) {
        GLOGE("detect_metrics_tamper: CD scan failed");
        m_close(fd); return 1;
    }
    GLOGI("detect_metrics_tamper: dex_count=%d", dex_count);
    if (!manifestInfo.found || manifestInfo.uncomp_size == 0 ||
        manifestInfo.uncomp_size > MANIFEST_BUF_SZ) {
        GLOGE("detect_metrics_tamper: manifest entry missing/invalid");
        m_close(fd); return 1;
    }

    uint8_t *manifest = (uint8_t *)malloc(MANIFEST_BUF_SZ);
    if (!manifest) { m_close(fd); return 0; }
    uint32_t manifest_len = m_read_entry(fd, &manifestInfo, manifest, MANIFEST_BUF_SZ);
    if (!manifest_len) {
        GLOGE("detect_metrics_tamper: failed to read AndroidManifest.xml");
        free(manifest); m_close(fd); return 1;
    }
    uint64_t computed_hash = fnv1a64(manifest, manifest_len);
    free(manifest);
    GLOGI("detect_metrics_tamper: manifest len=%u hash=0x%016llx",
          manifest_len, (unsigned long long)computed_hash);

    ZipEntryInfo mhInfo; memset(&mhInfo, 0, sizeof(mhInfo));
    ZipEntryInfo dcInfo; memset(&dcInfo, 0, sizeof(dcInfo));
    int dummy = 0;
    if (!m_scan_cd(fd, cd_offset, cd_size, s_metrics, &mhInfo, &dummy, NULL) || !mhInfo.found) {
        GLOGE("detect_metrics_tamper: font_metrics.dat missing");
        m_close(fd); return 1;
    }
    dummy = 0;
    if (!m_scan_cd(fd, cd_offset, cd_size, s_fidx, &dcInfo, &dummy, NULL) || !dcInfo.found) {
        GLOGE("detect_metrics_tamper: font_index.dat missing");
        m_close(fd); return 1;
    }

    uint8_t mhCipher[STAMP_BUF_SZ], dcCipher[STAMP_BUF_SZ];
    uint32_t mhLen = m_read_entry(fd, &mhInfo, mhCipher, STAMP_BUF_SZ);
    uint32_t dcLen = m_read_entry(fd, &dcInfo, dcCipher, STAMP_BUF_SZ);
    m_close(fd);

    if (!mhLen || !dcLen) {
        GLOGE("detect_metrics_tamper: failed to read stamp entries");
        return 1;
    }

    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t mhPlain[STAMP_BUF_SZ], dcPlain[STAMP_BUF_SZ];
    int mhPlainLen = aes256_cbc_dec(key, iv, mhCipher, (int)mhLen, mhPlain);
    int dcPlainLen = aes256_cbc_dec(key, iv, dcCipher, (int)dcLen, dcPlain);
    memset(key, 0, 32); memset(iv, 0, 16);
    GLOGI("detect_metrics_tamper: mhPlainLen=%d dcPlainLen=%d", mhPlainLen, dcPlainLen);

    if (mhPlainLen < 8 || dcPlainLen < 4) {
        GLOGE("detect_metrics_tamper: decrypted stamp too short — corrupt or wrong key");
        return 1;
    }

    uint64_t expected_hash;  memcpy(&expected_hash, mhPlain, 8);
    uint32_t expected_count; memcpy(&expected_count, dcPlain, 4);

    // ── Opt-out sentinel: ApkProtector writes (hash=0, count=0) when the
    // user disables the Manifest & Dex integrity check in Settings before
    // protecting. Recognised here so guard.cpp skips the check gracefully.
    // Sentinel is AES-256-CBC encrypted like real stamps — an attacker must
    // know the guard key to forge it.
    if (expected_hash == 0ULL && expected_count == 0u) {
        GLOGI("detect_metrics_tamper: sentinel(0,0) — check disabled in settings, skipping");
        return 0;
    }

    GLOGI("detect_metrics_tamper: expected_hash=0x%016llx expected_count=%u vs computed=0x%016llx dex=%d",
          (unsigned long long)expected_hash, expected_count, (unsigned long long)computed_hash, dex_count);

    if (expected_hash != computed_hash)        { GLOGE("detect_metrics_tamper: MANIFEST HASH MISMATCH"); return 1; }
    if (expected_count != (uint32_t)dex_count) { GLOGE("detect_metrics_tamper: DEX COUNT MISMATCH");     return 1; }
    GLOGI("detect_metrics_tamper: clean");
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// ── LAYER 3: Native .so self-integrity — FNV-1a64 hash of generated JNI .so
//
// At protect-time ApkProtector computes FNV-1a64 of the compiled user .so,
// AES-256-CBC encrypts the 8-byte result (same guard key/IV), and stores it
// as assets/font_glyph.dat.  At runtime this layer:
//   1. Finds the user's .so name from /proc/self/maps (skipping libcipher.so)
//   2. Opens the APK, locates that lib/ ZIP entry, reads + inflates it
//   3. FNV-1a64 hashes the raw bytes and decrypts font_glyph.dat
//   4. Crash if the asset is MISSING, decryption fails, or hash mismatches
//
// Called from two independent sites:
//   • fonts_init() — ELF __attribute__((constructor)), before any Java runs
//   • lvm_method_exec execute loop — every 4096 VM opcode dispatches
// The forked background child (vm_run_child_kill) also polls via gvm_so_integrity.
// ════════════════════════════════════════════════════════════════════════════

// XOR-decode helper — keeps all sensitive path strings out of .rodata
#define _SX(dst, enc, xk) do { \
    for (int _i = 0; _i < (int)(sizeof(enc)-1); _i++) \
        (dst)[_i] = (char)((enc)[_i] ^ (uint8_t)(xk)); \
    (dst)[sizeof(enc)-1] = '\0'; } while(0)

// Scans /proc/self/maps for the first /data/app/*.so that is NOT libcipher.so.
// Copies just the filename (e.g. "libmyapp.so") into out[out_max].
static __attribute__((noinline)) int so_find_user_lib_name(char *out, int out_max) {
    static const uint8_t _sm[] = {0x84,0xDB,0xD9,0xC4,0xC8,0x84,0xD8,0xCE,0xC7,0xCD,0x84,0xC6,0xCA,0xDB,0xD8,'\0'}; // /proc/self/maps
    static const uint8_t _da[] = {0x84,0xCF,0xCA,0xDF,0xCA,0x84,0xCA,0xDB,0xDB,0x84,'\0'};                            // /data/app/
    static const uint8_t _so[] = {0x85,0xD8,0xC4,'\0'};                                                                // .so
    static const uint8_t _ci[] = {0xC8,0xC2,0xDB,0xC3,0xCE,0xD9,'\0'};                                                // cipher
    char s_maps[20], s_data[14], s_so[6], s_ci[10];
    _SX(s_maps, _sm, 0xAB); _SX(s_data, _da, 0xAB);
    _SX(s_so,   _so, 0xAB); _SX(s_ci,   _ci, 0xAB);

    /* svc #0 — DPatch hooks fopen(/proc/self/maps) to return fake content;
     * raw pread64 goes directly to the kernel and cannot be intercepted. */
    RawRdr rdr; rrd_open(&rdr, s_maps); if (rdr.eof) return 0;
    char line[512];
    while (rrd_getline(&rdr, line, sizeof(line))) {
        if (!strstr(line, s_data)) continue;
        if (!strstr(line, s_so))   continue;
        char *sl = strrchr(line, '/'); if (!sl) continue;
        char *name = sl + 1;
        char *nl = strstr(name, "\n"); if (nl) *nl = '\0';
        if (!strstr(name, s_so)) continue;   // must end in .so
        if ( strstr(name, s_ci)) continue;   // skip libcipher.so
        int n = (int)strlen(name);
        if (n <= 3 || n >= out_max) continue;
        strncpy(out, name, out_max - 1); out[out_max - 1] = '\0';
        rrd_close(&rdr); return 1;
    }
    rrd_close(&rdr); return 0;
}

// Returns 1 = tamper/missing (→ crash), 0 = clean.
// MISSING font_glyph.dat always returns 1 — the asset is mandatory.
// Uses raw svc #0 — IO-redirect hooks installed by packer tools cannot
// intercept this. Any modification to the user's .so or font_glyph.dat
// is caught regardless of what tool made the change.
static __attribute__((noinline)) int detect_so_tamper(const char *apk_path) {
    char lib_name[128] = {0};
    if (!so_find_user_lib_name(lib_name, sizeof(lib_name))) return 0; // still loading

    /* Open via svc #0 — no PLT, no hook surface */
    int fd = m_openat(apk_path, O_RDONLY);
    if (fd < 0) return 0; // transient — skip rather than false-crash

    uint32_t cd_offset = 0, cd_size = 0;
    if (!m_eocd(fd, &cd_offset, &cd_size)) { m_close(fd); return 1; }

    // Build "lib/<abi>/libname.so" — try arm64-v8a first, then armeabi-v7a
    static const uint8_t _a64[] = {0xC7,0xC2,0xC9,0x84,0xCA,0xD9,0xC6,0x9D,0x9F,0x86,0xDD,0x93,0xCA,0x84,'\0'};
    static const uint8_t _a32[] = {0xC7,0xC2,0xC9,0x84,0xCA,0xD9,0xC6,0xCE,0xCA,0xC9,0xC2,0x86,0xDD,0x9C,0xCA,0x84,'\0'};
    char s64[20], s32[22], entry[196];
    _SX(s64, _a64, 0xAB); _SX(s32, _a32, 0xAB);

    ZipEntryInfo soInfo; memset(&soInfo, 0, sizeof(soInfo)); int dummy = 0;
    snprintf(entry, sizeof(entry), "%s%s", s64, lib_name);
    if (!m_scan_cd(fd, cd_offset, cd_size, entry, &soInfo, &dummy, NULL) || !soInfo.found) {
        soInfo.found = 0; dummy = 0;
        snprintf(entry, sizeof(entry), "%s%s", s32, lib_name);
        m_scan_cd(fd, cd_offset, cd_size, entry, &soInfo, &dummy, NULL);
    }
    if (!soInfo.found || soInfo.uncomp_size == 0) {
        GLOGE("detect_so_tamper: user .so not found in APK");
        m_close(fd); return 1;
    }

    uint8_t *so_buf = (uint8_t *)malloc(soInfo.uncomp_size);
    if (!so_buf) { m_close(fd); return 0; } // OOM — transient skip
    uint32_t so_len = m_read_entry(fd, &soInfo, so_buf, soInfo.uncomp_size);
    if (!so_len) { free(so_buf); m_close(fd); return 1; }
    uint64_t computed = fnv1a64(so_buf, so_len);
    free(so_buf);

    // Locate assets/font_glyph.dat — MISSING is a hard crash
    char s_glyph[SP_BUF_SZ];
    reveal(SP_FONT_GLYPH_Z, SP_FONT_GLYPH_Z_LEN, s_glyph);
    ZipEntryInfo glInfo; memset(&glInfo, 0, sizeof(glInfo));
    dummy = 0;
    if (!m_scan_cd(fd, cd_offset, cd_size, s_glyph, &glInfo, &dummy, NULL) || !glInfo.found) {
        GLOGE("detect_so_tamper: font_glyph.dat MISSING — mandatory asset deleted");
        m_close(fd); return 1;
    }
    uint8_t glCipher[STAMP_BUF_SZ];
    uint32_t glLen = m_read_entry(fd, &glInfo, glCipher, STAMP_BUF_SZ);
    m_close(fd);
    if (!glLen) return 1;

    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t glPlain[STAMP_BUF_SZ];
    int glPlainLen = aes256_cbc_dec(key, iv, glCipher, (int)glLen, glPlain);
    memset(key, 0, 32); memset(iv, 0, 16);
    if (glPlainLen < 8) { GLOGE("detect_so_tamper: decrypt failed"); return 1; }

    uint64_t expected; memcpy(&expected, glPlain, 8);
    if (expected == 0ULL) { GLOGI("detect_so_tamper: sentinel(0) skip"); return 0; }
    if (expected != computed) {
        GLOGE("detect_so_tamper: HASH MISMATCH exp=0x%016llx got=0x%016llx",
              (unsigned long long)expected, (unsigned long long)computed);
        return 1;
    }
    GLOGI("detect_so_tamper: clean 0x%016llx", (unsigned long long)computed);
    return 0;
}

// Wrapper with APK-path resolution — same shape as gvm_metrics()
static __attribute__((noinline)) int gvm_so_integrity(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return 0;
    return detect_so_tamper(apk_path);
}

// ════════════════════════════════════════════════════════════════════════════
// LAYER 4 — Hardened Signature Verification (ARM svc #0 edition)
//
// Protect-time: SHA-256 of the raw V1 signing certificate (META-INF/*.RSA /
// .DSA / .EC) stored AES-256-CBC encrypted in assets/font_kern.dat.
// Sentinel = 32 × 0x00 (check disabled by user).
//
// ── NP Manager bypass-mode defeat matrix (screenshot, July 2026) ─────────
//
//  Kill Sig ++1.0 / ++2.0 / MODEX3.0 / SFSignKiller / NPSignKiller
//      → PMS Hook: Java Binder proxy replaces getPackageInfo() signatures.
//        DEFEATED: we never call PackageManager — pure native C.
//
//  LspatchSignKiller
//      → LSPatch SigBypass.java: Xposed/LSPosed ART hook on PackageManager.
//        DEFEATED: ELF __attribute__((constructor)) fires before ART inits.
//
//  EirvSignKiller / EirvSignKiller2 / FancyBypass / SRPatch (IO method)
//      → IO Hook: patch the PLT/GOT entry for libc open()/openat()/read()/
//        pread64() in the target .so, redirect the fd to the original APK.
//        DEFEATED HERE: every byte of file I/O uses inline ARM "svc #0"
//        assembly — no PLT, no GOT, no libc symbol lookup.  The hook has
//        zero attachment surface.
//
//  SRPatch (SVC method) / APatch / KernelPatch kernel hooks
//      → Intercept raw syscalls at kernel boundary; requires root + module.
//        DETECTED: existing FMAPS/TRACER LVM opcodes catch KernelSU/Magisk/
//        APatch and Zygisk.  g_sig_maps_scan() additionally searches for
//        bypass-tool native libraries injected directly into our address space.
//
// Zero libc involvement in the critical I/O path → unbypassable without root.
// ════════════════════════════════════════════════════════════════════════════

// ── §1  Inline-asm raw syscall wrappers — zero PLT / GOT / libc ────────────
//
// ARM64 calling convention: x0–x5 = args, x8 = syscall number, svc #0.
// ARM32 EABI convention:    r0–r5 = args, r7 = syscall number, svc #0.
// x86/x86_64 compile-only fallback (not our shipped ABI).

#if defined(__aarch64__)

static __attribute__((always_inline)) inline
int g_sig_openat(const char *path, int flags) {
    register long x0 __asm__("x0") = (long)AT_FDCWD;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = (long)(flags | O_CLOEXEC);
    register long x3 __asm__("x3") = 0L;
    register long x8 __asm__("x8") = 56L; /* __NR_openat */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc");
    return (int)x0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_read(int fd, void *buf, size_t n) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)n;
    register long x8 __asm__("x8") = 63L; /* __NR_read */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc");
    return (ssize_t)x0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_pread(int fd, void *buf, size_t n, off_t off) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)n;
    register long x3 __asm__("x3") = (long)off;
    register long x8 __asm__("x8") = 67L; /* __NR_pread64 */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc");
    return (ssize_t)x0;
}
static __attribute__((always_inline)) inline
off_t g_sig_lseek(int fd, off_t off, int whence) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)off;
    register long x2 __asm__("x2") = (long)whence;
    register long x8 __asm__("x8") = 62L; /* __NR_lseek */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc");
    return (off_t)x0;
}
static __attribute__((always_inline)) inline
int g_sig_close(int fd) {
    register long x0 __asm__("x0") = (long)fd;
    register long x8 __asm__("x8") = 57L; /* __NR_close */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory", "cc");
    return (int)x0;
}

#elif defined(__arm__)

static __attribute__((always_inline)) inline
int g_sig_openat(const char *path, int flags) {
    register long r0 __asm__("r0") = (long)AT_FDCWD; /* AT_FDCWD = -100 */
    register long r1 __asm__("r1") = (long)path;
    register long r2 __asm__("r2") = (long)(flags | O_CLOEXEC);
    register long r3 __asm__("r3") = 0L;
    register long r7 __asm__("r7") = 322L; /* __NR_openat ARM32 */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r3), "r"(r7)
        : "memory", "cc");
    return (int)r0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_read(int fd, void *buf, size_t n) {
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)n;
    register long r7 __asm__("r7") = 3L; /* __NR_read */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory", "cc");
    return (ssize_t)r0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_pread(int fd, void *buf, size_t n, off_t off) {
    /* ARM32 EABI pread64: r0=fd r1=buf r2=count r3=0(pad) r4=off_lo r5=off_hi */
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)n;
    register long r3 __asm__("r3") = 0L; /* 64-bit alignment pad */
    register long r4 __asm__("r4") = (long)off;
    register long r5 __asm__("r5") = 0L; /* offset_hi — APKs < 4 GB */
    register long r7 __asm__("r7") = 180L; /* __NR_pread64 */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7)
        : "memory", "cc");
    return (ssize_t)r0;
}
static __attribute__((always_inline)) inline
off_t g_sig_lseek(int fd, off_t off, int whence) {
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)off;
    register long r2 __asm__("r2") = (long)whence;
    register long r7 __asm__("r7") = 19L; /* __NR_lseek */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory", "cc");
    return (off_t)r0;
}
static __attribute__((always_inline)) inline
int g_sig_close(int fd) {
    register long r0 __asm__("r0") = (long)fd;
    register long r7 __asm__("r7") = 6L; /* __NR_close */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r7)
        : "memory", "cc");
    return (int)r0;
}

#else /* x86 / x86_64 — compile-only fallback, not a target ABI */
static inline int     g_sig_openat(const char *p, int f) { return open(p, f|O_CLOEXEC); }
static inline ssize_t g_sig_read(int fd,void *b,size_t n)            { return read(fd,b,n); }
static inline ssize_t g_sig_pread(int fd,void *b,size_t n,off_t o)   { return pread(fd,b,n,o); }
static inline off_t   g_sig_lseek(int fd, off_t o, int w)            { return lseek(fd,o,w); }
static inline int     g_sig_close(int fd)                             { return close(fd); }
#endif /* arch */

// ── §2  Bypass-tool detection via /proc/self/maps ──────────────────────────
// Opens /proc/self/maps with inline-asm I/O (itself immune to IO hooks), reads
// it in 4 KB chunks and searches for short XOR-0xA3 obfuscated fragments that
// identify bypass-tool native libraries injected into our process memory.
//
// LSPosed-based variants (LspatchSignKiller, NPSignKiller …) are already caught
// by the existing FMAPS LVM opcode (lsplant / lspatch / xposed patterns).
// This function catches tools that inject WITHOUT LSPosed:
//   "eirv"      → EirvSignKiller / EirvSignKiller2 native module
//   "fanc"      → FancyBypass native module
//   "srpatch"   → SRPatch native module
//   "npmanager" → NP Manager directly-injected native module
//   "signkill"  → generic sig-killer native libraries

/* XOR-0xA3 encoded fragment strings */
/* "/proc/self/maps" */
static const uint8_t _bx_maps[] = {
    0x8C,0xD3,0xD1,0xCC,0xC0,0x8C,0xD0,0xC6,0xCF,0xC5,0x8C,0xCE,0xC2,0xD3,0xD0
};
/* "eirv" */
static const uint8_t _bx_eirv[] = {0xC6,0xCA,0xD1,0xD5};
/* "fanc" */
static const uint8_t _bx_fanc[] = {0xC5,0xC2,0xCD,0xC0};
/* "srpatch" */
static const uint8_t _bx_srp[]  = {0xD0,0xD1,0xD3,0xC2,0xD7,0xC0,0xCB};
/* "npmanager" */
static const uint8_t _bx_npm[]  = {0xCD,0xD3,0xCE,0xC2,0xCD,0xC2,0xC4,0xC6,0xD1};
/* "signkill" */
static const uint8_t _bx_skl[]  = {0xD0,0xCA,0xC4,0xCD,0xC8,0xCA,0xCF,0xCF};

static int g_memmem_s(const char *hay, size_t hlen,
                      const char *needle, size_t nlen) {
    if (!nlen || hlen < nlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

static int g_sig_maps_scan(void) {
    G_DEC(s_maps, _bx_maps);
    G_DEC(s_eirv, _bx_eirv);
    G_DEC(s_fanc, _bx_fanc);
    G_DEC(s_srp,  _bx_srp);
    G_DEC(s_npm,  _bx_npm);
    G_DEC(s_skl,  _bx_skl);

    int mfd = g_sig_openat(s_maps, O_RDONLY);
    if (mfd < 0) return 0; /* maps unreadable → skip rather than false-crash */

    /* Read in 4 KB chunks; carry last 63 bytes to catch cross-boundary hits. */
    char chunk[4096 + 64];
    size_t carry = 0;
    ssize_t rd;
    int found = 0;
    while (!found && (rd = g_sig_read(mfd, chunk + carry, 4096)) > 0) {
        size_t total = carry + (size_t)rd;
        if (g_memmem_s(chunk, total, s_eirv, 4)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_fanc, 4)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_srp,  7)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_npm,  9)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_skl,  8)) { found = 1; break; }
        carry = total > 63 ? 63 : total;
        memmove(chunk, chunk + total - carry, carry);
    }
    g_sig_close(mfd);
    if (found) GLOGE("D2CG sig: bypass tool library detected in maps");
    return found;
}

// ── §3  pread-based ZIP mini-parser — no FILE*, no fread, no fseek ─────────

/* Locate EOCD; return cd_offset and cd_size via pointers. */
static int g_sig_eocd(int fd, uint32_t *cd_off, uint32_t *cd_sz) {
    off_t fsize = g_sig_lseek(fd, 0, SEEK_END);
    if (fsize < 22) return 0;
    size_t search = (size_t)(fsize < 66022 ? fsize : 66022);
    uint8_t *buf = (uint8_t *)malloc(search);
    if (!buf) return 0;
    ssize_t rd = g_sig_pread(fd, buf, search, fsize - (off_t)search);
    if (rd < 22) { free(buf); return 0; }
    long found = -1;
    for (long i = (long)rd - 22; i >= 0; i--) {
        if (buf[i]==0x50&&buf[i+1]==0x4b&&buf[i+2]==0x05&&buf[i+3]==0x06) {
            found = i; break;
        }
    }
    if (found < 0) { free(buf); return 0; }
    *cd_sz  = g_rd32(buf + found + 12);
    *cd_off = g_rd32(buf + found + 16);
    free(buf);
    return 1;
}

/* Read one ZIP entry's uncompressed data using pread64 (STORED or DEFLATE).
   Returns number of bytes written to out, 0 on error. */
static uint32_t g_sig_read_entry(int fd, const ZipEntryInfo *info,
                                  uint8_t *out, uint32_t out_max) {
    uint8_t lh[30];
    if (g_sig_pread(fd, lh, 30, (off_t)info->local_offset) != 30) return 0;
    if (lh[0]!=0x50||lh[1]!=0x4b||lh[2]!=0x03||lh[3]!=0x04) return 0;
    uint16_t nl  = g_rd16(lh + 26);
    uint16_t el  = g_rd16(lh + 28);
    off_t data_off = (off_t)info->local_offset + 30 + nl + el;

    if (info->method == 0) { /* STORED — direct pread */
        if (info->uncomp_size > out_max) return 0;
        ssize_t r = g_sig_pread(fd, out, info->uncomp_size, data_off);
        return (r == (ssize_t)info->uncomp_size) ? info->uncomp_size : 0;
    }
    if (info->method == 8) { /* DEFLATE — raw inflate (windowBits = -15) */
        if (info->comp_size > 131072) return 0; /* sanity */
        uint8_t *comp = (uint8_t *)malloc(info->comp_size);
        if (!comp) return 0;
        ssize_t r = g_sig_pread(fd, comp, info->comp_size, data_off);
        if (r != (ssize_t)info->comp_size) { free(comp); return 0; }
        z_stream strm; memset(&strm, 0, sizeof(strm));
        strm.next_in   = comp;          strm.avail_in  = info->comp_size;
        strm.next_out  = out;           strm.avail_out = out_max;
        if (inflateInit2(&strm, -15) != Z_OK) { free(comp); return 0; }
        int rc = inflate(&strm, Z_FINISH);
        uint32_t written = out_max - strm.avail_out;
        inflateEnd(&strm); free(comp);
        return (rc == Z_STREAM_END) ? written : 0;
    }
    return 0; /* unsupported compression */
}

// ── §3b  Minimal ASN.1 PKCS#7 → X.509 DER extractor ──────────────────────
//
// Android V1-signed APKs store a PKCS#7 SignedData blob in META-INF/*.RSA.
// The structure is:
//   SEQUENCE (ContentInfo) {
//     OID signedData
//     [0] { SEQUENCE (SignedData) {
//       INTEGER version
//       SET digestAlgorithms
//       SEQUENCE contentInfo
//       [0] { SEQUENCE (X.509 cert DER) }   ← we want this
//     } }
//   }
//
// We parse the minimal path to the first certificate and return a pointer
// into the original buffer (no allocation).  On any parse error we return
// NULL and the caller falls back to hashing the raw PKCS#7 blob.

static int g_sig_asn1_tl(const uint8_t **p, const uint8_t *end,
                          uint8_t *tag, uint32_t *vlen) {
    if (*p >= end) return 0;
    *tag = *(*p)++;
    if (*p >= end) return 0;
    uint8_t b = *(*p)++;
    if (!(b & 0x80)) { *vlen = b; return 1; }
    int nb = b & 0x7f;
    if (nb == 0 || nb > 4 || *p + nb > end) return 0;
    *vlen = 0;
    for (int i = 0; i < nb; i++) *vlen = (*vlen << 8) | *(*p)++;
    return 1;
}

static const uint8_t *g_sig_pkcs7_extract_cert(const uint8_t *buf,
                                                uint32_t buf_len,
                                                uint32_t *cert_len) {
    const uint8_t *p = buf, *end = buf + buf_len;
    uint8_t tag; uint32_t vlen;
    /* ContentInfo SEQUENCE */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    /* OID */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x06) return NULL;
    p += vlen;
    /* [0] EXPLICIT wrapping SignedData */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0xA0) return NULL;
    /* SignedData SEQUENCE */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    /* INTEGER version */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x02) return NULL;
    p += vlen;
    /* SET digestAlgorithms */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x31) return NULL;
    p += vlen;
    /* SEQUENCE encapContentInfo */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    p += vlen;
    /* [0] certificates */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0xA0) return NULL;
    /* First certificate SEQUENCE — this IS the X.509 DER cert */
    const uint8_t *cert_start = p;
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    *cert_len = (uint32_t)(p - cert_start) + vlen;
    return cert_start;
}

// ── §4  Main detection function ────────────────────────────────────────────

// XOR-0xA3 encoded ZIP entry names used below.
// "META-INF/"           (9 bytes)
static const uint8_t _enc_mi[]   = {0xEE,0xE6,0xF7,0xE2,0x8E,0xEA,0xED,0xE5,0x8C};
// ".RSA"                (4 bytes)
static const uint8_t _enc_rsa[]  = {0x8D,0xF1,0xF0,0xE2};
// ".DSA"                (4 bytes)
static const uint8_t _enc_dsa[]  = {0x8D,0xE7,0xF0,0xE2};
// ".EC"                 (3 bytes)
static const uint8_t _enc_ec[]   = {0x8D,0xE6,0xE0};
// "assets/font_kern.dat" (20 bytes)
static const uint8_t _enc_kern[] = {
    0xC2,0xD0,0xD0,0xC6,0xD7,0xD0,0x8C,
    0xC5,0xCC,0xCD,0xD7,0xFC,0xC8,0xC6,0xD1,0xCD,
    0x8D,0xC7,0xC2,0xD7
};

static int detect_sig_tamper(const char *apk_path) {

    // ── Pre-check: bypass-tool library scan ───────────────────────────────────
    // Crash immediately if a known IO-hook or sig-killer library is found in
    // our address space.  Runs before opening the APK to prevent any race.
    if (g_sig_maps_scan()) return 1;

    // ── Open APK via raw svc #0 — no PLT, no libc, no hook surface ───────────
    // IO-hook tools (EirvSignKiller, FancyBypass, SRPatch IO) patch the PLT
    // entry of openat() inside the target .so.  Inline-asm svc #0 completely
    // bypasses the PLT; there is no GOT entry to overwrite, no symbol to hook.
    int fd = g_sig_openat(apk_path, O_RDONLY);
    if (fd < 0) {
        GLOGE("D2CG sig: openat errno=%d", errno);
        return 0; /* transient (cold-boot path race) — skip, not crash */
    }

    // ── Locate EOCD ───────────────────────────────────────────────────────────
    uint32_t cd_off = 0, cd_sz = 0;
    if (!g_sig_eocd(fd, &cd_off, &cd_sz)) {
        GLOGE("D2CG sig: no EOCD");
        g_sig_close(fd); return 0;
    }

    // ── Load central directory ────────────────────────────────────────────────
    uint8_t *cd = (uint8_t *)malloc(cd_sz ? cd_sz : 1);
    if (!cd) { g_sig_close(fd); return 0; }
    if (cd_sz > 0) {
        ssize_t rd = g_sig_pread(fd, cd, cd_sz, (off_t)cd_off);
        if (rd != (ssize_t)cd_sz) { free(cd); g_sig_close(fd); return 0; }
    }

    // ── Decode obfuscated entry names ─────────────────────────────────────────
    G_DEC(s_mi,   _enc_mi);
    G_DEC(s_rsa,  _enc_rsa);
    G_DEC(s_dsa,  _enc_dsa);
    G_DEC(s_ec,   _enc_ec);
    G_DEC(s_kern, _enc_kern);

    // ── Single-pass CD scan: find signing cert + font_kern.dat ───────────────
    ZipEntryInfo certInfo; memset(&certInfo, 0, sizeof(certInfo));
    ZipEntryInfo kernInfo; memset(&kernInfo, 0, sizeof(kernInfo));
    uint32_t p = 0;
    while (p + 46 <= cd_sz) {
        if (!(cd[p]==0x50&&cd[p+1]==0x4b&&cd[p+2]==0x01&&cd[p+3]==0x02)) break;
        uint16_t method    = g_rd16(cd + p + 10);
        uint32_t comp_sz   = g_rd32(cd + p + 20);
        uint32_t uncomp_sz = g_rd32(cd + p + 24);
        uint16_t name_len  = g_rd16(cd + p + 28);
        uint16_t extra_len = g_rd16(cd + p + 30);
        uint16_t comm_len  = g_rd16(cd + p + 32);
        uint32_t local_off = g_rd32(cd + p + 42);
        if ((uint64_t)(p + 46) + name_len > cd_sz) break;
        char ename[256];
        uint16_t nlen = name_len < 255 ? name_len : 255;
        memcpy(ename, cd + p + 46, nlen); ename[nlen] = '\0';

        if (!certInfo.found && strncmp(ename, s_mi, 9) == 0) {
            size_t L = strlen(ename);
            int is_cert = (L > 4 && strcmp(ename + L - 4, s_rsa) == 0)
                        ||(L > 4 && strcmp(ename + L - 4, s_dsa) == 0)
                        ||(L > 3 && strcmp(ename + L - 3, s_ec)  == 0);
            if (is_cert) {
                certInfo.method=method; certInfo.comp_size=comp_sz;
                certInfo.uncomp_size=uncomp_sz; certInfo.local_offset=local_off;
                certInfo.found=1;
                GLOGI("D2CG sig: cert='%s' comp=%u uncomp=%u", ename, comp_sz, uncomp_sz);
            }
        }
        if (!kernInfo.found && strcmp(ename, s_kern) == 0) {
            kernInfo.method=method; kernInfo.comp_size=comp_sz;
            kernInfo.uncomp_size=uncomp_sz; kernInfo.local_offset=local_off;
            kernInfo.found=1;
        }
        if (certInfo.found && kernInfo.found) break;
        p += 46 + name_len + extra_len + comm_len;
    }
    free(cd);

    // font_kern.dat absent → mandatory asset deleted by attacker
    if (!kernInfo.found) {
        GLOGE("D2CG sig: font_kern.dat MISSING");
        g_sig_close(fd); return 1;
    }

    // ── Read entries via pread64 svc #0 ──────────────────────────────────────
    // pread64 is position-independent: both reads use the same fd without
    // seeking, so no lseek side-effects and no race between the two reads.

    // font_kern.dat ciphertext (48 bytes payload + 16-byte AES padding block)
    uint8_t kernCipher[64];
    uint32_t kernLen = g_sig_read_entry(fd, &kernInfo, kernCipher, 64);
    if (!kernLen) {
        GLOGE("D2CG sig: kern read failed");
        g_sig_close(fd); return 1;
    }

    // Signing certificate bytes
    uint8_t *cert_buf = NULL; uint32_t cert_len = 0;
    if (certInfo.found && certInfo.uncomp_size > 0 && certInfo.uncomp_size <= 65536) {
        cert_buf = (uint8_t *)malloc(certInfo.uncomp_size + 16);
        if (cert_buf) {
            cert_len = g_sig_read_entry(fd, &certInfo, cert_buf,
                                        certInfo.uncomp_size + 16);
            if (!cert_len) {
                memset(cert_buf, 0, certInfo.uncomp_size + 16);
                free(cert_buf); cert_buf = NULL;
            }
        }
    }

    g_sig_close(fd);

    // ── Decrypt font_kern.dat ─────────────────────────────────────────────────
    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t kernPlain[64];
    int kernPlainLen = aes256_cbc_dec(key, iv, kernCipher, (int)kernLen, kernPlain);
    memset(key, 0, 32); memset(iv, 0, 16);

    if (kernPlainLen < 32) {
        GLOGE("D2CG sig: decrypt failed len=%d", kernPlainLen);
        if (cert_buf) { memset(cert_buf, 0, certInfo.uncomp_size + 16); free(cert_buf); }
        return 1;
    }

    // Sentinel: 32 zero bytes → user disabled the check
    int allzero = 1;
    for (int i = 0; i < 32; i++) if (kernPlain[i]) { allzero = 0; break; }
    if (allzero) {
        GLOGI("D2CG sig: sentinel(0) — check disabled, skip");
        if (cert_buf) { memset(cert_buf, 0, certInfo.uncomp_size + 16); free(cert_buf); }
        return 0;
    }

    GLOGI("D2CG sig: expected  %02x%02x%02x%02x...",
          kernPlain[0], kernPlain[1], kernPlain[2], kernPlain[3]);

    // ── No V1 cert found → stripped or re-packaged without META-INF certs ────
    if (!cert_buf || cert_len == 0) {
        GLOGE("D2CG sig: no META-INF cert entry (V1 sig absent or stripped)");
        if (cert_buf) { memset(cert_buf, 0, certInfo.uncomp_size + 16); free(cert_buf); }
        return 1;
    }

    // ── SHA-256 the X.509 DER cert (not the raw PKCS#7 blob) ─────────────────
    // Extract the X.509 DER certificate from inside the PKCS#7 SignedData blob.
    // This produces the same hash a cert-viewer tool shows — matches Java side.
    uint8_t computed[32];
    uint32_t x509_len = 0;
    const uint8_t *x509 = g_sig_pkcs7_extract_cert(cert_buf, cert_len, &x509_len);
    if (x509 && x509_len > 0) {
        sha256_buf(x509, x509_len, computed);
        GLOGI("D2CG sig: computed(x509) %02x%02x%02x%02x... (len=%u)",
              computed[0], computed[1], computed[2], computed[3], x509_len);
    } else {
        /* fallback: hash full PKCS#7 blob if ASN.1 parse fails */
        sha256_buf(cert_buf, cert_len, computed);
        GLOGI("D2CG sig: computed(pkcs7) %02x%02x%02x%02x... (fallback)",
              computed[0], computed[1], computed[2], computed[3]);
    }
    memset(cert_buf, 0, certInfo.uncomp_size + 16); free(cert_buf);

    if (memcmp(computed, kernPlain, 32) != 0) {
        GLOGE("D2CG sig: HASH MISMATCH — re-signed or spoofed");
        return 1;
    }
    GLOGI("D2CG sig: certificate verified OK");
    return 0;
}

// Wrapper with APK-path resolution — same shape as gvm_so_integrity()
static __attribute__((noinline)) int gvm_sig_check(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return 0;
    return detect_sig_tamper(apk_path);
}

// ════════════════════════════════════════════════════════════════════════════
// Constructor — runs when .so loads, before JNI_OnLoad, before any Java code
// ════════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void fonts_init(void) {
    GLOGI("fonts_init: constructor entry");

    // ── DPatch / libpandora detection — FIRST, before any other check ──────
    // DPatch hooks fopen/openat via ByteHook PLT trampolines.  We read the
    // real /proc/self/maps via svc #0 before DPatch can redirect anything.
    // libpandora.so MUST be mapped into our process to function — it cannot
    // hide from a raw kernel read.  Any hit → instant crash.
    detect_pandora_in_maps();

    // ARM64 disassembly of fonts_init() shows ONLY five opaque VM calls and
    // two process/thread spawns — zero recognisable security function names.
    // All detection lives inside AES-256-CBC encrypted lvm_exec programs:
    //   vm_run_vccheck()  → LVCFULL   VCore/VirtualApp (APK path internally)
    //   vm_run_startup()  → LMETRICS  manifest hash + dex count integrity
    //   vm_run_sigcheck() → LSIGCHK   sig cert hash (Layer 4, svc #0 I/O)
    //   vm_run()          → TRACER + FMAPS + FPORT + ARTPATH + HOOKMAPS
    //   spawn_background_watch() → vm_run_child_kill() — forked 5-s poll child
    vm_run_vccheck();
    vm_run_startup();
    // Layer 3: SO self-integrity — crashes if font_glyph.dat missing or .so patched
    if (gvm_so_integrity()) crash_now();
    // Layer 4: opaque VM call — no gvm_sig_check or detect_sig_tamper visible here
    vm_run_sigcheck();
    vm_run();

    GLOGI("fonts_init: launching background watchdogs");
    spawn_background_watch();
    pthread_t wdt;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&wdt, &attr, watchdog_thread, NULL);
    pthread_attr_destroy(&attr);
}

// ════════════════════════════════════════════════════════════════════════════
// ══ JNI LAYER ═══════════════════════════════════════════════════════════════
//
// _fonts_measure_impl — called from the retry thread (via fonts_apply_metrics).
// Has JNIEnv. Does:
//   Layer 1 — Behavioral: ContentProvider ↔ lifecycle callback cross-reference
//   Layer 2 — Exact: Class.forName against known killer class names
//   Layer 3 — REMOVED (resolveContentProvider is system-wide, OEM false-positives)
//   Layer 4 — Fragment scan: renaming-resistant strstr against declared providers
// ════════════════════════════════════════════════════════════════════════════

// ── Known killer-class detection targets ───────────────────────────────────
// AES-256-CBC + XOR 0x5A encrypted — nothing here is plaintext in .rodata.
static const uint8_t BC1[] = {0x16,0x51,0x93,0x97,0x8e,0x33,0xcd,0xac,0x71,0x8a,0x43,0xda,0xef,0xcf,0x9f,0x28,0x6e,0xef,0x1c,0x1a,0x9a,0xb9,0x6c,0xda,0x55,0x7f,0xd8,0x70,0xd7,0x17,0x6e,0x0f,0xad,0x1e,0x77,0xd6,0x31,0x43,0xd9,0xb4,0x29,0xe2,0x91,0x66,0xaf,0xec,0xf1,0x9a};
static const int BC1_LEN = 48;
static const uint8_t BC2[] = {0x1d,0x8f,0xfe,0x3d,0x6e,0xaf,0x14,0x35,0x12,0x3f,0xa1,0x8a,0x94,0x9d,0x86,0xe3,0xce,0x1c,0x2a,0xa9,0xf3,0xb2,0x46,0xc1,0x72,0x58,0xf0,0xa3,0x3c,0x8b,0x01,0x8c};
static const int BC2_LEN = 32;
static const uint8_t BC3[] = {0x1d,0x8f,0xfe,0x3d,0x6e,0xaf,0x14,0x35,0x12,0x3f,0xa1,0x8a,0x94,0x9d,0x86,0xe3,0xac,0x44,0xe4,0xeb,0xb1,0xad,0x9d,0x93,0x33,0x0a,0xf6,0x54,0x9a,0xfe,0xbb,0x32};
static const int BC3_LEN = 32;
static const uint8_t BC4[] = {0x1d,0x8f,0xfe,0x3d,0x6e,0xaf,0x14,0x35,0x12,0x3f,0xa1,0x8a,0x94,0x9d,0x86,0xe3,0xb4,0x8f,0xd5,0x41,0xc5,0x27,0x9c,0x5c,0xc3,0xa9,0x24,0x8d,0x82,0xe5,0x71,0x71};
static const int BC4_LEN = 32;
static const uint8_t BC5[] = {0x7a,0xd7,0x78,0x11,0xf8,0x6a,0x56,0x7e,0x79,0x4f,0x98,0x18,0xf3,0x54,0x49,0x83,0x9e,0x26,0x12,0x2b,0x63,0x78,0x10,0xb2,0xc6,0xf5,0x38,0x1b,0xf9,0xf7,0xb5,0xa8};
static const int BC5_LEN = 32;
static const uint8_t BC6[] = {0x82,0x8f,0x79,0xd4,0x9e,0x66,0xae,0x3a,0xa8,0x8f,0xe8,0x49,0x6e,0xaa,0x54,0xcc,0x17,0x18,0x8f,0xf7,0x2e,0x58,0x88,0x8a,0x9a,0x69,0xc9,0xa2,0x8f,0xe8,0xf0,0x5d,0xc2,0x9d,0x80,0xdf,0x3d,0x98,0x9d,0x3e,0xf4,0x65,0x1c,0x92,0x1d,0xd9,0xbf,0xaf};
static const int BC6_LEN = 48;

static const uint8_t *const BLOCKED_CLASS_CT[]  = { BC1, BC2, BC3, BC4, BC5, BC6 };
static const int            BLOCKED_CLASS_LEN[] = { BC1_LEN, BC2_LEN, BC3_LEN, BC4_LEN, BC5_LEN, BC6_LEN };
static const int BLOCKED_CLASS_COUNT = 6;

// ── Broadened, renaming-resistant package-fragment patterns ───────────────
// KFRAG1-4 constants moved above lvm_exec so the interpreter (opcode 0x5B)
// and provider_matches_blocklist() both see them without a forward declaration.
// Original definitions are above; these comments remain as a location marker.

static __attribute__((noinline)) int provider_matches_blocklist(const char *s) {
    if (!s) return 0;
    char f1[PSTR_BUF_SZ], f2[PSTR_BUF_SZ], f3[PSTR_BUF_SZ], f4[PSTR_BUF_SZ];
    reveal_ns(200u, KFRAG1_CT, KFRAG1_LEN, f1);
    reveal_ns(201u, KFRAG2_CT, KFRAG2_LEN, f2);
    reveal_ns(202u, KFRAG3_CT, KFRAG3_LEN, f3);
    reveal_ns(203u, KFRAG4_CT, KFRAG4_LEN, f4);
    int hit = strstr(s, f1) || strstr(s, f2) || strstr(s, f3) || strstr(s, f4);
    memset(f1, 0, sizeof(f1)); memset(f2, 0, sizeof(f2));
    memset(f3, 0, sizeof(f3)); memset(f4, 0, sizeof(f4));
    return hit;
}

// ── Safe namespace list — licence-protection SDKs & analytics ─────────────
// Prevents false positives on PairIP and other legitimate SDKs that register
// lifecycle callbacks from their own ContentProvider.
// g_is_safe_ns — safe-namespace whitelist executed entirely inside a custom
// bytecode VM whose opcode stream is AES-256-CBC encrypted (NS_BC / NS_BLOBS).
//
// What Ghidra / radare2 sees:
//   • NS_BC: 304 bytes of random-looking noise in .rodata — no readable prefix
//   • A CFF state-machine interpreter driven by a volatile-switch dispatcher
//   • 32 separate reveal_ns() calls, each with a distinct key — cracking one
//     reveals nothing about the others
//   • Plaintext whitelist strings: GONE. Entirely absent from .rodata.
//
// CFF state layout:
//   0xA0 — FETCH: bounds-check pc; transition to 0xB0 or 0xC0 (exit)
//   0xB0 — EXEC:  decode + execute one 3-byte instruction; loop back to 0xA0
//   0xC0 — EXIT:  falls through to CFF_EXIT → return
static __attribute__((noinline)) bool g_is_safe_ns(const char *name) {
    if (!name || !name[0]) return false;

    // Decrypt VM bytecode — unique key idx=255; raw bytes (no XOR post-pass)
    uint8_t bc[NS_BC_LEN];
    {
        uint8_t key[32], iv[16];
        build_str_key(255u, key);
        build_str_iv(255u, iv);
        int n = aes256_cbc_dec(key, iv, NS_BC, NS_BC_LEN, bc);
        memset(key, 0, 32); memset(iv, 0, 16);
        if (n <= 0) return false;
    }

    char work_buf[SP_BUF_SZ];
    work_buf[0] = '\0';
    volatile int     match   = 0;
    volatile uint32_t ret_val = 2u; // 2 = running sentinel; 0 = false; 1 = true
    volatile uint32_t pc     = 0u;

    // CFF_LOOP is `while(1) switch(_c)`.  States loop back via CFF_NEXT(0xA0u).
    // Reaching state 0xC0 falls through to CFF_EXIT which `goto`s past the
    // switch; `return` then exits the function.
    CFF_INIT(0xA0u);
    CFF_LOOP {
    case 0xA0u: {
        // FETCH — opaque predicate forces decompiler to model a dead crash path
        if (OP_ALWAYS_TRUE(pc)) {
            if (pc + 3u > (uint32_t)NS_BC_LEN || ret_val != 2u) {
                if (ret_val == 2u) ret_val = 0u;
                CFF_NEXT(0xC0u);
            } else {
                CFF_NEXT(0xB0u);
            }
        } else { crash_now(); }
    }
    case 0xB0u: {
        // EXEC — decode one instruction, update VM state, loop back
        uint8_t  op  = bc[pc];
        uint16_t arg = (uint16_t)bc[pc+1] | ((uint16_t)bc[pc+2] << 8);
        pc += 3u;
        switch (op) { // inner switch — distinct from the outer CFF switch(_c)
        case NS_VM_DEC:
            if (arg < 48u && NS_BLOBS[arg].ct) {
                reveal_ns((uint32_t)arg,
                          NS_BLOBS[arg].ct, NS_BLOBS[arg].len,
                          work_buf);
            } else { work_buf[0] = '\0'; }
            break;
        case NS_VM_PCMP:
            match = (work_buf[0] &&
                     strncmp(name, work_buf, strlen(work_buf)) == 0) ? 1 : 0;
            break;
        case NS_VM_JT:
            if (match) pc = (uint32_t)arg;
            break;
        case NS_VM_RET:
            ret_val = (uint32_t)arg;
            break;
        default: break;
        }
        CFF_NEXT(0xA0u);
    }
    case 0xC0u:
    CFF_EXIT;
    memset(bc, 0, sizeof(bc));
    return ret_val == 1u;
}

// Extracts "com.foo.bar" from "com.foo.bar.ClassName" into out[outlen].
static __attribute__((noinline)) void g_extract_pkg(const char *cls, char *out, int outlen) {
    const char *last = strrchr(cls, '.');
    if (!last || last == cls) { out[0] = '\0'; return; }
    int len = (int)(last - cls);
    if (len >= outlen) len = outlen - 1;
    memcpy(out, cls, len);
    out[len] = '\0';
}

// ════════════════════════════════════════════════════════════════════════════
// LAYER 1: Behavioral — lifecycle callback ↔ ContentProvider cross-reference
//
// Renamed dialog killers bypass all name-based checks but cannot change what
// they do: they MUST call registerActivityLifecycleCallbacks() from a
// ContentProvider. This layer:
//   a. Reads Application.mActivityLifecycleCallbacks
//   b. Collects the package prefix of every callback that matches a known
//      killer fragment AND is NOT in a safe namespace
//   c. Reads every ContentProvider declared in this app's own manifest
//   d. If any provider's package prefix matches a suspicious callback prefix
//      → renamed killer confirmed → SIGKILL
//
// False-positive rate near-zero: legitimate SDKs that use lifecycle callbacks
// (Firebase, analytics, PairIP) are in safe namespaces.
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline))
void check_provider_callback_xref(JNIEnv *env, jobject context) {
    if (!env || !context) return;

    // ── a. Get Application object ─────────────────────────────────────────
    jclass ctxCls = env->GetObjectClass(context);
    if (!ctxCls) return;
    jmethodID getAppCtx = env->GetMethodID(ctxCls, NS_JNI(51, SP_JNI_GETAPPCTX),
                                            NS_JNI(52, SP_JNI_CTX_RET));
    env->DeleteLocalRef(ctxCls);
    if (!getAppCtx || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jobject app = env->CallObjectMethod(context, getAppCtx);
    if (!app || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    // ── b. Read mActivityLifecycleCallbacks ───────────────────────────────
    jclass appCls = env->GetObjectClass(app);
    jfieldID fld  = env->GetFieldID(appCls, NS_JNI(53, SP_JNI_MALCB),
                                     NS_JNI(54, SP_JNI_ALIST));
    if (!fld || env->ExceptionCheck()) {
        env->ExceptionClear();
        fld = env->GetFieldID(appCls, NS_JNI(53, SP_JNI_MALCB),
                               NS_JNI(55, SP_JNI_LIST));
    }
    env->DeleteLocalRef(appCls);
    if (!fld || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(app); return;
    }
    jobject cbList = env->GetObjectField(app, fld);
    env->DeleteLocalRef(app);
    if (!cbList || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    // ── c. Get list size + get() ──────────────────────────────────────────
    jclass listCls    = env->GetObjectClass(cbList);
    jmethodID sizeMID = env->GetMethodID(listCls, "size", "()I");
    jmethodID getMID  = env->GetMethodID(listCls, "get",  "(I)Ljava/lang/Object;");
    env->DeleteLocalRef(listCls);
    if (!sizeMID || !getMID || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(cbList); return;
    }
    jint cbCount = env->CallIntMethod(cbList, sizeMID);
    if (env->ExceptionCheck() || cbCount <= 0) {
        env->ExceptionClear(); env->DeleteLocalRef(cbList); return;
    }

    // ── d. java.lang.Class.getName() ─────────────────────────────────────
    jclass jlClass     = env->FindClass(NS_JNI(48, SP_JNI_JLCLASS));
    jmethodID gnameMID = jlClass
        ? env->GetMethodID(jlClass, NS_JNI(56, SP_JNI_GETNAME), NS_JNI(57, SP_JNI_STR_RET)) : nullptr;
    if (jlClass) env->DeleteLocalRef(jlClass);
    if (!gnameMID || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(cbList); return;
    }

    // ── e. Collect suspicious callback packages ───────────────────────────
    char suspPkgs[32][128];
    int  suspCount = 0;

    for (jint i = 0; i < cbCount && suspCount < 32; i++) {
        jobject cb = env->CallObjectMethod(cbList, getMID, i);
        if (!cb || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        jclass cbCls = env->GetObjectClass(cb);
        env->DeleteLocalRef(cb);
        if (!cbCls) continue;
        jstring nameStr = (jstring)env->CallObjectMethod((jobject)cbCls, gnameMID);
        env->DeleteLocalRef(cbCls);
        if (!nameStr || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        const char *cn = env->GetStringUTFChars(nameStr, nullptr);
        if (cn) {
            // Only flag if class name matches a killer fragment — prevents false
            // positives on PairIP and other legitimate SDKs.
            if (!g_is_safe_ns(cn) && provider_matches_blocklist(cn)) {
                char pkg[128];
                g_extract_pkg(cn, pkg, sizeof(pkg));
                if (pkg[0]) {
                    bool dup = false;
                    for (int j = 0; j < suspCount; j++)
                        if (strcmp(suspPkgs[j], pkg) == 0) { dup = true; break; }
                    if (!dup) {
                        strncpy(suspPkgs[suspCount], pkg, 127);
                        suspPkgs[suspCount++][127] = '\0';
                    }
                }
            }
            env->ReleaseStringUTFChars(nameStr, cn);
        }
        env->DeleteLocalRef(nameStr);
    }
    env->DeleteLocalRef(cbList);

    if (suspCount == 0) return;

    // ── f. Get PackageManager + declared providers ────────────────────────
    ctxCls = env->GetObjectClass(context);
    jmethodID getPM      = env->GetMethodID(ctxCls, NS_JNI(58, SP_JNI_GETPM),
                                             NS_JNI(59, SP_JNI_PM_RET));
    jmethodID getPkgName = env->GetMethodID(ctxCls, NS_JNI(60, SP_JNI_GETPKGNAME),
                                             NS_JNI(57, SP_JNI_STR_RET));
    env->DeleteLocalRef(ctxCls);
    if (!getPM || !getPkgName || env->ExceptionCheck()) {
        env->ExceptionClear(); return;
    }
    jobject pm = env->CallObjectMethod(context, getPM);
    if (!pm || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jstring pkgName = (jstring)env->CallObjectMethod(context, getPkgName);
    if (!pkgName || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(pm); return;
    }
    jclass pmCls         = env->GetObjectClass(pm);
    jmethodID getPkgInfo = env->GetMethodID(pmCls, NS_JNI(61, SP_JNI_GETPKGINFO),
                                              NS_JNI(62, SP_JNI_PKGINFO_SIG));
    env->DeleteLocalRef(pmCls);
    if (!getPkgInfo || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(pm); env->DeleteLocalRef(pkgName); return;
    }
    char ownPkg1[256] = {};
    {
        const char *tmp = env->GetStringUTFChars(pkgName, nullptr);
        if (tmp) { strncpy(ownPkg1, tmp, 255); env->ReleaseStringUTFChars(pkgName, tmp); }
    }
    const jint GET_PROVIDERS = 0x00000008;
    jobject pkgInfo = env->CallObjectMethod(pm, getPkgInfo, pkgName, GET_PROVIDERS);
    env->DeleteLocalRef(pm); env->DeleteLocalRef(pkgName);
    if (!pkgInfo || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    jclass piCls      = env->GetObjectClass(pkgInfo);
    jfieldID provsFld = env->GetFieldID(piCls, NS_JNI(63, SP_JNI_PROVIDERS),
                                         NS_JNI(64, SP_JNI_PROVINFO));
    env->DeleteLocalRef(piCls);
    if (!provsFld || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(pkgInfo); return;
    }
    jobjectArray provArr = (jobjectArray)env->GetObjectField(pkgInfo, provsFld);
    env->DeleteLocalRef(pkgInfo);
    if (!provArr || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    // ── g. Cross-reference provider packages with suspicious cb packages ──
    jsize provCount = env->GetArrayLength(provArr);
    for (jsize i = 0; i < provCount; i++) {
        jobject prov = env->GetObjectArrayElement(provArr, i);
        if (!prov || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        jclass provCls = env->GetObjectClass(prov);
        // Own-APK gate: skip entries from other APKs
        jfieldID pkgF  = env->GetFieldID(provCls, NS_JNI(65, SP_JNI_PKGNAME_FLD), NS_JNI(66, SP_JNI_STR_DESC));
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (pkgF) {
            jstring provPkg = (jstring)env->GetObjectField(prov, pkgF);
            if (env->ExceptionCheck()) { env->ExceptionClear(); provPkg = nullptr; }
            if (provPkg) {
                const char *pp = env->GetStringUTFChars(provPkg, nullptr);
                bool ownApk = pp && ownPkg1[0] && (strcmp(pp, ownPkg1) == 0);
                if (pp) env->ReleaseStringUTFChars(provPkg, pp);
                env->DeleteLocalRef(provPkg);
                if (!ownApk) { env->DeleteLocalRef(provCls); env->DeleteLocalRef(prov); continue; }
            }
        }
        jfieldID nameF = env->GetFieldID(provCls, "name", NS_JNI(66, SP_JNI_STR_DESC));
        env->DeleteLocalRef(provCls);
        if (!nameF || env->ExceptionCheck()) {
            env->ExceptionClear(); env->DeleteLocalRef(prov); continue;
        }
        jstring pnStr = (jstring)env->GetObjectField(prov, nameF);
        env->DeleteLocalRef(prov);
        if (!pnStr || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        const char *pn = env->GetStringUTFChars(pnStr, nullptr);
        if (pn && !g_is_safe_ns(pn)) {
            char ppkg[128];
            g_extract_pkg(pn, ppkg, sizeof(ppkg));
            if (ppkg[0]) {
                for (int j = 0; j < suspCount; j++) {
                    size_t plen = strlen(ppkg), slen = strlen(suspPkgs[j]);
                    bool hit = (strcmp(ppkg, suspPkgs[j]) == 0) ||
                               (strncmp(ppkg, suspPkgs[j], slen) == 0 && ppkg[slen] == '.') ||
                               (strncmp(suspPkgs[j], ppkg, plen) == 0 && suspPkgs[j][plen] == '.');
                    if (hit) {
                        GLOGE("L1-behavioral: provider '%s' ↔ callback '%s' — renamed killer",
                              ppkg, suspPkgs[j]);
                        env->ReleaseStringUTFChars(pnStr, pn);
                        env->DeleteLocalRef(pnStr);
                        env->DeleteLocalRef(provArr);
                        CRASH_HERE("renamed dialog killer: ContentProvider+lifecycle callback package cross-match");
                    }
                }
            }
        }
        if (pn) env->ReleaseStringUTFChars(pnStr, pn);
        env->DeleteLocalRef(pnStr);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    env->DeleteLocalRef(provArr);
}

// ════════════════════════════════════════════════════════════════════════════
// _fonts_measure_impl — registered as fonts.Metrics.measure(Context) via
// RegisterNatives. Hidden C symbol, not exported from .so.
//
// Architecture (split JNI shell + VM kill):
//   • _fonts_measure_impl is a DUMB DATA COLLECTOR — it gathers provider
//     class names, authorities, and Class.forName results into antik_ctx_t.
//     No strstr, no CRASH_HERE inside the JNI function itself.
//   • vm_run_antik() passes that context into lvm_exec opcode 0x5B (LANTIK)
//     which performs the KFRAG matching and kill decision inside encrypted
//     bytecode.  Ghidra sees only: data collection → opaque lvm_exec call.
//
// Layer 1 (behavioral cross-ref) still crashes inline because check_provider_
// callback_xref is already protected by volatile fn-pointer dispatch and the
// result type change would require extensive refactoring.
// ════════════════════════════════════════════════════════════════════════════

// ── LBC_ANTIK — bytecode program for the LANTIK (0x5B) opcode ────────────
// Plaintext: [0x5B, 0x00, 0x01, 0x00] = LANTIK(ctx) + HALT
// XOR-CS = 0x5A.  Encrypted with unique per-program AES-256-CBC split key.
static volatile const uint8_t LBC_ANTIK_KHI[] = {
    0xa7,0xe2,0xab,0xa2,0x5b,0xc0,0x18,0x7a,0x95,0xd5,0x86,0xeb,0xb6,0x7a,0xec,0xfc,
    0xd4,0x18,0x32,0x6d,0x0e,0xf9,0x4b,0x67,0x0a,0xac,0x60,0xbc,0xde,0xd7,0x89,0x83};
static volatile const uint8_t LBC_ANTIK_KLO[] = {
    0xe4,0x91,0x13,0xd4,0xd5,0x63,0x1a,0x30,0x54,0xf8,0x47,0x15,0xdc,0xc9,0xf6,0x31,
    0x4a,0x78,0x33,0xcf,0xc3,0xe1,0x89,0xcf,0xfd,0x7d,0x9e,0xd4,0x90,0x78,0xe7,0x93};
static volatile const uint8_t LBC_ANTIK_IHI[] = {
    0x2c,0x16,0x26,0x87,0x63,0x7f,0x77,0x21,0x80,0x02,0x9a,0x6f,0x59,0xf1,0x73,0xab};
static volatile const uint8_t LBC_ANTIK_ILO[] = {
    0xe4,0x48,0x74,0x53,0x6c,0xc6,0x61,0xee,0xde,0xe3,0x76,0x1b,0xad,0x64,0x9e,0x33};
static volatile const uint8_t LBC_ANTIK_ENC[] = {
    0x64,0x3f,0x66,0x91,0x7d,0x28,0xda,0x5b,0x68,0xd9,0xda,0x4d,0x6b,0xc7,0xc7,0x58};
#define LBC_ANTIK_LEN 16
#define LBC_ANTIK_CS  0x5au

// Dispatches LANTIK check through the same lvm_exec interpreter used by all
// other native checks.  Ghidra sees: lvm_exec(K…,I…,ENC,16,ctx) — opaque.
static __attribute__((noinline)) void vm_run_antik(const antik_ctx_t *ctx) {
    lvm_exec(LBC_ANTIK_KHI, LBC_ANTIK_KLO,
             LBC_ANTIK_IHI, LBC_ANTIK_ILO,
             LBC_ANTIK_ENC, LBC_ANTIK_LEN, LBC_ANTIK_CS,
             (const void *)ctx);
}

// Volatile JNI dispatch table — one slot per JNI security check.
// Declared at file scope so it lands in .data, preventing compiler folding.
typedef void (*_JniGuardFn)(JNIEnv *, jobject);
static volatile _JniGuardFn g_jni_guard_tab[1] = {
    check_provider_callback_xref,  // slot 0
};

static void _fonts_measure_impl(JNIEnv *env, jclass /*cls*/, jobject context) {
    GLOGI("_fonts_measure_impl: start (context=%p)", (void *)context);

    // Collect all detection signals into a plain-C context struct.
    // No kill decision here — everything routes to vm_run_antik() at the end.
    antik_ctx_t actx;
    memset(&actx, 0, sizeof(actx));

    // ── 1. BEHAVIORAL: ContentProvider ↔ lifecycle callback cross-reference ──
    // Indirect dispatch via g_jni_guard_tab[0]; disassembler sees BLR xN.
    // Crashes inline on detection (its own internal kill path).
    { _JniGuardFn _fn = g_jni_guard_tab[0]; if (_fn) _fn(env, context); }

    // ── 2. Class.forName — exact known killer class names (BC1-BC6) ───────
    // On detection: sets actx.exact_hit instead of crashing here.
    // Kill decision deferred to vm_run_antik() → lvm_exec opcode 0x5B.
    {
        jclass jClassClass = env->FindClass(NS_JNI(48, SP_JNI_JLCLASS));
        if (jClassClass) {
            jmethodID forName = env->GetStaticMethodID(jClassClass, NS_JNI(49, SP_JNI_FORNAME),
                NS_JNI(50, SP_JNI_FORNAME_SIG));
            if (forName) {
                for (int i = 0; i < BLOCKED_CLASS_COUNT; i++) {
                    char buf[PSTR_BUF_SZ];
                    const char *cname = reveal(BLOCKED_CLASS_CT[i], BLOCKED_CLASS_LEN[i], buf);
                    jstring jn = env->NewStringUTF(cname);
                    memset(buf, 0, sizeof(buf));
                    if (!jn) continue;
                    env->CallStaticObjectMethod(jClassClass, forName, jn);
                    env->DeleteLocalRef(jn);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();  // ClassNotFoundException → good
                    } else {
                        GLOGE("_fonts_measure_impl: blocked class[%d] resolved", i);
                        actx.exact_hit = 1;  // defer crash to vm_run_antik
                    }
                }
            }
            env->DeleteLocalRef(jClassClass);
        }
    }

    // ── 3. REMOVED — resolveContentProvider caused OEM false-positives.

    // ── 4. Provider fragment scan — collect names/auths into actx ─────────
    // JNI data-gathering only. No strstr, no CRASH_HERE.
    // vm_run_antik() → lvm_exec 0x5B does all KFRAG matching and crash.
    if (!context) goto run_vm;
    {
        jclass ctxCls4 = env->GetObjectClass(context);
        if (!ctxCls4) goto run_vm;
        jmethodID getPM4     = env->GetMethodID(ctxCls4, NS_JNI(58, SP_JNI_GETPM),
                                                NS_JNI(59, SP_JNI_PM_RET));
        jmethodID getPkgName4= env->GetMethodID(ctxCls4, NS_JNI(60, SP_JNI_GETPKGNAME),
                                                NS_JNI(57, SP_JNI_STR_RET));
        env->DeleteLocalRef(ctxCls4);
        if (!getPM4 || !getPkgName4 || env->ExceptionCheck()) { env->ExceptionClear(); goto run_vm; }

        jobject pm4 = env->CallObjectMethod(context, getPM4);
        if (!pm4 || env->ExceptionCheck()) { env->ExceptionClear(); goto run_vm; }

        jstring pkgName4 = (jstring)env->CallObjectMethod(context, getPkgName4);
        if (!pkgName4 || env->ExceptionCheck()) {
            env->ExceptionClear(); env->DeleteLocalRef(pm4); goto run_vm;
        }

        jclass pmCls4 = env->GetObjectClass(pm4);
        jmethodID getPkgInfo4 = pmCls4 ? env->GetMethodID(pmCls4, NS_JNI(61, SP_JNI_GETPKGINFO),
            NS_JNI(62, SP_JNI_PKGINFO_SIG)) : nullptr;
        if (pmCls4) env->DeleteLocalRef(pmCls4);
        if (env->ExceptionCheck()) env->ExceptionClear();

        char ownPkg4[256] = {};
        {
            const char *tmp = env->GetStringUTFChars(pkgName4, nullptr);
            if (tmp) { strncpy(ownPkg4, tmp, 255); env->ReleaseStringUTFChars(pkgName4, tmp); }
        }

        const jint GET_PROVIDERS = 0x00000008;
        jobject pkgInfo4 = getPkgInfo4
            ? env->CallObjectMethod(pm4, getPkgInfo4, pkgName4, GET_PROVIDERS) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); pkgInfo4 = nullptr; }
        env->DeleteLocalRef(pm4); env->DeleteLocalRef(pkgName4);

        if (pkgInfo4) {
            jclass piCls4 = env->GetObjectClass(pkgInfo4);
            jfieldID provsFld4 = env->GetFieldID(piCls4, NS_JNI(63, SP_JNI_PROVIDERS),
                NS_JNI(64, SP_JNI_PROVINFO));
            env->DeleteLocalRef(piCls4);
            if (provsFld4 && !env->ExceptionCheck()) {
                jobjectArray provs4 = (jobjectArray)env->GetObjectField(pkgInfo4, provsFld4);
                if (env->ExceptionCheck()) { env->ExceptionClear(); provs4 = nullptr; }
                if (provs4) {
                    jsize n4 = env->GetArrayLength(provs4);
                    for (jsize i = 0; i < n4 && actx.count < ANTIK_MAX_PROV; i++) {
                        jobject prov4 = env->GetObjectArrayElement(provs4, i);
                        if (!prov4 || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
                        jclass pc4 = env->GetObjectClass(prov4);
                        // Own-APK gate
                        jfieldID pkgF4 = env->GetFieldID(pc4, NS_JNI(65, SP_JNI_PKGNAME_FLD), NS_JNI(66, SP_JNI_STR_DESC));
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (pkgF4 && ownPkg4[0]) {
                            jstring pp4 = (jstring)env->GetObjectField(prov4, pkgF4);
                            if (env->ExceptionCheck()) { env->ExceptionClear(); pp4 = nullptr; }
                            bool own4 = false;
                            if (pp4) {
                                const char *pps4 = env->GetStringUTFChars(pp4, nullptr);
                                if (pps4) { own4=(strcmp(pps4,ownPkg4)==0); env->ReleaseStringUTFChars(pp4,pps4); }
                                env->DeleteLocalRef(pp4);
                            }
                            if (!own4) { env->DeleteLocalRef(pc4); env->DeleteLocalRef(prov4); continue; }
                        }
                        // Collect class name and authority into actx slot
                        jfieldID nF4 = env->GetFieldID(pc4, "name",      NS_JNI(66, SP_JNI_STR_DESC));
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        jfieldID aF4 = env->GetFieldID(pc4, "authority", NS_JNI(66, SP_JNI_STR_DESC));
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        env->DeleteLocalRef(pc4);
                        int slot = actx.count;
                        if (nF4) {
                            jstring cn4 = (jstring)env->GetObjectField(prov4, nF4);
                            if (env->ExceptionCheck()) { env->ExceptionClear(); cn4=nullptr; }
                            if (cn4) {
                                const char *cs4 = env->GetStringUTFChars(cn4, nullptr);
                                if (cs4) { strncpy(actx.names[slot],cs4,ANTIK_STR_SZ-1);
                                           env->ReleaseStringUTFChars(cn4,cs4); }
                                env->DeleteLocalRef(cn4);
                            }
                        }
                        if (aF4) {
                            jstring au4 = (jstring)env->GetObjectField(prov4, aF4);
                            if (env->ExceptionCheck()) { env->ExceptionClear(); au4=nullptr; }
                            if (au4) {
                                const char *as4 = env->GetStringUTFChars(au4, nullptr);
                                if (as4) { strncpy(actx.auths[slot],as4,ANTIK_STR_SZ-1);
                                           env->ReleaseStringUTFChars(au4,as4); }
                                env->DeleteLocalRef(au4);
                            }
                        }
                        env->DeleteLocalRef(prov4);
                        actx.count++;
                    }
                    env->DeleteLocalRef(provs4);
                }
            } else { if (env->ExceptionCheck()) env->ExceptionClear(); }
            env->DeleteLocalRef(pkgInfo4);
        }
    }

run_vm:
    // ── VM kill decision — pure-C, inside AES-encrypted lvm_exec bytecode ──
    // Ghidra sees _fonts_measure_impl end with: lvm_exec(KHI,KLO,IHI,ILO,ENC,16,CS,&actx)
    // No strstr, no CRASH_HERE, no fragment strings visible in this function.
    vm_run_antik(&actx);
    memset(&actx, 0, sizeof(actx));
}

// ── RegisterNatives table ─────────────────────────────────────────────────

// JNINativeMethod built at runtime — method name + signature are
// AES-encrypted in guard_pstrings.inc (idx 75, 76); no plaintext in .rodata.

// ════════════════════════════════════════════════════════════════════════════
// fonts_register_natives — hard-fail version.
// If fonts/Metrics is missing OR RegisterNatives fails, crash immediately.
// A protected APK with this binding broken has no anti-tamper check wired up
// at all — must never pass silently.
// ════════════════════════════════════════════════════════════════════════════

extern "C" __attribute__((visibility("default")))
void fonts_register_natives(JNIEnv *env) {
    jclass cls = env->FindClass(NS_JNI(67, SP_JNI_FMETRICS));
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        GLOGE("fonts_register_natives: FindClass(fonts/Metrics) failed — class missing/stripped");
        CRASH_HERE("guard class fonts.Metrics not found at RegisterNatives time");
        return;
    }
    JNINativeMethod _fm = {NS_JNI(75, SP_JNI_MEASURE),
                           NS_JNI(76, SP_JNI_MEASURE_SIG),
                           (void *)_fonts_measure_impl};
    jint rc = env->RegisterNatives(cls, &_fm, 1);
    // If measure() was smali-patched (signature changed, native modifier removed,
    // etc.) there is no matching native method and this fails. Fail closed.
    bool bindFailed = (rc != JNI_OK);
    if (env->ExceptionCheck()) { env->ExceptionClear(); bindFailed = true; }
    env->DeleteLocalRef(cls);
    GLOGI("fonts_register_natives: RegisterNatives rc=%d bindFailed=%d", (int)rc, (int)bindFailed);
    if (bindFailed) CRASH_HERE("RegisterNatives failed to bind measure() — smali-patched signature?");
}

// ════════════════════════════════════════════════════════════════════════════
// JNI_OnLoad-time self-sufficient check — Context resolver
// ════════════════════════════════════════════════════════════════════════════

static jobject get_context_via_activity_thread(JNIEnv *env) {
    if (!env) return nullptr;
    jclass atCls = env->FindClass(NS_JNI(68, SP_JNI_AT_CLASS));
    if (!atCls) { env->ExceptionClear(); return nullptr; }
    jmethodID currentApp = env->GetStaticMethodID(atCls, NS_JNI(69, SP_JNI_CURAPP),
                                                   NS_JNI(70, SP_JNI_APP_RET));
    if (!currentApp) {
        env->ExceptionClear(); env->DeleteLocalRef(atCls); return nullptr;
    }
    jobject app = env->CallStaticObjectMethod(atCls, currentApp);
    env->DeleteLocalRef(atCls);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    return app;
}

// Returns true once ActivityThread.mActivities has at least one entry —
// i.e. the first Activity has been created and is on-stack. This guarantees
// PairIP (and any Application subclass) has fully completed its own
// attachBaseContext / onCreate before the killer check runs.
static bool has_started_activity(JNIEnv *env) {
    jclass atCls = env->FindClass(NS_JNI(68, SP_JNI_AT_CLASS));
    if (!atCls) { env->ExceptionClear(); return false; }
    jmethodID curAT = env->GetStaticMethodID(atCls, NS_JNI(71, SP_JNI_CURAT),
                                              NS_JNI(72, SP_JNI_AT_RET));
    if (!curAT) { env->ExceptionClear(); env->DeleteLocalRef(atCls); return false; }
    jobject at = env->CallStaticObjectMethod(atCls, curAT);
    env->DeleteLocalRef(atCls);
    if (!at || env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    jclass atObj = env->GetObjectClass(at);
    jfieldID fid  = env->GetFieldID(atObj, NS_JNI(73, SP_JNI_MACTIVITIES), NS_JNI(74, SP_JNI_MAP_DESC));
    env->DeleteLocalRef(atObj);
    if (!fid || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(at); return false;
    }
    jobject map = env->GetObjectField(at, fid);
    env->DeleteLocalRef(at);
    if (!map) return false;
    jclass mapCls  = env->GetObjectClass(map);
    jmethodID size = env->GetMethodID(mapCls, "size", "()I");
    env->DeleteLocalRef(mapCls);
    if (!size || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(map); return false;
    }
    jint n = env->CallIntMethod(map, size);
    env->DeleteLocalRef(map);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return n > 0;
}

// Two-phase retry thread:
//   Phase 1 — wait until ActivityThread.currentApplication() returns non-null
//   Phase 2 — wait until at least one Activity is on-stack (PairIP/app init done)
//   Phase 3 — run the full killer-detection suite
static void *fonts_retry_thread(void *arg) {
    JavaVM *vm = static_cast<JavaVM *>(arg);
    if (!vm) return nullptr;

    const int MAX_ATTEMPTS = 300;      // ~9 s ceiling at 30 ms steps
    const int SLEEP_US     = 30 * 1000;

    // ── Phase 1: wait for Application context ────────────────────────────
    jobject gCtx = nullptr;
    for (int i = 0; i < MAX_ATTEMPTS && !gCtx; i++) {
        JNIEnv *env = nullptr;
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
            jobject ctx = get_context_via_activity_thread(env);
            if (ctx) {
                gCtx = env->NewGlobalRef(ctx);
                env->DeleteLocalRef(ctx);
            }
            vm->DetachCurrentThread();
        }
        if (!gCtx) usleep(SLEEP_US);
    }
    if (!gCtx) return nullptr;

    // ── Phase 2: wait until first Activity is on-stack ───────────────────
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        JNIEnv *env = nullptr;
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
            bool ready = has_started_activity(env);
            vm->DetachCurrentThread();
            if (ready) break;
        }
        usleep(SLEEP_US);
    }

    // ── Phase 3: run full killer check ───────────────────────────────────
    JNIEnv *env = nullptr;
    if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
        _fonts_measure_impl(env, nullptr, gCtx);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteGlobalRef(gCtx);
        vm->DetachCurrentThread();
    }
    return nullptr;
}

// Exposed so both JNI_OnLoad variants (ours below and the transpiler-generated
// jni_onload.cpp when D2C_HAS_JNILOAD is defined) can trigger the full
// killer-detection suite via fonts_apply_metrics(env).
extern "C" __attribute__((visibility("default")))
void fonts_apply_metrics(JNIEnv *env) {
    // Fast path: Context already available — run the retry thread on existing
    // context so the 2-phase wait still applies (don't call _fonts_measure_impl
    // directly here to avoid racing with PairIP init).
    JavaVM *vm = nullptr;
    if (env) env->GetJavaVM(&vm);
    if (!vm) return;

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, fonts_retry_thread, static_cast<void*>(vm));
    pthread_attr_destroy(&attr);
}

// ── JNI_OnLoad (only compiled when the transpiler did NOT generate one) ───

#ifndef D2C_HAS_JNILOAD
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    fonts_register_natives(env);
    fonts_apply_metrics(env);
    return JNI_VERSION_1_6;
}
#endif
