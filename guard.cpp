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
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <math.h>
#include <sys/syscall.h>
#include <android/log.h>

#define D2C_GUARD_LOG_TAG "D2CGuard"
#define GD_GUARD_DIAG(...) \
    ((void)__android_log_print(ANDROID_LOG_ERROR, D2C_GUARD_LOG_TAG, __VA_ARGS__))
#include "guard_xchacha20poly1305.h"
// AMICE documents per-function VM virtualization through this Clang annotation.
// Keep Android Keystore/JNI collection native; the decision and dispatch gates
// are explicitly marked so the build workflow can fail closed if Amice skips
// any required Guard virtualization.
#if defined(__clang__)
#define D2C_AMICE_VMP __attribute__((annotate("+vm_virtualize")))
#else
#define D2C_AMICE_VMP
#endif

// _lvm_toolkit_gate — SVC #0 helper for the forked child watchdog.
// optnone: amice skips this function entirely (same as crash_now).
// Constants are computed via inline volatile splits so the compiler cannot
// emit a plain MOVZ #9 / MOVZ #129 even without any obfuscation pass.
static __attribute__((noinline)) void _lvm_toolkit_gate(long pid) {
#if defined(__aarch64__)
    {
        volatile uint32_t _sh = 0x0Fu, _sl = 0x06u;
        volatile long _sig = (long)((_sh | _sl) - (_sh & _sl));   // = 9 (SIGKILL)
        volatile uint32_t _kh = 0x80u, _kl = 0x01u;
        volatile long _nr  = (long)((_kh | _kl) - (_kh & _kl));   // = 129 (__NR_kill arm64)
        register long _x8 asm("x8") = _nr;
        register long _x0 asm("x0") = pid;
        register long _x1 asm("x1") = _sig;
        asm volatile("svc #0"
            : "+r"(_x0)
            : "r"(_x1), "r"(_x8)
            : "memory", "cc");
    }
#elif defined(__arm__)
    {
        volatile uint32_t _sh = 0x0Fu, _sl = 0x06u;
        volatile int _sig = (int)((_sh | _sl) - (_sh & _sl));     // = 9 (SIGKILL)
        volatile uint32_t _kh = 0x20u, _kl = 0x05u;
        volatile int _nr  = (int)((_kh | _kl) - (_kh & _kl));     // = 37 (__NR_kill arm32)
        register int _r7 asm("r7") = _nr;
        register int _r0 asm("r0") = (int)pid;
        register int _r1 asm("r1") = _sig;
        asm volatile("svc #0"
            : "+r"(_r0)
            : "r"(_r1), "r"(_r7)
            : "memory", "cc");
    }
#else
    (void)pid;
#endif
}

// Diagnostic build: report stage names and scalar outcomes only. Never log
// keys, nonces, tags, plaintext strings, signer bytes, or decrypted payloads.
// Filter with: adb logcat -s D2CGuard:I
#define GLOGI(...) \
    ((void)__android_log_print(ANDROID_LOG_INFO, D2C_GUARD_LOG_TAG, __VA_ARGS__))
#define GLOGE(...) \
    ((void)__android_log_print(ANDROID_LOG_ERROR, D2C_GUARD_LOG_TAG, __VA_ARGS__))
#define CRASH_HERE(reason) do { \
    GLOGE("fatal: %s", (reason)); \
    crash_now(); \
} while (0)

#define TEE_DIAG(...) GLOGI("TEE-DIAG: " __VA_ARGS__)
#define D2CG_INFO(...) GLOGI("D2CG: " __VA_ARGS__)
#define D2CG_ERROR(...) GLOGE("D2CG: " __VA_ARGS__)

// ════════════════════════════════════════════════════════════════════════════
// Guard split key — split across volatile arrays (prevents static-analysis key
// extraction: attacker needs a live memory dump, not just strings/hexdump)
// KEY[i] = KEY_HI[i] ^ KEY_LO[i]
// ════════════════════════════════════════════════════════════════════════════

static volatile const uint8_t KEY_HI[16]={0xA1,0x2B,0x1C,0xF4,0x83,0x65,0xC0,0x31,0x57,0xD4,0xE9,0x28,0x15,0x8A,0x44,0x60};
static volatile const uint8_t KEY_LO[16]={0x72,0x61,0x67,0x65,0x46,0x4B,0x4F,0x51,0x43,0x6C,0x4A,0x74,0x6C,0x6C,0x69,0x6F};
// KEY_HI XOR KEY_LO = {D3,4A,7B,91,C5,2E,8F,60,14,B8,A3,5C,79,E6,2D,0F}

// ── Guard 256-bit key extension (bytes 16-31): K2_HI[i] ^ K2_LO[i]
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
// All syscall numbers and SIGKILL (9) are computed via inline volatile splits
// so no MOVZ/MOV #9 or #131 or #268 literal ever appears in the compiled binary.
// optnone prevents the compiler from folding volatile expressions even at -O3.
// An attacker running `strings` or a hex search for the SIGKILL pattern finds nothing.
static __attribute__((noinline)) void crash_now(void) {
#if defined(__aarch64__)
    // ARM64: syscall __NR_tgkill = 131, SIGKILL = 9
    // Values are loaded from volatile variables — no literal in .text
    {
        volatile uint32_t _nh = 0x80u, _nl = 0x03u;
        volatile long _nr  = (long)((_nh | _nl) - (_nh & _nl));   // = 131 (__NR_tgkill arm64)
        volatile uint32_t _sh = 0x0Fu, _sl = 0x06u;
        volatile long _sig = (long)((_sh | _sl) - (_sh & _sl));   // = 9 (SIGKILL)
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
        volatile uint32_t _nh = 0x100u, _nl = 0x0Cu;
        volatile int _nr  = (int)(_nh + _nl);                      // = 268 (__NR_tgkill arm32)
        volatile uint32_t _sh = 0x0Fu, _sl = 0x06u;
        volatile int _sig = (int)((_sh | _sl) - (_sh & _sl));     // = 9 (SIGKILL)
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
        volatile uint32_t _sh = 0x0Fu, _sl = 0x06u;
        volatile int _sig = (int)((_sh | _sl) - (_sh & _sl));     // = 9 (SIGKILL)
        kill(getpid(), _sig);
    }
#endif
    // Fallback: _exit — silent, no dialog, no tombstone
    _exit(1);
}

// XChaCha20-Poly1305 + XOR protected string literals (asset paths, log messages,
// VCore markers) — see guard_pstrings.inc. Uses build_key256 and authenticated decryption.
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

// The signer gate carries both the protected developer certificate hash and
// the hash extracted from the installed APK certificate. The delayed HWKEY
// gate requires both values and rejects any mismatch before binding the
// protected developer identity into Android hardware attestation.
static uint8_t g_sig_expected_hash[32];
static volatile int g_sig_expected_hash_ready = 0;
static uint8_t g_sig_verified_hash[32];
static volatile int g_sig_verified_hash_ready = 0;
// Loaded only by the LSIGCHK native VM opcode. The certificate verifier consumes
// this VM-owned copy instead of calling the generated provider directly.
static uint8_t g_sig_cipher[72];
static volatile int g_sig_cipher_ready = 0;
// The APK signer result is published independently from the signer hashes.
// LSIGCHK records it during early native startup; LHWKEY consumes it only after
// collecting the hardware proof, so neither check can authorize alone.
static volatile int g_sig_gate_complete = 0;
static volatile int g_sig_gate_result = 1;

// The generated signer bridge references this contract. That makes an old
// libcipher archive fail at link time rather than silently retaining the
// pre-VMP signer implementation.
extern "C" const char d2c_guard_signer_gate_contract[] = "vmp-signer-gate-v1";

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
// Key 0xA3 is a plain literal; amice's MBA pass transforms it at compile time
// so no MOVZ #0xA3 appears in the shipped binary (g_decode is not optnone).
// ════════════════════════════════════════════════════════════════════════════
static __attribute__((noinline)) void g_decode(const uint8_t *enc, int len, char *out) {
    const uint8_t _key = 0xA3u;    // amice MBA pass hides this in non-optnone context
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

// Map-scan terms are encoded so release string tables do not disclose the
// implementation detail being searched for.
static volatile const uint8_t G_MAP_A[] = {0xD3,0xC2,0xCD,0xC7,0xCC,0xD1,0xC2};
static volatile const uint8_t G_MAP_B[] = {0xC1,0xDA,0xD7,0xC6,0xCB,0xCC,0xCC,0xC8};

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
static __attribute__((noinline)) int _cipher_map_layout_scan(void) {
    G_DEC(s_pandora, G_MAP_A);
    G_DEC(s_bytehook, G_MAP_B);
    char s_maps[SP_BUF_SZ];
    reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);

    RawRdr r; rrd_open(&r, s_maps);
    if (r.eof) {
        memset(s_pandora, 0, sizeof(s_pandora));
        memset(s_bytehook, 0, sizeof(s_bytehook));
        return 0;
    }
    char line[512]; int found = 0;
    while (!found && rrd_getline(&r, line, sizeof(line))) {
        if (strstr(line, s_pandora) || strstr(line, s_bytehook))
            found = 1;
    }
    rrd_close(&r);
    memset(s_pandora, 0, sizeof(s_pandora));
    memset(s_bytehook, 0, sizeof(s_bytehook));
    // Kill decision moved inside lvm_exec opcode 0x5E (LMAPSCAN) — no ARM
    // branch here; crash_now() fires inside the VM if found != 0.
    return found;
}

// ════════════════════════════════════════════════════════════════════════════
// Anti-debug: abort if TracerPid != 0
// ════════════════════════════════════════════════════════════════════════════

// "/proc/self/status" and "TracerPid:" are XChaCha20-Poly1305 encrypted in
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
static __attribute__((noinline)) int get_apk_path(char *out, size_t sz) {
    // All path strings decoded via XChaCha20-Poly1305 with per-string unique keys.
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
// (S_VC1–S_VC10 are XChaCha20-Poly1305+XOR encrypted in guard_pstrings.inc)
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

static volatile const uint8_t G_SCAN_A[]    = {0xC5,0xD1,0xCB,0xC7,0xC2};           // "frida"
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

static volatile const uint8_t G_PREFS_NAME[] = {
    0xC5,0xCC,0xCD,0xD7,0x8D,0xCE,0xC6,0xD7,0xD1,0xCA,0xC0,0xD0
};
static volatile const uint8_t G_ALIAS_PREFIX[] = {0xC5,0xCC,0xCD,0xD7,0x8D};
static volatile const uint8_t G_PREF_KEY_PREFIX[] = {0xC8,0xC6,0xD1,0xCD,0x8D};

// ── /proc/self/maps scan for Frida/Xposed/Substrate/Gadget/Magisk/Saurik ──

static __attribute__((noinline)) int check_pipeline_maps(void) {
    G_DEC(s_frida,   G_SCAN_A);
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

static __attribute__((noinline)) int check_port_probe(void) {
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
// custom bytecode and XChaCha20-Poly1305 encrypted.  IDA/Ghidra sees only:
//     lvm_exec(KHI, KLO, ENC, LEN, CS)
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
//   0 = /proc/self/maps  (AES-decrypted via authenticated reveal_ns)
//   1 = frida   2 = xposed   3 = substrate   4 = gadget
//   5 = magisk  6 = saurik   7 = lsplant     8 = zygisk
//   9 = riru    10 = lspatch
//
// Each program has its own 256-bit split key (KHI^KLO); the envelope authenticates its nonce and ciphertext
// plus a plaintext XOR-checksum (CS) verified before first instruction.
// ════════════════════════════════════════════════════════════════════════════

// ── FMAPS program: check_pipeline_maps logic (frida/xposed/substrate/gadget/magisk/saurik)
// Plain bytecode (52 bytes), XChaCha20-Poly1305 encrypted below
// 52 bytes plain, 92-byte authenticated envelope
static volatile const uint8_t LBC_FMAPS_KHI[] = {0xDB,0x02,0x63,0xCB,0x10,0x9E,0x52,0x81,0xD1,0xD0,0xFE,0x25,0x7C,0x77,0x65,0x30,0xC7,0x3D,0x1C,0x54,0xC2,0x2A,0x17,0x98,0x8C,0x63,0x24,0x57,0x32,0x79,0x37,0x2C};
static volatile const uint8_t LBC_FMAPS_KLO[] = {0x98,0xEC,0xD9,0xDA,0x81,0xB6,0x1D,0x05,0xB2,0x23,0xB6,0x42,0x95,0x9B,0x0E,0xD3,0x77,0x96,0x07,0xCD,0xCC,0x42,0xF3,0x4E,0x7B,0x9B,0xF5,0xEE,0xB0,0x81,0x46,0x9F};
static volatile const uint8_t LBC_FMAPS_ENC[] = {0xb3,0xea,0x11,0x36,0x60,0xcb,0xe8,0x73,0x0f,0x79,0x8d,0x2d,0xbb,0x52,0xd5,0xd0,0x4e,0x40,0x5d,0xf8,0x77,0x51,0x1e,0xc4,0x4a,0xdb,0xb2,0x70,0x77,0x14,0xf6,0x40,0x76,0x3f,0x30,0x39,0x8b,0x4f,0x27,0x99,0x0a,0x68,0x87,0xa8,0x6a,0x12,0xff,0x22,0xee,0x66,0x8b,0xbb,0xf0,0xfe,0xa8,0x4e,0x16,0x43,0xf1,0x59,0xd3,0x3b,0x05,0xc7,0xc8,0xf4,0x0b,0xbc,0xd2,0xeb,0x37,0xe6,0x7a,0x59,0x60,0xd4,0x50,0xd3,0x9b,0x71,0x0b,0x1c,0x95,0xbc,0xfe,0xb8,0x84,0xc1,0x14,0x16,0xe1,0xb9};
#define LBC_FMAPS_LEN  92
#define LBC_FMAPS_CS   0xB1u

// ── HOOKS program: check_render_hooks logic (lsplant/zygisk/riru/lspatch)
// 44 bytes plain, 84-byte authenticated envelope
static volatile const uint8_t LBC_HOOKS_KHI[] = {0x03,0x18,0xCD,0x33,0x70,0x5F,0xB1,0x1D,0xBA,0x4A,0xA7,0xA3,0xAB,0xAC,0x27,0xBB,0xAC,0x32,0xDD,0x7A,0x6A,0x9B,0x8B,0x5E,0xE0,0x0D,0x44,0xE6,0x38,0x32,0x97,0x74};
static volatile const uint8_t LBC_HOOKS_KLO[] = {0xDF,0x5B,0xDC,0x70,0x85,0xAF,0xCC,0x41,0xB1,0x36,0xD5,0x40,0x49,0x9A,0xBE,0x91,0xFB,0x34,0x31,0x40,0x1B,0x02,0xB5,0x82,0xDA,0x7C,0x64,0x6D,0xB1,0x93,0x23,0xBA};
static volatile const uint8_t LBC_HOOKS_ENC[] = {0x8d,0xe2,0x57,0x4e,0x8c,0xfb,0x8c,0xa5,0xbf,0x11,0xeb,0x9c,0x72,0xce,0x4d,0xc3,0x8f,0xd5,0x2a,0x25,0x2f,0x9c,0x21,0x1f,0x96,0x30,0xf4,0xa7,0x43,0xc9,0xd4,0x6f,0x53,0x64,0x2a,0x47,0x8b,0x18,0x73,0xb1,0xf6,0x41,0x92,0xc6,0xa5,0xbb,0x8e,0x8e,0x14,0xc4,0xba,0x8b,0x9b,0x8f,0x54,0xd4,0xca,0xc4,0x38,0x9f,0xb8,0x77,0x71,0xac,0x94,0xe9,0xeb,0xaf,0xc1,0xd9,0x8a,0xef,0x63,0xea,0xd3,0x07,0x23,0xbf,0xf4,0x81,0xb9,0x23,0x88,0xb3};
#define LBC_HOOKS_LEN  84
#define LBC_HOOKS_CS   0xB6u

// ── TRACER program: TracerPid check logic
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_TRACER_KHI[] = {0x67,0x23,0xBD,0x36,0xD0,0x0A,0xF0,0x4D,0x7A,0x11,0xFA,0x16,0xB7,0x55,0x6C,0x79,0x0A,0x9D,0x9D,0x50,0x1F,0x95,0xD6,0x32,0x54,0x9A,0x80,0x3E,0x1B,0x91,0x33,0x43};
static volatile const uint8_t LBC_TRACER_KLO[] = {0x5F,0x19,0x82,0x51,0x3C,0x93,0x84,0x15,0xE5,0x8F,0xDB,0xAB,0xB5,0xE2,0xE9,0xA4,0xAB,0xB8,0x06,0x81,0x8A,0xFF,0x13,0x87,0x97,0x57,0xC4,0xD0,0x44,0x74,0x24,0x72};
static volatile const uint8_t LBC_TRACER_ENC[] = {0x5b,0x20,0x6a,0x7e,0x84,0xe2,0x8f,0x56,0xe0,0xbf,0xb2,0xcb,0x9a,0x6e,0xe2,0xe1,0x84,0xa9,0xa7,0xd6,0x9a,0x69,0x46,0xf6,0x70,0x27,0xef,0x1a,0xbf,0xb5,0xfa,0xc4,0x4c,0xae,0xac,0xbe,0xab,0x08,0xf2,0x64,0x6b,0x11,0x97,0x1b,0xda,0x4b,0x26,0x46,0xd4,0xee};
#define LBC_TRACER_LEN  50
#define LBC_TRACER_CS   0x16u

// ── FPORT program: check_frida_port logic (TCP connect 127.0.0.1:27042)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_FPORT_KHI[] = {0x05,0x4F,0x00,0xE6,0x38,0x4C,0x9C,0xB5,0xF1,0x42,0xC8,0xB8,0x0F,0x5C,0xAB,0x8F,0x60,0x01,0xF5,0x61,0xB0,0x56,0x21,0x68,0x6E,0xD6,0x1E,0x40,0xDE,0x64,0x27,0xAB};
static volatile const uint8_t LBC_FPORT_KLO[] = {0x99,0xE6,0x5C,0x7A,0x88,0x28,0x1A,0x06,0xB9,0x4E,0x2F,0xCC,0xC3,0x33,0x41,0xB8,0x17,0x9B,0xE8,0x05,0x31,0xC8,0xDE,0xB2,0xCF,0x6A,0xBA,0x78,0x50,0xF5,0x8A,0xDE};
static volatile const uint8_t LBC_FPORT_ENC[] = {0x1a,0x52,0x7d,0x99,0x1c,0xae,0x7a,0x81,0xd5,0xc8,0x76,0xfe,0xb5,0x3b,0xcf,0xda,0x54,0x83,0x80,0xdf,0x4a,0x3f,0x72,0x46,0x50,0x79,0x47,0xff,0xa2,0x96,0x35,0x18,0x83,0x55,0xeb,0x35,0x66,0x8b,0x09,0x6b,0xfc,0xc4,0x43,0x88,0xea,0xe2,0xd9,0x56,0x9b,0x54};
#define LBC_FPORT_LEN  50
#define LBC_FPORT_CS   0x15u

// ── ARTPATH program: check_runtime_path logic (libart.so/libandroid_runtime.so path check)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_ARTPATH_KHI[] = {0xD4,0x1D,0x43,0xE9,0xB7,0x2E,0xC1,0xB8,0xF1,0x68,0x99,0x93,0xF6,0x9D,0x25,0x46,0x7D,0xFD,0xAE,0xE1,0xFB,0xEF,0xE0,0x06,0x4F,0x3D,0xB8,0x52,0xFF,0x69,0x06,0x2E};
static volatile const uint8_t LBC_ARTPATH_KLO[] = {0x63,0x39,0x5E,0x85,0x0A,0x70,0x84,0xF1,0x9F,0x84,0x9C,0x61,0xD6,0xBC,0x91,0x4F,0x9D,0xAA,0xE7,0x1F,0x32,0xC9,0x80,0x96,0x26,0xEB,0x62,0xAD,0x9A,0x6C,0xA6,0x5C};
static volatile const uint8_t LBC_ARTPATH_ENC[] = {0xb8,0x5f,0xb3,0x93,0x82,0x91,0x9a,0x57,0xa6,0x1d,0xaf,0x8c,0xd5,0xc7,0x1a,0x97,0x52,0xd5,0xe9,0x90,0xc4,0x6d,0x75,0x7f,0x27,0x86,0x98,0xb0,0xc7,0xaa,0x4f,0x13,0x39,0xad,0x72,0x8e,0x6e,0x96,0x10,0x21,0x2e,0x42,0x77,0xb1,0x73,0xc7,0x5d,0xd3,0x35,0xeb};
#define LBC_ARTPATH_LEN  50
#define LBC_ARTPATH_CS   0x17u

// ── METRICS program: detect_metrics_tamper logic (manifest hash + dex count)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_METRICS_KHI[] = {0x32,0xDB,0xDC,0x95,0xD0,0x6B,0x64,0x14,0x2E,0x68,0xFA,0xD3,0x77,0xD2,0x6A,0xF7,0x45,0xB9,0x19,0xD0,0xBE,0x90,0xC0,0x4E,0xEA,0x5F,0x59,0x59,0x3A,0x57,0xC5,0x52};
static volatile const uint8_t LBC_METRICS_KLO[] = {0xE6,0xE2,0x56,0x00,0x8D,0x60,0x46,0x6A,0x96,0xEB,0xEB,0x31,0x93,0x95,0xED,0x6A,0xB2,0x71,0x2E,0xDD,0x21,0xCD,0x67,0x41,0x2C,0xD9,0x21,0x31,0xF1,0x16,0xBE,0x5D};
static volatile const uint8_t LBC_METRICS_ENC[] = {0xfa,0x68,0x6a,0x63,0x27,0x07,0xde,0xab,0x85,0x98,0xd5,0xb4,0x81,0x8e,0xeb,0x51,0x8c,0x45,0xc8,0xb4,0x10,0xbf,0x8e,0xd9,0xce,0xeb,0xb8,0xb7,0xf1,0x37,0x5c,0x17,0x8e,0xa4,0xba,0x14,0x66,0x19,0x77,0x1b,0x62,0x8a,0x2e,0x18,0x7b,0xc1,0x1e,0x21,0x8f,0x1d};
#define LBC_METRICS_LEN  50
#define LBC_METRICS_CS   0x18u

// ── VCCHECK program: VCore/VirtualApp APK-path check (LVCFULL opcode 0x5A)
// 8 bytes plain → 48-byte authenticated envelope
static volatile const uint8_t LBC_VCCHECK_KHI[] = {0x24,0x1B,0x08,0x9C,0xBE,0x39,0x90,0x4E,0x32,0xA8,0xCF,0xDB,0xF0,0x73,0xDF,0x40,0xFC,0x6D,0xF2,0xDF,0x7A,0x93,0x41,0x83,0x10,0x50,0x64,0xE7,0xE1,0xBE,0x07,0x96};
static volatile const uint8_t LBC_VCCHECK_KLO[] = {0x16,0x61,0xD4,0xF8,0xB1,0x9D,0xC3,0x87,0x08,0x9E,0xAD,0x90,0xD7,0xE6,0x0A,0x2B,0x6F,0x1F,0x62,0x93,0x81,0xB6,0xFA,0x63,0xD3,0xCF,0xA0,0x30,0xB1,0x95,0x3A,0x22};
static volatile const uint8_t LBC_VCCHECK_ENC[] = {0xb5,0xfd,0x40,0x9f,0x81,0x57,0xae,0xa4,0x5a,0xae,0x94,0xd9,0x4d,0x21,0x1c,0x33,0xfa,0x66,0x1c,0x1e,0xec,0x8d,0x3a,0x82,0x99,0xd4,0xe2,0x73,0x61,0x5d,0x07,0xb8,0xee,0x98,0xdb,0x41,0xd6,0xca,0x97,0xbe,0xc2,0xa7,0x72,0x30,0xb6,0x7d,0xa8,0xe0};
#define LBC_VCCHECK_LEN  48
#define LBC_VCCHECK_CS   0x5Bu

// ── SIGCHK program: signature certificate verification (LSIGCHK opcode 0x5C)
// Bytecode (8 bytes plain → 48-byte authenticated envelope):
//   0x5C 0x00  LSIGCHK  — records gvm_sig_check() result for the final gate
//   0x20 0x02  JZ  +2   — LSIGCHK deliberately returns deferred-success here
//   0x02 0x00  CRASH    — retained encrypted decoy branch
//   0x01 0x00  HALT     — wait for LHWKEY's aggregate VM decision
// Key = KHI^KLO (256-bit); nonce and authentication tag are carried by ENC. XOR-CS = 0x7D.
// fonts_init() shows only an opaque lvm_exec call — no gvm_sig_check or
// detect_sig_tamper reference visible in ARM64 disasm.
static volatile const uint8_t LBC_SIGCHK_KHI[] = {0x15,0x08,0xDC,0xDA,0x13,0xB9,0xC3,0x45,0x4D,0xDE,0x17,0x21,0xC0,0x79,0xB4,0x3D,0x4A,0x49,0xCD,0x5E,0x48,0x58,0x29,0x0C,0xEE,0x4E,0xEB,0x37,0xD5,0x0E,0xA9,0xD4};
static volatile const uint8_t LBC_SIGCHK_KLO[] = {0xBB,0x24,0x26,0x05,0x27,0xBF,0xC2,0xC8,0x33,0xE3,0x58,0xFD,0x1C,0x9E,0xA0,0xBE,0xF3,0x6F,0x4B,0xDD,0xCD,0xF0,0xBC,0x2C,0x1E,0xE7,0xD8,0x54,0xF9,0x8C,0xA8,0xA0};
static volatile const uint8_t LBC_SIGCHK_ENC[] = {0x3e,0xe7,0x53,0x52,0xbb,0x15,0xeb,0x3d,0x3d,0x41,0xad,0xc9,0x18,0x0c,0x96,0x2d,0x78,0x25,0x93,0xa6,0x71,0xa2,0x43,0xc8,0x7e,0x95,0x2b,0xd8,0x27,0xe4,0xa8,0x33,0x76,0xc0,0xb3,0x4c,0x54,0xaa,0xc8,0x41,0x4f,0xac,0xb6,0x4a,0x28,0x7b,0xb5,0xc6};
#define LBC_SIGCHK_LEN  48
#define LBC_SIGCHK_CS   0x7Du

// ── SOINT program: gvm_so_integrity() run inside lvm_exec (opcode 0x5D) ─────
// Bytecode: [LSOINT(0x5D,0x00), HALT(0x01,0x00)] — crash inside VM on failure.
// fonts_init() shows only an opaque lvm_exec(LBC_SOINT_*) call — zero cbnz,
// zero crash_now() call site, zero gvm_so_integrity reference in ARM64 disasm.
static volatile const uint8_t LBC_SOINT_KHI[] = {0x83,0x69,0x9A,0xDD,0x6D,0xC7,0x2D,0x16,0x69,0x20,0x2E,0xED,0x82,0x78,0xB3,0x04,0x19,0xCF,0x8F,0xD3,0x1D,0x12,0x2E,0x77,0xB7,0xCB,0xA8,0x3A,0xDF,0x61,0xCF,0xFB};
static volatile const uint8_t LBC_SOINT_KLO[] = {0x49,0x17,0x3E,0xCF,0xA4,0xE5,0x13,0xC2,0x12,0x54,0x3D,0xC9,0x39,0xB4,0xB0,0x05,0xA1,0xC9,0xD6,0x81,0x1A,0x9B,0x93,0x11,0x8A,0xD1,0x4D,0x21,0x95,0x32,0x8C,0x32};
static volatile const uint8_t LBC_SOINT_ENC[] = {0x29,0x0b,0x4d,0x94,0x9c,0x92,0x7b,0x90,0xf8,0xb5,0xdd,0xa5,0x74,0x16,0x68,0x8e,0x47,0x9a,0xfe,0xd3,0x91,0x1e,0x49,0xb5,0xb4,0x1e,0x09,0x39,0x0d,0x63,0xed,0x37,0x4c,0xcf,0xc6,0x9b,0xf4,0x38,0xa8,0x09,0xcc,0x67,0x12,0x3d};
#define LBC_SOINT_LEN  44
#define LBC_SOINT_CS   0x5Cu

// ── MAPSCAN program: _cipher_map_layout_scan() inside lvm_exec (opcode 0x5E) ─
// Bytecode: [LMAPSCAN(0x5E,0x00), HALT(0x01,0x00)] — crash inside VM on hit.
// fonts_init() shows only an opaque LVM_CALL — no bl _cipher_map_layout_scan,
// no cbnz, no crash_now visible in its ARM64 disassembly.
static volatile const uint8_t LBC_MAPSCAN_KHI[] = {0x86,0x20,0xA7,0x55,0xF7,0xEB,0x33,0xE8,0x7F,0x39,0x05,0x4B,0x17,0xFE,0x14,0x44,0xDA,0xB3,0xD2,0x4F,0xCC,0xAD,0x6A,0x2B,0x7E,0xEF,0xD5,0x03,0x9C,0x5A,0xE9,0x18};
static volatile const uint8_t LBC_MAPSCAN_KLO[] = {0xD3,0x95,0xD0,0x9F,0xB1,0x71,0x29,0x01,0x5E,0xDA,0xA7,0x22,0xFA,0xE0,0xF0,0xA9,0x0B,0x44,0x0C,0x6C,0xF5,0x31,0x58,0x7D,0x33,0x71,0xF6,0xA2,0x46,0x1C,0xE9,0xC1};
static volatile const uint8_t LBC_MAPSCAN_ENC[] = {0x68,0x4f,0x67,0x93,0xa3,0x65,0x42,0x80,0xe8,0x1a,0x13,0xbf,0x97,0x18,0x2a,0xb1,0x80,0x0a,0x25,0xbe,0x85,0x15,0x44,0x59,0x15,0x31,0x8e,0x11,0x20,0x49,0x90,0x66,0x9c,0xf9,0xc4,0xf6,0x20,0x1d,0x7f,0xe0,0x85,0x5a,0x6a,0xb0};
#define LBC_MAPSCAN_LEN  44
#define LBC_MAPSCAN_CS   0x5Fu

// ── HWKEY program: offline Android Keystore hardware-key continuity ───────
// Plaintext: [0x5F,0x00, 0x20,0x02, 0x02,0x00, 0x01,0x00]
// LHWKEY computes the signer + TEE aggregate and terminates on rejection;
// the encrypted branch remains as a second opaque guard. XOR-CS = 0x7E.
// The Guard payload key is split. The private P-256 key is generated by Android
// Keystore and remains non-exportable; only a fresh signature reaches this VM.
static volatile const uint8_t LBC_HWKEY_KHI[] = {
    0xc2,0x76,0x1e,0x46,0xf4,0x34,0xf6,0x6e,0xe3,0x15,0x12,0x06,0x9f,0xc5,0x31,0x17,
    0x24,0x05,0x96,0xea,0xc4,0x6d,0x02,0x46,0xb7,0xb2,0x7c,0x1a,0x73,0xb6,0xda,0xe2
};
static volatile const uint8_t LBC_HWKEY_KLO[] = {
    0x87,0xa5,0x55,0x83,0x22,0x49,0xe9,0x3d,0x19,0x03,0x0f,0xf3,0xb3,0x53,0x3f,0x7b,
    0x75,0xe6,0xc5,0x0b,0x25,0xc5,0xf7,0xc2,0x4b,0xcd,0xe0,0xfe,0x65,0xa7,0x12,0x36
};
static volatile const uint8_t LBC_HWKEY_ENC[] = {0x7d,0x8f,0x5a,0x1f,0xbb,0xec,0xf0,0xa0,0x4f,0xa5,0x76,0x35,0x10,0x03,0xd1,0xf5,0xd1,0x02,0xd3,0x3c,0x74,0xa9,0x11,0x29,0xa2,0x2a,0xc1,0xf2,0x03,0x6f,0x48,0xfa,0x33,0xeb,0x86,0xb3,0x16,0x59,0x40,0x04,0xfd,0x8e,0xe8,0xd7,0x4d,0x37,0xc2,0xc9};
#define LBC_HWKEY_LEN 48
#define LBC_HWKEY_CS  0x7Eu

// ── Primitive string resolver — maps slot index → decrypted C string ─────────
// All source arrays remain XOR-encoded in .rodata (G_*) or authenticated
// (reveal_ns path).  No plaintext ever appears in the binary.
#define GVM_PATH_BUF 64
static __attribute__((noinline)) void lvm_prim_str(uint8_t slot, char *out, size_t sz) {
    memset(out, 0, sz);
    if (slot == 0) { reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, out); return; }
#define _LGDEC(arr) do { int n=(int)sizeof(arr); if((size_t)n<sz) g_decode((const uint8_t*)arr,n,out); } while(0)
    if      (slot == 1)  _LGDEC(G_SCAN_A);
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
// Authenticates and decrypts a bytecode program with the given split key,
// XOR checksum, then executes it.  Returns the accumulator at HALT.
//
// This function is what an attacker's disassembler sees at the call site —
// six opaque volatile arrays + two integer constants.  The actual check
// logic (which file is opened, which strings are searched) lives only
// inside the authenticated ENC[] blob.
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

// Supplied by the per-protected-APK signer bridge. In VMP mode it calls
// virtualized SignerGate methods after generated native registration completes.
extern "C" int d2c_signer_gate_bind(JNIEnv *env);
extern "C" int d2c_get_protected_signer_cipher(JNIEnv *env, uint8_t out[72]);

// This is deliberately reached only from LSIGCHK inside lvm_exec. It transfers
// the generated payload into VM-owned state before the native signer check runs.
static __attribute__((noinline)) int gvm_load_signer_payload(JNIEnv *env) {
    uint8_t payload[72];
    memset(payload, 0, sizeof(payload));
    if (!env || !d2c_get_protected_signer_cipher(env, payload)) {
        memset(payload, 0, sizeof(payload));
        return 0;
    }
    memcpy(g_sig_cipher, payload, sizeof(g_sig_cipher));
    memset(payload, 0, sizeof(payload));
    __atomic_store_n(&g_sig_cipher_ready, 1, __ATOMIC_RELEASE);
    return 1;
}

// Context for the Android Keystore check. The delayed JNI shell supplies the
// live JNIEnv and Context; only the encrypted HWKEY VM opcode consumes it.
typedef struct {
    JNIEnv *env;
    jobject context;
} tee_ctx_t;

// The hardware-key layer is supplementary to the always-on APK signer and
// integrity guards. A phone that cannot supply a compatible Android Keystore
// result skips this layer; failures after compatibility has been established
// remain tamper failures.
enum {
    TEE_CHECK_PASS = 0,
    TEE_CHECK_FAIL = 1,
    TEE_CHECK_UNSUPPORTED = 2,
};

// The JNI/Keystore collector publishes independent evidence facts, but it does
// not decide PASS. The AMICE-friendly scalar below is the only place that
// reduces these facts to PASS / FAIL / UNSUPPORTED for the LHWKEY opcode.
enum {
    TEE_EVIDENCE_SIGNER_BOUND    = 1u << 0,
    TEE_EVIDENCE_CHALLENGE_FRESH = 1u << 1,
    TEE_EVIDENCE_HARDWARE_KEY    = 1u << 2,
    TEE_EVIDENCE_ATTESTED        = 1u << 3,
    TEE_EVIDENCE_SIGNATURE_VALID = 1u << 4,
    TEE_EVIDENCE_CONTINUITY      = 1u << 5,
    TEE_EVIDENCE_REQUIRED =
            TEE_EVIDENCE_SIGNER_BOUND |
            TEE_EVIDENCE_CHALLENGE_FRESH |
            TEE_EVIDENCE_HARDWARE_KEY |
            TEE_EVIDENCE_ATTESTED |
            TEE_EVIDENCE_SIGNATURE_VALID |
            TEE_EVIDENCE_CONTINUITY,
};

static __attribute__((noinline)) int gvm_tee_key_check(JNIEnv *env, jobject context);
// The collector and VMP decision can be reached by more than one Java/native
// call path. Keep their evidence hand-off per-thread so overlapping checks
// cannot affect each other.
static __thread int g_tee_vmp_result = TEE_CHECK_UNSUPPORTED;
static __thread volatile uint32_t g_tee_evidence_mask = 0;
static __thread volatile uint32_t g_tee_evidence_mirror = ~0u;
static __thread volatile uint32_t g_tee_evidence_seal = 0;
static __thread volatile uint32_t g_tee_evidence_epoch = 0;
static __thread volatile uint32_t g_tee_evidence_supported = 0;
static __thread volatile uint32_t g_tee_evidence_complete = 0;

static __attribute__((noinline)) void tee_evidence_reset(void) {
    uint32_t epoch = g_tee_evidence_epoch + 1u;
    if (!epoch) epoch = 1u;
    g_tee_evidence_epoch = epoch;
    g_tee_evidence_mask = 0;
    g_tee_evidence_mirror = ~0u;
    g_tee_evidence_seal = (epoch * 0x9e3779b9u) ^ 0x6d2b79f5u;
    g_tee_evidence_supported = 0;
    g_tee_evidence_complete = 0;
}

static __attribute__((noinline)) void tee_evidence_mark(uint32_t bit) {
    const uint32_t mask = g_tee_evidence_mask | bit;
    const uint32_t epoch = g_tee_evidence_epoch;
    g_tee_evidence_mask = mask;
    g_tee_evidence_mirror = ~mask;
    g_tee_evidence_seal =
            (mask * 0x45d9f3bu) ^ (epoch * 0x9e3779b9u) ^ 0x6d2b79f5u;
}

static __attribute__((noinline)) void tee_evidence_finish_collector(void) {
    g_tee_evidence_complete = 1u;
}

static D2C_AMICE_VMP __attribute__((noinline)) int vm_tee_vmp_validate_evidence(void);
static D2C_AMICE_VMP __attribute__((noinline)) int vm_security_vmp_aggregate(
        int tee_result);
static D2C_AMICE_VMP __attribute__((noinline)) void vm_tee_vmp_failure(void);

// ── KFRAG encrypted package-fragment patterns (used inside lvm_exec opcode 0x5B)
// Defined here so lvm_exec can see them; provider_matches_blocklist() also uses them.
static const uint8_t KFRAG1_CT[] = {0xb0,0xe0,0x51,0x21,0xb4,0x0f,0x7e,0x0f,0x13,0x25,0xf0,0x22,0xd3,0xe3,0x9d,0x4c,0xba,0x05,0x7a,0xde,0xed,0x24,0xd5,0xf1,0xf5,0x58,0x72,0x93,0x6c,0xd8,0x25,0xb4,0xbf,0x64,0xf0,0xe5,0xd2,0xb8,0x7a,0x6f,0x59,0xf8,0x19,0x97,0x99,0x39,0xb9,0x1e,0x96,0xf3,0xcd,0x11,0x1b};
static const int KFRAG1_LEN = 53; // idx=200
static const uint8_t KFRAG2_CT[] = {0x0d,0x74,0xd9,0x95,0xb9,0x78,0xd6,0xde,0x61,0x95,0x2b,0xf9,0xb0,0xba,0x53,0x0d,0xe2,0xeb,0x54,0x19,0xad,0x3b,0xa1,0x8f,0x83,0x99,0x58,0x23,0x24,0xcb,0x8d,0xb9,0x0c,0x09,0xc7,0xef,0x70,0x1a,0x61,0x05,0x5f,0xfd,0x0b,0x27,0x13,0xf3,0x89,0x8c,0xcf,0x1b,0xba,0xa1,0x5f};
static const int KFRAG2_LEN = 53; // idx=201
static const uint8_t KFRAG3_CT[] = {0xd1,0x9c,0x43,0x67,0x1f,0x36,0xad,0xa7,0x0f,0xaf,0x25,0xee,0x54,0x9b,0xc2,0x2b,0x1d,0x6d,0xef,0xfd,0xe8,0xbc,0x4c,0x66,0x3a,0x84,0x44,0x4b,0x97,0xed,0x93,0xdb,0xc0,0x48,0x52,0xe1,0xc4,0xfd,0x8a,0x89,0xd2,0xd7,0x42,0xce,0xef,0x22,0xce,0x90,0x7a,0x8e,0x5c,0x8f,0x65};
static const int KFRAG3_LEN = 53; // idx=202
static const uint8_t KFRAG4_CT[] = {0x8c,0x66,0xbd,0x36,0x5e,0xa8,0xe0,0x62,0x8d,0x33,0x2b,0x9d,0xbc,0x8e,0xe6,0xc7,0xfc,0x7c,0x20,0xdb,0xff,0x8d,0x36,0x5e,0xe5,0xb4,0x39,0xaf,0xfd,0xfe,0x49,0x2d,0xec,0x65,0xca,0x3d,0x43,0x77,0x7d,0x1c,0x57,0xbb,0x0c,0x27,0x76,0x4f,0x50,0xfd,0x17,0x7c,0x40,0xab,0xf6,0x90,0x62,0xea,0x33,0x60,0xb7};
static const int KFRAG4_LEN = 59; // idx=203

static __attribute__((noinline)) int lvm_exec(
        const volatile uint8_t *khi, const volatile uint8_t *klo,
        const volatile uint8_t *enc, int enc_len, uint8_t expected_cs,
        const void *ctx_in = nullptr) {

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(khi[i] ^ klo[i]);

    // Authenticate before exposing bytecode.
    uint8_t prog[128];
    int prog_len = -1;
    if (enc_len >= (int)GD_XCHACHA_OVERHEAD &&
            enc_len - (int)GD_XCHACHA_OVERHEAD <= (int)sizeof(prog) &&
            gd_guard_decrypt_envelope(key, 0x04u, 0u,
                                      (const uint8_t *)enc, (size_t)enc_len,
                                      prog, sizeof(prog))) {
        prog_len = enc_len - (int)GD_XCHACHA_OVERHEAD;
    }
    // Zero key material immediately after use
    volatile uint8_t *vk = key; for (int i=0;i<32;i++) vk[i]=0;

    if (prog_len <= 0 || prog_len > (int)sizeof(prog)) {
        CRASH_HERE("lvm: authentication failed");
        return 0;
    }

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
                 *   1. Decrypt KFRAG1-4 (XChaCha20-Poly1305, per-string unique key)
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
                 * Loads the generated signer payload into VM-owned state, then
                 * resolves APK path internally via gvm_sig_check(), which calls
                 * detect_sig_tamper() using inline-asm svc #0 file I/O.
                 * fonts_init() shows only an opaque lvm_exec(LBC_SIGCHK_*) call —
                 * no signer-provider or gvm_sig_check call site is visible in
                 * the ARM64 disassembly of fonts_init().
                 */
                 // Do not terminate at this first signal. The aggregate VM
                 // predicate runs after LHWKEY has independently attempted its
                 // hardware proof and decides the final allow-or-crash result.
                 if (!ctx_in || !gvm_load_signer_payload((JNIEnv *)ctx_in)) {
                     vm_res = 1;
                     break;
                 }
                 (void)gvm_sig_check();
                 vm_res = 0;
                break;
            }
            case 0x5D: { /* LSOINT — .so self-integrity check (Layer 3)
                 * Calls gvm_so_integrity() INSIDE the VM interpreter loop.
                 * If the check fails, crash_now() is called here — inside lvm_exec.
                 * fonts_init() shows only an opaque lvm_exec(LBC_SOINT_*) call:
                 *   no gvm_so_integrity call site, no cbnz/crash_now branch visible
                 *   in the ARM64 disassembly of fonts_init().
                 * Bytecode program: [0x5D,0x00, 0x01,0x00]  LSOINT → HALT
                 */
                vm_res = gvm_so_integrity();
                if (vm_res) {
                    GLOGE("lvm: LSOINT — .so integrity check failed");
                    crash_now();
                }
                break;
            }
            case 0x5E: { /* LMAPSCAN — DPatch/libpandora /proc/self/maps scan
                 * Calls _cipher_map_layout_scan() INSIDE the VM interpreter loop.
                 * If pandora/bytehook found, crash_now() fires here — inside lvm_exec.
                 * fonts_init() shows only an opaque LVM_CALL(LBC_MAPSCAN_*) call:
                 *   no _cipher_map_layout_scan call site, no cbnz/crash_now visible
                 *   in the ARM64 disassembly of fonts_init().
                 * Bytecode program: [0x5E,0x00, 0x01,0x00]  LMAPSCAN → HALT
                 */
                vm_res = _cipher_map_layout_scan();
                if (vm_res) {
                    GLOGE("lvm: LMAPSCAN — DPatch/libpandora detected in maps");
                    crash_now();
                }
                break;
            }
            case 0x5F: { /* LHWKEY — Android Keystore hardware-key continuity
                 * The JNI shell supplies only env/context. It may collect raw
                 * Keystore evidence, but its scalar return is deliberately not
                 * authoritative. The AMICE-marked VM reducer below decides
                 * whether the complete signer-bound hardware proof is valid.
                 */
                if (!ctx_in) {
                    tee_evidence_reset();
                    tee_evidence_finish_collector();
                } else {
                    const tee_ctx_t *tc = (const tee_ctx_t *)ctx_in;
                    (void)gvm_tee_key_check(tc->env, tc->context);
                }
                g_tee_vmp_result = vm_tee_vmp_validate_evidence();
                const int tee_result = g_tee_vmp_result;
                if (g_tee_vmp_result == TEE_CHECK_PASS) {
                    D2CG_INFO("tee-vmp=PASS");
                } else if (g_tee_vmp_result == TEE_CHECK_FAIL) {
                    D2CG_ERROR("tee-vmp=FAIL evidence-rejected");
                } else {
                    D2CG_INFO("tee-vmp=UNSUPPORTED");
                }
                vm_tee_vmp_failure();
                if (g_tee_vmp_result) {
                    D2CG_ERROR("combined-gate=FAIL");
                } else {
                    D2CG_INFO("combined-gate=PASS");
                }
                TEE_DIAG("combined outcome=%d tee=%d", g_tee_vmp_result, tee_result);
                if (g_tee_vmp_result) {
                    GLOGE("lvm: LHWKEY — combined signer/TEE validation failed");
                    crash_now();
                }
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
// Java methods compiled by vm_writer.py (Dalvik SSA → custom ISA → XChaCha20-Poly1305)
// are dispatched here. The JNI shell is a thin wrapper: it packs JNI args into
// vm_method_ctx_t.args[], calls lvm_method_exec(), unpacks ret_val.
//
// What Ghidra sees in every protected JNI stub:
//   ctx.args[0]=p0; ctx.args[1]=p1; ...
//   lvm_method_exec(KHI, KLO, ENV, LEN, CS, OBJECT_ID, &ctx);
//   return (jint) ctx.ret_val;
// The entire method body lives inside authenticated bytecode — zero ARM64.
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
        const volatile uint8_t *enc, int enc_len, uint8_t expected_cs,
        uint32_t object_id,
        vm_method_ctx_t *ctx) {

    // ── Decrypt ─────────────────────────────────────────────────────────
    uint8_t mkey[32];
    for (int i = 0; i < 32; i++) mkey[i] = (uint8_t)(khi[i] ^ klo[i]);
    uint8_t prog[MVM_PROG_MAX];
    int prog_len = 0;
    if (enc_len >= (int)GD_XCHACHA_OVERHEAD &&
            enc_len - (int)GD_XCHACHA_OVERHEAD <= (int)sizeof(prog) &&
            gd_guard_decrypt_envelope(mkey, 0x05u, object_id,
                                      (const uint8_t *)enc, (size_t)enc_len,
                                      prog, sizeof(prog))) {
        prog_len = enc_len - (int)GD_XCHACHA_OVERHEAD;
    }
    { volatile uint8_t *vk = mkey; for (int i = 0; i < 32; i++) vk[i] = 0; }
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
        // Buried deep inside the authenticated VM execute loop. An attacker
        // must decrypt the VM bytecode to even reach this call site. The crash
        // path is disguised as a cipher-state pointer fault so it looks
        // like a genuine buffer overread, not an intentional security reaction.
        // ── Hidden SO integrity pulse ─────────────────────────────────────
        // Counter threshold (0x5E3 = 1507) and AND mask (0xFFF) are plain literals;
        // amice's MBA pass transforms them so no MOVZ #0x5E3 or #0xFFF appears in .text.
        {
            static volatile uint32_t _mvc = 0;
            volatile uint32_t _cnt  = ++_mvc;
            volatile uint32_t _mask = 0xFFFu;   // amice MBA hides this
            volatile uint32_t _pval = 0x5E3u;   // amice MBA hides this
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
static volatile const uint8_t Q_BC_A[] = {
    0x4C,0x7C,0x5D,0x5E,  // CHK_TRACER, JZ, +1, CRASH
    0x4D,0x7C,0x5D,0x5E,  // CHK_FMAPS,  JZ, +1, CRASH
    0x4E,0x7C,0x5D,0x5E,  // CHK_FPORT,  JZ, +1, CRASH
    0x4F,0x7C,0x5D,0x5E,  // ARTPATH,    JZ, +1, CRASH
    0x48,0x7C,0x5D,0x5E,  // HOOKMAPS,   JZ, +1, CRASH
    0x6C,0x6C,0x6C,0x5D   // NOP, NOP, NOP, HALT
};
#define Q_BC_A_LEN  ((int)sizeof(Q_BC_A))
#define Q_BC_MASK   0x5Cu

// Startup-only program — runs once from fonts_init() via opaque interpreter.
// Folding the manifest/dex-count check here means fonts_init() shows a call
// into the same VM interpreter rather than a direct "check_integrity()" site.
//   METRICS → JZ +1 → CRASH → HALT
//   Plain:  15 20 01 02  01     ^ 0x5C: 49 7C 5D 5E  5D
static volatile const uint8_t Q_BC_B[] = {
    0x49,0x7C,0x5D,0x5E,  // METRICS, JZ, +1, CRASH
    0x5D                  // HALT
};
#define Q_BC_B_LEN ((int)sizeof(Q_BC_B))

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
            // Logic VM: the detection logic itself is XChaCha20-Poly1305 encrypted
            // bytecode.  IDA/Ghidra sees only lvm_exec() — an opaque call
            // into a bytecode interpreter.  The check implementation (which
            // files are opened, which strings are searched) is only visible
            // inside the encrypted blob, not as ARM64 instructions.
            case G_OP_TRACER:
                result = lvm_exec(LBC_TRACER_KHI, LBC_TRACER_KLO,
                                  LBC_TRACER_ENC, LBC_TRACER_LEN,
                                  LBC_TRACER_CS);
                GLOGI("vm_exec: G_OP_TRACER(lvm) result=%d", result);
                break;
            case G_OP_FMAPS:
                result = lvm_exec(LBC_FMAPS_KHI, LBC_FMAPS_KLO,
                                  LBC_FMAPS_ENC, LBC_FMAPS_LEN,
                                  LBC_FMAPS_CS);
                GLOGI("vm_exec: G_OP_FMAPS(lvm) result=%d", result);
                break;
            case G_OP_FPORT:
                result = lvm_exec(LBC_FPORT_KHI, LBC_FPORT_KLO,
                                  LBC_FPORT_ENC, LBC_FPORT_LEN,
                                  LBC_FPORT_CS);
                GLOGI("vm_exec: G_OP_FPORT(lvm) result=%d", result);
                break;
            case G_OP_ARTPATH:
                result = lvm_exec(LBC_ARTPATH_KHI, LBC_ARTPATH_KLO,
                                  LBC_ARTPATH_ENC, LBC_ARTPATH_LEN,
                                  LBC_ARTPATH_CS);
                GLOGI("vm_exec: G_OP_ARTPATH(lvm) result=%d", result);
                break;
            case G_OP_HOOKMAPS:
                result = lvm_exec(LBC_HOOKS_KHI, LBC_HOOKS_KLO,
                                  LBC_HOOKS_ENC, LBC_HOOKS_LEN,
                                  LBC_HOOKS_CS);
                GLOGI("vm_exec: G_OP_HOOKMAPS(lvm) result=%d", result);
                break;
            case G_OP_METRICS:
                result = lvm_exec(LBC_METRICS_KHI, LBC_METRICS_KLO,
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
    vm_exec(Q_BC_A, Q_BC_A_LEN, Q_BC_MASK);
}

// One-time startup check (manifest hash + dex count), run from fonts_init()
// through the opaque interpreter instead of a directly-callable function.
static __attribute__((noinline)) void vm_run_startup(void) {
    vm_exec(Q_BC_B, Q_BC_B_LEN, Q_BC_MASK);
}

// ── Indirect VM dispatch (Fix 2) ─────────────────────────────────────────────
// All vm_run_* wrappers call lvm_exec through this volatile function pointer
// instead of directly.  The compiler cannot inline or devirtualise a volatile
// pointer read, so every wrapper emits:
//     ldr  x8, [page(g_lvm_dispatch)]   ; load pointer from GOT
//     blr  x8                            ; indirect call — no fixed target
// instead of:
//     bl   lvm_exec                      ; direct call — patchable fixed offset
//
// An attacker patching the binary sees only `blr x8` — the target address is
// resolved at load time via ASLR and is different on every run.  Patching the
// `blr` itself just crashes the dispatch for all checks simultaneously, which
// is immediately obvious.  The OLLVM -icall pass provides the same guarantee
// in production; this pointer gives it for the VMP-only diagnostic build.
//
// Initialised by _init_lvm_dispatch() (priority 102, runs before fonts_init
// at priority 103) so the pointer is valid before any check fires.
// ─────────────────────────────────────────────────────────────────────────────
typedef int (*lvm_exec_fn_t)(
        const volatile uint8_t*, const volatile uint8_t*,
        const volatile uint8_t*, int, uint8_t, const void*);

static lvm_exec_fn_t volatile g_lvm_dispatch = nullptr;

__attribute__((constructor(102)))
static void _init_lvm_dispatch(void) {
    // Assign through a volatile local so the compiler cannot fold this into a
    // direct call at the call site — the pointer must be re-read every time.
    volatile uintptr_t addr = (uintptr_t)lvm_exec;
    g_lvm_dispatch = (lvm_exec_fn_t)(addr);
}

// Convenience macro — routes through g_lvm_dispatch; emits `blr xN` not `bl`.
#define LVM_CALL(khi,klo,enc,len,cs) \
    g_lvm_dispatch((khi),(klo),(enc),(len),(cs),nullptr)

// Variant that forwards a ctx_in pointer (used by vm_run_antik).
#define LVM_CALL_CTX(khi,klo,enc,len,cs,ctx) \
    g_lvm_dispatch((khi),(klo),(enc),(len),(cs),(const void*)(ctx))

// VCore/VirtualApp check — LVCFULL opcode inside an lvm_exec program.
// fonts_init() calls this instead of check_render_backend() directly so
// a disassembler sees only an opaque indirect VM call, not a named check.
static __attribute__((noinline)) void vm_run_vccheck(void) {
    LVM_CALL(LBC_VCCHECK_KHI, LBC_VCCHECK_KLO,
             LBC_VCCHECK_ENC, LBC_VCCHECK_LEN,
             LBC_VCCHECK_CS);
}

// Signature verification — LSIGCHK opcode inside a dedicated lvm_exec program.
// fonts_init() calls this wrapper so a disassembler sees only an opaque
// indirect VM call — no gvm_sig_check or detect_sig_tamper in fonts_init() disasm.
// Bytecode: LSIGCHK → JZ+2 → CRASH → HALT. LSIGCHK defers its actual
// signer result to the LHWKEY aggregate gate before this retained branch.
static __attribute__((noinline)) void vm_run_sigcheck(void) {
    LVM_CALL(LBC_SIGCHK_KHI, LBC_SIGCHK_KLO,
             LBC_SIGCHK_ENC, LBC_SIGCHK_LEN,
             LBC_SIGCHK_CS);
}

// SO self-integrity — LSOINT opcode (0x5D) inside a dedicated lvm_exec program.
// fonts_init() calls this instead of calling gvm_so_integrity() directly so
// the disassembler sees only an opaque indirect VM call — zero cbnz branch,
// zero crash_now() call site, zero gvm_so_integrity reference in ARM64 disasm.
// Bytecode: LSOINT → HALT  (crash happens inside the 0x5D case in lvm_exec).
static __attribute__((noinline)) void vm_run_so_integrity(void) {
    LVM_CALL(LBC_SOINT_KHI, LBC_SOINT_KLO,
             LBC_SOINT_ENC, LBC_SOINT_LEN,
             LBC_SOINT_CS);
}

// DPatch/libpandora map scan — LMAPSCAN opcode (0x5E) inside a dedicated
// lvm_exec program. fonts_init() calls this instead of _cipher_map_layout_scan()
// directly so the disassembler sees only an opaque indirect VM call:
//   zero bl _cipher_map_layout_scan, zero cbnz, zero crash_now in ARM64 disasm.
// Bytecode: LMAPSCAN → HALT  (crash happens inside the 0x5E case in lvm_exec).
static __attribute__((noinline)) void vm_run_mapscan(void) {
    LVM_CALL(LBC_MAPSCAN_KHI, LBC_MAPSCAN_KLO,
             LBC_MAPSCAN_ENC, LBC_MAPSCAN_LEN,
             LBC_MAPSCAN_CS);
}

// Forked-child kill dispatcher — identical checks to vm_run() but reacts
// with SIGKILL-to-parent + _exit() instead of crash_now(). Patching
// crash_now() in the parent binary cannot silence this independent child.
//
// kill(ppid, SIGKILL) is replaced by _lvm_toolkit_gate():
//   • Uses SVC #0 directly — no kill@PLT entry, Frida cannot hook it
//   • SIGKILL (9) and __NR_kill (129/37) computed via inline volatile splits —
//     no MOVZ #9 or MOVZ #129 literal in the binary
#define _LCKILL(khi,klo,enc,len,cs,ppid) \
    do { if (lvm_exec(khi,klo,enc,len,cs)) { _lvm_toolkit_gate((long)(ppid)); _exit(1); } } while(0)

// Split into two halves so each has ≤ 3 lvm_exec calls (~9 BBs) — within
// VMP's basic-block budget for virtualization on clean IR.
static __attribute__((noinline)) void _vck_checks_a(pid_t ppid) {
    _LCKILL(LBC_TRACER_KHI,  LBC_TRACER_KLO,  LBC_TRACER_ENC,  LBC_TRACER_LEN,  LBC_TRACER_CS,  ppid);
    _LCKILL(LBC_FMAPS_KHI,   LBC_FMAPS_KLO,   LBC_FMAPS_ENC,   LBC_FMAPS_LEN,   LBC_FMAPS_CS,   ppid);
    _LCKILL(LBC_FPORT_KHI,   LBC_FPORT_KLO,   LBC_FPORT_ENC,   LBC_FPORT_LEN,   LBC_FPORT_CS,   ppid);
}
static __attribute__((noinline)) void _vck_checks_b(pid_t ppid) {
    _LCKILL(LBC_ARTPATH_KHI, LBC_ARTPATH_KLO, LBC_ARTPATH_ENC, LBC_ARTPATH_LEN, LBC_ARTPATH_CS, ppid);
    _LCKILL(LBC_HOOKS_KHI,   LBC_HOOKS_KLO,   LBC_HOOKS_ENC,   LBC_HOOKS_LEN,   LBC_HOOKS_CS,   ppid);
    _LCKILL(LBC_METRICS_KHI, LBC_METRICS_KLO, LBC_METRICS_ENC, LBC_METRICS_LEN, LBC_METRICS_CS, ppid);
}
// Thin dispatcher — 2 BBs, easily VMP-virtualizable.
static __attribute__((noinline)) void vm_run_child_kill(pid_t parent_pid) {
    _vck_checks_a(parent_pid);
    _vck_checks_b(parent_pid);
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
// Both are XChaCha20-Poly1305 encrypted using the Guard key and domain-bound AAD.
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
    // Decode ".dex" and "classes" via XChaCha20-Poly1305 — no plaintext in .rodata.
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
#define STAMP_BUF_SZ      64

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

// ── detect_metrics_tamper — split into two sub-functions so each fits
// within VMP's basic-block budget (~20 BBs per function).
// Logic is IDENTICAL to the original monolithic function.

// Phase 1: open APK via svc #0, parse EOCD, scan CD, read manifest, compute
// FNV-1a64 hash.  Fills mhInfo/dcInfo/dex_count/hash_out on success.
// Returns open fd (caller must m_close it) or -1 on any error.
static __attribute__((noinline)) int _dmt_scan_and_hash(
        const char *apk_path,
        ZipEntryInfo *mhInfo_out, ZipEntryInfo *dcInfo_out,
        int *dex_count_out, uint64_t *hash_out) {

    int fd = m_openat(apk_path, O_RDONLY);
    if (fd < 0) { GLOGI("detect_metrics_tamper: openat failed errno=%d", errno); return -1; }

    uint32_t cd_offset = 0, cd_size = 0;
    if (!m_eocd(fd, &cd_offset, &cd_size)) {
        GLOGE("detect_metrics_tamper: EOCD not found"); m_close(fd); return -2;
    }

    char s_manifest[SP_BUF_SZ], s_metrics[SP_BUF_SZ], s_fidx[SP_BUF_SZ];
    reveal_ns(13u, SP_MANIFEST,       SP_MANIFEST_LEN,       s_manifest);
    reveal_ns(14u, SP_ASSET_A, SP_ASSET_A_LEN, s_metrics);
    reveal_ns(15u, SP_ASSET_B, SP_ASSET_B_LEN, s_fidx);

    ZipEntryInfo manifestInfo; memset(&manifestInfo, 0, sizeof(manifestInfo));
    *dex_count_out = 0;
    if (!m_scan_cd(fd, cd_offset, cd_size, s_manifest, &manifestInfo, dex_count_out, NULL)) {
        GLOGE("detect_metrics_tamper: CD scan failed"); m_close(fd); return -3;
    }
    if (!manifestInfo.found || manifestInfo.uncomp_size == 0 ||
        manifestInfo.uncomp_size > MANIFEST_BUF_SZ) {
        GLOGE("detect_metrics_tamper: manifest entry missing/invalid"); m_close(fd); return -4;
    }

    uint8_t *manifest = (uint8_t *)malloc(MANIFEST_BUF_SZ);
    if (!manifest) { m_close(fd); return -1; }
    uint32_t mlen = m_read_entry(fd, &manifestInfo, manifest, MANIFEST_BUF_SZ);
    if (!mlen) {
        GLOGE("detect_metrics_tamper: failed to read AndroidManifest.xml");
        free(manifest); m_close(fd); return -5;
    }
    *hash_out = fnv1a64(manifest, mlen);
    free(manifest);

    int dummy = 0;
    memset(mhInfo_out, 0, sizeof(*mhInfo_out));
    if (!m_scan_cd(fd, cd_offset, cd_size, s_metrics, mhInfo_out, &dummy, NULL) || !mhInfo_out->found) {
        GLOGE("detect_metrics_tamper: font_metrics.dat missing"); m_close(fd); return -6;
    }
    dummy = 0;
    memset(dcInfo_out, 0, sizeof(*dcInfo_out));
    if (!m_scan_cd(fd, cd_offset, cd_size, s_fidx, dcInfo_out, &dummy, NULL) || !dcInfo_out->found) {
        GLOGE("detect_metrics_tamper: font_index.dat missing"); m_close(fd); return -7;
    }
    return fd;
}

// Phase 2: read both stamp entries from the already-open fd, AES-decrypt,
// compare against computed_hash / dex_count.  Always closes fd.
// Returns 1 = tamper, 0 = clean.
static __attribute__((noinline)) int _dmt_verify_stamps(
        int fd,
        const ZipEntryInfo *mhInfo, const ZipEntryInfo *dcInfo,
        uint64_t computed_hash, int dex_count) {

    uint8_t mhCipher[STAMP_BUF_SZ], dcCipher[STAMP_BUF_SZ];
    uint32_t mhLen = m_read_entry(fd, mhInfo, mhCipher, STAMP_BUF_SZ);
    uint32_t dcLen = m_read_entry(fd, dcInfo, dcCipher, STAMP_BUF_SZ);
    m_close(fd);

    if (!mhLen || !dcLen) { GLOGE("detect_metrics_tamper: failed to read stamp entries"); return 1; }

    uint8_t key[32];
    build_key256(key);
    uint8_t mhPlain[STAMP_BUF_SZ], dcPlain[STAMP_BUF_SZ];
    int mhLen2 = gd_guard_decrypt_envelope(
            key, 0x06u, 0u, mhCipher, mhLen, mhPlain, sizeof(mhPlain)) ? (int)mhLen - 40 : -1;
    int dcLen2 = gd_guard_decrypt_envelope(
            key, 0x07u, 0u, dcCipher, dcLen, dcPlain, sizeof(dcPlain)) ? (int)dcLen - 40 : -1;
    memset(key, 0, 32);

    if (mhLen2 != 8 || dcLen2 != 4) {
        GLOGE("detect_metrics_tamper: decrypted stamp too short"); return 1;
    }

    uint64_t expected_hash;  memcpy(&expected_hash, mhPlain, 8);
    uint32_t expected_count; memcpy(&expected_count, dcPlain, 4);

    // Opt-out sentinel: (hash=0, count=0) means check disabled in settings
    if (expected_hash == 0ULL && expected_count == 0u) {
        GLOGI("detect_metrics_tamper: sentinel(0,0) — check disabled"); return 0;
    }

    if (expected_hash != computed_hash)        { GLOGE("detect_metrics_tamper: MANIFEST HASH MISMATCH"); return 1; }
    if (expected_count != (uint32_t)dex_count) { GLOGE("detect_metrics_tamper: DEX COUNT MISMATCH");     return 1; }
    GLOGI("detect_metrics_tamper: clean");
    return 0;
}

// Returns 1 if tamper detected, 0 if clean. Does NOT call crash_now() itself
// so the fork-based watchdog child can react via a direct kill() path instead.
// Thin orchestrator — 2 BBs, within VMP budget.
static __attribute__((noinline)) int detect_metrics_tamper(const char *apk_path) {
    GLOGI("detect_metrics_tamper: checking %s", apk_path);
    ZipEntryInfo mhInfo, dcInfo;
    int dex_count = 0; uint64_t computed_hash = 0;
    int fd = _dmt_scan_and_hash(apk_path, &mhInfo, &dcInfo, &dex_count, &computed_hash);
    if (fd < 0) return (fd == -1) ? 0 : 1; // -1 = transient, else hard fail
    return _dmt_verify_stamps(fd, &mhInfo, &dcInfo, computed_hash, dex_count);
}

// ════════════════════════════════════════════════════════════════════════════
// ── LAYER 3: Native .so self-integrity — FNV-1a64 hash of generated JNI .so
//
// At protect-time ApkProtector computes FNV-1a64 of the compiled user .so,
// XChaCha20-Poly1305 encrypts the 8-byte result (same Guard key and domain-bound nonce), and stores it
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

// ── detect_so_tamper — split into two sub-functions (same logic, VMP-sized).

// Phase 1: resolve lib name, open APK, parse EOCD, scan CD for .so entry and
// font_glyph.dat.  Returns open fd on success, -1/-2/... on failure.
// Fills soInfo_out and glInfo_out; also fills computed_hash_out.
static __attribute__((noinline)) int _dst_scan_and_hash(
        const char *apk_path,
        ZipEntryInfo *soInfo_out, ZipEntryInfo *glInfo_out,
        uint64_t *computed_out) {

    char lib_name[128] = {0};
    if (!so_find_user_lib_name(lib_name, sizeof(lib_name))) return -1; // still loading

    int fd = m_openat(apk_path, O_RDONLY);
    if (fd < 0) return -1; // transient

    uint32_t cd_offset = 0, cd_size = 0;
    if (!m_eocd(fd, &cd_offset, &cd_size)) { m_close(fd); return -2; }

    static const uint8_t _a64[] = {0xC7,0xC2,0xC9,0x84,0xCA,0xD9,0xC6,0x9D,0x9F,0x86,0xDD,0x93,0xCA,0x84,'\0'};
    static const uint8_t _a32[] = {0xC7,0xC2,0xC9,0x84,0xCA,0xD9,0xC6,0xCE,0xCA,0xC9,0xC2,0x86,0xDD,0x9C,0xCA,0x84,'\0'};
    char s64[20], s32[22], entry[196];
    _SX(s64, _a64, 0xAB); _SX(s32, _a32, 0xAB);

    memset(soInfo_out, 0, sizeof(*soInfo_out));
    int dummy = 0;
    snprintf(entry, sizeof(entry), "%s%s", s64, lib_name);
    if (!m_scan_cd(fd, cd_offset, cd_size, entry, soInfo_out, &dummy, NULL) || !soInfo_out->found) {
        soInfo_out->found = 0; dummy = 0;
        snprintf(entry, sizeof(entry), "%s%s", s32, lib_name);
        m_scan_cd(fd, cd_offset, cd_size, entry, soInfo_out, &dummy, NULL);
    }
    if (!soInfo_out->found || soInfo_out->uncomp_size == 0) {
        GLOGE("detect_so_tamper: user .so not found in APK"); m_close(fd); return -3;
    }

    uint8_t *so_buf = (uint8_t *)malloc(soInfo_out->uncomp_size);
    if (!so_buf) { m_close(fd); return -1; } // OOM transient
    uint32_t so_len = m_read_entry(fd, soInfo_out, so_buf, soInfo_out->uncomp_size);
    if (!so_len) { free(so_buf); m_close(fd); return -4; }
    *computed_out = fnv1a64(so_buf, so_len);
    free(so_buf);

    char s_glyph[SP_BUF_SZ];
    reveal(SP_ASSET_C, SP_ASSET_C_LEN, s_glyph);
    memset(glInfo_out, 0, sizeof(*glInfo_out));
    dummy = 0;
    if (!m_scan_cd(fd, cd_offset, cd_size, s_glyph, glInfo_out, &dummy, NULL) || !glInfo_out->found) {
        GLOGE("detect_so_tamper: font_glyph.dat MISSING"); m_close(fd); return -5;
    }
    return fd;
}

// Phase 2: read glyph stamp, AES-decrypt, compare vs computed hash.
// Always closes fd. Returns 1=tamper, 0=clean.
static __attribute__((noinline)) int _dst_verify_glyph(
        int fd, const ZipEntryInfo *glInfo, uint64_t computed) {

    uint8_t glCipher[STAMP_BUF_SZ];
    uint32_t glLen = m_read_entry(fd, glInfo, glCipher, STAMP_BUF_SZ);
    m_close(fd);
    if (!glLen) return 1;

    uint8_t key[32];
    build_key256(key);
    uint8_t glPlain[STAMP_BUF_SZ];
    int glPlainLen = gd_guard_decrypt_envelope(
            key, 0x08u, 0u, glCipher, glLen, glPlain, sizeof(glPlain)) ? (int)glLen - 40 : -1;
    memset(key, 0, 32);
    if (glPlainLen != 8) { GLOGE("detect_so_tamper: decrypt failed"); return 1; }

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

// Returns 1 = tamper/missing (→ crash), 0 = clean.
// MISSING font_glyph.dat always returns 1 — the asset is mandatory.
// Uses raw svc #0 — IO-redirect hooks installed by packer tools cannot
// intercept this. Any modification to the user's .so or font_glyph.dat
// is caught regardless of what tool made the change.
// Thin orchestrator — 2 BBs, within VMP budget.
static __attribute__((noinline)) int detect_so_tamper(const char *apk_path) {
    ZipEntryInfo soInfo, glInfo; uint64_t computed = 0;
    int fd = _dst_scan_and_hash(apk_path, &soInfo, &glInfo, &computed);
    if (fd < 0) return (fd == -1) ? 0 : 1; // -1 = transient skip, else hard fail
    return _dst_verify_glyph(fd, &glInfo, computed);
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
// .DSA / .EC) is XChaCha20-Poly1305 encrypted with the existing Guard key and domain-bound nonce and the
// ciphertext is compiled into the final protected native library. The encrypted
// disabled sentinel is retained for the optional Settings toggle; there is no
// APK signer asset.
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

// ── §2  Offline Android Keystore hardware-key continuity ────────────────────
//
// This is deliberately local-only: it never sends an attestation certificate,
// challenge, device identity, or user data across the network.  On a supported
// device the AndroidKeyStore provider creates a P-256 key whose private half is
// non-exportable; KeyInfo is then used to reject software-backed keys.  The
// certificate fingerprint and verified APK signer fingerprint are stored
// together in app-private preferences so a deleted/substituted alias or changed
// APK signer is detected on later guarded starts.
//
// Android's attestation extension is requested at key generation time, matching
// the real KeyGenParameterSpec flow used by the supplied reference.  Offline
// code cannot act as an independent remote attestation verifier, so this layer
// is intentionally a hardware-backed *continuity* signal in addition to the
// existing raw-APK signer/integrity checks.

static __attribute__((noinline)) bool tee_pending(JNIEnv *env) {
    if (env && env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    return false;
}

// ── Android Key Attestation verifier ─────────────────────────────────────────
// Native policy/DER verification for the Google Key Attestation extension.
// Java's X509Certificate implementation is used only for cryptographic
// certificate-signature checks because the NDK build intentionally has no
// public libcrypto/X509 dependency to link against.

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} att_der_reader_t;

typedef struct {
    uint8_t cls;
    uint8_t constructed;
    uint32_t number;
    const uint8_t *value;
    size_t length;
} att_der_tlv_t;

static __attribute__((noinline)) bool att_der_next(
        att_der_reader_t *r, att_der_tlv_t *out) {
    if (!r || !out || r->p >= r->end) return false;
    const uint8_t first = *r->p++;
    out->cls = (uint8_t)(first >> 6);
    out->constructed = (first & 0x20) != 0;
    uint32_t number = first & 0x1f;
    if (number == 0x1f) {
        number = 0;
        int count = 0;
        uint8_t b;
        do {
            if (r->p >= r->end || count++ >= 5) return false;
            b = *r->p++;
            if (number > (UINT32_MAX >> 7)) return false;
            number = (number << 7) | (b & 0x7f);
        } while (b & 0x80);
    }
    if (r->p >= r->end) return false;
    uint8_t lb = *r->p++;
    size_t len = 0;
    if (!(lb & 0x80)) {
        len = lb;
    } else {
        const int bytes = lb & 0x7f;
        if (bytes == 0 || bytes > 4 || (size_t)(r->end - r->p) < (size_t)bytes)
            return false;
        for (int i = 0; i < bytes; ++i) len = (len << 8) | *r->p++;
    }
    if ((size_t)(r->end - r->p) < len) return false;
    out->number = number;
    out->value = r->p;
    out->length = len;
    r->p += len;
    return true;
}

static __attribute__((noinline)) bool att_der_int(
        const att_der_tlv_t *tlv, int *out) {
    if (!tlv || !out || tlv->cls != 0 ||
            (tlv->number != 2 && tlv->number != 10) ||
            !tlv->length || tlv->length > 4 || (tlv->value[0] & 0x80))
        return false;
    int value = 0;
    for (size_t i = 0; i < tlv->length; ++i) value = (value << 8) | tlv->value[i];
    *out = value;
    return true;
}

static __attribute__((noinline)) bool att_der_find_context(
        const uint8_t *data, size_t len, uint32_t wanted,
        const uint8_t **value, size_t *value_len) {
    att_der_reader_t r = {data, data + len};
    att_der_tlv_t tlv;
    while (att_der_next(&r, &tlv)) {
        if (tlv.cls == 2 && tlv.number == wanted) {
            if (value) *value = tlv.value;
            if (value_len) *value_len = tlv.length;
            return true;
        }
    }
    return false;
}

static __attribute__((noinline)) bool att_der_contains_octet(
        const uint8_t *data, size_t len, const uint8_t *wanted,
        size_t wanted_len, int depth) {
    if (!data || !wanted || depth > 10) return false;
    att_der_reader_t r = {data, data + len};
    att_der_tlv_t tlv;
    while (att_der_next(&r, &tlv)) {
        if (tlv.cls == 0 && tlv.number == 4) {
            if (tlv.length == wanted_len &&
                    memcmp(tlv.value, wanted, wanted_len) == 0)
                return true;
            // Tag 709 contains an OCTET STRING whose payload is itself the
            // DER-encoded AttestationApplicationId structure.
            if (att_der_contains_octet(
                    tlv.value, tlv.length, wanted, wanted_len, depth + 1))
                return true;
        }
        if (tlv.constructed &&
                att_der_contains_octet(tlv.value, tlv.length, wanted, wanted_len, depth + 1))
            return true;
    }
    return false;
}

static __attribute__((noinline)) bool att_parse_root_of_trust(
        const uint8_t *data, size_t len) {
    att_der_reader_t outer = {data, data + len};
    att_der_tlv_t seq;
    if (!att_der_next(&outer, &seq) || outer.p != outer.end ||
            seq.cls != 0 || seq.number != 16 || !seq.constructed)
        return false;
    att_der_reader_t r = {seq.value, seq.value + seq.length};
    att_der_tlv_t boot_key, lock_field, state_field, boot_hash;
    // RootOfTrust ::= SEQUENCE {
    //   verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
    //   verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING
    // }
    if (!att_der_next(&r, &boot_key) || boot_key.cls != 0 || boot_key.number != 4 ||
            !att_der_next(&r, &lock_field) || lock_field.cls != 0 ||
            lock_field.number != 1 || lock_field.length != 1 ||
            !att_der_next(&r, &state_field) ||
            !att_der_next(&r, &boot_hash) || boot_hash.cls != 0 ||
            boot_hash.number != 4 || r.p != r.end)
        return false;
    int ignored_state = -1;
    if (!att_der_int(&state_field, &ignored_state)) return false;
    return true;
}

static __attribute__((noinline)) bool att_parse_key_description(
        const uint8_t *extension, size_t extension_len,
        const uint8_t *expected_challenge, size_t expected_challenge_len,
        const uint8_t signer_hash[32]) {
    att_der_reader_t outer = {extension, extension + extension_len};
    att_der_tlv_t octets, key_desc;
    if (!att_der_next(&outer, &octets) || outer.p != outer.end ||
            octets.cls != 0 || octets.number != 4) {
        TEE_DIAG("attestation-reject=key-description-outer");
        return false;
    }
    att_der_reader_t inner = {octets.value, octets.value + octets.length};
    if (!att_der_next(&inner, &key_desc) || inner.p != inner.end ||
            key_desc.cls != 0 || key_desc.number != 16 || !key_desc.constructed) {
        TEE_DIAG("attestation-reject=key-description-sequence");
        return false;
    }
    att_der_reader_t fields = {key_desc.value, key_desc.value + key_desc.length};
    att_der_tlv_t f[8];
    for (int i = 0; i < 8; ++i) {
        if (!att_der_next(&fields, &f[i])) {
            TEE_DIAG("attestation-reject=key-description-fields");
            return false;
        }
    }
    if (fields.p != fields.end || f[1].cls != 0 || f[1].number != 10 ||
            f[3].cls != 0 || f[3].number != 10 ||
            f[4].cls != 0 || f[4].number != 4 ||
            f[6].cls != 0 || f[6].number != 16 ||
            f[7].cls != 0 || f[7].number != 16) {
        GLOGE("TEE: attestation extension rejected: invalid KeyDescription layout");
        TEE_DIAG("attestation-reject=key-description-layout");
        return false;
    }

    int attestation_level = -1, keymint_level = -1;
    if (!att_der_int(&f[1], &attestation_level) ||
            !att_der_int(&f[3], &keymint_level) ||
            attestation_level < 1 || keymint_level < 1 ||
            attestation_level != keymint_level) {
        GLOGE("TEE: attestation extension rejected: security levels attest=%d keymint=%d",
              attestation_level, keymint_level);
        TEE_DIAG("attestation-reject=security-level");
        return false; // 0 is SOFTWARE; 1=TEE, 2=STRONGBOX.
    }
    if (f[4].length != expected_challenge_len ||
            memcmp(f[4].value, expected_challenge, expected_challenge_len) != 0) {
        GLOGE("TEE: attestation extension rejected: signer-bound challenge mismatch");
        TEE_DIAG("attestation-reject=challenge-mismatch");
        return false;
    }

    const uint8_t *root_value = nullptr;
    size_t root_len = 0;
    if (!att_der_find_context(f[7].value, f[7].length, 704, &root_value, &root_len)) {
        GLOGE("TEE: attestation extension rejected: hardware RootOfTrust missing");
        TEE_DIAG("attestation-reject=root-of-trust-missing");
        return false;
    }
    if (!att_parse_root_of_trust(root_value, root_len)) {
        GLOGE("TEE: attestation extension rejected: malformed RootOfTrust");
        TEE_DIAG("attestation-reject=root-of-trust-malformed");
        return false;
    }
    // Validate RootOfTrust structure without making boot state part of the
    // signer decision. The signature-focused policy below binds the
    // attestation to the protected APK signer and package identity.
    TEE_DIAG("attestation RootOfTrust structure valid");

    // Android encodes the application signer digest under tag 709. Depending on
    // platform version it can be software- or hardware-enforced, so inspect both.
    const uint8_t *app_id = nullptr;
    size_t app_id_len = 0;
    bool app_id_found = att_der_find_context(
            f[6].value, f[6].length, 709, &app_id, &app_id_len);
    if (!app_id_found) app_id_found = att_der_find_context(
            f[7].value, f[7].length, 709, &app_id, &app_id_len);
    if (!app_id_found) {
        GLOGE("TEE: attestation extension rejected: application ID missing");
        TEE_DIAG("attestation-reject=application-id-missing");
        return false;
    }
    if (!att_der_contains_octet(app_id, app_id_len, signer_hash, 32, 0)) {
        GLOGE("TEE: attestation extension rejected: APK signer digest absent");
        TEE_DIAG("attestation-reject=apk-signer-digest");
        return false;
    }
    return true;
}

static const uint8_t ATT_GOOGLE_ROOT_SHA256[][32] = {
    {0xce,0xdb,0x1c,0xb6,0xdc,0x89,0x6a,0xe5,0xec,0x79,0x73,0x48,0xbc,0xe9,0x28,0x67,
     0x53,0xc2,0xb3,0x8e,0xe7,0x1c,0xe0,0xfb,0xe3,0x4a,0x9a,0x12,0x48,0x80,0x0d,0xfc},
    {0x6d,0x9d,0xb4,0xce,0x6c,0x5c,0x0b,0x29,0x31,0x66,0xd0,0x89,0x86,0xe0,0x57,0x74,
     0xa8,0x77,0x6c,0xeb,0x52,0x5d,0x9e,0x43,0x29,0x52,0x0d,0xe1,0x2b,0xa4,0xbc,0xc0},
};

static __attribute__((noinline)) bool tee_is_google_attestation_root(
        const uint8_t *encoded, size_t encoded_len) {
    uint8_t digest[32];
    sha256_buf(encoded, encoded_len, digest);
    bool match = false;
    for (size_t i = 0; i < sizeof(ATT_GOOGLE_ROOT_SHA256) / 32; ++i) {
        if (memcmp(digest, ATT_GOOGLE_ROOT_SHA256[i], 32) == 0) {
            match = true;
            break;
        }
    }
    memset(digest, 0, sizeof(digest));
    return match;
}

static __attribute__((noinline)) bool tee_verify_attestation_chain(
        JNIEnv *env, jobject keystore, jstring alias,
        const uint8_t *expected_challenge, size_t expected_challenge_len,
        const uint8_t signer_hash[32]) {
    if (!env || !keystore || !alias || !expected_challenge || !signer_hash ||
            env->PushLocalFrame(96) < 0)
        return false;
    bool ok = false;
    do {
        jclass keystore_cls = env->GetObjectClass(keystore);
        jmethodID get_chain = env->GetMethodID(
                keystore_cls, "getCertificateChain",
                "(Ljava/lang/String;)[Ljava/security/cert/Certificate;");
        if (!get_chain || tee_pending(env)) break;
        jobjectArray chain = (jobjectArray)env->CallObjectMethod(keystore, get_chain, alias);
        if (!chain || tee_pending(env)) break;
        const jsize count = env->GetArrayLength(chain);
        // A complete attestation path can legitimately be leaf + pinned root
        // with no intermediate certificate. Require a complete signed chain,
        // not an arbitrary three-certificate minimum.
        GLOGI("TEE: attestation certificate count=%d", (int)count);
        if (count < 2) {
            GLOGE("TEE: attestation chain rejected: missing trusted issuer");
        TEE_DIAG("attestation-reject=issuer-missing");
            break;
        }

        jclass x509_cls = env->FindClass("java/security/cert/X509Certificate");
        jclass cert_cls = env->FindClass("java/security/cert/Certificate");
        if (!x509_cls || !cert_cls || tee_pending(env)) break;
        jmethodID check_validity = env->GetMethodID(x509_cls, "checkValidity", "()V");
        jmethodID verify = env->GetMethodID(
                x509_cls, "verify", "(Ljava/security/PublicKey;)V");
        jmethodID get_extension = env->GetMethodID(
                x509_cls, "getExtensionValue", "(Ljava/lang/String;)[B");
        jmethodID get_public = env->GetMethodID(
                cert_cls, "getPublicKey", "()Ljava/security/PublicKey;");
        jmethodID get_encoded = env->GetMethodID(cert_cls, "getEncoded", "()[B");
        if (!check_validity || !verify || !get_extension || !get_public || !get_encoded ||
                tee_pending(env))
            break;

        jobject root = env->GetObjectArrayElement(chain, count - 1);
        if (!root || tee_pending(env)) break;
        jbyteArray root_encoded = (jbyteArray)env->CallObjectMethod(root, get_encoded);
        if (!root_encoded || tee_pending(env)) break;
        const jsize root_len = env->GetArrayLength(root_encoded);
        jbyte *root_bytes = env->GetByteArrayElements(root_encoded, nullptr);
        if (!root_bytes) break;
        const bool pinned_root = tee_is_google_attestation_root(
                (const uint8_t *)root_bytes, (size_t)root_len);
        env->ReleaseByteArrayElements(root_encoded, root_bytes, JNI_ABORT);
        if (!pinned_root) {
            GLOGE("TEE: attestation chain rejected: root is not pinned");
            TEE_DIAG("attestation-reject=root-not-pinned");
            break;
        }

        // Verify each non-root certificate's time validity and its signature
        // under the next certificate's public key. The pinned root is trusted
        // by exact DER SHA-256, not by an attacker-supplied subject name.
        bool chain_ok = true;
        for (jsize i = 0; i < count - 1; ++i) {
            jobject cert = env->GetObjectArrayElement(chain, i);
            jobject issuer = env->GetObjectArrayElement(chain, i + 1);
            if (!cert || !issuer || tee_pending(env)) { chain_ok = false; break; }
            env->CallVoidMethod(cert, check_validity);
            if (tee_pending(env)) { chain_ok = false; break; }
            jobject issuer_key = env->CallObjectMethod(issuer, get_public);
            if (!issuer_key || tee_pending(env)) { chain_ok = false; break; }
            env->CallVoidMethod(cert, verify, issuer_key);
            if (tee_pending(env)) { chain_ok = false; break; }
            if (i == count - 2) {
                jobject root_key = env->CallObjectMethod(root, get_public);
                if (!root_key || tee_pending(env)) { chain_ok = false; break; }
                env->CallVoidMethod(root, verify, root_key);
                if (tee_pending(env)) { chain_ok = false; break; }
            }
        }
        if (!chain_ok || tee_pending(env)) {
            GLOGE("TEE: attestation chain rejected: certificate signature or validity");
            TEE_DIAG("attestation-reject=certificate-chain");
            break;
        }

        jobject leaf = env->GetObjectArrayElement(chain, 0);
        jstring attestation_oid = env->NewStringUTF("1.3.6.1.4.1.11129.2.1.17");
        jbyteArray extension = (jbyteArray)env->CallObjectMethod(
                leaf, get_extension, attestation_oid);
        if (!extension || tee_pending(env)) {
            GLOGE("TEE: attestation chain rejected: leaf extension missing");
            TEE_DIAG("attestation-reject=leaf-extension-missing");
            break;
        }
        const jsize extension_len = env->GetArrayLength(extension);
        jbyte *extension_bytes = env->GetByteArrayElements(extension, nullptr);
        if (!extension_bytes) break;
        ok = att_parse_key_description(
                (const uint8_t *)extension_bytes, (size_t)extension_len,
                expected_challenge, expected_challenge_len, signer_hash);
        env->ReleaseByteArrayElements(extension, extension_bytes, JNI_ABORT);
        if (!ok) {
            GLOGE("TEE: attestation chain rejected: extension policy mismatch");
            TEE_DIAG("attestation-reject=extension-policy");
        }
    } while (false);
    env->PopLocalFrame(nullptr);
    GLOGI("TEE: Android Key Attestation chain %s", ok ? "passed" : "failed");
    return ok;
}

static __attribute__((noinline)) bool tee_generate_p256(
        JNIEnv *env, jstring alias, jbyteArray attestation_challenge) {
    GLOGI("TEE: key generation start hardware-tee-only=1");
    if (!env || !alias || !attestation_challenge || env->PushLocalFrame(64) < 0)
    {
        GLOGE("TEE: key generation setup failed hardware-tee-only=1");
        return false;
    }

    bool ok = false;
    do {
    jclass kpg_cls = env->FindClass("java/security/KeyPairGenerator");
    if (!kpg_cls || tee_pending(env)) break;
    jmethodID get_instance = env->GetStaticMethodID(
            kpg_cls, "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;");
    if (!get_instance || tee_pending(env)) break;
    jstring ec = env->NewStringUTF("EC");
    jstring provider = env->NewStringUTF("AndroidKeyStore");
    jobject generator = env->CallStaticObjectMethod(kpg_cls, get_instance, ec, provider);
    if (!generator || tee_pending(env)) break;

    jclass builder_cls = env->FindClass(
            "android/security/keystore/KeyGenParameterSpec$Builder");
    if (!builder_cls || tee_pending(env)) break;
    jmethodID ctor = env->GetMethodID(builder_cls, "<init>", "(Ljava/lang/String;I)V");
    if (!ctor || tee_pending(env)) break;
    const jint sign_and_verify = (1 << 2) | (1 << 3);
    jobject builder = env->NewObject(builder_cls, ctor, alias, sign_and_verify);
    if (!builder || tee_pending(env)) break;

    jmethodID set_digests = env->GetMethodID(
            builder_cls, "setDigests",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    if (!set_digests || tee_pending(env)) break;
    jclass string_cls = env->FindClass("java/lang/String");
    if (!string_cls || tee_pending(env)) break;
    jobjectArray digests = env->NewObjectArray(1, string_cls, nullptr);
    jstring sha256 = env->NewStringUTF("SHA-256");
    if (!digests || !sha256 || tee_pending(env)) break;
    env->SetObjectArrayElement(digests, 0, sha256);
    env->CallObjectMethod(builder, set_digests, digests);
    if (tee_pending(env)) break;

    jclass ec_spec_cls = env->FindClass("java/security/spec/ECGenParameterSpec");
    if (!ec_spec_cls || tee_pending(env)) break;
    jmethodID ec_spec_ctor = env->GetMethodID(ec_spec_cls, "<init>", "(Ljava/lang/String;)V");
    if (!ec_spec_ctor || tee_pending(env)) break;
    jstring p256 = env->NewStringUTF("secp256r1");
    jobject ec_spec = env->NewObject(ec_spec_cls, ec_spec_ctor, p256);
    if (!ec_spec || tee_pending(env)) break;
    jmethodID set_algorithm = env->GetMethodID(
            builder_cls, "setAlgorithmParameterSpec",
            "(Ljava/security/spec/AlgorithmParameterSpec;)"
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    if (!set_algorithm || tee_pending(env)) break;
    env->CallObjectMethod(builder, set_algorithm, ec_spec);
    if (tee_pending(env)) break;

    jmethodID set_challenge = env->GetMethodID(
            builder_cls, "setAttestationChallenge",
            "([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
    if (!set_challenge || tee_pending(env)) break;
    env->CallObjectMethod(builder, set_challenge, attestation_challenge);
    if (tee_pending(env)) break;

    jmethodID build = env->GetMethodID(
            builder_cls, "build", "()Landroid/security/keystore/KeyGenParameterSpec;");
    if (!build || tee_pending(env)) break;
    jobject spec = env->CallObjectMethod(builder, build);
    if (!spec || tee_pending(env)) break;
    jmethodID initialize = env->GetMethodID(
            kpg_cls, "initialize", "(Ljava/security/spec/AlgorithmParameterSpec;)V");
    if (!initialize || tee_pending(env)) break;
    env->CallVoidMethod(generator, initialize, spec);
    if (tee_pending(env)) break;
    jmethodID generate = env->GetMethodID(
            kpg_cls, "generateKeyPair", "()Ljava/security/KeyPair;");
    if (!generate || tee_pending(env)) break;
    jobject key_pair = env->CallObjectMethod(generator, generate);
    // Generate only through the normal Android Keystore hardware path. The
    // caller rejects the key below if the provider reports software backing.
    const bool generation_exception = tee_pending(env);
    ok = key_pair != nullptr && !generation_exception;

    } while (false);
    env->PopLocalFrame(nullptr);
    GLOGI("TEE: key generation %s hardware-tee-only=1",
          ok ? "passed" : "failed");
    return ok;
}

static __attribute__((noinline)) bool tee_key_is_hardware(
        JNIEnv *env, jobject private_key, jint sdk) {
    GLOGI("TEE: hardware-level check start sdk=%d", (int)sdk);
    if (!env || !private_key || env->PushLocalFrame(32) < 0) {
        GLOGE("TEE: hardware-level check setup failed");
        return false;
    }
    bool ok = false;
    do {
    jclass kf_cls = env->FindClass("java/security/KeyFactory");
    if (!kf_cls || tee_pending(env)) break;
    jmethodID get_instance = env->GetStaticMethodID(
            kf_cls, "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyFactory;");
    if (!get_instance || tee_pending(env)) break;
    jstring ec = env->NewStringUTF("EC");
    jstring provider = env->NewStringUTF("AndroidKeyStore");
    jobject key_factory = env->CallStaticObjectMethod(kf_cls, get_instance, ec, provider);
    if (!key_factory || tee_pending(env)) break;
    jclass info_cls = env->FindClass("android/security/keystore/KeyInfo");
    if (!info_cls || tee_pending(env)) break;
    jmethodID get_spec = env->GetMethodID(
            kf_cls, "getKeySpec",
            "(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;");
    if (!get_spec || tee_pending(env)) break;
    jobject info = env->CallObjectMethod(key_factory, get_spec, private_key, info_cls);
    if (!info || tee_pending(env)) break;

    if (sdk >= 31) {
        jmethodID get_level = env->GetMethodID(info_cls, "getSecurityLevel", "()I");
        if (!get_level || tee_pending(env)) break;
        const jint level = env->CallIntMethod(info, get_level);
        if (tee_pending(env)) break;
        // KeyProperties: SOFTWARE=0, TRUSTED_ENVIRONMENT=1, STRONGBOX=2.
        ok = level >= 1;
        GLOGI("TEE: KeyInfo securityLevel=%d hardware=%d",
              (int)level, ok ? 1 : 0);
    } else {
        jmethodID in_secure_hw = env->GetMethodID(
                info_cls, "isInsideSecureHardware", "()Z");
        if (!in_secure_hw || tee_pending(env)) break;
        ok = env->CallBooleanMethod(info, in_secure_hw) == JNI_TRUE && !tee_pending(env);
        GLOGI("TEE: KeyInfo insideSecureHardware=%d", ok ? 1 : 0);
    }

    } while (false);
    env->PopLocalFrame(nullptr);
    if (!ok) GLOGE("TEE: hardware-level check failed");
    return ok;
}

static __attribute__((noinline)) bool tee_sign_and_verify(
        JNIEnv *env, jobject private_key, jobject certificate, jbyteArray challenge) {
    GLOGI("TEE: fresh challenge sign/verify start");
    if (!env || !private_key || !certificate || !challenge || env->PushLocalFrame(48) < 0)
    {
        GLOGE("TEE: fresh challenge sign/verify setup failed");
        D2CG_ERROR("tee-signature-check=FAIL");
        return false;
    }
    bool ok = false;
    do {
    jclass signature_cls = env->FindClass("java/security/Signature");
    if (!signature_cls || tee_pending(env)) break;
    jmethodID get_instance = env->GetStaticMethodID(
            signature_cls, "getInstance", "(Ljava/lang/String;)Ljava/security/Signature;");
    if (!get_instance || tee_pending(env)) break;
    jstring ecdsa = env->NewStringUTF("SHA256withECDSA");
    jobject signer = env->CallStaticObjectMethod(signature_cls, get_instance, ecdsa);
    if (!signer || tee_pending(env)) break;
    jmethodID init_sign = env->GetMethodID(
            signature_cls, "initSign", "(Ljava/security/PrivateKey;)V");
    jmethodID update = env->GetMethodID(signature_cls, "update", "([B)V");
    jmethodID sign = env->GetMethodID(signature_cls, "sign", "()[B");
    if (!init_sign || !update || !sign || tee_pending(env)) break;
    env->CallVoidMethod(signer, init_sign, private_key);
    env->CallVoidMethod(signer, update, challenge);
    jbyteArray signature = (jbyteArray)env->CallObjectMethod(signer, sign);
    if (!signature || tee_pending(env)) break;

    jclass certificate_cls = env->GetObjectClass(certificate);
    if (!certificate_cls || tee_pending(env)) break;
    jmethodID get_public = env->GetMethodID(
            certificate_cls, "getPublicKey", "()Ljava/security/PublicKey;");
    if (!get_public || tee_pending(env)) break;
    jobject public_key = env->CallObjectMethod(certificate, get_public);
    if (!public_key || tee_pending(env)) break;
    jobject verifier = env->CallStaticObjectMethod(signature_cls, get_instance, ecdsa);
    if (!verifier || tee_pending(env)) break;
    jmethodID init_verify = env->GetMethodID(
            signature_cls, "initVerify", "(Ljava/security/PublicKey;)V");
    jmethodID verify = env->GetMethodID(signature_cls, "verify", "([B)Z");
    if (!init_verify || !verify || tee_pending(env)) break;
    env->CallVoidMethod(verifier, init_verify, public_key);
    env->CallVoidMethod(verifier, update, challenge);
    ok = env->CallBooleanMethod(verifier, verify, signature) == JNI_TRUE && !tee_pending(env);

    } while (false);
    env->PopLocalFrame(nullptr);
    GLOGI("TEE: fresh challenge sign/verify %s", ok ? "passed" : "failed");
    if (ok) {
        D2CG_INFO("tee-signature-check=PASS");
    } else {
        D2CG_ERROR("tee-signature-check=FAIL");
    }
    return ok;
}

/*
 * The Android Keystore namespace is not included in Auto Backup, but ordinary
 * SharedPreferences can be restored onto a different device.  Keeping the
 * continuity record in the app's no-backup directory prevents an old record
 * from being restored without its corresponding hardware key.
 *
 * Return values: 1 = matched/enrolled, 0 = no record, -1 = mismatch/error.
 * A pre-existing key is never enrolled silently: callers may use a matching
 * legacy record once to migrate existing protected installations.
 */
static __attribute__((noinline)) int tee_no_backup_continuity(
        JNIEnv *env, jobject context, const char *name, const char *expected,
        bool enroll_if_missing) {
    if (!env || !context || !name || !expected || env->PushLocalFrame(16) < 0)
        return -1;

    int result = -1;
    do {
        jclass context_cls = env->GetObjectClass(context);
        if (!context_cls || tee_pending(env)) break;
        jmethodID get_no_backup_dir = env->GetMethodID(
                context_cls, "getNoBackupFilesDir", "()Ljava/io/File;");
        if (!get_no_backup_dir || tee_pending(env)) break;
        jobject dir = env->CallObjectMethod(context, get_no_backup_dir);
        if (!dir || tee_pending(env)) break;
        jclass file_cls = env->GetObjectClass(dir);
        if (!file_cls || tee_pending(env)) break;
        jmethodID get_absolute_path = env->GetMethodID(
                file_cls, "getAbsolutePath", "()Ljava/lang/String;");
        if (!get_absolute_path || tee_pending(env)) break;
        jstring dir_path = (jstring)env->CallObjectMethod(dir, get_absolute_path);
        if (!dir_path || tee_pending(env)) break;
        const char *dir_utf = env->GetStringUTFChars(dir_path, nullptr);
        if (!dir_utf) break;

        char path[1024];
        const int path_len = snprintf(path, sizeof(path), "%s/.%s", dir_utf, name);
        env->ReleaseStringUTFChars(dir_path, dir_utf);
        if (path_len <= 0 || (size_t)path_len >= sizeof(path)) break;

        const size_t expected_len = strlen(expected);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char stored[160];
            ssize_t total = 0;
            while (total < (ssize_t)sizeof(stored)) {
                const ssize_t n = read(fd, stored + total, sizeof(stored) - (size_t)total);
                if (n == 0) break;
                if (n < 0) {
                    total = -1;
                    break;
                }
                total += n;
            }
            close(fd);
            if (total == (ssize_t)expected_len &&
                    memcmp(stored, expected, expected_len) == 0) {
                result = 1;
            }
            memset(stored, 0, sizeof(stored));
            break;
        }
        if (errno != ENOENT) break;
        if (!enroll_if_missing) {
            result = 0;
            break;
        }

        char temp_path[1088];
        const int temp_len = snprintf(
                temp_path, sizeof(temp_path), "%s.tmp.%ld", path, (long)getpid());
        if (temp_len <= 0 || (size_t)temp_len >= sizeof(temp_path)) break;
        fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (fd < 0) break;

        size_t written = 0;
        while (written < expected_len) {
            const ssize_t n = write(fd, expected + written, expected_len - written);
            if (n <= 0) break;
            written += (size_t)n;
        }
        const bool written_all = written == expected_len && fsync(fd) == 0;
        close(fd);
        if (!written_all) {
            unlink(temp_path);
            break;
        }
        if (rename(temp_path, path) != 0) {
            unlink(temp_path);
            break;
        }
        result = 1;
    } while (false);

    env->PopLocalFrame(nullptr);
    return result;
}

static __attribute__((noinline)) bool tee_legacy_continuity_matches(
        JNIEnv *env, jobject context, jclass context_cls, const char *legacy_key,
        const char *expected) {
    if (!env || !context || !context_cls || !legacy_key || !expected) return false;
    jmethodID get_prefs = env->GetMethodID(
            context_cls, "getSharedPreferences",
            "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    if (!get_prefs || tee_pending(env)) return false;
    G_DEC(s_prefs_name, G_PREFS_NAME);
    jstring prefs_name = env->NewStringUTF(s_prefs_name);
    memset(s_prefs_name, 0, sizeof(s_prefs_name));
    jstring continuity_key = env->NewStringUTF(legacy_key);
    if (!prefs_name || !continuity_key || tee_pending(env)) return false;
    jobject prefs = env->CallObjectMethod(context, get_prefs, prefs_name, 0);
    if (!prefs || tee_pending(env)) return false;
    jclass prefs_cls = env->GetObjectClass(prefs);
    if (!prefs_cls || tee_pending(env)) return false;
    jmethodID get_string = env->GetMethodID(
            prefs_cls, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!get_string || tee_pending(env)) return false;
    jstring stored = (jstring)env->CallObjectMethod(prefs, get_string, continuity_key, nullptr);
    if (!stored || tee_pending(env)) return false;
    const char *stored_utf = env->GetStringUTFChars(stored, nullptr);
    if (!stored_utf) return false;
    const bool matches = strcmp(stored_utf, expected) == 0;
    env->ReleaseStringUTFChars(stored, stored_utf);
    return matches;
}

static __attribute__((noinline)) int gvm_tee_key_check(JNIEnv *env, jobject context) {
    tee_evidence_reset();
    TEE_DIAG("collector start");
    GLOGI("TEE: guard begin");
    if (!env || !context || env->PushLocalFrame(96) < 0) {
        GLOGE("TEE: guard setup failed");
        TEE_DIAG("collector unsupported setup");
        tee_evidence_finish_collector();
        return TEE_CHECK_UNSUPPORTED;
    }
    // Start permissively: until a complete hardware-backed attestation chain
    // proves this device is compatible, Keystore API/provider differences must
    // not prevent the existing signer and integrity guards from protecting the
    // app. Once that proof succeeds, every later failure is a hard failure.
    int result = TEE_CHECK_UNSUPPORTED;
    const char *stage = "startup";
    do {
    jclass version_cls = env->FindClass("android/os/Build$VERSION");
    stage = "sdk";
    if (!version_cls || tee_pending(env)) break;
    jfieldID sdk_field = env->GetStaticFieldID(version_cls, "SDK_INT", "I");
    if (!sdk_field || tee_pending(env)) break;
    const jint sdk = env->GetStaticIntField(version_cls, sdk_field);
    if (tee_pending(env)) break;

    // KeyInfo and a usable attestation challenge start at API 24. Older
    // releases retain the normal signer/integrity guards and skip this optional
    // hardware-continuity layer.
    if (sdk < 24) {
        result = TEE_CHECK_UNSUPPORTED;
        break;
    }

    uint8_t expected_signer_hash[32];
    uint8_t signer_hash[32];
    memset(expected_signer_hash, 0, sizeof(expected_signer_hash));
    memset(signer_hash, 0, sizeof(signer_hash));
    stage = "protected-signer";
    if (!__atomic_load_n(&g_sig_expected_hash_ready, __ATOMIC_ACQUIRE)) {
        GLOGE("TEE: protected APK signer hash missing from LSIGCHK");
        TEE_DIAG("attestation-reject=signer-evidence-missing");
        result = TEE_CHECK_FAIL;
        break;
    }
    memcpy(expected_signer_hash, g_sig_expected_hash, sizeof(expected_signer_hash));
    memcpy(signer_hash, expected_signer_hash, sizeof(signer_hash));
    const bool installed_signer_ready =
            __atomic_load_n(&g_sig_verified_hash_ready, __ATOMIC_ACQUIRE);
    uint8_t verified_signer_hash[32];
    memset(verified_signer_hash, 0, sizeof(verified_signer_hash));
    if (installed_signer_ready) {
        memcpy(verified_signer_hash, g_sig_verified_hash, sizeof(verified_signer_hash));
    }
    const bool signer_bound = installed_signer_ready &&
            memcmp(expected_signer_hash, verified_signer_hash, sizeof(expected_signer_hash)) == 0;
    memset(expected_signer_hash, 0, sizeof(expected_signer_hash));
    memset(verified_signer_hash, 0, sizeof(verified_signer_hash));
    if (signer_bound) {
        tee_evidence_mark(TEE_EVIDENCE_SIGNER_BOUND);
        GLOGI("TEE: protected APK signer hash bound to hardware challenge");
    } else {
        // Keep collecting the hardware evidence using the protected developer
        // identity. The final VM aggregate rejects this launch, but executing
        // the TEE path makes a signer-only bypass insufficient to authorize it.
        GLOGE("TEE: protected and installed APK signer hashes differ");
        TEE_DIAG("attestation-reject=signer-evidence-conflict");
    }

    stage = "package";
    jclass context_cls = env->GetObjectClass(context);
    if (!context_cls || tee_pending(env)) break;
    jmethodID get_package = env->GetMethodID(
            context_cls, "getPackageName", "()Ljava/lang/String;");
    if (!get_package || tee_pending(env)) break;
    jstring package_name = (jstring)env->CallObjectMethod(context, get_package);
    if (!package_name || tee_pending(env)) break;
    const char *package_utf = env->GetStringUTFChars(package_name, nullptr);
    if (!package_utf) break;
    uint8_t package_hash[32];
    sha256_buf((const uint8_t *)package_utf, strlen(package_utf), package_hash);
    env->ReleaseStringUTFChars(package_name, package_utf);

    char alias_buf[48] = {0};
    char pref_key_buf[48] = {0};
    G_DEC(s_alias_prefix, G_ALIAS_PREFIX);
    G_DEC(s_pref_key_prefix, G_PREF_KEY_PREFIX);
    memcpy(alias_buf, s_alias_prefix, sizeof(G_ALIAS_PREFIX));
    memcpy(pref_key_buf, s_pref_key_prefix, sizeof(G_PREF_KEY_PREFIX));
    memset(s_alias_prefix, 0, sizeof(s_alias_prefix));
    memset(s_pref_key_prefix, 0, sizeof(s_pref_key_prefix));
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        alias_buf[5 + i * 2] = hex[(package_hash[i] >> 4) & 0x0f];
        alias_buf[6 + i * 2] = hex[package_hash[i] & 0x0f];
        pref_key_buf[5 + i * 2] = hex[(package_hash[i + 16] >> 4) & 0x0f];
        pref_key_buf[6 + i * 2] = hex[package_hash[i + 16] & 0x0f];
    }
    alias_buf[37] = '\0';
    pref_key_buf[37] = '\0';

    // This stable binding is embedded in the Android Key Attestation
    // certificate at key creation and validated on every later launch. It is
    // intentionally different from the fresh possession-signature challenge.
    static const uint8_t attestation_label[] = {
        'd','2','c','g','-','a','t','t','e','s','t','-','v','1'
    };
    uint8_t attestation_binding[32];
    SHA256Ctx bind_ctx;
    sha256_init(&bind_ctx);
    sha256_update(&bind_ctx, attestation_label, sizeof(attestation_label));
    sha256_update(&bind_ctx, signer_hash, sizeof(signer_hash));
    sha256_update(&bind_ctx, package_hash, sizeof(package_hash));
    sha256_final(&bind_ctx, attestation_binding);
    memset(package_hash, 0, sizeof(package_hash));

    jstring alias = env->NewStringUTF(alias_buf);
    stage = "keystore";
    if (!alias || tee_pending(env)) break;
    jclass keystore_cls = env->FindClass("java/security/KeyStore");
    if (!keystore_cls || tee_pending(env)) break;
    jmethodID ks_get_instance = env->GetStaticMethodID(
            keystore_cls, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;");
    if (!ks_get_instance || tee_pending(env)) break;
    jstring android_keystore = env->NewStringUTF("AndroidKeyStore");
    jobject keystore = env->CallStaticObjectMethod(
            keystore_cls, ks_get_instance, android_keystore);
    if (!keystore || tee_pending(env)) break;
    jmethodID ks_load = env->GetMethodID(
            keystore_cls, "load", "(Ljava/io/InputStream;[C)V");
    if (!ks_load || tee_pending(env)) break;
    env->CallVoidMethod(keystore, ks_load, nullptr, nullptr);
    if (tee_pending(env)) break;
    jmethodID contains_alias = env->GetMethodID(
            keystore_cls, "containsAlias", "(Ljava/lang/String;)Z");
    if (!contains_alias || tee_pending(env)) break;

    jclass random_cls = env->FindClass("java/security/SecureRandom");
    if (!random_cls || tee_pending(env)) break;
    jmethodID random_ctor = env->GetMethodID(random_cls, "<init>", "()V");
    jmethodID next_bytes = env->GetMethodID(random_cls, "nextBytes", "([B)V");
    if (!random_ctor || !next_bytes || tee_pending(env)) break;
    jobject random = env->NewObject(random_cls, random_ctor);
    // First half is fresh entropy; second half is the protected developer
    // signer SHA-256. Android's attested application identity independently
    // proves whether the installed signer matches that protected identity.
    jbyteArray sign_challenge = env->NewByteArray(64);
    jbyteArray attestation_challenge = env->NewByteArray(32);
    stage = "random";
    if (!random || !sign_challenge || !attestation_challenge || tee_pending(env)) break;
    env->CallVoidMethod(random, next_bytes, sign_challenge);
    if (tee_pending(env)) break;
    env->SetByteArrayRegion(sign_challenge, 32, 32, (const jbyte *)signer_hash);
    env->SetByteArrayRegion(
            attestation_challenge, 0, 32, (const jbyte *)attestation_binding);
    if (tee_pending(env)) break;
    tee_evidence_mark(TEE_EVIDENCE_CHALLENGE_FRESH);

    const bool key_existed = env->CallBooleanMethod(keystore, contains_alias, alias) == JNI_TRUE;
    if (tee_pending(env)) break;
    if (!key_existed) {
        stage = "key-generation";
        // Deliberately request the normal Android Keystore hardware path only.
        // KeyInfo below still rejects any software-backed result.
        const bool generated = tee_generate_p256(
                env, alias, attestation_challenge);
        if (!generated) break;
        GLOGI("TEE: new Android Keystore key created");
    } else if (tee_pending(env)) {
        break;
    } else {
        GLOGI("TEE: existing Android Keystore key loaded");
    }

    stage = "key-load";
    jmethodID get_key = env->GetMethodID(
            keystore_cls, "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;");
    jmethodID get_certificate = env->GetMethodID(
            keystore_cls, "getCertificate", "(Ljava/lang/String;)Ljava/security/cert/Certificate;");
    if (!get_key || !get_certificate || tee_pending(env)) break;
    jobject private_key = env->CallObjectMethod(keystore, get_key, alias, nullptr);
    jobject certificate = env->CallObjectMethod(keystore, get_certificate, alias);
    if (!private_key || !certificate || tee_pending(env)) break;
    stage = "hardware-level";
    if (!tee_key_is_hardware(env, private_key, sdk)) break;
    tee_evidence_mark(TEE_EVIDENCE_HARDWARE_KEY);
    TEE_DIAG("collector hardware-backed");
    GLOGI("TEE: hardware-backed key accepted");

    stage = "attestation-chain";
    if (!tee_verify_attestation_chain(
            env, keystore, alias, attestation_binding,
            sizeof(attestation_binding), signer_hash))
        break;
    tee_evidence_mark(TEE_EVIDENCE_ATTESTED);
    g_tee_evidence_supported = 1u;
    TEE_DIAG("collector attested");

    // From this point onward the device has demonstrated a complete compatible
    // hardware-backed attestation path. A later error means a key continuity,
    // certificate, or signing failure rather than an unsupported phone.
    result = TEE_CHECK_FAIL;

    stage = "certificate";
    jclass certificate_cls = env->GetObjectClass(certificate);
    if (!certificate_cls || tee_pending(env)) break;
    jmethodID get_encoded = env->GetMethodID(certificate_cls, "getEncoded", "()[B");
    if (!get_encoded || tee_pending(env)) break;
    jbyteArray encoded_cert = (jbyteArray)env->CallObjectMethod(certificate, get_encoded);
    if (!encoded_cert || tee_pending(env)) break;
    const jsize encoded_len = env->GetArrayLength(encoded_cert);
    if (encoded_len <= 0 || tee_pending(env)) break;
    jbyte *encoded_bytes = env->GetByteArrayElements(encoded_cert, nullptr);
    if (!encoded_bytes) break;
    uint8_t cert_hash[32];
    sha256_buf((const uint8_t *)encoded_bytes, (size_t)encoded_len, cert_hash);
    env->ReleaseByteArrayElements(encoded_cert, encoded_bytes, JNI_ABORT);
    char cert_hex[65];
    for (int i = 0; i < 32; ++i) {
        cert_hex[i * 2] = hex[(cert_hash[i] >> 4) & 0x0f];
        cert_hex[i * 2 + 1] = hex[cert_hash[i] & 0x0f];
    }
    cert_hex[64] = '\0';
    char signer_hex[65];
    for (int i = 0; i < 32; ++i) {
        signer_hex[i * 2] = hex[(signer_hash[i] >> 4) & 0x0f];
        signer_hex[i * 2 + 1] = hex[signer_hash[i] & 0x0f];
    }
    signer_hex[64] = '\0';
    char binding_hex[130];
    memcpy(binding_hex, cert_hex, 64);
    binding_hex[64] = ':';
    memcpy(binding_hex + 65, signer_hex, 64);
    binding_hex[129] = '\0';
    memset(cert_hash, 0, sizeof(cert_hash));

    // Prove the freshly constructed challenge (random bytes + verified APK
    // signer SHA-256) before accepting or enrolling any local binding.
    stage = "fresh-signature";
    if (!tee_sign_and_verify(env, private_key, certificate, sign_challenge)) break;
    tee_evidence_mark(TEE_EVIDENCE_SIGNATURE_VALID);

    stage = "continuity";
    int continuity = tee_no_backup_continuity(
            env, context, pref_key_buf, binding_hex, !key_existed);
    if (continuity == 0) {
        // A protected APK created by an earlier version kept this value in
        // SharedPreferences. Migrate exactly one matching legacy value; do not
        // accept a missing or mismatched record for an already-existing key.
        if (!tee_legacy_continuity_matches(
                env, context, context_cls, pref_key_buf, binding_hex)) break;
        continuity = tee_no_backup_continuity(
                env, context, pref_key_buf, binding_hex, true);
    }
    if (continuity != 1) break;
    tee_evidence_mark(TEE_EVIDENCE_CONTINUITY);
    GLOGI("TEE: no-backup certificate + APK signer continuity matched");

    result = TEE_CHECK_PASS;
    GLOGI("TEE: guard PASS");

    } while (false);
    env->PopLocalFrame(nullptr);
    tee_evidence_finish_collector();
    TEE_DIAG("collector result=%d supported=%d evidence=0x%02x stage=%s",
             result, (int)g_tee_evidence_supported,
             (unsigned)g_tee_evidence_mask, stage);
    if (result) GLOGE("TEE: guard FAIL stage=%s", stage);
    return result;
}

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
// ── detect_sig_tamper — split into two sub-functions (same logic, VMP-sized).

// Phase 1: pre-check bypass tools, open APK, parse EOCD, and scan the central
// directory for the signing certificate entry. The expected digest is supplied
// by compiled native code, not by the APK. Returns open fd on success, negative
// on failure. Fills certInfo_out.
static __attribute__((noinline)) int _dsig_open_and_scan(
        const char *apk_path,
         ZipEntryInfo *certInfo_out) {

    if (g_sig_maps_scan()) return -10; // bypass tool found → hard fail

    int fd = g_sig_openat(apk_path, O_RDONLY);
    if (fd < 0) { GLOGE("D2CG sig: openat errno=%d", errno); return -1; }

    uint32_t cd_off = 0, cd_sz = 0;
    if (!g_sig_eocd(fd, &cd_off, &cd_sz)) {
        GLOGE("D2CG sig: no EOCD"); g_sig_close(fd); return -1;
    }

    uint8_t *cd = (uint8_t *)malloc(cd_sz ? cd_sz : 1);
    if (!cd) { g_sig_close(fd); return -1; }
    if (cd_sz > 0) {
        ssize_t rd = g_sig_pread(fd, cd, cd_sz, (off_t)cd_off);
        if (rd != (ssize_t)cd_sz) { free(cd); g_sig_close(fd); return -1; }
    }

    G_DEC(s_mi,   _enc_mi);
    G_DEC(s_rsa,  _enc_rsa);
    G_DEC(s_dsa,  _enc_dsa);
    G_DEC(s_ec,   _enc_ec);

    memset(certInfo_out, 0, sizeof(*certInfo_out));
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

        if (!certInfo_out->found && strncmp(ename, s_mi, 9) == 0) {
            size_t L = strlen(ename);
            int is_cert = (L > 4 && strcmp(ename + L - 4, s_rsa) == 0)
                        ||(L > 4 && strcmp(ename + L - 4, s_dsa) == 0)
                        ||(L > 3 && strcmp(ename + L - 3, s_ec)  == 0);
            if (is_cert) {
                certInfo_out->method=method; certInfo_out->comp_size=comp_sz;
                certInfo_out->uncomp_size=uncomp_sz; certInfo_out->local_offset=local_off;
                certInfo_out->found=1;
            }
        }
        if (certInfo_out->found) break;
        p += 46 + name_len + extra_len + comm_len;
    }
    free(cd);

    return fd;
}

// Phase 2: read and authenticate the compiled XChaCha20-Poly1305 envelope,
// guard path, then compare it with the installed certificate entry.
// Always closes fd. Returns 1=tamper, 0=clean.
static __attribute__((noinline)) int _dsig_read_and_verify(
        int fd, const ZipEntryInfo *certInfo) {

    uint8_t expected_cipher[72];
    memset(expected_cipher, 0, sizeof(expected_cipher));
    if (!__atomic_load_n(&g_sig_cipher_ready, __ATOMIC_ACQUIRE)) {
        GLOGE("D2CG sig: signer payload was not loaded by LSIGCHK");
        g_sig_close(fd);
        memset(expected_cipher, 0, sizeof(expected_cipher));
        return 1;
    }
    memcpy(expected_cipher, g_sig_cipher, sizeof(expected_cipher));
    memset(g_sig_cipher, 0, sizeof(g_sig_cipher));
    __atomic_store_n(&g_sig_cipher_ready, 0, __ATOMIC_RELEASE);

    uint8_t key[32], expected_plain[64];
    build_key256(key);
    int expected_len = gd_guard_decrypt_envelope(
            key, 0x09u, 0u, expected_cipher, sizeof(expected_cipher),
            expected_plain, sizeof(expected_plain)) ? 32 : -1;
    memset(key, 0, sizeof(key));
    memset(expected_cipher, 0, sizeof(expected_cipher));
    if (expected_len != 32) {
        GLOGE("D2CG sig: compiled native signer ciphertext decrypt failed");
        memset(expected_plain, 0, sizeof(expected_plain));
        g_sig_close(fd);
        return 1;
    }

    uint8_t expected_hash[32];
    int expected_allzero = 1;
    for (int i = 0; i < 32; ++i) {
        if (expected_plain[i] != 0) { expected_allzero = 0; break; }
    }
    if (expected_allzero) {
        // Signature verification is an explicit user setting. The gate still
        // executes, but an all-zero payload means "pass without signer check".
        __atomic_store_n(&g_sig_gate_complete, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&g_sig_gate_result, 0, __ATOMIC_RELEASE);
        memset(expected_plain, 0, sizeof(expected_plain));
        g_sig_close(fd);
        return 0;
    }
    memcpy(expected_hash, expected_plain, sizeof(expected_hash));
    memset(expected_plain, 0, sizeof(expected_plain));

    uint8_t *cert_buf = NULL; uint32_t cert_len = 0;
    if (certInfo->found && certInfo->uncomp_size > 0 && certInfo->uncomp_size <= 65536) {
        cert_buf = (uint8_t *)malloc(certInfo->uncomp_size + 16);
        if (cert_buf) {
            cert_len = g_sig_read_entry(fd, certInfo, cert_buf, certInfo->uncomp_size + 16);
            if (!cert_len) { memset(cert_buf, 0, certInfo->uncomp_size + 16); free(cert_buf); cert_buf = NULL; }
        }
    }
    g_sig_close(fd);

    memcpy(g_sig_expected_hash, expected_hash, sizeof(g_sig_expected_hash));
    __atomic_store_n(&g_sig_expected_hash_ready, 1, __ATOMIC_RELEASE);

    if (!cert_buf || cert_len == 0) {
        GLOGE("D2CG sig: no META-INF cert entry (V1 sig absent or stripped)");
        if (cert_buf) { memset(cert_buf, 0, certInfo->uncomp_size + 16); free(cert_buf); }
        memset(expected_hash, 0, sizeof(expected_hash));
        return 1;
    }

    uint8_t computed[32];
    uint32_t x509_len = 0;
    const uint8_t *x509 = g_sig_pkcs7_extract_cert(cert_buf, cert_len, &x509_len);
    if (x509 && x509_len > 0) {
        sha256_buf(x509, x509_len, computed);
    } else {
        sha256_buf(cert_buf, cert_len, computed);
    }
    memset(cert_buf, 0, certInfo->uncomp_size + 16); free(cert_buf);

    if (memcmp(computed, expected_hash, 32) != 0) {
        GLOGE("D2CG sig: HASH MISMATCH — re-signed or spoofed");
        memset(expected_hash, 0, sizeof(expected_hash));
        return 1;
    }
    memset(expected_hash, 0, sizeof(expected_hash));
    memcpy(g_sig_verified_hash, computed, sizeof(g_sig_verified_hash));
    __atomic_store_n(&g_sig_verified_hash_ready, 1, __ATOMIC_RELEASE);
    GLOGI("D2CG sig: certificate verified OK");
    return 0;
}

// Thin orchestrator — 2 BBs, within VMP budget.
static __attribute__((noinline)) int detect_sig_tamper(const char *apk_path) {
    ZipEntryInfo certInfo;
    int fd = _dsig_open_and_scan(apk_path, &certInfo);
    if (fd < 0) return (fd == -1) ? 0 : 1; // -1=transient skip, -10/-11=hard fail
    return _dsig_read_and_verify(fd, &certInfo);
}

// Wrapper with APK-path resolution — same shape as gvm_so_integrity()
static __attribute__((noinline)) int gvm_sig_check(void) {
    __atomic_store_n(&g_sig_expected_hash_ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_sig_verified_hash_ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_sig_gate_complete, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_sig_gate_result, 1, __ATOMIC_RELEASE);
    memset(g_sig_expected_hash, 0, sizeof(g_sig_expected_hash));
    memset(g_sig_verified_hash, 0, sizeof(g_sig_verified_hash));
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) {
        D2CG_ERROR("apk-signer-check=UNAVAILABLE");
        __atomic_store_n(&g_sig_gate_complete, 1, __ATOMIC_RELEASE);
        return 1;
    }
    const int result = detect_sig_tamper(apk_path);
    if (result) {
        D2CG_ERROR("apk-signer-check=FAIL result=%d", result);
    } else {
        D2CG_INFO("apk-signer-check=PASS");
    }
    __atomic_store_n(&g_sig_gate_result, result ? 1 : 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_sig_gate_complete, 1, __ATOMIC_RELEASE);
    return result;
}

// ── VM gate forward declarations ──────────────────────────────────────────────
static D2C_AMICE_VMP void vm_gate_mapscan(void);
static D2C_AMICE_VMP void vm_gate_vccheck(void);
static D2C_AMICE_VMP void vm_gate_so_integrity(void);
static D2C_AMICE_VMP void vm_gate_sigcheck(JNIEnv *env);
static D2C_AMICE_VMP void vm_gate_hwkey(const tee_ctx_t *c);
static D2C_AMICE_VMP void vm_gate_antik(const antik_ctx_t *c);

// ════════════════════════════════════════════════════════════════════════════
// Constructor — runs when .so loads, before JNI_OnLoad, before any Java code
// ════════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void d2c_boot(void) {
    GLOGI("startup[0]: constructor entry");

    // ARM64 disassembly of fonts_init() shows ONLY seven opaque indirect VM
    // calls and two process/thread spawns — zero named security functions,
    // zero cbnz branches, zero crash_now() call sites, zero direct bl targets.
    // All detection AND kill decisions live inside XChaCha20-Poly1305 encrypted lvm_exec
    // programs dispatched through g_lvm_dispatch (volatile fn ptr → blr xN):
    //   vm_run_mapscan()       → LMAPSCAN  DPatch/libpandora map scan (FIRST)
    //   vm_run_vccheck()       → LVCFULL   VCore/VirtualApp (APK path internally)
    //   vm_run_startup()       → LMETRICS  manifest hash + dex count integrity
    //   vm_run_so_integrity()  → LSOINT    .so self-integrity (crash inside VM)
    //   vm_run_sigcheck()      → LSIGCHK   sig cert hash (Layer 4, svc #0 I/O)
    //   vm_run()               → TRACER + FMAPS + FPORT + ARTPATH + HOOKMAPS
    //   spawn_background_watch() → vm_run_child_kill() — forked 5-s poll child
    // DPatch/libpandora — FIRST, before any hook can redirect fopen/openat.
    // No bl _cipher_map_layout_scan, no cbnz, no crash_now in ARM disasm.
    GLOGI("startup[1]: map-scan begin");
    vm_gate_mapscan();
    GLOGI("startup[1]: map-scan passed");
    GLOGI("startup[2]: virtual-container check begin");
    vm_gate_vccheck();
    GLOGI("startup[2]: virtual-container check passed");
    GLOGI("startup[3]: APK metrics check begin");
    vm_run_startup();
    GLOGI("startup[3]: APK metrics check passed");
    // Layer 3: SO self-integrity — opaque VM call, crash decision inside lvm_exec.
    // No cbnz branch here; no gvm_so_integrity or crash_now visible in ARM disasm.
    GLOGI("startup[4]: native integrity check begin");
    vm_gate_so_integrity();
    GLOGI("startup[4]: native integrity check passed");
    // The signer gate requires generated VMP registrations and a live JNIEnv, so
    // it runs from the JNI retry stage instead of this pre-Java constructor.
    GLOGI("startup[5]: native environment checks begin");
    vm_run();
    GLOGI("startup[5]: native environment checks passed");

    GLOGI("startup[6]: launching background watchdogs");
    spawn_background_watch();
    pthread_t wdt;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int wdt_rc = pthread_create(&wdt, &attr, watchdog_thread, NULL);
    pthread_attr_destroy(&attr);
    GLOGI("startup[6]: constructor complete watchdog_rc=%d", wdt_rc);
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
// XChaCha20-Poly1305 + XOR 0x5A encrypted — nothing here is plaintext in .rodata.
static const uint8_t BC1[] = {0x6d,0x6c,0x4a,0xd1,0xda,0xc4,0x86,0x44,0xcf,0xe7,0x0b,0xd6,0x5a,0x55,0x64,0x52,0x2d,0x36,0x78,0x22,0x68,0xfe,0xc7,0xaf,0x13,0x47,0xb2,0x89,0x4e,0x1d,0x43,0x55,0x81,0x03,0x35,0x3f,0xe8,0xa8,0xcf,0x1b,0x63,0x67,0x3c,0x8f,0x59,0xf9,0xf9,0x89,0xf4,0x50,0x8b,0xe2,0xf8,0xa4,0xc2,0x8e,0xad,0x97,0xb1,0x93,0x70,0x7c,0x58,0x67,0xca,0x31,0x1e,0xe8,0x29,0xc3,0xa7,0x6e,0x33,0x97,0x7a,0xc8,0x43,0x8b,0xde,0xdf};
static const int BC1_LEN = 80;
static const uint8_t BC2[] = {0x21,0x3d,0x41,0x7f,0x29,0x65,0x85,0xd8,0xe4,0xab,0x4c,0xc3,0xd7,0x61,0xb8,0x86,0x0c,0x6f,0x48,0x22,0x6f,0x15,0x4f,0x31,0x3c,0xa5,0x85,0xb9,0x2c,0xe3,0x68,0xee,0x24,0xe2,0x66,0xf4,0xc7,0x37,0xb4,0xa7,0x86,0xac,0xe8,0x4a,0x98,0x9f,0x58,0xb0,0xd5,0xcf,0x75,0x90,0x63,0x8e,0xbb,0xae,0x35,0xc7,0xa0,0x7b,0xc0,0x90,0xd5};
static const int BC2_LEN = 63;
static const uint8_t BC3[] = {0xdd,0xec,0xe4,0x54,0x0b,0xde,0xd0,0x47,0x9a,0x9c,0x81,0xdf,0xce,0x9f,0x6c,0xff,0xcc,0x23,0x15,0xe2,0xa5,0xd2,0x5b,0x15,0x05,0x85,0x1f,0xde,0x6a,0xd6,0xc5,0xff,0x93,0x8a,0x92,0xbf,0xd9,0x92,0x71,0x1f,0xb7,0x54,0x7e,0xb5,0x67,0x26,0xd3,0x2a,0x3f,0x98,0x37,0xec,0x09,0xc7,0xb3,0x60,0x2b,0x82,0xf7,0x16,0x1c,0x29,0x02,0xed,0xed,0x85,0xac,0xa7,0x52,0x44};
static const int BC3_LEN = 70;
static const uint8_t BC4[] = {0xab,0xbe,0x65,0x10,0x67,0x8d,0x7f,0x28,0xb7,0xe8,0x50,0x44,0xdf,0xcb,0xc1,0xbf,0xea,0x3a,0xce,0x08,0x35,0x2b,0xef,0xec,0x40,0x18,0xcd,0x39,0x1b,0x72,0x6d,0x90,0x2e,0xf6,0x34,0xf8,0x31,0x8e,0xd9,0x52,0xe2,0x51,0x90,0xf3,0xab,0x88,0xda,0x7d,0x4b,0xe2,0xf2,0xdf,0xc6,0xcd,0x98,0x0f,0x0a,0x71,0xe1,0x18,0x08,0xc8,0xf2,0xc0,0x6b,0x03,0xf1,0xd9};
static const int BC4_LEN = 68;
static const uint8_t BC5[] = {0x01,0xf4,0xf4,0xe6,0x93,0x97,0x62,0x24,0xc8,0xf7,0x8d,0x89,0x2e,0x01,0xe0,0x13,0x39,0x73,0xa6,0xa8,0x91,0x4d,0x9b,0x51,0x0c,0x41,0x1a,0xea,0x20,0x49,0xa6,0x92,0xf0,0x93,0xf0,0x61,0x85,0xc7,0xf6,0x7f,0xf1,0xcd,0xad,0x40,0x52,0xb6,0x3e,0x04,0x48,0x8a,0x89,0x25,0x21,0x30,0x6f,0xbe,0x81,0x0e,0xef,0x11,0xb4,0x51};
static const int BC5_LEN = 62;
static const uint8_t BC6[] = {0xfb,0x8b,0x71,0x6b,0x17,0x77,0x53,0x7e,0xf1,0xa5,0x85,0xcb,0x8b,0x02,0x66,0x62,0x09,0x9b,0x8f,0x38,0x41,0x79,0x03,0xbf,0x70,0x14,0x68,0x3b,0x64,0x68,0x50,0x99,0xc1,0x06,0xaf,0x7b,0xc4,0x8a,0xa2,0xc3,0xba,0x31,0xdb,0x2e,0xed,0xf5,0xb8,0xb2,0xfd,0xa9,0xa6,0x21,0x6d,0x2c,0xf1,0x3c,0x94,0x7f,0x0b,0x6d,0x80,0x93,0x4d,0x71,0xa1,0x79,0x70,0x96,0xe1,0xe0,0x11,0x09};
static const int BC6_LEN = 72;

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
// bytecode VM whose opcode stream is XChaCha20-Poly1305 encrypted (NS_BC / NS_BLOBS).
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
    int bc_len = -1;
    {
        uint8_t key[32];
        build_str_key(255u, key);
        if (gd_guard_decrypt_envelope(
                key, 0x03u, 255u, NS_BC, NS_BC_LEN, bc, sizeof(bc))) {
            bc_len = NS_BC_LEN - (int)GD_XCHACHA_OVERHEAD;
        }
        memset(key, 0, 32);
        if (bc_len <= 0) return false;
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
            if (pc + 3u > (uint32_t)bc_len || ret_val != 2u) {
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
// XOR-CS = 0x5A.  Encrypted with unique per-program XChaCha20-Poly1305 split key.
static volatile const uint8_t LBC_ANTIK_KHI[] = {
    0xa7,0xe2,0xab,0xa2,0x5b,0xc0,0x18,0x7a,0x95,0xd5,0x86,0xeb,0xb6,0x7a,0xec,0xfc,
    0xd4,0x18,0x32,0x6d,0x0e,0xf9,0x4b,0x67,0x0a,0xac,0x60,0xbc,0xde,0xd7,0x89,0x83};
static volatile const uint8_t LBC_ANTIK_KLO[] = {
    0xe4,0x91,0x13,0xd4,0xd5,0x63,0x1a,0x30,0x54,0xf8,0x47,0x15,0xdc,0xc9,0xf6,0x31,
    0x4a,0x78,0x33,0xcf,0xc3,0xe1,0x89,0xcf,0xfd,0x7d,0x9e,0xd4,0x90,0x78,0xe7,0x93};
static volatile const uint8_t LBC_ANTIK_ENC[] = {0x07,0xb9,0xe5,0xdd,0x6e,0x89,0x3f,0x31,0x14,0xb6,0x90,0x9c,0x98,0xad,0x94,0x60,0x52,0x1e,0x05,0xdd,0xef,0x94,0x90,0x64,0x79,0x74,0x69,0x53,0xa1,0x91,0xac,0xfd,0x03,0x39,0xee,0x5f,0x52,0xee,0x90,0x4b,0xb0,0x3d,0xaa,0x67};
#define LBC_ANTIK_LEN 44
#define LBC_ANTIK_CS  0x5au

// Dispatches LANTIK check through the same indirect VM dispatch used by all
// other native checks.  Ghidra sees: blr xN (g_lvm_dispatch) — opaque indirect.
static __attribute__((noinline)) void vm_run_antik(const antik_ctx_t *ctx) {
    LVM_CALL_CTX(LBC_ANTIK_KHI, LBC_ANTIK_KLO,
                 LBC_ANTIK_ENC, LBC_ANTIK_LEN, LBC_ANTIK_CS,
                 ctx);
}

// ── VM Virtualize gates ───────────────────────────────────────────────────────
// Thin direct-call stubs so amice VM Virtualize can lift them into bytecode.
// LVM_CALL expands to `blr xN` (indirect via g_lvm_dispatch) which amice
// cannot virtualize. These gates use a plain `bl` so amice sees them as
// identical in shape to vm_run() and vm_run_startup() and virtualizes them.
// The underlying AES lvm_exec dispatch still runs inside the wrapped function.
// ─────────────────────────────────────────────────────────────────────────────
// vm_gate_* — structured after vm_run_child_kill (the proven 2-BB VMP pattern).
// Each gate is split into two noinline LVM_CALL helpers + a thin dispatcher.
// Dispatcher has exactly 2 BBs → same IR shape that gets vm_run_child_kill VMP'd.
// Double LVM_CALL = double verification (stronger) + VMP heuristic triggered.

static __attribute__((noinline)) void _vg_mapscan_a(void) {
    LVM_CALL(LBC_MAPSCAN_KHI, LBC_MAPSCAN_KLO,
             LBC_MAPSCAN_ENC, LBC_MAPSCAN_LEN,
             LBC_MAPSCAN_CS);
}
static __attribute__((noinline)) void _vg_mapscan_b(void) {
    LVM_CALL(LBC_MAPSCAN_KHI, LBC_MAPSCAN_KLO,
             LBC_MAPSCAN_ENC, LBC_MAPSCAN_LEN,
             LBC_MAPSCAN_CS);
}
static D2C_AMICE_VMP __attribute__((noinline)) void vm_gate_mapscan(void) {
    _vg_mapscan_a();
    _vg_mapscan_b();
}

static __attribute__((noinline)) void _vg_vccheck_a(void) {
    LVM_CALL(LBC_VCCHECK_KHI, LBC_VCCHECK_KLO,
             LBC_VCCHECK_ENC, LBC_VCCHECK_LEN,
             LBC_VCCHECK_CS);
}
static __attribute__((noinline)) void _vg_vccheck_b(void) {
    LVM_CALL(LBC_VCCHECK_KHI, LBC_VCCHECK_KLO,
             LBC_VCCHECK_ENC, LBC_VCCHECK_LEN,
             LBC_VCCHECK_CS);
}
static D2C_AMICE_VMP __attribute__((noinline)) void vm_gate_vccheck(void) {
    _vg_vccheck_a();
    _vg_vccheck_b();
}

static __attribute__((noinline)) void _vg_soint_a(void) {
    LVM_CALL(LBC_SOINT_KHI, LBC_SOINT_KLO,
             LBC_SOINT_ENC, LBC_SOINT_LEN,
             LBC_SOINT_CS);
}
static __attribute__((noinline)) void _vg_soint_b(void) {
    LVM_CALL(LBC_SOINT_KHI, LBC_SOINT_KLO,
             LBC_SOINT_ENC, LBC_SOINT_LEN,
             LBC_SOINT_CS);
}
static D2C_AMICE_VMP __attribute__((noinline)) void vm_gate_so_integrity(void) {
    _vg_soint_a();
    _vg_soint_b();
}

static __attribute__((noinline)) void _vg_sigchk_a(JNIEnv *env) {
    LVM_CALL_CTX(LBC_SIGCHK_KHI, LBC_SIGCHK_KLO,
                 LBC_SIGCHK_ENC, LBC_SIGCHK_LEN,
                 LBC_SIGCHK_CS, env);
}
static __attribute__((noinline)) void _vg_sigchk_b(JNIEnv *env) {
    LVM_CALL_CTX(LBC_SIGCHK_KHI, LBC_SIGCHK_KLO,
                 LBC_SIGCHK_ENC, LBC_SIGCHK_LEN,
                 LBC_SIGCHK_CS, env);
}
static D2C_AMICE_VMP __attribute__((noinline)) void vm_gate_sigcheck(JNIEnv *env) {
    _vg_sigchk_a(env);
    _vg_sigchk_b(env);
}

// Hardware-key bridge remains native because it carries JNI context. The
// scalar result decision is isolated below as the AMICE VMP target.
static __attribute__((noinline)) void _vg_hwkey_a(const tee_ctx_t *c) {
    LVM_CALL_CTX(LBC_HWKEY_KHI, LBC_HWKEY_KLO,
                 LBC_HWKEY_ENC, LBC_HWKEY_LEN,
                 LBC_HWKEY_CS, c);
}
static __attribute__((noinline)) void _vg_hwkey_b(const tee_ctx_t *c) {
    LVM_CALL_CTX(LBC_HWKEY_KHI, LBC_HWKEY_KLO,
                 LBC_HWKEY_ENC, LBC_HWKEY_LEN,
                 LBC_HWKEY_CS, c);
}
static D2C_AMICE_VMP __attribute__((noinline)) void vm_gate_hwkey(const tee_ctx_t *c) {
    _vg_hwkey_a(c);
    _vg_hwkey_b(c);
}

// AMICE VMP target: no JNI, pointers, framework calls, or platform-dependent
// operations cross this boundary. It owns the policy reduction for the
// collected proof rather than trusting one native PASS/FAIL return value.
static D2C_AMICE_VMP __attribute__((noinline)) int vm_tee_vmp_validate_evidence(void) {
    const uint32_t complete = g_tee_evidence_complete;
    const uint32_t supported = g_tee_evidence_supported;
    const uint32_t mask = g_tee_evidence_mask;
    const uint32_t mirror = g_tee_evidence_mirror;
    const uint32_t seal = g_tee_evidence_seal;
    const uint32_t epoch = g_tee_evidence_epoch;
    const uint32_t expected_seal =
            (mask * 0x45d9f3bu) ^ (epoch * 0x9e3779b9u) ^ 0x6d2b79f5u;

    if (!complete) return TEE_CHECK_FAIL;
    if (!supported) {
        return TEE_CHECK_UNSUPPORTED;
    }

    const uint32_t invalid =
            (mask ^ (uint32_t)TEE_EVIDENCE_REQUIRED) |
            (mirror ^ ~mask) |
            (seal ^ expected_seal);
    return invalid ? TEE_CHECK_FAIL : TEE_CHECK_PASS;
}

// AMICE VMP target: combines the independent APK signer gate with the
// VM-reduced hardware proof. A hardware-unsupported device keeps the existing
// compatibility behavior; every signer failure and every supported-device TEE
// failure is fail-closed.
static D2C_AMICE_VMP __attribute__((noinline)) int vm_security_vmp_aggregate(
        int tee_result) {
    const int signer_complete =
            __atomic_load_n(&g_sig_gate_complete, __ATOMIC_ACQUIRE);
    const int signer_result =
            __atomic_load_n(&g_sig_gate_result, __ATOMIC_ACQUIRE);
    const int tee_invalid =
            tee_result != TEE_CHECK_PASS &&
            tee_result != TEE_CHECK_FAIL &&
            tee_result != TEE_CHECK_UNSUPPORTED;
    return !signer_complete || signer_result ||
            tee_result == TEE_CHECK_FAIL || tee_invalid;
}

// AMICE VMP target: converts both completed gate results into the encrypted
// LHWKEY crash predicate. The caller never branches on the collector's scalar
// return value alone.
static D2C_AMICE_VMP __attribute__((noinline)) void vm_tee_vmp_failure(void) {
    g_tee_vmp_result = vm_security_vmp_aggregate(g_tee_vmp_result);
}

static __attribute__((noinline)) void _vg_antik_a(const antik_ctx_t *c) {
    LVM_CALL_CTX(LBC_ANTIK_KHI, LBC_ANTIK_KLO,
                 LBC_ANTIK_ENC, LBC_ANTIK_LEN,
                 LBC_ANTIK_CS, c);
}
static __attribute__((noinline)) void _vg_antik_b(const antik_ctx_t *c) {
    LVM_CALL_CTX(LBC_ANTIK_KHI, LBC_ANTIK_KLO,
                 LBC_ANTIK_ENC, LBC_ANTIK_LEN,
                 LBC_ANTIK_CS, c);
}
static D2C_AMICE_VMP __attribute__((noinline)) void vm_gate_antik(const antik_ctx_t *c) {
    _vg_antik_a(c);
    _vg_antik_b(c);
}

// Volatile JNI dispatch table — one slot per JNI security check.
// Declared at file scope so it lands in .data, preventing compiler folding.
typedef void (*_JniGuardFn)(JNIEnv *, jobject);
static volatile _JniGuardFn g_jni_guard_tab[1] = {
    check_provider_callback_xref,  // slot 0
};

static void _d2c_measure(JNIEnv *env, jclass /*cls*/, jobject context) {
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
    // ── VM kill decision — pure-C, inside authenticated lvm_exec bytecode ──
    // Ghidra sees _fonts_measure_impl end with: lvm_exec(KHI,KLO,ENC,16,CS,&actx)
    // No strstr, no CRASH_HERE, no fragment strings visible in this function.
    vm_gate_antik(&actx);
    memset(&actx, 0, sizeof(actx));
}

// ── RegisterNatives table ─────────────────────────────────────────────────

// JNINativeMethod built at runtime — method name + signature are
// XChaCha20-Poly1305 encrypted in guard_pstrings.inc (idx 75, 76); no plaintext in .rodata.

// ════════════════════════════════════════════════════════════════════════════
// fonts_register_natives — hard-fail version.
// If fonts/Metrics is missing OR RegisterNatives fails, crash immediately.
// A protected APK with this binding broken has no anti-tamper check wired up
// at all — must never pass silently.
// ════════════════════════════════════════════════════════════════════════════

extern "C" __attribute__((visibility("default")))
void d2c_register(JNIEnv *env) {
    jclass cls = env->FindClass(NS_JNI(67, SP_JNI_FMETRICS));
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        GLOGE("fonts_register_natives: FindClass(fonts/Metrics) failed — class missing/stripped");
        CRASH_HERE("guard class fonts.Metrics not found at RegisterNatives time");
        return;
    }
    JNINativeMethod _fm = {NS_JNI(75, SP_JNI_MEASURE),
                           NS_JNI(76, SP_JNI_MEASURE_SIG),
                           (void *)_d2c_measure};
    jint rc = env->RegisterNatives(cls, &_fm, 1);
    // If measure() was smali-patched (signature changed, native modifier removed,
    // etc.) there is no matching native method and this fails. Fail closed.
    bool bindFailed = (rc != JNI_OK);
    if (env->ExceptionCheck()) { env->ExceptionClear(); bindFailed = true; }
    env->DeleteLocalRef(cls);
    GLOGI("fonts_register_natives: RegisterNatives rc=%d bindFailed=%d", (int)rc, (int)bindFailed);
    if (bindFailed) CRASH_HERE("RegisterNatives failed to bind measure() — smali-patched signature?");
}

/*
 * Compatibility exports for already-generated JNI loaders. Older generated
 * libjiagu.so objects resolve these exact names at load time. Keep the
 * implementation identifiers neutral, but preserve the ABI contract until all
 * callers are regenerated.
 */
extern "C" __attribute__((visibility("default"), alias("d2c_register")))
void fonts_register_natives(JNIEnv *env);

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

// Startup retry thread:
//   Phase 1 — wait until ActivityThread.currentApplication() returns non-null
//   Phase 2 — run the signer-bound hardware TEE gate before activity startup
//   Phase 3 — wait until at least one Activity is on-stack, then run the
//             remaining lifecycle-sensitive killer-detection suite
static void *d2c_retry(void *arg) {
    JavaVM *vm = static_cast<JavaVM *>(arg);
    if (!vm) {
        GLOGE("jni-startup[0]: missing JavaVM");
        return nullptr;
    }

    const int MAX_ATTEMPTS = 300;      // ~9 s ceiling at 30 ms steps
    const int SLEEP_US     = 30 * 1000;

    // ── Phase 1: wait for Application context ────────────────────────────
    GLOGI("jni-startup[1]: waiting for Application context");
    jobject gCtx = nullptr;
    int context_attempts = 0;
    for (int i = 0; i < MAX_ATTEMPTS && !gCtx; i++) {
        context_attempts = i + 1;
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
    if (!gCtx) {
        GLOGE("jni-startup[1]: Application context timeout attempts=%d", context_attempts);
        return nullptr;
    }
    GLOGI("jni-startup[1]: Application context ready attempts=%d", context_attempts);

    // ── Phase 2: TEE must run as soon as Application exists ──────────────
    // Do not wait for ActivityThread.mActivities here. The prior placement
    // intentionally delayed the LHWKEY VM opcode until an Activity was already
    // visible, which allowed a re-signed diagnostic test APK to be used before
    // its attestation failure terminated the process.
    JNIEnv *tee_env = nullptr;
    GLOGI("jni-startup[2]: signer gate begin");
    if (vm->AttachCurrentThread(&tee_env, nullptr) == JNI_OK && tee_env) {
        tee_ctx_t tctx;
        tctx.env = tee_env;
        tctx.context = gCtx;
        // SignerGate was bound after generated native registrations in JNI_OnLoad.
        // LSIGCHK now obtains its payload from the VMP interpreter on this thread.
        vm_gate_sigcheck(tee_env);
        GLOGI("jni-startup[2]: signer gate passed");
        TEE_DIAG("startup TEE gate");
        GLOGI("jni-startup[2]: hardware TEE gate begin");
        vm_gate_hwkey(&tctx);
        GLOGI("jni-startup[2]: hardware TEE gate passed");
        if (tee_env->ExceptionCheck()) tee_env->ExceptionClear();
        vm->DetachCurrentThread();
    } else {
        GLOGE("jni-startup[2]: AttachCurrentThread failed");
    }

    // ── Phase 3: wait until first Activity is on-stack ───────────────────
    GLOGI("jni-startup[3]: waiting for first Activity");
    bool activity_ready = false;
    int activity_attempts = 0;
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        activity_attempts = i + 1;
        JNIEnv *env = nullptr;
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
            bool ready = has_started_activity(env);
            vm->DetachCurrentThread();
            if (ready) {
                activity_ready = true;
                break;
            }
        }
        usleep(SLEEP_US);
    }
    if (activity_ready) {
        GLOGI("jni-startup[3]: first Activity ready attempts=%d", activity_attempts);
    } else {
        GLOGE("jni-startup[3]: Activity wait timeout attempts=%d; continuing", activity_attempts);
    }

    // ── Phase 4: run remaining lifecycle-sensitive checks ────────────────
    JNIEnv *env = nullptr;
    GLOGI("jni-startup[4]: lifecycle checks begin");
    if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
        _d2c_measure(env, nullptr, gCtx);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteGlobalRef(gCtx);
        vm->DetachCurrentThread();
        GLOGI("jni-startup[4]: lifecycle checks complete");
    } else {
        GLOGE("jni-startup[4]: AttachCurrentThread failed");
    }
    return nullptr;
}

// Exposed so both JNI_OnLoad variants (ours below and the transpiler-generated
// jni_onload.cpp when D2C_HAS_JNILOAD is defined) can trigger the full
// killer-detection suite via fonts_apply_metrics(env).
extern "C" __attribute__((visibility("default")))
void d2c_apply(JNIEnv *env) {
    // Fast path: Context already available — run the retry thread on existing
    // context so the 2-phase wait still applies (don't call _fonts_measure_impl
    // directly here to avoid racing with PairIP init).
    JavaVM *vm = nullptr;
    if (env) env->GetJavaVM(&vm);
    if (!vm) {
        GLOGE("d2c_apply: JavaVM unavailable");
        return;
    }

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int retry_rc = pthread_create(&t, &attr, d2c_retry, static_cast<void*>(vm));
    pthread_attr_destroy(&attr);
    GLOGI("d2c_apply: retry thread rc=%d", retry_rc);
}

extern "C" __attribute__((visibility("default"), alias("d2c_apply")))
void fonts_apply_metrics(JNIEnv *env);

// ── JNI_OnLoad (only compiled when the transpiler did NOT generate one) ───

#ifndef D2C_HAS_JNILOAD
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    GLOGI("JNI_OnLoad: entry");
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        GLOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }
    GLOGI("JNI_OnLoad: registering natives");
    d2c_register(env);
    GLOGI("JNI_OnLoad: starting Java-aware checks");
    d2c_apply(env);
    GLOGI("JNI_OnLoad: complete");
    return JNI_VERSION_1_6;
}
#endif
