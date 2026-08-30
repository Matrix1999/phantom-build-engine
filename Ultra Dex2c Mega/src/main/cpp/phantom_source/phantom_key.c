// phantom_key.c -- JNI entry-point for libphantom.so
//
// Public JNI exports:
// Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeLoadShards
// Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeSwapApplication
//
// Security model:
// * Inner per-APK key derived from (salt, sha256(pkg_name)) via ARX KDF.
// * Outer DEX payload envelope uses one universal XChaCha20-Poly1305 root key.
//   HChaCha20 derives a nonce-specific subkey inside VMP-marked Phantom code, so
//   the universal root key never crosses a normal native call boundary.
// * Key NEVER crosses the JNI boundary -- lives only on the C stack, zeroed on return.
// * API 26+ shard loading returns only a ClassLoader. No plaintext-returning
//   JNI path is present in production source.
//
// Anti-Frida / Anti-Debugger layers:
//
// LAYER 1  nativeLoadShards()
// Decrypts and loads DEX buffers inside one JNI call so no plaintext DEX byte[]
// is returned to Java code. Successful native mappings remain live for ART.
//
// LAYER 2  detect_frida_loop()  [1 s cadence, background thread]
// Frida/ptrace heuristics, TracerPid scans, self-observable proc-fd dump
// artifacts, eBPF probe detection, JDWP thread scan, and framework checks.
//
// LAYER 3  BLOCK_ROOTED_DEVICES (optional, salt-controlled policy)
// When enabled by the protected bundle, the runtime checks SELinux, su,
// Magisk/KernelSU paths, capabilities, mounts, and build properties.
// This is still not a defense against a modified/privileged kernel.
//
// detect_frida_init() fires via __attribute__((constructor)) the instant
// System.load(libphantom.so) is called -- before nativeLoadShards is reached.
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
#include "phantom_cipher.h"
#include "phantom_chacha20poly1305.h"
#include "phantom_pstrings.inc"
#include "phantom_integrity.inc"

/*
 * Runtime diagnostics are disabled for normal/release builds. Enable with
 * -DPHANTOM_DEBUG_LOG=1 for a temporary diagnostic blob. Logs contain stage
 * names, indexes, sizes, and return codes only; never keys, salts, or DEX
 * contents. Keep this disabled for production APKs.
 */
#if defined(PHANTOM_DEBUG_LOG) && PHANTOM_DEBUG_LOG
#include <android/log.h>
#include <stdarg.h>
#define PH_LOG_TAG "UltraPhantom"
/*
 * Keep Android's variadic logger outside Amice VM lifting. VMP-marked callers
 * make a normal helper call, while the helper itself remains ordinary native
 * code so debug builds do not depend on variadic-call virtualization.
 */
#if defined(__clang__)
#define PH_DEBUG_NOVMP __attribute__((optnone))
#else
#define PH_DEBUG_NOVMP
#endif
#if defined(__clang__) || defined(__GNUC__)
#define PH_DEBUG_PRINTF __attribute__((format(printf, 2, 3)))
#else
#define PH_DEBUG_PRINTF
#endif
static PH_DEBUG_NOVMP PH_DEBUG_PRINTF __attribute__((noinline)) void ph_debug_log(
        int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(priority, PH_LOG_TAG, format, args);
    va_end(args);
}
#define PH_LOGI(...) ph_debug_log(ANDROID_LOG_INFO, __VA_ARGS__)
#define PH_LOGE(...) ph_debug_log(ANDROID_LOG_ERROR, __VA_ARGS__)
#define PH_NUKE(...) do {                                             \
    PH_LOGE("nuke_app: " __VA_ARGS__);                               \
    nuke_app();                                                       \
} while (0)
#else
#define PH_LOGI(...) ((void)0)
#define PH_LOGE(...) ((void)0)
#define PH_NUKE(...) nuke_app()
#endif

// ?
// Anti-dump / Anti-Frida -- constants & types
// ?

#define MAX_LINE   512
#define MAX_LENGTH 256
#define MAX_SZ     (80 * 1024 * 1024)


// ── Detection string constants ────────────────────────────────────────────────
// Plain strings — the same proven logic used in the working reference build.
// String hiding via OLLVM is applied at compile time; no runtime decryption needed.

// ── String protection — AES-256-CBC + XOR 0x5A + per-string unique key ────────
// Replaces former XOR-only scheme.  All decryption happens inside VMP bytecode
// (ph_reveal_ns is +vm_virtualize).  .rodata holds only ciphertext — no keys,
// no recognisable plaintext, no XOR key arrays.
//
// PH_AES(var, NAME)  — declares char var[SP_BUF_SZ], decrypts SP_NAME blob.
//                      Defined in phantom_cipher.h (requires phantom_pstrings.inc).
// PH_ZERO(buf, sz)   — volatile wipe; compiler cannot optimize away.
#define PH_ZERO(buf, sz) do {                               \
    volatile char *_vp = (buf);                             \
    for (int _zi = 0; _zi < (sz); _zi++) _vp[_zi] = 0;    \
} while(0)
// PH_AES is defined in phantom_cipher.h after the include above.
// ALWAYS call PH_ZERO(var, SP_BUF_SZ) when done with the buffer.

/*
 * Keep bulk cleanup native and constant-stack.
 *
 * AMICE_VM_VIRTUALIZE=true also lifts otherwise-unannotated eligible helpers.
 * A byte-at-a-time wipe therefore turns a multi-megabyte shard cleanup into
 * millions of VM loop iterations and eventually exhausts the thread stack.
 *
 * The compiler barrier both keeps the memset observable (so it cannot be
 * deleted before free) and makes this helper ineligible for VM lifting.
 */
static __attribute__((noinline)) void ph_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    memset(ptr, 0, len);
    __asm__ volatile("" : : "r"(ptr) : "memory");
}
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

/* ── amice-safe libc replacements ────────────────────────────────────────────
   htonl/htons/atoi all pull in libc which amice can't lift.  Replace with
   pure arithmetic that the VM can handle natively. */

__attribute__((always_inline))
static inline uint32_t my_htonl(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8)
         | ((v & 0x0000FF00u) << 8)  | ((v & 0x000000FFu) << 24);
}
__attribute__((always_inline))
static inline uint16_t my_htons(uint16_t v) {
    return (uint16_t)(((v & 0x00FFu) << 8) | ((v & 0xFF00u) >> 8));
}
__attribute__((always_inline))
static inline int my_atoi(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == ':') s++;
    int n = 0;
    while (*s >= '0' && *s <= '9') n = n * 10 + (*s++ - '0');
    return n;
}

/* Replace snprintf for path building: dst = a + b + c (NUL-terminated). */
__attribute__((always_inline))
static inline void my_path_cat3(char *dst, int dstmax,
                                 const char *a, const char *b, const char *c) {
    int n = 0;
    if (a) { while (*a && n < dstmax - 1) dst[n++] = *a++; }
    if (b) { while (*b && n < dstmax - 1) dst[n++] = *b++; }
    if (c) { while (*c && n < dstmax - 1) dst[n++] = *c++; }
    dst[n] = '\0';
}

/* Minimal linux_dirent64 for vm_getdents64 — replaces opendir/readdir. */
struct ph_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[1];  /* variable-length, walk via d_reclen */
};

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

__attribute__((always_inline))
static inline long raw_syscall_5(long no, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = no;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    __asm__ volatile("svc #0\n"
        : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory", "cc");
    return x0;
}

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

/* ── Hidden symbol resolver (2026) ────────────────────────────────────────
   Resolves pthread_create + prctl at runtime via dl_iterate_phdr ELF walk.
   No dlopen / dlsym needed — removes both symbols from the PLT import table.
   dl_iterate_phdr is already imported for hook_phdr_cb, so no new entry.    */
typedef struct { const char *lib; const char *sym; void *addr; } _ph_res_t;

static int _ph_res_cb(struct dl_phdr_info *info, size_t sz, void *ud) {
    (void)sz;
    _ph_res_t *ctx = (void *)ud;
    if (!info->dlpi_name) return 0;
    /* match soname suffix */
    const char *n = info->dlpi_name;
    size_t nl = 0; while (n[nl]) nl++;
    size_t ll = 0; const char *l = ctx->lib; while (l[ll]) ll++;
    if (nl < ll || my_strncmp(n + nl - ll, ctx->lib, ll + 1) != 0) return 0;

    ElfW(Addr) base = (ElfW(Addr))info->dlpi_addr;
    ElfW(Sym)  *sym  = NULL;
    const char *str  = NULL;
    uint32_t   *hash = NULL;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_DYNAMIC) continue;
        ElfW(Dyn) *dyn = (ElfW(Dyn)*)(base + info->dlpi_phdr[i].p_vaddr);
        for (; dyn->d_tag != DT_NULL; dyn++) {
            if      (dyn->d_tag == DT_SYMTAB) sym  = (ElfW(Sym) *)dyn->d_un.d_ptr;
            else if (dyn->d_tag == DT_STRTAB) str  = (const char*)dyn->d_un.d_ptr;
            else if (dyn->d_tag == DT_HASH)   hash = (uint32_t   *)dyn->d_un.d_ptr;
        }
        break;
    }
    if (!sym || !str || !hash) return 0;

    uint32_t nchain = hash[1];
    const char *want = ctx->sym;
    size_t wl = 0; while (want[wl]) wl++;
    for (uint32_t i = 0; i < nchain; i++) {
        if (!sym[i].st_name || !sym[i].st_value) continue;
        if (my_strncmp(str + sym[i].st_name, want, wl + 1) == 0) {
            ctx->addr = (void *)(base + (ElfW(Addr))sym[i].st_value);
            return 1;
        }
    }
    return 0;
}

/* vm_pthread_create — resolves pthread_create at runtime via ELF symtab walk.
   No PLT import: sym.imp.pthread_create is gone from the binary.
   Names built char-by-char on stack so no .rodata string literal leaks.     */
static __attribute__((noinline)) int vm_pthread_create(
        pthread_t *t, const pthread_attr_t *attr,
        void *(*fn)(void *), void *arg) {
    static volatile void *_cached = NULL;
    if (!_cached) {
        char _lib[8];
        _lib[0]='l';_lib[1]='i';_lib[2]='b';_lib[3]='c';
        _lib[4]='.';_lib[5]='s';_lib[6]='o';_lib[7]='\0';
        char _sym[16];
        _sym[0]='p';_sym[1]='t';_sym[2]='h';_sym[3]='r';_sym[4]='e';
        _sym[5]='a';_sym[6]='d';_sym[7]='_';_sym[8]='c';_sym[9]='r';
        _sym[10]='e';_sym[11]='a';_sym[12]='t';_sym[13]='e';_sym[14]='\0';
        _ph_res_t ctx = { _lib, _sym, NULL };
        dl_iterate_phdr(_ph_res_cb, &ctx);
        _cached = ctx.addr;
    }
    if (!_cached) return -1;
    typedef int (*_pth_t)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
    return ((_pth_t)(void *)_cached)(t, attr, fn, arg);
}

/* vm_prctl — raw syscall via existing raw_syscall_5 (arm64) / syscall() (arm32).
   Removes prctl from the PLT import table entirely.                          */
static __attribute__((noinline)) int vm_prctl(int opt, unsigned long a2) {
#if defined(__aarch64__)
    return (int)raw_syscall_5(__NR_prctl, (long)opt, (long)a2, 0L, 0L, 0L);
#else
    return (int)syscall(__NR_prctl, (long)opt, (long)a2, 0L, 0L, 0L);
#endif
}

/* vm_read_one_line: noinline bridge so VM-virtualized callers see call_native,
   not the my_read asm inside the body (amice bails if it tries to lift asm). */
static __attribute__((noinline)) ssize_t vm_read_one_line(int fd, char *buf, unsigned int max_len);

static __attribute__((noinline)) ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
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
static __attribute__((noinline)) ssize_t vm_read_one_line(int fd, char *buf, unsigned int max_len)
    { return read_one_line(fd, buf, max_len); }

/* ── VM Virtualize syscall bridges ──────────────────────────────────────────
   amice translator.rs bails on any call whose callee is InlineAsm
   (line 7617: "inline asm calls are not supported by vm_virtualize").
   my_openat / my_read / my_close are always_inline wrappers around
   raw_syscall_* which emits "svc #0" asm — so they trigger the bail.
   Solution: wrap them in noinline stubs. The VM calls these as call_native
   (native thunk, no bytecode needed for the callee). Full syscall semantics
   are preserved; the VM just doesn't peek inside the thunk.
   Defined HERE — before any detection function that uses them. */
static __attribute__((noinline)) int vm_openat(int d, const char *p, int f, int m)
    { return my_openat(d, p, f, m); }
static __attribute__((noinline)) long vm_read(int fd, void *b, size_t n)
    { return (long)my_read(fd, b, n); }
static __attribute__((noinline)) int vm_close(int fd)
    { return my_close(fd); }
static __attribute__((noinline)) long vm_write(int fd, const void *b, size_t n)
    { return (long)my_write(fd, b, n); }
static __attribute__((noinline)) int vm_socket(int domain, int type, int protocol)
    { return my_socket(domain, type, protocol); }
static __attribute__((noinline)) int vm_connect(int fd, const struct sockaddr *addr, socklen_t len)
    { return my_connect(fd, addr, len); }
static __attribute__((noinline)) int vm_nanosleep(const struct timespec *r, struct timespec *e)
    { return my_nanosleep(r, e); }
static __attribute__((noinline)) long vm_readlinkat(int d, const char *p, char *b, size_t s)
    { return (long)my_readlinkat(d, p, b, s); }
static __attribute__((noinline)) int vm_dl_iterate_phdr(
    int (*cb)(struct dl_phdr_info*, size_t, void*), void *data)
    { return dl_iterate_phdr(cb, data); }
/* vm_strstr/vm_atoi/vm_strncmp/vm_memset/vm_path_cat3/vm_decrypt_n/vm_zero
   removed — detection functions now use my_strstr/atoi/my_strncmp/my_memset
   directly (plain string constants, no encrypted buffers). */

/* ── Extra vm_* bridges — no inline asm in body, amice lifts callers fine ───
   getdents64  : replaces opendir/readdir/closedir (those are libc, amice bails)
   setsockopt  : replaces libc setsockopt in check_frida_port
   fstatat     : replaces lstat (only if d_type == DT_UNKNOWN)
   getpid/gettid/tgkill/kill : let nuke_app be VM-virtualized (no inline asm) */
#if defined(__aarch64__)
static __attribute__((noinline)) long vm_getdents64(int fd, void *buf, size_t n)
    { return raw_syscall_3(61 /*__NR_getdents64*/, fd, (long)buf, (long)n); }
static __attribute__((noinline)) int vm_setsockopt(int fd, int lv, int opt, const void *v, int l)
    { return (int)raw_syscall_5(208/*__NR_setsockopt*/, fd, lv, opt, (long)v, l); }
static __attribute__((noinline)) int vm_fstatat(int dfd, const char *p, struct stat *st, int fl)
    { return (int)raw_syscall_4(79 /*__NR_newfstatat*/, dfd, (long)p, (long)st, fl); }
static __attribute__((noinline)) long vm_getpid(void)
    { return raw_syscall_3(172/*__NR_getpid*/, 0, 0, 0); }
static __attribute__((noinline)) long vm_gettid(void)
    { return raw_syscall_3(178/*__NR_gettid*/, 0, 0, 0); }
static __attribute__((noinline)) void vm_tgkill(long pid, long tid, long sig)
    { raw_syscall_3(131/*__NR_tgkill*/, pid, tid, sig); }
static __attribute__((noinline)) void vm_kill(long pid, long sig)
    { raw_syscall_3(129/*__NR_kill*/, pid, sig, 0); }
static __attribute__((noinline)) int vm_mprotect(void *a, size_t l, int prot)
    { return (int)raw_syscall_3(226/*__NR_mprotect*/, (long)a, (long)l, (long)prot); }
#else /* armeabi-v7a — syscall() wrapper, no inline asm */
static __attribute__((noinline)) long vm_getdents64(int fd, void *buf, size_t n)
    { return (long)syscall(__NR_getdents64, fd, buf, n); }
static __attribute__((noinline)) int vm_setsockopt(int fd, int lv, int opt, const void *v, int l)
    { return (int)syscall(__NR_setsockopt, fd, lv, opt, v, (socklen_t)l); }
static __attribute__((noinline)) int vm_fstatat(int dfd, const char *p, struct stat *st, int fl)
    { return (int)syscall(__NR_fstatat64, dfd, p, st, fl); }
static __attribute__((noinline)) long vm_getpid(void)
    { return (long)syscall(__NR_getpid); }
static __attribute__((noinline)) long vm_gettid(void)
    { return (long)syscall(__NR_gettid); }
static __attribute__((noinline)) void vm_tgkill(long pid, long tid, long sig)
    { syscall(__NR_tgkill, pid, tid, sig); }
static __attribute__((noinline)) void vm_kill(long pid, long sig)
    { syscall(__NR_kill, pid, sig); }
static __attribute__((noinline)) int vm_mprotect(void *a, size_t l, int prot)
    { return my_mprotect(a, l, prot); }
#endif

/*
 * mmap/munmap/madvise bridges deliberately stay native.  AMICE virtualized
 * callers see one bounded call_native operation instead of trying to lower
 * libc or an architecture-specific six-argument syscall.
 */
static __attribute__((noinline)) void *vm_mmap_private_rw(size_t len) {
    return mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
static __attribute__((noinline)) int vm_munmap(void *addr, size_t len) {
    return munmap(addr, len);
}
static __attribute__((noinline)) int vm_madvise(void *addr, size_t len, int advice) {
    return madvise(addr, len, advice);
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

/* nuke_app: +vm_virtualize — all syscalls via vm_* bridges (no inline asm).
   vm_getpid/vm_gettid/vm_tgkill/vm_kill are noinline stubs that hold the asm;
   amice lifts this function as pure bytecode without bailing on svc. */
__attribute__((annotate("+vm_virtualize")))
__attribute__((noreturn)) static void nuke_app(void) {
    long pid = vm_getpid();
    long tid = vm_gettid();
    vm_tgkill(pid, tid, 9 /*SIGKILL*/);
    vm_kill(pid, 9 /*SIGKILL*/);
    volatile int *p = (volatile int *)0;
    *p = 0xDEAD;
    __builtin_unreachable();
}


// ?
// Original anti-Frida detection functions
// ?

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_ptrace(void) {
    char buf[512];
    PH_AES(_ss, PROC_SELFSTATUS);
    int fd = vm_openat(AT_FDCWD, _ss, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_ss, SP_BUF_SZ);
    if (fd >= 0) {
        ssize_t bytes = vm_read(fd, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            PH_AES(_tp, TRACER_PID);
            char *tracer = my_strstr(buf, _tp);
            PH_ZERO(_tp, SP_BUF_SZ);
            if (tracer) {
                int pid = my_atoi(tracer + 10);
                if (pid > 0) { vm_close(fd); PH_NUKE("ptrace — TracerPid=%d", pid); nuke_app(); }
            }
        }
        vm_close(fd);
    }
}


// ?

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
/* detect_frida_threads: rewritten to use vm_getdents64 (raw syscall) instead of
   opendir/readdir/closedir (libc — amice bails on those).  snprintf replaced with
   my_path_cat3 (pure arithmetic, no asm).  atoi → my_atoi. */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_frida_threads(void) {
    PH_AES(_task, PROC_TASK);
    int dfd = vm_openat(AT_FDCWD, _task, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    PH_ZERO(_task, SP_BUF_SZ);
    if (dfd < 0) return;

    PH_AES(_jdwp, JDWP);
    PH_AES(_gum, GUM_JS_LOOP);
    PH_AES(_gm, GMAIN);
    PH_AES(_tp, TRACER_PID);

    char dirbuf[2048];
    ssize_t nread;
    while ((nread = vm_getdents64(dfd, dirbuf, sizeof(dirbuf))) > 0) {
        for (ssize_t off = 0; off < nread; ) {
            struct ph_dirent64 *de = (struct ph_dirent64 *)(dirbuf + off);
            off += de->d_reclen;
            if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
                (de->d_name[1] == '.' && de->d_name[2] == '\0'))) continue;

            // ── 1. comm file — raw thread name ──────────────────────────────
            {
                char comm_path[MAX_LENGTH] = "";
                PH_AES(_ctask, PROC_TASK);
                PH_AES(_comm_sfx, COMM_SUFFIX);
                my_path_cat3(comm_path, MAX_LENGTH,
                             _ctask, de->d_name, _comm_sfx);
                PH_ZERO(_comm_sfx, SP_BUF_SZ);
                PH_ZERO(_ctask, SP_BUF_SZ);
                int fd = vm_openat(AT_FDCWD, comm_path, O_RDONLY | O_CLOEXEC, 0);
                if (fd >= 0) {
                    char name[MAX_LENGTH] = "";
                    vm_read_one_line(fd, name, MAX_LENGTH);
                    vm_close(fd);
                    if (my_strncmp(name, _jdwp, 4) == 0 ||
                        my_strstr(name, _gum) || my_strstr(name, _gm)) {
                        PH_NUKE("Frida/JDWP thread via comm: %s", name);
                        PH_ZERO(_jdwp, SP_BUF_SZ); PH_ZERO(_gum, SP_BUF_SZ); PH_ZERO(_gm, SP_BUF_SZ); PH_ZERO(_tp, SP_BUF_SZ);
                        vm_close(dfd); nuke_app();
                    }
                }
            }

            // ── 2. status file — TracerPid + backup Name: ───────────────────
            {
                char status_path[MAX_LENGTH] = "";
                PH_AES(_stask, PROC_TASK);
                PH_AES(_stat_sfx, STATUS_SUFFIX);
                my_path_cat3(status_path, MAX_LENGTH,
                             _stask, de->d_name, _stat_sfx);
                PH_ZERO(_stat_sfx, SP_BUF_SZ);
                PH_ZERO(_stask, SP_BUF_SZ);
                int fd = vm_openat(AT_FDCWD, status_path, O_RDONLY | O_CLOEXEC, 0);
                if (fd >= 0) {
                    char buf[1024] = "";
                    ssize_t n = vm_read(fd, buf, sizeof(buf) - 1);
                    vm_close(fd);
                    if (n > 0) {
                        buf[n] = '\0';
                        char *tracer = my_strstr(buf, _tp);
                        if (tracer && my_atoi(tracer + 10) > 0) {
                            PH_NUKE("per-task TracerPid on task %s", de->d_name);
                            PH_ZERO(_jdwp, SP_BUF_SZ); PH_ZERO(_gum, SP_BUF_SZ); PH_ZERO(_gm, SP_BUF_SZ); PH_ZERO(_tp, SP_BUF_SZ);
                            vm_close(dfd); nuke_app();
                        }
                        PH_AES(_nf, STR_NAME_FIELD);
                        char *name_field = my_strstr(buf, _nf);
                        PH_ZERO(_nf, SP_BUF_SZ);
                        if (name_field) {
                            name_field += 5;
                            while (*name_field == '\t' || *name_field == ' ') name_field++;
                            if (my_strstr(name_field, _gum) || my_strstr(name_field, _gm)) {
                                PH_NUKE("Frida thread via status Name: task %s", de->d_name);
                                PH_ZERO(_jdwp, SP_BUF_SZ); PH_ZERO(_gum, SP_BUF_SZ); PH_ZERO(_gm, SP_BUF_SZ); PH_ZERO(_tp, SP_BUF_SZ);
                                vm_close(dfd); nuke_app();
                            }
                        }
                    }
                }
            }
        }
    }
    PH_ZERO(_jdwp, SP_BUF_SZ); PH_ZERO(_gum, SP_BUF_SZ); PH_ZERO(_gm, SP_BUF_SZ); PH_ZERO(_tp, SP_BUF_SZ);
    vm_close(dfd);
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

// Returns 1 if port 127.0.0.1:port responds with the Frida fingerprint.
// FRIDA_WS_REQUEST is decrypted per-call onto the stack and wiped after send.
/* check_frida_port: my_socket/my_connect/my_write/setsockopt/htonl/htons all replaced
   with vm_* bridges or my_* pure-arithmetic helpers so no inline asm remains in body. */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int check_frida_port(int port) {
    int fd = vm_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct timeval tv = {0, 400000};
    vm_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    vm_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = my_htonl(INADDR_LOOPBACK);
    addr.sin_port        = my_htons((uint16_t)port);

    if (vm_connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        vm_close(fd);
        return 0;
    }

    {
        PH_AES(_req, FRIDA_WS_REQ);
        vm_write(fd, _req, (ssize_t)my_strlen(_req));
        PH_ZERO(_req, SP_BUF_SZ);
    }

    char res[512];
    my_memset(res, 0, sizeof(res));
    vm_read(fd, res, sizeof(res) - 1);
    vm_close(fd);

    PH_AES(_wa, FRIDA_WS);
    int hit = my_strstr(res, _wa) != NULL;
    PH_ZERO(_wa, SP_BUF_SZ);
    return hit;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_frida_websocket(void) {

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

/* detect_frida_namedpipe: opendir/readdir/closedir → vm_getdents64, lstat → vm_fstatat,
   snprintf → my_path_cat3 so no libc calls block VMP virtualization. */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_frida_namedpipe(void) {
    PH_AES(_pfd, PROC_FD);
    int dfd = vm_openat(AT_FDCWD, _pfd, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    PH_ZERO(_pfd, SP_BUF_SZ);
    if (dfd < 0) return;

    char dirbuf[2048];
    ssize_t nread;
    while ((nread = vm_getdents64(dfd, dirbuf, sizeof(dirbuf))) > 0) {
        for (ssize_t off = 0; off < nread; ) {
            struct ph_dirent64 *de = (struct ph_dirent64 *)(dirbuf + off);
            off += de->d_reclen;
            if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
                (de->d_name[1] == '.' && de->d_name[2] == '\0'))) continue;

            char filePath[MAX_LENGTH] = "";
            PH_AES(_pfd2, PROC_FD);
            char _pfd2s[16]; my_path_cat3(_pfd2s, 16, _pfd2, "/", NULL);
            PH_ZERO(_pfd2, SP_BUF_SZ);
            my_path_cat3(filePath, MAX_LENGTH, _pfd2s, de->d_name, NULL);

            struct stat filestat;
            my_memset(&filestat, 0, sizeof(filestat));
            int stat_rc = vm_fstatat(
                    AT_FDCWD, filePath, &filestat, AT_SYMLINK_NOFOLLOW);
            if (stat_rc == 0 && (filestat.st_mode & S_IFMT) == S_IFLNK) {
                char buf[MAX_LENGTH] = "";
                long link_len = vm_readlinkat(
                        AT_FDCWD, filePath, buf, MAX_LENGTH - 1u);
                if (link_len < 0) continue;
                if (link_len >= MAX_LENGTH) link_len = MAX_LENGTH - 1;
                buf[link_len] = '\0';
                PH_AES(_linj, LINJECTOR);
                int _linj_found = my_strstr(buf, _linj) != NULL;
                PH_ZERO(_linj, SP_BUF_SZ);
                if (_linj_found) {
                    PH_NUKE("Frida named pipe detected — fd link: %s", buf);
                    vm_close(dfd); nuke_app();
                }
            }
        }
    }
    vm_close(dfd);
}

/* Defined after the SHA-256 implementation. */
static __attribute__((noinline)) void detect_phantom_self_integrity(void);

/*
 * Self-observable procfs dump artifacts.
 *
 * A normal external reader of /proc/<pid>/mem does not create a file
 * descriptor in the target process, so this is intentionally additive to
 * detect_ptrace() and the per-thread TracerPid scan rather than a replacement
 * for them.  It catches injected/in-process dump helpers that leave handles
 * to memory or kernel-process interfaces open in our fd table.
 *
 * The paths are high-confidence indicators for this process: Phantom itself
 * never opens per-process proc memory, pagemap, kcore, or kmem descriptors.
 * Do not fail closed on
 * ordinary maps/status descriptors because Android runtimes legitimately use
 * those files.
 */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_proc_dump_artifacts(void) {
    PH_AES(_pfd, PROC_FD);
    int dfd = vm_openat(AT_FDCWD, _pfd, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    PH_ZERO(_pfd, SP_BUF_SZ);
    if (dfd < 0) return;

    PH_AES(_mem, PROC_MEM_SUFFIX);
    PH_AES(_page, PROC_PAGEMAP_SUFFIX);
    PH_AES(_kcore, PROC_KCORE_SUFFIX);
    PH_AES(_kmem, PROC_KMEM_SUFFIX);

    char dirbuf[2048];
    ssize_t nread;
    while ((nread = vm_getdents64(dfd, dirbuf, sizeof(dirbuf))) > 0) {
        for (ssize_t off = 0; off < nread; ) {
            struct ph_dirent64 *de = (struct ph_dirent64 *)(dirbuf + off);
            if (de->d_reclen < 24 || off + de->d_reclen > nread) break;
            off += de->d_reclen;
            if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
                (de->d_name[1] == '.' && de->d_name[2] == '\0'))) continue;

            char fdpath[MAX_LENGTH] = "";
            PH_AES(_base, PROC_FD);
            my_path_cat3(fdpath, MAX_LENGTH, _base, "/", de->d_name);
            PH_ZERO(_base, SP_BUF_SZ);

            char target[MAX_LENGTH] = "";
            long target_len = vm_readlinkat(
                    AT_FDCWD, fdpath, target, MAX_LENGTH - 1u);
            if (target_len < 0) continue;
            if (target_len >= MAX_LENGTH) target_len = MAX_LENGTH - 1;
            target[target_len] = '\0';

            if (my_strstr(target, _mem) || my_strstr(target, _page) ||
                my_strstr(target, _kcore) || my_strstr(target, _kmem)) {
                PH_ZERO(_mem, SP_BUF_SZ);
                PH_ZERO(_page, SP_BUF_SZ);
                PH_ZERO(_kcore, SP_BUF_SZ);
                PH_ZERO(_kmem, SP_BUF_SZ);
                vm_close(dfd);
                PH_NUKE("suspicious proc memory/kernel fd");
                nuke_app();
            }
            PH_ZERO(target, sizeof(target));
        }
    }

    PH_ZERO(_mem, SP_BUF_SZ);
    PH_ZERO(_page, SP_BUF_SZ);
    PH_ZERO(_kcore, SP_BUF_SZ);
    PH_ZERO(_kmem, SP_BUF_SZ);
    vm_close(dfd);
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

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_ebpf_uprobe(void) {
    char buf[4096];
    // ── path 1 ────────────────────────────────────────────────────────────────
    {
        PH_AES(_p1, PATH_UPROBE_DBG);
        int fd = vm_openat(AT_FDCWD, _p1, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_p1, SP_BUF_SZ);
        if (fd >= 0) {
            my_memset(buf, 0, sizeof(buf));
            ssize_t n = vm_read(fd, buf, sizeof(buf) - 1);
            vm_close(fd);
            if (n > 0) {
                PH_AES(_la, STR_LIBART);
                PH_AES(_dd, STR_DEX_DUMP);
                int hit = my_strstr(buf, _la) != NULL || my_strstr(buf, _dd) != NULL;
                PH_ZERO(_la, SP_BUF_SZ); PH_ZERO(_dd, SP_BUF_SZ);
                if (hit) { PH_NUKE("eBPF uprobe on libart detected"); nuke_app(); }
            }
        }
    }
    // ── path 2 ────────────────────────────────────────────────────────────────
    {
        PH_AES(_p2, PATH_UPROBE);
        int fd = vm_openat(AT_FDCWD, _p2, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_p2, SP_BUF_SZ);
        if (fd >= 0) {
            my_memset(buf, 0, sizeof(buf));
            ssize_t n = vm_read(fd, buf, sizeof(buf) - 1);
            vm_close(fd);
            if (n > 0) {
                PH_AES(_la, STR_LIBART);
                PH_AES(_dd, STR_DEX_DUMP);
                int hit = my_strstr(buf, _la) != NULL || my_strstr(buf, _dd) != NULL;
                PH_ZERO(_la, SP_BUF_SZ); PH_ZERO(_dd, SP_BUF_SZ);
                if (hit) { PH_NUKE("eBPF uprobe on libart detected"); nuke_app(); }
            }
        }
    }

    /*
     * Kernel kprobes are a separate event source from uprobes.  Only active
     * entries naming libart or a DEX dumper are hostile; the mere presence of
     * a readable tracing filesystem is not.
     */
    {
        PH_AES(_kp1, PATH_KPROBE_DBG);
        int fd = vm_openat(AT_FDCWD, _kp1, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_kp1, SP_BUF_SZ);
        if (fd >= 0) {
            my_memset(buf, 0, sizeof(buf));
            ssize_t n = vm_read(fd, buf, sizeof(buf) - 1);
            vm_close(fd);
            if (n > 0) {
                PH_AES(_la, STR_LIBART);
                PH_AES(_dd, STR_DEX_DUMP);
                int hit = my_strstr(buf, _la) != NULL ||
                          my_strstr(buf, _dd) != NULL;
                PH_ZERO(_la, SP_BUF_SZ);
                PH_ZERO(_dd, SP_BUF_SZ);
                if (hit) {
                    PH_NUKE("eBPF kprobe on libart detected");
                    nuke_app();
                }
            }
        }
    }
    {
        PH_AES(_kp2, PATH_KPROBE);
        int fd = vm_openat(AT_FDCWD, _kp2, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_kp2, SP_BUF_SZ);
        if (fd >= 0) {
            my_memset(buf, 0, sizeof(buf));
            ssize_t n = vm_read(fd, buf, sizeof(buf) - 1);
            vm_close(fd);
            if (n > 0) {
                PH_AES(_la, STR_LIBART);
                PH_AES(_dd, STR_DEX_DUMP);
                int hit = my_strstr(buf, _la) != NULL ||
                          my_strstr(buf, _dd) != NULL;
                PH_ZERO(_la, SP_BUF_SZ);
                PH_ZERO(_dd, SP_BUF_SZ);
                if (hit) {
                    PH_NUKE("eBPF kprobe on libart detected");
                    nuke_app();
                }
            }
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
/* Extracted so hook_phdr_cb itself stays tiny — amice can then VM-virtualize it */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int _phdr_name_matches(const char *name) {
    PH_AES(_ri, HOOK_RIRU);
    PH_AES(_zy, HOOK_ZYGISK);
    PH_AES(_xp, HOOK_XPOSED);
    PH_AES(_ls, HOOK_LSPD);
    PH_AES(_ex, HOOK_EDXPOSED);
    PH_AES(_fr, HOOK_FRIDA);
    int hit = (my_strstr(name,_ri) || my_strstr(name,_zy) ||
               my_strstr(name,_xp) || my_strstr(name,_ls) ||
               my_strstr(name,_ex) || my_strstr(name,_fr));
    PH_ZERO(_ri, SP_BUF_SZ);PH_ZERO(_zy, SP_BUF_SZ);PH_ZERO(_xp, SP_BUF_SZ);
    PH_ZERO(_ls, SP_BUF_SZ);PH_ZERO(_ex, SP_BUF_SZ);PH_ZERO(_fr, SP_BUF_SZ);
    return hit;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int hook_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    if (_phdr_name_matches(info->dlpi_name)) { *(int *)data = 1; return 1; }
    return 0;
}

/*
 * Linker/maps consistency gate.
 *
 * Name scans catch known frameworks. This independent structural check catches
 * a different class of concealment: an executable PT_LOAD segment present in
 * the dynamic linker's list but hidden or permission-rewritten in procfs.
 * Only executable linker segments are compared, so ART oat/JIT mappings that
 * are not ELF objects do not create false positives.
 */
#define PH_MAX_EXEC_SEGMENTS 512
typedef struct {
    uintptr_t start;
    uintptr_t end;
    uint8_t   need_read;
    uint8_t   seen;
} ph_exec_segment_t;

typedef struct {
    ph_exec_segment_t seg[PH_MAX_EXEC_SEGMENTS];
    unsigned int count;
    unsigned int skipped;
    int invalid;
} ph_linker_map_ctx_t;

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int ph_collect_exec_segments_cb(
        struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    ph_linker_map_ctx_t *ctx = (ph_linker_map_ctx_t *)data;
    if (!ctx) return 1;
    /*
     * Bionic can expose auxiliary linker records without a complete
     * program-header table (for example vendor/VDSO records).  They are not
     * executable objects that can participate in the maps comparison, so
     * ignore them instead of treating a valid device layout as tampering.
     */
    if (!info || !info->dlpi_phdr || info->dlpi_phnum == 0 ||
        info->dlpi_phnum > 256) {
        ctx->skipped++;
        return 0;
    }

    if (ctx->count >= PH_MAX_EXEC_SEGMENTS) {
        ctx->skipped++;
        return 1;
    }

    uintptr_t base = (uintptr_t)info->dlpi_addr;
    int saw_header = 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;
        if ((ph->p_flags & PF_W) && (ph->p_flags & PF_X)) {
            ctx->invalid = 1;
            return 1;
        }

        uintptr_t raw_start = base + (uintptr_t)ph->p_vaddr;
        uintptr_t raw_end = raw_start + (uintptr_t)ph->p_memsz;
        if (raw_end <= raw_start) {
            ctx->skipped++;
            continue;
        }

        if (ph->p_offset == 0 && (ph->p_flags & PF_R)) {
            const uint8_t *eh = (const uint8_t *)raw_start;
            if (eh[EI_MAG0] != ELFMAG0 || eh[EI_MAG1] != ELFMAG1 ||
                eh[EI_MAG2] != ELFMAG2 || eh[EI_MAG3] != ELFMAG3) {
                ctx->invalid = 1;
                return 1;
            }
            saw_header = 1;
        }

        if (!(ph->p_flags & PF_X)) continue;
        if (ctx->count >= PH_MAX_EXEC_SEGMENTS) {
            ctx->invalid = 1;
            return 1;
        }

        uintptr_t page_mask = (uintptr_t)4095;
        ph_exec_segment_t *out = &ctx->seg[ctx->count++];
        out->start = raw_start & ~page_mask;
        out->end = (raw_end + page_mask) & ~page_mask;
        out->need_read = (ph->p_flags & PF_R) ? 1u : 0u;
        out->seen = 0;
    }
    (void)saw_header;
    return 0;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int ph_parse_maps_range(
        const char *line, uintptr_t *start, uintptr_t *end,
        int *readable, int *writable, int *executable) {
    uintptr_t a = 0, b = 0;
    int digits = 0;
    const char *p = line;
    if (!p) return 0;
    while (*p) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else break;
        if (a > (UINTPTR_MAX >> 4)) return 0;
        a = (a << 4) | (uintptr_t)v;
        ++digits; ++p;
    }
    if (!digits || *p++ != '-') return 0;
    digits = 0;
    while (*p) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else break;
        if (b > (UINTPTR_MAX >> 4)) return 0;
        b = (b << 4) | (uintptr_t)v;
        ++digits; ++p;
    }
    if (!digits || b <= a || *p++ != ' ') return 0;
    if (!p[0] || !p[1] || !p[2]) return 0;
    *start = a; *end = b;
    *readable = p[0] == 'r';
    *writable = p[1] == 'w';
    *executable = p[2] == 'x';
    return 1;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_linker_maps_consistency(void) {
    ph_linker_map_ctx_t ctx;
    my_memset(&ctx, 0, sizeof(ctx));
    vm_dl_iterate_phdr(ph_collect_exec_segments_cb, &ctx);
    if (ctx.invalid) {
        PH_NUKE("invalid linker ELF metadata");
        nuke_app();
    }
    if (ctx.count == 0) {
        PH_NUKE("no executable linker segments");
        nuke_app();
    }
    if (ctx.skipped) {
        PH_LOGI("linker/map check: skipped unsupported linker records=%u",
                ctx.skipped);
    }

    PH_AES(_maps, PROC_MAPS);
    int fd = vm_openat(AT_FDCWD, _maps, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_maps, SP_BUF_SZ);
    if (fd < 0) {
        PH_NUKE("cannot verify executable maps");
        nuke_app();
    }

    char line[MAX_LINE];
    while (vm_read_one_line(fd, line, MAX_LINE) > 0) {
        uintptr_t ms = 0, me = 0;
        int mr = 0, mw = 0, mx = 0;
        if (!ph_parse_maps_range(line, &ms, &me, &mr, &mw, &mx)) continue;
        if (!mx) continue;
        for (unsigned int i = 0; i < ctx.count; ++i) {
            ph_exec_segment_t *seg = &ctx.seg[i];
            if (ms <= seg->start && me >= seg->end &&
                (!seg->need_read || mr) && !mw) {
                seg->seen = 1;
            }
        }
    }
    vm_close(fd);

    for (unsigned int i = 0; i < ctx.count; ++i) {
        if (!ctx.seg[i].seen) {
            ph_secure_zero(&ctx, sizeof(ctx));
            PH_NUKE("linker executable hidden from maps");
            nuke_app();
        }
    }
    ph_secure_zero(&ctx, sizeof(ctx));
}

/*
 * BlackDex is not a privileged external memory reader in its normal mode. It
 * hosts the protected APK inside its own process, loads libblackdex.so there,
 * then hooks ART/DexFile while Phantom would otherwise create plaintext DEX.
 *
 * This preflight is intentionally independent of the root-block setting:
 * BlackDex works on non-rooted devices, so waiting for detect_root() would
 * leave the DEX-loading window open. Every check below completes before the
 * per-APK key is derived or a shard is copied from Java.
 */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int blackdex_phdr_cb(
        struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

    PH_AES(_bd, BLACKDEX_LIB);
    PH_AES(_bdd, BLACKDEX_D_LIB);
    PH_AES(_host, BLACKDEX_HOST);
    PH_AES(_core, BLACKBOX_CORE);
    int hit = my_strstr(info->dlpi_name, _bd) ||
              my_strstr(info->dlpi_name, _bdd) ||
              my_strstr(info->dlpi_name, _host) ||
              my_strstr(info->dlpi_name, _core);
    PH_ZERO(_bd, SP_BUF_SZ); PH_ZERO(_bdd, SP_BUF_SZ);
    PH_ZERO(_host, SP_BUF_SZ); PH_ZERO(_core, SP_BUF_SZ);
    if (hit) { *(int *)data = 1; return 1; }
    return 0;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_blackdex_before_decrypt(
        const uint8_t *package_name, size_t package_len) {
    char expected[513];
    char cmdline[513];
    size_t i;

    /*
     * BlackBox cannot change the kernel-visible host process name. A normal
     * protected app runs as "<package>" or "<package>:<declared-process>";
     * BlackDex runs it under its own host/proxy process instead.
     */
    if (!package_name || package_len == 0 || package_len > 512) {
        PH_NUKE("invalid protected package identity");
        nuke_app();
    }
    for (i = 0; i < package_len; ++i) expected[i] = (char)package_name[i];
    expected[package_len] = '\0';
    my_memset(cmdline, 0, sizeof(cmdline));

    PH_AES(_cmdline_path, PROC_CMDLINE);
    int cfd = vm_openat(AT_FDCWD, _cmdline_path, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_cmdline_path, SP_BUF_SZ);
    if (cfd < 0) {
        PH_ZERO(expected, sizeof(expected));
        PH_NUKE("cannot verify process identity");
        nuke_app();
    }
    long cmdline_len = vm_read(cfd, cmdline, sizeof(cmdline) - 1);
    vm_close(cfd);
    if (cmdline_len <= 0) {
        PH_ZERO(expected, sizeof(expected)); PH_ZERO(cmdline, sizeof(cmdline));
        PH_NUKE("empty process identity");
        nuke_app();
    }
    cmdline[sizeof(cmdline) - 1] = '\0';
    int valid_process = my_strncmp(cmdline, expected, package_len) == 0 &&
                        (cmdline[package_len] == '\0' || cmdline[package_len] == ':');
    PH_ZERO(expected, sizeof(expected)); PH_ZERO(cmdline, sizeof(cmdline));
    if (!valid_process) {
        PH_NUKE("virtual host process detected");
        nuke_app();
    }

    /*
     * Check both kernel maps and the dynamic-linker list. The two sources are
     * deliberately separate because a hooked procfs reader does not alter the
     * linker's loaded-object list.
     */
    PH_AES(_maps_path, PROC_MAPS);
    int mfd = vm_openat(AT_FDCWD, _maps_path, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_maps_path, SP_BUF_SZ);
    if (mfd >= 0) {
        PH_AES(_bd, BLACKDEX_LIB);
        PH_AES(_bdd, BLACKDEX_D_LIB);
        PH_AES(_host, BLACKDEX_HOST);
        PH_AES(_core, BLACKBOX_CORE);
        char map[MAX_LINE] = "";
        while (vm_read_one_line(mfd, map, MAX_LINE) > 0) {
            if (my_strstr(map, _bd) || my_strstr(map, _bdd) ||
                my_strstr(map, _host) || my_strstr(map, _core)) {
                PH_ZERO(_bd, SP_BUF_SZ); PH_ZERO(_bdd, SP_BUF_SZ);
                PH_ZERO(_host, SP_BUF_SZ); PH_ZERO(_core, SP_BUF_SZ);
                vm_close(mfd);
                PH_NUKE("BlackDex mapping detected");
                nuke_app();
            }
        }
        PH_ZERO(_bd, SP_BUF_SZ); PH_ZERO(_bdd, SP_BUF_SZ);
        PH_ZERO(_host, SP_BUF_SZ); PH_ZERO(_core, SP_BUF_SZ);
        vm_close(mfd);
    }

    int linker_hit = 0;
    vm_dl_iterate_phdr(blackdex_phdr_cb, &linker_hit);
    if (linker_hit) {
        PH_NUKE("BlackDex linker entry detected");
        nuke_app();
    }
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_riru_zygisk(void) {

    // ── 1. /proc/self/maps scan ───────────────────────────────────────────────
    // Open a fresh fd each call — avoids cross-thread fd sharing.
    {
        PH_AES(_pm, PROC_MAPS);
        int fd = vm_openat(AT_FDCWD, _pm, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_pm, SP_BUF_SZ);
        if (fd >= 0) {
            PH_AES(_ri, HOOK_RIRU);
            PH_AES(_zy, HOOK_ZYGISK);
            PH_AES(_xp, HOOK_XPOSED);
            PH_AES(_ls, HOOK_LSPD);
            PH_AES(_ex, HOOK_EDXPOSED);
            PH_AES(_fr, HOOK_FRIDA);
            char map[MAX_LINE] = "";
            while (vm_read_one_line(fd, map, MAX_LINE) > 0) {
                if (my_strstr(map,_ri) || my_strstr(map,_zy) ||
                    my_strstr(map,_xp) || my_strstr(map,_ls) ||
                    my_strstr(map,_ex) || my_strstr(map,_fr)) {
                    PH_ZERO(_ri, SP_BUF_SZ);PH_ZERO(_zy, SP_BUF_SZ);PH_ZERO(_xp, SP_BUF_SZ);
                    PH_ZERO(_ls, SP_BUF_SZ);PH_ZERO(_ex, SP_BUF_SZ);PH_ZERO(_fr, SP_BUF_SZ);
                    PH_NUKE("hooking framework in /proc/self/maps: %s", map);
                    vm_close(fd); nuke_app();
                }
            }
            PH_ZERO(_ri, SP_BUF_SZ);PH_ZERO(_zy, SP_BUF_SZ);PH_ZERO(_xp, SP_BUF_SZ);
            PH_ZERO(_ls, SP_BUF_SZ);PH_ZERO(_ex, SP_BUF_SZ);PH_ZERO(_fr, SP_BUF_SZ);
            vm_close(fd);
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

    // ── 3. Known install paths — stack-per-use decrypt ───────────────────────
    #define _CHK_HOOK(name) do { char _hp[SP_BUF_SZ]; ph_reveal_ns(PH_IDX_##name, SP_##name, SP_##name##_LEN, _hp); int _fd = vm_openat(AT_FDCWD, _hp, O_RDONLY|O_CLOEXEC, 0); PH_ZERO(_hp, SP_BUF_SZ); if (_fd >= 0) { vm_close(_fd); PH_NUKE("hook path exists"); nuke_app(); } } while(0)
    _CHK_HOOK(PATH_RIRU);
    _CHK_HOOK(PATH_RIRU_MOD);
    _CHK_HOOK(PATH_ZYGISK_MOD);
    _CHK_HOOK(PATH_RIRU_MISC);
    _CHK_HOOK(PATH_XPOSED_LIB);
    _CHK_HOOK(PATH_XPOSED_LIB64);
    _CHK_HOOK(PATH_XPOSED_JAR);
    #undef _CHK_HOOK
}

/*
 * Synchronous pre-decrypt gate.
 *
 * The background watcher catches tooling that attaches after startup, but a
 * dumper can otherwise attach, wait for a decrypt request, and observe the
 * short plaintext window before the next five-second pass. Run the existing
 * high-confidence debugger, instrumentation, and injection checks immediately
 * before either JNI entry point can derive a key or materialize a DEX.
 *
 * This deliberately does not call detect_root(): root by itself is governed by
 * the application's existing salt-controlled policy. Hooking, tracing, and
 * instrumentation remain hostile regardless of that policy.
 */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_general_dumper_before_decrypt(void) {
    PH_LOGI("pre-decrypt gate: begin");
    /*
     * Re-apply the process-memory seal on every decrypt boundary. If it
     * succeeds but a subsequent read reports the process dumpable, a runtime
     * component has interfered with the protection state.
     */
    int seal_rc = vm_prctl(PR_SET_DUMPABLE, 0);
    PH_LOGI("pre-decrypt gate: dumpable seal rc=%d", seal_rc);
    if (seal_rc == 0 && vm_prctl(PR_GET_DUMPABLE, 0) != 0) {
        PH_NUKE("process became dumpable");
        nuke_app();
    }
    PH_LOGI("pre-decrypt gate: self-integrity check");
    detect_phantom_self_integrity();
    /* All functions below use independent high-confidence observations. */
    PH_LOGI("pre-decrypt gate: ptrace check");
    detect_ptrace();          /* TracerPid */
    PH_LOGI("pre-decrypt gate: thread check");
    detect_frida_threads();   /* per-thread tracer, JDWP, gum-js-loop */
    PH_LOGI("pre-decrypt gate: proc fd check");
    detect_proc_dump_artifacts(); /* self-observable /proc memory handles */
    PH_LOGI("pre-decrypt gate: named-pipe check");
    detect_frida_namedpipe(); /* named-pipe and fd artifacts */
    PH_LOGI("pre-decrypt gate: websocket check");
    detect_frida_websocket(); /* active Frida server protocol */
    PH_LOGI("pre-decrypt gate: ebpf check");
    detect_ebpf_uprobe();     /* active kernel uprobe instrumentation */
    PH_LOGI("pre-decrypt gate: framework check");
    detect_riru_zygisk();     /* maps, linker, and known hook framework paths */
    PH_LOGI("pre-decrypt gate: pass");
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

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void detect_root(void) {
    PH_LOGI("root gate: begin");

    // ── A. su binary existence — stack-per-use decrypt ───────────────────────
    #define _CHK_SU(name) do { char _su[SP_BUF_SZ]; ph_reveal_ns(PH_IDX_##name, SP_##name, SP_##name##_LEN, _su); int _fd = vm_openat(AT_FDCWD, _su, O_RDONLY|O_CLOEXEC, 0); PH_ZERO(_su, SP_BUF_SZ); if (_fd >= 0) { vm_close(_fd); PH_NUKE("su binary"); nuke_app(); } } while(0)
    _CHK_SU(PATH_SU_LOCAL);
    _CHK_SU(PATH_SU_LOCAL_BIN);
    _CHK_SU(PATH_SU_LOCAL_XBIN);
    _CHK_SU(PATH_SU_SBIN);
    _CHK_SU(PATH_SU_SU_BIN);
    _CHK_SU(PATH_SU_SYS_BIN);
    _CHK_SU(PATH_SU_SYS_XBIN);
    _CHK_SU(PATH_SU_EXT);
    _CHK_SU(PATH_SU_FAILSAFE);
    _CHK_SU(PATH_SU_SD);
    _CHK_SU(PATH_SU_USR);
    _CHK_SU(PATH_SU_CACHE);
    _CHK_SU(PATH_SU_DATA);
    _CHK_SU(PATH_SU_DEV);
    #undef _CHK_SU

    // ── B. /proc/self/mounts — Magisk mount signatures ────────────────────────
    {
        PH_AES(_mnt, PATH_PROC_MOUNTS);
        int fd = vm_openat(AT_FDCWD, _mnt, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_mnt, SP_BUF_SZ);
        if (fd >= 0) {
            PH_AES(_mg, STR_MAGISK);
            PH_AES(_cm, STR_CORE_MIRROR);
            PH_AES(_ci, STR_CORE_IMG);
            char buf[MAX_LINE] = "";
            while (vm_read_one_line(fd, buf, MAX_LINE) > 0) {
                if (my_strstr(buf,_mg) || my_strstr(buf,_cm) || my_strstr(buf,_ci)) {
                    PH_ZERO(_mg, SP_BUF_SZ);PH_ZERO(_cm, SP_BUF_SZ);PH_ZERO(_ci, SP_BUF_SZ);
                    PH_NUKE("Magisk mount detected: %s", buf);
                    vm_close(fd); nuke_app();
                }
            }
            PH_ZERO(_mg, SP_BUF_SZ);PH_ZERO(_cm, SP_BUF_SZ);PH_ZERO(_ci, SP_BUF_SZ);
            vm_close(fd);
        }
    }
    PH_LOGI("root gate: pass");
}

// ?
// detect_frida_loop -- one-second cadence
// Frida thread names, named pipes, binary checksums, ptrace, eBPF uprobes,
// and the general pre-decrypt gate while the process remains alive.
// ?

/* g_block_rooted — set to 1 when nativeLoadShards reads
   salt[0] bit-7 == 1 (block-rooted toggle ON).  Starts at 0 so that
   detect_root() and detect_riru_zygisk() in the background loop are
   suppressed until the salt is read and the flag is known.
   Declared volatile so the compiler does not cache it across loop iterations. */
static volatile int g_block_rooted = 0;

/* Defined below with the other rooted-device probes. */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_selinux(void);

/*
 * The DEX loader is deliberately one-shot per process. Every protected process
 * loads its own libphantom instance, so this rejects only repeated/re-entrant
 * calls in the same process. The atomic transitions also make unexpected call
 * ordering fail closed without relying on Java-side state.
 */
typedef enum {
    PH_LOAD_IDLE = 0,
    PH_LOAD_ENVIRONMENT,
    PH_LOAD_KEY_READY,
    PH_LOAD_SHARDS_LOADING,
    PH_LOAD_CLASSLOADER,
    PH_LOAD_COMPLETE,
    PH_LOAD_FAILED
} ph_load_state_t;

static volatile int g_ph_load_state = PH_LOAD_IDLE;

static __attribute__((noinline)) bool ph_load_begin(void) {
    return __sync_bool_compare_and_swap(&g_ph_load_state,
                                        PH_LOAD_IDLE, PH_LOAD_ENVIRONMENT);
}

static __attribute__((noinline)) bool ph_load_advance(
        ph_load_state_t expected, ph_load_state_t next) {
    return __sync_bool_compare_and_swap(&g_ph_load_state, expected, next);
}

static __attribute__((noinline)) void ph_load_fail(void) {
    __sync_lock_test_and_set(&g_ph_load_state, PH_LOAD_FAILED);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void *detect_frida_loop(void *args) {
    (void)args;
    struct timespec timereq;
    timereq.tv_sec  = 1;
    timereq.tv_nsec = 0;
    while (1) {
        detect_general_dumper_before_decrypt();
        if (g_block_rooted) {
            cr_selinux();                         // re-check enforcement at runtime
            detect_root();                        // su binaries + Magisk mounts
        }
        vm_nanosleep(&timereq, NULL);
    }
    return NULL;
}
/* check_rooted — called from nativeLoadShards when salt[0] bit-7 == 1. */
/* check_rooted split into 6 small noinline sub-functions — static const char* arrays
   produce GOT-relative loads on arm64 that VMP cannot lift. Each sub-function is
   small, pure vm_* calls only, and explicitly annotated +vm_virtualize. */

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_selinux(void) {
    PH_AES(_s1, PATH_SELINUX1);
    int fd = vm_openat(AT_FDCWD, _s1, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_s1, SP_BUF_SZ);
    if (fd < 0) {
        PH_AES(_s2, PATH_SELINUX2);
        fd = vm_openat(AT_FDCWD, _s2, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_s2, SP_BUF_SZ);
    }
    if (fd < 0) return;
    char b[4] = {0}; vm_read(fd, b, 3); vm_close(fd);
    if (b[0] == '0') { PH_NUKE("SELinux permissive"); nuke_app(); }
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_su_binaries(void) {
#define _CK_SU(name) do { \
    char _sp[SP_BUF_SZ]; ph_reveal_ns(PH_IDX_##name, SP_##name, SP_##name##_LEN, _sp); \
    int _f = vm_openat(AT_FDCWD, _sp, O_RDONLY|O_CLOEXEC, 0); \
    PH_ZERO(_sp, SP_BUF_SZ); \
    if (_f>=0){vm_close(_f);PH_NUKE("su binary");nuke_app();} } while(0)
    _CK_SU(PATH_SU_LOCAL);
    _CK_SU(PATH_SU_LOCAL_BIN);
    _CK_SU(PATH_SU_LOCAL_XBIN);
    _CK_SU(PATH_SU_SBIN);
    _CK_SU(PATH_SU_SU_BIN);
    _CK_SU(PATH_SU_SYS_BIN);
    _CK_SU(PATH_SU_EXT);
    _CK_SU(PATH_SU_FAILSAFE);
    _CK_SU(PATH_SU_SD);
    _CK_SU(PATH_SU_USR);
    _CK_SU(PATH_SU_SYS_XBIN);
    _CK_SU(PATH_SU_CACHE);
    _CK_SU(PATH_SU_DATA);
    _CK_SU(PATH_SU_DEV);
#undef _CK_SU
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_root_dirs(void) {
#define _CK_DIR(name) do { \
    char _dp[SP_BUF_SZ]; ph_reveal_ns(PH_IDX_##name, SP_##name, SP_##name##_LEN, _dp); \
    int _f = vm_openat(AT_FDCWD, _dp, O_RDONLY|O_CLOEXEC|O_DIRECTORY, 0); \
    PH_ZERO(_dp, SP_BUF_SZ); \
    if (_f>=0){vm_close(_f);PH_NUKE("root dir exists");nuke_app();} } while(0)
    _CK_DIR(PATH_MAGISK);
    _CK_DIR(PATH_KSU);
    _CK_DIR(PATH_APD);
    _CK_DIR(PATH_LSPD_DIR);
    _CK_DIR(PATH_MAGISK_SBIN);
    _CK_DIR(PATH_MAGISK_DEV);
    _CK_DIR(PATH_XPOSED_JAR);
    _CK_DIR(PATH_XPOSED_PROP);
#undef _CK_DIR
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_mounts(void) {
    PH_AES(_mp, PATH_PROC_MOUNTS);
    int mfd = vm_openat(AT_FDCWD, _mp, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_mp, SP_BUF_SZ);
    if (mfd < 0) return;
    /* Decrypt strstr targets once before the loop — no repeated stack alloc */
    PH_AES(_m_mag, STR_MAGISK);
    PH_AES(_m_cmr, STR_CORE_MIRROR);
    PH_AES(_m_cim, STR_CORE_IMG);
    PH_AES(_m_lspd, HOOK_LSPD);
    PH_AES(_m_zyg, HOOK_ZYGISK);
    PH_AES(_m_xpo, HOOK_XPOSED);
    char buf[512]; int pos = 0; ssize_t n;
    while ((n = vm_read(mfd, buf + pos, (ssize_t)sizeof(buf) - pos - 1)) > 0) {
        buf[pos + n] = '\0';
        if (my_strstr(buf, _m_mag) || my_strstr(buf, _m_cmr) ||
            my_strstr(buf, _m_cim) || my_strstr(buf, _m_lspd) ||
            my_strstr(buf, _m_zyg) || my_strstr(buf, _m_xpo)) {
            vm_close(mfd); PH_NUKE("mount marker found"); nuke_app();
        }
        if (pos + n > 11) {
            for (int k = 0; k < 11; k++) buf[k] = buf[(pos+n)-11+k];
            pos = 11;
        } else { pos = 0; }
    }
    PH_ZERO(_m_mag, SP_BUF_SZ); PH_ZERO(_m_cmr, SP_BUF_SZ); PH_ZERO(_m_cim, SP_BUF_SZ);
    PH_ZERO(_m_lspd, SP_BUF_SZ); PH_ZERO(_m_zyg, SP_BUF_SZ); PH_ZERO(_m_xpo, SP_BUF_SZ);
    vm_close(mfd);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_capeff(void) {
    PH_AES(_cst, PROC_SELFSTATUS);
    int sfd = vm_openat(AT_FDCWD, _cst, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_cst, SP_BUF_SZ);
    if (sfd < 0) return;
    char sb[2048]; ssize_t sn = vm_read(sfd, sb, sizeof(sb)-1); vm_close(sfd);
    if (sn <= 0) return;
    sb[sn] = '\0';
    PH_AES(_ceff, STR_CAPEFF);
    const char *cap = my_strstr(sb, _ceff);
    PH_ZERO(_ceff, SP_BUF_SZ);
    if (!cap) return;
    cap += 7; while (*cap == ' ' || *cap == '\t') cap++;
    while (*cap == '0') cap++;
    if (*cap && *cap != '\n') { PH_NUKE("CapEff elevated"); nuke_app(); }
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void cr_buildprop(void) {
    PH_AES(_bp, PATH_BUILD_PROP);
    int bfd = vm_openat(AT_FDCWD, _bp, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_bp, SP_BUF_SZ);
    if (bfd < 0) return;
    PH_AES(_tk, STR_TEST_KEYS);
    PH_AES(_dk, STR_DEV_KEYS);
    char bb[512]; int bp = 0; ssize_t bn;
    while ((bn = vm_read(bfd, bb + bp, (ssize_t)sizeof(bb) - bp - 1)) > 0) {
        bb[bp + bn] = '\0';
        if (my_strstr(bb, _tk) || my_strstr(bb, _dk)) {
            PH_ZERO(_tk, SP_BUF_SZ); PH_ZERO(_dk, SP_BUF_SZ);
            vm_close(bfd); PH_NUKE("build.prop bad key"); nuke_app();
        }
        if (bp + bn > 9) {
            for (int k = 0; k < 9; k++) bb[k] = bb[(bp+bn)-9+k];
            bp = 9;
        } else { bp = 0; }
    }
    PH_ZERO(_tk, SP_BUF_SZ); PH_ZERO(_dk, SP_BUF_SZ);
    vm_close(bfd);
}

/* Thin dispatcher — calls the 6 sub-functions above. */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void check_rooted(void) {
    cr_selinux();
    cr_su_binaries();
    cr_root_dirs();
    cr_mounts();
    cr_capeff();
    cr_buildprop();
}

/* vm_spawn_watcher — VMP-virtualized so the constructor body shows zero named
   PLT imports in ARM64 disassembly.
   Before this fix, detect_frida_init compiled to:
       bl sym.imp.prctl            ← named, fixed offset, trivially found
       bl sym.imp.pthread_create   ← named, fixed offset — 4-byte NOP kills all detection
   After this fix, detect_frida_init compiles to:
       bl fcn.AAAA   ← stripped vm_prctl, no sym.imp label
       bl fcn.BBBB   ← stripped vm_spawn_watcher, no sym.imp label
   pthread_create is called inside the VM as call_native(vm_pthread_create) —
   no bl pthread_create exists at any fixed binary offset an attacker can NOP. */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void vm_spawn_watcher(void) {
    pthread_t t;
    vm_pthread_create(&t, NULL, detect_frida_loop, NULL);
}

__attribute__((constructor))
void detect_frida_init(void) {
    PH_LOGI("constructor: begin");
    vm_prctl(PR_SET_DUMPABLE, 0);
    PH_LOGI("constructor: dumpable sealed");
    detect_phantom_self_integrity();
    vm_spawn_watcher();
    PH_LOGI("constructor: watcher started");
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

/* ── sha256 split into three noinline pieces so amice x0-x31 limit is not hit ──
   sha256_block as a monolith has w[64] stack array + 8 hash vars + temporaries
   = too many simultaneous live values for the VM register file.
   Split:
     _sha_expand   — w[] message schedule expansion (pointer-based, ~8 live regs)
     _sha_compress — 64-round compression via pointers (~17 live regs max)
     sha256_block  — thin noinline dispatcher; amice sees it as call_native thunk
     sha256        — driver: +vm_virtualize, calls sha256_block as call_native   */

/* Step A: expand message schedule into caller-supplied w[64]
   noinline only — NOT annotated; arm64 IR causes apply-phase crash if VMP'd here */
static __attribute__((noinline)) void _sha_expand(uint32_t *w, const uint8_t *data) {
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)
              |((uint32_t)data[i*4+2]<<8)|(uint32_t)data[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
}

/* Step B: 64-round compression; w and K256 accessed via pointer loads only
   noinline only — NOT annotated; same reason as _sha_expand */
static __attribute__((noinline)) void _sha_compress(uint32_t *h, const uint32_t *w) {
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    int i;
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

/* Thin dispatcher — noinline so amice treats it as call_native from sha256 */
static __attribute__((noinline)) void sha256_block(uint32_t h[8], const uint8_t data[64]) {
    uint32_t w[64];
    _sha_expand(w, data);
    _sha_compress(h, w);
}

/* sha256 driver — +vm_virtualize, no libc calls (my_memset + byte loop) */
__attribute__((noinline))
__attribute__((annotate("+vm_virtualize")))
static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    size_t i;
    uint64_t bit_len = (uint64_t)len * 8;
    while (len >= 64) { sha256_block(h, msg); msg += 64; len -= 64; }
    my_memset(block, 0, 64);
    for (i = 0; i < len; i++) block[i] = msg[i];
    block[len] = 0x80;
    if (len >= 56) { sha256_block(h, block); my_memset(block, 0, 64); }
    for (i = 0; i < 8; i++) block[56+i] = (uint8_t)(bit_len >> (56 - i*8));
    sha256_block(h, block);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i]>>24);
        out[i*4+1] = (uint8_t)(h[i]>>16);
        out[i*4+2] = (uint8_t)(h[i]>>8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

/*
 * Phantom self-integrity.
 *
 * The build workflow stamps the final ABI's executable PT_LOAD segments. At
 * runtime we locate the loaded object containing this function, hash the same
 * executable segments from memory, and compare against that stamp. Hashing
 * only PF_X/p_filesz bytes avoids mutable data, BSS, and ordinary relocation
 * state. Hashes are combined as SHA256(SHA256(segment_0) || ...), so the
 * runtime never allocates a second copy of the executable image.
 *
 * This catches code-page patching after the authenticated blob is loaded. It
 * does not make a compromised kernel trustworthy: a privileged kernel can
 * change the code and hide the modified pages from the process.
 */
#define PH_MAX_SELF_EXEC_SEGMENTS 32

typedef struct {
    uintptr_t start;
    size_t len;
} ph_self_exec_range_t;

typedef struct {
    uintptr_t marker;
    ph_self_exec_range_t ranges[PH_MAX_SELF_EXEC_SEGMENTS];
    unsigned int count;
    int invalid;
} ph_self_integrity_ctx_t;

static __attribute__((noinline)) int ph_collect_self_exec_segments_cb(
        struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    ph_self_integrity_ctx_t *ctx = (ph_self_integrity_ctx_t *)data;
    if (!ctx || !info || !info->dlpi_phdr || info->dlpi_phnum == 0 ||
        info->dlpi_phnum > 256) {
        return 0;
    }

    uintptr_t base = (uintptr_t)info->dlpi_addr;
    int owns_marker = 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X) ||
            ph->p_filesz == 0) continue;
        uintptr_t start = base + (uintptr_t)ph->p_vaddr;
        uintptr_t end = start + (uintptr_t)ph->p_filesz;
        if (end <= start) {
            ctx->invalid = 1;
            return 1;
        }
        if (ctx->marker >= start && ctx->marker < end) owns_marker = 1;
    }
    if (!owns_marker) return 0;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X) ||
            ph->p_filesz == 0) continue;
        if (ctx->count >= PH_MAX_SELF_EXEC_SEGMENTS) {
            ctx->invalid = 1;
            return 1;
        }
        uintptr_t start = base + (uintptr_t)ph->p_vaddr;
        uintptr_t end = start + (uintptr_t)ph->p_filesz;
        if (end <= start) {
            ctx->invalid = 1;
            return 1;
        }
        ctx->ranges[ctx->count].start = start;
        ctx->ranges[ctx->count].len = (size_t)(end - start);
        ctx->count++;
    }
    return 1;
}

/*
 * The address-bearing anchor is intentionally native: taking a function's
 * address prevents Amice from virtualizing that function.  Keeping it separate
 * lets the actual enforcement gate remain VM-backed.
 */
static __attribute__((noinline, used)) void ph_self_integrity_anchor(void) {
    __asm__ __volatile__("" ::: "memory");
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void ph_self_hash_range(
        uintptr_t start, size_t len, uint8_t *digest) {
    sha256((const uint8_t *)start, len, digest);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void ph_self_finalize_digest(
        const uint8_t *segment_hashes, size_t byte_count, uint8_t *actual) {
    sha256(segment_hashes, byte_count, actual);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) uint32_t ph_self_compare_word(
        uint32_t actual, uint32_t expected) {
    return actual ^ expected;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int ph_self_compare_reduce(
        uint32_t diff, uint32_t expected_or) {
    return expected_or != 0 && diff == 0;
}

static __attribute__((noinline)) int ph_self_compare_digest(
        const uint8_t *actual) {
    uint32_t diff = 0;
    uint32_t expected_or = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        unsigned int offset = i * 4u;
        uint32_t actual_word =
                ((uint32_t)actual[offset]) |
                ((uint32_t)actual[offset + 1u] << 8) |
                ((uint32_t)actual[offset + 2u] << 16) |
                ((uint32_t)actual[offset + 3u] << 24);
        uint32_t expected_word =
                ((uint32_t)PHANTOM_EXPECTED_EXEC_SHA256[offset]) |
                ((uint32_t)PHANTOM_EXPECTED_EXEC_SHA256[offset + 1u] << 8) |
                ((uint32_t)PHANTOM_EXPECTED_EXEC_SHA256[offset + 2u] << 16) |
                ((uint32_t)PHANTOM_EXPECTED_EXEC_SHA256[offset + 3u] << 24);
        diff |= ph_self_compare_word(actual_word, expected_word);
        expected_or |= expected_word;
    }
    return ph_self_compare_reduce(diff, expected_or);
}

static __attribute__((noinline)) int ph_self_integrity_compute(void) {
    ph_self_integrity_ctx_t ctx;
    my_memset(&ctx, 0, sizeof(ctx));
    ctx.marker = (uintptr_t)&ph_self_integrity_anchor;
    vm_dl_iterate_phdr(ph_collect_self_exec_segments_cb, &ctx);

    if (ctx.invalid || ctx.count == 0 || ctx.count > PH_MAX_SELF_EXEC_SEGMENTS) {
        ph_secure_zero(&ctx, sizeof(ctx));
        return 0;
    }

    uint8_t segment_hashes[PH_MAX_SELF_EXEC_SEGMENTS * 32];
    my_memset(segment_hashes, 0, sizeof(segment_hashes));
    for (unsigned int i = 0; i < ctx.count; ++i) {
        ph_self_hash_range(ctx.ranges[i].start, ctx.ranges[i].len,
                           segment_hashes + (i * 32u));
    }

    uint8_t actual[32];
    my_memset(actual, 0, sizeof(actual));
    ph_self_finalize_digest(segment_hashes, (size_t)ctx.count * 32u, actual);
    int clean = ph_self_compare_digest(actual);
    ph_secure_zero(actual, sizeof(actual));
    ph_secure_zero(segment_hashes, sizeof(segment_hashes));
    ph_secure_zero(&ctx, sizeof(ctx));
    return clean;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int ph_self_enforcement_policy(int clean) {
    return clean == 0;
}

static __attribute__((noinline)) void detect_phantom_self_integrity(void) {
    if (ph_self_enforcement_policy(ph_self_integrity_compute())) {
        PH_NUKE("Phantom executable integrity mismatch");
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

/*
 * Universal outer payload key.
 *
 * The root words, HChaCha state, and derived subkey stay inside the VM-only
 * key path. The small helpers below deliberately keep each lowering unit
 * narrow: Amice has a finite virtual register file, and materializing the
 * complete root expansion plus a 16-word HChaCha state in one function causes
 * it to fall back to ordinary native code.
 */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) int stage_bridge(
        uint8_t subkey[32],
        uint8_t nonce[12],
        uint8_t aad[4],
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        const uint8_t tag[16],
        uint8_t *plaintext) {
    int ok = ph_chacha20poly1305_decrypt(
            subkey, nonce, aad, 4, ciphertext, ciphertext_len, tag, plaintext);
    ph_secure_zero(subkey, 32);
    ph_secure_zero(nonce, 12);
    ph_secure_zero(aad, 4);
    return ok;
}

typedef struct {
    uint32_t word[16];
} ph_hchacha_state_t;

/*
 * Fixed-index root leaves avoid the switch/phi form that Amice rejects as
 * undef/poison. Each leaf writes one decoded root word directly into the
 * HChaCha state, so no complete native root-key byte array is needed.
 */
#define PH_DEFINE_ROOT_STAGE(N, ENCODED)                                      \
    __attribute__((annotate("+vm_virtualize")))                              \
    static __attribute__((noinline)) void stage_root_word##N##_vm(            \
            ph_hchacha_state_t *s) {                                          \
        const uint32_t i = (N);                                               \
        uint32_t v = (ENCODED);                                               \
        const uint32_t mix = 0xA5A5A5A5u ^ (i * 0x9E3779B9u);                 \
        const uint32_t rot = (i % 5u) + 3u;                                   \
        const uint32_t add = 0x31415927u + (i * 0x01020304u);                 \
        v ^= mix;                                                             \
        v = (v >> rot) | (v << (32u - rot));                                 \
        s->word[4u + i] = v - add;                                            \
    }

PH_DEFINE_ROOT_STAGE(0, 0x8bb1bb95u)
PH_DEFINE_ROOT_STAGE(1, 0x893e5bf8u)
PH_DEFINE_ROOT_STAGE(2, 0xc33ecd2bu)
PH_DEFINE_ROOT_STAGE(3, 0xec495222u)
PH_DEFINE_ROOT_STAGE(4, 0x66578f23u)
PH_DEFINE_ROOT_STAGE(5, 0x16111f8fu)
PH_DEFINE_ROOT_STAGE(6, 0x020f84aau)
PH_DEFINE_ROOT_STAGE(7, 0xedb5b00fu)
#undef PH_DEFINE_ROOT_STAGE

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_root_group0_vm(
        ph_hchacha_state_t *s) {
    stage_root_word0_vm(s);
    stage_root_word1_vm(s);
    stage_root_word2_vm(s);
    stage_root_word3_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_root_group1_vm(
        ph_hchacha_state_t *s) {
    stage_root_word4_vm(s);
    stage_root_word5_vm(s);
    stage_root_word6_vm(s);
    stage_root_word7_vm(s);
}

/*
 * Keep the HChaCha round state in a separate VM function. Inlining the full
 * 16-word/20-round state into stage_apply pushes Amice beyond its VM lowering
 * budget. The state is passed through memory between small VM functions so
 * each function has only a bounded number of live scalar values.
 */
__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_qr_vm(
        ph_hchacha_state_t *s, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    uint32_t xa = s->word[a];
    uint32_t xb = s->word[b];
    uint32_t xc = s->word[c];
    uint32_t xd = s->word[d];
    xa += xb; xd ^= xa; xd = (xd << 16) | (xd >> 16);
    xc += xd; xb ^= xc; xb = (xb << 12) | (xb >> 20);
    xa += xb; xd ^= xa; xd = (xd << 8) | (xd >> 24);
    xc += xd; xb ^= xc; xb = (xb << 7) | (xb >> 25);
    s->word[a] = xa;
    s->word[b] = xb;
    s->word[c] = xc;
    s->word[d] = xd;
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_constants_vm(
        ph_hchacha_state_t *s) {
    s->word[0] = 0x61707865u;
    s->word[1] = 0x3320646eu;
    s->word[2] = 0x79622d32u;
    s->word[3] = 0x6b206574u;
}

#define PH_DEFINE_NONCE_STAGE(N)                                              \
    __attribute__((annotate("+vm_virtualize")))                              \
    static __attribute__((noinline)) void stage_hchacha_nonce##N##_vm(        \
            const uint8_t full_nonce[16], ph_hchacha_state_t *s) {            \
        s->word[12u + (N)] = ph_chacha_load32_le(full_nonce + ((N) * 4u));    \
    }

PH_DEFINE_NONCE_STAGE(0)
PH_DEFINE_NONCE_STAGE(1)
PH_DEFINE_NONCE_STAGE(2)
PH_DEFINE_NONCE_STAGE(3)
#undef PH_DEFINE_NONCE_STAGE

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_prepare_vm(
        const uint8_t full_nonce[16], ph_hchacha_state_t *s) {
    stage_hchacha_constants_vm(s);
    stage_hchacha_nonce0_vm(full_nonce, s);
    stage_hchacha_nonce1_vm(full_nonce, s);
    stage_hchacha_nonce2_vm(full_nonce, s);
    stage_hchacha_nonce3_vm(full_nonce, s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_column_vm(
        ph_hchacha_state_t *s) {
    stage_hchacha_qr_vm(s, 0, 4, 8, 12);
    stage_hchacha_qr_vm(s, 1, 5, 9, 13);
    stage_hchacha_qr_vm(s, 2, 6, 10, 14);
    stage_hchacha_qr_vm(s, 3, 7, 11, 15);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_diagonal_vm(
        ph_hchacha_state_t *s) {
    stage_hchacha_qr_vm(s, 0, 5, 10, 15);
    stage_hchacha_qr_vm(s, 1, 6, 11, 12);
    stage_hchacha_qr_vm(s, 2, 7, 8, 13);
    stage_hchacha_qr_vm(s, 3, 4, 9, 14);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_round_vm(
        ph_hchacha_state_t *s) {
    stage_hchacha_column_vm(s);
    stage_hchacha_diagonal_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_rounds0_vm(
        ph_hchacha_state_t *s) {
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_rounds1_vm(
        ph_hchacha_state_t *s) {
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_rounds2_vm(
        ph_hchacha_state_t *s) {
    stage_hchacha_round_vm(s);
    stage_hchacha_round_vm(s);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_store_vm(
        const ph_hchacha_state_t *s, uint8_t subkey[32]) {
    ph_chacha_store32_le(subkey + 0,  s->word[0]);
    ph_chacha_store32_le(subkey + 4,  s->word[1]);
    ph_chacha_store32_le(subkey + 8,  s->word[2]);
    ph_chacha_store32_le(subkey + 12, s->word[3]);
    ph_chacha_store32_le(subkey + 16, s->word[12]);
    ph_chacha_store32_le(subkey + 20, s->word[13]);
    ph_chacha_store32_le(subkey + 24, s->word[14]);
    ph_chacha_store32_le(subkey + 28, s->word[15]);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_hchacha_vm(
        ph_hchacha_state_t *state,
        const uint8_t full_nonce[16],
        uint8_t subkey[32]) {
    stage_hchacha_prepare_vm(full_nonce, state);
    stage_hchacha_rounds0_vm(state);
    stage_hchacha_rounds1_vm(state);
    stage_hchacha_rounds2_vm(state);
    stage_hchacha_store_vm(state, subkey);
}

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void stage_apply(
        ph_hchacha_state_t *state) {
    stage_root_group0_vm(state);
    stage_root_group1_vm(state);
}

static __attribute__((noinline)) int stage_decrypt(
        int shard_index,
        const uint8_t *full_nonce,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        const uint8_t *tag,
        uint8_t *plaintext) {
    ph_hchacha_state_t state = {{0}};
    uint8_t subkey[32];
    uint8_t nonce[12] = {0};
    uint8_t aad[4];
    stage_apply(&state);
    stage_hchacha_vm(&state, full_nonce, subkey);
    ph_secure_zero(&state, sizeof(state));
    for (int i = 0; i < 8; ++i) nonce[4 + i] = full_nonce[16 + i];
    aad[0] = (uint8_t)((uint32_t)shard_index >> 24);
    aad[1] = (uint8_t)((uint32_t)shard_index >> 16);
    aad[2] = (uint8_t)((uint32_t)shard_index >> 8);
    aad[3] = (uint8_t)shard_index;
    return stage_bridge(
            subkey, nonce, aad, ciphertext, ciphertext_len, tag, plaintext);
}

__attribute__((noinline))
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

__attribute__((noinline))
__attribute__((annotate("+vm_virtualize")))
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
    if (!in || !out_len) {
        return NULL;
    }
    *out_len = 0;
    memset(&zs, 0, sizeof(zs));
    ret = inflateInit(&zs);
    if (ret != Z_OK) {
        return NULL;
    }
    if (in_len > (SIZE_MAX - 4096u) / 4u) {
        inflateEnd(&zs);
        return NULL;
    }
    cap = in_len * 4 + 4096;
    buf = (uint8_t *)malloc(cap);
    if (!buf) {
        inflateEnd(&zs);
        return NULL;
    }
    zs.next_in   = (Bytef *)in;
    zs.avail_in  = (uInt)in_len;
    zs.next_out  = (Bytef *)buf;
    zs.avail_out = (uInt)cap;
    for (;;) {
        ret = inflate(&zs, Z_FINISH);
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            ph_secure_zero(buf, cap);
            free(buf);
            inflateEnd(&zs);
            return NULL;
        }
        used = cap - zs.avail_out;
        if (cap > SIZE_MAX / 2u) {
            ph_secure_zero(buf, used);
            free(buf);
            inflateEnd(&zs);
            return NULL;
        }
        cap *= 2;
        tmp  = (uint8_t *)realloc(buf, cap);
        if (!tmp) {
            ph_secure_zero(buf, used);
            free(buf);
            inflateEnd(&zs);
            return NULL;
        }
        buf = tmp;
        zs.next_out  = (Bytef *)(buf + used);
        zs.avail_out = (uInt)(cap - used);
    }
    *out_len = cap - zs.avail_out;
    inflateEnd(&zs);
    return buf;
}

/*
 * Direct DEX backing store.
 *
 * ART may lazily resolve classes from InMemoryDexClassLoader after its
 * constructor returns, so successful direct mappings must remain valid for the
 * class-loader lifetime. They are read-only and MADV_DONTDUMP; failed loads and
 * library teardown securely wipe and unmap them.
 */
#define PH_MAX_DIRECT_DEX_MAPS 64
typedef struct {
    void  *base;
    size_t map_len;
    size_t data_len;
} ph_direct_dex_map_t;

static ph_direct_dex_map_t g_direct_dex_maps[PH_MAX_DIRECT_DEX_MAPS];
static volatile unsigned int g_direct_dex_count = 0;

__attribute__((annotate("+vm_virtualize,-vm_flatten")))
static __attribute__((noinline)) int ph_stage_policy_vm(size_t data_len, size_t map_len) {
    if (data_len < 112) return 0;
    if (data_len > MAX_SZ) return 0;
    size_t padded_len = data_len + 4095u;
    if (padded_len < data_len) return 0;
    padded_len &= ~(size_t)4095u;
    if (map_len != padded_len) return 0;
    return 1;
}

static __attribute__((noinline)) void ph_wipe_unmap_direct(
        void *base, size_t map_len) {
    if (!base || base == MAP_FAILED || map_len == 0) return;
    if (vm_mprotect(base, map_len, PROT_READ | PROT_WRITE) == 0) {
        ph_secure_zero(base, map_len);
        vm_madvise(base, map_len, MADV_DONTNEED);
    }
    vm_munmap(base, map_len);
}

static __attribute__((noinline)) void ph_release_direct_dex_maps(void) {
    unsigned int count = g_direct_dex_count;
    if (count > PH_MAX_DIRECT_DEX_MAPS) count = PH_MAX_DIRECT_DEX_MAPS;
    for (unsigned int i = 0; i < count; ++i) {
        ph_wipe_unmap_direct(g_direct_dex_maps[i].base,
                             g_direct_dex_maps[i].map_len);
        g_direct_dex_maps[i].base = NULL;
        g_direct_dex_maps[i].map_len = 0;
        g_direct_dex_maps[i].data_len = 0;
    }
    g_direct_dex_count = 0;
}

__attribute__((destructor))
static void ph_direct_dex_destructor(void) {
    ph_release_direct_dex_maps();
}

/*
 * Probe through the actual parent class loader rather than FindClass(), whose
 * result depends on the native caller's loader context. A normal
 * ClassNotFoundException is expected and cleared; a returned Class proves the
 * Xposed bridge is present in this process.
 */
static __attribute__((noinline)) void detect_java_xposed_bridge(
        JNIEnv *env, jobject parent_cl) {
    PH_LOGI("class-loader probe: begin");
    if (!env || !parent_cl) {
        PH_NUKE("missing class loader for hook probe");
        nuke_app();
    }
    jclass loader_cls = (*env)->GetObjectClass(env, parent_cl);
    if (!loader_cls || (*env)->ExceptionCheck(env)) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        PH_NUKE("cannot inspect application class loader");
        nuke_app();
    }
    jmethodID load_class = (*env)->GetMethodID(
            env, loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load_class || (*env)->ExceptionCheck(env)) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, loader_cls);
        PH_NUKE("cannot resolve class loader probe");
        nuke_app();
    }

    char name[48];
    name[0]='d'; name[1]='e'; name[2]='.'; name[3]='r'; name[4]='o';
    name[5]='b'; name[6]='v'; name[7]='.'; name[8]='a'; name[9]='n';
    name[10]='d'; name[11]='r'; name[12]='o'; name[13]='i'; name[14]='d';
    name[15]='.'; name[16]='x'; name[17]='p'; name[18]='o'; name[19]='s';
    name[20]='e'; name[21]='d'; name[22]='.'; name[23]='X'; name[24]='p';
    name[25]='o'; name[26]='s'; name[27]='e'; name[28]='d'; name[29]='B';
    name[30]='r'; name[31]='i'; name[32]='d'; name[33]='g'; name[34]='e';
    name[35]='\0';

    jstring target = (*env)->NewStringUTF(env, name);
    PH_ZERO(name, sizeof(name));
    if (!target || (*env)->ExceptionCheck(env)) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, loader_cls);
        PH_NUKE("cannot create hook probe");
        nuke_app();
    }

    jobject found = (*env)->CallObjectMethod(env, parent_cl, load_class, target);
    jthrowable thrown = NULL;
    if ((*env)->ExceptionCheck(env)) {
        thrown = (*env)->ExceptionOccurred(env);
        (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, target);
    (*env)->DeleteLocalRef(env, loader_cls);
    if (found) {
        (*env)->DeleteLocalRef(env, found);
        if (thrown) (*env)->DeleteLocalRef(env, thrown);
        PH_NUKE("Xposed bridge class present");
        nuke_app();
    }
    if (thrown) {
        char cnfe_name[33];
        cnfe_name[0]='j'; cnfe_name[1]='a'; cnfe_name[2]='v'; cnfe_name[3]='a';
        cnfe_name[4]='/'; cnfe_name[5]='l'; cnfe_name[6]='a'; cnfe_name[7]='n';
        cnfe_name[8]='g'; cnfe_name[9]='/'; cnfe_name[10]='C'; cnfe_name[11]='l';
        cnfe_name[12]='a'; cnfe_name[13]='s'; cnfe_name[14]='s';
        cnfe_name[15]='N'; cnfe_name[16]='o'; cnfe_name[17]='t';
        cnfe_name[18]='F'; cnfe_name[19]='o'; cnfe_name[20]='u';
        cnfe_name[21]='n'; cnfe_name[22]='d'; cnfe_name[23]='E';
        cnfe_name[24]='x'; cnfe_name[25]='c'; cnfe_name[26]='e';
        cnfe_name[27]='p'; cnfe_name[28]='t'; cnfe_name[29]='i';
        cnfe_name[30]='o'; cnfe_name[31]='n'; cnfe_name[32]='\0';
        jclass cnfe = (*env)->FindClass(env, cnfe_name);
        PH_ZERO(cnfe_name, sizeof(cnfe_name));
        int expected_absence = cnfe && (*env)->IsInstanceOf(env, thrown, cnfe);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        if (cnfe) (*env)->DeleteLocalRef(env, cnfe);
        (*env)->DeleteLocalRef(env, thrown);
        if (!expected_absence) {
            PH_NUKE("class loader hook probe failed");
            nuke_app();
        }
    }
    /* ClassNotFoundException is the expected clean-device result. */
    PH_LOGI("class-loader probe: pass");
}

// ?
// nativeLoadShards -- sole DEX-loading JNI entry-point
//
// Decrypts all shards into private native mappings, transitions those mappings
// to read-only, constructs InMemoryDexClassLoader from direct ByteBuffers, and
// returns only the ClassLoader. No plaintext-returning or Java byte[] DEX path
// exists in this translation unit.
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
    PH_LOGI("nativeLoadShards: enter");
    if (!ph_load_begin()) {
        PH_LOGE("nativeLoadShards: rejected re-entry/state=%d", g_ph_load_state);
        return NULL;
    }
    PH_LOGI("nativeLoadShards: load state entered");
    detect_general_dumper_before_decrypt();
    PH_LOGI("nativeLoadShards: pre-decrypt gate passed");
    detect_java_xposed_bridge(env, j_parent_cl);
    PH_LOGI("nativeLoadShards: class-loader probe passed");

    jobject  result_cl    = NULL;
    uint8_t  salt[16]     = {0};
    uint8_t  pkg_hash[32] = {0};
    uint8_t  key[16]      = {0};

    ph_direct_dex_map_t pending_maps[PH_MAX_DIRECT_DEX_MAPS];
    int        n_pending_maps = 0;
    int        i;
    for (i = 0; i < 64; i++) {
        pending_maps[i].base = NULL;
        pending_maps[i].map_len = 0;
        pending_maps[i].data_len = 0;
    }

    /* ── 1. Salt ──────────────────────────────────────────────────────────── */
    if (!j_salt) {
        PH_LOGE("nativeLoadShards: missing salt");
        goto cleanup;
    }
    {
        jint salt_len = (*env)->GetArrayLength(env, j_salt);
        if (salt_len != 16) {
            PH_LOGE("nativeLoadShards: invalid salt length=%d", salt_len);
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: salt length validated");
    }
    (*env)->GetByteArrayRegion(env, j_salt, 0, 16, (jbyte *)salt);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        PH_LOGE("nativeLoadShards: salt read failed");
        goto cleanup;
    }
    {
        int blk = (salt[0] & 0x80) != 0;
        salt[0] &= 0x7F;
        g_block_rooted = blk;
        if (blk) {
            PH_LOGI("nativeLoadShards: rooted-device blocking enabled");
            check_rooted();
        }
    }
    PH_LOGI("nativeLoadShards: salt policy processed");

    /* ── 2. Package name hash ─────────────────────────────────────────────── */
    if (j_pkg_name_utf8) {
        jint pl = (*env)->GetArrayLength(env, j_pkg_name_utf8);
        if (pl > 0 && pl <= 512) {
            PH_LOGI("nativeLoadShards: package name length=%d", pl);
            uint8_t pb[512];
            (*env)->GetByteArrayRegion(env, j_pkg_name_utf8, 0, pl, (jbyte *)pb);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                ph_secure_zero(pb, sizeof(pb));
                PH_LOGE("nativeLoadShards: package name read failed");
                goto cleanup;
            }
            detect_blackdex_before_decrypt(pb, (size_t)pl);
            sha256(pb, (size_t)pl, pkg_hash);
            memset(pb, 0, sizeof(pb));
        } else {
            PH_LOGE("nativeLoadShards: invalid package name length=%d", pl);
            goto cleanup;
        }
    } else {
        PH_LOGE("nativeLoadShards: missing package name");
        goto cleanup;
    }
    arx_kdf(salt, pkg_hash, key);
    PH_LOGI("nativeLoadShards: key derivation complete");
    if (!ph_load_advance(PH_LOAD_ENVIRONMENT, PH_LOAD_KEY_READY)) {
        PH_LOGE("nativeLoadShards: invalid state after key derivation");
        goto cleanup;
    }
    PH_LOGI("nativeLoadShards: key-ready state entered");

    /* ── 3. Validate shard array ──────────────────────────────────────────── */
    if (!j_enc_shards) {
        PH_LOGE("nativeLoadShards: missing shard array");
        goto cleanup;
    }
    {
        jint sc = (*env)->GetArrayLength(env, j_enc_shards);
        if (sc <= 0 || sc > 64) {
            PH_LOGE("nativeLoadShards: invalid shard count=%d", sc);
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: shard count=%d", sc);
        if (!ph_load_advance(PH_LOAD_KEY_READY, PH_LOAD_SHARDS_LOADING)) {
            PH_LOGE("nativeLoadShards: invalid state before shards");
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: shard-loading state entered");

        /* ── 4. Resolve JNI classes and methods ───────────────────────────── */
        jclass bb_cl = (*env)->FindClass(env, "java/nio/ByteBuffer");
        if (!bb_cl) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: ByteBuffer class lookup failed");
            goto cleanup;
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: ByteBuffer lookup raised exception");
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: ByteBuffer class resolved");

        jclass imdcl = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
        if (!imdcl) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: InMemoryDexClassLoader lookup failed");
            goto cleanup;
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: InMemoryDexClassLoader lookup raised exception");
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: InMemoryDexClassLoader resolved");

        jmethodID ctor = (*env)->GetMethodID(env, imdcl, "<init>",
                             "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        if (!ctor) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: class-loader constructor lookup failed");
            goto cleanup;
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: constructor lookup raised exception");
            goto cleanup;
        }

        jobjectArray bufs = (*env)->NewObjectArray(env, sc, bb_cl, NULL);
        if (!bufs) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: ByteBuffer array allocation failed");
            goto cleanup;
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: ByteBuffer array allocation raised exception");
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: JNI loader objects ready");

        /* ── 5. Decrypt each shard — plaintext stays inside this JNI call ── */
        for (i = 0; i < sc; i++) {
            PH_LOGI("nativeLoadShards: shard %d begin", i);
            /*
             * Re-check between shards. The entry-point gate protects the
             * initial key derivation; this closes the gap where a dumper
             * attaches while a multi-shard load is still in progress.
             */
            detect_general_dumper_before_decrypt();

            uint8_t *enc_buf = NULL, *aead_buf = NULL;
            uint8_t *inter_buf = NULL, *plain_buf = NULL;
            size_t   aead_len = 0, inter_len = 0, plain_len = 0;

            jbyteArray j_enc = (jbyteArray)(*env)->GetObjectArrayElement(env, j_enc_shards, i);
            if (!j_enc || (*env)->ExceptionCheck(env)) {
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                PH_LOGE("nativeLoadShards: shard %d lookup failed", i);
                goto cleanup;
            }
            jint enc_len = (*env)->GetArrayLength(env, j_enc);
            if (enc_len < 40) {
                PH_LOGE("nativeLoadShards: shard %d invalid encrypted length=%d", i, enc_len);
                (*env)->DeleteLocalRef(env, j_enc);
                goto cleanup;
            }
            PH_LOGI("nativeLoadShards: shard %d encrypted length=%d", i, enc_len);

            enc_buf = (uint8_t *)malloc((size_t)enc_len);
            if (!enc_buf) {
                PH_LOGE("nativeLoadShards: shard %d encrypted allocation failed", i);
                (*env)->DeleteLocalRef(env, j_enc);
                goto cleanup;
            }
            (*env)->GetByteArrayRegion(env, j_enc, 0, enc_len, (jbyte *)enc_buf);
            (*env)->DeleteLocalRef(env, j_enc);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                PH_LOGE("nativeLoadShards: shard %d encrypted read failed", i);
                ph_secure_zero(enc_buf, (size_t)enc_len);
                free(enc_buf);
                goto cleanup;
            }

            /*
             * Universal authenticated envelope:
             * [24-byte nonce][ciphertext][16-byte Poly1305 tag].
             * The shard index is authenticated as four-byte big-endian AAD.
             */
            aead_len = (size_t)enc_len - 24u - 16u;
            if (aead_len == 0) {
                PH_LOGE("nativeLoadShards: shard %d empty authenticated payload", i);
                ph_secure_zero(enc_buf, (size_t)enc_len);
                free(enc_buf);
                goto cleanup;
            }
            aead_buf = (uint8_t *)malloc(aead_len);
            if (!aead_buf) {
                PH_LOGE("nativeLoadShards: shard %d authenticated allocation failed", i);
                ph_secure_zero(enc_buf, (size_t)enc_len);
                free(enc_buf);
                goto cleanup;
            }
            int stage_ok = stage_decrypt(
                    i,
                    enc_buf,
                    enc_buf + 24,
                    aead_len,
                    enc_buf + 24 + aead_len,
                    aead_buf);
            if (!stage_ok) {
                PH_LOGE("nativeLoadShards: shard %d authenticated decrypt failed", i);
                ph_secure_zero(enc_buf, (size_t)enc_len);
                free(enc_buf);
                ph_secure_zero(aead_buf, aead_len);
                free(aead_buf);
                goto cleanup;
            }
            ph_secure_zero(enc_buf, (size_t)enc_len);
            free(enc_buf);
            PH_LOGI("nativeLoadShards: shard %d authenticated decrypt passed", i);

            /* Outer inflate */
            inter_buf = inflate_alloc(aead_buf, aead_len, &inter_len);
            ph_secure_zero(aead_buf, aead_len);
            free(aead_buf);
            if (!inter_buf) {
                PH_LOGE("nativeLoadShards: shard %d outer inflate failed", i);
                goto cleanup;
            }
            PH_LOGI("nativeLoadShards: shard %d outer inflate length=%zu", i, inter_len);

            /* ARX XOR */
            { arx_ctx_t arx; arx_ctx_init(&arx, key); arx_xor(&arx, inter_buf, inter_len);
              memset(&arx, 0, sizeof(arx)); }

            /* Inner inflate */
            plain_buf = inflate_alloc(inter_buf, inter_len, &plain_len);
            ph_secure_zero(inter_buf, inter_len); free(inter_buf);
            if (!plain_buf) {
                PH_LOGE("nativeLoadShards: shard %d inner inflate failed", i);
                goto cleanup;
            }

            if (plain_len > (size_t)INT32_MAX) {
                PH_LOGE("nativeLoadShards: shard %d plaintext too large=%zu", i, plain_len);
                ph_secure_zero(plain_buf, plain_len); free(plain_buf);
                goto cleanup;
            }
            PH_LOGI("nativeLoadShards: shard %d plaintext length=%zu", i, plain_len);

            /*
             * Plaintext moves from the temporary inflate
             * allocation into a private native mapping, not a Java byte[].
             */
            size_t map_len = (plain_len + 4095u) & ~(size_t)4095u;
            if (!ph_stage_policy_vm(plain_len, map_len)) {
                PH_LOGE("nativeLoadShards: shard %d stage policy rejected data=%zu map=%zu",
                        i, plain_len, map_len);
                ph_secure_zero(plain_buf, plain_len); free(plain_buf);
                goto cleanup;
            }
            void *dex_map = vm_mmap_private_rw(map_len);
            if (dex_map == MAP_FAILED) {
                PH_LOGE("nativeLoadShards: shard %d native mapping failed length=%zu",
                        i, map_len);
                ph_secure_zero(plain_buf, plain_len); free(plain_buf);
                goto cleanup;
            }
            memcpy(dex_map, plain_buf, plain_len);
            ph_secure_zero(plain_buf, plain_len); free(plain_buf);
            plain_buf = NULL;
            vm_madvise(dex_map, map_len, MADV_DONTDUMP);
#ifdef MADV_DONTFORK
            vm_madvise(dex_map, map_len, MADV_DONTFORK);
#endif
            if (vm_mprotect(dex_map, map_len, PROT_READ) != 0) {
                PH_LOGE("nativeLoadShards: shard %d read-only transition failed", i);
                ph_wipe_unmap_direct(dex_map, map_len);
                goto cleanup;
            }
            PH_LOGI("nativeLoadShards: shard %d native mapping ready length=%zu", i, map_len);

            jobject bb = (*env)->NewDirectByteBuffer(
                    env, dex_map, (jlong)plain_len);
            if (!bb || (*env)->ExceptionCheck(env)) {
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                PH_LOGE("nativeLoadShards: shard %d direct buffer creation failed", i);
                ph_wipe_unmap_direct(dex_map, map_len);
                goto cleanup;
            }
            pending_maps[n_pending_maps].base = dex_map;
            pending_maps[n_pending_maps].map_len = map_len;
            pending_maps[n_pending_maps].data_len = plain_len;
            ++n_pending_maps;
            (*env)->SetObjectArrayElement(env, bufs, i, bb);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                (*env)->DeleteLocalRef(env, bb);
                PH_LOGE("nativeLoadShards: shard %d buffer array insertion failed", i);
                goto cleanup;
            }
            (*env)->DeleteLocalRef(env, bb);
            PH_LOGI("nativeLoadShards: shard %d ready", i);
        }

        if (!ph_load_advance(PH_LOAD_SHARDS_LOADING, PH_LOAD_CLASSLOADER)) {
            PH_LOGE("nativeLoadShards: invalid state before class-loader construction");
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: constructing InMemoryDexClassLoader");

        /* ── 6. new InMemoryDexClassLoader(bufs, parent)
                  ART parses + mmaps every DEX synchronously inside this call.
                  Hooking this return gets only a ClassLoader — not a byte[]. ── */
        result_cl = (*env)->NewObject(env, imdcl, ctor, bufs, j_parent_cl);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            PH_LOGE("nativeLoadShards: InMemoryDexClassLoader constructor raised exception");
            result_cl = NULL;
        }
        if (!result_cl) {
            PH_LOGE("nativeLoadShards: class-loader construction failed");
            goto cleanup;
        }
        PH_LOGI("nativeLoadShards: class-loader constructed");
        if (!ph_load_advance(PH_LOAD_CLASSLOADER, PH_LOAD_COMPLETE)) {
            if (result_cl) (*env)->DeleteLocalRef(env, result_cl);
            result_cl = NULL;
            PH_LOGE("nativeLoadShards: invalid state after class-loader construction");
            goto cleanup;
        }

        /*
         * Commit successful backing mappings only after ART accepted every
         * shard. The one-shot loader state prevents concurrent commits.
         */
        if (g_direct_dex_count != 0 ||
            n_pending_maps != sc ||
            n_pending_maps > PH_MAX_DIRECT_DEX_MAPS) {
            (*env)->DeleteLocalRef(env, result_cl);
            result_cl = NULL;
            PH_LOGE("nativeLoadShards: mapping commit validation failed pending=%d shards=%d",
                    n_pending_maps, sc);
            goto cleanup;
        }
        for (i = 0; i < n_pending_maps; ++i) {
            g_direct_dex_maps[i] = pending_maps[i];
            pending_maps[i].base = NULL;
            pending_maps[i].map_len = 0;
            pending_maps[i].data_len = 0;
        }
        g_direct_dex_count = (unsigned int)n_pending_maps;
        PH_LOGI("nativeLoadShards: committed %d live native mappings", n_pending_maps);
    }

cleanup:
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    for (i = 0; i < n_pending_maps; ++i) {
        if (pending_maps[i].base) {
            ph_wipe_unmap_direct(pending_maps[i].base,
                                 pending_maps[i].map_len);
            pending_maps[i].base = NULL;
        }
    }
    ph_secure_zero(pending_maps, sizeof(pending_maps));
    ph_secure_zero(salt,     sizeof(salt));
    ph_secure_zero(pkg_hash, sizeof(pkg_hash));
    ph_secure_zero(key,      sizeof(key));
    if (!result_cl) {
        PH_LOGE("nativeLoadShards: failed; cleanup complete");
        ph_load_fail();
    } else {
        PH_LOGI("nativeLoadShards: success; cleanup complete");
    }
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
    PH_LOGI("provider patch: begin");
    /* ActivityThread.mProviderMap — ArrayMap<String, ProviderClientRecord> */
    jclass atCls2 = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!atCls2) {
        (*env)->ExceptionClear(env);
        PH_LOGE("provider patch: ActivityThread lookup failed");
        return;
    }
    jfieldID mProvMapFid = (*env)->GetFieldID(env, atCls2,
            "mProviderMap", "Landroid/util/ArrayMap;");
    (*env)->DeleteLocalRef(env, atCls2);
    if (!mProvMapFid) {
        (*env)->ExceptionClear(env);
        PH_LOGE("provider patch: mProviderMap lookup failed");
        return;
    }

    jobject provMap = (*env)->GetObjectField(env, activityThread, mProvMapFid);
    if (!provMap) {
        PH_LOGI("provider patch: no providers");
        return;
    }

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
    PH_LOGI("provider patch: records=%d", len);
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
    PH_LOGI("provider patch: complete");
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
    jobject result = NULL;
    PH_LOGI("nativeSwapApplication: enter");

    /* ── ActivityThread ──────────────────────────────────────────────────── */
    jclass atCls = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!atCls) {
        (*env)->ExceptionClear(env);
        PH_LOGE("nativeSwapApplication: ActivityThread lookup failed");
        return NULL;
    }

    jmethodID curThreadMid = (*env)->GetStaticMethodID(env, atCls,
            "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (!curThreadMid) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, atCls);
        PH_LOGE("nativeSwapApplication: currentActivityThread lookup failed");
        return NULL;
    }

    jobject thread = (*env)->CallStaticObjectMethod(env, atCls, curThreadMid);
    if (!thread || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, atCls);
        PH_LOGE("nativeSwapApplication: currentActivityThread call failed");
        return NULL;
    }
    PH_LOGI("nativeSwapApplication: ActivityThread resolved");

    /* ── AppBindData → LoadedApk ─────────────────────────────────────────── */
    jclass abdCls = (*env)->FindClass(env, "android/app/ActivityThread$AppBindData");
    jfieldID mBoundFid = (*env)->GetFieldID(env, atCls, "mBoundApplication",
            "Landroid/app/ActivityThread$AppBindData;");
    if (!abdCls || !mBoundFid) {
        (*env)->ExceptionClear(env);
        if (abdCls) (*env)->DeleteLocalRef(env, abdCls); /* avoid local ref leak */
        PH_LOGE("nativeSwapApplication: AppBindData lookup failed");
        goto done;
    }
    jobject mBoundApp = (*env)->GetObjectField(env, thread, mBoundFid);

    jfieldID infoFid = (*env)->GetFieldID(env, abdCls, "info", "Landroid/app/LoadedApk;");
    if (!infoFid) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, abdCls); goto done; }
    jobject loadedApk = (*env)->GetObjectField(env, mBoundApp, infoFid);
    if (!mBoundApp || !loadedApk) {
        (*env)->DeleteLocalRef(env, abdCls);
        PH_LOGE("nativeSwapApplication: LoadedApk lookup failed");
        goto done;
    }
    PH_LOGI("nativeSwapApplication: LoadedApk resolved");

    jfieldID bindAppInfoFid = (*env)->GetFieldID(env, abdCls, "appInfo",
            "Landroid/content/pm/ApplicationInfo;");
    jobject bindDataAppInfo = (bindAppInfoFid && !(*env)->ExceptionCheck(env))
            ? (*env)->GetObjectField(env, mBoundApp, bindAppInfoFid) : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, abdCls);

    /* ── LoadedApk fields ────────────────────────────────────────────────── */
    jclass laCls = (*env)->FindClass(env, "android/app/LoadedApk");
    if (!laCls) {
        (*env)->ExceptionClear(env);
        PH_LOGE("nativeSwapApplication: LoadedApk class lookup failed");
        goto done;
    }

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
    PH_LOGI("nativeSwapApplication: creating real Application");
    if (instrCls) {
        jmethodID newAppMid = (*env)->GetMethodID(env, instrCls, "newApplication",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)"
                "Landroid/app/Application;");
        if (newAppMid && instr) {
            realApp = (*env)->CallObjectMethod(env, instr, newAppMid,
                    classLoader, realAppClass, baseContext);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                PH_LOGE("nativeSwapApplication: Instrumentation.newApplication failed");
                realApp = NULL;
            }
        } else { (*env)->ExceptionClear(env); }
        (*env)->DeleteLocalRef(env, instrCls);
    } else { (*env)->ExceptionClear(env); }

    /* Fallback: LoadedApk.makeApplication(false, null) */
    if (!realApp) {
        PH_LOGI("nativeSwapApplication: trying LoadedApk.makeApplication fallback");
        if (mAppFid) (*env)->SetObjectField(env, loadedApk, mAppFid, NULL);
        jmethodID makeAppMid = (*env)->GetMethodID(env, laCls, "makeApplication",
                "(ZLandroid/app/Instrumentation;)Landroid/app/Application;");
        if (makeAppMid) {
            realApp = (*env)->CallObjectMethod(env, loadedApk, makeAppMid, JNI_FALSE, NULL);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                PH_LOGE("nativeSwapApplication: makeApplication fallback failed");
                realApp = NULL;
            }
        } else { (*env)->ExceptionClear(env); }
        if (realApp) {
            PH_LOGI("nativeSwapApplication: fallback created real Application");
            if (mInitFid) (*env)->SetObjectField(env, thread, mInitFid, realApp);
            ph_patch_providers_native(env, thread, realApp);
            result = (*env)->NewGlobalRef(env, realApp);
        }
        (*env)->DeleteLocalRef(env, laCls);
        goto done;
    }
    PH_LOGI("nativeSwapApplication: real Application created");


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

    (*env)->DeleteLocalRef(env, laCls);

done:
    (*env)->DeleteLocalRef(env, atCls);
    (*env)->DeleteLocalRef(env, thread);
    /* Return local ref — caller (Java) owns this reference */
    if (result) {
        PH_LOGI("nativeSwapApplication: success");
        jobject local = (*env)->NewLocalRef(env, result);
        (*env)->DeleteGlobalRef(env, result);
        return local;
    }
    PH_LOGE("nativeSwapApplication: failed");
    return NULL;
}
