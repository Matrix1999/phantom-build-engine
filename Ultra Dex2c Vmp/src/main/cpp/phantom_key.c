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
#include "phantom_cipher.h"
#include "phantom_pstrings.inc"

// ── Debug logging — ENABLED (adb logcat -s d2cg)
// PH_LOG / PH_NUKE use non-varargs bridges so amice can VM-virtualize callers.
// __android_log_print is variadic — amice bails on varargs at the call site.
// __android_log_write is a plain non-varargs call that amice handles fine.
// Format args (e.g. %d, %s) are intentionally dropped in VM-safe path;
// the message string itself identifies which check fired.
// Disable for release: replace vm_log_d/vm_log_w bodies with ((void)0).
#define PH_NUKE(reason, ...) nuke_app()
/* Forward declarations — defined near the other vm_* bridges below. */
static void vm_log_d(const char *msg);
static void vm_log_w(const char *msg);
// ─────────────────────────────────────────────────────────────────────────────

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
/* Non-varargs log bridges — amice lifts callers; varargs __android_log_print
   would cause it to bail on every detection function. */
static __attribute__((noinline)) void vm_log_d(const char *msg)
    { __android_log_write(ANDROID_LOG_DEBUG, "d2cg", msg); }
static __attribute__((noinline)) void vm_log_w(const char *msg)
    { __android_log_write(ANDROID_LOG_WARN,  "d2cg", msg); }

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
            vm_fstatat(AT_FDCWD, filePath, &filestat, AT_SYMLINK_NOFOLLOW);
            if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                char buf[MAX_LENGTH] = "";
                vm_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
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
}

// ?
// detect_frida_loop -- 5-second cadence
// Frida thread names, named pipes, binary checksums, ptrace, eBPF uprobes.
// ?

/* g_block_rooted — set to 1 the first time nativeDecryptShard reads
   salt[0] bit-7 == 1 (block-rooted toggle ON).  Starts at 0 so that
   detect_root() and detect_riru_zygisk() in the background loop are
   suppressed until the salt is read and the flag is known.
   Declared volatile so the compiler does not cache it across loop iterations. */
static volatile int g_block_rooted = 0;

__attribute__((annotate("+vm_virtualize")))
static __attribute__((noinline)) void *detect_frida_loop(void *args) {
    (void)args;
    struct timespec timereq;
    timereq.tv_sec  = 5;
    timereq.tv_nsec = 0;
    while (1) {
        detect_frida_threads();                   // JDWP + per-task TracerPid + gum-js-loop/gmain
        detect_frida_namedpipe();
        detect_frida_websocket();                 // WebSocket fingerprint: tyZql/Y8dNFFyopTrHadWzvbvRs=
        detect_ptrace();
        detect_ebpf_uprobe();
        if (g_block_rooted) detect_riru_zygisk();  // Riru/Zygisk/Xposed: maps + phdr + paths — only if toggle ON
        if (g_block_rooted) detect_root();        // su binaries + Magisk mounts — only if toggle ON
        vm_nanosleep(&timereq, NULL);
    }
    return NULL;
}
/* check_rooted — called from nativeDecryptShard when salt[0] bit-7 == 1. */
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
    vm_prctl(PR_SET_DUMPABLE, 0);
    vm_spawn_watcher();
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

    PH_AES(_maps, PROC_MAPS);
    int fd = vm_openat(AT_FDCWD, _maps, O_RDONLY | O_CLOEXEC, 0);
    PH_ZERO(_maps, SP_BUF_SZ);
    if (fd < 0) return;

    char line[MAX_LINE];
    while (vm_read_one_line(fd, line, MAX_LINE) > 0) {
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
            if (vm_mprotect(ptr, 4096, PROT_READ | PROT_WRITE) != 0) continue;
        }

        // Zero DEX magic + version string (bytes 0-7): e.g. "dex\n035\0"
        my_memset(ptr, 0, 8);
        // Zero endian_tag (bytes 40-43): 0x12345678 little-endian
        my_memset(ptr + 40, 0, 4);

        // Restore original permissions
        if (was_ro) vm_mprotect(ptr, 4096, PROT_READ);
    }
    vm_close(fd);
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

/* Step A: expand message schedule into caller-supplied w[64] */
__attribute__((noinline))
__attribute__((annotate("+vm_virtualize")))
static void _sha_expand(uint32_t *w, const uint8_t *data) {
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

/* Step B: 64-round compression; w and K256 accessed via pointer loads only */
__attribute__((noinline))
__attribute__((annotate("+vm_virtualize")))
static void _sha_compress(uint32_t *h, const uint32_t *w) {
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
    vm_prctl(PR_SET_DUMPABLE, 0);

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
        g_block_rooted = blk;
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
        PH_AES(_maps2, PROC_MAPS);
        int mfd = vm_openat(AT_FDCWD, _maps2, O_RDONLY | O_CLOEXEC, 0);
        PH_ZERO(_maps2, SP_BUF_SZ);
        if (mfd >= 0) {
            char ml[MAX_LINE];
            while (vm_read_one_line(mfd, ml, MAX_LINE) > 0) {
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
                if (ro && vm_mprotect(ptr, 4096, PROT_READ|PROT_WRITE) != 0) continue;
                my_memset(ptr, 0, 8);
                if ((me - ms) > 44) my_memset(ptr + 40, 0, 4);
                if (ro) vm_mprotect(ptr, 4096, PROT_READ);
            }
            vm_close(mfd);
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
        }
        (*env)->DeleteLocalRef(env, laCls);
        goto done;
    }


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
    vm_prctl(PR_SET_DUMPABLE, 0);

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
        salt[0] &= 0x7F;          /* clear flag bit — KDF uses clean salt */
        g_block_rooted = block_rooted;  /* tell background loop */
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
