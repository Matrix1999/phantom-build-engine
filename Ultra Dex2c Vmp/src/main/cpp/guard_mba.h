// guard_mba.h — Mixed Boolean Arithmetic (MBA) helpers for sensitive constants.
//
// PURPOSE
// ───────
// OLLVM's control-flow passes (-fla, -bcf, -split) hide logic.
// OLLVM's -sub pass hides *arithmetic* inside functions.
// But NEITHER hides a compile-time integer literal fed directly to a register:
//
//   register long _x2 asm("x2") = 9L;   →   MOVZ X2, #9   ← trivially patchable
//
// This header closes that gap:
//  • Every sensitive integer constant is returned by a __attribute__((noinline))
//    function whose body contains only runtime-computable expressions.
//  • Because the functions are noinline, the compiler cannot propagate their
//    return values as constants into callers.
//  • Because OLLVM's -sub_loop=3 runs on these functions, the arithmetic inside
//    is further transformed into MBA chains — no recognisable constant emitted.
//  • The call sites see only a BL/BLR instruction; no literal operand.
//
// USAGE
// ─────
//   #include "guard_mba.h"
//
//   // Instead of:   register long _x2 asm("x2") = 9L;
//   volatile long _sig = _mba_sigkill();
//   register long _x2 asm("x2") = _sig;
//
// OLLVM flags required in CMakeLists.txt (applied to guard.cpp):
//   -mllvm -sub -mllvm -sub_loop=3
//   -mllvm -bcf -mllvm -bcf_loop=2
//   -mllvm -fla -mllvm -split
//
// ════════════════════════════════════════════════════════════════════════════

#pragma once
#include <stdint.h>

// ── SIGKILL = 9 ─────────────────────────────────────────────────────────────
// Expressed as (0xF | 0x6) - (0xF & 0x6) = 15 - 6 = 9  (MBA XOR form)
// With -sub_loop=3 the subtraction itself gets further substituted.
static __attribute__((noinline)) long _mba_sigkill(void) {
    volatile uint32_t _a = 0xFu, _b = 0x6u;
    uint32_t _r = (_a | _b) - (_a & _b);   // MBA: a XOR b = (a|b)-(a&b)
    return (long)_r;                         // = 9, but no MOVZ #9 in binary
}

static __attribute__((noinline)) int _mba_sigkill32(void) {
    volatile uint32_t _a = 0xFu, _b = 0x6u;
    return (int)((_a | _b) - (_a & _b));    // = 9
}

// ── __NR_tgkill ARM64 = 131 ──────────────────────────────────────────────────
// 131 = 0x80 XOR 0x03 expressed as MBA: (0x80|0x03) - (0x80&0x03) = 0x83-0 = 131
// Then +0: ((a|b)-(a&b)) with a=0x80, b=0x03 → 0x83 = 131
static __attribute__((noinline)) long _mba_nr_tgkill64(void) {
    volatile uint32_t _hi = 0x80u;          // 128
    volatile uint32_t _lo = 0x03u;          // 3
    return (long)((_hi | _lo) - (_hi & _lo)); // = 131, no MOVZ #131
}

// ── __NR_tgkill ARM32 = 268 ──────────────────────────────────────────────────
// 268 = 256 + 12  →  MBA: 256 = (0x100|0)-(0x100&0) = 256;  then +12
static __attribute__((noinline)) int _mba_nr_tgkill32(void) {
    volatile uint32_t _hi = 0x100u;         // 256
    volatile uint32_t _lo = 0x0Cu;          // 12
    return (int)(_hi + _lo);                // = 268, no MOVZ #268
}

// ── __NR_kill ARM64 = 129 ───────────────────────────────────────────────────
// 129 = 0x80 | 0x01 = (0x80|0x01)-(0x80&0x01) = 0x81 = 129
static __attribute__((noinline)) long _mba_nr_kill64(void) {
    volatile uint32_t _hi = 0x80u;
    volatile uint32_t _lo = 0x01u;
    return (long)((_hi | _lo) - (_hi & _lo)); // = 129
}

// ── __NR_kill ARM32 = 37 ────────────────────────────────────────────────────
// 37 = 0x20 | 0x05 = (0x20|0x05)-(0x20&0x05) = 0x25 = 37
static __attribute__((noinline)) int _mba_nr_kill32(void) {
    volatile uint32_t _hi = 0x20u;
    volatile uint32_t _lo = 0x05u;
    return (int)((_hi | _lo) - (_hi & _lo)); // = 37
}

// ── G_XOR_KEY = 0xA3 ────────────────────────────────────────────────────────
// 0xA3 = 0xA0 | 0x03:  MBA → (0xA0|0x03)-(0xA0&0x03) = 0xA3 - 0 = 0xA3
static __attribute__((noinline)) uint8_t _mba_xor_key_a3(void) {
    volatile uint32_t _hi = 0xA0u;
    volatile uint32_t _lo = 0x03u;
    return (uint8_t)((_hi | _lo) - (_hi & _lo)); // = 0xA3
}

// ── PSTR_XOR_MASK = 0x5A ────────────────────────────────────────────────────
// 0x5A = 0x50 | 0x0A:  MBA → (0x50|0x0A)-(0x50&0x0A) = 0x5A
static __attribute__((noinline)) uint8_t _mba_xor_mask_5a(void) {
    volatile uint32_t _hi = 0x50u;
    volatile uint32_t _lo = 0x0Au;
    return (uint8_t)((_hi | _lo) - (_hi & _lo)); // = 0x5A
}

// ── VM SO-integrity pulse counter: 0x5E3 ────────────────────────────────────
// 0x5E3 = 0x5C0 + 0x23:  both parts further split so no single literal
// = (0x580 + 0x40) + (0x20 + 0x03) = 0x5C0 + 0x23 = 0x5E3
static __attribute__((noinline)) uint32_t _mba_pulse_val(void) {
    volatile uint32_t _hi = 0x5C0u;         // 1472
    volatile uint32_t _lo = 0x23u;          //   35
    return _hi + _lo;                        // = 0x5E3 = 1507
}

// ── VM pulse AND mask: 0xFFF ─────────────────────────────────────────────────
// ~0u >> 20u = 0x00000FFF — no literal 0xFFF anywhere
static __attribute__((noinline)) uint32_t _mba_pulse_mask(void) {
    volatile uint32_t _all = ~0u;
    volatile uint32_t _sh  = 20u;
    return _all >> _sh;                      // = 0xFFF
}

// ── Sentinel: zero value via MBA (used in safe-path returns) ─────────────────
static __attribute__((noinline)) uint32_t _mba_zero(void) {
    volatile uint32_t _v = 0xFFFFFFFFu;
    return _v ^ _v;                          // = 0, no MOV #0
}

// ── Helper: kill parent via raw SVC (no kill@PLT) ───────────────────────────
// Drop-in replacement for  kill(ppid, SIGKILL)  in the child watchdog.
// Uses SVC #0 directly — no PLT hook surface.
static __attribute__((noinline)) void _mba_kill_via_svc(long pid) {
#if defined(__aarch64__)
    {
        volatile long _sig = _mba_sigkill();
        volatile long _nr  = _mba_nr_kill64();
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
        volatile int _sig = _mba_sigkill32();
        volatile int _nr  = _mba_nr_kill32();
        register int _r7 asm("r7") = _nr;
        register int _r0 asm("r0") = (int)pid;
        register int _r1 asm("r1") = _sig;
        asm volatile("svc #0"
            : "+r"(_r0)
            : "r"(_r1), "r"(_r7)
            : "memory", "cc");
    }
#else
    (void)pid;  // fallback handled by caller
#endif
}
