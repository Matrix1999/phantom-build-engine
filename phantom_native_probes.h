#ifndef PHANTOM_NATIVE_PROBES_H
#define PHANTOM_NATIVE_PROBES_H

#include <stdint.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ucontext.h>
#include "phantom_runtime_checks.h"

#ifdef __clang__
#define PH_PROBE_VM __attribute__((noinline, used, annotate("+vm_virtualize,+vm_flatten")))
#else
#define PH_PROBE_VM __attribute__((noinline, used))
#endif

/* These two instruction sequences must execute on the actual CPU. Lifting
 * them into a software VM would destroy the behavior being measured. All
 * decisions, signal-context validation and context mutation remain VM targets.
 * The assembly has no "pass" flag and is covered by Phantom's executable hash. */
extern unsigned int ph_probe_exclusive_native(volatile unsigned int *word);
extern unsigned int ph_probe_signal_send_native(
        long pid, long tid, int signo, unsigned int nonce);
extern const unsigned char ph_probe_signal_resume_pc[];

#if defined(__aarch64__)
__asm__(
    ".pushsection .text.ph_native_probe,\"ax\",%progbits\n"
    ".balign 4\n"
    ".global ph_probe_exclusive_native\n"
    ".hidden ph_probe_exclusive_native\n"
    ".type ph_probe_exclusive_native,%function\n"
    "ph_probe_exclusive_native:\n"
    "mov x2,x0\n"
    "ldxr w1,[x2]\n"
    "mov x8,#178\n"
    "svc #0\n"
    "stxr w3,w1,[x2]\n"
    "mov w0,w3\n"
    "ret\n"
    ".size ph_probe_exclusive_native,.-ph_probe_exclusive_native\n"
    ".global ph_probe_signal_send_native\n"
    ".hidden ph_probe_signal_send_native\n"
    ".type ph_probe_signal_send_native,%function\n"
    "ph_probe_signal_send_native:\n"
    "mov w12,w3\n"
    "mov w13,#0x5a\n"
    "eor w13,w12,w13\n"
    "mov x8,#131\n" /* tgkill */
    "svc #0\n"
    ".global ph_probe_signal_resume_pc\n"
    ".hidden ph_probe_signal_resume_pc\n"
    "ph_probe_signal_resume_pc:\n"
    "mov w0,w12\n"
    "ret\n"
    ".size ph_probe_signal_send_native,.-ph_probe_signal_send_native\n"
    ".popsection\n");
#elif defined(__arm__)
__asm__(
    ".pushsection .text.ph_native_probe,\"ax\",%progbits\n"
    ".syntax unified\n.arm\n.balign 4\n"
    ".global ph_probe_exclusive_native\n"
    ".hidden ph_probe_exclusive_native\n"
    ".type ph_probe_exclusive_native,%function\n"
    "ph_probe_exclusive_native:\n"
    "push {r4,r5,r7,lr}\n"
    "mov r2,r0\n"
    "ldrex r1,[r2]\n"
    "mov r7,#224\n"
    "svc #0\n"
    "strex r3,r1,[r2]\n"
    "mov r0,r3\n"
    "pop {r4,r5,r7,pc}\n"
    ".size ph_probe_exclusive_native,.-ph_probe_exclusive_native\n"
    ".global ph_probe_signal_send_native\n"
    ".hidden ph_probe_signal_send_native\n"
    ".type ph_probe_signal_send_native,%function\n"
    "ph_probe_signal_send_native:\n"
    "push {r4,r5,r7,lr}\n"
    "mov r12,r3\n"
    "eor r4,r3,#0x5a\n"
    "movw r7,#268\n" /* tgkill */
    "svc #0\n"
    ".global ph_probe_signal_resume_pc\n"
    ".hidden ph_probe_signal_resume_pc\n"
    "ph_probe_signal_resume_pc:\n"
    "mov r0,r12\n"
    "pop {r4,r5,r7,pc}\n"
    ".size ph_probe_signal_send_native,.-ph_probe_signal_send_native\n"
    ".popsection\n");
#elif defined(PH_PROBE_HOST_TEST) && defined(__x86_64__)
/* Host signal-contract test only; never part of an Android release. */
static unsigned int ph_probe_host_exclusive(volatile unsigned int *word) {
    (void)word;
    return 1u;
}
#define ph_probe_exclusive_native ph_probe_host_exclusive
__asm__(
    ".pushsection .text.ph_native_probe,\"ax\",@progbits\n"
    ".global ph_probe_signal_send_native\n"
    ".hidden ph_probe_signal_send_native\n"
    ".type ph_probe_signal_send_native,@function\n"
    "ph_probe_signal_send_native:\n"
    "push %r12\npush %r13\n"
    "mov %ecx,%r12d\n"
    "mov %ecx,%r13d\nxor $0x5a,%r13d\n"
    "mov $234,%eax\nsyscall\n"
    ".global ph_probe_signal_resume_pc\n"
    ".hidden ph_probe_signal_resume_pc\n"
    "ph_probe_signal_resume_pc:\n"
    "mov %r12d,%eax\n"
    "pop %r13\npop %r12\nret\n"
    ".size ph_probe_signal_send_native,.-ph_probe_signal_send_native\n"
    ".popsection\n");
#else
#error Phantom native probes require ARM64 or ARMv7
#endif

typedef struct {
    volatile sig_atomic_t armed;
    volatile sig_atomic_t delivered;
    int signo;
    long pid;
    unsigned int nonce;
    unsigned int token;
    unsigned int setup_ok;
    uintptr_t resume_pc;
} ph_probe_signal_state_t;

static ph_probe_signal_state_t g_ph_probe_signal;
static int g_ph_probe_signal_busy;
static unsigned int g_ph_probe_sequence;

static PH_RUNTIME_NATIVE ph_probe_signal_state_t *ph_probe_signal_state_native(void) {
    return &g_ph_probe_signal;
}

static PH_PROBE_VM int ph_probe_atomic_ok_vm(unsigned int status) {
    return status == 1u;
}

static PH_PROBE_VM unsigned int ph_signal_mix_vm(unsigned int nonce) {
    unsigned int token = ((nonce << 7) | (nonce >> 25)) ^ 0xa5c39e17u;
    /* A no-op syscall must never accidentally produce the accepted token. */
    return token == nonce ? token ^ 1u : token;
}

static PH_PROBE_VM int ph_signal_route_vm(
        ph_probe_signal_state_t *state, int signo, int code, long pid) {
    return state->armed && signo == state->signo &&
           code == SI_TKILL && pid == state->pid;
}

static PH_PROBE_VM int ph_signal_context_vm(
        void *context, ph_probe_signal_state_t *state) {
    if (!context) return 0;
    ucontext_t *uc = (ucontext_t *)context;
#if defined(__aarch64__)
    if (uc->uc_mcontext.regs[12] != state->nonce ||
        uc->uc_mcontext.regs[13] != (state->nonce ^ 0x5au) ||
        uc->uc_mcontext.pc != state->resume_pc || !uc->uc_mcontext.sp ||
        (uc->uc_mcontext.sp & 15u)) return 0;
    uc->uc_mcontext.regs[12] = ph_signal_mix_vm(state->nonce);
#elif defined(__arm__)
    if (uc->uc_mcontext.arm_ip != state->nonce ||
        uc->uc_mcontext.arm_r4 != (state->nonce ^ 0x5au) ||
        uc->uc_mcontext.arm_pc != state->resume_pc || !uc->uc_mcontext.arm_sp ||
        (uc->uc_mcontext.arm_sp & 7u)) return 0;
    uc->uc_mcontext.arm_ip = ph_signal_mix_vm(state->nonce);
#elif defined(PH_PROBE_HOST_TEST) && defined(__x86_64__)
    if ((uint64_t)uc->uc_mcontext.gregs[REG_R12] != state->nonce ||
        (uint64_t)uc->uc_mcontext.gregs[REG_R13] != (state->nonce ^ 0x5au) ||
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP] != state->resume_pc ||
        !uc->uc_mcontext.gregs[REG_RSP])
        return 0;
    uc->uc_mcontext.gregs[REG_R12] = ph_signal_mix_vm(state->nonce);
#endif
    return 1;
}

/* Only arithmetic and preallocated state: no allocation, locks, logging, or
 * libc calls in the signal handler. It is a required VM bytecode target. */
static PH_PROBE_VM void ph_probe_signal_handler_vm(
        int signo, siginfo_t *info, void *context) {
    ph_probe_signal_state_t *state = ph_probe_signal_state_native();
    if (!info) return;
    if (!ph_signal_route_vm(state, signo, info->si_code, info->si_pid)) return;
    if (ph_signal_context_vm(context, state)) state->delivered = 1;
}

/* OS ABI plumbing, not enforcement. A default-disposition, unblocked signal
 * is selected for a bounded self-tgkill; existing handlers and masks
 * are restored. Never intercept ART's SIGSEGV/SIGBUS/SIGQUIT handlers. */
static PH_RUNTIME_NATIVE ph_probe_signal_state_t *ph_probe_signal_round_native(void) {
    if (__sync_lock_test_and_set(&g_ph_probe_signal_busy, 1)) return NULL;
    ph_probe_signal_state_t *state = &g_ph_probe_signal;
    state->armed = 0;
    state->delivered = 0;
    state->setup_ok = 0;
    sigset_t original, blocked, restored;
    if (sigprocmask(SIG_SETMASK, NULL, &original) != 0) return state;
    state->signo = 0;
    struct sigaction previous, action;
    /* Legacy Bionic LP32 sigset_t cannot represent realtime signals. Use only
     * normally ignored legacy signals there; never steal an installed handler.
     * LP64 can prefer an unused realtime signal. */
    const int legacy[] = {SIGURG, SIGWINCH};
    for (unsigned int i = 0; i < sizeof(legacy) / sizeof(legacy[0]); ++i) {
        int candidate = legacy[i];
        if (sigismember(&original, candidate) != 0) continue;
        if (sigaction(candidate, NULL, &previous) != 0) continue;
        if (previous.sa_handler == SIG_DFL) {
            state->signo = candidate;
            break;
        }
    }
#if !defined(__arm__)
    for (int candidate = SIGRTMAX; candidate >= (int)SIGRTMIN + 3; --candidate) {
        if (state->signo) break;
        if (sigismember(&original, candidate) != 0) continue;
        if (sigaction(candidate, NULL, &previous) != 0) continue;
        if (previous.sa_handler == SIG_DFL) {
            state->signo = candidate;
            break;
        }
    }
#endif
    if (!state->signo) return state;
    blocked = original;
    if (sigaddset(&blocked, state->signo) != 0 ||
        sigprocmask(SIG_SETMASK, &blocked, NULL) != 0) return state;
    action = previous;
    action.sa_sigaction = ph_probe_signal_handler_vm;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(state->signo, &action, NULL) != 0) {
        sigprocmask(SIG_SETMASK, &original, NULL);
        return state;
    }
    state->pid = (long)getpid();
    long tid = (long)syscall(__NR_gettid);
    state->nonce = ++g_ph_probe_sequence ^ (unsigned int)tid ^
                   (unsigned int)(uintptr_t)state ^ 0x6d2b79f5u;
    state->resume_pc = (uintptr_t)ph_probe_signal_resume_pc;
    state->armed = 1;
    if (sigprocmask(SIG_SETMASK, &original, NULL) == 0) {
        state->token = ph_probe_signal_send_native(
                state->pid, tid, state->signo, state->nonce);
    }
    state->armed = 0;
    /* Block during restoration; no signal is pending after synchronous self
     * delivery on genuine Linux. Keep this handler if restoration fails. */
    if (sigprocmask(SIG_SETMASK, &blocked, &restored) == 0) {
        int handler_ok = sigaction(state->signo, &previous, NULL) == 0;
        int mask_ok = sigprocmask(SIG_SETMASK, &original, NULL) == 0;
        state->setup_ok = handler_ok && mask_ok;
    }
    return state;
}

static PH_RUNTIME_NATIVE void ph_probe_signal_finish_native(void) {
    __sync_lock_release(&g_ph_probe_signal_busy);
}

static PH_RUNTIME_NATIVE unsigned int ph_probe_atomic_capture_native(void) {
    volatile unsigned int word = 0x31415926u;
    return ph_probe_exclusive_native(&word);
}

static PH_PROBE_VM int ph_signal_result_vm(ph_probe_signal_state_t *state) {
    return state->setup_ok && state->delivered &&
           state->token == ph_signal_mix_vm(state->nonce);
}

#endif
