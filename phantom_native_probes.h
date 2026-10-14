#ifndef PHANTOM_NATIVE_PROBES_H
#define PHANTOM_NATIVE_PROBES_H

#include <stdint.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ucontext.h>
#include "phantom_runtime_checks.h"

#ifdef __clang__
#define PH_PROBE_VM __attribute__((noinline, annotate("+vm_virtualize")))
#define PH_PROBE_VM_FLAT __attribute__((noinline, annotate("+vm_virtualize,+vm_flatten")))
#else
#define PH_PROBE_VM __attribute__((noinline))
#define PH_PROBE_VM_FLAT __attribute__((noinline))
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
    pid_t pid;
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

/* Flattened bytecode validates the complete kernel-delivered frame and edits
 * the saved return register. The native entry only forwards the ABI values. */
static PH_PROBE_VM unsigned int ph_signal_route_vm(
        unsigned int armed, int signo, int expected_signo, int info_signo,
        int code, pid_t sender_pid, pid_t expected_pid) {
    unsigned int valid = (unsigned int)(armed == 1u);
    valid &= (unsigned int)(signo == expected_signo);
    valid &= (unsigned int)(info_signo == expected_signo);
    valid &= (unsigned int)(code == SI_TKILL);
    valid &= (unsigned int)(sender_pid == expected_pid);
    return valid;
}

static PH_PROBE_VM unsigned int ph_signal_frame_vm(
        uintptr_t actual_nonce, uintptr_t actual_marker, uintptr_t actual_pc,
        uintptr_t expected_pc, uintptr_t sp, unsigned int nonce) {
    unsigned int valid = (unsigned int)(actual_nonce == (uintptr_t)nonce);
    valid &= (unsigned int)(actual_marker ==
                            ((uintptr_t)nonce ^ (uintptr_t)0x5au));
    valid &= (unsigned int)(actual_pc == expected_pc);
    valid &= (unsigned int)(sp != 0u);
#if defined(__aarch64__)
    valid &= (unsigned int)((sp & 15u) == 0u);
#elif defined(__arm__)
    valid &= (unsigned int)((sp & 7u) == 0u);
#endif
    return valid;
}

static PH_PROBE_VM unsigned int ph_signal_delivery_vm(
        unsigned int route_valid, unsigned int frame_valid) {
    return (unsigned int)(route_valid == 1u) &
           (unsigned int)(frame_valid == 1u);
}

static PH_PROBE_VM_FLAT void ph_signal_context_apply_vm(
        void *context, unsigned int accepted, unsigned int nonce) {
    if (accepted != 1u) return;
    ucontext_t *uc = (ucontext_t *)context;
#if defined(__aarch64__)
    uc->uc_mcontext.regs[12] = nonce ^ 0xa5c39e17u;
#elif defined(__arm__)
    uc->uc_mcontext.arm_ip = nonce ^ 0xa5c39e17u;
#elif defined(PH_PROBE_HOST_TEST) && defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_R12] = nonce ^ 0xa5c39e17u;
#endif
}

/* POSIX requires a native, address-taken signal entry point. It makes no
 * detection decisions and only forwards the delivered frame to VM bytecode. */
static PH_RUNTIME_NATIVE void ph_probe_signal_handler_native(
        int signo, siginfo_t *info, void *context) {
    ph_probe_signal_state_t *state = ph_probe_signal_state_native();
    int info_signo = 0, code = 0;
    pid_t sender_pid = 0;
    if (info) {
        info_signo = info->si_signo;
        code = info->si_code;
        sender_pid = info->si_pid;
    }
    unsigned int route_valid = ph_signal_route_vm(
            (unsigned int)state->armed, signo, state->signo,
            info_signo, code, sender_pid, state->pid);
    uintptr_t actual_nonce = 0, actual_marker = 0, actual_pc = 0, sp = 0;
    if (context) {
        ucontext_t *uc = (ucontext_t *)context;
#if defined(__aarch64__)
        actual_nonce = (uintptr_t)uc->uc_mcontext.regs[12];
        actual_marker = (uintptr_t)uc->uc_mcontext.regs[13];
        actual_pc = (uintptr_t)uc->uc_mcontext.pc;
        sp = (uintptr_t)uc->uc_mcontext.sp;
#elif defined(__arm__)
        actual_nonce = (uintptr_t)uc->uc_mcontext.arm_ip;
        actual_marker = (uintptr_t)uc->uc_mcontext.arm_r4;
        actual_pc = (uintptr_t)uc->uc_mcontext.arm_pc;
        sp = (uintptr_t)uc->uc_mcontext.arm_sp;
#elif defined(PH_PROBE_HOST_TEST) && defined(__x86_64__)
        actual_nonce = (uintptr_t)uc->uc_mcontext.gregs[REG_R12];
        actual_marker = (uintptr_t)uc->uc_mcontext.gregs[REG_R13];
        actual_pc = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
        sp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
#endif
    }
    unsigned int frame_valid = ph_signal_frame_vm(
            actual_nonce, actual_marker, actual_pc, state->resume_pc,
            sp, state->nonce);
    unsigned int accepted = ph_signal_delivery_vm(route_valid, frame_valid);
    ph_signal_context_apply_vm(context, accepted, state->nonce);
    state->delivered = (sig_atomic_t)accepted;
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
    action.sa_sigaction = ph_probe_signal_handler_native;
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

static PH_PROBE_VM_FLAT unsigned int ph_signal_result_vm(
        unsigned int setup_ok, unsigned int delivered,
        unsigned int token, unsigned int nonce) {
    if (setup_ok != 1u) return 0u;
    if (delivered != 1u) return 0u;
    if (token != (nonce ^ 0xa5c39e17u)) return 0u;
    return 1u;
}

#endif
