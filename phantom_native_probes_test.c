#define _GNU_SOURCE 1
#if defined(__x86_64__)
#define PH_PROBE_HOST_TEST 1
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "phantom_native_probes.h"

static void test_policy(void) {
    for (unsigned int i = 0; i < 10000; ++i)
        assert((i ^ 0xa5c39e17u) != i);
    ph_probe_signal_state_t state = {0};
    assert(!ph_signal_result_vm(0, 0, 0));
    unsigned int route_valid = ph_signal_route_vm(
            1, SIGURG, SIGURG, SIGURG, SI_TKILL, 12, 12);
    assert(route_valid == 1u);
    assert(ph_signal_route_vm(
            1, SIGURG, SIGURG, SIGURG, SI_USER, 12, 12) == 0u);
    assert(ph_signal_route_vm(
            1, SIGURG, SIGURG, SIGURG, SI_TKILL, 13, 12) == 0u);
    assert(ph_signal_route_vm(
            0, SIGURG, SIGURG, SIGURG, SI_TKILL, 12, 12) == 0u);

    state.armed = 1; state.signo = SIGURG;
    state.pid = 12; state.nonce = 1234;
#if defined(__x86_64__)
    ucontext_t uc;
    memset(&uc, 0, sizeof(uc));
    state.resume_pc = (uintptr_t)&test_policy;
    uc.uc_mcontext.gregs[REG_R12] = state.nonce;
    uc.uc_mcontext.gregs[REG_R13] = state.nonce ^ 0x5au;
    uc.uc_mcontext.gregs[REG_RIP] = state.resume_pc;
    uc.uc_mcontext.gregs[REG_RSP] = (greg_t)(uintptr_t)&uc;
    unsigned int frame_valid = ph_signal_frame_vm(
            (uintptr_t)uc.uc_mcontext.gregs[REG_R12],
            (uintptr_t)uc.uc_mcontext.gregs[REG_R13],
            (uintptr_t)uc.uc_mcontext.gregs[REG_RIP], state.resume_pc,
            (uintptr_t)uc.uc_mcontext.gregs[REG_RSP], state.nonce);
    assert(frame_valid == 1u);
    unsigned int return_value =
            ph_signal_delivery_vm(route_valid, frame_valid, state.nonce);
    assert(return_value == (state.nonce ^ 0xa5c39e17u));
    volatile uint32_t *saved_return_register =
            (volatile uint32_t *)&uc.uc_mcontext.gregs[REG_R12];
    ph_signal_context_apply_vm(saved_return_register, return_value);
    assert(*saved_return_register == (state.nonce ^ 0xa5c39e17u));
    assert(ph_signal_delivery_vm(0u, frame_valid, state.nonce) == state.nonce);
    assert(ph_signal_frame_vm(
            (uintptr_t)*saved_return_register,
            (uintptr_t)uc.uc_mcontext.gregs[REG_R13],
            (uintptr_t)uc.uc_mcontext.gregs[REG_RIP], state.resume_pc,
            (uintptr_t)uc.uc_mcontext.gregs[REG_RSP], state.nonce) == 0u);
#endif
    state.setup_ok = 1;
    state.token = state.nonce ^ 0xa5c39e17u;
    assert(ph_signal_result_vm(state.setup_ok, state.token, state.nonce) == 1u);
    ++state.nonce;
    assert(ph_signal_result_vm(state.setup_ok, state.token, state.nonce) == 0u);
    state.setup_ok = 0;
    assert(ph_signal_result_vm(state.setup_ok, state.token, state.nonce) == 0u);
    puts("VM policy negative/replay cases: PASS");
}

static void user_signal_handler(int signo) { (void)signo; }

static void test_signal_rounds(void) {
    sigset_t before, after;
    struct sigaction old_urg, old_winch, new_urg, new_winch;
    assert(sigprocmask(SIG_SETMASK, NULL, &before) == 0);
    assert(sigaction(SIGURG, NULL, &old_urg) == 0);
    assert(sigaction(SIGWINCH, NULL, &old_winch) == 0);
    struct sigaction user_action;
    memset(&user_action, 0, sizeof(user_action));
    user_action.sa_handler = user_signal_handler;
    sigemptyset(&user_action.sa_mask);
    assert(sigaction(SIGURG, &user_action, NULL) == 0);
    for (int i = 0; i < 16; ++i) {
        ph_probe_signal_state_t *state = ph_probe_signal_round_native();
        assert(state && ph_signal_result_vm(
                state->setup_ok, state->token, state->nonce));
        assert(state->token != state->nonce); /* Kernel restored modified context. */
        assert(state->signo != SIGURG); /* Never replace the installed handler. */
        assert(!state->armed);
        assert(ph_probe_signal_round_native() == NULL); /* No overlapping owner. */
        ph_probe_signal_finish_native();
    }
    assert(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
    for (int signo = 1; signo < NSIG; ++signo)
        assert(sigismember(&before, signo) == sigismember(&after, signo));
    assert(sigaction(SIGURG, NULL, &new_urg) == 0);
    assert(sigaction(SIGWINCH, NULL, &new_winch) == 0);
    assert(user_signal_handler == new_urg.sa_handler);
    assert(old_winch.sa_handler == new_winch.sa_handler);
    assert(sigaction(SIGURG, &old_urg, NULL) == 0);
    puts("Real self-signal/context continuation and restoration: PASS");
}

int main(int argc, char **argv) {
    test_policy();
    test_signal_rounds();
    unsigned int status = ph_probe_atomic_capture_native();
#if defined(__x86_64__)
    puts("Atomic ARM instructions: NOT TESTED on x86 host");
#else
    printf("Actual ARM syscall/exclusive status: %u\n", status);
    if (argc < 2 || strcmp(argv[1], "--record-atomic") != 0)
        assert(status == 1u);
#endif
    (void)argc; (void)argv; (void)status;
    return 0;
}
