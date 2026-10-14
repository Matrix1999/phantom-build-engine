#define _GNU_SOURCE 1
#if defined(__x86_64__)
#define PH_PROBE_HOST_TEST 1
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "phantom_native_probes.h"

static void test_policy(void) {
    assert(ph_probe_atomic_ok_vm(1));
    assert(!ph_probe_atomic_ok_vm(0));
    assert(!ph_probe_atomic_ok_vm(2));
    assert(!ph_probe_atomic_ok_vm(UINT_MAX));
    for (unsigned int i = 0; i < 10000; ++i)
        assert(ph_signal_mix_vm(i) != i);
    ph_probe_signal_state_t state = {0};
    assert(!ph_signal_route_vm(&state, SIGURG, SI_TKILL, 12));
    state.armed = 1; state.signo = SIGURG; state.pid = 12; state.nonce = 1234;
    assert(ph_signal_route_vm(&state, SIGURG, SI_TKILL, 12));
    assert(!ph_signal_route_vm(&state, SIGWINCH, SI_TKILL, 12));
    assert(!ph_signal_route_vm(&state, SIGURG, SI_USER, 12));
    assert(!ph_signal_route_vm(&state, SIGURG, SI_TKILL, 13));
    assert(!ph_signal_context_vm(NULL, &state));
#if defined(__x86_64__)
    ucontext_t uc;
    memset(&uc, 0, sizeof(uc));
    assert(!ph_signal_context_vm(&uc, &state));
    state.resume_pc = (uintptr_t)&test_policy;
    uc.uc_mcontext.gregs[REG_R12] = state.nonce;
    uc.uc_mcontext.gregs[REG_R13] = state.nonce ^ 0x5au;
    uc.uc_mcontext.gregs[REG_RIP] = state.resume_pc;
    uc.uc_mcontext.gregs[REG_RSP] = (greg_t)(uintptr_t)&uc;
    assert(ph_signal_context_vm(&uc, &state));
    assert((unsigned int)uc.uc_mcontext.gregs[REG_R12] ==
           ph_signal_mix_vm(state.nonce));
#endif
    assert(!ph_signal_result_vm(&state));
    state.setup_ok = state.delivered = 1;
    state.token = ph_signal_mix_vm(state.nonce);
    assert(ph_signal_result_vm(&state));
    ++state.nonce;
    assert(!ph_signal_result_vm(&state)); /* No replay into another round. */
    state.setup_ok = 0;
    assert(!ph_signal_result_vm(&state));
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
        assert(state && ph_signal_result_vm(state));
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
        assert(ph_probe_atomic_ok_vm(status));
#endif
    (void)argc; (void)argv; (void)status;
    return 0;
}
