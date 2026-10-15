#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include "phantom_runtime_checks.h"

static void test_page_rounding(void) {
    size_t rounded = 0u;
    assert(ph_round_up_to_page(112u, 4096u, &rounded) && rounded == 4096u);
    assert(ph_round_up_to_page(4097u, 4096u, &rounded) && rounded == 8192u);
    assert(ph_round_up_to_page(4097u, 16384u, &rounded) && rounded == 16384u);
    assert(ph_round_up_to_page(16384u, 16384u, &rounded) && rounded == 16384u);

    rounded = 123u;
    assert(!ph_round_up_to_page(SIZE_MAX, 4096u, &rounded));
    assert(rounded == 123u);
    assert(!ph_round_up_to_page(1u, 6000u, &rounded));
    puts("4-KiB/16-KiB page rounding and overflow checks: PASS");
}

static void *ack_worker(void *arg) {
    ph_watch_ack(arg, 22);
    return NULL;
}

typedef struct {
    ph_watch_state_t watch;
    int stop;
} round_fixture;

static void *round_worker(void *arg) {
    round_fixture *fixture = arg;
    long tid = syscall(SYS_gettid);
    while (!__atomic_load_n(&fixture->stop, __ATOMIC_ACQUIRE)) {
        unsigned int round = ph_watch_check_round(&fixture->watch);
        ph_watch_ack_checked(&fixture->watch, tid, round);
        syscall(SYS_futex, &fixture->watch.completed_round,
                FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
        struct timespec timeout = {1, 0};
        syscall(SYS_futex, &fixture->watch.requested_round,
                FUTEX_WAIT_PRIVATE, round, &timeout, NULL, 0);
    }
    return NULL;
}

static void test_real_rounds(void) {
    round_fixture fixture = {0};
    assert(ph_watch_begin(&fixture.watch));
    pthread_t worker;
    assert(pthread_create(&worker, NULL, round_worker, &fixture) == 0);
    long caller = syscall(SYS_gettid);
    struct timespec pause = {0, 1000000};
    for (unsigned int i = 0; i < 2000u &&
         ph_watch_ready(&fixture.watch, caller) == 0; ++i)
        nanosleep(&pause, NULL);
    assert(ph_watch_ready(&fixture.watch, caller) == 1);
    for (unsigned int expected = 1; expected <= 8u; ++expected) {
        unsigned int round = ph_watch_request(&fixture.watch, caller);
        assert(round == expected);
        syscall(SYS_futex, &fixture.watch.requested_round,
                FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
        for (unsigned int i = 0; i < 200u &&
             ph_watch_round_ready(&fixture.watch, caller, round) == 0; ++i) {
            struct timespec timeout = {0, 10000000};
            unsigned int completed = __atomic_load_n(
                    &fixture.watch.completed_round, __ATOMIC_ACQUIRE);
            syscall(SYS_futex, &fixture.watch.completed_round,
                    FUTEX_WAIT_PRIVATE, completed, &timeout, NULL, 0);
        }
        assert(ph_watch_round_ready(&fixture.watch, caller, round) == 1);
    }
    __atomic_store_n(&fixture.stop, 1, __ATOMIC_RELEASE);
    syscall(SYS_futex, &fixture.watch.requested_round,
            FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    assert(pthread_join(worker, NULL) == 0);
}

int main(void) {
    test_page_rounding();
    ph_watch_state_t watch = {0};
    assert(ph_watch_ready(&watch, 11) == -1);
    assert(ph_watch_begin(&watch));
    assert(!ph_watch_begin(&watch));
    assert(ph_watch_ready(&watch, 11) == 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, ack_worker, &watch) == 0);
    assert(pthread_join(thread, NULL) == 0);
    assert(ph_watch_ready(&watch, 11) == 1);
    assert(ph_watch_ready(&watch, 22) == -1);
    assert(ph_watch_ready(&watch, 0) == -1);
    ph_watch_ack(&watch, 22);
    assert(watch.passes == 2);
    ph_watch_fail(&watch);
    ph_watch_ack(&watch, 22);
    assert(ph_watch_ready(&watch, 11) == -1);
    ph_watch_state_t bad_tid = {0};
    assert(ph_watch_begin(&bad_tid));
    ph_watch_ack(&bad_tid, 0);
    assert(ph_watch_ready(&bad_tid, 11) == -1);
    ph_watch_state_t no_ack = {0};
    assert(ph_watch_begin(&no_ack));
    for (int i = 0; i < 200; ++i)
        assert(ph_watch_ready(&no_ack, 11) == 0);
    ph_watch_fail(&no_ack);
    assert(ph_watch_ready(&no_ack, 11) == -1);
    ph_watch_state_t rounds = {0};
    assert(ph_watch_begin(&rounds));
    unsigned int prior_pass = ph_watch_check_round(&rounds);
    ph_watch_ack_checked(&rounds, 22, prior_pass);
    unsigned int first = ph_watch_request(&rounds, 11);
    assert(first == 1);
    assert(ph_watch_request(&rounds, 11) == 0); /* No overlapping round. */
    ph_watch_ack_checked(&rounds, 22, prior_pass);
    assert(ph_watch_round_ready(&rounds, 11, first) == 0);
    ph_watch_ack_checked(&rounds, 22, first);
    assert(ph_watch_round_ready(&rounds, 11, first) == 1);
    unsigned int second = ph_watch_request(&rounds, 11);
    assert(second == 2);
    ph_watch_ack_checked(&rounds, 22, first); /* Old response is not reusable. */
    assert(ph_watch_round_ready(&rounds, 11, second) == 0);
    assert(ph_watch_round_ready(&rounds, 22, second) == -1);
    assert(ph_watch_round_ready(&rounds, 11, first) == -1);
    assert(ph_watch_round_ready(&rounds, 11, 0) == -1);
    ph_watch_fail(&rounds);
    ph_watch_ack_checked(&rounds, 22, second);
    assert(ph_watch_round_ready(&rounds, 11, second) == -1);
    ph_watch_state_t overflow = {0};
    assert(ph_watch_begin(&overflow));
    ph_watch_ack(&overflow, 22);
    overflow.requested_round = UINT_MAX;
    overflow.completed_round = UINT_MAX;
    assert(ph_watch_request(&overflow, 11) == 0);
    test_real_rounds();
    uint32_t count = 0;
    uint32_t gnu64[] = {1, 2, 1, 0, 0, 0, 2, 0, 1};
    assert(ph_gnu_symbol_count(gnu64, sizeof(gnu64), 8, &count));
    assert(count == 4);
    assert(!ph_gnu_symbol_count(gnu64, sizeof(gnu64) - 4, 8, &count));
    uint32_t gnu32[] = {1, 2, 1, 0, 0, 2, 1};
    assert(ph_gnu_symbol_count(gnu32, sizeof(gnu32), 4, &count));
    assert(count == 3);
    gnu32[5] = 1;
    assert(!ph_gnu_symbol_count(gnu32, sizeof(gnu32), 4, &count));
    assert(!ph_gnu_symbol_count(gnu64, sizeof(gnu64), 16, &count));
    char path[64];
    assert(ph_task_path(path, sizeof(path), "/proc/self/task", "1234", "/comm"));
    assert(strcmp(path, "/proc/self/task/1234/comm") == 0);
    assert(ph_task_path(path, sizeof(path), "/proc/self/task/", "1234", "/status"));
    assert(strcmp(path, "/proc/self/task/1234/status") == 0);
    assert(!ph_task_path(path, 8, "/proc/self/task", "1234", "/status"));
    assert(path[0] == '\0');
    assert(!ph_task_path(path, sizeof(path), "/proc/self/task", "1234", "status"));
    assert(ph_task_name_valid("1234", 5));
    assert(!ph_task_name_valid("1234", 4));
    assert(!ph_task_name_valid("../x", 5));
    assert(!ph_task_name_valid("", 1));
    assert(!ph_task_name_valid("12345678901", 12));
    assert(ph_dumpability_ok(0, 0));
    assert(!ph_dumpability_ok(-1, 0));
    assert(!ph_dumpability_ok(0, -1));
    assert(!ph_dumpability_ok(0, 1));
    int pid = -1;
    const char clean[] = "Name:\tapp\nTracerPid:\t0\nUid:\t10000\n";
    assert(ph_tracer_pid(clean, strlen(clean), "TracerPid:", &pid) && pid == 0);
    const char traced[] = "TracerPid: 1234 \r\n";
    assert(ph_tracer_pid(traced, strlen(traced), "TracerPid:", &pid) && pid == 1234);
    const char *bad[] = {"Name: TracerPid: 0\n", "TracerPid: -1\n",
        "TracerPid: \n", "TracerPid: 0x0\n", "TracerPid: 2147483648\n",
        "TracerPid: 0", "TracerPid: 12other\n"};
    for (unsigned int i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(!ph_tracer_pid(bad[i], strlen(bad[i]), "TracerPid:", &pid));
    puts("Phantom runtime checks: watcher state/real-thread tests PASS");
    return 0;
}
