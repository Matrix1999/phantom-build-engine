#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "phantom_runtime_checks.h"

static void *ack_worker(void *arg) {
    ph_watch_ack(arg, 22);
    return NULL;
}

int main(void) {
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
