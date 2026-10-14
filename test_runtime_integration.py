#!/usr/bin/env python3
"""Host-test actual runtime-gate function bodies; no crypto keys or APK execution.

This does not stand in for an Android/Amice build or an ART/device test.
"""
import argparse
import os
import re
import subprocess
from pathlib import Path


def function(source, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\(", source)
    if not match:
        raise AssertionError(f"Missing function: {name}")
    start = source.rfind("\n", 0, match.start()) + 1
    brace = source.index("{", match.end())
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    source = (here / "phantom_key.c").read_text()
    args.out.mkdir(parents=True, exist_ok=True)
    extracted = "\n\n".join(function(source, name) for name in (
        "ph_loaded_bytes", "ph_dynamic_pointer", "_ph_res_cb"))
    resolver = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include "phantom_runtime_checks.h"
#define my_strncmp strncmp
typedef struct { const char *lib; const char *sym; void *addr; } _ph_res_t;
'''
    resolver += extracted + r'''
int main(void) {
    _ph_res_t request = {"libc.so.6", "pthread_create", NULL};
    dl_iterate_phdr(_ph_res_cb, &request);
    assert(request.addr == (void *)pthread_create);
    request.sym = "not_a_real_phantom_symbol";
    request.addr = NULL;
    dl_iterate_phdr(_ph_res_cb, &request);
    assert(request.addr == NULL);
    assert(_ph_res_cb(NULL, 0, &request) == 0);
    puts("Actual ELF resolver on host libc: PASS");
    return 0;
}
'''
    gate = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "phantom_runtime_checks.h"
#define PH_XCHACHA(var, token) char var[64] = #token
#define PH_ZERO(var, size) memset(var, 0, size)
#define SP_BUF_SZ 64
static ph_watch_state_t g_ph_watcher;
static jmp_buf killed;
static int open_result = 100, interrupted = 0, empty_read = 0;
static const char *status = "Name: app\nTRACER_PID 0\n";
static int sleeps = 0, ack_after = -1;
static void nuke_app(void) { longjmp(killed, 1); }
static long vm_gettid(void) { return 11; }
static int vm_nanosleep(const struct timespec *t, struct timespec *remain) {
    (void)t; (void)remain;
    ++sleeps;
    if (sleeps == ack_after) ph_watch_ack(&g_ph_watcher, 22);
    return 0;
}
static int vm_openat(int d, const char *p, int f, int m) {
    (void)d; (void)p; (void)f; (void)m; return open_result;
}
static int vm_close(int fd) { (void)fd; return 0; }
static ssize_t vm_read(int fd, void *buf, size_t bytes) {
    (void)fd;
    if (interrupted) { --interrupted; return -EINTR; }
    if (empty_read) return 0;
    size_t n = strlen(status);
    if (n > bytes) n = bytes;
    memcpy(buf, status, n);
    return n;
}
'''
    # Only replace the protected label macro, not the production function.
    gate = gate.replace('char var[64] = #token', 'char var[64] = '
                        '(strcmp(#token, "TRACER_PID") == 0 ? "TracerPid:" : "")')
    # Arrays cannot be initialized by a conditional expression: copy instead.
    gate = gate.replace('char var[64] = (strcmp(#token, "TRACER_PID") == 0 ? '
                        '"TracerPid:" : "")',
                        'char var[64]; strcpy(var, strcmp(#token, "TRACER_PID") '
                        '== 0 ? "TracerPid:" : "")')
    gate += "\n\n" + function(source, "detect_ptrace")
    gate += "\n\n" + function(source, "ph_require_watcher")
    gate += r'''
static void expected_reject(void (*fn)(void)) {
    if (setjmp(killed) == 0) { fn(); assert(!"expected rejection"); }
}
int main(void) {
    status = "Name: app\nTracerPid: 0\n";
    detect_ptrace();
    interrupted = 2;
    detect_ptrace();
    interrupted = 4;
    expected_reject(detect_ptrace);
    interrupted = 0;
    open_result = -1;
    expected_reject(detect_ptrace);
    open_result = 100;
    empty_read = 1;
    expected_reject(detect_ptrace);
    empty_read = 0;
    status = "Name: app\n";
    expected_reject(detect_ptrace);
    status = "TracerPid: 7\n";
    expected_reject(detect_ptrace);
    expected_reject(ph_require_watcher);
    assert(ph_watch_begin(&g_ph_watcher));
    sleeps = 0; ack_after = 3;
    ph_require_watcher();
    assert(sleeps == 3);
    ph_watch_fail(&g_ph_watcher);
    expected_reject(ph_require_watcher);
    memset(&g_ph_watcher, 0, sizeof(g_ph_watcher));
    assert(ph_watch_begin(&g_ph_watcher));
    sleeps = 0; ack_after = -1;
    expected_reject(ph_require_watcher);
    assert(sleeps == 200);
    assert(ph_watch_ready(&g_ph_watcher, 11) == -1);
    puts("Actual essential gate/watcher wait bodies: PASS");
    return 0;
}
'''
    for name, text in (("resolver", resolver), ("gate", gate)):
        c = args.out / f"{name}-host-test.c"
        exe = args.out / f"{name}-host-test"
        c.write_text(text)
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O2",
                        "-Wall", "-Wextra", "-Wno-unused-function",
                        "-Wno-attributes", "-Werror", "-pthread", "-I", str(here),
                        str(c), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    # Protect both early key derivation and each shard's materialization.
    loader = function(source, "Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeLoadShards")
    assert loader.index("ph_require_watcher();") < loader.index("arx_kdf(")
    assert loader.count("ph_require_watcher();") == 2
    assert "NewDirectByteBuffer" in loader
    assert "ph_direct_dex_map_t pending_maps" in loader
    print("JNI placement and retained DEX lifetime: PASS")


if __name__ == "__main__":
    main()
