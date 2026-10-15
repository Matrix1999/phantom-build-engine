#ifndef PHANTOM_OS_CONSISTENCY_H
#define PHANTOM_OS_CONSISTENCY_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "phantom_runtime_checks.h"

typedef enum {
    PH_OS_PROBE_UNSUPPORTED = 0,
    PH_OS_PROBE_OK = 1,
    PH_OS_PROBE_INCONSISTENT = 2
} ph_os_probe_result_t;

/* Use a private one-page mapping; never touch a live DEX mapping or fault
 * deliberately. Unsupported page sizes and denied operations are neutral. */
static PH_RUNTIME_NATIVE ph_os_probe_result_t
ph_probe_memory_semantics_native(void) {
    long reported_page_size = sysconf(_SC_PAGESIZE);
    if (reported_page_size <= 0) return PH_OS_PROBE_UNSUPPORTED;

    size_t page_size = (size_t)reported_page_size;
    if ((page_size & (page_size - 1u)) != 0u)
        return PH_OS_PROBE_INCONSISTENT;
    if (page_size > 1024u * 1024u) return PH_OS_PROBE_UNSUPPORTED;

    void *mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return PH_OS_PROBE_UNSUPPORTED;

    ph_os_probe_result_t result = PH_OS_PROBE_OK;
    if (((uintptr_t)mapping % page_size) != 0u) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    volatile unsigned char *bytes = (volatile unsigned char *)mapping;
    bytes[0] = 0x6bu;
    bytes[page_size - 1u] = 0xd4u;
    if (bytes[0] != 0x6bu || bytes[page_size - 1u] != 0xd4u) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    if (mprotect(mapping, page_size, PROT_READ) != 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (bytes[0] != 0x6bu || bytes[page_size - 1u] != 0xd4u) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }
    if (mprotect(mapping, page_size, PROT_READ | PROT_WRITE) != 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }

    bytes[0] = 0x35u;
    bytes[page_size - 1u] = 0xa7u;
    if (bytes[0] != 0x35u || bytes[page_size - 1u] != 0xa7u)
        result = PH_OS_PROBE_INCONSISTENT;

cleanup:
    if (munmap(mapping, page_size) != 0 && result == PH_OS_PROBE_OK)
        result = PH_OS_PROBE_UNSUPPORTED;
    return result;
}

/* Exercise eventfd readiness through both poll and epoll with zero-timeout
 * queries. Every descriptor is local to this probe and closed on exit. */
static PH_RUNTIME_NATIVE ph_os_probe_result_t
ph_probe_event_notification_native(void) {
    int event_fd = -1;
    int epoll_fd = -1;
    ph_os_probe_result_t result = PH_OS_PROBE_UNSUPPORTED;

    event_fd = eventfd(0u, EFD_CLOEXEC | EFD_NONBLOCK);
    if (event_fd < 0) goto cleanup;

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) goto cleanup;

    const uint64_t event_value = UINT64_C(0x0123456789abcdef);
    const uint64_t event_tag = UINT64_C(0x7068616e746f6d31);
    struct epoll_event registration = {0};
    registration.events = EPOLLIN;
    registration.data.u64 = event_tag;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &registration) != 0)
        goto cleanup;

    ssize_t written = write(event_fd, &event_value, sizeof(event_value));
    if (written != (ssize_t)sizeof(event_value)) {
        if (written >= 0) result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }
    result = PH_OS_PROBE_OK;

    struct pollfd poll_state = {0};
    poll_state.fd = event_fd;
    poll_state.events = POLLIN;
    int poll_ready = poll(&poll_state, 1u, 0);
    if (poll_ready < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (poll_ready != 1 || !(poll_state.revents & POLLIN) ||
        (poll_state.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    struct epoll_event observed[1];
    int epoll_ready = epoll_wait(epoll_fd, observed, 1, 0);
    if (epoll_ready < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (epoll_ready != 1 || observed[0].data.u64 != event_tag ||
        !(observed[0].events & EPOLLIN) ||
        (observed[0].events & (EPOLLERR | EPOLLHUP))) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    uint64_t observed_value = 0;
    ssize_t received = read(event_fd, &observed_value, sizeof(observed_value));
    if (received < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (received != (ssize_t)sizeof(observed_value) ||
        observed_value != event_value) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    poll_state.revents = 0;
    poll_ready = poll(&poll_state, 1u, 0);
    if (poll_ready < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (poll_ready != 0 || poll_state.revents != 0) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    epoll_ready = epoll_wait(epoll_fd, observed, 1, 0);
    if (epoll_ready < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (epoll_ready != 0) result = PH_OS_PROBE_INCONSISTENT;

cleanup:
    if (epoll_fd >= 0 && close(epoll_fd) != 0 &&
        result == PH_OS_PROBE_OK)
        result = PH_OS_PROBE_UNSUPPORTED;
    if (event_fd >= 0 && close(event_fd) != 0 &&
        result == PH_OS_PROBE_OK)
        result = PH_OS_PROBE_UNSUPPORTED;
    return result;
}

typedef struct {
    pthread_key_t key;
    int initially_empty;
    int set_result;
    int value_matches;
    int clear_result;
    int clear_value_matches;
    volatile int state;
    volatile unsigned int references;
} ph_tls_probe_context_t;

enum {
    PH_TLS_PROBE_RUNNING = 0,
    PH_TLS_PROBE_ORPHANED = 1,
    PH_TLS_PROBE_DONE = 2,
    PH_TLS_PROBE_ORPHAN_CLEANED = 3
};

static unsigned char g_ph_tls_main_sentinel;

static PH_RUNTIME_NATIVE void ph_tls_probe_release(
        ph_tls_probe_context_t *context) {
    if (__atomic_sub_fetch(&context->references, 1u, __ATOMIC_ACQ_REL) == 0u)
        free(context);
}

static PH_RUNTIME_NATIVE void ph_tls_probe_finish_worker(
        ph_tls_probe_context_t *context) {
    int expected = PH_TLS_PROBE_RUNNING;
    if (!__atomic_compare_exchange_n(&context->state, &expected,
                                     PH_TLS_PROBE_DONE, 0,
                                     __ATOMIC_RELEASE, __ATOMIC_ACQUIRE) &&
        expected == PH_TLS_PROBE_ORPHANED) {
        (void)pthread_key_delete(context->key);
        __atomic_store_n(&context->state, PH_TLS_PROBE_ORPHAN_CLEANED,
                         __ATOMIC_RELEASE);
    }
    ph_tls_probe_release(context);
}

static PH_RUNTIME_NATIVE void *ph_tls_probe_worker(void *opaque) {
    ph_tls_probe_context_t *context = (ph_tls_probe_context_t *)opaque;
    context->initially_empty = pthread_getspecific(context->key) == NULL;
    context->set_result = pthread_setspecific(context->key, context);
    if (context->set_result == 0) {
        context->value_matches = pthread_getspecific(context->key) == context;
        context->clear_result = pthread_setspecific(context->key, NULL);
        if (context->clear_result == 0 &&
            pthread_getspecific(context->key) == NULL)
            context->clear_value_matches = 1;
    }
    ph_tls_probe_finish_worker(context);
    return NULL;
}

/* Verify real pthread key isolation and cleanup. The parent holds a distinct
 * value while the worker checks its own initially-empty thread-local slot.
 * No scheduling order or elapsed-time threshold is used. */
static PH_RUNTIME_NATIVE ph_os_probe_result_t
ph_probe_thread_local_semantics_native(void) {
    ph_tls_probe_context_t *context =
            (ph_tls_probe_context_t *)calloc(1u, sizeof(*context));
    if (!context) return PH_OS_PROBE_UNSUPPORTED;

    pthread_t worker;
    int key_created = 0;
    ph_os_probe_result_t result = PH_OS_PROBE_UNSUPPORTED;

    __atomic_store_n(&context->references, 1u, __ATOMIC_RELAXED);
    if (pthread_key_create(&context->key, NULL) != 0) {
        ph_tls_probe_release(context);
        return PH_OS_PROBE_UNSUPPORTED;
    }
    key_created = 1;
    if (pthread_setspecific(context->key, &g_ph_tls_main_sentinel) != 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (pthread_getspecific(context->key) != &g_ph_tls_main_sentinel) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    __atomic_add_fetch(&context->references, 1u, __ATOMIC_RELAXED);
    if (pthread_create(&worker, NULL, ph_tls_probe_worker, context) != 0) {
        ph_tls_probe_release(context);
        goto cleanup;
    }
    if (pthread_join(worker, NULL) != 0) {
        int previous = __atomic_exchange_n(&context->state,
                                           PH_TLS_PROBE_ORPHANED,
                                           __ATOMIC_ACQ_REL);
        if (previous == PH_TLS_PROBE_DONE) {
            (void)pthread_setspecific(context->key, NULL);
            (void)pthread_key_delete(context->key);
            __atomic_store_n(&context->state, PH_TLS_PROBE_ORPHAN_CLEANED,
                             __ATOMIC_RELEASE);
        }
        (void)pthread_detach(worker);
        ph_tls_probe_release(context);
        return PH_OS_PROBE_UNSUPPORTED;
    }

    if (context->set_result != 0 || context->clear_result != 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (!context->initially_empty || !context->value_matches ||
        !context->clear_value_matches ||
        pthread_getspecific(context->key) != &g_ph_tls_main_sentinel) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }
    result = PH_OS_PROBE_OK;

cleanup:
    if (key_created &&
        __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) !=
                PH_TLS_PROBE_ORPHAN_CLEANED) {
        int clear_result = pthread_setspecific(context->key, NULL);
        int delete_result = pthread_key_delete(context->key);
        if ((clear_result != 0 || delete_result != 0) &&
            result == PH_OS_PROBE_OK)
            result = PH_OS_PROBE_UNSUPPORTED;
    }
    ph_tls_probe_release(context);
    return result;
}

#endif
