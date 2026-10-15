#ifndef PHANTOM_OS_CONSISTENCY_H
#define PHANTOM_OS_CONSISTENCY_H

#include <poll.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "phantom_runtime_checks.h"

typedef enum {
    PH_OS_PROBE_UNSUPPORTED = 0,
    PH_OS_PROBE_OK = 1,
    PH_OS_PROBE_INCONSISTENT = 2
} ph_os_probe_result_t;

/*
 * Exercise only a private temporary page. Return UNSUPPORTED for ordinary
 * resource/policy errors; report INCONSISTENT only when a successful operation
 * contradicts the documented result or corrupts the page contents.
 */
static PH_RUNTIME_NATIVE ph_os_probe_result_t
ph_probe_memory_semantics_native(void) {
    long page_bytes = sysconf(_SC_PAGESIZE);
    if (page_bytes <= 0) return PH_OS_PROBE_UNSUPPORTED;

    size_t page_size = (size_t)page_bytes;
    if ((page_size & (page_size - 1u)) != 0u)
        return PH_OS_PROBE_INCONSISTENT;
    if (page_size > 1024u * 1024u) return PH_OS_PROBE_UNSUPPORTED;

    void *mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return PH_OS_PROBE_UNSUPPORTED;

    ph_os_probe_result_t result = PH_OS_PROBE_OK;
    if (((uintptr_t)mapping & (page_size - 1u)) != 0u) {
        result = PH_OS_PROBE_INCONSISTENT;
    } else {
        volatile uint8_t *bytes = (volatile uint8_t *)mapping;
        bytes[0] = 0x5au;
        bytes[page_size - 1u] = 0xa5u;

        if (mprotect(mapping, page_size, PROT_READ) != 0) {
            result = PH_OS_PROBE_UNSUPPORTED;
        } else if (mprotect(mapping, page_size,
                            PROT_READ | PROT_WRITE) != 0) {
            result = PH_OS_PROBE_UNSUPPORTED;
        } else if (bytes[0] != 0x5au ||
                   bytes[page_size - 1u] != 0xa5u) {
            result = PH_OS_PROBE_INCONSISTENT;
        } else {
            bytes[0] = 0x3cu;
            result = bytes[0] == 0x3cu
                    ? PH_OS_PROBE_OK : PH_OS_PROBE_INCONSISTENT;
        }
    }

    if (munmap(mapping, page_size) != 0 &&
        result == PH_OS_PROBE_OK) {
        result = PH_OS_PROBE_UNSUPPORTED;
    }
    return result;
}

/*
 * Confirm eventfd counter/readiness semantics without waiting or relying on
 * scheduling. A missing/denied resource is unsupported, not an emulator
 * verdict; contradictory successful results are reported separately.
 */
static PH_RUNTIME_NATIVE ph_os_probe_result_t
ph_probe_eventfd_semantics_native(void) {
    int fd = eventfd(0u, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) return PH_OS_PROBE_UNSUPPORTED;

    const uint64_t expected = UINT64_C(0x0123456789abcdef);
    uint64_t observed = 0u;
    ph_os_probe_result_t result = PH_OS_PROBE_OK;

    ssize_t written = write(fd, &expected, sizeof(expected));
    if (written < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if ((size_t)written != sizeof(expected)) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    struct pollfd descriptor = {fd, POLLIN, 0};
    int ready = poll(&descriptor, 1u, 0);
    if (ready < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if (ready != 1 || (descriptor.revents & POLLIN) == 0 ||
        (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    ssize_t bytes_read = read(fd, &observed, sizeof(observed));
    if (bytes_read < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
        goto cleanup;
    }
    if ((size_t)bytes_read != sizeof(observed) || observed != expected) {
        result = PH_OS_PROBE_INCONSISTENT;
        goto cleanup;
    }

    descriptor.revents = 0;
    ready = poll(&descriptor, 1u, 0);
    if (ready < 0) {
        result = PH_OS_PROBE_UNSUPPORTED;
    } else if (ready != 0) {
        result = PH_OS_PROBE_INCONSISTENT;
    }

cleanup:
    if (close(fd) != 0 && result == PH_OS_PROBE_OK)
        result = PH_OS_PROBE_UNSUPPORTED;
    return result;
}

#endif
