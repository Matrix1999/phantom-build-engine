#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>

#include "phantom_os_consistency.h"

int main(void) {
    ph_os_probe_result_t memory = ph_probe_memory_semantics_native();
    ph_os_probe_result_t eventfd = ph_probe_eventfd_semantics_native();

    assert(memory != PH_OS_PROBE_INCONSISTENT);
    assert(eventfd != PH_OS_PROBE_INCONSISTENT);

    printf("Temporary mmap/mprotect/munmap semantics: %s\n",
           memory == PH_OS_PROBE_OK ? "PASS" : "UNSUPPORTED");
    printf("Nonblocking eventfd/poll/read semantics: %s\n",
           eventfd == PH_OS_PROBE_OK ? "PASS" : "UNSUPPORTED");
    return 0;
}
