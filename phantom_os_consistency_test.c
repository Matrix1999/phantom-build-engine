#define _GNU_SOURCE 1

#include <assert.h>
#include <stdio.h>

#include "phantom_os_consistency.h"

static void report_probe(const char *name, ph_os_probe_result_t result) {
    assert(result != PH_OS_PROBE_INCONSISTENT);
    if (result == PH_OS_PROBE_UNSUPPORTED) {
        printf("%s: unsupported by this host; no rejection\\n", name);
        return;
    }
    assert(result == PH_OS_PROBE_OK);
    printf("%s: passed using host OS APIs\\n", name);
}

int main(void) {
    report_probe("mmap/mprotect/munmap",
                 ph_probe_memory_semantics_native());
    report_probe("eventfd/poll/epoll",
                 ph_probe_event_notification_native());
    report_probe("pthread TLS lifecycle",
                 ph_probe_thread_local_semantics_native());
    return 0;
}
