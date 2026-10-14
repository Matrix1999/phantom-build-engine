#ifndef PHANTOM_RUNTIME_CHECKS_H
#define PHANTOM_RUNTIME_CHECKS_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

/* Atomic/syscall-adjacent bridges stay native, not new VMP targets. */
#ifdef __clang__
#define PH_RUNTIME_NATIVE __attribute__((noinline, annotate("-vm_virtualize,-vm_flatten")))
#else
#define PH_RUNTIME_NATIVE __attribute__((noinline))
#endif

enum {
    PH_WATCH_IDLE = 0,
    PH_WATCH_STARTING = 1,
    PH_WATCH_RUNNING = 2,
    PH_WATCH_FAILED = 3
};

typedef struct {
    int state;
    long tid;
    unsigned int passes;
} ph_watch_state_t;

static PH_RUNTIME_NATIVE int ph_watch_begin(ph_watch_state_t *watch) {
    int expected = PH_WATCH_IDLE;
    return __atomic_compare_exchange_n(&watch->state, &expected,
            PH_WATCH_STARTING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static PH_RUNTIME_NATIVE void ph_watch_fail(ph_watch_state_t *watch) {
    __atomic_store_n(&watch->state, PH_WATCH_FAILED, __ATOMIC_RELEASE);
}

static PH_RUNTIME_NATIVE void ph_watch_ack(ph_watch_state_t *watch, long tid) {
    if (tid <= 0) {
        ph_watch_fail(watch);
        return;
    }
    __atomic_store_n(&watch->tid, tid, __ATOMIC_RELAXED);
    __atomic_add_fetch(&watch->passes, 1u, __ATOMIC_RELAXED);
    /* Do not let a delayed child overwrite a failed creation result. */
    int expected = PH_WATCH_STARTING;
    __atomic_compare_exchange_n(&watch->state, &expected,
            PH_WATCH_RUNNING, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

/* 1: checked watcher pass; 0: still starting; -1: unusable or same thread. */
static PH_RUNTIME_NATIVE int ph_watch_ready(
        const ph_watch_state_t *watch, long caller_tid) {
    int state = __atomic_load_n(&watch->state, __ATOMIC_ACQUIRE);
    if (state == PH_WATCH_IDLE || state == PH_WATCH_FAILED ||
        caller_tid <= 0) return -1;
    if (state != PH_WATCH_RUNNING) return 0;
    long tid = __atomic_load_n(&watch->tid, __ATOMIC_RELAXED);
    unsigned int passes = __atomic_load_n(&watch->passes, __ATOMIC_RELAXED);
    return tid > 0 && tid != caller_tid && passes > 0 ? 1 : -1;
}

/* DT_GNU_HASH has no nchain field. Derive the symbol bound without reading
 * outside its containing PT_LOAD mapping; accept either ELF word width. */
static PH_RUNTIME_NATIVE int ph_gnu_symbol_count(
        const uint32_t *hash, size_t bytes, size_t word_bytes, uint32_t *count) {
    if (!hash || !count || bytes < 16 ||
        (word_bytes != 4 && word_bytes != 8)) return 0;
    uint32_t buckets = hash[0], first = hash[1], bloom = hash[2];
    if (!buckets || !bloom || buckets > 1048576u ||
        bloom > 1048576u || first > 1048576u) return 0;
    size_t bucket_offset = 16u + (size_t)bloom * word_bytes;
    if (bucket_offset > bytes ||
        buckets > (bytes - bucket_offset) / 4u) return 0;
    const uint32_t *bucket = (const uint32_t *)(
            (const unsigned char *)hash + bucket_offset);
    uint32_t last = 0;
    for (uint32_t i = 0; i < buckets; ++i) {
        if (bucket[i] && bucket[i] < first) return 0;
        if (bucket[i] > last) last = bucket[i];
    }
    if (!last) { *count = first; return 1; }
    size_t chain_offset = bucket_offset + (size_t)buckets * 4u;
    const uint32_t *chain = (const uint32_t *)(
            (const unsigned char *)hash + chain_offset);
    size_t chain_count = (bytes - chain_offset) / 4u;
    for (uint32_t index = last; index < 1048576u; ++index) {
        size_t slot = (size_t)index - first;
        if (slot >= chain_count) return 0;
        if (chain[slot] & 1u) { *count = index + 1u; return 1; }
    }
    return 0;
}

static PH_RUNTIME_NATIVE int ph_task_name_valid(
        const char *name, size_t available) {
    if (!name || !available) return 0;
    for (size_t i = 0; i < available && i <= 10u; ++i) {
        if (!name[i]) return i > 0;
        if (name[i] < '0' || name[i] > '9') return 0;
    }
    return 0;
}

/* Never silently truncate a security probe or rely on a slash in the label. */
static PH_RUNTIME_NATIVE int ph_task_path(
        char *out, size_t capacity, const char *base,
        const char *tid, const char *suffix) {
    if (!out || !capacity || !base || !tid || !suffix || suffix[0] != '/')
        return 0;
    size_t pos = 0;
    const char *parts[3] = {base, tid, suffix};
    for (unsigned int part = 0; part < 3; ++part) {
        if (part == 1 && pos > 0 && out[pos - 1u] != '/') {
            if (pos + 1u >= capacity) { out[0] = '\0'; return 0; }
            out[pos++] = '/';
        }
        for (const char *p = parts[part]; *p; ++p) {
            if (pos + 1u >= capacity) { out[0] = '\0'; return 0; }
            out[pos++] = *p;
        }
    }
    out[pos] = '\0';
    return 1;
}

static PH_RUNTIME_NATIVE int ph_dumpability_ok(int set_result, int get_result) {
    return set_result == 0 && get_result == 0;
}

/* Missing/malformed is not equivalent to an explicit untraced process. */
static PH_RUNTIME_NATIVE int ph_tracer_pid(
        const char *status, size_t bytes, const char *label, int *pid) {
    if (!status || !label || !pid) return 0;
    size_t label_len = 0;
    while (label[label_len]) ++label_len;
    if (!label_len) return 0;
    for (size_t line = 0; line < bytes; ) {
        size_t end = line;
        while (end < bytes && status[end] != '\n') ++end;
        if (end == bytes) return 0; /* Truncated line: do not guess. */
        size_t matched = 0;
        while (matched < label_len && line + matched < end &&
               status[line + matched] == label[matched]) ++matched;
        if (matched == label_len) {
            size_t pos = line + label_len;
            while (pos < end && (status[pos] == ' ' || status[pos] == '\t'))
                ++pos;
            if (pos == end || status[pos] < '0' || status[pos] > '9') return 0;
            unsigned int value = 0;
            while (pos < end && status[pos] >= '0' && status[pos] <= '9') {
                unsigned int digit = (unsigned int)(status[pos++] - '0');
                if (value > ((unsigned int)INT_MAX - digit) / 10u) return 0;
                value = value * 10u + digit;
            }
            while (pos < end && (status[pos] == ' ' || status[pos] == '\t' ||
                                 status[pos] == '\r')) ++pos;
            if (pos != end) return 0;
            *pid = (int)value;
            return 1;
        }
        line = end + 1u;
    }
    return 0;
}

#endif
