/*
 * dex2c_runtime.c — plain-C mirror of codehasan/dex2c Dex2C.cpp (TCC path).
 * Matches codehasan verbatim: FindClass + GetMethodID/GetStaticMethodID only.
 * No fallbacks, no classloader capture, no parent-delegation bypass.
 */
#include "Dex2C_runtime.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ── Simple hash cache (std::map not available in C) ─────────────────────── */
#define CACHE_SIZE 4096
typedef struct { const char *k1, *k2, *k3; void *v; } CEntry;
static CEntry class_cache[CACHE_SIZE];
static CEntry method_cache[CACHE_SIZE];
static CEntry field_cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int hash3(const char *a, const char *b, const char *c) {
    unsigned int h = 5381;
    if (a) while (*a) h = ((h<<5)+h)^(unsigned char)*a++;
    if (b) while (*b) h = ((h<<5)+h)^(unsigned char)*b++;
    if (c) while (*c) h = ((h<<5)+h)^(unsigned char)*c++;
    return h % CACHE_SIZE;
}

/* ── d2c_throw_exception ─────────────────────────────────────────────────── */
void d2c_throw_exception(JNIEnv *env, const char *class_name, const char *message) {
    jclass c = (*env)->FindClass(env, class_name);
    if (c) {
        (*env)->ThrowNew(env, c, message);
        (*env)->DeleteLocalRef(env, c);
    }
}

/* ── d2c_filled_new_array ────────────────────────────────────────────────── */
void d2c_filled_new_array(JNIEnv *env, jarray array, const char *type, jint count, ...) {
    va_list args;
    va_start(args, count);
    char ty = type[0];
    int ref = (ty == '[' || ty == 'L');
    for (int i = 0; i < count; i++) {
        if (ref) {
            jobject obj = (jobject)(uintptr_t)va_arg(args, long);
            (*env)->SetObjectArrayElement(env, (jobjectArray)array, i, obj);
        } else {
            jint val = va_arg(args, jint);
            (*env)->SetIntArrayRegion(env, (jintArray)array, i, 1, &val);
        }
    }
    va_end(args);
}

/* ── numeric conversions ─────────────────────────────────────────────────── */
int64_t d2c_double_to_long(double val) {
    if (val != val) return 0;
    if (val > (double)INT64_MAX) return INT64_MAX;
    if (val < (double)INT64_MIN) return INT64_MIN;
    return (int64_t)val;
}

int64_t d2c_float_to_long(float val) {
    if (val != val) return 0;
    if (val > (float)INT64_MAX) return INT64_MAX;
    if (val < (float)INT64_MIN) return INT64_MIN;
    return (int64_t)val;
}

int32_t d2c_double_to_int(double val) {
    if (val != val) return 0;
    if (val > (double)INT32_MAX) return INT32_MAX;
    if (val < (double)INT32_MIN) return INT32_MIN;
    return (int32_t)val;
}

int32_t d2c_float_to_int(float val) {
    if (val != val) return 0;
    if (val > (float)INT32_MAX) return INT32_MAX;
    if (val < (float)INT32_MIN) return INT32_MIN;
    return (int32_t)val;
}

/* ── d2c_is_instance_of ──────────────────────────────────────────────────── */
bool d2c_is_instance_of(JNIEnv *env, jobject instance, const char *class_name) {
    if (!instance) return false;
    jclass c = (*env)->FindClass(env, class_name);
    if (!c) { (*env)->ExceptionClear(env); return false; }
    bool result = (*env)->IsInstanceOf(env, instance, c);
    (*env)->DeleteLocalRef(env, c);
    return result;
}

/* ── d2c_check_cast ──────────────────────────────────────────────────────── */
bool d2c_check_cast(JNIEnv *env, jobject instance, jclass clz, const char *class_name) {
    if ((*env)->IsInstanceOf(env, instance, clz)) return false;
    d2c_throw_exception(env, "java/lang/ClassCastException", class_name);
    return true;
}

/* ── d2c_resolve_class ───────────────────────────────────────────────────── */
bool d2c_resolve_class(JNIEnv *env, jclass *cached_class, const char *class_name) {
    if (*cached_class) return false;
    unsigned int idx = hash3(class_name, NULL, NULL);
    pthread_mutex_lock(&cache_mutex);
    if (class_cache[idx].k1 && strcmp(class_cache[idx].k1, class_name) == 0) {
        *cached_class = (jclass)class_cache[idx].v;
        pthread_mutex_unlock(&cache_mutex);
        return false;
    }
    pthread_mutex_unlock(&cache_mutex);
    jclass clz = (*env)->FindClass(env, class_name);
    if (!clz) return true;
    jclass global = (jclass)(*env)->NewGlobalRef(env, clz);
    (*env)->DeleteLocalRef(env, clz);
    *cached_class = global;
    pthread_mutex_lock(&cache_mutex);
    class_cache[idx].k1 = class_name;
    class_cache[idx].v  = global;
    pthread_mutex_unlock(&cache_mutex);
    return false;
}

/* ── d2c_resolve_method ──────────────────────────────────────────────────── */
bool d2c_resolve_method(JNIEnv *env, jclass *cached_class, jmethodID *cached_method,
                        bool is_static, const char *class_name,
                        const char *method_name, const char *signature) {
    if (*cached_method) return false;
    if (d2c_resolve_class(env, cached_class, class_name)) return true;

    unsigned int idx = hash3(class_name, method_name, signature);
    pthread_mutex_lock(&cache_mutex);
    if (method_cache[idx].k1
        && strcmp(method_cache[idx].k1, class_name)  == 0
        && strcmp(method_cache[idx].k2, method_name) == 0
        && strcmp(method_cache[idx].k3, signature)   == 0) {
        *cached_method = (jmethodID)method_cache[idx].v;
        pthread_mutex_unlock(&cache_mutex);
        return false;
    }
    pthread_mutex_unlock(&cache_mutex);

    jmethodID mid = is_static
        ? (*env)->GetStaticMethodID(env, *cached_class, method_name, signature)
        : (*env)->GetMethodID      (env, *cached_class, method_name, signature);

    if (mid) {
        pthread_mutex_lock(&cache_mutex);
        method_cache[idx].k1 = class_name;
        method_cache[idx].k2 = method_name;
        method_cache[idx].k3 = signature;
        method_cache[idx].v  = mid;
        pthread_mutex_unlock(&cache_mutex);
        *cached_method = mid;
    }
    return mid == NULL;
}

/* ── d2c_resolve_field ───────────────────────────────────────────────────── */
bool d2c_resolve_field(JNIEnv *env, jclass *cached_class, jfieldID *cached_field,
                       bool is_static, const char *class_name,
                       const char *field_name, const char *signature) {
    if (*cached_field) return false;
    if (d2c_resolve_class(env, cached_class, class_name)) return true;

    unsigned int idx = hash3(class_name, field_name, signature);
    pthread_mutex_lock(&cache_mutex);
    if (field_cache[idx].k1
        && strcmp(field_cache[idx].k1, class_name) == 0
        && strcmp(field_cache[idx].k2, field_name) == 0
        && strcmp(field_cache[idx].k3, signature)  == 0) {
        *cached_field = (jfieldID)field_cache[idx].v;
        pthread_mutex_unlock(&cache_mutex);
        return false;
    }
    pthread_mutex_unlock(&cache_mutex);

    jfieldID fid = is_static
        ? (*env)->GetStaticFieldID(env, *cached_class, field_name, signature)
        : (*env)->GetFieldID      (env, *cached_class, field_name, signature);

    if (fid) {
        pthread_mutex_lock(&cache_mutex);
        field_cache[idx].k1 = class_name;
        field_cache[idx].k2 = field_name;
        field_cache[idx].k3 = signature;
        field_cache[idx].v  = fid;
        pthread_mutex_unlock(&cache_mutex);
        *cached_field = fid;
    }
    return fid == NULL;
}
