#ifndef PHANTOM_JNI_CONSISTENCY_H
#define PHANTOM_JNI_CONSISTENCY_H

#include <jni.h>

#include "phantom_os_consistency.h"

/* Called on the Java-attached loader thread. It only uses standard JNI
 * operations and neither attaches a thread nor retains a JNI reference. */
static PH_RUNTIME_NATIVE ph_os_probe_result_t
ph_probe_jni_environment_native(JNIEnv *env, jclass caller_class) {
    if (!env || !*env || !caller_class) return PH_OS_PROBE_INCONSISTENT;
    if (!(*env)->ExceptionCheck || !(*env)->GetVersion ||
        !(*env)->GetJavaVM || !(*env)->GetObjectRefType ||
        !(*env)->IsSameObject)
        return PH_OS_PROBE_UNSUPPORTED;
    if ((*env)->ExceptionCheck(env)) return PH_OS_PROBE_UNSUPPORTED;

    jint version = (*env)->GetVersion(env);
    if (version < JNI_VERSION_1_6) return PH_OS_PROBE_UNSUPPORTED;

    JavaVM *vm = NULL;
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK || !vm)
        return PH_OS_PROBE_UNSUPPORTED;
    if (!*vm || !(*vm)->GetEnv) return PH_OS_PROBE_UNSUPPORTED;

    void *current_env = NULL;
    jint status = (*vm)->GetEnv(vm, &current_env, JNI_VERSION_1_6);
    if (status == JNI_EVERSION) return PH_OS_PROBE_UNSUPPORTED;
    if (status != JNI_OK || !current_env)
        return PH_OS_PROBE_INCONSISTENT;
    if (current_env != (void *)env)
        return PH_OS_PROBE_INCONSISTENT;

    jobjectRefType reference_type =
            (*env)->GetObjectRefType(env, (jobject)caller_class);
    jboolean self_same =
            (*env)->IsSameObject(env, caller_class, caller_class);
    jboolean nonnull_same =
            (*env)->IsSameObject(env, caller_class, NULL);
    if ((*env)->ExceptionCheck(env)) return PH_OS_PROBE_UNSUPPORTED;
    if (reference_type == JNIInvalidRefType ||
        self_same != JNI_TRUE || nonnull_same != JNI_FALSE)
        return PH_OS_PROBE_INCONSISTENT;

    return PH_OS_PROBE_OK;
}

#endif
