#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAGIC 0x4D433244u

extern const unsigned char _scripts_blob_start[];
extern const unsigned char _scripts_blob_end[];

/* ── Key stored as volatile bytes — prevents constant-folding to immediates ── */
/*    Attacker needs a live memory dump, not just static disassembly.           */
static volatile const uint8_t _K0[8] = {0xA8,0x32,0x75,0xBC,0x5D,0x90,0x49,0x79};
static volatile const uint8_t _M0[8] = {0x5A,0xC3,0x8E,0x11,0x77,0xF0,0x6B,0x9D};

static volatile const uint8_t _K1[8] = {0x5B,0xDA,0x72,0x3E,0xB5,0x74,0x94,0x5C};
static volatile const uint8_t _M1[8] = {0x4E,0x32,0xA1,0x07,0xBC,0x28,0x55,0xE9};

static volatile const uint8_t _K2[8] = {0x95,0xA9,0xD1,0xD2,0x41,0x4E,0xFF,0x76};
static volatile const uint8_t _M2[8] = {0x83,0x6A,0xD4,0x2F,0x91,0x4C,0xB8,0x05};

static volatile const uint8_t _K3[8] = {0xBB,0x7E,0xCC,0x98,0xA8,0xE7,0xCE,0x3C};
static volatile const uint8_t _M3[8] = {0x60,0xCE,0x37,0x1A,0xF5,0x88,0x3C,0x57};

static __attribute__((noinline)) void _kp0(uint8_t *o) {
    for (int i = 0; i < 8; i++) o[i] = _K0[i] ^ _M0[i];
}
static __attribute__((noinline)) void _kp1(uint8_t *o) {
    for (int i = 0; i < 8; i++) o[i] = _K1[i] ^ _M1[i];
}
static __attribute__((noinline)) void _kp2(uint8_t *o) {
    for (int i = 0; i < 8; i++) o[i] = _K2[i] ^ _M2[i];
}
static __attribute__((noinline)) void _kp3(uint8_t *o) {
    for (int i = 0; i < 8; i++) o[i] = _K3[i] ^ _M3[i];
}

static __attribute__((noinline)) void _build_key(uint8_t *key32) {
    _kp0(key32);
    _kp1(key32 + 8);
    _kp2(key32 + 16);
    _kp3(key32 + 24);
}

// ── LAYER 1: Dynamic JNI — internal implementation (NOT exported) ──────────
//
// This function is registered at runtime via RegisterNatives in JNI_OnLoad.
// The mangled static name Java_com_dex2c_mega_engine_... is gone from .dynsym.
// An attacker using `nm -D libscripts.so` will see only JNI_OnLoad.

static jbyteArray _ngs_impl(JNIEnv *env, jclass cls) {
    (void)cls;

    const unsigned char *blob = _scripts_blob_start;
    jsize total = (jsize)(_scripts_blob_end - _scripts_blob_start);

    if (total < 8) return NULL;

    unsigned int magic =
        (unsigned int)blob[0] | ((unsigned int)blob[1] << 8) |
        ((unsigned int)blob[2] << 16) | ((unsigned int)blob[3] << 24);
    if (magic != MAGIC) return NULL;

    unsigned int zip_len =
        (unsigned int)blob[4] | ((unsigned int)blob[5] << 8) |
        ((unsigned int)blob[6] << 16) | ((unsigned int)blob[7] << 24);
    const unsigned char *enc = blob + 8;

    if (zip_len == 0 || zip_len > (unsigned int)(total - 8)) return NULL;

    uint8_t key[32];
    _build_key(key);

    jbyteArray arr = (*env)->NewByteArray(env, (jsize)zip_len);
    if (!arr) { memset(key, 0, 32); return NULL; }

    jbyte *out = (*env)->GetByteArrayElements(env, arr, NULL);
    if (!out) {
        memset(key, 0, 32);
        (*env)->DeleteLocalRef(env, arr);
        return NULL;
    }

    for (unsigned int i = 0; i < zip_len; i++)
        out[i] = (jbyte)(enc[i] ^ key[i % 32]);

    (*env)->ReleaseByteArrayElements(env, arr, out, 0);
    memset(key, 0, 32);
    return arr;
}

// ── RegisterNatives + JNI_OnLoad ───────────────────────────────────────────

static const JNINativeMethod SCRIPTS_METHODS[] = {
    {
        "nativeGetScripts",          // Java method name
        "()[B",                      // returns byte[]
        (void *)_ngs_impl            // internal C pointer — not in .dynsym
    }
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    jclass cls = (*env)->FindClass(env,
        "com/dex2c/mega/engine/Dex2cPythonBridge");
    if (!cls) return JNI_ERR;

    (*env)->RegisterNatives(env, cls, SCRIPTS_METHODS,
        (jint)(sizeof(SCRIPTS_METHODS) / sizeof(SCRIPTS_METHODS[0])));
    (*env)->DeleteLocalRef(env, cls);
    return JNI_VERSION_1_6;
}
