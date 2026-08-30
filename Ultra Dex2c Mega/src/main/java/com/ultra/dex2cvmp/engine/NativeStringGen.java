package com.ultra.dex2cvmp.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * NativeStringGen — generates ph_strings.cpp for native string injection.
 *
 * Encryption layers (per-run random keys, compiled into .so):
 *   1. XOR (32-byte key, position-twisted)
 *   2. ChaCha20 stream cipher (32-byte key + 12-byte nonce, no padding)
 *
 * Key protection layers:
 *   A. Arithmetic gate (_ph_gate): 5 random constants → XOR masks cc20Key[0..3].
 *      Used by ph_strings_register (called from JNI_OnLoad — pure C, safe).
 *   B. JNI gate (VMP mode only): calls PhStringGate.computeToken() via JNI.
 *      In VMP mode computeToken() runs as VMP opcodes (opaque to Ghidra).
 *      In DEX2C mode it is compiled ARM.
 *      Used only by phStrInject (called from <clinit>, after VMP engine is ready).
 *
 * Critical rule: ALL strings are encrypted with the REAL key K.
 * _pha_key stores K[0..3] XOR'd with arithmetic-gate-token (for register path).
 * _pha_jk  stores K[0..3] XOR'd with JNI-gate-token     (for inject path).
 * Each path recovers K independently before decrypting.
 */
public class NativeStringGen {

    public static class StringEntry {
        public final String fieldName;
        public final String value;
        public StringEntry(String fieldName, String value) {
            this.fieldName = fieldName;
            this.value     = value;
        }
    }

    /**
     * Generate ph_strings.cpp and ph_aes_impl.h into cSourceDir.
     * Must be called AFTER GateContext.token / GateContext.enabled are set.
     */
    public static void generate(Map<String, List<StringEntry>> table,
                                File cSourceDir) throws Exception {
        if (table == null || table.isEmpty()) return;
        cSourceDir.mkdirs();

        // ── Keys ─────────────────────────────────────────────────────────────
        SecureRandom rng = new SecureRandom();
        byte[] xorKey  = new byte[32];
        byte[] cc20Key = new byte[32];   // will become _pha_key after masking
        byte[] nonce   = new byte[12];
        rng.nextBytes(xorKey);
        rng.nextBytes(cc20Key);
        rng.nextBytes(nonce);

        // Save the REAL key K before any masking — all strings are encrypted with K.
        byte[] realKey = cc20Key.clone();

        // ── Arithmetic gates ×8 ──────────────────────────────────────────────
        // Each gate covers 4 bytes of K → all 32 bytes are gate-protected.
        // Recovering K requires tracing 8 independent noinline/optnone functions.
        int[][] gc = new int[8][5];
        int[]   gv = new int[8];
        for (int _g = 0; _g < 8; _g++) {
            for (int _k = 0; _k < 5; _k++) gc[_g][_k] = rng.nextInt();
            gc[_g][4] |= 1; // odd → invertible mod 2^32
            int _v = gc[_g][0] ^ gc[_g][1];
            _v = Integer.rotateLeft(_v, 13); _v += gc[_g][2]; _v ^= gc[_g][3];
            _v = Integer.rotateRight(_v, 7); _v *= gc[_g][4];
            gv[_g] = _v;
            cc20Key[_g*4+0] ^= (byte)((_v >>> 24) & 0xFF);
            cc20Key[_g*4+1] ^= (byte)((_v >>> 16) & 0xFF);
            cc20Key[_g*4+2] ^= (byte)((_v >>>  8) & 0xFF);
            cc20Key[_g*4+3] ^= (byte)( _v         & 0xFF);
        }
        // cc20Key is now _pha_key (all 32 bytes gate-masked)

        // ── JNI gate (VMP mode only) ─────────────────────────────────────────
        // _pha_jk[0..3] = K[0..3] ^ jni_token.
        // _pha_jk[4..31] = K[4..31] ^ gate[1..7] (reuses arithmetic gates 1-7).
        boolean jniGate = GateContext.enabled;
        byte[] jniMaskedKey = null;
        if (jniGate) {
            int jt = GateContext.token;
            jniMaskedKey = realKey.clone();
            // K[0..3]: masked by JNI token (computeToken from VMP)
            jniMaskedKey[0] ^= (byte)((jt >>> 24) & 0xFF);
            jniMaskedKey[1] ^= (byte)((jt >>> 16) & 0xFF);
            jniMaskedKey[2] ^= (byte)((jt >>>  8) & 0xFF);
            jniMaskedKey[3] ^= (byte)( jt          & 0xFF);
            // K[4..31]: masked by arithmetic gates 1-7 (same values, both paths share)
            for (int _g = 1; _g < 8; _g++) {
                jniMaskedKey[_g*4+0] ^= (byte)((gv[_g] >>> 24) & 0xFF);
                jniMaskedKey[_g*4+1] ^= (byte)((gv[_g] >>> 16) & 0xFF);
                jniMaskedKey[_g*4+2] ^= (byte)((gv[_g] >>>  8) & 0xFF);
                jniMaskedKey[_g*4+3] ^= (byte)( gv[_g]          & 0xFF);
            }
        }

        // ── Write ph_aes_impl.h ───────────────────────────────────────────────
        File cipherHdr = new File(cSourceDir, "ph_aes_impl.h");
        try (FileOutputStream fos = new FileOutputStream(cipherHdr)) {
            fos.write(AesCrypto.getAesImplCode().getBytes(StandardCharsets.UTF_8));
        }

        StringBuilder sb = new StringBuilder(8192);
        sb.append("// ph_strings.cpp — AUTO-GENERATED — DO NOT EDIT\n");
        sb.append("// Strings encrypted with ChaCha20 + XOR (double-layer, random keys per run).\n");
        sb.append("// SetStaticObjectField + NewStringUTF resolved via vtable pointer (Frida-safe).\n\n");
         sb.append("#include <jni.h>\n#include <string.h>\n#include <stdlib.h>\n");
        sb.append("#include <stddef.h>\n#include <stdint.h>\n");
        sb.append("#include \"ph_aes_impl.h\"\n\n");

        // ── XOR key halves — HI⊕LO split so no single readable array is the key ─
        // Generate random HI halves; LO = data XOR HI → runtime: HI^LO = data.
        byte[] phk0hi = new byte[16], phk0lo = new byte[16];
        byte[] phk1hi = new byte[16], phk1lo = new byte[16];
        rng.nextBytes(phk0hi); rng.nextBytes(phk1hi);
        for (int i = 0; i < 16; i++) {
            phk0lo[i] = (byte)(xorKey[i]      ^ phk0hi[i]);
            phk1lo[i] = (byte)(xorKey[16 + i] ^ phk1hi[i]);
        }
        emitByteArr(sb, "static const unsigned char _phk0_hi[16]", phk0hi);
        emitByteArr(sb, "static const unsigned char _phk0_lo[16]", phk0lo);
        emitByteArr(sb, "static const unsigned char _phk1_hi[16]", phk1hi);
        emitByteArr(sb, "static const unsigned char _phk1_lo[16]", phk1lo);
        sb.append('\n');

        // ── _pha_key HI⊕LO: arithmetic-gated cc20 key (register path) ────────
        byte[] phaKeyHi = new byte[32], phaKeyLo = new byte[32];
        rng.nextBytes(phaKeyHi);
        for (int i = 0; i < 32; i++) phaKeyLo[i] = (byte)(cc20Key[i] ^ phaKeyHi[i]);
        emitByteArr(sb, "static const uint8_t _pha_key_hi[32]", phaKeyHi);
        emitByteArr(sb, "static const uint8_t _pha_key_lo[32]", phaKeyLo);

        sb.append("static const uint8_t _pha_nonce[12] = {");
        for (int i = 0; i < 12; i++) { if (i>0) sb.append(','); sb.append(String.format("0x%02X", nonce[i]&0xFF)); }
        sb.append("};\n");

        if (jniGate) {
            // ── _pha_jk HI⊕LO: JNI-gated cc20 key (inject path) ──────────────
            byte[] phaJkHi = new byte[32], phaJkLo = new byte[32];
            rng.nextBytes(phaJkHi);
            for (int i = 0; i < 32; i++) phaJkLo[i] = (byte)(jniMaskedKey[i] ^ phaJkHi[i]);
            emitByteArr(sb, "static const uint8_t _pha_jk_hi[32]", phaJkHi);
            emitByteArr(sb, "static const uint8_t _pha_jk_lo[32]", phaJkLo);
        }
        sb.append('\n');

        // ── 8 arithmetic gate functions — each masks 4 bytes of K ────────────
        for (int _g = 0; _g < 8; _g++) {
            sb.append("static __attribute__((noinline,optnone)) uint32_t _ph_gate").append(_g).append("(void){\n");
            sb.append(String.format(
                "    volatile uint32_t _a=0x%08XU,_b=0x%08XU,_c=0x%08XU,_d=0x%08XU,_e=0x%08XU;\n",
                gc[_g][0], gc[_g][1], gc[_g][2], gc[_g][3], gc[_g][4]));
            sb.append("    uint32_t _v=(uint32_t)_a; _v^=(uint32_t)_b;\n");
            sb.append("    _v=(_v<<13)|(_v>>19); _v+=(uint32_t)_c; _v^=(uint32_t)_d;\n");
            sb.append("    _v=(_v>>7)|(_v<<25);  _v*=(uint32_t)_e; return _v;\n");
            sb.append("}\n");
        }
        // _ph_rkey: reconstructs K from HI^LO then un-masks all 8 gates (all 32 bytes)
        sb.append("static __attribute__((noinline,optnone)) void _ph_rkey(uint8_t* dst) {\n");
        sb.append("    const volatile uint8_t* _hi=_pha_key_hi; const volatile uint8_t* _lo=_pha_key_lo;\n");
        sb.append("    for(int _i=0;_i<32;_i++) dst[_i]=_hi[_i]^_lo[_i];\n");
        for (int _g = 0; _g < 8; _g++) {
            sb.append("    {const uint32_t _gv=_ph_gate").append(_g).append("();\n");
            sb.append("     dst[").append(_g*4  ).append("]^=(uint8_t)((_gv>>24)&0xFF);");
            sb.append(" dst[").append(_g*4+1).append("]^=(uint8_t)((_gv>>16)&0xFF);\n");
            sb.append("     dst[").append(_g*4+2).append("]^=(uint8_t)((_gv>>8)&0xFF);");
            sb.append(" dst[").append(_g*4+3).append("]^=(uint8_t)(_gv&0xFF);}\n");
        }
        sb.append("}\n\n");

        // ── _phd_cc20: always_inline → no single hookable entry point ──────────
        // _si: compile-time string index XOR'd into nonce → unique keystream per string.
        // volatile array pointers prevent optimizer from folding HI^LO at inlined call sites.
        sb.append("static __attribute__((always_inline)) inline void _phd_cc20(const uint8_t* key,\n");
        sb.append("                      const unsigned char* e, int n,\n");
        sb.append("                      uint8_t* tb, char* o, int _si) {\n");
        sb.append("    uint8_t _n[12]; __builtin_memcpy(_n,_pha_nonce,12);\n");
        sb.append("    _n[0]^=(uint8_t)(_si&0xFF); _n[1]^=(uint8_t)((_si>>8)&0xFF);\n");
        sb.append("    _n[2]^=(uint8_t)((_si>>16)&0xFF); _n[3]^=(uint8_t)((_si>>24)&0xFF);\n");
        sb.append("    const volatile unsigned char* _h0=_phk0_hi,*_l0=_phk0_lo;\n");
        sb.append("    const volatile unsigned char* _h1=_phk1_hi,*_l1=_phk1_lo;\n");
        sb.append("    memcpy(tb, e, n);\n");
        sb.append("    _pha_cc20_dec(key, _n, tb, n);\n");
        sb.append("    for (int _i = 0; _i < n; _i++) {\n");
        sb.append("        const unsigned char _xk =\n");
        sb.append("            (_i < 16\n");
        sb.append("                ? (unsigned char)(_h0[_i&15] ^ _l0[_i&15])\n");
        sb.append("                : (unsigned char)(_h1[_i&15] ^ _l1[_i&15]))\n");
        sb.append("            ^ (unsigned char)(_i * 0x1D);\n");
        sb.append("        o[_i] = (char)(tb[_i] ^ _xk);\n");
        sb.append("    }\n");
        sb.append("    o[n] = '\\0';\n");
        sb.append("    memset(tb, 0, n);\n");
        sb.append("}\n\n");

        // ── Vtable-indirect SetStaticObjectField ──────────────────────────────
        sb.append("static void _ph_set(JNIEnv* env, jclass clz, jfieldID fid, jstring s) {\n");
        sb.append("    typedef void (*_fn_t)(JNIEnv*, jclass, jfieldID, jobject);\n");
        sb.append("    const size_t _off = offsetof(JNINativeInterface, SetStaticObjectField);\n");
        sb.append("    void* const* _vtbl = *(void* const**)env;\n");
        sb.append("    volatile _fn_t _fn = (_fn_t)_vtbl[_off / sizeof(void*)];\n");
        sb.append("    _fn(env, clz, fid, s);\n");
        sb.append("}\n\n");

        // ── Vtable-indirect NewStringUTF ──────────────────────────────────────
        sb.append("static jstring _ph_new_str(JNIEnv* env, const char* s) {\n");
        sb.append("    typedef jstring (*_fn_t)(JNIEnv*, const char*);\n");
        sb.append("    const size_t _off = offsetof(JNINativeInterface, NewStringUTF);\n");
        sb.append("    void* const* _vtbl = *(void* const**)env;\n");
        sb.append("    volatile _fn_t _fn = (_fn_t)_vtbl[_off / sizeof(void*)];\n");
        sb.append("    return _fn(env, s);\n");
        sb.append("}\n\n");

        // ── Per-class encrypted arrays + injection functions ──────────────────
        int _phSi = 0;  // global index for per-string nonce tweak (Fix 2)
        Map<String, Integer> _phFcSiMap = new LinkedHashMap<>();
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();
            List<StringEntry> fields = ce.getValue();
            if (fields.isEmpty()) continue;

            String jniCls  = toJniClassName(classDesc);
            String funcName = "Java_" + jniCls + "_phStrInject";

            String fcPath = classDesc;
            if (fcPath.startsWith("L")) fcPath = fcPath.substring(1);
            if (fcPath.endsWith(";"))   fcPath = fcPath.substring(0, fcPath.length() - 1);
            byte[] fcPlain = fcPath.getBytes(StandardCharsets.UTF_8);
            // Each string gets unique nonce: base nonce XOR le32(strIdx)
            int _fcSi = _phSi++;
            _phFcSiMap.put(classDesc, _fcSi);
            byte[] fcEnc = AesCrypto.encrypt(fcPlain, xorKey, realKey, nonce, _fcSi);

            sb.append("// ").append(classDesc).append(" — ").append(fields.size()).append(" field(s)\n");
            emitByteArr(sb, "static const unsigned char _phc_" + jniCls
                    + "[" + fcEnc.length + "]", fcEnc);

            // Assign unique indices for every name+value pair before emitting arrays
            int[] _nameSi = new int[fields.size()], _valSi = new int[fields.size()];
            byte[][] _namePlains = new byte[fields.size()][], _valPlains = new byte[fields.size()][];
            for (int i = 0; i < fields.size(); i++) {
                StringEntry se = fields.get(i);
                _namePlains[i] = se.fieldName.getBytes(StandardCharsets.UTF_8);
                _valPlains[i]  = se.value.getBytes(StandardCharsets.UTF_8);
                _nameSi[i] = _phSi++;
                _valSi[i]  = _phSi++;
                byte[] nameEnc = AesCrypto.encrypt(_namePlains[i], xorKey, realKey, nonce, _nameSi[i]);
                byte[] valEnc  = AesCrypto.encrypt(_valPlains[i],  xorKey, realKey, nonce, _valSi[i]);
                emitByteArr(sb, "static const unsigned char _phv_" + jniCls + "_" + i
                        + "[" + valEnc.length + "]", valEnc);
                emitByteArr(sb, "static const unsigned char _phn_" + jniCls + "_" + i
                        + "[" + nameEnc.length + "]", nameEnc);
            }

            // ── JNI injection function ────────────────────────────────────────
            sb.append("extern \"C\" JNIEXPORT void JNICALL ").append(funcName)
              .append("(JNIEnv* env, jclass clz) {\n");

            if (jniGate) {
                // JNI gate: K[0..3] via computeToken (VMP), K[4..31] via arithmetic gates 1-7
                sb.append("    uint8_t _ik[32];\n");
                sb.append("    {const volatile uint8_t* _jh=_pha_jk_hi; const volatile uint8_t* _jl=_pha_jk_lo;\n");
                sb.append("     for(int _qi=0;_qi<32;_qi++) _ik[_qi]=_jh[_qi]^_jl[_qi];}\n");
                sb.append("    {\n");
                sb.append("        jclass _gc = env->FindClass(\"").append(GateContext.CLASS_DESC).append("\");\n");
                sb.append("        if (_gc) {\n");
                sb.append("            jmethodID _gm = env->GetStaticMethodID(_gc, \"")
                  .append(GateContext.METHOD_NAME).append("\", \"")
                  .append(GateContext.METHOD_SIG).append("\");\n");
                sb.append("            if (_gm) {\n");
                sb.append("                const jint _gt = env->CallStaticIntMethod(_gc, _gm);\n");
                sb.append("                _ik[0]^=(uint8_t)((_gt>>24)&0xFF);\n");
                sb.append("                _ik[1]^=(uint8_t)((_gt>>16)&0xFF);\n");
                sb.append("                _ik[2]^=(uint8_t)((_gt>> 8)&0xFF);\n");
                sb.append("                _ik[3]^=(uint8_t)(_gt&0xFF);\n");
                sb.append("            }\n");
                sb.append("            env->DeleteLocalRef(_gc);\n");
                sb.append("        }\n");
                sb.append("        if (env->ExceptionCheck()) env->ExceptionClear();\n");
                sb.append("    }\n");
                // Un-mask K[4..31] with arithmetic gates 1-7 (shared with _ph_rkey path)
                for (int _gg = 1; _gg < 8; _gg++) {
                    sb.append("    {const uint32_t _gv=_ph_gate").append(_gg).append("();\n");
                    sb.append("     _ik[").append(_gg*4  ).append("]^=(uint8_t)((_gv>>24)&0xFF);");
                    sb.append(" _ik[").append(_gg*4+1).append("]^=(uint8_t)((_gv>>16)&0xFF);\n");
                    sb.append("     _ik[").append(_gg*4+2).append("]^=(uint8_t)((_gv>>8)&0xFF);");
                    sb.append(" _ik[").append(_gg*4+3).append("]^=(uint8_t)(_gv&0xFF);}\n");
                }
            } else {
                sb.append("    uint8_t _ik[32]; _ph_rkey(_ik);\n");
            }

             sb.append("    jfieldID _f; jstring _s;\n");

            for (int i = 0; i < fields.size(); i++) {
                String valArr  = "_phv_" + jniCls + "_" + i;
                String nameArr = "_phn_" + jniCls + "_" + i;

                sb.append("    {\n");
                 // Allocate from the heap using the exact plaintext length.
                 // Static strings can contain large Base64 assets (for example,
                 // Kawogo's 219 KB embedded PNG), so fixed stack buffers are
                 // unsafe and would overflow during _phd_cc20().
                 sb.append("        uint8_t* _tn = (uint8_t*)malloc(")
                   .append(_namePlains[i].length).append("u ? ")
                   .append(_namePlains[i].length).append("u : 1u);\n");
                 sb.append("        char* _b2 = (char*)malloc(")
                   .append(_namePlains[i].length + 1).append("u);\n");
                 sb.append("        if (!_tn || !_b2) {\n");
                 sb.append("            if (_tn) free(_tn); if (_b2) free(_b2);\n");
                 sb.append("            jclass _oom = env->FindClass(\"java/lang/OutOfMemoryError\");\n");
                 sb.append("            if (_oom) { env->ThrowNew(_oom, \"VMP string-name buffer allocation failed\"); env->DeleteLocalRef(_oom); }\n");
                 sb.append("            return; }\n");
                sb.append("        _phd_cc20(_ik, ").append(nameArr).append(", ")
                  .append(_namePlains[i].length).append(", _tn, _b2, ").append(_nameSi[i]).append(");\n");
                sb.append("        _f = env->GetStaticFieldID(clz, _b2, \"Ljava/lang/String;\");\n");
                 memsetAndFree(sb, "_b2", "_tn", _namePlains[i].length + 1);
                 sb.append("        if (!_f) { if(env->ExceptionCheck()) env->ExceptionClear();\n");
                 sb.append("            goto _next_").append(i).append("; }\n");
                 sb.append("        uint8_t* _tv = (uint8_t*)malloc(")
                   .append(_valPlains[i].length).append("u ? ")
                   .append(_valPlains[i].length).append("u : 1u);\n");
                 sb.append("        char* _b = (char*)malloc(")
                   .append(_valPlains[i].length + 1).append("u);\n");
                 sb.append("        if (!_tv || !_b) {\n");
                 sb.append("            if (_tv) free(_tv); if (_b) free(_b);\n");
                 sb.append("            jclass _oom = env->FindClass(\"java/lang/OutOfMemoryError\");\n");
                 sb.append("            if (_oom) { env->ThrowNew(_oom, \"VMP string buffer allocation failed\"); env->DeleteLocalRef(_oom); }\n");
                 sb.append("            return; }\n");
                sb.append("        _phd_cc20(_ik, ").append(valArr).append(", ")
                  .append(_valPlains[i].length).append(", _tv, _b, ").append(_valSi[i]).append(");\n");
                sb.append("        _s = _ph_new_str(env, _b);\n");
                sb.append("        if (_s) { _ph_set(env, clz, _f, _s); env->DeleteLocalRef(_s); }\n");
                 memsetAndFree(sb, "_b", "_tv", _valPlains[i].length + 1);
                 sb.append("        if (env->ExceptionCheck()) return;\n");
                sb.append("    }\n");
                sb.append("    _next_").append(i).append(":;\n");
                sb.append("    if(env->ExceptionCheck()) env->ExceptionClear();\n");
            }
            sb.append("    memset(_ik, 0, 32);\n");
            sb.append("}\n\n");
        }

        // ── RegisterNatives table ─────────────────────────────────────────────
        sb.append("// ── ph_strings_register — called from JNI_OnLoad ─────────────────────\n");
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();
            if (ce.getValue().isEmpty()) continue;
            String jniCls   = toJniClassName(classDesc);
            String funcName = "Java_" + jniCls + "_phStrInject";
            sb.append("static JNINativeMethod _phr_").append(jniCls).append("[] = {\n");
            sb.append("    {\"phStrInject\",\"()V\",(void*)").append(funcName).append("}\n");
            sb.append("};\n");
        }

        // ph_strings_register: always uses arithmetic gate (_ph_rkey) — safe at JNI_OnLoad.
        sb.append("extern \"C\" void ph_strings_register(JNIEnv* env) {\n");
        sb.append("    uint8_t _rk[32]; _ph_rkey(_rk);  // arithmetic gate: safe at JNI_OnLoad\n");
         sb.append("    jclass _c;\n");
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();
            if (ce.getValue().isEmpty()) continue;
            String jniCls = toJniClassName(classDesc);
            String fcPath = classDesc;
            if (fcPath.startsWith("L")) fcPath = fcPath.substring(1);
            if (fcPath.endsWith(";"))   fcPath = fcPath.substring(0, fcPath.length() - 1);
            byte[] fcPlain = fcPath.getBytes(StandardCharsets.UTF_8);

             sb.append("    {\n");
             sb.append("        uint8_t* _tc = (uint8_t*)malloc(")
               .append(fcPlain.length).append("u ? ")
               .append(fcPlain.length).append("u : 1u);\n");
             sb.append("        char* _cb = (char*)malloc(")
               .append(fcPlain.length + 1).append("u);\n");
             sb.append("        if (!_tc || !_cb) { if (_tc) free(_tc); if (_cb) free(_cb); return; }\n");
            sb.append("        _phd_cc20(_rk, _phc_").append(jniCls).append(", ")
              .append(fcPlain.length).append(", _tc, _cb, ").append(_phFcSiMap.get(classDesc)).append(");\n");
             sb.append("        _c = env->FindClass(_cb);\n");
            sb.append("    if(_c){ env->RegisterNatives(_c,_phr_").append(jniCls)
              .append(",1); env->DeleteLocalRef(_c); }\n");
            sb.append("    if(env->ExceptionCheck()) env->ExceptionClear();\n");
             sb.append("        memset(_cb, 0, ").append(fcPlain.length + 1).append("u);\n");
             sb.append("        memset(_tc, 0, ").append(fcPlain.length).append("u);\n");
             sb.append("        free(_cb); free(_tc);\n");
             sb.append("    }\n");
        }
        sb.append("    memset(_rk, 0, 32);\n");
        sb.append("}\n");

        File out = new File(cSourceDir, "ph_strings.cpp");
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void memsetAndFree(StringBuilder sb, String output, String temp, int outputLength) {
        sb.append("        memset(").append(output).append(", 0, ")
          .append(outputLength).append("u);\n");
        sb.append("        free(").append(output).append("); free(").append(temp).append(");\n");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static final char[] _HEX = "0123456789ABCDEF".toCharArray();

    /** Emit a C byte-array declaration from a Java byte[]. */
    private static void emitByteArr(StringBuilder sb, String decl, byte[] data) {
        sb.append(decl).append(" = {");
        for (int i = 0; i < data.length; i++) {
            if (i > 0) sb.append(',');
            int b = data[i] & 0xFF;
            sb.append("0x").append(_HEX[b >> 4]).append(_HEX[b & 0xF]);
        }
        sb.append("};\n");
    }

    static String toJniClassName(String desc) {
        String s = desc;
        if (s.startsWith("L")) s = s.substring(1);
        if (s.endsWith(";"))   s = s.substring(0, s.length() - 1);
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if      (c == '/') sb.append('_');
            else if (c == '_') sb.append("_1");
            else if (c == '$') sb.append("_00024");
            else               sb.append(c);
        }
        return sb.toString();
    }
}
