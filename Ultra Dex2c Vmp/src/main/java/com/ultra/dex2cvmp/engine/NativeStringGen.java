package com.ultra.dex2cvmp.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * NativeStringGen — generates ph_strings.cpp for native string injection.
 *
 * Security properties of the generated code:
 *   1. Field VALUES      — XOR-encrypted byte arrays (per-run random 32-byte key)
 *   2. Field NAMES       — XOR-encrypted (same key) — no plaintext field name in binary
 *   3. Class paths       — XOR-encrypted (same key) — no plaintext class path in binary
 *   4. SetStaticObjectField — called via offsetof-based vtable pointer, not by name,
 *                             bypassing standard Frida Interceptor.attach hook point
 *   5. Stack buffer      — memset'd to zero immediately after use
 *   6. Key split         — stored as two separate 16-byte halves + position-dependent
 *                          twist (i * 0x1D) to resist pattern analysis
 */
public class NativeStringGen {

    /** One stripped field: name + plaintext value (collected from original DEX). */
    public static class StringEntry {
        public final String fieldName;
        public final String value;

        public StringEntry(String fieldName, String value) {
            this.fieldName = fieldName;
            this.value     = value;
        }
    }

    /**
     * Generate ph_strings.cpp into cSourceDir.
     *
     * @param table       classDesc (e.g. "Lcom/example/Foo;") → list of stripped fields
     * @param cSourceDir  directory where .cpp source files live (same as transpiler output)
     */
    public static void generate(Map<String, List<StringEntry>> table,
                                File cSourceDir) throws IOException {
        if (table == null || table.isEmpty()) return;
        cSourceDir.mkdirs();

        // Random 32-byte XOR key — unique per protection run, compiled into .so
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        StringBuilder sb = new StringBuilder(8192);
        sb.append("// ph_strings.cpp — AUTO-GENERATED — DO NOT EDIT\n");
        sb.append("// Field values, field names, and class paths are all XOR-encrypted.\n");
        sb.append("// SetStaticObjectField is called through a vtable pointer (offsetof),\n");
        sb.append("// not by direct name — bypasses standard JNI hook interception.\n\n");
        sb.append("#include <jni.h>\n");
        sb.append("#include <string.h>\n");
        sb.append("#include <stddef.h>\n\n");

        // ── Key: two separate 16-byte halves ─────────────────────────────────
        sb.append("static const unsigned char _phk0[16] = {");
        for (int i = 0; i < 16; i++) {
            if (i > 0) sb.append(',');
            sb.append(String.format("0x%02X", key[i] & 0xFF));
        }
        sb.append("};\n");
        sb.append("static const unsigned char _phk1[16] = {");
        for (int i = 16; i < 32; i++) {
            if (i > 16) sb.append(',');
            sb.append(String.format("0x%02X", key[i] & 0xFF));
        }
        sb.append("};\n\n");

        // ── XOR decrypt helper ───────────────────────────────────────────────
        sb.append("static void _phd(const unsigned char* e, int n, char* o) {\n");
        sb.append("    for (int i = 0; i < n; i++) {\n");
        sb.append("        const unsigned char k = (i < 16 ? _phk0[i & 15] : _phk1[i & 15])\n");
        sb.append("                                ^ (unsigned char)(i * 0x1D);\n");
        sb.append("        o[i] = (char)(e[i] ^ k);\n");
        sb.append("    }\n");
        sb.append("    o[n] = '\\0';\n");
        sb.append("}\n\n");

        // ── Vtable-indirect SetStaticObjectField ─────────────────────────────
        // Uses offsetof(JNINativeInterface, SetStaticObjectField) so the correct
        // slot is resolved at compile time without any direct symbol reference.
        // This means Frida's Interceptor.attach(findExportByName("SetStaticObjectField"))
        // does NOT intercept this call — it appears as an indirect branch in the .so.
        sb.append("static void _ph_set(JNIEnv* env, jclass clz, jfieldID fid, jstring s) {\n");
        sb.append("    typedef void (*_fn_t)(JNIEnv*, jclass, jfieldID, jobject);\n");
        sb.append("    const size_t _off = offsetof(JNINativeInterface, SetStaticObjectField);\n");
        sb.append("    void* const* _vtbl = *(void* const**)env;\n");
        sb.append("    volatile _fn_t _fn = (_fn_t)_vtbl[_off / sizeof(void*)];\n");
        sb.append("    _fn(env, clz, fid, s);\n");
        sb.append("}\n\n");

        // ── Vtable-indirect NewStringUTF ──────────────────────────────────────
        // Same technique: resolve NewStringUTF through the JNINativeInterface
        // vtable at runtime so Frida's named-export hook on "NewStringUTF"
        // does NOT fire. The call appears as a plain indirect branch in the .so.
        sb.append("static jstring _ph_new_str(JNIEnv* env, const char* s) {\n");
        sb.append("    typedef jstring (*_fn_t)(JNIEnv*, const char*);\n");
        sb.append("    const size_t _off = offsetof(JNINativeInterface, NewStringUTF);\n");
        sb.append("    void* const* _vtbl = *(void* const**)env;\n");
        sb.append("    volatile _fn_t _fn = (_fn_t)_vtbl[_off / sizeof(void*)];\n");
        sb.append("    return _fn(env, s);\n");
        sb.append("}\n\n");

        // ── Per-class encrypted data + injection functions ───────────────────
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();       // "Lcom/example/Foo;"
            List<StringEntry> fields = ce.getValue();
            if (fields.isEmpty()) continue;

            String jniCls  = toJniClassName(classDesc);  // "com_example_Foo"
            String funcName = "Java_" + jniCls + "_phStrInject";

            // Class path for FindClass: strip L prefix and ; suffix → "com/example/Foo"
            String fcPath = classDesc;
            if (fcPath.startsWith("L")) fcPath = fcPath.substring(1);
            if (fcPath.endsWith(";"))   fcPath = fcPath.substring(0, fcPath.length() - 1);
            byte[] fcEnc = encrypt(fcPath.getBytes(StandardCharsets.UTF_8), key);

            sb.append("// ").append(classDesc).append(" — ")
              .append(fields.size()).append(" field(s)\n");

            // Encrypted class path array
            sb.append("static const unsigned char _phc_").append(jniCls)
              .append('[').append(fcEnc.length).append("] = {");
            for (int j = 0; j < fcEnc.length; j++) {
                if (j > 0) sb.append(',');
                sb.append(String.format("0x%02X", fcEnc[j] & 0xFF));
            }
            sb.append("};\n");

            // Encrypted value + field name arrays — one pair per field
            for (int i = 0; i < fields.size(); i++) {
                StringEntry se = fields.get(i);

                // Encrypted VALUE
                byte[] valEnc  = encrypt(se.value.getBytes(StandardCharsets.UTF_8), key);
                sb.append("static const unsigned char _phv_").append(jniCls)
                  .append('_').append(i).append('[').append(valEnc.length).append("] = {");
                for (int j = 0; j < valEnc.length; j++) {
                    if (j > 0) sb.append(',');
                    sb.append(String.format("0x%02X", valEnc[j] & 0xFF));
                }
                sb.append("};\n");

                // Encrypted FIELD NAME
                byte[] nameEnc = encrypt(se.fieldName.getBytes(StandardCharsets.UTF_8), key);
                sb.append("static const unsigned char _phn_").append(jniCls)
                  .append('_').append(i).append('[').append(nameEnc.length).append("] = {");
                for (int j = 0; j < nameEnc.length; j++) {
                    if (j > 0) sb.append(',');
                    sb.append(String.format("0x%02X", nameEnc[j] & 0xFF));
                }
                sb.append("};\n");
            }

            // ── JNI injection function ───────────────────────────────────────
            // extern "C" is mandatory — ph_strings.cpp is compiled as C++ and
            // without it the symbol gets C++ mangled, breaking ART's static
            // Java_* lookup in DEX2C mode (VMP uses RegisterNatives so it is
            // immune to mangling, but DEX2C relies on the unmangled symbol name).
            sb.append("extern \"C\" JNIEXPORT void JNICALL ").append(funcName)
              .append("(JNIEnv* env, jclass clz) {\n");
            sb.append("    char _b[512]; jfieldID _f; jstring _s;\n");

            for (int i = 0; i < fields.size(); i++) {
                StringEntry se   = fields.get(i);
                byte[] valPlain  = se.value.getBytes(StandardCharsets.UTF_8);
                byte[] namePlain = se.fieldName.getBytes(StandardCharsets.UTF_8);
                String valArr    = "_phv_" + jniCls + "_" + i;
                String nameArr   = "_phn_" + jniCls + "_" + i;

                // Decrypt value into _b, then field name into _b2
                sb.append("    {\n");
                sb.append("        char _b2[256];\n");
                // Decrypt field name
                sb.append("        _phd(").append(nameArr).append(',')
                  .append(namePlain.length).append(",_b2);\n");
                // GetStaticFieldID with decrypted name
                sb.append("        _f = env->GetStaticFieldID(clz, _b2, \"Ljava/lang/String;\");\n");
                sb.append("        memset(_b2, 0, ").append(namePlain.length + 1).append(");\n");
                sb.append("        if (!_f) { if(env->ExceptionCheck()) env->ExceptionClear();\n");
                sb.append("            goto _next_").append(i).append("; }\n");
                // Decrypt value
                sb.append("        _phd(").append(valArr).append(',')
                  .append(valPlain.length).append(",_b);\n");
                sb.append("        _s = _ph_new_str(env, _b);\n");
                sb.append("        memset(_b, 0, ").append(valPlain.length + 1).append(");\n");
                sb.append("        if (_s) { _ph_set(env, clz, _f, _s);\n");
                sb.append("                  env->DeleteLocalRef(_s); }\n");
                sb.append("    }\n");
                sb.append("    _next_").append(i).append(":;\n");
                sb.append("    if(env->ExceptionCheck()) env->ExceptionClear();\n");
            }
            sb.append("}\n\n");
        }

        // ── RegisterNatives registration function ────────────────────────────
        // Class paths in FindClass are passed as decrypted strings from stack buffers
        // — no plaintext class path survives in the binary.
        sb.append("// ── ph_strings_register — called from JNI_OnLoad ──────────────────\n");
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();
            List<StringEntry> fields = ce.getValue();
            if (fields.isEmpty()) continue;
            String jniCls   = toJniClassName(classDesc);
            String funcName  = "Java_" + jniCls + "_phStrInject";
            sb.append("static JNINativeMethod _phr_").append(jniCls).append("[] = {\n");
            sb.append("    {\"phStrInject\",\"()V\",(void*)").append(funcName).append("}\n");
            sb.append("};\n");
        }

        sb.append("extern \"C\" void ph_strings_register(JNIEnv* env) {\n");
        sb.append("    char _cb[256]; jclass _c;\n");
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();
            List<StringEntry> fields = ce.getValue();
            if (fields.isEmpty()) continue;
            String jniCls = toJniClassName(classDesc);
            String fcPath = classDesc;
            if (fcPath.startsWith("L")) fcPath = fcPath.substring(1);
            if (fcPath.endsWith(";"))   fcPath = fcPath.substring(0, fcPath.length() - 1);
            int fcLen = fcPath.getBytes(StandardCharsets.UTF_8).length;

            // Decrypt class path at runtime — no plaintext class path in binary
            sb.append("    _phd(_phc_").append(jniCls).append(',').append(fcLen).append(",_cb);\n");
            sb.append("    _c = env->FindClass(_cb);\n");
            sb.append("    memset(_cb, 0, ").append(fcLen + 1).append(");\n");
            sb.append("    if(_c){ env->RegisterNatives(_c,_phr_").append(jniCls)
              .append(",1); env->DeleteLocalRef(_c); }\n");
            sb.append("    if(env->ExceptionCheck()) env->ExceptionClear();\n");
        }
        sb.append("}\n");

        File out = new File(cSourceDir, "ph_strings.cpp");
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** XOR-encrypt plaintext — matches the _phd() decrypt function above. */
    private static byte[] encrypt(byte[] plain, byte[] key) {
        byte[] enc = new byte[plain.length];
        for (int i = 0; i < plain.length; i++) {
            int ki = (i < 16 ? (key[i & 15] & 0xFF) : (key[16 + (i & 15)] & 0xFF))
                   ^ ((i * 0x1D) & 0xFF);
            enc[i] = (byte)(plain[i] ^ ki);
        }
        return enc;
    }

    /**
     * Convert DEX class descriptor to JNI class name component.
     *   "Lcom/example/Foo;"  → "com_example_Foo"
     *   "Lcom/a_b/Foo$Bar;"  → "com_a_1b_Foo_00024Bar"
     */
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

    private static String escapeStr(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
