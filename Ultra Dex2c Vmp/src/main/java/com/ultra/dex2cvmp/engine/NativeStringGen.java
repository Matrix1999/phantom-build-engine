package com.ultra.dex2cvmp.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * NativeStringGen — generates ph_strings.cpp for native string injection.
 *
 * During protection, static String fields with hardcoded initializer values are
 * stripped from the shell DEX (field declaration stays, "= value" disappears).
 * This generator produces a C++ file that:
 *   1. Stores each stripped value XOR-encrypted with a random per-run key
 *   2. Emits a JNI function per class (Java_<Class>_phStrInject) that decrypts
 *      and restores all fields via JNI reflection (GetStaticFieldID +
 *      SetStaticObjectField) — works even on "static final" fields
 *
 * The generated ph_strings.cpp is placed in cSourceDir alongside the dex2c/VMP
 * C++ output and compiled into the same .so — no separate asset, no extra file.
 *
 * Call order at runtime (guaranteed by Tier1DexPatcher):
 *   <clinit> runs
 *     → System.loadLibrary("libname")   ← .so loaded, phStrInject registered
 *     → phStrInject()                   ← JNI sets all stripped fields
 *   <clinit> finishes
 *   App reads field → value is there → no crash
 *
 * Works for both dex2c mode and VMP mode. Works regardless of DEX packer state.
 */
public class NativeStringGen {

    /** One stripped field: name + plaintext value (collected from original DEX). */
    public static class StringEntry {
        public final String fieldName;
        public final String value;

        public StringEntry(String fieldName, String value) {
            this.fieldName = fieldName;
            this.value = value;
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

        StringBuilder sb = new StringBuilder(4096);
        sb.append("// ph_strings.cpp — AUTO-GENERATED — DO NOT EDIT\n");
        sb.append("// Native string injection: stripped static String field values\n");
        sb.append("// are stored XOR-encrypted here and restored at class init via JNI.\n\n");
        sb.append("#include <jni.h>\n");
        sb.append("#include <string.h>\n\n");

        // Key stored as two separate half-arrays to avoid a single contiguous key in binary
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

        // Inline decrypt: XOR with key byte (position-dependent to resist pattern analysis)
        sb.append("static void _phd(const unsigned char* e, int n, char* o) {\n");
        sb.append("    for (int i = 0; i < n; i++) {\n");
        sb.append("        const unsigned char k = (i < 16 ? _phk0[i & 15] : _phk1[i & 15])\n");
        sb.append("                                ^ (unsigned char)(i * 0x1D);\n");
        sb.append("        o[i] = (char)(e[i] ^ k);\n");
        sb.append("    }\n");
        sb.append("    o[n] = '\\0';\n");
        sb.append("}\n\n");

        // Per-class injection functions
        for (Map.Entry<String, List<StringEntry>> ce : table.entrySet()) {
            String classDesc = ce.getKey();   // "Lcom/example/Foo;"
            List<StringEntry> fields = ce.getValue();
            if (fields.isEmpty()) continue;

            String jniCls = toJniClassName(classDesc);   // "com_example_Foo"
            String funcName = "Java_" + jniCls + "_phStrInject";

            sb.append("// ").append(classDesc).append(" — ")
              .append(fields.size()).append(" field(s)\n");

            // Encrypted data arrays — one per field
            for (int i = 0; i < fields.size(); i++) {
                byte[] plain = fields.get(i).value.getBytes(StandardCharsets.UTF_8);
                byte[] enc   = encrypt(plain, key);
                sb.append("static const unsigned char _phe_").append(jniCls)
                  .append('_').append(i).append('[').append(enc.length).append("] = {");
                for (int j = 0; j < enc.length; j++) {
                    if (j > 0) sb.append(',');
                    sb.append(String.format("0x%02X", enc[j] & 0xFF));
                }
                sb.append("}; /* ").append(escapeComment(fields.get(i).fieldName)).append(" */\n");
            }

            // JNI injection function
            sb.append("JNIEXPORT void JNICALL ").append(funcName)
              .append("(JNIEnv* env, jclass clz) {\n");
            sb.append("    char _b[512]; jfieldID _f; jstring _s;\n");

            for (int i = 0; i < fields.size(); i++) {
                StringEntry se  = fields.get(i);
                byte[] plain    = se.value.getBytes(StandardCharsets.UTF_8);
                String arr      = "_phe_" + jniCls + "_" + i;
                String fldEsc   = escapeStr(se.fieldName);

                sb.append("    _phd(").append(arr).append(',').append(plain.length)
                  .append(",_b);\n");
                sb.append("    _f=env->GetStaticFieldID(clz,\"").append(fldEsc)
                  .append("\",\"Ljava/lang/String;\");\n");
                sb.append("    if(_f){_s=env->NewStringUTF(_b);\n");
                sb.append("           if(_s){env->SetStaticObjectField(clz,_f,_s);\n");
                sb.append("                  env->DeleteLocalRef(_s);}}\n");
                sb.append("    if(env->ExceptionCheck())env->ExceptionClear();\n");
                sb.append("    memset(_b,0,").append(plain.length + 1).append(");\n");
            }
            sb.append("}\n\n");
        }

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
     * JNI name-mangling rules: '/' → '_', '_' → '_1', '$' → '_00024'
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

    private static String escapeComment(String s) {
        return s.replace("*/", "* /");
    }
}
