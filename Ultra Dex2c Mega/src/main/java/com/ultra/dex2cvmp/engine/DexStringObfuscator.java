package com.ultra.dex2cvmp.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.*;

/**
 * DexStringObfuscator — post-processes DEX2C / VMP generated C++ source files.
 *
 * Encrypts ALL string literals that appear as arguments to:
 *   • env->NewStringUTF("…")       → replaced with phDecStr_N(env)  [returns jstring]
 *   • (*env)->NewStringUTF(env,"…")→ same
 *   • GetStaticFieldID(*, "…", *)  → replaced with phCStr_N()       [returns const char*]
 *   • GetFieldID(*, "…", *)        → same
 *   • GetStaticMethodID(*, "…", *) → same
 *   • GetMethodID(*, "…", *)       → same
 *   • FindClass("…")               → same
 *   • const char* x = "…"         → same (static variable assignments)
 *
 * ChaCha20 + XOR double-layer: output length == input length, no padding.
 */
public class DexStringObfuscator {

    private static final Set<String> SKIP_FILES = new HashSet<>(Arrays.asList(
            "ph_strings.cpp", "ph_str_obf.cpp", "ph_str_obf.h", "ph_aes_impl.h"
    ));

    // ── Patterns ──────────────────────────────────────────────────────────────

    // NewStringUTF: returns jstring  → phDecStr_N(env)
    private static final Pattern NSU_CPP = Pattern.compile(
            "env\\s*->\\s*NewStringUTF\\s*\\(\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");
    private static final Pattern NSU_C = Pattern.compile(
            "\\(\\*\\s*env\\s*\\)\\s*->\\s*NewStringUTF\\s*\\(\\s*env\\s*,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");

    // JNI reflection calls: string literal arg → phCStr_N()
    //
    // DEX2C Python transpiler emits C-style JNI:
    //   (*env)->GetStaticFieldID(env, clz, "FIELD", "type")  ← C-style (3 args before string)
    //   (*env)->FindClass(env, "ClassName")                  ← C-style (1 arg before string)
    // VMP / manual code may emit C++-style:
    //   env->GetStaticFieldID(clz, "FIELD", "type")          ← C++-style (1 arg before string)
    //   env->FindClass("ClassName")                          ← C++-style (0 args before string)
    // We handle both with separate patterns.

    // GetStaticFieldID / GetFieldID — C-style: (env, clz, "name", "type")
    private static final Pattern GSFID_C = Pattern.compile(
            "(GetStaticFieldID|GetFieldID)\\s*\\(\\s*env\\s*,[^,]+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*,");
    // GetStaticFieldID / GetFieldID — C++-style: (clz, "name", "type")
    private static final Pattern GSFID_CPP = Pattern.compile(
            "(GetStaticFieldID|GetFieldID)\\s*\\((?!\\s*env\\s*,)[^,]+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*,");

    // GetStaticMethodID / GetMethodID — C-style: (env, clz, "name", "sig")
    private static final Pattern GSMID_C = Pattern.compile(
            "(GetStaticMethodID|GetMethodID)\\s*\\(\\s*env\\s*,[^,]+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*,");
    // GetStaticMethodID / GetMethodID — C++-style: (clz, "name", "sig")
    private static final Pattern GSMID_CPP = Pattern.compile(
            "(GetStaticMethodID|GetMethodID)\\s*\\((?!\\s*env\\s*,)[^,]+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*,");

    // FindClass — C-style: (env, "ClassName")
    private static final Pattern FCLASS_C = Pattern.compile(
            "(FindClass)\\s*\\(\\s*env\\s*,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");
    // FindClass — C++-style: ("ClassName")
    private static final Pattern FCLASS_CPP = Pattern.compile(
            "(FindClass)\\s*\\(\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");

    // ThrowNew — C-style: (env, exClass, "message") — hides "Class not found: X" etc.
    private static final Pattern THROWNEW_C = Pattern.compile(
            "(ThrowNew)\\s*\\(\\s*env\\s*,[^,]+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");
    // ThrowNew — C++-style: (exClass, "message")
    private static final Pattern THROWNEW_CPP = Pattern.compile(
            "(ThrowNew)\\s*\\((?!\\s*env\\s*,)[^,]+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");

    // ── Entry point ──────────────────────────────────────────────────────────

    public static int obfuscate(File sourceDir) throws Exception {
        File[] files = sourceDir.listFiles();
        if (files == null) return 0;

        List<File> sources = new ArrayList<>();
        for (File f : files) {
            String n = f.getName();
            if ((n.endsWith(".c") || n.endsWith(".cpp")) && !SKIP_FILES.contains(n))
                sources.add(f);
        }
        if (sources.isEmpty()) return 0;

        SecureRandom rng = new SecureRandom();
        byte[] xorKey  = new byte[32];
        byte[] cc20Key = new byte[32];
        byte[] nonce   = new byte[12];
        rng.nextBytes(xorKey); rng.nextBytes(cc20Key); rng.nextBytes(nonce);

        // Save REAL key K before masking — all strings must be encrypted with K.
        // cc20Key after masking = _pso_ck (stored in .rodata); _psod() recovers K at runtime.
        byte[] realCc20Key = cc20Key.clone();

        // ── Gates ×8 — each masks 4 bytes of cc20Key → all 32 bytes gate-protected ─
        int[][] gc = new int[8][5];
        int[]   gv = new int[8];
        for (int _g = 0; _g < 8; _g++) {
            for (int _k = 0; _k < 5; _k++) gc[_g][_k] = rng.nextInt();
            gc[_g][4] |= 1;
            int _v = gc[_g][0] ^ gc[_g][1];
            _v = Integer.rotateLeft(_v, 13); _v += gc[_g][2]; _v ^= gc[_g][3];
            _v = Integer.rotateRight(_v, 7); _v *= gc[_g][4];
            gv[_g] = _v;
            cc20Key[_g*4+0] ^= (byte)((_v >>> 24) & 0xFF);
            cc20Key[_g*4+1] ^= (byte)((_v >>> 16) & 0xFF);
            cc20Key[_g*4+2] ^= (byte)((_v >>>  8) & 0xFF);
            cc20Key[_g*4+3] ^= (byte)( _v         & 0xFF);
        }

        // Write cipher header
        writeUtf8(new File(sourceDir, "ph_aes_impl.h"), AesCrypto.getAesImplCode());

        // Two dedup maps: jstring pool and cstring pool (separate indices)
        Map<String, Integer> jstrings = new LinkedHashMap<>(); // for NewStringUTF
        Map<String, Integer> cstrings = new LinkedHashMap<>(); // for reflection / char* uses

        // Pass 1: collect
        for (File src : sources) {
            String content = readUtf8(src);
            collectNsu(content, jstrings);
            collectCstr(content, cstrings, jstrings);
        }
        if (jstrings.isEmpty() && cstrings.isEmpty()) return 0;

        // Pass 2: replace
        int totalReplaced = 0;
        for (File src : sources) {
            String original = readUtf8(src);
            String patched  = replaceAll(original, jstrings, cstrings);
            if (!patched.equals(original)) {
                if (!patched.contains("ph_str_obf.h"))
                    patched = "#include \"ph_str_obf.h\"\n" + patched;
                writeUtf8(src, patched);
                totalReplaced++;
            }
        }
        if (totalReplaced == 0) return 0;

        generateHelpers(sourceDir, xorKey, realCc20Key, cc20Key, nonce, gc, jstrings, cstrings);
        return jstrings.size() + cstrings.size();
    }

    // ── Collection ────────────────────────────────────────────────────────────

    private static void collectNsu(String content, Map<String, Integer> idx) {
        for (Pattern p : new Pattern[]{NSU_CPP, NSU_C}) {
            Matcher m = p.matcher(content);
            while (m.find()) idx.putIfAbsent(m.group(1), idx.size());
        }
    }

    private static void collectCstr(String content, Map<String, Integer> cstr,
                                    Map<String, Integer> jstr) {
        for (Pattern p : new Pattern[]{
                GSFID_C, GSFID_CPP, GSMID_C, GSMID_CPP,
                FCLASS_C, FCLASS_CPP, THROWNEW_C, THROWNEW_CPP}) {
            Matcher m = p.matcher(content);
            while (m.find()) {
                String lit = m.group(2);
                if (!jstr.containsKey(lit))
                    cstr.putIfAbsent(lit, cstr.size());
            }
        }
        // D2C_RESOLVE_* macro calls — all quoted string args inside (class names, field/method names, sigs)
        collectD2cMacros(content, cstr, jstr);
    }

    // ── D2C macro handler ─────────────────────────────────────────────────────
    // writer.py emits macros like:
    //   D2C_RESOLVE_CLASS(clz, "ClassName")
    //   D2C_RESOLVE_STATIC_FIELD(clz, fld, "ClassName", "FieldName", "Type")
    //   D2C_RESOLVE_METHOD(clz, mid, "ClassName", "MethodName", "(Sig)Type")
    //   D2C_CHECK_CAST(v, clz, "ClassName")
    // We scan the call body character-by-character so quoted strings containing
    // ')' (e.g. method sigs "(I)V") are handled without regex depth tricks.

    private static final Pattern D2C_MACRO_HEAD = Pattern.compile(
            "(?:D2C_RESOLVE_(?:CLASS|STATIC_FIELD|FIELD|STATIC_METHOD|METHOD)|D2C_CHECK_CAST|d2c_is_instance_of)\\s*\\(");
    private static final Pattern INNER_STR = Pattern.compile(
            "\"((?:[^\"\\\\]|\\\\.)*)\"");

    /** Extract quoted string body and advance pos, returning the new position after the closing '"'. */
    private static int scanQuotedString(String s, int start, StringBuilder out) {
        int i = start; // s[start] == '"' already appended by caller
        while (i < s.length()) {
            char c = s.charAt(i);
            out.append(c);
            i++;
            if (c == '\\') {
                if (i < s.length()) { out.append(s.charAt(i)); i++; }
            } else if (c == '"') {
                break;
            }
        }
        return i;
    }

    /** Collect all string literals inside D2C macro calls into cstr. */
    private static void collectD2cMacros(String content, Map<String, Integer> cstr,
                                         Map<String, Integer> jstr) {
        Matcher head = D2C_MACRO_HEAD.matcher(content);
        while (head.find()) {
            String body = extractD2cBody(content, head.end());
            Matcher inner = INNER_STR.matcher(body);
            while (inner.find()) {
                String lit = inner.group(1);
                if (!jstr.containsKey(lit)) cstr.putIfAbsent(lit, cstr.size());
            }
        }
    }

    /** Replace all quoted literals inside D2C macro calls with phCStr_N(). */
    private static String applyD2cMacros(String content, Map<String, Integer> cstr) {
        Matcher head = D2C_MACRO_HEAD.matcher(content);
        StringBuffer result = new StringBuffer(content.length());
        while (head.find()) {
            result.append(content, result.length() == 0 ? 0 : result.length(), head.start());
            // Re-align: appendReplacement handles this, use manual approach
            // We'll build this differently — see below
        }
        // Use full manual approach for correct offset tracking
        result = new StringBuffer(content.length());
        head.reset();
        int lastEnd = 0;
        while (head.find()) {
            result.append(content, lastEnd, head.end()); // up to and including '('
            int bodyStart = head.end();
            // Scan to find the body + closing ')'
            int[] endPos = {bodyStart};
            String body = extractD2cBodyWithEnd(content, bodyStart, endPos);
            // Replace string literals inside body
            Matcher inner = INNER_STR.matcher(body);
            StringBuffer innerSb = new StringBuffer(body.length());
            while (inner.find()) {
                String lit = inner.group(1);
                Integer idx = cstr.get(lit);
                String rep = (idx != null) ? "phCStr_" + idx + "()" : inner.group();
                inner.appendReplacement(innerSb, Matcher.quoteReplacement(rep));
            }
            inner.appendTail(innerSb);
            result.append(innerSb);
            result.append(')');
            lastEnd = endPos[0];
        }
        result.append(content, lastEnd, content.length());
        return result.toString();
    }

    /** Extract the body of a D2C macro call (between '(' and matching ')'), respecting quoted strings. */
    private static String extractD2cBody(String s, int after_open_paren) {
        StringBuilder body = new StringBuilder();
        int i = after_open_paren, depth = 1;
        while (i < s.length() && depth > 0) {
            char c = s.charAt(i);
            if (c == '"') {
                body.append(c); i++;
                i = scanQuotedString(s, i, body);
            } else {
                if (c == '(') depth++;
                else if (c == ')') { depth--; if (depth == 0) break; }
                body.append(c); i++;
            }
        }
        return body.toString();
    }

    /** Like extractD2cBody but also writes the position after the closing ')' into endPos[0]. */
    private static String extractD2cBodyWithEnd(String s, int after_open_paren, int[] endPos) {
        StringBuilder body = new StringBuilder();
        int i = after_open_paren, depth = 1;
        while (i < s.length() && depth > 0) {
            char c = s.charAt(i);
            if (c == '"') {
                body.append(c); i++;
                i = scanQuotedString(s, i, body);
            } else {
                if (c == '(') depth++;
                else if (c == ')') { depth--; if (depth == 0) { i++; break; } }
                body.append(c); i++;
            }
        }
        endPos[0] = i;
        return body.toString();
    }

    // ── Replacement ───────────────────────────────────────────────────────────

    private static String replaceAll(String content,
                                     Map<String, Integer> jstr,
                                     Map<String, Integer> cstr) {
        // C-style NSU first (more specific), then C++ NSU
        content = applyNsu(content, NSU_C,   jstr, true);
        content = applyNsu(content, NSU_CPP, jstr, false);
        // Reflection / error calls — C-style first (has env, prefix), then C++
        content = applyReflect(content, GSFID_C,      cstr, 1, 2);
        content = applyReflect(content, GSFID_CPP,    cstr, 1, 2);
        content = applyReflect(content, GSMID_C,      cstr, 1, 2);
        content = applyReflect(content, GSMID_CPP,    cstr, 1, 2);
        content = applyReflectSingle(content, FCLASS_C,      cstr, 2);
        content = applyReflectSingle(content, FCLASS_CPP,    cstr, 2);
        content = applyReflectSingle(content, THROWNEW_C,    cstr, 2);
        content = applyReflectSingle(content, THROWNEW_CPP,  cstr, 2);
        // D2C_RESOLVE_* macros — covers all string literals emitted by writer.py
        // (class names, field names, method names, type signatures)
        content = applyD2cMacros(content, cstr);
        return content;
    }

    /** Replace NewStringUTF("lit") with phDecStr_N(env) */
    private static String applyNsu(String content, Pattern pat,
                                   Map<String, Integer> idx, boolean isCStyle) {
        StringBuffer sb = new StringBuffer(content.length());
        Matcher m = pat.matcher(content);
        while (m.find()) {
            Integer i = idx.get(m.group(1));
            if (i == null) { m.appendReplacement(sb, Matcher.quoteReplacement(m.group())); continue; }
            m.appendReplacement(sb, "phDecStr_" + i + "(env)");
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Replace the string literal in reflection calls like:
     *   GetStaticFieldID(clz, "FIELD", "Ljava/lang/String;")
     *   → GetStaticFieldID(clz, phCStr_N(), "Ljava/lang/String;")
     *
     * group(fnGroup) = function name, group(litGroup) = the literal text.
     * We reconstruct the original match replacing only the quoted literal.
     */
    private static String applyReflect(String content, Pattern pat,
                                       Map<String, Integer> idx,
                                       int fnGroup, int litGroup) {
        StringBuffer sb = new StringBuffer(content.length());
        Matcher m = pat.matcher(content);
        while (m.find()) {
            String lit  = m.group(litGroup);
            Integer i   = idx.get(lit);
            if (i == null) { m.appendReplacement(sb, Matcher.quoteReplacement(m.group())); continue; }
            // Rebuild: funcName(…before-lit…, phCStr_N(), …keep trailing comma…
            String original = m.group();
            String replaced = original.replace("\"" + lit + "\"", "phCStr_" + i + "()");
            m.appendReplacement(sb, Matcher.quoteReplacement(replaced));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** Same but for single-arg patterns like FindClass("lit") */
    private static String applyReflectSingle(String content, Pattern pat,
                                             Map<String, Integer> idx, int litGroup) {
        StringBuffer sb = new StringBuffer(content.length());
        Matcher m = pat.matcher(content);
        while (m.find()) {
            String lit = m.group(litGroup);
            Integer i  = idx.get(lit);
            if (i == null) { m.appendReplacement(sb, Matcher.quoteReplacement(m.group())); continue; }
            String original = m.group();
            String replaced = original.replace("\"" + lit + "\"", "phCStr_" + i + "()");
            m.appendReplacement(sb, Matcher.quoteReplacement(replaced));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // ── Helper generation ─────────────────────────────────────────────────────

    private static void generateHelpers(File sourceDir,
                                        byte[] xorKey, byte[] realCc20Key, byte[] cc20Key,
                                        byte[] nonce,
                                        int[][] gc,
                                        Map<String, Integer> jstrings,
                                        Map<String, Integer> cstrings) throws Exception {
        // realCc20Key = K (real key, used for encryption — matches what _psod() recovers)
        // cc20Key     = _pso_ck (K[0..3] ^ arith_gate, stored in .rodata)
        StringBuilder hdr = new StringBuilder(4096);
        StringBuilder cpp = new StringBuilder(16384);

        // ── Header ───────────────────────────────────────────────────────────
        hdr.append("// ph_str_obf.h — AUTO-GENERATED — DO NOT EDIT\n");
        hdr.append("// ChaCha20 + XOR double-layer string encryption.\n");
        hdr.append("#pragma once\n#include <jni.h>\n\n");
        hdr.append("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
        // jstring helpers
        for (Map.Entry<String, Integer> e : jstrings.entrySet())
            hdr.append("jstring phDecStr_").append(e.getValue()).append("(JNIEnv* env);\n");
        hdr.append("\n");
        // const char* helpers
        for (Map.Entry<String, Integer> e : cstrings.entrySet())
            hdr.append("const char* phCStr_").append(e.getValue()).append("(void);\n");
        hdr.append("\n#ifdef __cplusplus\n}\n#endif\n");

        // ── cpp preamble ─────────────────────────────────────────────────────
        cpp.append("// ph_str_obf.cpp — AUTO-GENERATED — DO NOT EDIT\n");
        cpp.append("// All string literals encrypted with ChaCha20 + XOR.\n\n");
        cpp.append("#include \"ph_str_obf.h\"\n#include <string.h>\n");
        cpp.append("#include <stdint.h>\n#include <stddef.h>\n");
        cpp.append("#include \"ph_aes_impl.h\"\n\n");

        // ── HI⊕LO splits — no single .rodata array is the real key/xor-material ─
        java.security.SecureRandom _srng = new java.security.SecureRandom();

        // XOR key halves
        byte[] k0hi = new byte[16], k0lo = new byte[16];
        byte[] k1hi = new byte[16], k1lo = new byte[16];
        _srng.nextBytes(k0hi); _srng.nextBytes(k1hi);
        for (int i = 0; i < 16; i++) {
            k0lo[i] = (byte)(xorKey[i]      ^ k0hi[i]);
            k1lo[i] = (byte)(xorKey[16 + i] ^ k1hi[i]);
        }
        emitByteArray(cpp, "static const unsigned char _pso_k0_hi[16]", k0hi, 0, 16);
        emitByteArray(cpp, "static const unsigned char _pso_k0_lo[16]", k0lo, 0, 16);
        emitByteArray(cpp, "static const unsigned char _pso_k1_hi[16]", k1hi, 0, 16);
        emitByteArray(cpp, "static const unsigned char _pso_k1_lo[16]", k1lo, 0, 16);

        // ChaCha20 key split (cc20Key = _pso_ck = K[0..3] XOR arith_gate, K[4..31] plain)
        byte[] ckhi = new byte[32], cklo = new byte[32];
        _srng.nextBytes(ckhi);
        for (int i = 0; i < 32; i++) cklo[i] = (byte)(cc20Key[i] ^ ckhi[i]);
        emitByteArray(cpp, "static const uint8_t _pso_ck_hi[32]", ckhi, 0, 32);
        emitByteArray(cpp, "static const uint8_t _pso_ck_lo[32]", cklo, 0, 32);

        // Nonce stays plain — it is not secret (ChaCha20 nonce is public)
        emitByteArray(cpp, "static const uint8_t _pso_n[12]", nonce, 0, 12);

        cpp.append("\n");

        // ── 8 gate functions — each unmasks 4 bytes of K ─────────────────────
        for (int _g = 0; _g < 8; _g++) {
            cpp.append("static __attribute__((noinline,optnone)) uint32_t _pso_gate").append(_g).append("(void){\n");
            cpp.append(String.format(
                "    volatile uint32_t _a=0x%08XU,_b=0x%08XU,_c=0x%08XU,_d=0x%08XU,_e=0x%08XU;\n",
                gc[_g][0], gc[_g][1], gc[_g][2], gc[_g][3], gc[_g][4]));
            cpp.append("    uint32_t _v=(uint32_t)_a; _v^=(uint32_t)_b;\n");
            cpp.append("    _v=(_v<<13)|(_v>>19); _v+=(uint32_t)_c; _v^=(uint32_t)_d;\n");
            cpp.append("    _v=(_v>>7)|(_v<<25);  _v*=(uint32_t)_e; return _v;\n");
            cpp.append("}\n");
        }
        cpp.append("\n");

        // ── _psod: always_inline → no single hookable entry point ─────────────
        // _si: compile-time string index XOR'd into nonce → unique keystream per string.
        // volatile pointers prevent optimizer folding HI^LO at inlined call sites.
        cpp.append("static __attribute__((always_inline)) inline void _psod(const unsigned char* e, int n, uint8_t* tb, char* o, int _si) {\n");
        cpp.append("    uint8_t _rk[32];\n");
        cpp.append("    const volatile uint8_t* _chi=_pso_ck_hi; const volatile uint8_t* _clo=_pso_ck_lo;\n");
        cpp.append("    for(int _qi=0;_qi<32;_qi++) _rk[_qi]=_chi[_qi]^_clo[_qi];\n");
        for (int _g = 0; _g < 8; _g++) {
            cpp.append("    {const uint32_t _gv=_pso_gate").append(_g).append("();\n");
            cpp.append("     _rk[").append(_g*4  ).append("]^=(uint8_t)((_gv>>24)&0xFF);");
            cpp.append(" _rk[").append(_g*4+1).append("]^=(uint8_t)((_gv>>16)&0xFF);\n");
            cpp.append("     _rk[").append(_g*4+2).append("]^=(uint8_t)((_gv>>8)&0xFF);");
            cpp.append(" _rk[").append(_g*4+3).append("]^=(uint8_t)(_gv&0xFF);}\n");
        }
        cpp.append("    uint8_t _nn[12]; __builtin_memcpy(_nn,_pso_n,12);\n");
        cpp.append("    _nn[0]^=(uint8_t)(_si&0xFF); _nn[1]^=(uint8_t)((_si>>8)&0xFF);\n");
        cpp.append("    _nn[2]^=(uint8_t)((_si>>16)&0xFF); _nn[3]^=(uint8_t)((_si>>24)&0xFF);\n");
        cpp.append("    const volatile unsigned char* _h0=_pso_k0_hi,*_l0=_pso_k0_lo;\n");
        cpp.append("    const volatile unsigned char* _h1=_pso_k1_hi,*_l1=_pso_k1_lo;\n");
        cpp.append("    memcpy(tb, e, n);\n");
        cpp.append("    _pha_cc20_dec(_rk, _nn, tb, n);\n");
        cpp.append("    for (int _i = 0; _i < n; _i++) {\n");
        cpp.append("        const unsigned char _xk =\n");
        cpp.append("            (_i < 16\n");
        cpp.append("                ? (unsigned char)(_h0[_i&15] ^ _l0[_i&15])\n");
        cpp.append("                : (unsigned char)(_h1[_i&15] ^ _l1[_i&15]))\n");
        cpp.append("            ^ (unsigned char)(_i * 0x1D);\n");
        cpp.append("        o[_i] = (char)(tb[_i] ^ _xk);\n");
        cpp.append("    }\n");
        cpp.append("    o[n] = '\\0';\n");
        cpp.append("    memset(tb, 0, n); memset(_rk, 0, 32);\n");
        cpp.append("}\n\n");

        // ── Vtable-indirect NewStringUTF ──────────────────────────────────────
        cpp.append("static jstring _pso_new_str(JNIEnv* env, const char* s) {\n");
        cpp.append("    typedef jstring (*_fn_t)(JNIEnv*, const char*);\n");
        cpp.append("    const size_t _off = offsetof(JNINativeInterface, NewStringUTF);\n");
        cpp.append("    void* const* _vt = *(void* const**)env;\n");
        cpp.append("    volatile _fn_t _fn = (_fn_t)_vt[_off / sizeof(void*)];\n");
        cpp.append("    return _fn(env, s);\n");
        cpp.append("}\n\n");

        // ── jstring decrypt functions — per-string nonce via idx ─────────────
        for (Map.Entry<String, Integer> e : jstrings.entrySet()) {
            String lit   = e.getKey();
            int    idx   = e.getValue();
            byte[] plain = unescapeCLiteral(lit).getBytes(StandardCharsets.UTF_8);
            // Unique nonce: base nonce XOR le32(idx)
            byte[] enc   = (plain.length == 0) ? new byte[0]
                         : AesCrypto.encrypt(plain, xorKey, realCc20Key, nonce, idx);

            emitByteArray(cpp, "static const unsigned char _pj" + idx
                    + "[" + Math.max(enc.length, 1) + "]", enc.length == 0 ? new byte[]{0} : enc, 0,
                    enc.length == 0 ? 1 : enc.length);

            cpp.append("extern \"C\" jstring phDecStr_").append(idx).append("(JNIEnv* env) {\n");
            if (plain.length == 0) {
                cpp.append("    return _pso_new_str(env, \"\");\n");
            } else {
                cpp.append("    char _b[").append(plain.length + 1).append("];\n");
                cpp.append("    uint8_t _tb[").append(plain.length).append("];\n");
                cpp.append("    _psod(_pj").append(idx).append(", ").append(plain.length)
                   .append(", _tb, _b, ").append(idx).append(");\n");
                cpp.append("    jstring _r = _pso_new_str(env, _b);\n");
                cpp.append("    memset(_b, 0, ").append(plain.length + 1).append(");\n");
                cpp.append("    return _r;\n");
            }
            cpp.append("}\n\n");
        }

        // ── const char* functions — per-string nonce offset by jstrings.size() ─
        // Fix 4: separate _rdy flag — no sentinel bug for strings starting with '\0'.
        final int _csi_off = jstrings.size();
        for (Map.Entry<String, Integer> e : cstrings.entrySet()) {
            String lit   = e.getKey();
            int    idx   = e.getValue();
            int    si    = _csi_off + idx;  // globally unique nonce index
            byte[] plain = unescapeCLiteral(lit).getBytes(StandardCharsets.UTF_8);
            byte[] enc   = (plain.length == 0) ? new byte[0]
                         : AesCrypto.encrypt(plain, xorKey, realCc20Key, nonce, si);

            emitByteArray(cpp, "static const unsigned char _pc" + idx
                    + "[" + Math.max(enc.length, 1) + "]", enc.length == 0 ? new byte[]{0} : enc, 0,
                    enc.length == 0 ? 1 : enc.length);

            cpp.append("extern \"C\" const char* phCStr_").append(idx).append("(void) {\n");
            if (plain.length == 0) {
                cpp.append("    return \"\";\n");
            } else {
                cpp.append("    static char _b[").append(plain.length + 1).append("];\n");
                cpp.append("    static uint8_t _rdy = 0;\n");
                cpp.append("    if (!_rdy) {\n");
                cpp.append("        uint8_t _tb[").append(plain.length).append("];\n");
                cpp.append("        _psod(_pc").append(idx).append(", ").append(plain.length)
                   .append(", _tb, _b, ").append(si).append(");\n");
                cpp.append("        _rdy = 1;\n");
                cpp.append("    }\n");
                cpp.append("    return _b;\n");
            }
            cpp.append("}\n\n");
        }

        writeUtf8(new File(sourceDir, "ph_str_obf.h"),   hdr.toString());
        writeUtf8(new File(sourceDir, "ph_str_obf.cpp"), cpp.toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static final char[] _HEX = "0123456789ABCDEF".toCharArray();

    private static void emitByteArray(StringBuilder sb, String decl,
                                      byte[] data, int from, int to) {
        sb.append(decl).append(" = {");
        for (int i = from; i < to; i++) {
            if (i > from) sb.append(',');
            int b = data[i] & 0xFF;
            sb.append("0x").append(_HEX[b >> 4]).append(_HEX[b & 0xF]);
        }
        sb.append("};\n");
    }

    static String unescapeCLiteral(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c != '\\') { sb.append(c); continue; }
            if (i >= s.length()) break;
            char esc = s.charAt(i++);
            switch (esc) {
                case 'n':  sb.append('\n'); break;
                case 'r':  sb.append('\r'); break;
                case 't':  sb.append('\t'); break;
                case '\\': sb.append('\\'); break;
                case '"':  sb.append('"');  break;
                case '\'': sb.append('\''); break;
                case '0':  sb.append('\0'); break;
                case 'a':  sb.append('\007'); break;
                case 'b':  sb.append('\b');   break;
                case 'x': {
                    int end = Math.min(i + 2, s.length());
                    String hex = "";
                    while (i < end && isHexDigit(s.charAt(i))) hex += s.charAt(i++);
                    if (!hex.isEmpty()) sb.append((char) Integer.parseInt(hex, 16));
                    else sb.append('x');
                    break;
                }
                default: {
                    if (esc >= '1' && esc <= '7') {
                        StringBuilder oct = new StringBuilder().append(esc);
                        int end = Math.min(i + 2, s.length());
                        while (i < end && s.charAt(i) >= '0' && s.charAt(i) <= '7')
                            oct.append(s.charAt(i++));
                        sb.append((char) Integer.parseInt(oct.toString(), 8));
                    } else sb.append(esc);
                }
            }
        }
        return sb.toString();
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static String readUtf8(File f) throws IOException {
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    private static void writeUtf8(File f, String content) throws IOException {
        Files.write(f.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }
}
