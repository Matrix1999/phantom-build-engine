package com.ultra.dex2cvmp.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.*;

/**
 * DexStringObfuscator — post-processes DEX2C / VMP generated C++ source files
 * to replace every plaintext NewStringUTF("literal") call with an inline
 * XOR-decrypt call.
 *
 * Without this step every const-string opcode from transpiled method bodies
 * lands in .rodata as a readable C string literal — even when OLLVM is off.
 * After this step no plaintext string value reaches the compiler; all content
 * is stored as encrypted byte arrays and decrypted at call time from the stack.
 *
 * Works independently of ph_strings.cpp (which covers static field initializers).
 * When OLLVM SOBF is also enabled the two layers reinforce each other.
 *
 * Entry point: {@link #obfuscate(File)}
 */
public class DexStringObfuscator {

    // Files we generated ourselves — never touch them
    private static final Set<String> SKIP_FILES = new HashSet<>(Arrays.asList(
            "ph_strings.cpp", "ph_str_obf.cpp", "ph_str_obf.h"
    ));

    /**
     * Scan all .c / .cpp files in {@code sourceDir}, replace every
     * {@code env->NewStringUTF("literal")} with an encrypted decrypt call,
     * and write the helper sources ({@code ph_str_obf.h} / {@code ph_str_obf.cpp})
     * into the same directory so NdkBuilder compiles them automatically.
     *
     * @return total number of literal occurrences replaced (0 = nothing to do)
     */
    public static int obfuscate(File sourceDir) throws IOException {
        File[] files = sourceDir.listFiles();
        if (files == null) return 0;

        List<File> sources = new ArrayList<>();
        for (File f : files) {
            String n = f.getName();
            if ((n.endsWith(".c") || n.endsWith(".cpp")) && !SKIP_FILES.contains(n)) {
                sources.add(f);
            }
        }
        if (sources.isEmpty()) return 0;

        // Random 32-byte key — same XOR scheme as NativeStringGen, fresh per run
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        // Ordered map: C-literal text → stable index (deduplicates identical strings)
        Map<String, Integer> stringIndex = new LinkedHashMap<>();

        // ── Pass 1: collect all unique string literals ────────────────────────
        for (File src : sources) {
            String content = readUtf8(src);
            collectLiterals(content, stringIndex);
        }
        if (stringIndex.isEmpty()) return 0;

        // ── Pass 2: replace in each file ─────────────────────────────────────
        int totalReplaced = 0;
        for (File src : sources) {
            String original = readUtf8(src);
            String patched  = replaceLiterals(original, stringIndex);
            if (!patched.equals(original)) {
                // Prepend include so the decrypt functions are visible
                if (!patched.contains("ph_str_obf.h")) {
                    patched = "#include \"ph_str_obf.h\"\n" + patched;
                }
                writeUtf8(src, patched);
                // Count replacements in this file
                totalReplaced += countReplacements(original);
            }
        }
        if (totalReplaced == 0) return 0;

        // ── Generate ph_str_obf.h and ph_str_obf.cpp ─────────────────────────
        generateHelpers(sourceDir, key, stringIndex);

        return totalReplaced;
    }

    // ── Regex patterns ────────────────────────────────────────────────────────

    /**
     * Matches C++ JNI:  env->NewStringUTF("...")
     * Group 1 = the raw C string literal content (without surrounding quotes).
     */
    private static final Pattern CPP_PAT = Pattern.compile(
            "env\\s*->\\s*NewStringUTF\\s*\\(\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");

    /**
     * Matches C JNI:  (*env)->NewStringUTF(env, "...")
     * Group 1 = the raw C string literal content.
     */
    private static final Pattern C_PAT = Pattern.compile(
            "\\(\\*\\s*env\\s*\\)\\s*->\\s*NewStringUTF\\s*\\(\\s*env\\s*,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s*\\)");

    private static void collectLiterals(String content, Map<String, Integer> idx) {
        for (Pattern p : new Pattern[]{CPP_PAT, C_PAT}) {
            Matcher m = p.matcher(content);
            while (m.find()) idx.putIfAbsent(m.group(1), idx.size());
        }
    }

    private static String replaceLiterals(String content, Map<String, Integer> idx) {
        // Replace C JNI style first (longer match, avoids partial overlap with CPP_PAT)
        content = replacePattern(content, C_PAT,   idx, false);
        content = replacePattern(content, CPP_PAT, idx, true);
        return content;
    }

    /**
     * @param cppStyle true  → replacement is {@code phDecStr_N(env)}
     *                 false → replacement is also {@code phDecStr_N(env)}
     *                 (the decrypt function always takes JNIEnv* and returns jstring)
     */
    private static String replacePattern(String content, Pattern pat,
                                         Map<String, Integer> idx, boolean cppStyle) {
        StringBuffer sb = new StringBuffer(content.length());
        Matcher m = pat.matcher(content);
        while (m.find()) {
            String lit = m.group(1);
            Integer i  = idx.get(lit);
            if (i == null) { m.appendReplacement(sb, Matcher.quoteReplacement(m.group())); continue; }
            m.appendReplacement(sb, "phDecStr_" + i + "(env)");
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static int countReplacements(String original) {
        int n = 0;
        for (Pattern p : new Pattern[]{CPP_PAT, C_PAT}) {
            Matcher m = p.matcher(original);
            while (m.find()) n++;
        }
        return n;
    }

    // ── Helper file generation ────────────────────────────────────────────────

    private static void generateHelpers(File sourceDir, byte[] key,
                                        Map<String, Integer> strings) throws IOException {
        StringBuilder hdr = new StringBuilder(4096);
        StringBuilder cpp = new StringBuilder(8192);

        // ── Header ───────────────────────────────────────────────────────────
        hdr.append("// ph_str_obf.h — AUTO-GENERATED — DO NOT EDIT\n");
        hdr.append("// Inline string literal decrypt helpers for DEX2C/VMP transpiled sources.\n");
        hdr.append("#pragma once\n");
        hdr.append("#include <jni.h>\n\n");
        hdr.append("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
        for (Map.Entry<String, Integer> e : strings.entrySet()) {
            hdr.append("jstring phDecStr_").append(e.getValue()).append("(JNIEnv* env);\n");
        }
        hdr.append("\n#ifdef __cplusplus\n}\n#endif\n");

        // ── Implementation ───────────────────────────────────────────────────
        cpp.append("// ph_str_obf.cpp — AUTO-GENERATED — DO NOT EDIT\n");
        cpp.append("// NewStringUTF literals replaced with XOR-encrypted byte arrays.\n");
        cpp.append("// Key: random 32-byte per protection run, split into two 16-byte halves.\n\n");
        cpp.append("#include \"ph_str_obf.h\"\n");
        cpp.append("#include <string.h>\n\n");

        // Key halves
        cpp.append("static const unsigned char _pso_k0[16] = {");
        for (int i = 0; i < 16; i++) {
            if (i > 0) cpp.append(',');
            cpp.append(String.format("0x%02X", key[i] & 0xFF));
        }
        cpp.append("};\n");
        cpp.append("static const unsigned char _pso_k1[16] = {");
        for (int i = 16; i < 32; i++) {
            if (i > 16) cpp.append(',');
            cpp.append(String.format("0x%02X", key[i] & 0xFF));
        }
        cpp.append("};\n\n");

        // Decrypt helper — identical scheme to NativeStringGen._phd()
        cpp.append("static void _psod(const unsigned char* e, int n, char* o) {\n");
        cpp.append("    for (int i = 0; i < n; i++) {\n");
        cpp.append("        const unsigned char k =\n");
        cpp.append("            (i < 16 ? _pso_k0[i & 15] : _pso_k1[i & 15])\n");
        cpp.append("            ^ (unsigned char)(i * 0x1D);\n");
        cpp.append("        o[i] = (char)(e[i] ^ k);\n");
        cpp.append("    }\n");
        cpp.append("    o[n] = '\\0';\n");
        cpp.append("}\n\n");

        // Per-string encrypted array + extern-C decrypt function
        for (Map.Entry<String, Integer> e : strings.entrySet()) {
            String lit = e.getKey();
            int    idx = e.getValue();

            byte[] plain = unescapeCLiteral(lit).getBytes(StandardCharsets.UTF_8);
            byte[] enc   = encrypt(plain, key);

            // Encrypted array
            cpp.append("static const unsigned char _pso_s").append(idx)
               .append('[').append(Math.max(enc.length, 1)).append("] = {");
            if (enc.length == 0) {
                cpp.append("0x00");   // empty string — placeholder byte, length=0 passed to _psod
            } else {
                for (int i = 0; i < enc.length; i++) {
                    if (i > 0) cpp.append(',');
                    cpp.append(String.format("0x%02X", enc[i] & 0xFF));
                }
            }
            cpp.append("};\n");

            // Decrypt function — extern "C" so C translation units can call it
            cpp.append("extern \"C\" jstring phDecStr_").append(idx).append("(JNIEnv* env) {\n");
            if (plain.length == 0) {
                cpp.append("    return env->NewStringUTF(\"\");\n");
            } else {
                cpp.append("    char _b[").append(plain.length + 1).append("];\n");
                cpp.append("    _psod(_pso_s").append(idx).append(", ")
                   .append(plain.length).append(", _b);\n");
                cpp.append("    jstring _r = env->NewStringUTF(_b);\n");
                cpp.append("    memset(_b, 0, ").append(plain.length + 1).append(");\n");
                cpp.append("    return _r;\n");
            }
            cpp.append("}\n\n");
        }

        writeUtf8(new File(sourceDir, "ph_str_obf.h"),   hdr.toString());
        writeUtf8(new File(sourceDir, "ph_str_obf.cpp"), cpp.toString());
    }

    // ── Crypto ────────────────────────────────────────────────────────────────

    /** Same XOR scheme as NativeStringGen.encrypt() so both layers share a pattern. */
    static byte[] encrypt(byte[] plain, byte[] key) {
        byte[] enc = new byte[plain.length];
        for (int i = 0; i < plain.length; i++) {
            int ki = (i < 16 ? (key[i & 15] & 0xFF) : (key[16 + (i & 15)] & 0xFF))
                   ^ ((i * 0x1D) & 0xFF);
            enc[i] = (byte)(plain[i] ^ ki);
        }
        return enc;
    }

    /**
     * Decode a C string literal body (the part between the quotes) to its
     * actual byte content.  Handles common escape sequences used by dex2c:
     * \\, \", \n, \r, \t, \0, \xNN (hex), \NNN (octal).
     */
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
                    // \xNN — consume up to 2 hex digits
                    int end = Math.min(i + 2, s.length());
                    String hex = "";
                    while (i < end && isHexDigit(s.charAt(i))) { hex += s.charAt(i++); }
                    if (!hex.isEmpty()) sb.append((char) Integer.parseInt(hex, 16));
                    else sb.append('x');
                    break;
                }
                default: {
                    // Octal \NNN
                    if (esc >= '1' && esc <= '7') {
                        StringBuilder oct = new StringBuilder().append(esc);
                        int end = Math.min(i + 2, s.length());
                        while (i < end && s.charAt(i) >= '0' && s.charAt(i) <= '7')
                            oct.append(s.charAt(i++));
                        sb.append((char) Integer.parseInt(oct.toString(), 8));
                    } else {
                        sb.append(esc);
                    }
                }
            }
        }
        return sb.toString();
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    // ── I/O helpers ───────────────────────────────────────────────────────────

    private static String readUtf8(File f) throws IOException {
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    private static void writeUtf8(File f, String content) throws IOException {
        Files.write(f.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }
}
