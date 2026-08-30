package com.ultra.dex2cvmp.engine;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** Generates the final-link signer bridge for either protection engine. */
public final class SignerGateNativeGen {

    private SignerGateNativeGen() {}

    public static File generate(File cSourceDir, boolean useVmp, byte[] cipher) throws Exception {
        if (cipher == null || cipher.length != GateContext.SIGNER_CIPHER_BYTES) {
            throw new IllegalArgumentException("Signer cipher must be exactly 48 bytes.");
        }
        String source = useVmp ? buildVmpBridge() : buildDex2cProvider(cipher);
        File out = new File(cSourceDir, "d2c_signer_gate.cpp");
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(source.getBytes(StandardCharsets.UTF_8));
        }
        if (!out.isFile() || out.length() == 0) {
            throw new IllegalStateException("Unable to generate signer bridge source.");
        }
        return out;
    }

    private static String buildVmpBridge() {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("#include <jni.h>\n#include <stdint.h>\n#include <string.h>\n\n");
        sb.append("extern \"C\" const char d2c_guard_signer_gate_contract[];\n");
        sb.append("static jclass g_signer_gate = nullptr;\n");
        sb.append("static jmethodID g_signer_parts[")
                .append(GateContext.SIGNER_PART_COUNT).append("] = {};\n\n");
        sb.append("extern \"C\" int d2c_signer_gate_bind(JNIEnv* env) {\n");
        sb.append("  if (!env || d2c_guard_signer_gate_contract[0] != 'v') return 0;\n");
        sb.append("  if (g_signer_gate) return 1;\n");
        sb.append("  jclass local = env->FindClass(\"")
                .append(GateContext.SIGNER_CLASS_DESC).append("\");\n");
        sb.append("  if (!local || env->ExceptionCheck()) { if (env->ExceptionCheck()) env->ExceptionClear(); return 0; }\n");
        sb.append("  jclass global = (jclass)env->NewGlobalRef(local); env->DeleteLocalRef(local);\n");
        sb.append("  if (!global || env->ExceptionCheck()) { if (env->ExceptionCheck()) env->ExceptionClear(); return 0; }\n");
        for (int i = 0; i < GateContext.SIGNER_PART_COUNT; i++) {
            sb.append("  g_signer_parts[").append(i).append("] = env->GetStaticMethodID(global, \"")
                    .append(GateContext.signerPartMethodName(i)).append("\", \"()I\");\n");
            sb.append("  if (!g_signer_parts[").append(i)
                    .append("] || env->ExceptionCheck()) { if (env->ExceptionCheck()) env->ExceptionClear(); env->DeleteGlobalRef(global); memset(g_signer_parts, 0, sizeof(g_signer_parts)); return 0; }\n");
        }
        sb.append("  g_signer_gate = global; return 1;\n}\n\n");
        sb.append("extern \"C\" int d2c_get_protected_signer_cipher(JNIEnv* env, uint8_t out[")
                .append(GateContext.SIGNER_CIPHER_BYTES).append("]) {\n");
        sb.append("  if (!env || !out || !g_signer_gate) return 0;\n");
        sb.append("  for (int i = 0; i < ").append(GateContext.SIGNER_PART_COUNT).append("; i++) {\n");
        sb.append("    jint word = env->CallStaticIntMethod(g_signer_gate, g_signer_parts[i]);\n");
        sb.append("    if (env->ExceptionCheck()) { env->ExceptionClear(); memset(out, 0, ")
                .append(GateContext.SIGNER_CIPHER_BYTES).append("); return 0; }\n");
        sb.append("    out[i * 4] = (uint8_t)((uint32_t)word >> 24); out[i * 4 + 1] = (uint8_t)((uint32_t)word >> 16);\n");
        sb.append("    out[i * 4 + 2] = (uint8_t)((uint32_t)word >> 8); out[i * 4 + 3] = (uint8_t)word;\n");
        sb.append("  }\n  return 1;\n}\n");
        return sb.toString();
    }

    private static String buildDex2cProvider(byte[] cipher) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("#include <jni.h>\n#include <stdint.h>\n#include <string.h>\n\n");
        sb.append("// AES-CBC encrypted signer digest; never contains the SHA-256 plaintext.\n");
        sb.append("static const uint8_t kSignerCipher[")
                .append(GateContext.SIGNER_CIPHER_BYTES).append("] = {");
        for (int i = 0; i < cipher.length; i++) {
            if (i % 12 == 0) sb.append("\n  ");
            sb.append(String.format("0x%02x", cipher[i] & 0xff));
            if (i + 1 < cipher.length) sb.append(',');
        }
        sb.append("\n};\n\n");
        sb.append("extern \"C\" int d2c_signer_gate_bind(JNIEnv* env) {\n");
        sb.append("  return env ? 1 : 0;\n}\n\n");
        sb.append("extern \"C\" int d2c_get_protected_signer_cipher(JNIEnv* env, uint8_t out[")
                .append(GateContext.SIGNER_CIPHER_BYTES).append("]) {\n");
        sb.append("  if (!env || !out) return 0;\n");
        sb.append("  memcpy(out, kSignerCipher, sizeof(kSignerCipher));\n");
        sb.append("  return 1;\n}\n");
        return sb.toString();
    }

}