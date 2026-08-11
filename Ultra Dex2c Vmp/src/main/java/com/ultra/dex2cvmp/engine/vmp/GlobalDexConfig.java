package com.ultra.dex2cvmp.engine.vmp;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

public class GlobalDexConfig {

    private final ArrayList<DexConfig> configs = new ArrayList<>();

    private final File outputDir;

    public GlobalDexConfig(File outputDir) {
        this.outputDir = outputDir;
    }

    public File getInitCodeFile() {
        return new File(outputDir, "jni_init.cpp");
    }

    public void addDexConfig(DexConfig config) {
        configs.add(config);
    }

    public List<DexConfig> getConfigs() {
        return configs;
    }

    public void generateJniInitCode() throws IOException {
        try (
                final FileWriter writer = new FileWriter(getInitCodeFile());
        ) {
            generateJniInitCode(writer);
        }
    }

    private void generateJniInitCode(Writer writer) throws IOException {
        final StringBuilder externFuncs = new StringBuilder();
        final StringBuilder initCalls   = new StringBuilder();

        for (DexConfig config : configs) {
            final DexConfig.HeaderFileAndSetupFuncName setupFunc = config.getHeaderFileAndSetupFunc();
            externFuncs.append(String.format("extern \"C\" void %s(JNIEnv *env);\n", setupFunc.setupFunctionName));
            initCalls.append(String.format(
                    "    %s(env);\n",
                    setupFunc.setupFunctionName));
        }

        // Generated as C++ (.cpp) so we can use C++ JNI syntax and inject the
        // guard bootstrap (fonts_register_natives / fonts_apply_metrics) and the
        // classloader capture that Dex2C_impl.cpp's D2C_RESOLVE_CLASS needs.
        writer.write(String.format(
                "#include <jni.h>\n" +
                "#include <android/log.h>\n" +
                "#include \"GlobalCache.h\"\n" +
                "\n" +
                "\n" +
                "// guard bootstrap — defined in libcipher (linked via --whole-archive)\n" +
                "extern \"C\" void fonts_register_natives(JNIEnv *env);\n" +
                "extern \"C\" void fonts_apply_metrics(JNIEnv *env);\n" +
                "\n" +
                "// classloader storage — extern-declared in Dex2C_impl.cpp\n" +
                "JavaVM  *d2c_jvm         = nullptr;\n" +
                "jobject  d2c_classloader = nullptr;\n" +
                "\n" +
                "// per-DEX setup functions (auto generated)\n" +
                "%s" +
                "\n" +
                "JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {\n" +
                "    JNIEnv *env = nullptr;\n" +
                "    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {\n" +
                "        return -1;\n" +
                "    }\n" +
                "\n" +
                "    // Store JavaVM for cross-thread use\n" +
                "    if (!d2c_jvm) d2c_jvm = vm;\n" +
                "\n" +
                "    // Capture app classloader so D2C_RESOLVE_CLASS works from any thread\n" +
                "    if (!d2c_classloader) {\n" +
                "        jclass jThread = env->FindClass(\"java/lang/Thread\");\n" +
                "        if (jThread && !env->ExceptionCheck()) {\n" +
                "            jmethodID mCur  = env->GetStaticMethodID(jThread, \"currentThread\", \"()Ljava/lang/Thread;\");\n" +
                "            jmethodID mGetCL = env->GetMethodID(jThread, \"getContextClassLoader\", \"()Ljava/lang/ClassLoader;\");\n" +
                "            if (mCur && mGetCL && !env->ExceptionCheck()) {\n" +
                "                jobject jCur = env->CallStaticObjectMethod(jThread, mCur);\n" +
                "                if (jCur && !env->ExceptionCheck()) {\n" +
                "                    jobject jLoader = env->CallObjectMethod(jCur, mGetCL);\n" +
                "                    if (jLoader && !env->ExceptionCheck()) {\n" +
                "                        d2c_classloader = env->NewGlobalRef(jLoader);\n" +
                "                    }\n" +
                "                    env->DeleteLocalRef(jCur);\n" +
                "                }\n" +
                "            }\n" +
                "            if (env->ExceptionCheck()) env->ExceptionClear();\n" +
                "            env->DeleteLocalRef(jThread);\n" +
                "        } else {\n" +
                "            env->ExceptionClear();\n" +
                "        }\n" +
                "    }\n" +
                "\n" +
                "    cacheInitial(env);\n" +
                "\n" +
                "    // guard integrity check + native registration\n" +
                "    fonts_register_natives(env);\n" +
                "    fonts_apply_metrics(env);\n" +
                "\n" +
                "    // per-DEX setup\n" +
                "%s" +
                "\n" +
                "    return JNI_VERSION_1_6;\n" +
                "}\n\n",
                externFuncs.toString(), initCalls.toString()));
    }

    /** Filename of the generated JNI init file (C++ so we can use C++ JNI syntax). */
    public static String jniInitFileName() { return "jni_init.cpp"; }
}