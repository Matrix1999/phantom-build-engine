package com.ultra.dex2cvmp.engine;

import java.io.File;

/**
 * Shared gate parameters set by ApkProtector before NativeStringGen.generate()
 * is called, so the native-string generator can embed the JNI gate.
 *
 * NOT persisted — lives only for the duration of a single protect run.
 */
public class GateContext {

    /** Return value of PhStringGate.computeToken() — chosen randomly at build time. */
    public static volatile int     token   = 0;

    /** True when gate DEX was successfully injected and the JNI gate should be used. */
    public static volatile boolean enabled = false;

    /** DEX-format descriptor of the gate class (slashes, no L…;). */
    public static final String CLASS_DESC  = "com/ultra/dex2cvmp/gate/PhStringGate";

    /** Name of the gate method whose return value is the secret token. */
    public static final String METHOD_NAME = "computeToken";

    /** JNI method signature for computeToken(). */
    public static final String METHOD_SIG  = "()I";

    /** VMP-only signer payload gate. It is separate from the static-string token gate. */
    public static final String SIGNER_CLASS_DESC = "com/ultra/dex2cvmp/gate/SignerGate";
    public static final String SIGNER_PART_PREFIX = "part";
    public static final int SIGNER_PART_COUNT = 12;
    public static final int SIGNER_CIPHER_BYTES = SIGNER_PART_COUNT * 4;

    public static String signerPartMethodName(int index) {
        if (index < 0 || index >= SIGNER_PART_COUNT) {
            throw new IllegalArgumentException("Invalid signer part index: " + index);
        }
        return SIGNER_PART_PREFIX + index;
    }

    /**
     * Allocate a synthetic classesN.dex name after the highest existing DEX
     * ordinal. Counting files is unsafe when classes.dex or another ordinal is
     * temporarily absent because it can select and overwrite an existing file.
     */
    public static File nextSyntheticDexFile(File dexDir) {
        int highestOrdinal = 0;
        File[] existing = dexDir.listFiles(
                file -> file.isFile() && file.getName().matches("classes\\d*\\.dex"));
        if (existing != null) {
            for (File file : existing) {
                String name = file.getName();
                int ordinal;
                if ("classes.dex".equals(name)) {
                    ordinal = 1;
                } else {
                    try {
                        ordinal = Integer.parseInt(
                                name.substring("classes".length(), name.length() - 4));
                    } catch (NumberFormatException ignored) {
                        continue;
                    }
                }
                highestOrdinal = Math.max(highestOrdinal, ordinal);
            }
        }

        int nextOrdinal = highestOrdinal + 1;
        while (true) {
            String name = nextOrdinal == 1
                    ? "classes.dex"
                    : "classes" + nextOrdinal + ".dex";
            File candidate = new File(dexDir, name);
            if (!candidate.exists()) return candidate;
            nextOrdinal++;
        }
    }

    private GateContext() {}
}
