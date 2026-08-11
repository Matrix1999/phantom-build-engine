package com.ultra.dex2cvmp.engine;

public class MethodInfo {
    public static final int ACC_STATIC   = 0x0008;
    public static final int ACC_NATIVE   = 0x0100;
    public static final int ACC_ABSTRACT = 0x0400;

    public static final int SIG_UNSUPPORTED = -1;

    public final String dexEntry;
    public final String className;
    public final String methodName;
    public final String descriptor;
    public final int accessFlags;

    public MethodInfo(String dexEntry, String className, String methodName,
                      String descriptor, int accessFlags) {
        this.dexEntry     = dexEntry;
        this.className    = className;
        this.methodName   = methodName;
        this.descriptor   = descriptor;
        this.accessFlags  = accessFlags;
    }

    public boolean isStatic() {
        return (accessFlags & ACC_STATIC) != 0;
    }

    public boolean canWrapNative() {
        if ((accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) return false;
        if (methodName.equals("<init>") || methodName.equals("<clinit>")) return false;

        // ── Kotlin coroutine guard ───────────────────────────────────────────
        // The raw "invokeSuspend" method IS the coroutine state machine:
        //   override fun invokeSuspend(result: Any?): Any?
        // It uses a label-based switch that the dex2c Python type-inferencer
        // often handles correctly, BUT if it succeeds it generates C that may
        // mishandle the Kotlin Result wrapper and continuation protocol at
        // runtime.  Block it by name so it always stays as Dalvik bytecode.
        //
        // Note: "invokeSuspend$lambda$N" are simple lambda method references
        // (different name) and are NOT blocked here — they are safe to protect.
        if (methodName.equals("invokeSuspend")) return false;

        return true;
    }

    public String toDexSignature() {
        return className + "->" + methodName + descriptor;
    }

    public String renamedMethod() {
        // Looks like a compiler-generated lambda body — blends in with
        // desugared Kotlin and R8-processed classes, harder to spot in jadx.
        // The hash makes it unique per method so there are no collisions.
        int hash = (className + methodName + descriptor).hashCode() & 0x7FFFFFFF;
        return "-$$lambda$d2c$" + Integer.toHexString(hash);
    }

    /**
     * Maps the Java method descriptor to one of the 32 pre-compiled C trampoline
     * signature types in libdex2c.so.
     *
     * Types  0-15 = virtual (instance) methods.
     * Types 16-31 = static methods (same patterns, different JNI call variant).
     *
     * Returns SIG_UNSUPPORTED (-1) for signatures not covered — those methods
     * fall back to smali-level obfuscation instead of native wrapping.
     */
    public int getSigType() {
        int base = isStatic() ? 16 : 0;
        return base + getSigTypeVirtual();
    }

    private int getSigTypeVirtual() {
        // --- zero-arg signatures ---
        if (descriptor.equals("()V"))  return 0;
        if (descriptor.equals("()Z"))  return 2;
        if (descriptor.equals("()I"))  return 3;
        if (descriptor.equals("()J"))  return 4;

        // ()Object  — any object/array return, no args
        if (descriptor.matches("\\(\\)(L[^;]+;|\\[.+)")) return 5;

        // --- one Object arg ---
        // (Object)V  — single ref-type arg, void return
        if (descriptor.matches("\\((L[^;]+;|\\[.+)\\)V")) return 1;
        // (Object)Z
        if (descriptor.matches("\\((L[^;]+;|\\[.+)\\)Z")) return 6;
        // (Object)Object
        if (descriptor.matches("\\((L[^;]+;|\\[.+)\\)(L[^;]+;|\\[.+)")) return 7;

        // --- one primitive arg ---
        if (descriptor.equals("(I)V"))  return 8;
        if (descriptor.equals("(I)I"))  return 9;
        if (descriptor.equals("(II)V")) return 10;
        if (descriptor.equals("(II)I")) return 11;
        if (descriptor.equals("(Z)V"))  return 12;
        if (descriptor.equals("(J)J"))  return 13;

        // --- two Object args ---
        if (descriptor.matches("\\((L[^;]+;|\\[.+)(L[^;]+;|\\[.+)\\)(L[^;]+;|\\[.+)")) return 14;
        if (descriptor.matches("\\((L[^;]+;|\\[.+)(L[^;]+;|\\[.+)\\)V")) return 15;

        return SIG_UNSUPPORTED;
    }
}
