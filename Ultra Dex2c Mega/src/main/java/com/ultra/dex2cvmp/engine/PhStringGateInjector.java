package com.ultra.dex2cvmp.engine;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.HiddenApiRestriction;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.base.reference.BaseMethodReference;
import com.android.tools.smali.dexlib2.base.reference.BaseTypeReference;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31i;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.ultra.dex2cvmp.engine.vmp.Dex2c;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.EmptyConstructorMethod;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.*;

/**
 * Builds a minimal DEX containing a single synthetic class:
 *
 *   public class com.ultra.dex2cvmp.gate.PhStringGate {
 *       public static int computeToken() { return TOKEN; }
 *   }
 *
 * TOKEN is chosen randomly at build time and stored in GateContext.token.
 * In VMP mode, the transpiler converts computeToken() to custom VMP opcodes
 * so the return value is opaque to static analysis (Ghidra / IDA).
 * In DEX2C mode it becomes compiled ARM inside the .so.
 *
 * Crucially, this class does NOT rewrite the APK zip — it only writes
 * classesN.dex to dexDir.  That avoids the STORED-compression breakage that
 * crashed native lib loading in earlier prototypes.
 *
 * The gate DEX reaches the VMP transpiler via DexTranspiler.transpile()'s
 * extraDex parameter and reaches the output APK via ApkRebuilder picking up
 * everything in dexDir.
 */
public class PhStringGateInjector {

    private static final String GATE_TYPE = "L" + GateContext.CLASS_DESC + ";";

    /**
     * Write the gate DEX to dexDir as classesN.dex (next available slot).
     *
     * @param dexDir   directory that already holds the APK's extracted DEX files
     * @param token    the int literal computeToken() will return at runtime
     * @return         the written File — pass to DexTranspiler as extraDex
     */
    public static File inject(File dexDir, int token) throws Exception {
        File gateDex = GateContext.nextSyntheticDexFile(dexDir);

        // Build DEX via the same DexPool035 pipeline as injectVmpNativeUtil
        DexPool pool = new DexPool(com.android.tools.smali.dexlib2.Opcodes.getDefault());
        pool.internClass(new GateClassDef(token));
        Dex2c.writeDexPool035(pool, gateDex);

        android.util.Log.i("PhStringGateInjector",
                "Gate DEX written: " + gateDex.getName()
                + "  token=0x" + Integer.toHexString(token));
        return gateDex;
    }

    // ── Synthetic ClassDef ─────────────────────────────────────────────────────

    private static final class GateClassDef extends BaseTypeReference implements ClassDef {

        private final int token;
        GateClassDef(int token) { this.token = token; }

        @Nonnull @Override public String  getType()        { return GATE_TYPE; }
        @Override          public int     getAccessFlags() { return AccessFlags.PUBLIC.getValue(); }
        @Nullable @Override public String getSuperclass()  { return "Ljava/lang/Object;"; }
        @Nonnull @Override public List<String> getInterfaces() { return Collections.emptyList(); }
        @Nullable @Override public String getSourceFile()  { return null; }
        @Nonnull @Override public Set<? extends Annotation> getAnnotations() { return Collections.emptySet(); }
        @Nonnull @Override public Iterable<? extends Field> getStaticFields()   { return Collections.emptyList(); }
        @Nonnull @Override public Iterable<? extends Field> getInstanceFields()  { return Collections.emptyList(); }
        @Nonnull @Override public Iterable<? extends Field> getFields()          { return Collections.emptyList(); }
        @Nonnull @Override public Iterable<? extends Method> getVirtualMethods() { return Collections.emptyList(); }

        @Nonnull @Override
        public Iterable<? extends Method> getDirectMethods() {
            List<Method> methods = new ArrayList<>(2);
            methods.add(new EmptyConstructorMethod(GATE_TYPE, "Ljava/lang/Object;"));
            methods.add(new ComputeTokenMethod(token));
            return methods;
        }

        @Nonnull @Override
        public Iterable<? extends Method> getMethods() { return getDirectMethods(); }
    }

    // ── computeToken()I { return token; } ─────────────────────────────────────

    private static final class ComputeTokenMethod extends BaseMethodReference implements Method {

        private final int token;
        ComputeTokenMethod(int token) { this.token = token; }

        @Nonnull @Override public String getDefiningClass() { return GATE_TYPE; }
        @Nonnull @Override public String getName()          { return GateContext.METHOD_NAME; }
        @Nonnull @Override public String getReturnType()    { return "I"; }
        @Nonnull @Override public List<? extends CharSequence> getParameterTypes() { return Collections.emptyList(); }
        @Nonnull @Override public List<? extends MethodParameter> getParameters()  { return Collections.emptyList(); }

        @Override
        public int getAccessFlags() {
            return AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
        }

        @Nonnull @Override public Set<? extends Annotation> getAnnotations()        { return Collections.emptySet(); }
        @Nonnull @Override public Set<HiddenApiRestriction> getHiddenApiRestrictions() { return Collections.emptySet(); }

        @Override
        public MethodImplementation getImplementation() {
            // const v0, <token>   → 32-bit literal
            // return v0
            MutableMethodImplementation impl = new MutableMethodImplementation(1);
            impl.addInstruction(new BuilderInstruction31i(Opcode.CONST, 0, token));
            impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            return impl;
        }
    }
}
