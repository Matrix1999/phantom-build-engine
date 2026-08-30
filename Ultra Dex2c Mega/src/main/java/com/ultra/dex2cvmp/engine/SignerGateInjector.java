package com.ultra.dex2cvmp.engine;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.HiddenApiRestriction;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.base.reference.BaseMethodReference;
import com.android.tools.smali.dexlib2.base.reference.BaseTypeReference;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31i;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.Annotation;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.ultra.dex2cvmp.engine.vmp.Dex2c;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.EmptyConstructorMethod;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Creates the small synthetic class that owns the encrypted signer payload in
 * VMP mode. Each four-byte payload word is recovered through a separate method,
 * so no native provider contains the complete ciphertext.
 */
public final class SignerGateInjector {

    private static final int PART_COUNT = 12;
    private static final String GATE_TYPE = "L" + GateContext.SIGNER_CLASS_DESC + ";";

    private SignerGateInjector() {}

    /**
     * Add SignerGate to an already-created small gate DEX.  The existing gate
     * DEX is intentionally the only file rewritten here; it contains synthetic
     * classes and is tiny compared with an application's primary DEX.
     */
    public static File injectInto(File gateDex, byte[] cipher) throws Exception {
        if (cipher == null || cipher.length != PART_COUNT * 4) {
            throw new IllegalArgumentException("Signer cipher must be exactly 48 bytes.");
        }

        if (gateDex == null || !gateDex.isFile()) {
            throw new IllegalArgumentException("Gate DEX does not exist: " + gateDex);
        }

        DexBackedDexFile existing;
        try (BufferedInputStream input = new BufferedInputStream(
                new FileInputStream(gateDex))) {
            existing = DexBackedDexFile.fromInputStream(null, input);
        }

        DexPool pool = new DexPool(existing.getOpcodes());
        for (ClassDef classDef : existing.getClasses()) {
            pool.internClass(classDef);
        }
        pool.internClass(new SignerGateClassDef(cipher));
        Dex2c.writeDexPool035(pool, gateDex);
        return gateDex;
    }

    private static final class SignerGateClassDef extends BaseTypeReference implements ClassDef {
        private final int[] words = new int[PART_COUNT];
        private final int[] masks = new int[PART_COUNT];

        SignerGateClassDef(byte[] cipher) {
            SecureRandom random = new SecureRandom();
            for (int i = 0; i < PART_COUNT; i++) {
                int off = i * 4;
                words[i] = ((cipher[off] & 0xff) << 24)
                        | ((cipher[off + 1] & 0xff) << 16)
                        | ((cipher[off + 2] & 0xff) << 8)
                        | (cipher[off + 3] & 0xff);
                masks[i] = random.nextInt() | 1;
            }
        }

        @Nonnull @Override public String getType() { return GATE_TYPE; }
        @Override public int getAccessFlags() { return AccessFlags.PUBLIC.getValue(); }
        @Nullable @Override public String getSuperclass() { return "Ljava/lang/Object;"; }
        @Nonnull @Override public List<String> getInterfaces() { return Collections.emptyList(); }
        @Nullable @Override public String getSourceFile() { return null; }
        @Nonnull @Override public Set<? extends Annotation> getAnnotations() { return Collections.emptySet(); }
        @Nonnull @Override public Iterable<? extends Field> getStaticFields() { return Collections.emptyList(); }
        @Nonnull @Override public Iterable<? extends Field> getInstanceFields() { return Collections.emptyList(); }
        @Nonnull @Override public Iterable<? extends Field> getFields() { return Collections.emptyList(); }
        @Nonnull @Override public Iterable<? extends Method> getVirtualMethods() { return Collections.emptyList(); }

        @Nonnull @Override
        public Iterable<? extends Method> getDirectMethods() {
            List<Method> methods = new ArrayList<>(PART_COUNT + 1);
            methods.add(new EmptyConstructorMethod(GATE_TYPE, "Ljava/lang/Object;"));
            for (int i = 0; i < PART_COUNT; i++) {
                methods.add(new SignerPartMethod(i, words[i], masks[i]));
            }
            return methods;
        }

        @Nonnull @Override public Iterable<? extends Method> getMethods() { return getDirectMethods(); }
    }

    private static final class SignerPartMethod extends BaseMethodReference implements Method {
        private final int index;
        private final int maskedWord;
        private final int mask;

        SignerPartMethod(int index, int word, int mask) {
            this.index = index;
            this.mask = mask;
            this.maskedWord = word ^ mask;
        }

        @Nonnull @Override public String getDefiningClass() { return GATE_TYPE; }
        @Nonnull @Override public String getName() { return GateContext.signerPartMethodName(index); }
        @Nonnull @Override public String getReturnType() { return "I"; }
        @Nonnull @Override public List<? extends CharSequence> getParameterTypes() { return Collections.emptyList(); }
        @Nonnull @Override public List<? extends MethodParameter> getParameters() { return Collections.emptyList(); }
        @Override public int getAccessFlags() {
            return AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
        }
        @Nonnull @Override public Set<? extends Annotation> getAnnotations() { return Collections.emptySet(); }
        @Nonnull @Override public Set<HiddenApiRestriction> getHiddenApiRestrictions() { return Collections.emptySet(); }

        @Override
        public MethodImplementation getImplementation() {
            MutableMethodImplementation impl = new MutableMethodImplementation(2);
            impl.addInstruction(new BuilderInstruction31i(Opcode.CONST, 0, maskedWord));
            impl.addInstruction(new BuilderInstruction31i(Opcode.CONST, 1, mask));
            impl.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 0, 1));
            impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            return impl;
        }
    }
}