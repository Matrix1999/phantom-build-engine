package com.ultra.dex2cvmp.engine;

import android.util.Log;

import com.v7878.dex.DexConstants;
import com.v7878.dex.DexIO;
import com.v7878.dex.DexVersion;
import com.v7878.dex.Opcode;
import com.v7878.dex.WriteOptions;
import com.v7878.dex.immutable.Annotation;
import com.v7878.dex.immutable.ClassDef;
import com.v7878.dex.immutable.Dex;
import com.v7878.dex.immutable.ExceptionHandler;
import com.v7878.dex.immutable.FieldDef;
import com.v7878.dex.immutable.MethodDef;
import com.v7878.dex.immutable.MethodId;
import com.v7878.dex.immutable.MethodImplementation;
import com.v7878.dex.immutable.Parameter;
import com.v7878.dex.immutable.TryBlock;
import com.v7878.dex.immutable.TypeId;
import com.v7878.dex.immutable.bytecode.Instruction;
import com.v7878.dex.immutable.bytecode.InstructionN0x;
import com.v7878.dex.immutable.bytecode.InstructionN1c;
import com.v7878.dex.immutable.bytecode.InstructionNv5c;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tier1DexPatcher — patches DEX files using vova7878/DexFile.
 *
 * Key advantage over the previous dexlib2 implementation: vova7878/DexFile
 * reads unknown/obfuscated instructions as raw bytes (InstructionRaw0x) and
 * writes them back verbatim via WriteOptions.defaultOptions() which uses
 * RawFix.DO_NOT_TOUCH. Bystander classes with obfuscated bytecode are NEVER
 * re-encoded — they pass through as raw bytes. No L3/L4/L5 fallbacks needed.
 *
 * Pipeline:
 *   patchAll()          → strip compiled methods + inject <clinit> loadLibrary + guard class
 *   appendGuardDex()    → last-resort standalone guard DEX (fallback only)
 */
public class Tier1DexPatcher {

    private static final String TAG              = "Tier1DexPatcher";
    private static final String DEFAULT_LIB_NAME = "ultra-dex2cvmp";

    private static final TypeId  CONTEXT_TYPE         = TypeId.of("Landroid/content/Context;");

    // Code units prepended into <clinit> by prependLoadLibrary:
    //   const-string (2) + invoke-static (3) = 5
    private static final int CLINIT_PREPEND_CU = 5;

    private static final TypeId  GUARD_CLASS_TYPE  = TypeId.of("Lfonts/Metrics;");
    private static final String  GUARD_METHOD      = "measure";
    private static final String  GUARD_SOURCE_FILE = "FontMetrics.kt";

    private static final Pattern CLASSES_DEX_PATTERN =
            Pattern.compile("classes(\\d*)\\.dex");

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Stage 1 — in-place bytecode strip + <clinit> injection.
     *
     * For every DEX that contains a target class:
     *   • Compiled methods become ACC_NATIVE stubs (null implementation).
     *   • <clinit> gets System.loadLibrary prepended (or synthesised).
     *   • fonts.Metrics guard class merged into the first patched DEX.
     *   • Bystander classes are passed through completely unchanged —
     *     vova7878/DexFile writes raw bytes back as-is (RawFix.DO_NOT_TOUCH),
     *     so obfuscated bytecode never causes a re-encode failure.
     *
     * @return total compiled method stubs created.
     */
    public static int patchAll(File dexDir, Set<String> compiledKeys) throws IOException {
        return patchAll(dexDir, compiledKeys, DEFAULT_LIB_NAME);
    }

    public static int patchAll(File dexDir, Set<String> compiledKeys,
                                String libName) throws IOException {
        return patchAll(dexDir, compiledKeys, libName, null);
    }

    public static int patchAll(File dexDir, Set<String> compiledKeys, String libName,
                               java.util.function.Consumer<String> progress) throws IOException {
        Set<String> targetTypes = new HashSet<>();
        for (String key : compiledKeys) {
            int arrow = key.indexOf("->");
            if (arrow > 0) targetTypes.add(key.substring(0, arrow));
        }

        File[] files = dexDir.listFiles();
        if (files == null) return 0;
        Arrays.sort(files, Comparator.comparing(File::getName));

        int total = 0;
        boolean guardPlaced = false;
        File primaryDex = null;

        for (File f : files) {
            if (!f.getName().endsWith(".dex")) continue;
            if ("classes.dex".equals(f.getName())) primaryDex = f;

            if (!dexHasTargetClasses(f, targetTypes)) {
                Log.d(TAG, "Bystander: " + f.getName() + " — no target classes, skipping");
                if (progress != null)
                    progress.accept("Bystander " + f.getName() + ": no target classes, left as-is");
                continue;
            }

            if (progress != null)
                progress.accept("Patching " + f.getName() + " (%.1f KB)…".formatted(f.length() / 1024f));

            boolean addGuardHere = !guardPlaced;
            File tmp = new File(f.getParent(), f.getName() + ".patched");
            int n = patchInPlace(f, tmp, compiledKeys, targetTypes, libName, addGuardHere);
            total += n;
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING);

            if (addGuardHere) {
                guardPlaced = true;
                Log.i(TAG, "fonts.Metrics merged into " + f.getName() +
                        " (load-bearing — contains stripped target classes)");
            }
            if (progress != null) progress.accept("Patched " + f.getName() + " — " + n + " method(s) stripped");
        }

        if (!guardPlaced) {
            if (primaryDex != null) {
                File tmp = new File(primaryDex.getParent(), primaryDex.getName() + ".patched");
                patchInPlace(primaryDex, tmp, compiledKeys, targetTypes, libName, true);
                Files.move(tmp.toPath(), primaryDex.toPath(), StandardCopyOption.REPLACE_EXISTING);
                guardPlaced = true;
                Log.i(TAG, "fonts.Metrics merged into classes.dex (primary — no target classes selected)");
                if (progress != null)
                    progress.accept("fonts.Metrics merged into classes.dex (primary, always load-bearing)");
            } else {
                Log.w(TAG, "classes.dex not found — falling back to standalone guard DEX");
                appendGuardDex(dexDir, libName);
                if (progress != null) progress.accept("fonts.Metrics injected via fallback standalone DEX");
            }
        }

        Log.i(TAG, "Stripped " + total + " method(s) in-place");
        return total;
    }

    /**
     * Stage 2 — standalone guard DEX (last-resort fallback only).
     * Appended as the next classes*.dex index when classes.dex cannot be found.
     */
    public static File appendGuardDex(File dexDir, String libName) throws IOException {
        File[] files = dexDir.listFiles();
        int maxIndex = 1;
        if (files != null) {
            for (File f : files) {
                Matcher m = CLASSES_DEX_PATTERN.matcher(f.getName());
                if (!m.matches()) continue;
                String digits = m.group(1);
                int idx = digits.isEmpty() ? 1 : Integer.parseInt(digits);
                if (idx > maxIndex) maxIndex = idx;
            }
        }
        File out = new File(dexDir, "classes" + (maxIndex + 1) + ".dex");
        List<ClassDef> classes = new ArrayList<>();
        classes.add(buildGuardClassDef());
        Files.write(out.toPath(), writeDex035(Dex.of(classes)));
        Log.i(TAG, "fonts.Metrics injected unconditionally → " + out.getName());
        return out;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IN-PLACE STRIP — patchInPlace
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Strip compiled methods to ACC_NATIVE stubs and inject <clinit> loadLibrary —
     * all in the same DEX file. Bystander classes (non-target) are added to the
     * output pool as-is; vova7878/DexFile's default WriteOptions uses
     * RawFix.DO_NOT_TOUCH which writes unknown/obfuscated instructions verbatim.
     * No retry loop, no L3/L4/L5 fallbacks required.
     *
     * @return count of native stubs created.
     */
    private static int patchInPlace(File dexFile, File outputDex,
                                    Set<String> compiledKeys,
                                    Set<String> targetTypes,
                                    String libName,
                                    boolean addGuard) throws IOException {
        byte[] data = Files.readAllBytes(dexFile.toPath());
        Dex input = DexIO.read(data);
        int count = 0;

        List<ClassDef> newClasses = new ArrayList<>();

        for (ClassDef cls : input.getClasses()) {
            String clsType = cls.getType().toString();

            if (!targetTypes.contains(clsType)) {
                // ── Bystander class ─────────────────────────────────────────
                // vova7878/DexFile reads unknown opcodes as InstructionRaw0x and
                // writes them back as raw bytes via RawFix.DO_NOT_TOUCH (default).
                // Zero re-encoding work, zero risk of failure on obfuscated code.
                newClasses.add(cls);
                continue;
            }

            // ── Target class: strip compiled methods, inject loadLibrary ────
            List<MethodDef> newMethods = new ArrayList<>();
            boolean clinitFound = false;

            for (MethodDef m : cls.getMethods()) {
                String key = buildKey(cls.getType(), m);

                if (compiledKeys.contains(key)) {
                    if ("<init>".equals(m.getName())) {
                        // ART rejects native constructors — keep original bytecode.
                        newMethods.add(m);
                        Log.w(TAG, "→ keeping <init> bytecode (native <init> rejected by ART): " + key);
                    } else {
                        newMethods.add(makeNative(m));
                        count++;
                        Log.d(TAG, "→ native stub: " + key);
                    }
                } else if ("<clinit>".equals(m.getName())) {
                    clinitFound = true;
                    newMethods.add(prependLoadLibrary(m, libName));
                } else {
                    newMethods.add(m);
                }
            }

            if (!clinitFound) newMethods.add(buildClinitMethod(libName));

            newClasses.add(ClassDef.of(
                    cls.getType(), cls.getAccessFlags(), cls.getSuperclass(),
                    cls.getInterfaces(), cls.getSourceFile(),
                    cls.getFields(), newMethods, cls.getAnnotations()));
        }

        if (addGuard) {
            newClasses.add(buildGuardClassDef());
            Log.d(TAG, "fonts.Metrics injected into " + dexFile.getName());
        }

        // writeDex035 wraps DexIO.write and forces the magic header to "dex\n035\0"
        // so tools like MT Manager (which reject 036–040) can open the output.
        Files.write(outputDex.toPath(), writeDex035(Dex.of(newClasses)));
        Log.i(TAG, "In-place strip (vova7878/DexFile): " + count + " stub(s) in " + dexFile.getName());
        return count;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // METHOD BUILDERS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Convert a method to ACC_NATIVE with null implementation.
     * Parameter names are stripped (debug_info_item requires a code_item;
     * native methods have code_off=0 so there's no legal location for one).
     */
    private static MethodDef makeNative(MethodDef m) {
        int flags = (m.getAccessFlags() | DexConstants.ACC_NATIVE)
                  & ~DexConstants.ACC_ABSTRACT;
        List<Parameter> strippedParams = new ArrayList<>();
        for (Parameter p : m.getParameters()) {
            strippedParams.add(Parameter.of(p.getType(), null, p.getAnnotations()));
        }
        return MethodDef.of(m.getName(), m.getReturnType(), strippedParams,
                flags, m.getHiddenApiFlags(), null, m.getAnnotations());
    }

    /** Build a brand-new <clinit> that just calls System.loadLibrary(libName). */
    private static MethodDef buildClinitMethod(String libName) {
        List<Instruction> instrs = new ArrayList<>();
        instrs.add(makeConstString(0, libName));
        instrs.add(makeInvokeLoadLibrary(0));
        instrs.add(InstructionN0x.of(Opcode.RETURN_VOID));
        MethodImplementation impl = MethodImplementation.of(
                1, instrs, Collections.emptyList(), Collections.emptyList());
        return MethodDef.of("<clinit>", TypeId.V, Collections.emptyList(),
                DexConstants.ACC_STATIC | DexConstants.ACC_CONSTRUCTOR,
                0, impl, Collections.emptyList());
    }

    /** Prepend System.loadLibrary(libName) to an existing <clinit>. */
    private static MethodDef prependLoadLibrary(MethodDef m, String libName) {
        MethodImplementation impl = m.getImplementation();
        if (impl == null) return buildClinitMethod(libName);

        List<Instruction> newInstrs = new ArrayList<>();
        newInstrs.add(makeConstString(0, libName));
        newInstrs.add(makeInvokeLoadLibrary(0));
        newInstrs.addAll(impl.getInstructions());

        int newRegCount = Math.max(impl.getRegisterCount(), 1);

        List<TryBlock> newTryBlocks = new ArrayList<>();
        for (TryBlock tb : impl.getTryBlocks()) {
            List<ExceptionHandler> newHandlers = new ArrayList<>();
            for (ExceptionHandler eh : tb.getHandlers()) {
                newHandlers.add(ExceptionHandler.of(
                        eh.getExceptionType(), eh.getAddress() + CLINIT_PREPEND_CU));
            }
            Integer newCatchAll = tb.getCatchAllAddress() != null
                    ? tb.getCatchAllAddress() + CLINIT_PREPEND_CU : null;
            newTryBlocks.add(TryBlock.of(
                    tb.getStartAddress() + CLINIT_PREPEND_CU,
                    tb.getUnitCount(), newCatchAll, newHandlers));
        }

        MethodImplementation newImpl = MethodImplementation.of(
                newRegCount, newInstrs, newTryBlocks, Collections.emptyList());
        return MethodDef.of(m.getName(), m.getReturnType(), m.getParameters(),
                m.getAccessFlags(), m.getHiddenApiFlags(), newImpl, m.getAnnotations());
    }

    /** Build the synthetic fonts.Metrics guard ClassDef. */
    private static ClassDef buildGuardClassDef() {
        MethodDef checkMethod = MethodDef.of(
                GUARD_METHOD, TypeId.V,
                Collections.singletonList(Parameter.of(CONTEXT_TYPE)),
                DexConstants.ACC_PUBLIC | DexConstants.ACC_STATIC | DexConstants.ACC_NATIVE,
                0, null, Collections.emptyList());
        return ClassDef.of(
                GUARD_CLASS_TYPE,
                DexConstants.ACC_PUBLIC,
                TypeId.of("Ljava/lang/Object;"),
                Collections.emptyList(),
                GUARD_SOURCE_FILE,
                Collections.emptyList(),
                Collections.singletonList(checkMethod),
                Collections.emptyList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INSTRUCTION BUILDERS
    // ─────────────────────────────────────────────────────────────────────────

    private static Instruction makeConstString(int reg, String value) {
        return InstructionN1c.of(Opcode.CONST_STRING, reg, value);
    }

    private static Instruction makeInvokeLoadLibrary(int reg) {
        return InstructionNv5c.of(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0,
                MethodId.of(TypeId.of("Ljava/lang/System;"), "loadLibrary",
                        TypeId.V, TypeId.of("Ljava/lang/String;")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private static String buildKey(TypeId classType, MethodDef m) {
        StringBuilder desc = new StringBuilder("(");
        for (Parameter p : m.getParameters()) desc.append(p.getType());
        desc.append(")").append(m.getReturnType());
        return classType + "->" + m.getName() + desc;
    }

    /**
     * Patch the DEX magic header to force version 035.
     *
     * DexIO.write() selects the version automatically based on opcodes/features
     * in the file, and on newer vova7878 builds that may mean 036, 037, 039 or
     * 040.  Many editors (MT Manager, NP Manager, apktool, etc.) reject anything
     * above 035.  We patch bytes [4..7] of the returned buffer from
     * "dex\nXXX\0" → "dex\n035\0" before writing to disk.
     *
     * This is safe as long as we do not emit opcodes that were actually
     * introduced after DEX 035 (invoke-polymorphic, invoke-custom, const-
     * method-handle, const-method-type).  All instructions we synthesise
     * (const-string, invoke-static, invoke-super, return-void) are DEX 035
     * compatible, and bystander classes are written verbatim via
     * RawFix.DO_NOT_TOUCH so their opcodes are never re-encoded.
     */
    // WriteOptions that locks the output version to DEX 035.
    // DexVersion.DEX035 is supported on all Android APIs (minApi=1).
    // All instructions we synthesise (const-string, invoke-static,
    // invoke-super, return-void) exist since DEX 035, so this is safe.
    // Bystander classes pass through as raw bytes (RawFix.DO_NOT_TOUCH)
    // so their opcodes are never re-encoded regardless of the version flag.
    private static final WriteOptions WRITE_OPTIONS_035 =
            WriteOptions.defaultOptions().withDexVersion(DexVersion.DEX035);

    private static byte[] writeDex035(Dex dex) {
        return DexIO.write(WRITE_OPTIONS_035, dex);
    }

    /**
     * Parse-based target-class detection using DexIO.
     *
     * Replaces the old binary byte-scan ({@code dexContainsAnyTarget}).  The
     * byte-scan was fast but produced false-negatives on some APKs (short
     * obfuscated names that are substrings of unrelated byte sequences,
     * MUTF-8 edge-cases, etc.).  Parsing the DEX and walking the actual
     * class-definition list is 100 % accurate at the cost of one extra read
     * for bystander DEX files — a worthwhile trade to guarantee no DEX is
     * ever silently skipped.
     */
    private static boolean dexHasTargetClasses(File dexFile,
                                               Set<String> targetTypes) throws IOException {
        if (targetTypes.isEmpty()) return false;
        Dex dex = DexIO.read(Files.readAllBytes(dexFile.toPath()));
        for (ClassDef cls : dex.getClasses()) {
            if (targetTypes.contains(cls.getType().toString())) return true;
        }
        return false;
    }

}
