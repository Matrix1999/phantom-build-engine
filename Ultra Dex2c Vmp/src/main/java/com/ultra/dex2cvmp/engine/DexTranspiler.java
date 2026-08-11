package com.ultra.dex2cvmp.engine;

import android.util.Log;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.ultra.dex2cvmp.engine.vmp.Dex2c;
import com.ultra.dex2cvmp.engine.vmp.GlobalDexConfig;
import com.ultra.dex2cvmp.engine.vmp.converter.ClassAnalyzer;
import com.ultra.dex2cvmp.engine.vmp.converter.instructionrewriter.RandomInstructionRewriter;
import com.ultra.dex2cvmp.engine.vmp.filters.BasicKeepConfig;
import com.ultra.dex2cvmp.engine.vmp.filters.ClassAndMethodFilter;
import com.ultra.dex2cvmp.engine.vmp.filters.SimpleConvertConfig;
import com.ultra.dex2cvmp.engine.vmp.filters.SimpleRules;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * DexTranspiler — routes APK methods to either:
 *
 *   MODE_DEX2C  — codehasan/dex2c Python transpiler (existing path, unchanged)
 *   MODE_VMP    — maoabc/nmmp VMP interpreter (Dalvik → custom opcodes + C VM)
 *   MODE_HYBRID — VMP for selected classes, dex2c for everything else
 *
 * The routing decision is made per-protect-run via the {@code mode} parameter.
 * Both paths write their C output files to {@code outputDir}; NdkBuilder
 * picks them all up in a single compilation pass.
 */
public class DexTranspiler {

    private static final String TAG = "DexTranspiler";

    // ── Modes ────────────────────────────────────────────────────────────────
    public static final int MODE_DEX2C  = 0;  // existing Python bridge only
    public static final int MODE_VMP    = 1;  // NMMP VMP interpreter only
    public static final int MODE_HYBRID = 2;  // VMP for vmpFilter classes, dex2c for rest

    // ── Callback / result types ──────────────────────────────────────────────
    public interface TranspileCallback {
        void onProgress(String message);
    }

    public static class TranspileResult {
        public final Map<String, String> compiled  = new LinkedHashMap<>();
        public final List<String>        errors    = new ArrayList<>();
        public       GlobalDexConfig     vmpConfig = null;   // non-null when VMP ran
        public int successCount() { return compiled.size(); }
    }

    private final android.content.Context context;

    public DexTranspiler(android.content.Context context) {
        this.context = context.getApplicationContext();
    }

    // ── Public entry points ──────────────────────────────────────────────────

    /**
     * Transpile with explicit mode selection.
     *
     * @param apkPath    path to the input APK
     * @param filterText classes to protect — one class name per line for dex2c,
     *                   or NMMP SimpleRules format for VMP
     *                   ("class com.foo.Bar { *; }")
     * @param outputDir  directory to write generated C / C++ files into
     * @param mode       MODE_DEX2C | MODE_VMP | MODE_HYBRID
     * @param cb         progress callback (nullable)
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, int mode,
                                     TranspileCallback cb) {
        switch (mode) {
            case MODE_VMP:    return transpileVmp(apkPath, filterText, outputDir, cb);
            case MODE_HYBRID: return transpileHybrid(apkPath, filterText, outputDir, cb);
            default:          return transpileDex2c(apkPath, filterText, outputDir, cb);
        }
    }

    /**
     * Legacy overload — defaults to MODE_DEX2C (backwards-compatible).
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, TranspileCallback cb) {
        return transpileDex2c(apkPath, filterText, outputDir, cb);
    }

    // ── Path 1: existing Python dex2c (unchanged) ────────────────────────────

    private TranspileResult transpileDex2c(String apkPath, String filterText,
                                           File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile(DEX2C) apk=" + apkPath);
        Dex2cPythonBridge bridge = new Dex2cPythonBridge(context);
        if (!bridge.isAvailable()) {
            TranspileResult r = new TranspileResult();
            r.errors.add("Python runtime not available — check storage and try again.");
            return r;
        }
        return bridge.transpile(apkPath, filterText, outputDir, cb);
    }

    // ── Path 2: NMMP VMP interpreter ─────────────────────────────────────────

    /**
     * VMP path — converts selected Dalvik methods to randomised custom opcodes
     * interpreted at runtime by the nmmvm C engine (InterpC-portable.cpp).
     *
     * filterText uses NMMP SimpleRules format, e.g.:
     *   class com.foo.LicenseChecker { *; }
     *   class com.foo.CryptoUtil { *; }
     *
     * If filterText is plain class names (one per line, no "class" keyword),
     * we auto-wrap them into SimpleRules format.
     */
    private TranspileResult transpileVmp(String apkPath, String filterText,
                                         File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile(VMP) apk=" + apkPath);
        TranspileResult result = new TranspileResult();
        try {
            progress(cb, "VMP: extracting DEX files from APK…");
            List<File> dexFiles = extractDexFiles(apkPath, outputDir);
            if (dexFiles.isEmpty()) {
                result.errors.add("VMP: no DEX files found in " + apkPath);
                return result;
            }
            progress(cb, "VMP: parsing class hierarchy…");
            // buildClassAnalyzerWithCache runs on ALL DEX files — needed for correct
            // virtual-method dispatch resolution.  The cache (fix #1) lets
            // handleAllDex reuse each parsed DexBackedDexFile instead of
            // calling fromInputStream() a second time per hot DEX.
            ClassAnalyzerResult analyzerResult = buildClassAnalyzerWithCache(dexFiles);
            ClassAnalyzer classAnalyzer = analyzerResult.analyzer;

            progress(cb, "VMP: building filter rules…");
            ClassAndMethodFilter filter = buildFilter(filterText, classAnalyzer);

            // ── Smart DEX targeting ─────────────────────────────────────────
            // Identify which DEX files actually contain the user's target classes.
            // DEX files with no target classes ("cold") are skipped by handleAllDex;
            // they remain in dexDir untouched so ApkRebuilder includes them as-is.
            Set<String> targetDescriptors = parseTargetDescriptors(filterText);
            List<File> hotDexFiles = filterHotDexFiles(dexFiles, targetDescriptors, cb);
            if (hotDexFiles.isEmpty()) {
                // Fallback: target classes not found in index — process all DEX files
                Log.w(TAG, "VMP smart targeting: no matches found, falling back to full scan");
                hotDexFiles = dexFiles;
            } else if (hotDexFiles.size() < dexFiles.size()) {
                progress(cb, "VMP: smart targeting — " + hotDexFiles.size()
                        + " hot / " + (dexFiles.size() - hotDexFiles.size())
                        + " cold DEX files (cold skipped)");
            }

            // Random opcode map — different every protect run
            RandomInstructionRewriter rewriter = new RandomInstructionRewriter();

            progress(cb, "VMP: converting methods → custom opcodes + C stubs…");
            File vmpOutDir = new File(outputDir, "vmp");
            if (!vmpOutDir.exists()) vmpOutDir.mkdirs();

            GlobalDexConfig vmpConfig = Dex2c.handleAllDex(
                    hotDexFiles, filter, rewriter, classAnalyzer,
                    analyzerResult.parsedFiles,   // fix #1: pre-parsed cache
                    vmpOutDir,
                    msg -> progress(cb, msg));

            result.vmpConfig = vmpConfig;

            // Generate a per-run DexOpcodes.h that matches the randomized bytecode opcode map.
            // Without this, the static vmp_headers/DexOpcodes.h (standard Dalvik ordering) is
            // used during compilation but the bytecode was written with a shuffled opcode map →
            // every instruction dispatches to the wrong handler in vmInterpret → SIGSEGV.
            // This replicates NMMP's CmakeUtils.writeOpcodeHeaderFile() logic.
            progress(cb, "VMP: generating per-run DexOpcodes.h…");
            try {
                File dexOpcodesH = new File(vmpOutDir, "DexOpcodes.h");
                generateDexOpcodesHeader(rewriter, dexOpcodesH);
                Log.i(TAG, "Per-run DexOpcodes.h written → " + dexOpcodesH.getAbsolutePath());
            } catch (Exception e) {
                Log.e(TAG, "generateDexOpcodesHeader failed", e);
                result.errors.add("VMP: DexOpcodes.h generation failed: " + e.getMessage());
                return result;
            }

            // Register ALL generated C files so NdkBuilder compiles every one:
            //   classes_native_functions.c  — method bodies as vmCode[] structs
            //   classes_resolver.c          — RegisterNatives table
            //   jni_init.c                  — JNI_OnLoad that calls each *_setup()
            // We glob the whole vmpOutDir rather than hardcoding names so multi-DEX
            // APKs (classes.dex + classes2.dex → two native_functions files) all land.
            // Glob all generated source files (.c and .cpp — jni_init is now .cpp)
            // and headers (.h) from vmpOutDir into outputDir (= cSourceDir).
            File[] srcFiles = vmpOutDir.listFiles(f -> {
                String n = f.getName();
                return n.endsWith(".c") || n.endsWith(".cpp") || n.endsWith(".h");
            });
            if (srcFiles != null) {
                for (File sf : srcFiles) {
                    File dest = new File(outputDir, sf.getName());
                    Files.copy(sf.toPath(), dest.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                    if (sf.getName().endsWith(".h")) {
                        Log.d(TAG, "VMP header copied: " + sf.getName());
                    } else {
                        result.compiled.put("vmp_" + sf.getName(), dest.getAbsolutePath());
                        Log.d(TAG, "VMP source registered: " + sf.getName());
                    }
                }
            }

            progress(cb, "VMP: done — " + result.compiled.size() + " C file(s) registered.");
        } catch (Exception e) {
            Log.e(TAG, "VMP transpile failed", e);
            result.errors.add("VMP error: " + e.getMessage());
        }
        return result;
    }

    // ── Path 3: HYBRID (VMP selected classes + dex2c the rest) ──────────────

    private TranspileResult transpileHybrid(String apkPath, String filterText,
                                            File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile(HYBRID) apk=" + apkPath);

        // Split filterText: lines starting with "vmp:" → VMP, rest → dex2c
        StringBuilder vmpFilter   = new StringBuilder();
        StringBuilder dex2cFilter = new StringBuilder();
        for (String line : filterText.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("vmp:")) {
                vmpFilter.append(trimmed.substring(4).trim()).append("\n");
            } else if (!trimmed.isEmpty()) {
                dex2cFilter.append(trimmed).append("\n");
            }
        }

        TranspileResult combined = new TranspileResult();

        // Run VMP leg
        if (vmpFilter.length() > 0) {
            progress(cb, "HYBRID: running VMP leg…");
            TranspileResult vmpResult = transpileVmp(
                    apkPath, vmpFilter.toString(), outputDir, cb);
            combined.compiled.putAll(vmpResult.compiled);
            combined.errors.addAll(vmpResult.errors);
            combined.vmpConfig = vmpResult.vmpConfig;
        }

        // Run dex2c leg
        if (dex2cFilter.length() > 0) {
            progress(cb, "HYBRID: running dex2c leg…");
            TranspileResult d2cResult = transpileDex2c(
                    apkPath, dex2cFilter.toString(), outputDir, cb);
            combined.compiled.putAll(d2cResult.compiled);
            combined.errors.addAll(d2cResult.errors);
        }

        return combined;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Extract all classes*.dex files from the APK into a temp dir and return
     * their File handles in order (classes.dex, classes2.dex, …).
     */
    private List<File> extractDexFiles(String apkPath, File baseDir) throws IOException {
        File dexDir = new File(baseDir, "extracted_dex");
        if (!dexDir.exists()) dexDir.mkdirs();

        List<File> dexFiles = new ArrayList<>();
        byte[] buf = new byte[65536];

        try (ZipInputStream zis = new ZipInputStream(
                new BufferedInputStream(new FileInputStream(apkPath)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name.matches("classes\\d*\\.dex")) {
                    File out = new File(dexDir, name);
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        int n;
                        while ((n = zis.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    dexFiles.add(out);
                    Log.d(TAG, "Extracted " + name + " (" + out.length() + " bytes)");
                }
            }
        }
        // Sort: classes.dex < classes2.dex < classes3.dex …
        dexFiles.sort((a, b) -> {
            int na = dexIndex(a.getName());
            int nb = dexIndex(b.getName());
            return Integer.compare(na, nb);
        });
        return dexFiles;
    }

    private static int dexIndex(String name) {
        // "classes.dex" → 1, "classes2.dex" → 2, etc.
        String num = name.replace("classes", "").replace(".dex", "");
        return num.isEmpty() ? 1 : Integer.parseInt(num);
    }

    /**
     * Result of buildClassAnalyzerWithCache(): the ClassAnalyzer for hierarchy
     * resolution PLUS a map of every parsed DexBackedDexFile keyed by filename.
     *
     * The map lets handleAllDex() (fix #1) pass already-parsed files straight
     * into splitDex() instead of calling DexBackedDexFile.fromInputStream() a
     * second time for every hot DEX.
     */
    private static final class ClassAnalyzerResult {
        final ClassAnalyzer analyzer;
        final Map<String, DexBackedDexFile> parsedFiles;   // filename → parsed DEX

        ClassAnalyzerResult(ClassAnalyzer a, Map<String, DexBackedDexFile> p) {
            analyzer    = a;
            parsedFiles = p;
        }
    }

    /**
     * Build a ClassAnalyzer across all DEX files and simultaneously cache each
     * parsed DexBackedDexFile so hot DEX files are not parsed a second time
     * during splitDex() (fix #1: avoids double fromInputStream() per hot DEX).
     */
    private ClassAnalyzerResult buildClassAnalyzerWithCache(List<File> dexFiles) throws IOException {
        ClassAnalyzer analyzer = new ClassAnalyzer();
        Map<String, DexBackedDexFile> cache = new LinkedHashMap<>();
        for (File f : dexFiles) {
            DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                    null,
                    new BufferedInputStream(new FileInputStream(f)));
            analyzer.loadDexFile(dexFile);
            cache.put(f.getName(), dexFile);
        }
        return new ClassAnalyzerResult(analyzer, cache);
    }

    /**
     * Build a ClassAndMethodFilter from the user-supplied filter text.
     *
     * Supports:
     *   1. NMMP SimpleRules format  : "class com.foo.Bar { *; }"
     *   2. Dot-notation class name  : "com.example.MyClass"
     *   3. Smali whole-class        : "Lcom/example/MyClass;"
     *   4. Smali method entry       : "Lcom/example/MyClass;->foo()V"
     *
     * For (4), the specific method name is preserved in the SimpleRule so only
     * that method gets VMP'd — not the entire class.
     * Multiple method entries for the same class are merged into one rule block.
     */
    private ClassAndMethodFilter buildFilter(String filterText,
                                             ClassAnalyzer classAnalyzer) throws IOException {
        String rulesText = filterText;
        if (!filterText.contains("class ")) {
            // Collect whole-class entries and per-method entries independently.
            // Nothing supersedes — both manual tree and class-paste are fully honoured.
            // If the same class appears as whole AND with specific methods, SimpleRules
            // stores both MethodRules under the same ClassRule key; { *; } then matches
            // any method so all methods get VMP'd — correct behaviour.
            java.util.LinkedHashSet<String> classEntries = new java.util.LinkedHashSet<>();
            java.util.LinkedHashMap<String, java.util.LinkedHashSet<String>> methodEntries =
                    new java.util.LinkedHashMap<>();

            for (String line : filterText.split("\\r?\\n")) {
                String entry = line.trim();
                if (entry.isEmpty() || entry.startsWith("#")) continue;

                if (entry.contains("(")) {
                    // Method-level entry — two formats produced by the UI tree:
                    //
                    //   Format A (smali with arrow):
                    //     "Lcom/foo/Bar;->onCreate(Landroid/os/Bundle;)V"
                    //
                    //   Format B (MethodNode.fullPattern — NO "->"):
                    //     "com/foo/Bar;onCreate(Landroid/os/Bundle;)V"
                    //       ↑ classPrefix = typeDesc.substring(1) = "com/foo/Bar;"
                    //         method name immediately follows the last ";" before "("
                    //
                    // Detect which format and split accordingly.
                    String smaliClass, rest;
                    int arrow = entry.indexOf("->");
                    if (arrow >= 0) {
                        // Format A
                        smaliClass = entry.substring(0, arrow);
                        rest       = entry.substring(arrow + 2);
                    } else {
                        // Format B: split at the last ";" that precedes the "("
                        int paren    = entry.indexOf('(');
                        int lastSemi = entry.lastIndexOf(';', paren);
                        if (lastSemi < 0) {
                            // No ";" before "(" — cannot identify class, skip
                            continue;
                        }
                        smaliClass = entry.substring(0, lastSemi + 1); // "com/foo/Bar;"
                        rest       = entry.substring(lastSemi + 1);    // "onCreate(...)V"
                    }

                    int paren = rest.indexOf('(');
                    String methodName = paren > 0 ? rest.substring(0, paren) : rest;
                    if ("<init>".equals(methodName) || "<clinit>".equals(methodName)) continue;

                    // Normalise all class identifier formats → dot notation for SimpleRules:
                    //   "Lcom/foo/Bar;"  (smali full)          → "com.foo.Bar"
                    //   "com/foo/Bar;"   (fullPattern prefix)   → "com.foo.Bar"
                    //   "com/foo/Bar"    (slash, no semi)       → "com.foo.Bar"
                    //   "com.foo.Bar"    (already dot)          → "com.foo.Bar"
                    String dotClass;
                    if (smaliClass.startsWith("L") && smaliClass.endsWith(";")) {
                        dotClass = smaliClass.substring(1, smaliClass.length() - 1).replace('/', '.');
                    } else if (smaliClass.endsWith(";")) {
                        dotClass = smaliClass.substring(0, smaliClass.length() - 1).replace('/', '.');
                    } else {
                        dotClass = smaliClass.replace('/', '.');
                    }
                    if (!dotClass.isEmpty()) {
                        methodEntries.computeIfAbsent(dotClass,
                                k -> new java.util.LinkedHashSet<>()).add(methodName);
                    }
                } else {
                    // Whole-class entry — normalise all formats → dot notation:
                    //   "Lcom/foo/Bar;"  → "com.foo.Bar"
                    //   "com/foo/Bar;"   → "com.foo.Bar"
                    //   "com/foo/Bar"    → "com.foo.Bar"
                    //   "com.foo.Bar"    → "com.foo.Bar" (already correct)
                    String cls = entry;
                    if (cls.startsWith("L") && cls.endsWith(";")) {
                        cls = cls.substring(1, cls.length() - 1).replace('/', '.');
                    } else if (cls.endsWith(";")) {
                        cls = cls.substring(0, cls.length() - 1).replace('/', '.');
                    } else {
                        cls = cls.replace('/', '.');
                    }
                    if (!cls.isEmpty()) classEntries.add(cls);
                }
            }

            // Build SimpleRules text — whole-class first, then per-method
            StringBuilder sb = new StringBuilder();
            for (String cls : classEntries) {
                sb.append("class ").append(cls).append(" { *; }\n");
            }
            for (java.util.Map.Entry<String, java.util.LinkedHashSet<String>> e
                    : methodEntries.entrySet()) {
                sb.append("class ").append(e.getKey()).append(" {\n");
                for (String m : e.getValue()) sb.append("    ").append(m).append(";\n");
                sb.append("}\n");
            }
            rulesText = sb.toString();
        }

        SimpleRules rules = new SimpleRules();
        rules.parse(new StringReader(rulesText));

        // BasicKeepConfig skips constructors + static-initializers
        // (ART verifier cannot handle VMP'd <init> / <clinit>)
        BasicKeepConfig keepConfig = new BasicKeepConfig();

        return new SimpleConvertConfig(keepConfig, rules);
    }

    /**
     * Generate a per-run DexOpcodes.h by reading the static template from assets and
     * patching the enum body + goto-table body with the current rewriter's opcode map.
     *
     * This replicates NMMP's CmakeUtils.writeOpcodeHeaderFile() which NMMP runs at
     * protection time before passing source files to cmake/ndk-build. Without this step
     * the VM runtime is compiled with the standard (identity) opcode ordering but the
     * protected bytecode uses the randomized ordering → every opcode dispatches to the
     * wrong handler in vmInterpret → deterministic SIGSEGV.
     *
     * Note on double-backslash in generateConfig() output: the gotoTableWriter receives
     * lines ending with "\\\n" (two chars: backslash + newline). When those lines are
     * used as a String.replaceAll() replacement string, each "\\" becomes a literal
     * single "\" in the output — which is exactly the C macro line-continuation syntax.
     */
    private void generateDexOpcodesHeader(
            com.ultra.dex2cvmp.engine.vmp.converter.instructionrewriter.InstructionRewriter rewriter,
            File dest) throws IOException {
        // Read the static DexOpcodes.h template from assets
        String template;
        try (InputStream is = context.getAssets().open("vmp_headers/DexOpcodes.h");
             java.util.Scanner sc = new java.util.Scanner(is, "UTF-8").useDelimiter("\\A")) {
            template = sc.hasNext() ? sc.next() : "";
        }

        // Generate randomized enum body and goto-table body
        StringWriter enumW = new StringWriter();
        StringWriter gotoW = new StringWriter();
        rewriter.generateConfig(enumW, gotoW);

        // Replace enum body:  "enum Opcode { … };" → new enum with shuffled values
        Pattern enumPat = Pattern.compile(
                "enum Opcode \\{.*?\\};",
                Pattern.MULTILINE | Pattern.DOTALL);
        String result = enumPat.matcher(template)
                .replaceAll(String.format("enum Opcode {\n%s};", enumW));

        // Replace goto-table body:  "_name[kNumPackedOpcodes] = { … };" → new table
        Pattern gotoPat = Pattern.compile(
                "_name\\[kNumPackedOpcodes\\] = \\{.*?\\};",
                Pattern.MULTILINE | Pattern.DOTALL);
        result = gotoPat.matcher(result)
                .replaceAll(String.format(
                        "_name[kNumPackedOpcodes] = {        \\\\\n%s};", gotoW));

        try (FileWriter fw = new FileWriter(dest)) {
            fw.write(result);
        }
    }

    /**
     * Extract smali class descriptors (e.g. "Lcom/foo/Bar;") from filter text
     * without building a full ClassAndMethodFilter.  Used by filterHotDexFiles
     * to identify target classes before committing to a full DEX parse.
     *
     * Handles all four filter formats:
     *   1. NMMP SimpleRules  : "class com.foo.Bar { *; }"
     *   2. Dot-notation      : "com.example.MyClass"
     *   3. Smali whole-class : "Lcom/example/MyClass;"
     *   4. Smali method      : "Lcom/example/MyClass;->foo()V"
     */
    private static Set<String> parseTargetDescriptors(String filterText) {
        Set<String> descriptors = new HashSet<>();
        for (String line : filterText.split("\\r?\\n")) {
            String entry = line.trim();
            if (entry.isEmpty() || entry.startsWith("#")) continue;

            String cls = null;
            if (entry.startsWith("class ")) {
                // SimpleRules: "class com.foo.Bar { ... }"
                String body = entry.substring(6).trim();
                int brace = body.indexOf('{');
                cls = (brace > 0 ? body.substring(0, brace) : body).trim();
                // dot → smali
                cls = 'L' + cls.replace('.', '/') + ';';
            } else {
                // Strip method part if present
                int arrow = entry.indexOf("->");
                String clsPart = arrow >= 0 ? entry.substring(0, arrow) : entry;

                // Strip trailing semicolon ambiguity from method entries without arrow:
                // "com/foo/Bar;methodName(I)V" — split at first ";" before "("
                if (arrow < 0 && clsPart.contains("(")) {
                    int paren = clsPart.indexOf('(');
                    int semi  = clsPart.lastIndexOf(';', paren);
                    if (semi >= 0) clsPart = clsPart.substring(0, semi + 1);
                }

                // Normalise → "Lcom/foo/Bar;"
                if (clsPart.startsWith("L") && clsPart.endsWith(";")) {
                    cls = clsPart;                             // already smali
                } else if (clsPart.endsWith(";")) {
                    cls = 'L' + clsPart;                      // "com/foo/Bar;" → add L
                } else {
                    cls = 'L' + clsPart.replace('.', '/') + ';'; // dot or slash, no semi
                }
            }
            if (cls != null && cls.length() > 2) descriptors.add(cls);
        }
        return descriptors;
    }

    /**
     * Binary-search the DEX type_ids table to identify which DEX files contain
     * at least one of the target class descriptors.
     *
     * The DEX spec guarantees type_ids is sorted lexicographically, so we can
     * binary-search each target descriptor directly from the raw file bytes —
     * no dexlib2 object model, no class_defs sequential scan, no bytecode loaded.
     *
     *   Current linear scan : up to N comparisons per DEX (e.g. 9 000 for classes.dex)
     *   Binary search        : ⌈log₂ N⌉ comparisons per target  (~13 for 9 000 classes)
     *
     * For a 15-DEX app where the user's classes live in 2 DEX files:
     *   Old: handleAllDex processes all 15 → splitDex + C gen × 15
     *   New: handleAllDex processes 2 hot files only → splitDex + C gen × 2
     *        Cold 13 DEX files stay in dexDir untouched → ApkRebuilder includes them as-is
     *
     * If the binary search throws (corrupt header, unknown format), the DEX is
     * included conservatively so no target class is ever silently missed.
     *
     * @param dexFiles          all extracted DEX files
     * @param targetDescriptors smali descriptors e.g. "Lcom/foo/Bar;"
     * @param cb                progress callback (may be null)
     * @return subset of dexFiles that contain at least one target class
     */
    private List<File> filterHotDexFiles(List<File> dexFiles,
                                          Set<String> targetDescriptors,
                                          TranspileCallback cb) {
        if (targetDescriptors.isEmpty() || dexFiles.size() <= 1) return dexFiles;

        // Split into:
        //   qualified   — "Lsome/pkg/Foo;"   → binary search works (exact match)
        //   unqualified — "LBareClassName;"   → no package, binary search cannot find it;
        //                                       use linear suffix scan instead.
        Set<String> qualified   = new HashSet<>();
        Set<String> unqualified = new HashSet<>();
        for (String d : targetDescriptors) {
            if (d.indexOf('/') >= 0) qualified.add(d);
            else                     unqualified.add(d);
        }

        progress(cb, "VMP: building class→DEX index ("
                + dexFiles.size() + " DEX, no bytecode)…");

        List<File> hot = new ArrayList<>();
        for (File dexFile : dexFiles) {
            try {
                boolean isHot = dexContainsAny(dexFile, qualified, unqualified);
                if (isHot) {
                    hot.add(dexFile);
                    Log.d(TAG, "VMP hot DEX: " + dexFile.getName());
                } else {
                    Log.d(TAG, "VMP cold DEX (skipped): " + dexFile.getName());
                }
            } catch (Exception e) {
                // Binary search failed — include conservatively so no class is missed.
                Log.w(TAG, "VMP DEX binary-search failed for " + dexFile.getName()
                        + " — including as hot to be safe: " + e.getMessage());
                hot.add(dexFile);
            }
        }
        return hot;
    }

    // ── Raw DEX binary-search helpers ────────────────────────────────────────

    /**
     * Returns true if any descriptor in {@code targets} exists in {@code dexFile},
     * using a binary search on the raw type_ids table for qualified descriptors,
     * and a linear suffix scan for bare (no-package) class names.
     *
     * DEX header layout (all little-endian uint32, relevant fields):
     *   offset 56 : string_ids_size
     *   offset 60 : string_ids_off  → uint32[] where each entry is an offset to string_data
     *   offset 64 : type_ids_size
     *   offset 68 : type_ids_off    → uint32[] of string_ids indices, SORTED lexicographically
     *
     * string_data format at string_ids[i]:  ULEB128 utf16_size · MUTF-8 bytes · 0x00
     */
    private static boolean dexContainsAny(File dexFile,
                                           Set<String> qualified,
                                           Set<String> unqualified) throws IOException {
        try (java.io.RandomAccessFile raf =
                     new java.io.RandomAccessFile(dexFile, "r")) {

            raf.seek(60);
            int stringIdsOff = readIntLE(raf);   // offset 60
            int typeIdsSize  = readIntLE(raf);   // offset 64
            int typeIdsOff   = readIntLE(raf);   // offset 68

            if (typeIdsSize <= 0) return false;

            // ── Binary-search fully-qualified descriptors (e.g. "Lcom/foo/Bar;") ──
            for (String target : qualified) {
                if (binarySearchType(raf, target, typeIdsOff, typeIdsSize, stringIdsOff)) {
                    return true;
                }
            }

            // ── Linear suffix scan for bare class names (e.g. "LBffSubjectInfo;") ──
            // A bare name has no '/' so its real descriptor could be
            // "Lany/package/BffSubjectInfo;" — we can't binary-search that.
            // We read every type string once and check whether it ends with
            // the bare-name suffix (e.g. "/BffSubjectInfo;" or "LBffSubjectInfo;").
            if (!unqualified.isEmpty()) {
                for (int i = 0; i < typeIdsSize; i++) {
                    String typeStr = readDexTypeString(raf, typeIdsOff, i, stringIdsOff);
                    for (String bare : unqualified) {
                        // Match "Lsome/pkg/Foo;" via suffix "/Foo;" OR exact "LFoo;"
                        String simpleName = bare.substring(1); // strip leading 'L' → "Foo;"
                        if (typeStr.endsWith("/" + simpleName) || typeStr.equals(bare)) {
                            return true;
                        }
                    }
                }
            }

            return false;
        }
    }

    /**
     * Standard binary search over the sorted type_ids array.
     * Each entry is a uint32 index into string_ids; we follow it to the
     * actual descriptor string and compare with {@code target}.
     */
    private static boolean binarySearchType(java.io.RandomAccessFile raf,
                                             String target,
                                             int typeIdsOff, int typeIdsSize,
                                             int stringIdsOff) throws IOException {
        int lo = 0, hi = typeIdsSize - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            String typeStr = readDexTypeString(raf, typeIdsOff, mid, stringIdsOff);
            int cmp = typeStr.compareTo(target);
            if (cmp == 0) return true;
            if (cmp < 0)  lo = mid + 1;
            else           hi = mid - 1;
        }
        return false;
    }

    /**
     * Reads the type descriptor string at position {@code index} in type_ids.
     *
     * Chain: type_ids[index] → string_id_index
     *        string_ids[string_id_index] → string_data_offset
     *        string_data_offset: ULEB128 utf16_size · MUTF-8 · 0x00
     *
     * Class descriptors are always ASCII (e.g. "Lcom/foo/Bar;"), so
     * reading bytes until 0x00 is correct and safe — no multi-byte MUTF-8
     * sequences appear in descriptor strings.
     */
    private static String readDexTypeString(java.io.RandomAccessFile raf,
                                             int typeIdsOff, int index,
                                             int stringIdsOff) throws IOException {
        // 1. type_ids[index] → string_id index (4 bytes each)
        raf.seek(typeIdsOff + (long) index * 4);
        int stringIdx = readIntLE(raf);

        // 2. string_ids[stringIdx] → offset of string_data (4 bytes each)
        raf.seek(stringIdsOff + (long) stringIdx * 4);
        int stringDataOff = readIntLE(raf);

        // 3. string_data: skip ULEB128 utf16_size, then read MUTF-8 until 0x00
        raf.seek(stringDataOff);
        readUleb128(raf);   // discard utf16 length — we read until the null terminator

        StringBuilder sb = new StringBuilder(64);
        int b;
        while ((b = raf.read()) > 0) {   // 0x00 = terminator, -1 = EOF
            sb.append((char) b);
        }
        return sb.toString();
    }

    /** Reads a 4-byte little-endian unsigned int from {@code raf}. */
    private static int readIntLE(java.io.RandomAccessFile raf) throws IOException {
        int b0 = raf.read(), b1 = raf.read(),
            b2 = raf.read(), b3 = raf.read();
        return (b0 & 0xFF)
             | ((b1 & 0xFF) <<  8)
             | ((b2 & 0xFF) << 16)
             | ((b3 & 0xFF) << 24);
    }

    /** Reads and discards a ULEB128-encoded integer from {@code raf}. */
    private static void readUleb128(java.io.RandomAccessFile raf) throws IOException {
        int b;
        do { b = raf.read(); } while ((b & 0x80) != 0 && b != -1);
    }

    private static void progress(TranspileCallback cb, String msg) {
        Log.i(TAG, msg);
        if (cb != null) cb.onProgress(msg);
    }
}
