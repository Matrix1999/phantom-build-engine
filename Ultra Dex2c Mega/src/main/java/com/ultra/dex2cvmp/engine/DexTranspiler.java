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
        public final Set<String> requestedVmpMethodKeys = new LinkedHashSet<>();
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
        return transpile(apkPath, filterText, outputDir, mode, cb, null, null);
    }

    /**
     * Overload that accepts extra DEX files for the VMP transpiler.
     * Avoids APK zip rewriting (which strips STORED compression from .so entries
     * and breaks native lib loading) by injecting extra classes at the Java level.
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, int mode,
                                     TranspileCallback cb,
                                     List<File> extraDex) {
        return transpile(apkPath, filterText, outputDir, mode, cb, null, extraDex);
    }

    /**
     * Transpile using a caller-owned DEX workspace.  The workspace is shared by
     * APK extraction, both transpilers, and the final patcher so the APK is
     * unzipped only once.
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, int mode,
                                     TranspileCallback cb,
                                     List<File> sharedDexFiles,
                                     List<File> extraDex) {
        switch (mode) {
            case MODE_VMP:
                return transpileVmp(apkPath, filterText, outputDir, cb,
                        sharedDexFiles, extraDex);
            case MODE_HYBRID:
                return transpileHybrid(apkPath, filterText, outputDir, cb,
                        sharedDexFiles, extraDex);
            default:
                return transpileDex2c(apkPath, filterText, outputDir, cb, sharedDexFiles);
        }
    }

    /**
     * Legacy overload — defaults to MODE_DEX2C (backwards-compatible).
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, TranspileCallback cb) {
        return transpileDex2c(apkPath, filterText, outputDir, cb, null);
    }

    // ── Path 1: existing Python dex2c (unchanged) ────────────────────────────

    private TranspileResult transpileDex2c(String apkPath, String filterText,
                                           File outputDir, TranspileCallback cb,
                                           List<File> sharedDexFiles) {
        Log.i(TAG, "transpile(DEX2C) apk=" + apkPath);
        Dex2cPythonBridge bridge = new Dex2cPythonBridge(context);
        if (!bridge.isAvailable()) {
            TranspileResult r = new TranspileResult();
            r.errors.add("Python runtime not available — check storage and try again.");
            return r;
        }
        return bridge.transpile(apkPath, filterText, outputDir, cb, sharedDexFiles);
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
        return transpileVmp(apkPath, filterText, outputDir, cb, null, null);
    }

    private TranspileResult transpileVmp(String apkPath, String filterText,
                                         File outputDir, TranspileCallback cb,
                                         List<File> sharedDexFiles,
                                         List<File> extraDex) {
        Log.i(TAG, "transpile(VMP) apk=" + apkPath);
        TranspileResult result = new TranspileResult();
        try {
            List<File> dexFiles;
            if (sharedDexFiles != null && !sharedDexFiles.isEmpty()) {
                progress(cb, "VMP: using shared DEX workspace…");
                dexFiles = new ArrayList<>(sharedDexFiles);
            } else {
                progress(cb, "VMP: extracting DEX files from APK…");
                dexFiles = extractDexFiles(apkPath, outputDir);
            }
            // Inject extra DEX files (e.g. gate class) without modifying the APK zip.
            // APK zip rewriting strips STORED compression from .so entries → lib load fails.
            if (extraDex != null) {
                for (File f : extraDex) {
                    if (f != null && f.exists() && !dexFiles.contains(f)) dexFiles.add(f);
                }
            }
            if (dexFiles.isEmpty()) {
                result.errors.add("VMP: no DEX files found in " + apkPath);
                return result;
            }
            // ── Smart DEX targeting ─────────────────────────────────────────
            // Stage 1 deliberately happens before constructing any dexlib2
            // objects.  The raw class_defs lookup is cheap and prevents cold DEX
            // files from entering the method-conversion path.
            Set<String> targetDescriptors = parseTargetDescriptors(filterText);
            // VMP must locate DEXes by classes they DEFINE, not merely by types
            // they reference.  A referenced type can appear in many unrelated
            // DEX files and would otherwise make every DEX look hot.
            List<File> hotDexFiles = filterVmpHotDexFiles(dexFiles, targetDescriptors, cb);
            if (hotDexFiles.isEmpty()) {
                // Fallback: target classes not found in index — process all DEX files
                Log.w(TAG, "VMP smart targeting: no matches found, falling back to full scan");
                hotDexFiles = dexFiles;
            } else {
                progress(cb, "VMP: smart targeting — " + hotDexFiles.size()
                        + " hot / " + (dexFiles.size() - hotDexFiles.size())
                        + " cold DEX files"
                        + (hotDexFiles.size() < dexFiles.size() ? " (cold skipped)" : ""));
            }

            progress(cb, "VMP: parsing class metadata for method resolution…");
            // Stage 2 keeps class metadata from every DEX because virtual
            // dispatch, superclass lookup, and interface static-field rewrites
            // can cross DEX boundaries.  ClassAnalyzer.loadDexFile() only
            // indexes class/method/field metadata; it does not call
            // Method.getImplementation(), so cold DEX method bodies remain
            // lazy.  Only hot DEX objects are retained in parsedFiles and
            // handed to handleAllDex for conversion.
            ClassAnalyzerResult analyzerResult =
                    buildClassAnalyzerWithCache(dexFiles, hotDexFiles);
            ClassAnalyzer classAnalyzer = analyzerResult.analyzer;

            progress(cb, "VMP: building filter rules…");
            ClassAndMethodFilter filter = buildFilter(filterText, classAnalyzer);
            result.requestedVmpMethodKeys.addAll(parseExactMethodKeys(filterText));

            // Random opcode map — different every protect run
            RandomInstructionRewriter rewriter = new RandomInstructionRewriter();

            progress(cb, "VMP: converting methods → custom opcodes + C stubs…");
            // Write VMP output straight into the final compiler source directory.
            // The previous vmp/ staging folder required copying every generated
            // source and header before compilation.
            File vmpOutDir = outputDir;
            if (!vmpOutDir.exists() && !vmpOutDir.mkdirs()) {
                throw new IOException("Unable to create VMP output directory.");
            }

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
            // and headers (.h) directly from the final compiler directory.
            File[] srcFiles = vmpOutDir.listFiles(f -> {
                String n = f.getName();
                return n.endsWith(".c") || n.endsWith(".cpp") || n.endsWith(".h");
            });
            if (srcFiles != null) {
                for (File sf : srcFiles) {
                    if (sf.getName().endsWith(".h")) {
                        Log.d(TAG, "VMP header ready: " + sf.getName());
                    } else {
                        result.compiled.put("vmp_" + sf.getName(), sf.getAbsolutePath());
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
        return transpileHybrid(apkPath, filterText, outputDir, cb, null, null);
    }

    /**
     * Hybrid mode accepts supplemental DEX files for its VMP leg. This lets a
     * build keep user-selected application code on DEX2C while routing a
     * synthetic security gate through VMP without rewriting the input APK ZIP.
     */
    private TranspileResult transpileHybrid(String apkPath, String filterText,
                                             File outputDir, TranspileCallback cb,
                                            List<File> sharedDexFiles,
                                            List<File> vmpExtraDex) {
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
                    apkPath, vmpFilter.toString(), outputDir, cb,
                    sharedDexFiles, vmpExtraDex);
            combined.compiled.putAll(vmpResult.compiled);
            combined.errors.addAll(vmpResult.errors);
            combined.vmpConfig = vmpResult.vmpConfig;
        }

        // Run dex2c leg
        if (dex2cFilter.length() > 0) {
            progress(cb, "HYBRID: running dex2c leg…");
            TranspileResult d2cResult = transpileDex2c(
                    apkPath, dex2cFilter.toString(), outputDir, cb, sharedDexFiles);
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

    /**
     * Locate the DEX files that contain the selected classes without creating
     * dexlib2 or Python parser objects.  DEX2C uses this before invoking Python
     * so it receives only relevant files from the shared workspace.
     */
    static List<File> selectDexFilesForFilter(List<File> dexFiles, String filterText) {
        if (dexFiles == null || dexFiles.isEmpty()) return Collections.emptyList();

        Set<String> targetDescriptors = parseTargetDescriptors(filterText);
        List<File> hotDexFiles = filterHotDexFiles(dexFiles, targetDescriptors, null);
        // A malformed or unrecognised rule must never make DEX2C silently skip
        // user code.  Preserve the original conservative all-DEX fallback.
        return hotDexFiles.isEmpty() ? new ArrayList<>(dexFiles) : hotDexFiles;
    }

    private static int dexIndex(String name) {
        // "classes.dex" → 1, "classes2.dex" → 2, etc.
        String num = name.replace("classes", "").replace(".dex", "");
        return num.isEmpty() ? 1 : Integer.parseInt(num);
    }

    /**
     * Result of buildClassAnalyzerWithCache(): the ClassAnalyzer for hierarchy
     * resolution PLUS a map of the hot parsed DexBackedDexFile objects keyed by
     * filename.
     *
     * Cold DEX files still contribute their class metadata to the analyzer, but
     * are not retained for method conversion.  This keeps the conversion cache
     * proportional to the selected DEX set.
     */
    private static final class ClassAnalyzerResult {
        final ClassAnalyzer analyzer;
        final Map<String, DexBackedDexFile> parsedFiles;   // hot filename → parsed DEX

        ClassAnalyzerResult(ClassAnalyzer a, Map<String, DexBackedDexFile> p) {
            analyzer    = a;
            parsedFiles = p;
        }
    }

    /**
     * Build a ClassAnalyzer across all DEX files while caching only hot DEX
     * objects for splitDex().
     *
     * ClassAnalyzer indexes class definitions, method signatures, and fields
     * without asking methods for their implementations.  That distinction is
     * important here: cold DEX files remain available for hierarchy and method
     * resolution, but their bytecode is not loaded as part of the metadata pass.
     * Hot DEX files are parsed once and reused by handleAllDex().
     */
    private ClassAnalyzerResult buildClassAnalyzerWithCache(List<File> dexFiles,
                                                            List<File> hotDexFiles)
            throws IOException {
        ClassAnalyzer analyzer = new ClassAnalyzer();
        Map<String, DexBackedDexFile> cache = new LinkedHashMap<>();
        Set<String> hotNames = new HashSet<>();
        for (File hotDexFile : hotDexFiles) {
            hotNames.add(hotDexFile.getName());
        }

        for (File f : dexFiles) {
            // dexlib2 keeps method implementations lazy.  Loading a cold file
            // here is therefore a metadata-only contribution to the analyzer;
            // do not put it in the conversion cache.
            DexBackedDexFile dexFile;
            try (BufferedInputStream input =
                         new BufferedInputStream(new FileInputStream(f))) {
                dexFile = DexBackedDexFile.fromInputStream(null, input);
            }
            analyzer.loadDexFile(dexFile);
            if (hotNames.contains(f.getName())) {
                cache.put(f.getName(), dexFile);
            }
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
        // Always normalise line-by-line so mixed filter text (some "class ..." lines
        // already in SimpleRules format, some bare class names / smali descriptors)
        // works correctly.  "class ..." lines are passed through verbatim; everything
        // else is wrapped.  This was previously an all-or-nothing guard
        // (!filterText.contains("class ")) which broke as soon as any "class " line
        // was present (e.g. the injected gate class rule) while user lines were bare.
        java.util.LinkedHashSet<String> classEntries = new java.util.LinkedHashSet<>();
        java.util.LinkedHashMap<String, java.util.LinkedHashSet<String>> methodEntries =
                new java.util.LinkedHashMap<>();
        // Already-formatted SimpleRules lines ("class X { ... }") are collected
        // separately and emitted as-is at the end.
        StringBuilder passthroughRules = new StringBuilder();

        // State machine for multi-line "class X {\n  m;\n}" blocks in the input.
        boolean inPassthroughBlock = false;

        for (String line : filterText.split("\\r?\\n")) {
            String entry = line.trim();

            // Pass through already-formatted SimpleRules lines unchanged.
            if (inPassthroughBlock) {
                passthroughRules.append(line).append("\n");
                if (entry.contains("}")) inPassthroughBlock = false;
                continue;
            }
            if (entry.startsWith("class ")) {
                passthroughRules.append(line).append("\n");
                // If the opening brace has no closing brace on the same line → multi-line block
                if (entry.contains("{") && !entry.contains("}")) inPassthroughBlock = true;
                continue;
            }

            if (entry.isEmpty() || entry.startsWith("#")) continue;

            if (entry.contains("(")) {
                // Method-level entry — two formats produced by the UI tree:
                //   Format A (smali with arrow):  "Lcom/foo/Bar;->onCreate(Landroid/os/Bundle;)V"
                //   Format B (MethodNode.fullPattern — NO "->"):
                //     "com/foo/Bar;onCreate(Landroid/os/Bundle;)V"
                String smaliClass, rest;
                int arrow = entry.indexOf("->");
                if (arrow >= 0) {
                    smaliClass = entry.substring(0, arrow);
                    rest       = entry.substring(arrow + 2);
                } else {
                    int paren    = entry.indexOf('(');
                    int lastSemi = entry.lastIndexOf(';', paren);
                    if (lastSemi < 0) continue; // cannot identify class
                    smaliClass = entry.substring(0, lastSemi + 1);
                    rest       = entry.substring(lastSemi + 1);
                }

                int paren = rest.indexOf('(');
                String methodName = paren > 0 ? rest.substring(0, paren) : rest;
                if ("<init>".equals(methodName) || "<clinit>".equals(methodName)) continue;

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
                            k -> new java.util.LinkedHashSet<>()).add(rest);
                }
            } else {
                // Whole-class entry — normalise all formats → dot notation.
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

        // Build final SimpleRules text:
        //   1. Whole-class entries (bare / smali → normalised)
        //   2. Per-method entries  (bare / smali → normalised)
        //   3. Already-formatted passthrough lines (gate rule, etc.)
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
        sb.append(passthroughRules);
        String rulesText = sb.toString();

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
        boolean inSimpleRulesBlock = false;
        for (String line : filterText.split("\\r?\\n")) {
            String entry = line.trim();
            if (entry.isEmpty() || entry.startsWith("#")) continue;

            if (inSimpleRulesBlock) {
                if (entry.contains("}")) inSimpleRulesBlock = false;
                continue;
            }

            String cls = null;
            if (entry.startsWith("class ")) {
                // SimpleRules: "class com.foo.Bar { ... }"
                String body = entry.substring(6).trim();
                int brace = body.indexOf('{');
                cls = (brace > 0 ? body.substring(0, brace) : body).trim();
                // dot → smali
                cls = 'L' + cls.replace('.', '/') + ';';
                if (!entry.contains("}")) inSimpleRulesBlock = true;
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
     * Validate user-selected class owners against the classes actually defined
     * by the input DEX files. This is intentionally shared by DEX2C and VMP at
     * the APK entry point, before either converter can generate C/C++.
     *
     * @throws IOException if a DEX cannot be inspected
     * @throws IllegalArgumentException if an exact selected class is missing
     */
    public static void validateSelectedClasses(List<File> dexFiles,
                                               String filterText,
                                               TranspileCallback cb) throws IOException {
        Set<String> targets = parseTargetDescriptors(filterText);
        if (targets.isEmpty()) return;

        Set<String> qualified = new LinkedHashSet<>();
        Set<String> unqualified = new LinkedHashSet<>();
        for (String target : targets) {
            if (target.indexOf('*') >= 0 || target.indexOf('?') >= 0
                    || target.indexOf('!') >= 0) {
                // Wildcard/exclusion rules are valid rules, not exact class
                // selections. They cannot be validated as one class name.
                continue;
            }
            if (target.indexOf('/') >= 0) qualified.add(target);
            else unqualified.add(target);
        }
        if (qualified.isEmpty() && unqualified.isEmpty()) return;

        progress(cb, "Checking " + (qualified.size() + unqualified.size())
                + " selected class(es) against DEX definitions…");
        Set<String> found = new HashSet<>();
        for (File dexFile : dexFiles) {
            Set<String> matches = dexDefinedTargets(
                    dexFile, qualified, unqualified);
            found.addAll(matches);
        }

        Set<String> missing = new LinkedHashSet<>();
        missing.addAll(qualified);
        missing.addAll(unqualified);
        missing.removeAll(found);
        if (!missing.isEmpty()) {
            StringBuilder message = new StringBuilder(
                    "Selected class(es) not found in the APK DEX files:");
            for (String descriptor : missing) {
                message.append("\n  - ").append(descriptorToDisplayName(descriptor));
                progress(cb, "ERROR: selected class not found — "
                        + descriptorToDisplayName(descriptor));
            }
            throw new IllegalArgumentException(message.toString());
        }

        progress(cb, "Class list verified — all " + found.size()
                + " selected class(es) exist in the APK");
    }

    private static String descriptorToDisplayName(String descriptor) {
        if (descriptor != null && descriptor.startsWith("L")
                && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1)
                    .replace('/', '.');
        }
        return descriptor;
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
    private static List<File> filterHotDexFiles(List<File> dexFiles,
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

    /**
     * VMP-only hot-Dex selector.
     *
     * The old raw selector searched type_ids.  type_ids contains every type
     * referenced by a DEX, not just classes defined by that DEX, so a common
     * selected class could make all DEX files appear hot.  VMP conversion is
     * expensive because every hot file is split, re-encoded, and emitted as
     * native VM code.  Walk class_defs instead: each class_def_item owns one
     * defined class, and class_defs are sorted by class_idx in a valid DEX.
     *
     * This path is deliberately separate from the legacy DEX2C selector.  It
     * keeps this optimization scoped to VMP while retaining the DEX2C fallback
     * behavior until that mode is changed independently.
     */
    private static List<File> filterVmpHotDexFiles(List<File> dexFiles,
                                                   Set<String> targetDescriptors,
                                                   TranspileCallback cb) {
        if (targetDescriptors.isEmpty() || dexFiles.size() <= 1) return dexFiles;
        if (!supportsExactAsciiClassLookup(targetDescriptors)) {
            progress(cb, "VMP: non-exact or non-ASCII class rule detected"
                    + " — using conservative full-DEX targeting");
            return dexFiles;
        }

        Set<String> qualified   = new HashSet<>();
        Set<String> unqualified = new HashSet<>();
        for (String d : targetDescriptors) {
            if (d.indexOf('/') >= 0) qualified.add(d);
            else                     unqualified.add(d);
        }
        if (!unqualified.isEmpty()) {
            progress(cb, "VMP: unqualified class rule detected"
                    + " — using conservative full-DEX targeting");
            return dexFiles;
        }

        progress(cb, "VMP: building defined-class→DEX index ("
                + dexFiles.size() + " DEX, exact linear class_defs)…");

        long started = System.nanoTime();
        List<File> hot = new ArrayList<>();
        Set<String> foundTargets = new HashSet<>();
        boolean uncertain = false;
        for (File dexFile : dexFiles) {
            try {
                Set<String> matches = dexDefinedTargets(
                        dexFile, qualified, Collections.emptySet());
                if (!matches.isEmpty()) {
                    hot.add(dexFile);
                    foundTargets.addAll(matches);
                    Log.d(TAG, "VMP hot DEX (defined target): " + dexFile.getName());
                } else {
                    Log.d(TAG, "VMP cold DEX (no defined target): " + dexFile.getName());
                }
            } catch (Exception e) {
                // Never silently omit a selected class from a malformed DEX.
                Log.w(TAG, "VMP defined-class scan failed for " + dexFile.getName()
                        + " — including as hot to be safe: " + e.getMessage());
                hot.add(dexFile);
                uncertain = true;
            }
        }

        Set<String> missingTargets = new LinkedHashSet<>(qualified);
        missingTargets.removeAll(foundTargets);
        if (uncertain || !missingTargets.isEmpty()) {
            String reason = uncertain
                    ? "one or more DEX tables could not be verified"
                    : missingTargets.size() + " selected class(es) were not found";
            progress(cb, "VMP: exact target coverage uncertain (" + reason
                    + ") — processing all DEX files");
            Log.w(TAG, "VMP hot-DEX narrowing abandoned: " + reason
                    + "; missing=" + missingTargets);
            return dexFiles;
        }

        long elapsedMs = (System.nanoTime() - started) / 1_000_000L;
        progress(cb, "VMP: exact target coverage verified — "
                + foundTargets.size() + " class(es), " + hot.size()
                + " hot DEX in " + elapsedMs + " ms");
        return hot;
    }

    /**
     * Extract exact method keys emitted by the manual tree. These keys are
     * checked against the generated VMP implementation DEX so synthetic gate
     * methods can never hide an omitted user selection.
     */
    private static Set<String> parseExactMethodKeys(String filterText) {
        Set<String> keys = new LinkedHashSet<>();
        for (String line : filterText.split("\\r?\\n")) {
            String entry = line.trim();
            if (entry.isEmpty() || entry.startsWith("#")
                    || entry.startsWith("class ") || !entry.contains("(")) {
                continue;
            }

            String owner;
            String methodAndDescriptor;
            int arrow = entry.indexOf("->");
            if (arrow >= 0) {
                owner = entry.substring(0, arrow);
                methodAndDescriptor = entry.substring(arrow + 2);
            } else {
                int paren = entry.indexOf('(');
                int ownerEnd = entry.lastIndexOf(';', paren);
                if (ownerEnd < 0) continue;
                owner = entry.substring(0, ownerEnd + 1);
                methodAndDescriptor = entry.substring(ownerEnd + 1);
            }

            int paren = methodAndDescriptor.indexOf('(');
            if (paren <= 0) continue;
            String methodName = methodAndDescriptor.substring(0, paren);
            if ("<init>".equals(methodName) || "<clinit>".equals(methodName)) continue;

            String descriptor;
            if (owner.startsWith("L") && owner.endsWith(";")) {
                descriptor = owner;
            } else if (owner.endsWith(";")) {
                descriptor = "L" + owner;
            } else {
                descriptor = "L" + owner.replace('.', '/') + ";";
            }
            keys.add(descriptor + "->" + methodAndDescriptor);
        }
        return keys;
    }

    /**
     * Exact UI class and method selections reduce to ASCII owner descriptors.
     * Wildcards, exclusions, inheritance constraints, or Unicode names require
     * the full VMP rule engine and therefore cannot be safely narrowed here.
     */
    private static boolean supportsExactAsciiClassLookup(Set<String> targetDescriptors) {
        for (String descriptor : targetDescriptors) {
            if (descriptor == null || descriptor.length() < 3
                    || descriptor.charAt(0) != 'L'
                    || descriptor.charAt(descriptor.length() - 1) != ';'
                    || descriptor.indexOf(';') != descriptor.length() - 1) {
                return false;
            }
            for (int i = 0; i < descriptor.length(); i++) {
                char c = descriptor.charAt(i);
                if (c < 0x21 || c > 0x7E
                        || c == '*' || c == '?' || c == '!'
                        || c == '[' || c == ']' || c == '{' || c == '}'
                        || c == '(' || c == ')' || c == ',') {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Returns true if a DEX defines at least one target class.
     *
     * DEX header offsets:
     *   56 string_ids_size, 60 string_ids_off
     *   64 type_ids_size,   68 type_ids_off
     *   96 class_defs_size, 100 class_defs_off
     *
     * Each class_def_item is 32 bytes and starts with class_idx, which points
     * through type_ids to the class descriptor.  The class_defs table is
     * walked linearly because some valid-in-practice/obfuscated APKs do not
     * preserve the ordering assumed by a binary search.  A false "cold" result
     * would silently skip a user-selected class, so correctness wins here.
     */
    private static Set<String> dexDefinedTargets(File dexFile,
                                                 Set<String> qualified,
                                                 Set<String> unqualified) throws IOException {
        Set<String> matches = new HashSet<>();
        try (java.io.RandomAccessFile raf =
                     new java.io.RandomAccessFile(dexFile, "r")) {
            long fileLength = raf.length();
            if (fileLength < 112L) {
                throw new IOException("truncated DEX header");
            }

            raf.seek(56);
            int stringIdsSize = readIntLEStrict(raf);
            int stringIdsOff  = readIntLEStrict(raf);
            int typeIdsSize   = readIntLEStrict(raf);
            int typeIdsOff    = readIntLEStrict(raf);

            raf.seek(96);
            int classDefsSize = readIntLEStrict(raf);
            int classDefsOff  = readIntLEStrict(raf);

            if (stringIdsSize < 0 || stringIdsOff < 0
                    || typeIdsSize < 0 || typeIdsOff < 0
                    || classDefsSize < 0 || classDefsOff < 0) {
                throw new IOException("negative DEX table offset or size");
            }
            if (typeIdsSize == 0 || classDefsSize == 0) return matches;
            if (stringIdsSize == 0 || stringIdsOff == 0
                    || typeIdsOff == 0 || classDefsOff == 0) {
                throw new IOException("missing required DEX table");
            }
            if ((long) stringIdsOff + (long) stringIdsSize * 4L > fileLength
                    || (long) typeIdsOff + (long) typeIdsSize * 4L > fileLength
                    || (long) classDefsOff + (long) classDefsSize * 32L > fileLength) {
                throw new IOException("DEX class/type/string table exceeds file bounds");
            }

            for (int i = 0; i < classDefsSize; i++) {
                String typeStr = readDefinedClassTypeString(
                        raf, classDefsOff, i, typeIdsOff, typeIdsSize,
                        stringIdsOff, stringIdsSize, fileLength);
                if (qualified.contains(typeStr)) {
                    matches.add(typeStr);
                }
                for (String bare : unqualified) {
                    String simpleName = bare.substring(1);
                    if (typeStr.endsWith("/" + simpleName) || typeStr.equals(bare)) {
                        matches.add(bare);
                    }
                }
            }
            return matches;
        }
    }

    /** Resolve one class_def_item → class_idx → type_ids → descriptor string. */
    private static String readDefinedClassTypeString(java.io.RandomAccessFile raf,
                                                      int classDefsOff,
                                                      int classDefIndex,
                                                      int typeIdsOff,
                                                      int typeIdsSize,
                                                      int stringIdsOff,
                                                      int stringIdsSize,
                                                      long fileLength) throws IOException {
        raf.seek(classDefsOff + (long) classDefIndex * 32L);
        int classIdx = readIntLEStrict(raf);
        if (classIdx < 0 || classIdx >= typeIdsSize) {
            throw new IOException("class_idx outside type_ids");
        }

        raf.seek(typeIdsOff + (long) classIdx * 4L);
        int stringIdx = readIntLEStrict(raf);
        if (stringIdx < 0 || stringIdx >= stringIdsSize) {
            throw new IOException("class descriptor string_idx outside string_ids");
        }

        raf.seek(stringIdsOff + (long) stringIdx * 4L);
        int stringDataOff = readIntLEStrict(raf);
        if (stringDataOff <= 0 || (long) stringDataOff >= fileLength) {
            throw new IOException("class descriptor string_data outside DEX");
        }

        raf.seek(stringDataOff);
        int declaredUtf16Length = readUleb128Strict(raf);

        StringBuilder descriptor = new StringBuilder(64);
        while (true) {
            int b = raf.read();
            if (b == -1) {
                throw new IOException("unterminated class descriptor");
            }
            if (b == 0) break;
            // Exact fast targeting is ASCII-only. Any MUTF-8 sequence makes
            // this DEX conservatively hot rather than risking a false cold.
            if (b > 0x7F) {
                throw new IOException("non-ASCII class descriptor");
            }
            descriptor.append((char) b);
        }

        if (descriptor.length() < 3
                || descriptor.charAt(0) != 'L'
                || descriptor.charAt(descriptor.length() - 1) != ';') {
            throw new IOException("invalid class descriptor");
        }
        if (declaredUtf16Length != descriptor.length()) {
            throw new IOException("class descriptor length mismatch");
        }
        return descriptor.toString();
    }

    /** EOF-safe little-endian uint32 reader for the conservative VMP scanner. */
    private static int readIntLEStrict(java.io.RandomAccessFile raf) throws IOException {
        int b0 = raf.read();
        int b1 = raf.read();
        int b2 = raf.read();
        int b3 = raf.read();
        if ((b0 | b1 | b2 | b3) < 0) {
            throw new IOException("truncated uint32");
        }
        return b0
                | (b1 << 8)
                | (b2 << 16)
                | (b3 << 24);
    }

    /** Checked ULEB32 reader used by the conservative VMP class_defs scanner. */
    private static int readUleb128Strict(java.io.RandomAccessFile raf) throws IOException {
        int value = 0;
        for (int i = 0; i < 5; i++) {
            int b = raf.read();
            if (b == -1) throw new IOException("truncated ULEB128");
            if (i == 4 && (b & 0xF0) != 0) {
                throw new IOException("ULEB128 overflow");
            }
            value |= (b & 0x7F) << (i * 7);
            if ((b & 0x80) == 0) return value;
        }
        throw new IOException("invalid ULEB128");
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
