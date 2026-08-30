package com.ultra.dex2cvmp.engine.vmp;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.v7878.dex.DexIO;
import com.v7878.dex.DexVersion;
import com.v7878.dex.WriteOptions;
import com.v7878.dex.immutable.Dex;
import java.nio.file.Files;
import com.google.common.collect.HashMultimap;
import com.ultra.dex2cvmp.engine.vmp.converter.ClassAnalyzer;
import com.ultra.dex2cvmp.engine.vmp.converter.JniCodeGenerator;
import com.ultra.dex2cvmp.engine.vmp.converter.instructionrewriter.InstructionRewriter;
import com.ultra.dex2cvmp.engine.vmp.converter.instructionrewriter.RandomInstructionRewriter;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.MethodConverter;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.MyClassDef;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.RegisterNativesCallerClassDef;
import com.ultra.dex2cvmp.engine.vmp.filters.ClassAndMethodFilter;
import com.ultra.dex2cvmp.engine.vmp.util.Pair;

import javax.annotation.Nonnull;
import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Dex2c {

    public static final String LANDROID_APP_APPLICATION = "Landroid/app/Application;";

    /** Simple callback so callers can surface per-class / per-DEX progress. */
    public interface ProgressListener {
        void onMessage(String msg);
    }

    // Same pattern as Tier1DexPatcher — lock every written DEX to version 035.
    // dexlib2's DexPool can silently mis-encode wide types, try-catch tables,
    // and annotations; passing the output through vova7878/DexIO corrects it.
    private static final WriteOptions WRITE_OPTIONS_035 =
            WriteOptions.defaultOptions().withDexVersion(DexVersion.DEX035);

    /**
     * Write a dexlib2 DexPool to {@code file}, re-encode through vova7878/DexIO
     * locked to DEX 035, and return the corrected bytes.
     *
     * Returning the bytes (fix #2) lets callers feed them directly to the next
     * step (e.g. DexBackedDexFile) without a redundant disk read.
     *
     * Fixes wide-type register miscounts, try-catch mis-encodings, annotation
     * bugs, and string-pool issues that dexlib2's own writer occasionally produces.
     */
    public static byte[] writeDexPool035(DexPool pool, File file) throws IOException {
        pool.writeTo(new FileDataStore(file));
        byte[] raw     = Files.readAllBytes(file.toPath());
        byte[] fixed   = DexIO.write(WRITE_OPTIONS_035, DexIO.read(raw));
        Files.write(file.toPath(), fixed);
        return fixed;   // caller can reuse these bytes instead of re-reading the file
    }

    private Dex2c() {
    }

    /**
     * 处理多个dex文件
     *
     * @param dexFiles dex文件列表
     * @param outDir   生成c文件等输出目录
     * @return 输出结果配置
     * @throws IOException
     */
    /** Backward-compatible overload — no progress reporting. */
    public static GlobalDexConfig handleAllDex(@Nonnull List<File> dexFiles,
                                               @Nonnull ClassAndMethodFilter filter,
                                               @Nonnull InstructionRewriter instructionRewriter,
                                               @Nonnull ClassAnalyzer classAnalyzer,
                                               @Nonnull File outDir) throws IOException {
        return handleAllDex(dexFiles, filter, instructionRewriter, classAnalyzer, outDir, null);
    }

    public static GlobalDexConfig handleAllDex(@Nonnull List<File> dexFiles,
                                               @Nonnull ClassAndMethodFilter filter,
                                               @Nonnull InstructionRewriter instructionRewriter,
                                               @Nonnull ClassAnalyzer classAnalyzer,
                                               @Nonnull File outDir,
                                               @javax.annotation.Nullable ProgressListener progress) throws IOException {
        return handleAllDex(dexFiles, filter, instructionRewriter, classAnalyzer, null, outDir, progress);
    }

    /**
     * Fix #1: cache-aware overload.
     *
     * {@code parsedCache} maps DEX filename → already-parsed DexBackedDexFile
     * (built by buildClassAnalyzerWithCache in DexTranspiler).  When a hit
     * is found, handleDex() is called with the pre-parsed object — no second
     * fromInputStream() parse per hot DEX file.  Falls back to file-based
     * parsing for any DEX not in the cache (null cache = original behaviour).
     */
    public static GlobalDexConfig handleAllDex(@Nonnull List<File> dexFiles,
                                               @Nonnull ClassAndMethodFilter filter,
                                               @Nonnull InstructionRewriter instructionRewriter,
                                               @Nonnull ClassAnalyzer classAnalyzer,
                                               @javax.annotation.Nullable Map<String, DexBackedDexFile> parsedCache,
                                               @Nonnull File outDir,
                                               @javax.annotation.Nullable ProgressListener progress) throws IOException {
        if (!outDir.exists()) outDir.mkdirs();
        final GlobalDexConfig globalConfig = new GlobalDexConfig(outDir);

        int availableCores = Runtime.getRuntime().availableProcessors();
        long maxHeapBytes = Runtime.getRuntime().maxMemory();
        // Run at most two independent DEX pipelines. Runtime.maxMemory() is an
        // Android per-app heap cap, not the phone's physical RAM; requiring a
        // large fixed heap here disabled parallelism on normal phones. Memory is
        // bounded below by submitting only one two-DEX window at a time.
        int workerCount = Math.min(dexFiles.size(),
                Math.max(1, Math.min(2, availableCores)));
        boolean canRunParallel = workerCount > 1
                && instructionRewriter instanceof RandomInstructionRewriter;

        if (canRunParallel) {
            if (progress != null) {
                progress.onMessage("VMP: DEX conversion mode: PARALLEL — " + workerCount
                        + " worker(s), bounded windows, " + dexFiles.size()
                        + " hot DEX files, heap cap " + (maxHeapBytes / (1024L * 1024L))
                        + " MB");
            }
            ExecutorService executor = Executors.newFixedThreadPool(workerCount);
            List<Future<DexConfig>> activeFutures = new ArrayList<>(workerCount);
            try {
                // A bounded producer/consumer window avoids queueing every DEX
                // conversion (and its captured parser state) at once. The first
                // window converts classes2/classes3 concurrently; only after it
                // is collected do gate or later hot DEXes start.
                for (int batchStart = 0; batchStart < dexFiles.size();
                     batchStart += workerCount) {
                    activeFutures.clear();
                    int batchEnd = Math.min(dexFiles.size(), batchStart + workerCount);
                    for (int i = batchStart; i < batchEnd; i++) {
                        final int dexPosition = i;
                        final File file = dexFiles.get(i);
                        final DexBackedDexFile cached =
                                parsedCache != null ? parsedCache.get(file.getName()) : null;
                        final InstructionRewriter workerRewriter =
                                ((RandomInstructionRewriter) instructionRewriter).fork();
                        activeFutures.add(executor.submit(() -> {
                            ProgressListener workerProgress =
                                    progress == null ? null : message -> {
                                synchronized (progress) {
                                    progress.onMessage(message);
                                }
                            };
                            if (workerProgress != null) {
                                workerProgress.onMessage("VMP: processing " + file.getName()
                                        + " (" + (dexPosition + 1) + "/"
                                        + dexFiles.size() + ")…");
                            }
                            if (cached != null) {
                                return handleDex(cached, file.getName(), filter, classAnalyzer,
                                        workerRewriter, outDir, workerProgress);
                            }
                            return handleDex(file, filter, classAnalyzer,
                                    workerRewriter, outDir, workerProgress);
                        }));
                    }

                    // Preserve original DEX order in GlobalDexConfig/JNI init
                    // output regardless of which worker finishes first.
                    for (Future<DexConfig> future : activeFutures) {
                        DexConfig config;
                        try {
                            config = future.get();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException("VMP parallel DEX conversion interrupted", e);
                        } catch (ExecutionException e) {
                            Throwable cause = e.getCause();
                            if (cause instanceof IOException) throw (IOException) cause;
                            throw new IOException("VMP parallel DEX conversion failed", cause);
                        }
                        config.setShellMethods(null);
                        globalConfig.addDexConfig(config);
                    }
                }
            } finally {
                for (Future<DexConfig> future : activeFutures) {
                    if (!future.isDone()) future.cancel(true);
                }
                executor.shutdownNow();
            }
        } else {
            if (progress != null) {
                String serialReason;
                if (availableCores <= 1) {
                    serialReason = "not enough available CPU cores";
                } else {
                    serialReason = "rewriter does not support isolated workers";
                }
                progress.onMessage("VMP: DEX conversion mode: SERIAL — " + serialReason);
            }
            for (int i = 0; i < dexFiles.size(); i++) {
                File file = dexFiles.get(i);
                if (progress != null) {
                    progress.onMessage("VMP: processing " + file.getName()
                            + " (" + (i + 1) + "/" + dexFiles.size() + ")…");
                }

                final DexConfig config;
                DexBackedDexFile cached =
                        parsedCache != null ? parsedCache.get(file.getName()) : null;
                if (cached != null) {
                    config = handleDex(cached, file.getName(), filter, classAnalyzer,
                            instructionRewriter, outDir, progress);
                } else {
                    config = handleDex(file, filter, classAnalyzer,
                            instructionRewriter, outDir, progress);
                }
                config.setShellMethods(null);
                globalConfig.addDexConfig(config);
            }
        }
        if (progress != null) progress.onMessage("VMP: generating JNI init tables…");
        globalConfig.generateJniInitCode();
        if (progress != null) progress.onMessage("VMP: JNI init tables ready");
        return globalConfig;
    }

    /**
     * 处理单个dex文件
     */
    public static DexConfig handleDex(@Nonnull File dexFile,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir) throws IOException {
        return handleDex(dexFile, filter, classAnalyzer, instructionRewriter, outDir, null);
    }

    public static DexConfig handleDex(@Nonnull File dexFile,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir,
                                      @javax.annotation.Nullable ProgressListener progress) throws IOException {
        return handleDex(new BufferedInputStream(new FileInputStream(dexFile)),
                dexFile.getName(),
                filter,
                classAnalyzer,
                instructionRewriter,
                outDir,
                progress);
    }

    public static DexConfig handleModuleDex(@Nonnull File dexFile,
                                            @Nonnull ClassAndMethodFilter filter,
                                            @Nonnull ClassAnalyzer classAnalyzer,
                                            @Nonnull InstructionRewriter instructionRewriter,
                                            @Nonnull File outDir) throws IOException {
        final GlobalDexConfig globalDexConfig = new GlobalDexConfig(outDir);
        final DexConfig dexConfig = handleDex(dexFile, filter, classAnalyzer, instructionRewriter, outDir);
        globalDexConfig.addDexConfig(dexConfig);

        globalDexConfig.generateJniInitCode();
        return dexConfig;
    }

    /**
     * 处理单个dex流
     */
    public static DexConfig handleDex(@Nonnull InputStream dex,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir) throws IOException {
        return handleDex(dex, dexFileName, filter, classAnalyzer, instructionRewriter, outDir, null);
    }

    public static DexConfig handleDex(@Nonnull InputStream dex,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir,
                                      @javax.annotation.Nullable ProgressListener progress) throws IOException {
        // Parse the stream and delegate to the pre-parsed overload
        DexBackedDexFile originDexFile = DexBackedDexFile.fromInputStream(null, dex);
        return handleDex(originDexFile, dexFileName, filter, classAnalyzer,
                instructionRewriter, outDir, progress);
    }

    /**
     * Fix #1: core handleDex overload that accepts an already-parsed DexBackedDexFile.
     *
     * Called by the cache-aware handleAllDex() overload to avoid a second
     * fromInputStream() parse for DEX files already loaded by buildClassAnalyzer().
     * The InputStream overload above still works and routes through this one.
     */
    public static DexConfig handleDex(@Nonnull DexBackedDexFile originDexFile,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir,
                                      @javax.annotation.Nullable ProgressListener progress) throws IOException {
        if (!outDir.exists()) outDir.mkdirs();
        DexConfig config = splitDex(originDexFile, dexFileName, filter, classAnalyzer, outDir, progress);

        if (progress != null) progress.onMessage("VMP: generating C code for " + dexFileName + "…");

        // Fix #2: reuse impl bytes cached by splitDex — avoids a disk read
        final DexBackedDexFile nativeImplDexFile;
        byte[] implBytes = config.getImplDexBytes();
        if (implBytes != null) {
            nativeImplDexFile = DexBackedDexFile.fromInputStream(null,
                    new BufferedInputStream(new java.io.ByteArrayInputStream(implBytes)));
        } else {
            nativeImplDexFile = DexBackedDexFile.fromInputStream(null,
                    new BufferedInputStream(new FileInputStream(config.getImplDexFile())));
        }

        //根据符号dex生成c代码
        try (FileWriter nativeCodeWriter = new FileWriter(config.getNativeFunctionsFile());
             FileWriter resolverWriter = new FileWriter(config.getResolverFile());
        ) {
            JniCodeGenerator codeGenerator = new JniCodeGenerator(nativeImplDexFile,
                    classAnalyzer,
                    instructionRewriter);
            codeGenerator.generate(config, resolverWriter, nativeCodeWriter);
            config.setResult(codeGenerator);
        }

        // Native offsets are now known. Build the registration-hooked shell DEX
        // directly from the in-memory class definitions and write it once.
        finalizeShellDex(config, 60000);

        if (progress != null) progress.onMessage("VMP: C code written for " + dexFileName);
        return config;
    }

    //分割dex产生两个dex,一个为壳dex,一个为实现dex,壳dex将会打包进apk,实现dex会被转换为c代码
    @Nonnull
    private static DexConfig splitDex(@Nonnull InputStream dex,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull File outDir,
                                      @javax.annotation.Nullable ProgressListener progress) throws IOException {
        DexBackedDexFile originDexFile = DexBackedDexFile.fromInputStream(null, dex);
        return splitDex(originDexFile, dexFileName, filter, classAnalyzer, outDir, progress);
    }

    /** Fix #1: core splitDex that accepts a pre-parsed DexBackedDexFile. */
    @Nonnull
    private static DexConfig splitDex(@Nonnull DexBackedDexFile originDexFile,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull File outDir,
                                      @javax.annotation.Nullable ProgressListener progress) throws IOException {

        // Keep the shell class definitions until native registration offsets are
        // known. Writing the shell here and rewriting it later for classesInit0
        // doubled the most expensive DEX serialization work.
        List<ClassDef> shellClasses = new ArrayList<>();

        DexPool nativeImplDexPool = new DexPool(originDexFile.getOpcodes());

        final MethodConverter methodConverter = new MethodConverter(classAnalyzer);

        HashMultimap<String, List<? extends Method>> shellMethods = HashMultimap.create();

        // Collect classes into a list so we can report N/total progress
        List<ClassDef> allClasses = new ArrayList<>();
        for (ClassDef c : originDexFile.getClasses()) allClasses.add(c);
        int total = allClasses.size();

        // Emit every class if small; otherwise every 5th to avoid flooding the log
        int stride = total <= 20 ? 1 : (total <= 100 ? 5 : 10);
        int converted = 0;

        for (int ci = 0; ci < total; ci++) {
            final ClassDef classDef = allClasses.get(ci);
            if (filter.acceptClass(classDef)) {
                converted++;
                // Human-readable class name: "Lcom/foo/Bar;" → "com.foo.Bar"
                String shortName = classDef.getType()
                        .replaceAll("^L", "").replaceAll(";$", "").replace('/', '.');
                if (progress != null && (ci % stride == 0 || ci == total - 1)) {
                    progress.onMessage("  [" + (ci + 1) + "/" + total + "] " + shortName);
                }

                final ArrayList<Method> shellDirectMethods = new ArrayList<>();
                final ArrayList<Method> shellVirtualMethods = new ArrayList<>();

                final ArrayList<Method> implDirectMethods = new ArrayList<>();
                final ArrayList<Method> implVirtualMethods = new ArrayList<>();

                // 处理所有需要转换的方法
                for (Method method : classDef.getMethods()) {
                    if (filter.acceptMethod(method)
                        // 有直接调用jna方法的指令,则不能进行native化
                        // 感觉很少会发生,默认就把这个判断注释掉了,谁需要再去掉注释
//                            && !classAnalyzer.hasCallJnaMethod(method)
                    ) {
                        final Pair<List<? extends Method>, Method> pair = methodConverter.convert(method);
                        // 转换后可能出现变为多个方法
                        addMethods(shellDirectMethods, shellVirtualMethods, pair.first);

                        //记录当前类，所有需要被修改的方法
                        shellMethods.put(classDef.getType(), pair.first);

                        //只有一个具体实现
                        addMethod(implDirectMethods, implVirtualMethods, pair.second);
                    } else {
                        //不需要进行处理
                        addMethod(shellDirectMethods, shellVirtualMethods, method);
                    }
                }

                //把需要转换的方法设为native
                shellClasses.add(new MyClassDef(classDef, shellDirectMethods, shellVirtualMethods));
                //收集所有需要转换的方法生成新dex
                nativeImplDexPool.internClass(new MyClassDef(classDef, implDirectMethods, implVirtualMethods));
            } else {
                //不需要处理的class,直接复制
                shellClasses.add(classDef);
            }
        }
        if (progress != null) {
            progress.onMessage("VMP: converted " + converted + " class(es) in " + dexFileName
                    + " → preparing final DEX 035…");
        }

        DexConfig config = new DexConfig(outDir, dexFileName);

        config.setShellMethods(shellMethods);
        config.setPendingShellClasses(shellClasses, originDexFile.getOpcodes());

        // Fix #2: capture corrected impl bytes so handleDex() can feed them
        // directly to DexBackedDexFile without a disk re-read.
        byte[] implBytes = writeDexPool035(nativeImplDexPool, config.getImplDexFile());
        config.setImplDexBytes(implBytes);
        return config;
    }

    private static void addMethods(List<Method> directMethods,
                                   List<Method> virtualMethods,
                                   List<? extends Method> methods) {
        for (Method method : methods) {
            addMethod(directMethods, virtualMethods, method);
        }
    }

    private static void addMethod(List<Method> directMethods,
                                  List<Method> virtualMethods,
                                  Method method) {
        if (MethodUtil.isDirect(method)) {
            directMethods.add(method);
        } else {
            virtualMethods.add(method);
        }
    }

    //在处理过的class的static{}块最前面添加注册本地方法代码,如果不存在static{}块则新增<clinit>方法
    public static List<DexPool> injectCallRegisterNativeInsns(DexConfig config,
                                                              DexPool lastDexPool,
                                                              Set<String> mainClassSet,
                                                              int maxPoolSize) throws IOException {

        DexBackedDexFile dexNativeFile = DexBackedDexFile.fromInputStream(
                null,
                new BufferedInputStream(new FileInputStream(config.getShellDexFile())));

        return injectCallRegisterNativeInsns(config, lastDexPool, mainClassSet,
                maxPoolSize, dexNativeFile.getClasses(), dexNativeFile.getOpcodes());
    }

    private static List<DexPool> injectCallRegisterNativeInsns(
            DexConfig config,
            DexPool lastDexPool,
            Set<String> mainClassSet,
            int maxPoolSize,
            Iterable<? extends ClassDef> shellClasses,
            com.android.tools.smali.dexlib2.Opcodes opcodes) {
        List<DexPool> dexPools = new ArrayList<>();
        dexPools.add(lastDexPool);

        Iterator<? extends ClassDef> classIterator = shellClasses.iterator();
        while (classIterator.hasNext()) {
            ClassDef classDef = classIterator.next();
            if (mainClassSet.contains(classDef.getType())) {//提前处理过的class,不用再处理
                continue;
            }
            internClass(config, lastDexPool, classDef);

            // Do not create an empty trailing DEX when the final class itself
            // crosses the soft pool limit.
            if (lastDexPool.hasOverflowed(maxPoolSize) && classIterator.hasNext()) {
                lastDexPool = new DexPool(opcodes);
                dexPools.add(lastDexPool); // written via writeDexPool035 by the caller
            }
        }
        return dexPools;
    }

    private static void finalizeShellDex(DexConfig config, int maxPoolSize) throws IOException {
        List<ClassDef> shellClasses = config.getPendingShellClasses();
        com.android.tools.smali.dexlib2.Opcodes opcodes = config.getPendingShellOpcodes();
        if (shellClasses == null || opcodes == null) {
            throw new IOException("VMP shell classes are unavailable for " + config.getDexName());
        }

        long started = System.nanoTime();
        DexPool startPool = new DexPool(opcodes);
        List<DexPool> pools = injectCallRegisterNativeInsns(
                config, startPool, Collections.emptySet(), maxPoolSize,
                shellClasses, opcodes);
        List<File> outputs = new ArrayList<>(pools.size());
        try {
            for (int i = 0; i < pools.size(); i++) {
                File output = i == 0
                        ? config.getShellDexFile()
                        : new File(config.getOutputDir(),
                                config.getDexName() + "_shell_" + (i + 1) + ".dex");
                writeDexPool035(pools.get(i), output);
                outputs.add(output);
            }
            config.setFinalizedShellDexFiles(outputs);
        } finally {
            // Release references to the original parsed DEX as soon as its final
            // shell output is complete; large multi-DEX jobs must stay bounded.
            config.clearPendingShellClasses();
        }
        long elapsedMs = (System.nanoTime() - started) / 1_000_000L;
        System.out.println("VMP: finalized hooked shell " + config.getDexName()
                + " in " + elapsedMs + " ms (" + outputs.size() + " DEX)");
    }

    private static void internClass(DexConfig config, DexPool dexPool, ClassDef classDef) {
        final Set<String> classes = config.getHandledNativeClasses();
        final String type = classDef.getType();
        final String className = type.substring(1, type.length() - 1);
        if (classes.contains(className)) {
            final RegisterNativesCallerClassDef nativeClassDef = new RegisterNativesCallerClassDef(
                    classDef,
                    config.getOffsetFromClassName(className),
                    "L" + config.getRegisterNativesClassName() + ";",
                    config.getRegisterNativesMethodName());
            dexPool.internClass(nativeClassDef);
        } else {
            dexPool.internClass(classDef);
        }
    }

}