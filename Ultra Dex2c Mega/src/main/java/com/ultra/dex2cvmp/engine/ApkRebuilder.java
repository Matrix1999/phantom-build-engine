package com.ultra.dex2cvmp.engine;

import java.io.*;
import java.util.*;
import java.util.zip.*;

public class ApkRebuilder {

    public static void rebuild(File inputApk, File outputApk, File patchedDexDir,
                               File nativeLibDir, File extraAssetsDir) throws IOException {
        rebuild(inputApk, outputApk, patchedDexDir, nativeLibDir, extraAssetsDir,
                (java.util.function.Consumer<String>) null);
    }

    public static void rebuild(File inputApk, File outputApk, File patchedDexDir,
                               File nativeLibDir, File extraAssetsDir,
                               java.util.function.Consumer<String> progress) throws IOException {
        try (ZipFile in = new ZipFile(inputApk);
             ZipOutputStream out = new ZipOutputStream(new FileOutputStream(outputApk))) {

            /* Build set of asset names we are injecting so we skip originals */
            Set<String> injectedAssets = new HashSet<>();
            if (extraAssetsDir != null && extraAssetsDir.exists()) {
                File[] af = extraAssetsDir.listFiles();
                if (af != null) for (File f : af) injectedAssets.add("assets/" + f.getName());
            }

            /* Collect every DEX entry name present in the original APK.
             * We need this to guarantee zero DEX files are ever dropped:
             * any original DEX not present in patchedDexDir will be copied
             * verbatim from the original at the end as a safety fallback. */
            Set<String> originalDexEntries = new LinkedHashSet<>();
            Enumeration<? extends ZipEntry> scan = in.entries();
            while (scan.hasMoreElements()) {
                String n = scan.nextElement().getName();
                if (isDexEntry(n)) originalDexEntries.add(n);
            }

            if (progress != null) progress.accept("Copying original APK entries…");
            int copied = 0;
            Enumeration<? extends ZipEntry> entries = in.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (shouldSkip(name, injectedAssets)) continue;

                ZipEntry copy = new ZipEntry(name);
                copy.setTime(entry.getTime());
                if (entry.getMethod() == ZipEntry.STORED) {
                    copy.setMethod(ZipEntry.STORED);
                    copy.setSize(entry.getSize());
                    copy.setCompressedSize(entry.getCompressedSize());
                    copy.setCrc(entry.getCrc());
                }
                out.putNextEntry(copy);
                if (!entry.isDirectory()) {
                    try (InputStream is = in.getInputStream(entry)) {
                        is.transferTo(out);
                    }
                }
                out.closeEntry();
                copied++;
            }
            if (progress != null) progress.accept("Copied " + copied + " original entries");

            /* ── Inject patched/bystander DEX files from patchedDexDir ─────
             * Track which original DEX names we successfully inject so we can
             * fall back for any that are missing (extraction edge cases, etc.) */
            Set<String> injectedDexNames = new HashSet<>();
            if (progress != null) progress.accept("Injecting patched DEX files…");
            File[] dexFiles = patchedDexDir.listFiles();
            if (dexFiles != null) {
                // Sort for deterministic ordering (classes.dex < classes2.dex …)
                Arrays.sort(dexFiles, Comparator.comparing(File::getName));
                for (File dex : dexFiles) {
                    if (dex.getName().matches("classes(\\d*)\\.dex")) {
                        if (progress != null) progress.accept("  Packing " + dex.getName() + " (%.1f KB)".formatted(dex.length() / 1024f));
                        putDeflated(out, dex.getName(), dex);
                        injectedDexNames.add(dex.getName());
                    }
                }
            }

            /* ── Safety fallback: copy any original DEX that wasn't in patchedDexDir ──
             * Prevents DEX files from being silently dropped when the extraction
             * step misses them (unusual APK structures, edge-case naming, etc.). */
            for (String originalDexName : originalDexEntries) {
                // Strip any directory prefix to get the bare file name
                String bareName = originalDexName.contains("/")
                        ? originalDexName.substring(originalDexName.lastIndexOf('/') + 1)
                        : originalDexName;
                if (!injectedDexNames.contains(bareName)) {
                    ZipEntry dexEntry = in.getEntry(originalDexName);
                    if (dexEntry != null) {
                        if (progress != null)
                            progress.accept("  Fallback: copying original " + bareName + " (not in patchedDexDir)");
                        putDeflated(out, bareName, in.getInputStream(dexEntry));
                    }
                }
            }

            if (progress != null) progress.accept("Injecting native library…");
            addNativeLibs(out, nativeLibDir, nativeLibDir);

            /* Inject extra assets (dex2c_map.bin, etc.) */
            if (extraAssetsDir != null && extraAssetsDir.exists()) {
                File[] af = extraAssetsDir.listFiles();
                if (af != null && af.length > 0) {
                    if (progress != null) progress.accept("Injecting security assets…");
                    for (File f : af) {
                        if (f.isFile()) {
                            putDeflated(out, "assets/" + f.getName(), f);
                        }
                    }
                }
            }

            if (progress != null) progress.accept("APK rebuild complete");
        }
    }

    /**
     * Returns true if a ZIP entry is a DEX file (root-level or prefixed with ./),
     * regardless of whether it uses the standard classes*.dex naming.
     */
    private static boolean isDexEntry(String name) {
        // Strip optional leading "./" that some build tools emit
        String bare = name.startsWith("./") ? name.substring(2) : name;
        return bare.matches("classes(\\d*)\\.dex");
    }

    private static boolean shouldSkip(String name, Set<String> injectedAssets) {
        // Drop ALL DEX entries — we re-inject them all from patchedDexDir
        // (with the safety fallback in rebuild() for any that weren't extracted).
        if (isDexEntry(name)) return true;
        if (name.matches("META-INF/[^/]+\\.(RSA|DSA|EC|SF)") || name.equals("META-INF/MANIFEST.MF")) return true;
        if (name.matches("lib/[^/]+/libdex2c\\.so")) return true;
        if (injectedAssets.contains(name)) return true; /* will be re-injected below */
        return false;
    }

    /** Legacy overload used by existing call-sites that pass a mapFile */
    public static void rebuild(File inputApk, File outputApk, File patchedDexDir,
                               File nativeLibDir, File extraAssetsDir, File mapFile) throws IOException {
        /* Merge mapFile into extraAssetsDir if provided */
        if (mapFile != null && mapFile.exists() && mapFile.length() > 4 && extraAssetsDir != null) {
            File dest = new File(extraAssetsDir, "dex2c_map.bin");
            try (InputStream in2 = new FileInputStream(mapFile);
                 OutputStream o2 = new FileOutputStream(dest)) {
                in2.transferTo(o2);
            }
        }
        rebuild(inputApk, outputApk, patchedDexDir, nativeLibDir, extraAssetsDir);
    }

    private static void addNativeLibs(ZipOutputStream out, File baseDir, File dir) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) {
                addNativeLibs(out, baseDir, f);
            } else if (f.getName().endsWith(".so")) {
                String relative = baseDir.toURI().relativize(f.toURI()).getPath();
                putStored(out, "lib/" + relative, f);
            }
        }
    }

    private static void putDeflated(ZipOutputStream out, String name, File file) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        entry.setTime(file.lastModified());
        out.putNextEntry(entry);
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.transferTo(out);
        }
        out.closeEntry();
    }

    /** Overload used by the fallback path that streams directly from the original ZIP. */
    private static void putDeflated(ZipOutputStream out, String name, InputStream src) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        out.putNextEntry(entry);
        src.transferTo(out);
        out.closeEntry();
    }

    private static byte[] readAllBytes(InputStream in) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    private static void putStored(ZipOutputStream out, String name, File file) throws IOException {
        byte[] data;
        try (FileInputStream fis = new FileInputStream(file)) {
            data = readAllBytes(fis);
        }
        CRC32 crc = new CRC32();
        crc.update(data);
        ZipEntry entry = new ZipEntry(name);
        entry.setMethod(ZipEntry.STORED);
        entry.setSize(data.length);
        entry.setCompressedSize(data.length);
        entry.setCrc(crc.getValue());
        entry.setTime(file.lastModified());
        out.putNextEntry(entry);
        out.write(data);
        out.closeEntry();
    }
}
