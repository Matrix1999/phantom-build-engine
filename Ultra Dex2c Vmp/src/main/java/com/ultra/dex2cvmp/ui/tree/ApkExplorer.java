package com.ultra.dex2cvmp.ui.tree;

import com.v7878.dex.DexIO;
import com.v7878.dex.immutable.ClassDef;
import com.v7878.dex.immutable.MethodDef;
import com.v7878.dex.immutable.Parameter;

import java.io.File;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Parses an APK file (via vova7878/DexFile) and builds a Package → Class → Method tree.
 * Run on a background thread — this can take several seconds for large APKs.
 *
 * Multi-DEX support: iterates every classes*.dex entry inside the APK zip,
 * reads each with DexIO.read(). Unknown/obfuscated instructions are read as
 * raw bytes (InstructionRaw0x via RawFix.DO_NOT_TOUCH) — the explorer never
 * fails on obfuscated APKs.
 */
public class ApkExplorer {

    public static List<PackageNode> explore(File apkFile) throws Exception {
        // className → List<MethodNode>
        Map<String, List<MethodNode>> classMap = new TreeMap<>();

        try (ZipFile zip = new ZipFile(apkFile)) {
            // Collect all classes*.dex entries, sorted so classes.dex comes first
            List<? extends ZipEntry> dexEntries = zip.stream()
                    .filter(e -> {
                        String n = e.getName();
                        return n.matches("classes(\\d*)\\.dex");
                    })
                    .sorted(Comparator.comparing(ZipEntry::getName))
                    .collect(Collectors.toList());

            for (ZipEntry entry : dexEntries) {
                byte[] data;
                try (InputStream in = zip.getInputStream(entry)) {
                    data = in.readAllBytes();
                }

                for (ClassDef cls : DexIO.read(data).getClasses()) {
                    String typeDesc = cls.getType().toString(); // e.g. "Lcom/example/Foo;"
                    if (!typeDesc.startsWith("L") || !typeDesc.endsWith(";")) continue;

                    // Convert to dotted name
                    String className = typeDesc.substring(1, typeDesc.length() - 1)
                            .replace('/', '.');

                    if (isSystemClass(className)) continue;

                    List<MethodNode> methods = new ArrayList<>();
                    // classPrefix for the fullPattern key: "com/example/Foo;"
                    String classPrefix = typeDesc.substring(1);

                    for (MethodDef m : cls.getMethods()) {
                        String mName = m.getName();
                        if (mName.startsWith("<")) continue; // skip constructors/<clinit>

                        int flags     = m.getAccessFlags();
                        boolean isAbstract = (flags & 0x0400) != 0;
                        boolean isNative   = (flags & 0x0100) != 0;
                        if (isAbstract || isNative) continue; // engine cannot wrap these

                        String params = m.getParameters().stream()
                                .map(p -> p.getType().toString())
                                .collect(Collectors.joining());
                        String returnType = m.getReturnType().toString();
                        String descriptor = "(" + params + ")" + returnType;

                        // Pattern for MethodScanner: className;methodName(...)returnType
                        String fullPattern = classPrefix + mName + descriptor;

                        // Friendly display: "onResume(String, int) → void"
                        String displaySig = mName + "(" + friendlyParams(m) + ") → "
                                + friendlyType(returnType);

                        methods.add(new MethodNode(mName, descriptor, displaySig, fullPattern));
                    }

                    methods.sort(Comparator.comparing(mn -> mn.name));
                    // Only overwrite if not already present (first DEX wins)
                    classMap.putIfAbsent(className, methods);
                }
            }
        }

        // Group by package
        Map<String, List<ClassNode>> pkgMap = new TreeMap<>();
        for (Map.Entry<String, List<MethodNode>> e : classMap.entrySet()) {
            String className = e.getKey();
            String pkg       = packageOf(className);
            String simple    = simpleNameOf(className);
            ClassNode cls    = new ClassNode(className, simple, e.getValue());
            pkgMap.computeIfAbsent(pkg, k -> new ArrayList<>()).add(cls);
        }

        List<PackageNode> packages = new ArrayList<>();
        for (Map.Entry<String, List<ClassNode>> e : pkgMap.entrySet()) {
            List<ClassNode> classes = e.getValue();
            classes.sort(Comparator.comparing(c -> c.simpleName));
            packages.add(new PackageNode(e.getKey(), classes));
        }
        return packages;
    }

    private static boolean isSystemClass(String name) {
        return name.startsWith("android.")
            || name.startsWith("androidx.")
            || name.startsWith("kotlin.")
            || name.startsWith("kotlinx.")
            || name.startsWith("java.")
            || name.startsWith("javax.")
            || name.startsWith("sun.")
            || name.startsWith("com.google.android.")
            || name.startsWith("dalvik.")
            || name.startsWith("org.jetbrains.")
            || name.startsWith("com.squareup.")
            || name.startsWith("okhttp3.")
            || name.startsWith("okio.")
            || name.startsWith("retrofit2.")
            || name.startsWith("rx.");
    }

    private static String packageOf(String className) {
        int dot = className.lastIndexOf('.');
        return dot >= 0 ? className.substring(0, dot) : "(default)";
    }

    private static String simpleNameOf(String className) {
        int dot = className.lastIndexOf('.');
        return dot >= 0 ? className.substring(dot + 1) : className;
    }

    private static String friendlyParams(MethodDef method) {
        List<String> parts = new ArrayList<>();
        for (Parameter p : method.getParameters()) {
            parts.add(friendlyType(p.getType().toString()));
        }
        return String.join(", ", parts);
    }

    static String friendlyType(String desc) {
        // strip array prefix
        int arrays = 0;
        while (desc.startsWith("[")) { arrays++; desc = desc.substring(1); }
        String base;
        switch (desc) {
            case "V": base = "void";    break;
            case "Z": base = "boolean"; break;
            case "B": base = "byte";    break;
            case "S": base = "short";   break;
            case "C": base = "char";    break;
            case "I": base = "int";     break;
            case "J": base = "long";    break;
            case "F": base = "float";   break;
            case "D": base = "double";  break;
            default:
                if (desc.startsWith("L") && desc.endsWith(";")) {
                    String inner = desc.substring(1, desc.length() - 1);
                    int slash = inner.lastIndexOf('/');
                    base = slash >= 0 ? inner.substring(slash + 1) : inner;
                } else {
                    base = desc;
                }
        }
        StringBuilder sb = new StringBuilder(base);
        for (int i = 0; i < arrays; i++) sb.append("[]");
        return sb.toString();
    }
}
