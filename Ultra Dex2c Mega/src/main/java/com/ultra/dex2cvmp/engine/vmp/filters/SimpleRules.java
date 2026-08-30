package com.ultra.dex2cvmp.engine.vmp.filters;

import com.google.common.collect.HashMultimap;
import com.android.tools.smali.dexlib2.iface.Method;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * class * extends android.app.Activity
 * class * implements java.io.Serializable
 * class my.package.AClass
 * class my.package.* { *; }
 * class * extends java.util.ArrayList {
 * if*;
 * }
 * class A {
 * }
 * class B extends A {
 * }
 * class C extends B {
 * }
 * The rule 'class * extends A' only match B
 */
public class SimpleRules {
    private final HashMultimap<ClassRule, MethodRule> convertRules = HashMultimap.create();


    public SimpleRules() {
    }

    public void parse(Reader ruleReader) throws IOException {
        try (BufferedReader reader = new BufferedReader(ruleReader)) {
            ClassRule classRule = null;
            final ArrayList<String> methodNameList = new ArrayList<>();
            boolean methodParsing = false;
            int lineNumb = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if ("".equals(line)) {//empty line
                    lineNumb++;
                    continue;
                }
                if (line.startsWith("class")) {
                    final String[] split = line.split(" +");
                    final int length = split.length;
                    if (length < 2) {
                        throw new IOException("Error rule " + lineNumb + ": " + line);
                    }
                    String className = split[1];
                    String supperName = "";
                    String interfaceName = "";
                    if (length >= 4) {
                        if ("extends".equals(split[2])) {//class * extends A
                            supperName = split[3];
                        } else if ("implements".equals(split[2])) {//class * implements I
                            interfaceName = split[3];
                        }
                    }
                    classRule = new ClassRule(className, supperName, interfaceName);
                    int mstart;
                    if ((mstart = line.indexOf('{')) != -1) { // my.pkg.A { methodA;methodB;}
                        int mend;
                        if ((mend = line.indexOf('}')) != -1) {
                            final String[] methodNames = line.substring(mstart + 1, mend).trim().split(";");
                            if (methodNames.length == 0) {
                                throw new IOException("Error rule " + lineNumb + ": " + line);
                            }
                            for (String name : methodNames) {
                                convertRules.put(classRule, new MethodRule(name));
                            }
                        } else {
                            methodNameList.clear();
                            methodParsing = true;
                        }
                    } else {
                        //any methods
                        convertRules.put(classRule, new MethodRule("*"));
                    }
                } else if (methodParsing) {
                    // my.pkg.A {
                    //   methodA;
                    //   methodB;
                    // }
                    if (line.indexOf('}') != -1) {
                        if (methodNameList.isEmpty()) {
                            throw new IOException("Error rule " + lineNumb + ": " + line);
                        }
                        for (String methodName : methodNameList) {
                            if ("".equals(methodName)) {
                                continue;
                            }
                            convertRules.put(classRule, new MethodRule(methodName));
                        }
                        methodParsing = false;
                    } else {
                        String methodPattern = line;
                        if (methodPattern.endsWith(";")) {
                            methodPattern = methodPattern.substring(
                                    0, methodPattern.length() - 1).trim();
                        }
                        methodNameList.add(methodPattern);
                    }
                } else {
                    throw new IOException("Error rule " + lineNumb + ": " + line);
                }

                lineNumb++;
            }
        }
    }

    // The currently matched class is worker-local. Parallel DEX conversion can
    // evaluate different classes concurrently without one worker replacing
    // another worker's method rules.
    private final ThreadLocal<Set<MethodRule>> methodRules = new ThreadLocal<>();

    public boolean matchClass(@Nonnull String classType, @Nullable String supperType, @Nonnull List<String> ifacTypes) {
        for (ClassRule rule : convertRules.keySet()) {
            final String typePattern = classNameToType(rule.className);
            if (wildcardMatch(typePattern, classType)) {// match classType
                if (!"".equals(rule.supperName)) {//supper name not empty
                    if (supperType != null) {
                        final String type = classNameToType(rule.supperName);
                        if (supperType.equals(type)) {
                            methodRules.set(convertRules.get(rule));
                            return true;
                        }
                    }
                    continue;
                }
                if (!"".equals(rule.interfaceName)) {//interface name not empty
                    for (String iface : ifacTypes) {
                        if (iface.equals(classNameToType(rule.interfaceName))) {
                            methodRules.set(convertRules.get(rule));
                            return true;
                        }
                    }
                    continue;
                }
                methodRules.set(convertRules.get(rule));
                return true;
            }
        }
        methodRules.remove();
        return false;
    }

    public boolean matchMethod(String methodName) {
        Set<MethodRule> rules = methodRules.get();
        if (rules == null || methodName == null) {
            return false;
        }
        for (MethodRule methodRule : rules) {
            if (wildcardMatch(methodRule.methodName, methodName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Match either a traditional method-name rule or an exact
     * name+descriptor rule. Exact UI selections retain their descriptor so
     * choosing one overload cannot accidentally convert every overload.
     */
    public boolean matchMethod(Method method) {
        Set<MethodRule> rules = methodRules.get();
        if (rules == null || method == null) {
            return false;
        }
        StringBuilder exact = new StringBuilder(method.getName()).append('(');
        for (CharSequence parameterType : method.getParameterTypes()) {
            exact.append(parameterType);
        }
        exact.append(')').append(method.getReturnType());

        for (MethodRule methodRule : rules) {
            String pattern = methodRule.methodName;
            if (pattern.indexOf('(') >= 0) {
                if (wildcardMatch(pattern, exact.toString())) return true;
            } else if (wildcardMatch(pattern, method.getName())) {
                return true;
            }
        }
        return false;
    }

    private static String classNameToType(String className) {
        return "L" + className.replace('.', '/') + ";";
    }

    /**
     * Plain wildcard match — no Java regex at all.
     * Only '*' is special (matches any sequence of characters).
     * '$', '.', '(' and every other character are treated as literals,
     * so inner-class names (Outer$Inner), array types ([L…;), and
     * obfuscated method names never cause false misses.
     *
     * This mirrors how dex2c passes filter text straight to Python for
     * plain string comparison — no regex engine involved.
     *
     * Examples:
     *   wildcardMatch("Lcom/foo/Bar;",        "Lcom/foo/Bar;")        → true  (exact)
     *   wildcardMatch("LREVERSAL_X$Inner;",   "LREVERSAL_X$Inner;")   → true  ($ literal)
     *   wildcardMatch("L*;",                  "Lcom/foo/Bar;")         → true  (wildcard)
     *   wildcardMatch("Lcom/foo/*;",          "Lcom/foo/Bar;")         → true  (pkg wildcard)
     *   wildcardMatch("*",                    "run")                   → true  (method wildcard)
     *   wildcardMatch("run",                  "run")                   → true  (exact method)
     *   wildcardMatch("run",                  "onClick")               → false
     */
    private static boolean wildcardMatch(String pattern, String text) {
        // Fast paths
        if ("*".equals(pattern))          return true;
        if (!pattern.contains("*"))       return pattern.equals(text);

        // General case: split on '*', verify each segment appears in order.
        // split(..., -1) keeps trailing empty strings so trailing '*' works correctly.
        String[] segs = pattern.split("\\*", -1);
        int pos = 0;
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            if (seg.isEmpty()) continue;
            int idx = text.indexOf(seg, pos);
            if (idx < 0) return false;
            // First segment must be anchored at the start (no implicit leading wildcard)
            if (i == 0 && idx != 0) return false;
            pos = idx + seg.length();
        }
        // Last non-empty segment must be anchored at the end (no implicit trailing wildcard)
        String last = segs[segs.length - 1];
        if (!last.isEmpty() && !text.endsWith(last)) return false;
        return true;
    }

    private static class ClassRule {
        @Nonnull
        private final String className;
        //supper class
        @Nonnull
        private final String supperName;
        //interface
        @Nonnull
        private final String interfaceName;

        public ClassRule(@Nonnull String className) {
            this(className, "", "");
        }

        public ClassRule(@Nonnull String className, @Nonnull String supperName, @Nonnull String interfaceName) {
            this.className = className;
            this.supperName = supperName;
            this.interfaceName = interfaceName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ClassRule classRule = (ClassRule) o;

            if (!className.equals(classRule.className)) return false;
            if (!supperName.equals(classRule.supperName)) return false;
            return interfaceName.equals(classRule.interfaceName);
        }

        @Override
        public int hashCode() {
            int result = className.hashCode();
            result = 31 * result + supperName.hashCode();
            result = 31 * result + interfaceName.hashCode();
            return result;
        }
    }

    private static class MethodRule {
        @Nonnull
        private final String methodName;
        // args ?
        // private final List<String> args;

        public MethodRule(@Nonnull String methodName) {
            this.methodName = methodName;
        }
    }
}
