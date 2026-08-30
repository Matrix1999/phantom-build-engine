package com.ultra.dex2cvmp.engine.vmp.filters;


import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;

public interface ClassAndMethodFilter {
    boolean acceptClass(ClassDef classDef);

    boolean acceptMethod(Method method);
}
