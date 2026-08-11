package com.ultra.dex2cvmp.ui.tree;

import java.util.List;

public class PackageNode {
    public final String name;           // "com.example.app"
    public final List<ClassNode> classes;
    public boolean expanded;

    public PackageNode(String name, List<ClassNode> classes) {
        this.name        = name;
        this.classes     = classes;
        this.expanded    = false;
    }

    /** true=all, false=none, null=partial */
    public Boolean getSelectionState() {
        int sel = 0;
        for (ClassNode c : classes) {
            if (c.getSelectionState() == Boolean.TRUE) sel++;
        }
        if (sel == classes.size()) return true;
        if (sel == 0)              return false;
        return null;
    }

    public void setAll(boolean val) {
        for (ClassNode c : classes) c.setAllMethods(val);
    }

    public int countSelectedClasses() {
        int n = 0;
        for (ClassNode c : classes) {
            Boolean s = c.getSelectionState();
            if (s != Boolean.FALSE) n++;
        }
        return n;
    }
}
