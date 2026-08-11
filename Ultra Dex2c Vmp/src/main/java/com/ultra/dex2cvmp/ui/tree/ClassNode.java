package com.ultra.dex2cvmp.ui.tree;

import java.util.List;

public class ClassNode {
    public final String fullName;     // "com.example.app.MainActivity"
    public final String simpleName;   // "MainActivity"
    public final List<MethodNode> methods;
    public boolean selected;
    public boolean expanded;

    public ClassNode(String fullName, String simpleName, List<MethodNode> methods) {
        this.fullName   = fullName;
        this.simpleName = simpleName;
        this.methods    = methods;
        this.selected   = false;
        this.expanded   = false;
    }

    /** true=all, false=none, null=partial */
    public Boolean getSelectionState() {
        if (methods.isEmpty()) return selected;
        int sel = 0;
        for (MethodNode m : methods) if (m.selected) sel++;
        if (sel == methods.size()) return true;
        if (sel == 0)              return false;
        return null; // partial
    }

    public void setAllMethods(boolean val) {
        selected = val;
        for (MethodNode m : methods) m.selected = val;
    }

    /** Build filter line(s) for this class based on selection. */
    public String buildFilter() {
        Boolean state = getSelectionState();
        if (state == Boolean.FALSE) return null;
        if (state == Boolean.TRUE) {
            // Whole class — engine normalizes "com.example.X" → "com/example/X;.*"
            return fullName;
        }
        // Partial — emit each selected method's full pattern
        StringBuilder sb = new StringBuilder();
        for (MethodNode m : methods) {
            if (m.selected) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(m.fullPattern);
            }
        }
        return sb.length() > 0 ? sb.toString() : null;
    }
}
