package com.ultra.dex2cvmp.ui.tree;

public class MethodNode {
    public final String name;
    public final String descriptor;   // "(Landroid/os/Bundle;)V"
    public final String displaySig;   // "onCreate(Bundle) → void"
    public final String fullPattern;  // "com/example/MainActivity;onCreate(...)V"
    public boolean selected;

    public MethodNode(String name, String descriptor, String displaySig, String fullPattern) {
        this.name        = name;
        this.descriptor  = descriptor;
        this.displaySig  = displaySig;
        this.fullPattern = fullPattern;
        this.selected    = false;
    }
}
