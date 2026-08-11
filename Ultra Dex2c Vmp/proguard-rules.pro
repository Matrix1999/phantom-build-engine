##──── MAXIMUM OBFUSCATION — nothing readable survives ───────────────────────##

##──── R8 full-mode: repack everything into one flat package ─────────────────##
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
-optimizationpasses 3

##──── Strip every debug artifact ────────────────────────────────────────────##
-renamesourcefileattribute a
-keepattributes SourceFile,LineNumberTable
-keepattributes !LocalVariable*,!LocalVariableType*
-keepattributes !Signature
-keepattributes !*Annotation*

##──── JNI: native method names MUST survive mangling ────────────────────────##
-keepclasseswithmembernames class * {
    native <methods>;
}

##──── Android component names referenced in AndroidManifest ─────────────────##
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends androidx.fragment.app.Fragment
-keep public class * extends androidx.fragment.app.DialogFragment

##──── Only the class name needs to survive for Manifest-declared components ──##
-keepnames class com.dex2c.mega.** extends android.app.Activity
-keepnames class com.dex2c.mega.** extends android.app.Service
-keepnames class com.dex2c.mega.** extends android.content.BroadcastReceiver
-keepnames class com.dex2c.mega.** extends androidx.fragment.app.Fragment

##──── Views inflated from XML need constructors ─────────────────────────────##
-keep class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

##──── Navigation ─────────────────────────────────────────────────────────────##
-keepnames class androidx.navigation.** { *; }

##──── Parcelable ─────────────────────────────────────────────────────────────##
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

##──── Serializable ───────────────────────────────────────────────────────────##
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

##──── vova7878/DexFile (reflection + internal raw writers) ──────────────────##
-keep class com.v7878.dex.** { *; }
-keep class com.v7878.collections.** { *; }
-dontwarn com.v7878.**

##──── Suppress misc warnings ────────────────────────────────────────────────##
-dontwarn javax.**
-dontwarn org.antlr.**
-dontwarn sun.**
-dontwarn java.lang.instrument.**
-ignorewarnings

##──── Obfuscate internal field/method names aggressively ────────────────────##
# Do NOT keep any com.dex2c.mega.** member names — let R8 rename them all.
# The only exceptions are the Android lifecycle hooks already covered above.

##──── Remove all logging in release ─────────────────────────────────────────##
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
    public static java.lang.String getStackTraceString(...);
}

##──── apksig library — used by reflection internally ────────────────────────##
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

##──── Enum optimisation ─────────────────────────────────────────────────────##
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
