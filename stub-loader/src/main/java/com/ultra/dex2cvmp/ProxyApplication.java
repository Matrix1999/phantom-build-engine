package com.ultra.dex2cvmp;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.ArrayMap;



import com.ultra.dex2cvmp.data.Const;
import com.ultra.dex2cvmp.utils.DexProtector;
import com.ultra.dex2cvmp.utils.Reflect;

import java.util.ArrayList;
import java.util.Iterator;

public class ProxyApplication extends Application {
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            new DexProtector(base).install(base);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Application app = realApplication();
        if (app != null) {
            app.onCreate();
        }
    }

    private Application realApplication() {
        // ── 1. Collect all references ─────────────────────────────────────────
        Object currentActivityThread = Reflect.invokeMethod(
                "android.app.ActivityThread", null,
                "currentActivityThread", new Object[]{}, null);
        Object mBoundApplication = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread, "mBoundApplication");
        Object loadedApkInfo = Reflect.getFieldValue(
                "android.app.ActivityThread$AppBindData", mBoundApplication, "info");
        Object oldApplication = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread, "mInitialApplication");
        ArrayList<Application> mAllApplications = (ArrayList<Application>) Reflect
                .getFieldValue("android.app.ActivityThread", currentActivityThread, "mAllApplications");
        ApplicationInfo loadedApkAppInfo = (ApplicationInfo) Reflect
                .getFieldValue("android.app.LoadedApk", loadedApkInfo, "mApplicationInfo");
        ApplicationInfo appBindDataAppInfo = (ApplicationInfo) Reflect
                .getFieldValue("android.app.ActivityThread$AppBindData", mBoundApplication, "appInfo");
        Object instrumentation = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread, "mInstrumentation");
        ClassLoader cl = (ClassLoader) Reflect.getFieldValue(
                "android.app.LoadedApk", loadedApkInfo, "mClassLoader");

        // ── 2. Patch className so the new Application is the real app ─────────
        String realAppClass = Const.getRealApp();
        if (loadedApkAppInfo  != null) loadedApkAppInfo.className  = realAppClass;
        if (appBindDataAppInfo != null) appBindDataAppInfo.className = realAppClass;

        // ── 3. Create the real Application WITHOUT nulling mApplication ────────
        //
        // ROOT CAUSE of the VMP-mode crash (TheRouterLibThread NPE):
        //   Android initialises ContentProviders BEFORE calling
        //   ProxyApplication.onCreate().  TheRouter's ContentProvider spawns
        //   background threads in ContentProvider.onCreate().  Those threads
        //   call getApplicationContext() concurrently.  The old approach:
        //
        //     mApplication = null;          ← window opens
        //     makeApplication();            ← slow in VMP (large DEX, VMP runtime
        //                                     initialises on first class load)
        //     // mApplication = realApp     ← window closes inside makeApplication
        //
        //   In dex2c mode the DEX is tiny (method bodies are native stubs) so
        //   makeApplication() finishes before the background thread is scheduled.
        //   In VMP mode the DEX is large so the window is wide enough to be hit.
        //
        // FIX — atomic swap, mApplication is NEVER null:
        //   Call Instrumentation.newApplication() directly while mApplication is
        //   still ProxyApplication.  This creates and attaches the real Application
        //   object.  Then swap mApplication from ProxyApplication → realApp in one
        //   assignment.  Any thread calling getApplicationContext() concurrently
        //   sees either ProxyApplication (before swap) or realApp (after swap),
        //   never null.
        Application app = null;
        try {
            // Instrumentation.newApplication(ClassLoader, String, Context)
            // is public and stable across all Android versions.
            // It instantiates the class, calls Application.attach(context)
            // which calls attachBaseContext — same as makeApplication() does.
            app = (Application) Reflect.invokeMethod(
                    "android.app.Instrumentation", instrumentation,
                    "newApplication",
                    new Object[]{cl, realAppClass, getBaseContext()},
                    ClassLoader.class, String.class, Context.class);
        } catch (Throwable ignored) {
            // Fallback: old null+makeApplication path (narrow window, still safe
            // for dex2c mode and for devices where newApplication() signature
            // differs from the expected form above).
        }

        if (app == null) {
            // Fallback — minimise null window same as before
            Reflect.setFieldValue("android.app.LoadedApk", loadedApkInfo, "mApplication", null);
            app = (Application) Reflect.invokeMethod(
                    "android.app.LoadedApk", loadedApkInfo, "makeApplication",
                    new Object[]{false, null},
                    boolean.class, Instrumentation.class);
            // makeApplication() adds app to mAllApplications and sets mApplication
            // internally, so skip those steps below.
            Reflect.setFieldValue("android.app.ActivityThread",
                    currentActivityThread, "mInitialApplication", app);
            patchProviders(currentActivityThread, app);
            return app;
        }

        // ── 4. Update mAllApplications ────────────────────────────────────────
        if (mAllApplications != null) {
            mAllApplications.remove(oldApplication);
            mAllApplications.add(app);
        }

        // ── 5. Atomic swap: ProxyApplication → realApp (never null) ──────────
        Reflect.setFieldValue("android.app.LoadedApk",     loadedApkInfo,           "mApplication",       app);
        Reflect.setFieldValue("android.app.ActivityThread", currentActivityThread,   "mInitialApplication", app);

        // ── 6. Patch ContentProvider contexts ─────────────────────────────────
        patchProviders(currentActivityThread, app);

        return app;
    }

    /**
     * Update every in-process ContentProvider's mContext from the old
     * ProxyApplication to the newly installed real Application.
     *
     * ContentProviders are installed by ActivityThread BEFORE our
     * ProxyApplication.onCreate() runs, so their stored context still
     * points to ProxyApplication at this point.
     */
    private void patchProviders(Object currentActivityThread, Application realApp) {
        // mProviderMap is ArrayMap<String, ProviderClientRecord> — NOT <String, String>.
        // Using raw ArrayMap avoids the ClassCastException on all Android versions.
        @SuppressWarnings("rawtypes")
        ArrayMap mProviderMap = (ArrayMap) Reflect.getFieldOjbect(
                "android.app.ActivityThread", currentActivityThread, "mProviderMap");
        if (mProviderMap == null) return;
        for (Object providerClientRecord : mProviderMap.values()) {
            if (providerClientRecord == null) continue;
            Object localProvider = Reflect.getFieldOjbect(
                    "android.app.ActivityThread$ProviderClientRecord",
                    providerClientRecord, "mLocalProvider");
            if (localProvider != null) {
                Reflect.setFieldOjbect("android.content.ContentProvider",
                        "mContext", localProvider, realApp);
            }
        }
    }
}