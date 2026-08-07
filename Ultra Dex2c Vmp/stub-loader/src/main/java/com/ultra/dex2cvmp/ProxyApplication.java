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
        // ── 1. Collect all references BEFORE touching mApplication ────────────
        // This minimises the null window that causes a race with background
        // threads (e.g. TheRouterLibThread) that call getApplicationContext()
        // concurrently.  Previously mApplication was nulled here and then
        // 7+ reflection operations ran before makeApplication() restored it;
        // any thread calling getApplicationContext() in that window got null
        // and Kotlin's non-null cast threw NullPointerException.
        Object currentActivityThread = Reflect.invokeMethod("android.app.ActivityThread", null, "currentActivityThread", new Object[]{}, null);
        Object mBoundApplication = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread,
                "mBoundApplication");
        Object loadedApkInfo = Reflect.getFieldValue(
                "android.app.ActivityThread$AppBindData",
                mBoundApplication, "info");
        Object oldApplication = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread,
                "mInitialApplication");
        ArrayList<Application> mAllApplications = (ArrayList<Application>) Reflect
                .getFieldValue("android.app.ActivityThread",
                        currentActivityThread, "mAllApplications");
        ApplicationInfo loadedApk = (ApplicationInfo) Reflect
                .getFieldValue("android.app.LoadedApk", loadedApkInfo,
                        "mApplicationInfo");
        ApplicationInfo appBindData = (ApplicationInfo) Reflect
                .getFieldValue("android.app.ActivityThread$AppBindData",
                        mBoundApplication, "appInfo");

        // ── 2. Apply className + list changes (still no null window yet) ──────
        if (loadedApk != null) {
            loadedApk.className = Const.getRealApp();
        }
        if (appBindData != null) {
            appBindData.className = Const.getRealApp();
        }
        if (mAllApplications != null) {
            mAllApplications.remove(oldApplication);
        }

        // ── 3. Null + makeApplication back-to-back (minimise null window) ─────
        // getApplicationContext() returns null between these two lines.
        // Keeping them adjacent means the window is only as wide as the
        // makeApplication() JNI call itself, not 7+ extra reflection ops.
        Reflect.setFieldValue("android.app.LoadedApk", loadedApkInfo, "mApplication", null);
        Application app = (Application) Reflect.invokeMethod(
                "android.app.LoadedApk", loadedApkInfo, "makeApplication",
                new Object[]{false, null},
                boolean.class, Instrumentation.class);

        Reflect.setFieldValue("android.app.ActivityThread", currentActivityThread, "mInitialApplication", app);

        //
        ArrayMap<String, String> mProviderMap = (ArrayMap<String, String>) Reflect.getFieldOjbect(
                "android.app.ActivityThread", currentActivityThread,
                "mProviderMap");
        Iterator<String> it = null;
        if (mProviderMap != null) {
            it = mProviderMap.values().iterator();
        }
        if (it != null) {
            while (it.hasNext()) {
                Object providerClientRecord = it.next();
                Object localProvider = Reflect.getFieldOjbect(
                        "android.app.ActivityThread$ProviderClientRecord",
                        providerClientRecord, "mLocalProvider");
                if (localProvider != null) {
                    Reflect.setFieldOjbect("android.content.ContentProvider",
                            "mContext", localProvider, app);
                }
            }
        }
        return app;
    }
}