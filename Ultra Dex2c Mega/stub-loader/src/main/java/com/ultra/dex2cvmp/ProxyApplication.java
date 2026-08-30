package com.ultra.dex2cvmp;

import android.app.Application;
import android.content.Context;

import com.ultra.dex2cvmp.data.Const;
import com.ultra.dex2cvmp.utils.DexCrypto;
import com.ultra.dex2cvmp.utils.DexProtector;

/**
 * Stub Application — stays resident only until the real Application is swapped in.
 *
 * Design (mirrors DPT-Shell's approach):
 *
 *   attachBaseContext() — decrypts + loads the protected DEX shards via
 *     DexProtector.install(). Installs InMemoryDexClassLoader and re-parents
 *     LoadedApk.mClassLoader.  No ActivityThread reflection here.
 *
 *   onCreate() — calls nativeSwapApplication() which does ALL ActivityThread
 *     reflection in native C inside libphantom.so (OLLVM-obfuscated):
 *       • mBoundApplication / AppBindData / LoadedApk — className patched
 *       • Instrumentation.newApplication() — real Application created + attached
 *       • mAllApplications swap — atomic, mApplication never null
 *       • mProviderMap patched via raw JNI jobjects — no Java generics,
 *         no ClassCastException possible on any Android version
 *     Then calls realApp.onCreate().
 *
 * Zero Java reflection in this file — all ActivityThread manipulation is hidden
 * inside the obfuscated native blob and invisible in the stub DEX string pool.
 */
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
        // All ActivityThread swap logic lives in native C (phantom_key.c).
        // Raw JNI jobject pointers are used throughout — no Java generics,
        // no ClassCastException possible regardless of Android version.
        Application realApp = DexCrypto.nativeSwapApplication(
                getClassLoader(),
                Const.getRealApp(),
                getBaseContext());
        if (realApp != null) {
            realApp.onCreate();
        }
    }
}
