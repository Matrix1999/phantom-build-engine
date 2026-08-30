package com.ultra.dex2cvmp.ui;

import android.app.Application;
import android.content.*;
import android.net.Uri;
import android.os.Build;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import com.ultra.dex2cvmp.service.ProtectionService;

public class ProtectViewModel extends AndroidViewModel {

    private static final String PREFS_NAME        = "dex2c_mega_prefs";
    private static final String KEY_VMP           = "vmp_enabled";
    private static final String KEY_BLOCK_ROOTED  = "block_rooted_enabled";

    private Uri    inputUri;
    private String inputName          = "";
    private boolean signEnabled       = false;
    private boolean vmpEnabled        = false;

    private final MutableLiveData<String>  status     = new MutableLiveData<>("");
    private final MutableLiveData<Integer> progress   = new MutableLiveData<>(0);
    private final MutableLiveData<String>  outputPath = new MutableLiveData<>("");
    private final MutableLiveData<Boolean> running    = new MutableLiveData<>(false);
    private final MutableLiveData<String>  error      = new MutableLiveData<>("");

    // Persisted console log — survives tab switches
    private final StringBuilder consoleLog = new StringBuilder();
    private long protectionStartMs = 0;

    private BroadcastReceiver receiver;

    public ProtectViewModel(Application app) {
        super(app);

        // Restore persisted toggle states
        SharedPreferences prefs = app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        vmpEnabled = prefs.getBoolean(KEY_VMP, false);
        // blockRootedEnabled is NOT cached here — isBlockRootedEnabled() reads
        // SharedPreferences fresh every call so Settings changes are always reflected.

        // Session recovery: if a protection job is still running (same process),
        // restore the running state so the UI can reconnect to it.
        if (ProtectionService.SERVICE_RUNNING) {
            running.setValue(true);
            progress.setValue(ProtectionService.LAST_PROGRESS);
            status.setValue(ProtectionService.LAST_STATUS.isEmpty()
                    ? "Reconnecting to protection service…" : ProtectionService.LAST_STATUS);
        }

        registerReceiver();
    }

    private void registerReceiver() {
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent i) {
                int    pct = i.getIntExtra(ProtectionService.EXTRA_PERCENT, 0);
                String msg = i.getStringExtra(ProtectionService.EXTRA_MSG);
                String out = i.getStringExtra(ProtectionService.EXTRA_OUTPUT);
                String err = i.getStringExtra(ProtectionService.EXTRA_ERROR);

                progress.postValue(pct);
                if (msg != null) status.postValue(msg);
                if (out != null) { outputPath.postValue(out); running.postValue(false); }
                if (err != null) { error.postValue(err);      running.postValue(false); }
            }
        };
        IntentFilter filter = new IntentFilter(ProtectionService.BROADCAST_PROGRESS);
        if (Build.VERSION.SDK_INT >= 33) {
            getApplication().registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            getApplication().registerReceiver(receiver, filter);
        }
    }

    public void setInputUri(Uri uri, String displayName) {
        this.inputUri  = uri;
        this.inputName = displayName;
        outputPath.setValue("");
        progress.setValue(0);
    }

    public Uri    getInputUri()   { return inputUri; }
    public String getInputName()  { return inputName; }

    public boolean isSignEnabled()           { return signEnabled; }
    public void    setSignEnabled(boolean v) { this.signEnabled = v; }

    public boolean isVmpEnabled()            { return vmpEnabled; }
    public void    setVmpEnabled(boolean v) {
        this.vmpEnabled = v;
        getApplication()
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_VMP, v)
            .apply();
    }

    /** Always reads SharedPreferences fresh — never returns a stale cached value. */
    public boolean isBlockRootedEnabled() {
        return getApplication()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_BLOCK_ROOTED, true);
    }
    public void setBlockRootedEnabled(boolean v) {
        getApplication()
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_BLOCK_ROOTED, v)
            .apply();
    }

    public LiveData<String>  getStatus()     { return status; }
    public LiveData<Integer> getProgress()   { return progress; }
    public LiveData<String>  getOutputPath() { return outputPath; }
    public LiveData<Boolean> isRunning()     { return running; }
    public LiveData<String>  getError()      { return error; }

    public String  getConsoleLog()                    { return consoleLog.toString(); }
    public void    appendConsoleLog(String line)      { consoleLog.append(line); }
    public void    clearConsoleLog()                  { consoleLog.setLength(0); }
    public long    getProtectionStartMs()             { return protectionStartMs; }
    public void    setProtectionStartMs(long ms)      { protectionStartMs = ms; }

    public void runProtection(String filterText, boolean sign, boolean vmp, boolean blockRooted) {
        if (inputUri == null || Boolean.TRUE.equals(running.getValue())) return;
        running.setValue(true);
        progress.setValue(5);
        status.setValue("Starting protection...");

        Intent intent = new Intent(getApplication(), ProtectionService.class);
        intent.setAction(ProtectionService.ACTION_START);
        intent.putExtra(ProtectionService.EXTRA_URI,          inputUri);
        intent.putExtra(ProtectionService.EXTRA_FILTER,       filterText);
        intent.putExtra(ProtectionService.EXTRA_SIGN,         sign);
        intent.putExtra(ProtectionService.EXTRA_VMP,          vmp);
        intent.putExtra(ProtectionService.EXTRA_BLOCK_ROOTED, blockRooted);

        if (Build.VERSION.SDK_INT >= 26) {
            getApplication().startForegroundService(intent);
        } else {
            getApplication().startService(intent);
        }
    }

    public void cancel() {
        Intent intent = new Intent(getApplication(), ProtectionService.class);
        intent.setAction(ProtectionService.ACTION_CANCEL);
        getApplication().startService(intent);
        running.setValue(false);
        progress.setValue(0);
        status.setValue("Cancelled.");
    }

    @Override
    protected void onCleared() {
        super.onCleared();
        try { getApplication().unregisterReceiver(receiver); } catch (Exception ignored) {}
    }
}
