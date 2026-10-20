package com.sushant.e2eechat;

import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Local plugins must be registered BEFORE super.onCreate.
        registerPlugin(AppSecurityPlugin.class);
        super.onCreate(savedInstanceState);

        // Secure by default: no screenshots, blank preview in the recent-apps
        // list. The person can switch this off in Settings (applock.js calls
        // AppSecurity.setSecure on every page load to apply their choice).
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    }
}
