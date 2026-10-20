package com.sushant.e2eechat;

import android.view.Window;
import android.view.WindowManager;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Small local Capacitor plugin used by the app lock (public/applock.js):
 *
 *  - setSecure({ enabled })   turns Android's FLAG_SECURE on/off. While on, the
 *                             OS blocks screenshots / screen recording AND shows
 *                             a blank tile in the "recent apps" switcher.
 *  - biometricAvailable()     { available: boolean } - is a fingerprint enrolled?
 *  - authenticate({ title, subtitle, cancel })
 *                             shows the system fingerprint prompt, resolves
 *                             { ok: true } on success or { ok: false, error }.
 *
 * Exposed to JavaScript as Capacitor.Plugins.AppSecurity.
 */
@CapacitorPlugin(name = "AppSecurity")
public class AppSecurityPlugin extends Plugin {

    @PluginMethod
    public void setSecure(PluginCall call) {
        final boolean enabled = Boolean.TRUE.equals(call.getBoolean("enabled", true));
        getActivity().runOnUiThread(() -> {
            Window window = getActivity().getWindow();
            if (enabled) {
                window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
            call.resolve();
        });
    }

    @PluginMethod
    public void biometricAvailable(PluginCall call) {
        int can = BiometricManager.from(getContext())
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        JSObject ret = new JSObject();
        ret.put("available", can == BiometricManager.BIOMETRIC_SUCCESS);
        call.resolve(ret);
    }

    @PluginMethod
    public void authenticate(PluginCall call) {
        final String title = call.getString("title", "Unlock");
        final String subtitle = call.getString("subtitle", "");
        final String cancel = call.getString("cancel", "Use PIN");

        getActivity().runOnUiThread(() -> {
            BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    JSObject ret = new JSObject();
                    ret.put("ok", true);
                    call.resolve(ret);
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    JSObject ret = new JSObject();
                    ret.put("ok", false);
                    ret.put("error", errString == null ? "" : errString.toString());
                    call.resolve(ret);
                }
                // onAuthenticationFailed (a wrong finger) is ignored: the system
                // prompt stays open and lets the person try again.
            };

            BiometricPrompt prompt = new BiometricPrompt(
                    getActivity(), ContextCompat.getMainExecutor(getContext()), callback);

            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setNegativeButtonText(cancel)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build();
            prompt.authenticate(info);
        });
    }
}
