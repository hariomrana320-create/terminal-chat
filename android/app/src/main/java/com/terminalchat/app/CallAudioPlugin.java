package com.terminalchat.app;

import android.content.Context;
import android.media.AudioManager;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "CallAudio")
public class CallAudioPlugin extends Plugin {

    private AudioManager audioManager;

    @Override
    public void load() {
        audioManager = (AudioManager)
            getContext().getSystemService(Context.AUDIO_SERVICE);
    }

    @PluginMethod
    public void setSpeaker(PluginCall call) {
        if (audioManager == null) {
            call.reject("Audio service unavailable");
            return;
        }

        Boolean enabled = call.getBoolean("enabled");
        if (enabled == null) {
            call.reject("enabled must be true or false");
            return;
        }

        audioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);
        audioManager.setSpeakerphoneOn(enabled);

        JSObject result = new JSObject();
        result.put("speaker", enabled);
        call.resolve(result);
    }

    @PluginMethod
    public void resetAudio(PluginCall call) {
        if (audioManager != null) {
            audioManager.setSpeakerphoneOn(false);
            audioManager.setMode(AudioManager.MODE_NORMAL);
        }
        call.resolve();
    }
}
