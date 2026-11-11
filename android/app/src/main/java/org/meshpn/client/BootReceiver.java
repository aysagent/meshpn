package org.meshpn.client;
import android.content.*;
import android.net.VpnService;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c,Intent i){
        if(Intent.ACTION_BOOT_COMPLETED.equals(i.getAction())&&ConfigStore.prefs(c).getBoolean("autostart",false)
            &&VpnService.prepare(c)==null){
            try{ConfigStore.active(c);VpnClientService.start(c);}catch(Exception ignored){}
        }
    }
}
