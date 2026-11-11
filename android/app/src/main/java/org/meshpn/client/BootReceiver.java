package org.meshpn.client;
import android.content.*;
import android.net.VpnService;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c,Intent i){
        try{
            if(i!=null&&Intent.ACTION_BOOT_COMPLETED.equals(i.getAction())&&ConfigStore.prefs(c).getBoolean("autostart",false)
                &&VpnService.prepare(c)==null){ConfigStore.active(c);VpnClientService.start(c);}
        }catch(Exception ignored){} // Some TV firmware omits or rejects VPN consent.
    }
}
