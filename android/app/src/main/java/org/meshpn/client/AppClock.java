package org.meshpn.client;

import android.os.SystemClock;

final class AppClock {
    static final VpnClock VPN=new VpnClock(System::currentTimeMillis,SystemClock::elapsedRealtime);
    private AppClock(){}
    static String diagnostic(){
        return "VPN UTC millis: "+VPN.nowMillis()+"\nVPN clock mode: "+VPN.mode()
            +"\nVPN correction minutes: "+VPN.minutes()+"\nClock correction persistence: current app process only";
    }
}
