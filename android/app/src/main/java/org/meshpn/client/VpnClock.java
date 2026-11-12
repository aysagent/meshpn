package org.meshpn.client;

/** Explicit, process-local UTC correction. Never changes the device clock. */
final class VpnClock {
    interface Source {long now();}
    static final int MAX_MINUTES=24*60;
    private final Source wall,elapsed;
    private boolean manual;
    private long baseWall,baseElapsed,baseUtc;
    private int minutes;
    private String reason="system";
    VpnClock(Source wall,Source elapsed){this.wall=wall;this.elapsed=elapsed;}
    synchronized long nowMillis(){
        long w=wall.now(),e=elapsed.now();
        if(manual){
            long age=e-baseElapsed;
            // If Android/NTP repairs the system clock, never add the old
            // correction a second time. elapsedRealtime includes deep sleep.
            if(age<0||Math.abs((w-baseWall)-age)>5000){clear("system_clock_changed");return w;}
            return baseUtc+age;
        }
        return w;
    }
    synchronized void setMinutes(int value){
        if(value<-MAX_MINUTES||value>MAX_MINUTES)throw new IllegalArgumentException("clock_correction_range");
        if(value==0){clear("system");return;}
        long w=wall.now(),e=elapsed.now(),utc=w+value*60000L;
        // ARMv7 API 23 time_t is signed 32 bit. Do not silently overflow it.
        if(utc<0||utc/1000>Integer.MAX_VALUE)throw new IllegalArgumentException("clock_epoch_range");
        baseWall=w;baseElapsed=e;baseUtc=utc;minutes=value;manual=true;reason="manual";
    }
    synchronized void reset(){clear("system");}
    private void clear(String why){manual=false;minutes=0;reason=why;}
    synchronized int minutes(){nowMillis();return minutes;}
    synchronized String mode(){nowMillis();return reason;}
}
