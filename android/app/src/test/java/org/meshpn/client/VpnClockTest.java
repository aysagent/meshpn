package org.meshpn.client;
import org.junit.Test;
import static org.junit.Assert.*;

public class VpnClockTest {
    static class Fixture {
        long wall=1794513600000L,elapsed=123456;
        VpnClock clock=new VpnClock(()->wall,()->elapsed);
        void advance(long ms){wall+=ms;elapsed+=ms;}
    }
    @Test public void defaultsToSystemAndManualHourAdvancesAcrossSleep(){
        Fixture f=new Fixture();assertEquals(f.wall,f.clock.nowMillis());
        f.clock.setMinutes(60);assertEquals(f.wall+3600000,f.clock.nowMillis());
        f.advance(7200000);assertEquals(f.wall+3600000,f.clock.nowMillis());assertEquals("manual",f.clock.mode());
    }
    @Test public void ntpRepairDoesNotDoubleApplyCorrection(){
        Fixture f=new Fixture();f.clock.setMinutes(60);f.advance(2000);f.wall+=3600000;
        assertEquals(f.wall,f.clock.nowMillis());assertEquals(0,f.clock.minutes());assertEquals("system_clock_changed",f.clock.mode());
    }
    @Test public void backwardsSystemJumpAlsoInvalidates(){
        Fixture f=new Fixture();f.clock.setMinutes(-60);f.wall-=3600000;
        assertEquals(f.wall,f.clock.nowMillis());assertEquals(0,f.clock.minutes());
    }
    @Test public void smallSystemSlewKeepsMonotonicManualUtc(){
        Fixture f=new Fixture();f.clock.setMinutes(61);long start=f.clock.nowMillis();f.advance(10000);f.wall+=1500;
        assertEquals(start+10000,f.clock.nowMillis());assertEquals(61,f.clock.minutes());
    }
    @Test public void resetAndZeroRestoreSystemClock(){
        Fixture f=new Fixture();f.clock.setMinutes(60);f.clock.reset();assertEquals(f.wall,f.clock.nowMillis());
        f.clock.setMinutes(-60);f.clock.setMinutes(0);assertEquals(f.wall,f.clock.nowMillis());assertEquals("system",f.clock.mode());
    }
    @Test public void restartDoesNotRestoreAnUnverifiedOffset(){
        Fixture f=new Fixture();f.clock.setMinutes(60);VpnClock restarted=new VpnClock(()->f.wall,()->f.elapsed);
        assertEquals(f.wall,restarted.nowMillis());assertEquals(0,restarted.minutes());
    }
    @Test public void elapsedRollbackInvalidatesAnchor(){
        Fixture f=new Fixture();f.clock.setMinutes(60);f.elapsed=0;assertEquals(f.wall,f.clock.nowMillis());assertEquals(0,f.clock.minutes());
    }
    @Test public void invalidCorrectionsAndArm32OverflowAreRejectedWithoutReplacingValidState(){
        Fixture f=new Fixture();f.clock.setMinutes(60);
        for(int n:new int[]{1441,-1441,Integer.MAX_VALUE,Integer.MIN_VALUE}){
            try{f.clock.setMinutes(n);fail();}catch(IllegalArgumentException expected){}
            assertEquals(60,f.clock.minutes());
        }
        f.wall=Integer.MAX_VALUE*1000L;try{f.clock.setMinutes(1);fail();}catch(IllegalArgumentException expected){}
        Fixture g=new Fixture();g.wall=0;try{g.clock.setMinutes(-1);fail();}catch(IllegalArgumentException expected){}
    }
}
