package org.meshpn.client;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class VpnConsentTest {
    static class Host implements VpnConsent.Host<String> {
        boolean granted;int launches,starts,prepares;long now=100;String message="";
        String failure;final List<String> events=new ArrayList<>();
        public String prepare(){prepares++;if("prepare".equals(failure))throw new SecurityException("PRIVATE VALUE");return granted?null:"system-dialog";}
        public void launch(String intent){assertEquals("system-dialog",intent);if("launch".equals(failure))throw new IllegalStateException("PRIVATE VALUE");launches++;}
        public void start(){if("start".equals(failure))throw new IllegalStateException("PRIVATE VALUE");starts++;}
        public void event(String s){events.add(s);}
        public void message(String s){message=s;}
        public long elapsed(){return now;}
    }
    private VpnConsent<String> flow(Host h){return new VpnConsent<>(h,false,0);}
    @Test public void existingGrantStartsWithoutDialog(){
        Host h=new Host();h.granted=true;VpnConsent<String> f=flow(h);f.request();
        assertEquals(1,h.starts);assertEquals(0,h.launches);assertFalse(f.pending());
    }
    @Test public void immediateCancellationCannotStartAndRecordsRecheck(){
        Host h=new Host();VpnConsent<String> f=flow(h);f.request();h.now=125;f.result(0);
        assertEquals(0,h.starts);assertEquals(2,h.prepares);assertFalse(f.pending());
        assertTrue(h.events.contains("result=0 elapsed_ms=25"));assertTrue(h.events.contains("recheck=confirmation_required"));
        assertTrue(h.message.contains("сбой окна"));
    }
    @Test public void okWithoutActualGrantIsNotEnough(){
        Host h=new Host();VpnConsent<String> f=flow(h);f.request();f.result(-1);
        assertEquals(0,h.starts);assertTrue(h.message.contains("всё ещё требуется"));
    }
    @Test public void cancelledResultWithRealGrantCanStart(){
        Host h=new Host();VpnConsent<String> f=flow(h);f.request();h.granted=true;f.result(0);
        assertEquals(1,h.starts);assertTrue(h.events.contains("recheck=granted"));
    }
    @Test public void okAndGrantStartsOnceDespiteDuplicateCallback(){
        Host h=new Host();VpnConsent<String> f=flow(h);f.request();h.granted=true;f.result(-1);f.result(-1);
        assertEquals(1,h.starts);assertTrue(h.events.contains("unexpected_result=-1"));
    }
    @Test public void pendingRequestSuppressesDoubleClick(){
        Host h=new Host();VpnConsent<String> f=flow(h);f.request();f.request();
        assertEquals(1,h.launches);assertEquals(1,h.prepares);assertTrue(f.pending());
    }
    @Test public void restoredActivityCompletesPendingConsent(){
        Host h=new Host();VpnConsent<String> old=flow(h);old.request();
        VpnConsent<String> restored=new VpnConsent<>(h,old.pending(),old.started());
        h.granted=true;restored.result(-1);assertEquals(1,h.starts);assertFalse(restored.pending());
    }
    @Test public void unsolicitedResultDoesNotStartEvenWithGrant(){
        Host h=new Host();h.granted=true;flow(h).result(-1);assertEquals(0,h.starts);assertEquals(0,h.prepares);
    }
    @Test public void failuresNameStageWithoutLeakingExceptionMessage(){
        for(String stage:new String[]{"prepare","launch","start"}){
            Host h=new Host();h.failure=stage;h.granted=stage.equals("start");VpnConsent<String> f=flow(h);f.request();
            assertFalse(f.pending());assertEquals(0,h.starts);assertFalse(h.events.toString().contains("PRIVATE"));assertFalse(h.message.contains("PRIVATE"));
            assertTrue(h.events.toString().contains(stage.equals("start")?"service_start_error=":"_error="));
        }
    }
    @Test public void recheckFailureDoesNotTrustOk(){
        Host h=new Host();VpnConsent<String> f=flow(h);f.request();h.failure="prepare";f.result(-1);
        assertEquals(0,h.starts);assertFalse(f.pending());assertTrue(h.events.contains("recheck_error=SecurityException"));
    }
}
