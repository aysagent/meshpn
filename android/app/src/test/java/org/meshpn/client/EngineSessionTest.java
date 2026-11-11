package org.meshpn.client;
import org.junit.Test;
import java.util.concurrent.*;
import static org.junit.Assert.*;

public class EngineSessionTest {
    static class Backend implements EngineSession.Backend {
        int creates,stops,releases,changes;
        public long create(){creates++;return 42;}
        public void stop(long h){assertEquals(42,h);stops++;}
        public void release(long h){assertEquals(42,h);releases++;}
        public void networkChanged(long h){assertEquals(42,h);changes++;}
    }
    @Test public void cancellationBeforeOpenDoesNotLoadNative(){
        Backend b=new Backend();EngineSession s=new EngineSession(b);s.stop();assertEquals(0,s.open());s.close();
        assertEquals(0,b.creates);assertEquals(0,b.releases);
    }
    @Test public void failedLibraryLoadDoesNotInvokeCleanupOnBrokenClass(){
        Backend b=new Backend(){public long create(){throw new UnsatisfiedLinkError("fixture");}};
        EngineSession s=new EngineSession(b);
        try{s.open();fail();}catch(UnsatisfiedLinkError expected){}
        s.stop();s.close();assertEquals(0,b.releases);assertEquals(0,b.stops);
    }
    @Test public void zeroHandleFailsWithoutReleasingZero(){
        Backend b=new Backend(){public long create(){return 0;}};EngineSession s=new EngineSession(b);
        try{s.open();fail();}catch(IllegalStateException expected){}
        s.close();assertEquals(0,b.releases);
    }
    @Test public void callbacksAfterCloseAndRepeatedStopAreIgnored(){
        Backend b=new Backend();EngineSession s=new EngineSession(b);assertEquals(42,s.open());s.networkChanged();
        s.stop();s.stop();s.networkChanged();s.close();s.close();s.networkChanged();
        assertEquals(1,b.creates);assertEquals(1,b.stops);assertEquals(1,b.releases);assertEquals(1,b.changes);
        assertEquals(0,s.open());
    }
    @Test public void stopDoesNotWaitForLibraryInitializationAndLateHandleIsReleased() throws Exception {
        CountDownLatch entered=new CountDownLatch(1),resume=new CountDownLatch(1);
        Backend b=new Backend(){public long create(){entered.countDown();try{assertTrue(resume.await(3,TimeUnit.SECONDS));}catch(InterruptedException e){throw new AssertionError(e);}return super.create();}};
        EngineSession s=new EngineSession(b);ExecutorService pool=Executors.newFixedThreadPool(2);
        try{
            Future<Long> opening=pool.submit(s::open);assertTrue(entered.await(1,TimeUnit.SECONDS));
            pool.submit(()->{s.stop();s.close();}).get(1,TimeUnit.SECONDS);
            resume.countDown();assertEquals(Long.valueOf(0),opening.get(1,TimeUnit.SECONDS));
            assertEquals(1,b.releases);assertEquals(0,b.stops);
        }finally{resume.countDown();pool.shutdownNow();}
    }
}
