package org.meshpn.client;
import org.junit.Test;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.Assert.*;

public class HttpsProbeTest {
    static class Connection extends HttpURLConnection {
        Connection() throws Exception{super(new URL("https://example.org/"));}
        public void connect(){}
        public void disconnect(){}
        public boolean usingProxy(){return false;}
        public int getResponseCode(){assertFalse(getUseCaches());assertEquals("HEAD",getRequestMethod());return 204;}
    }
    @Test public void resultDoesNotClaimFreshDnsAndCacheIsDisabled() throws Exception {
        CountDownLatch done=new CountDownLatch(1);AtomicReference<String> text=new AtomicReference<>();
        assertTrue(HttpsProbe.start(2000,Connection::new,s->{text.set(s);done.countDown();}));
        assertTrue(done.await(2,TimeUnit.SECONDS));assertTrue(text.get().contains("HTTP 204"));assertTrue(text.get().contains("DNS-кэша"));
        // Completion notification precedes resource cleanup by a few instructions.
        Thread.sleep(30);
    }
    @Test public void hungResolverHasDeadlineAndCannotSpawnUnboundedWorkers() throws Exception {
        CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),done=new CountDownLatch(1),cleaned=new CountDownLatch(1);
        AtomicInteger replies=new AtomicInteger();AtomicReference<String> result=new AtomicReference<>();
        try{
            assertTrue(HttpsProbe.start(100,()->{
                entered.countDown();assertTrue(release.await(3,TimeUnit.SECONDS));
                return new Connection(){public void disconnect(){cleaned.countDown();}};
            },s->{replies.incrementAndGet();result.set(s);done.countDown();}));
            assertTrue(entered.await(1,TimeUnit.SECONDS));assertTrue(done.await(1,TimeUnit.SECONDS));
            assertTrue(result.get().contains("лимит времени"));
            assertFalse(HttpsProbe.start(100,Connection::new,s->fail("duplicate probe")));
        }finally{release.countDown();}
        assertTrue(cleaned.await(1,TimeUnit.SECONDS));Thread.sleep(30);assertEquals(1,replies.get());
    }
}
