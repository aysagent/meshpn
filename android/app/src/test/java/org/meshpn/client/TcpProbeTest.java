package org.meshpn.client;

import org.junit.Test;
import java.io.IOException;
import java.net.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.Assert.*;

public class TcpProbeTest {
    @Test public void connectsWithoutSendingPayloadAndClosesSocket() throws Exception {
        try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){
            listener.setSoTimeout(1000);
            TcpProbe.Result r=TcpProbe.run("127.0.0.1",listener.getLocalPort(),1000,s->{
                assertFalse(s.isConnected());return true;
            },()->false);
            assertTrue(r.toString(),r.ok());assertTrue(r.localPort>0);assertEquals("127.0.0.1",r.localAddress);
            try(Socket accepted=listener.accept()){accepted.setSoTimeout(1000);assertEquals(-1,accepted.getInputStream().read());}
        }
    }
    @Test public void refusedProtectionNeverConnectsAndClosesSocket() throws Exception {
        final Socket[] seen=new Socket[1];
        TcpProbe.Result r=TcpProbe.run("127.0.0.1",443,1000,s->{seen[0]=s;return false;},()->false);
        assertEquals("socket_prepare_refused",r.code);assertTrue(seen[0].isClosed());
    }
    @Test public void cancellationBeforeSocketDoesNotCallProtection(){
        TcpProbe.Result r=TcpProbe.run("127.0.0.1",443,1000,s->{fail("cancelled");return true;},()->true);
        assertEquals("cancelled",r.code);
    }
    @Test public void cancellationDuringProtectionClosesSocket(){
        AtomicBoolean stopped=new AtomicBoolean();final Socket[] seen=new Socket[1];
        TcpProbe.Result r=TcpProbe.run("127.0.0.1",443,1000,s->{seen[0]=s;stopped.set(true);return true;},stopped::get);
        assertEquals("cancelled",r.code);assertTrue(seen[0].isClosed());
    }
    @Test public void bindingFailureIsSanitizedAndSocketClosed(){
        final Socket[] seen=new Socket[1];
        TcpProbe.Result r=TcpProbe.run("127.0.0.1",443,1000,s->{seen[0]=s;throw new IOException("secret");},()->false);
        assertEquals("IOException",r.code);assertEquals("protect_or_bind",r.stage);
        assertFalse(r.toString().contains("secret"));assertTrue(seen[0].isClosed());
    }
    @Test public void invalidAddressCannotTriggerDnsOrOpenSocket(){
        for(String value:new String[]{"example.org","127.0.0.1.extra","256.1.1.1","1.2.3.-1","1.2.3.4\n",""}){
            TcpProbe.Result r=TcpProbe.run(value,443,1000,s->{fail("invalid numeric endpoint");return true;},()->false);
            assertEquals("endpoint",r.stage);assertFalse(r.ok());
        }
    }
    @Test public void invalidTimeoutAndPortAreRejected(){
        for(int timeout:new int[]{0,-1,10001})assertFalse(TcpProbe.run("127.0.0.1",443,timeout,s->true,()->false).ok());
        assertEquals("endpoint",TcpProbe.run("127.0.0.1",65536,1000,s->true,()->false).stage);
    }
    @Test public void handoffReceivesConnectedSocketBeforeJavaClose() throws Exception {
        final Socket[] handed=new Socket[1];
        try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){
            TcpProbe.Result r=TcpProbe.run("127.0.0.1",listener.getLocalPort(),1000,s->true,()->false,s->{
                assertTrue(s.isConnected());assertFalse(s.isClosed());handed[0]=s;
            });
            assertTrue(r.toString(),r.ok());assertTrue(handed[0].isClosed());
        }
    }
    @Test public void failedHandoffClosesSocketAndDoesNotExposeException() throws Exception {
        final Socket[] handed=new Socket[1];
        try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){
            TcpProbe.Result r=TcpProbe.run("127.0.0.1",listener.getLocalPort(),1000,s->true,()->false,s->{
                handed[0]=s;throw new IOException("private handoff data");
            });
            assertFalse(r.ok());assertEquals("handoff",r.stage);assertTrue(handed[0].isClosed());
            assertFalse(r.toString().contains("private"));
        }
    }
    @Test public void explicitSourceBindIsUsedByActualTcpConnection() throws Exception {
        try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){
            listener.setSoTimeout(1000);
            TcpProbe.Result r=TcpProbe.run("127.0.0.1",listener.getLocalPort(),1000,s->{
                s.bind(new InetSocketAddress(TcpProbe.numericAddress("127.0.0.1"),0));return true;
            },()->false);
            assertTrue(r.toString(),r.ok());assertEquals("127.0.0.1",r.localAddress);
            try(Socket incoming=listener.accept()){assertEquals(r.localPort,incoming.getPort());}
        }
    }
}
