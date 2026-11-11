package org.meshpn.client;

import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class Ipv4RoutesTest {
    private static long number(String ip) throws Exception {
        long n=0;for(byte b:TcpProbe.numericAddress(ip).getAddress())n=(n<<8)|(b&255);return n;
    }
    private static int matches(List<Ipv4Routes.Route> routes,long ip) throws Exception {
        int n=0;for(Ipv4Routes.Route r:routes){long base=number(r.address.getHostAddress()),size=1L<<(32-r.prefix);if(ip>=base&&ip<base+size)n++;}return n;
    }
    @Test public void onlyExitIsExcludedForProjectorServer() throws Exception {
        List<Ipv4Routes.Route> routes=Ipv4Routes.excluding("84.201.14.124");assertEquals(32,routes.size());
        assertEquals(0,matches(routes,number("84.201.14.124")));
        for(String ip:new String[]{"84.201.14.123","84.201.14.125","1.1.1.1","8.8.8.8","192.168.1.16","10.99.0.1"})assertEquals(ip,1,matches(routes,number(ip)));
    }
    @Test public void partitionHasNoOverlapOrExternalGaps() throws Exception {
        List<String> exits=new ArrayList<>(Arrays.asList("0.0.0.0","255.255.255.255","128.0.0.0","126.255.255.255","127.0.0.1","84.201.14.124"));
        Random random=new Random(23);for(int i=0;i<128;i++)exits.add((random.nextInt(223)+1)+"."+random.nextInt(256)+"."+random.nextInt(256)+"."+random.nextInt(256));
        for(String exit:exits){
            List<long[]> ranges=new ArrayList<>();long excluded=number(exit);
            for(Ipv4Routes.Route r:Ipv4Routes.excluding(exit)){
                assertFalse(r.address.isLoopbackAddress());assertTrue(r.prefix>=1&&r.prefix<=32);
                long base=number(r.address.getHostAddress()),size=1L<<(32-r.prefix);
                assertEquals(0,base%size);assertFalse(excluded>=base&&excluded<base+size);
                ranges.add(new long[]{base,base+size});
            }
            ranges.sort(Comparator.comparingLong(r->r[0]));long cursor=0;
            for(long[] r:ranges){assertTrue(r[0]>=cursor);gap(cursor,r[0],excluded);cursor=r[1];}
            gap(cursor,1L<<32,excluded);
        }
    }
    private static void gap(long begin,long end,long exit){
        long loopBegin=0x7f000000L,loopEnd=0x80000000L;
        long permitted=Math.max(0,Math.min(end,loopEnd)-Math.max(begin,loopBegin));
        if(exit>=begin&&exit<end&&(exit<loopBegin||exit>=loopEnd))permitted++;
        assertEquals("unexpected route gap",end-begin,permitted);
    }
    @Test public void android6LoopbackBaseIsNeverPassedToBuilder() throws Exception {
        for(Ipv4Routes.Route r:Ipv4Routes.excluding("126.1.2.3"))assertFalse(r.address.isLoopbackAddress());
        assertEquals(1,matches(Ipv4Routes.excluding("126.1.2.3"),number("126.1.2.4")));
    }
    @Test public void invalidExitCannotGenerateBroadDefaultRoute() throws Exception {
        for(String exit:new String[]{"exit.example","1.2.3.256","::1"}){
            try{Ipv4Routes.excluding(exit);fail("accepted invalid exit");}catch(Exception expected){}
        }
    }
}
