package org.meshpn.client;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** Android 6 has no excludeRoute(): cover IPv4 with the exit /32 removed. */
final class Ipv4Routes {
    static final class Route {
        final InetAddress address;
        final int prefix;
        Route(long network,int prefix) throws Exception {
            address=InetAddress.getByAddress(new byte[]{(byte)(network>>>24),(byte)(network>>>16),(byte)(network>>>8),(byte)network});
            this.prefix=prefix;
        }
        public String toString(){return address.getHostAddress()+"/"+prefix;}
    }
    static List<Route> excluding(String exit) throws Exception {
        byte[] bytes=TcpProbe.numericAddress(exit).getAddress();long ip=0;
        for(byte b:bytes)ip=(ip<<8)|(b&255);
        List<Route> routes=new ArrayList<>();
        for(int prefix=1;prefix<=32;prefix++){
            long bit=1L<<(32-prefix),mask=(0xffffffffL<<(32-prefix))&0xffffffffL;
            Route route=new Route((ip^bit)&mask,prefix);
            // Builder on API 23 rejects a loopback base. Such a CIDR is wholly
            // inside 127/8, which remains local regardless of the VPN routes.
            if(!route.address.isLoopbackAddress())routes.add(route);
        }
        return routes;
    }
}
