package org.meshpn.client;

/** Select only an Internet-capable physical network, never the VPN default. */
final class UplinkSelection {
    static final class Candidate<T> {
        final T network;
        final boolean internet,notVpn,vpn,validated;
        Candidate(T network,boolean internet,boolean notVpn,boolean vpn,boolean validated){
            this.network=network;this.internet=internet;this.notVpn=notVpn;this.vpn=vpn;this.validated=validated;
        }
    }
    static <T> T choose(T active,Iterable<Candidate<T>> candidates){
        T first=null,validated=null;
        for(Candidate<T> c:candidates){
            if(c.network==null||!c.internet||!c.notVpn||c.vpn)continue;
            if(c.network.equals(active))return c.network;
            if(first==null)first=c.network;
            if(validated==null&&c.validated)validated=c.network;
        }
        return validated!=null?validated:first;
    }
}
