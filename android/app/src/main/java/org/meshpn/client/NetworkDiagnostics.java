package org.meshpn.client;

import android.content.Context;
import android.net.*;

final class NetworkDiagnostics {
    static boolean physical(NetworkCapabilities c){
        return c!=null&&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)&&!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }
    static Network physicalNetwork(Context context){
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network active=cm.getActiveNetwork();
        java.util.List<UplinkSelection.Candidate<Network>> candidates=new java.util.ArrayList<>();
        for(Network network:cm.getAllNetworks()){
            NetworkCapabilities c=cm.getNetworkCapabilities(network);if(c==null)continue;
            candidates.add(new UplinkSelection.Candidate<>(network,c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),c.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)));
        }
        return UplinkSelection.choose(active,candidates);
    }
    static java.net.InetAddress physicalIpv4(Context context,Network network){
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(!physical(cm.getNetworkCapabilities(network)))return null;
        LinkProperties link=cm.getLinkProperties(network);if(link==null)return null;
        for(LinkAddress item:link.getLinkAddresses()){
            java.net.InetAddress address=item.getAddress();
            if(address instanceof java.net.Inet4Address&&!address.isAnyLocalAddress()&&!address.isLoopbackAddress()
                &&!address.isLinkLocalAddress()&&!address.isMulticastAddress())return address;
        }
        return null;
    }
    static String snapshot(Context context){
        StringBuilder out=new StringBuilder();
        try{
            ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
            out.append("active_network=").append(cm.getActiveNetwork()).append('\n');
            Network[] all=cm.getAllNetworks();
            for(int i=0;i<Math.min(all.length,8);i++){
                Network n=all[i];NetworkCapabilities c=cm.getNetworkCapabilities(n);
                out.append("network=").append(n).append(" physical_internet=").append(physical(c));
                if(c!=null)out.append(" wifi=").append(c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                    .append(" cellular=").append(c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
                    .append(" ethernet=").append(c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
                    .append(" vpn=").append(c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
                    .append(" validated=").append(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
                LinkProperties link=cm.getLinkProperties(n);
                if(link!=null){
                    out.append(" interface=").append(link.getInterfaceName());
                    int count=0;for(LinkAddress address:link.getLinkAddresses()){
                        if(count++>=8)break;out.append(" address=").append(address.getAddress().getHostAddress()).append('/').append(address.getPrefixLength());
                    }
                    int defaults=0;for(RouteInfo route:link.getRoutes())if(route.isDefaultRoute())defaults++;
                    out.append(" default_routes=").append(defaults);
                }
                out.append('\n');
            }
        }catch(Exception e){out.append("network_inventory_unavailable=").append(e.getClass().getSimpleName()).append('\n');}
        return out.toString();
    }
}
