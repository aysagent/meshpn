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
        if(active!=null&&physical(cm.getNetworkCapabilities(active)))return active;
        Network fallback=null;Network[] all=cm.getAllNetworks();
        for(int i=0;i<Math.min(all.length,8);i++){
            NetworkCapabilities c=cm.getNetworkCapabilities(all[i]);if(!physical(c))continue;
            if(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))return all[i];
            if(fallback==null)fallback=all[i];
        }
        return fallback;
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
                    int defaults=0;for(RouteInfo route:link.getRoutes())if(route.isDefaultRoute())defaults++;
                    out.append(" default_routes=").append(defaults);
                }
                out.append('\n');
            }
        }catch(Exception e){out.append("network_inventory_unavailable=").append(e.getClass().getSimpleName()).append('\n');}
        return out.toString();
    }
}
