package org.meshpn.client;

/** Emit the actual app route plan for the isolated Linux routing regression. */
public final class RoutePlan {
    public static void main(String[] args) throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("exit IPv4 required");
        for(Ipv4Routes.Route route:Ipv4Routes.excluding(args[0]))System.out.println(route);
    }
}
