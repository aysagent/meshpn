package org.meshpn.client;

import java.net.*;
import java.nio.channels.*;

/** TCP only: numeric IPv4 endpoint, no DNS, TLS, credentials or payload. */
final class TcpProbe {
    interface Prepare { boolean socket(Socket socket) throws Exception; }
    interface Stopped { boolean get(); }
    static final class Result {
        final String code,stage;
        final long millis;
        final int localPort;
        Result(String code,String stage,long millis,int port){this.code=code;this.stage=stage;this.millis=millis;localPort=port;}
        boolean ok(){return code.equals("tcp_connected");}
        public String toString(){return code+" stage="+stage+" elapsed_ms="+millis+" local_port="+localPort;}
    }
    static InetAddress numericAddress(String value) throws Exception {
        String[] parts=value.split("\\.",-1);
        if(parts.length!=4)throw new IllegalArgumentException();
        byte[] bytes=new byte[4];
        for(int i=0;i<4;i++){
            if(!parts[i].matches("[0-9]{1,3}"))throw new IllegalArgumentException();
            int n=Integer.parseInt(parts[i]);if(n>255)throw new IllegalArgumentException();bytes[i]=(byte)n;
        }
        return InetAddress.getByAddress(bytes);
    }
    static Result run(String address,int port,int timeoutMs,Prepare prepare,Stopped stopped){
        long start=System.nanoTime();String stage="endpoint";int local=0;
        try{
            if(timeoutMs<1||timeoutMs>10000)throw new IllegalArgumentException();
            InetSocketAddress endpoint=new InetSocketAddress(numericAddress(address),port);
            if(stopped.get())return result("cancelled",stage,start,local);
            stage="socket";
            try(SocketChannel channel=SocketChannel.open();Selector selector=Selector.open()){
                channel.configureBlocking(false);
                stage="protect_or_bind";
                if(!prepare.socket(channel.socket()))return result("socket_prepare_refused",stage,start,local);
                if(stopped.get())return result("cancelled",stage,start,local);
                stage="connect";
                boolean connected=channel.connect(endpoint);
                channel.register(selector,SelectionKey.OP_CONNECT);
                while(!connected){
                    if(stopped.get())return result("cancelled",stage,start,local);
                    long left=timeoutMs-(System.nanoTime()-start)/1000000;
                    if(left<=0)return result("tcp_timeout",stage,start,channel.socket().getLocalPort());
                    selector.select(Math.min(left,100));selector.selectedKeys().clear();
                    connected=channel.finishConnect();
                }
                local=channel.socket().getLocalPort();
                return result("tcp_connected",stage,start,local);
            }
        }catch(Exception e){return result(e.getClass().getSimpleName(),stage,start,local);}
    }
    private static Result result(String code,String stage,long start,int local){
        return new Result(code,stage,(System.nanoTime()-start)/1000000,local);
    }
}
