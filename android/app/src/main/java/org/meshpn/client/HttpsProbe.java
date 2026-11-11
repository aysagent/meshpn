package org.meshpn.client;

import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** One process-wide probe, including after Activity recreation. DNS may ignore interrupt. */
final class HttpsProbe {
    interface Listener { void completed(String message); }
    interface Factory { HttpURLConnection open() throws Exception; }
    private static final ExecutorService worker=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"vpn-probe");t.setDaemon(true);return t;});
    private static final ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"vpn-probe-deadline");t.setDaemon(true);return t;});
    private static final AtomicBoolean occupied=new AtomicBoolean();
    static boolean start(Listener listener){
        return start(15000,()->(HttpURLConnection)new URL("https://example.org/").openConnection(Proxy.NO_PROXY),listener);
    }
    static boolean start(long timeoutMs,Factory factory,Listener listener){
        if(!occupied.compareAndSet(false,true))return false;
        AtomicReference<Listener> pending=new AtomicReference<>(listener);
        Listener once=message->{Listener target=pending.getAndSet(null);if(target!=null)target.completed(message);};
        ScheduledFuture<?> deadline=timer.schedule(()->once.completed("Проверка превысила лимит времени (включая DNS). VPN продолжает работать независимо."),timeoutMs,TimeUnit.MILLISECONDS);
        worker.execute(()->{
            HttpURLConnection connection=null;long began=System.nanoTime();
            try{
                connection=factory.open();connection.setUseCaches(false);connection.setRequestMethod("HEAD");
                connection.setConnectTimeout(5000);connection.setReadTimeout(5000);connection.setInstanceFollowRedirects(false);
                int code=connection.getResponseCode();
                once.completed("HTTPS: HTTP "+code+", "+TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began)
                    +" мс. Имя разрешено (возможно, из DNS-кэша); это не тест утечек DNS.");
            }catch(Exception e){once.completed("HTTPS-проверка не прошла. Проверьте сеть, дату и VPN. Может влиять системное хранилище CA Android.");}
            finally{
                deadline.cancel(false);
                try{if(connection!=null)connection.disconnect();}finally{occupied.set(false);}
            }
        });
        return true;
    }
}
