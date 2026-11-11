package org.meshpn.client;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import org.json.JSONObject;
import java.io.File;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicReference;

public final class VpnClientService extends VpnService {
    static final String START="org.meshpn.client.START", STOP="org.meshpn.client.STOP";
    private static final AtomicReference<EngineSession> owner=new AtomicReference<>();
    private static volatile VpnClientService instance;
    static volatile String state="stopped", lastError="";
    static volatile long tx=0,rx=0,connectionEpoch=0;
    private static final ArrayDeque<String> history=new ArrayDeque<>();
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile EngineSession session;
    private boolean destroyed;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networks;

    static boolean busy(){return owner.get()!=null;}
    static synchronized String logs(){return android.text.TextUtils.join("\n",history);}
    private static synchronized void log(String value){
        if(history.size()>=120)history.removeFirst();
        history.addLast(new java.text.SimpleDateFormat("HH:mm:ss",java.util.Locale.ROOT).format(new java.util.Date())+"  "+value);
    }
    static void start(Context context){
        Intent i=new Intent(context,VpnClientService.class).setAction(START);
        if(Build.VERSION.SDK_INT>=26)context.startForegroundService(i);else context.startService(i);
    }
    static void disconnect(Context context){
        VpnClientService s=instance;if(s!=null)s.main.post(s::requestStop);
    }
    @Override public void onCreate(){super.onCreate();instance=this;}
    private Notification notification(){
        NotificationManager manager=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(Build.VERSION.SDK_INT>=26)manager.createNotificationChannel(new NotificationChannel("vpn","VPN",NotificationManager.IMPORTANCE_LOW));
        Notification.Builder b=Build.VERSION.SDK_INT>=26?new Notification.Builder(this,"vpn"):new Notification.Builder(this);
        int flags=PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE;
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),flags);
        PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,VpnClientService.class).setAction(STOP),flags);
        return b.setSmallIcon(R.drawable.icon).setContentTitle("Clean VPN · boring-tls")
            .setContentText(label(state)).setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(R.drawable.icon,"Отключить",stop).build()).build();
    }
    private void publish(String next){
        if(!state.equals(next)){state=next;++connectionEpoch;log(next);}
        if(session!=null&&!destroyed)((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(1,notification());
    }
    public static String label(String s){
        switch(s){
            case "ready":return "Подключён";
            case "starting":case "idle":case "connecting":return "Подключается…";
            case "handshake":return "Проверка TLS и авторизации…";
            case "stopping":return "Отключается…";
            case "stopped":return "Отключён";
            case "waiting_uplink":return "Нет сети";
            case "network_changed":return "Сеть изменилась, переподключение…";
            case "tls_verify_not_yet_valid":case "tls_verify_expired":case "auth_clock_skew":return "Проверьте дату и время устройства / сертификат";
            case "tls_verify_untrusted":case "tls_verify_name":case "tls_verify_failed":return "Ошибка проверки сертификата";
            case "permission_required":return "Нужно разрешение Android на VPN";
            case "native_unavailable":return "Native-библиотека недоступна для этого устройства";
            case "vpn_interface_failed":return "Не удалось создать VPN-интерфейс Android";
            case "configuration_or_startup_refused":return "Не удалось запустить: проверьте конфигурацию";
            default:return "Переподключение / ошибка: "+s;
        }
    }
    @Override public int onStartCommand(Intent intent,int flags,int id){
        if(intent!=null&&STOP.equals(intent.getAction())){requestStop();return START_NOT_STICKY;}
        if(session!=null)return START_NOT_STICKY;
        if(intent==null||!START.equals(intent.getAction())){stopSelf();return START_NOT_STICKY;}
        final EngineSession next=new EngineSession(EngineSession.nativeBackend());
        final boolean acquired;
        synchronized(ConfigStore.class){acquired=owner.compareAndSet(null,next);}
        if(!acquired){stopSelf();return START_NOT_STICKY;}
        session=next;lastError="";tx=rx=0;state="starting";++connectionEpoch;
        boolean workerStarted=false;
        try {
            startForeground(1,notification());
            if(prepare(this)!=null){finish(next,"permission_required");return START_NOT_STICKY;}
            // Neither native validation nor config I/O holds the main looper.
            new Thread(null,()->runTunnel(next),"clean-vpn-native",2*1024*1024).start();
            workerStarted=true;
            watchNetworks(next);
            log("starting; transport=boring-tls; DNS through TUN; no kill switch");
        }catch(Exception|LinkageError e){
            next.stop();
            if(!workerStarted)finish(next,"configuration_or_startup_refused");
        }
        return START_NOT_STICKY;
    }
    private void watchNetworks(EngineSession current){
        try{
            connectivity=(ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
            networks=new ConnectivityManager.NetworkCallback(){
                @Override public void onAvailable(Network n){current.networkChanged();}
                @Override public void onLost(Network n){current.networkChanged();}
            };
            connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),networks);
        }catch(Exception e){networks=null;log("network_monitor_unavailable; native retry remains enabled");}
    }
    private void unwatchNetworks(){
        if(networks!=null)try{connectivity.unregisterNetworkCallback(networks);}catch(Exception ignored){}
        networks=null;
    }
    private void runTunnel(EngineSession current){
        ParcelFileDescriptor tun=null;String terminal="configuration_or_startup_refused";
        try{
            final Enrollment config;final File engine;
            synchronized(ConfigStore.class){config=ConfigStore.load(this);engine=ConfigStore.engine(this);}
            long handle=current.open();
            if(handle==0||current.stopped()){terminal="stopped";return;}
            // Check files/profile before capturing any application traffic.
            if(!NativeBridge.validate(engine.getAbsolutePath()))return;
            if(current.stopped()){terminal="stopped";return;}
            terminal="vpn_interface_failed";
            Builder b=new Builder().setSession("Clean VPN · "+config.name).setMtu(1280).addAddress(config.peer,32).addRoute("0.0.0.0",0);
            for(String dns:config.dns)b.addDnsServer(dns);
            // No IPv6 address/route/DNS/allowFamily: Android blocks this family.
            tun=b.establish();if(tun==null){terminal="permission_required";return;}
            if(current.stopped()){terminal="stopped";return;}
            int result=NativeBridge.run(handle,engine.getAbsolutePath(),tun.getFd(),this);
            terminal=result==0?"stopped":"configuration_or_startup_refused";
        }catch(LinkageError e){terminal="native_unavailable";}
        catch(Exception e){/* Fixed stage code only; no config contents in logs. */}
        finally{
            if(tun!=null)try{tun.close();}catch(Exception ignored){}
            current.close();
            final String result=current.stopped()?"stopped":terminal;
            main.post(()->finish(current,result));
        }
    }
    private void finish(EngineSession current,String terminal){
        // An obsolete worker/callback must never clear another session's lease.
        if(session!=current)return;
        current.close();unwatchNetworks();session=null;
        if(owner.compareAndSet(current,null)){
            if(!terminal.equals("stopped"))lastError=terminal;
            publish(terminal);
        }
        if(!destroyed){stopForeground(true);stopSelf();}
    }
    // Called on the native worker, before connect(), including every retry.
    public boolean protectSocket(int socket){EngineSession s=session;return s!=null&&!s.stopped()&&protect(socket);}
    public void onNativeEvent(String line){
        final EngineSession current=session;
        if(current==null||current.stopped())return;
        try{
            JSONObject j=new JSONObject(line);
            main.post(()->{
                if(session!=current||owner.get()!=current||current.stopped())return;
                tx=j.optLong("tx_packets",tx);rx=j.optLong("rx_packets",rx);
                JSONObject d=j.optJSONObject("diagnostics"),p=d==null?null:d.optJSONObject("packet"),end=p==null?null:p.optJSONObject("last_end");
                if(end!=null)lastError=end.optString("code");
                if(j.optString("event").equals("state"))publish(j.optString("state"));
            });
        }catch(Exception ignored){}
    }
    private void requestStop(){
        EngineSession current=session;
        if(current==null){stopForeground(true);stopSelf();return;}
        publish("stopping");current.stop();
    }
    @Override public void onRevoke(){main.post(this::requestStop);}
    @Override public void onDestroy(){
        destroyed=true;unwatchNetworks();EngineSession current=session;if(current!=null)current.stop();
        if(instance==this)instance=null;
        super.onDestroy();
    }
}
