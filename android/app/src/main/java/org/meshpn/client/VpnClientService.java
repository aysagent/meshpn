package org.meshpn.client;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import org.json.JSONObject;
import java.io.File;
import java.util.ArrayDeque;

public final class VpnClientService extends VpnService {
    static final String START="org.meshpn.client.START", STOP="org.meshpn.client.STOP";
    private static volatile VpnClientService instance;
    private static final java.util.concurrent.atomic.AtomicBoolean engineRunning=new java.util.concurrent.atomic.AtomicBoolean();
    static volatile String activeDirectory="", state="stopped", lastError="";
    static volatile long tx=0,rx=0;
    private static final ArrayDeque<String> history=new ArrayDeque<>();
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile long handle;
    private volatile boolean stopping;
    private Thread worker;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networks;

    static boolean busy(){return engineRunning.get();}
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
        VpnClientService s=instance;
        if(s!=null)s.main.post(s::requestStop);
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
        if(!state.equals(next)){state=next;log(next);}
        if(worker!=null)((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(1,notification());
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
            case "configuration_or_startup_refused":return "Не удалось запустить: проверьте конфигурацию";
            default:return "Переподключение / ошибка: "+s;
        }
    }
    @Override public int onStartCommand(Intent intent,int flags,int id){
        if(intent!=null&&STOP.equals(intent.getAction())){requestStop();return START_NOT_STICKY;}
        if(worker!=null)return START_NOT_STICKY;
        if(prepare(this)!=null){publish("permission_required");stopSelf();return START_NOT_STICKY;}
        if(!engineRunning.compareAndSet(false,true)){stopSelf();return START_NOT_STICKY;}
        try {
            final Enrollment config;final File engine;
            synchronized(ConfigStore.class){
                config=ConfigStore.load(this);engine=ConfigStore.engine(this);activeDirectory=engine.getParent();
            }
            handle=NativeBridge.create();if(handle==0)throw new Exception("native_create");
            stopping=false;lastError="";tx=rx=0;state="starting";
            startForeground(1,notification());
            worker=new Thread(null,()->runTunnel(config,engine),"clean-vpn-native",2*1024*1024);
            worker.start();
            connectivity=(ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
            networks=new ConnectivityManager.NetworkCallback(){
                @Override public void onAvailable(Network n){NativeBridge.networkChanged(handle);}
                @Override public void onLost(Network n){NativeBridge.networkChanged(handle);}
            };
            connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),networks);
            log("starting; transport=boring-tls; DNS through TUN; no kill switch");
        }catch(Exception|LinkageError e){
            lastError="startup_failed";log(lastError);publish("configuration_or_startup_refused");
            if(worker!=null)requestStop();else {NativeBridge.release(handle);handle=0;activeDirectory="";engineRunning.set(false);stopForeground(true);stopSelf();}
        }
        return START_NOT_STICKY;
    }
    private void runTunnel(Enrollment c,File engine){
        ParcelFileDescriptor tun=null;int result=1;
        try{
            if(!stopping){
                Builder b=new Builder().setSession("Clean VPN · "+c.name).setMtu(1280).addAddress(c.peer,32).addRoute("0.0.0.0",0);
                for(String dns:c.dns)b.addDnsServer(dns);
                // No IPv6 address, route, DNS or allowFamily: Android blocks
                // this family while the IPv4-only VPN is established. No bypass.
                tun=b.establish();
                if(tun==null)throw new Exception("vpn_permission_revoked");
                if(!stopping)result=NativeBridge.run(handle,engine.getAbsolutePath(),tun.getFd(),this);
            }
        }catch(Exception|LinkageError e){lastError="vpn_interface_or_native_failed";log(lastError);}
        finally {
            if(tun!=null)try{tun.close();}catch(Exception ignored){}
            NativeBridge.release(handle);
            final int exit=result;
            main.post(()->{
                handle=0;worker=null;activeDirectory="";
                engineRunning.set(false);
                if(networks!=null)try{connectivity.unregisterNetworkCallback(networks);}catch(Exception ignored){}
                networks=null;
                publish(stopping||exit==0?"stopped":"configuration_or_startup_refused");
                stopForeground(true);stopSelf();
            });
        }
    }
    // Called on the native worker, before connect(), including every retry.
    public boolean protectSocket(int socket){return !stopping&&protect(socket);}
    public void onNativeEvent(String line){
        try{
            JSONObject j=new JSONObject(line);
            tx=j.optLong("tx_packets",tx);rx=j.optLong("rx_packets",rx);
            JSONObject diagnostics=j.optJSONObject("diagnostics");
            if(diagnostics!=null){JSONObject p=diagnostics.optJSONObject("packet");if(p!=null){JSONObject end=p.optJSONObject("last_end");if(end!=null)lastError=end.optString("code");}}
            if(j.optString("event").equals("state")){
                String next=j.optString("state");
                main.post(()->{if(!stopping)publish(next);});
            }
        }catch(Exception ignored){}
    }
    private void requestStop(){
        if(worker==null){publish("stopped");stopForeground(true);stopSelf();return;}
        stopping=true;publish("stopping");NativeBridge.stop(handle);
    }
    @Override public void onRevoke(){main.post(this::requestStop);}
    @Override public void onDestroy(){
        stopping=true;if(handle!=0)NativeBridge.stop(handle);
        if(instance==this)instance=null;
        super.onDestroy();
    }
}
