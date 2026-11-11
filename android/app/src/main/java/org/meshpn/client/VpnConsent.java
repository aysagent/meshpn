package org.meshpn.client;

/** Explicit user request -> system dialog -> authoritative prepare() recheck. */
final class VpnConsent<T> {
    interface Host<T> {
        T prepare() throws Exception;
        void launch(T intent) throws Exception;
        void start() throws Exception;
        void event(String text);
        void message(String text);
        long elapsed();
    }
    private final Host<T> host;
    private boolean pending;
    private long started;
    VpnConsent(Host<T> host,boolean pending,long started){this.host=host;this.pending=pending;this.started=started;}
    boolean pending(){return pending;}
    long started(){return started;}
    void request(){
        if(pending)return;
        String stage="prepare";
        try{
            host.event("request");
            T intent=host.prepare();
            if(intent==null){host.event("prepare=granted");start();return;}
            host.event("prepare=confirmation_required");
            pending=true;started=host.elapsed();stage="launch";
            host.launch(intent);host.event("dialog_launched");
        }catch(Exception|LinkageError e){pending=false;failed(stage,e);}
    }
    void result(int code){
        if(!pending){host.event("unexpected_result="+code);return;}
        pending=false;
        host.event("result="+code+" elapsed_ms="+Math.max(0,host.elapsed()-started));
        try{
            // RESULT_OK alone does not prove current consent; another VPN can
            // revoke it. A non-OK result may still leave this app authorized.
            if(host.prepare()==null){host.event("recheck=granted");start();}
            else{
                host.event("recheck=confirmation_required");
                host.message(code==-1?"Android сообщил OK, но разрешение VPN всё ещё требуется. Сохраните отчёт диагностики.":
                    "Системное окно завершилось без разрешения VPN. Это может быть отмена или сбой окна. Если окна не было — сохраните отчёт диагностики.");
            }
        }catch(Exception|LinkageError e){failed("recheck",e);}
    }
    private void start(){
        try{host.start();host.event("service_start_requested");}
        catch(Exception|LinkageError e){failed("service_start",e);}
    }
    private void failed(String stage,Throwable e){
        host.event(stage+"_error="+e.getClass().getSimpleName());
        host.message("Не удалось пройти этап «"+stage+"» запроса VPN. Сохраните отчёт диагностики.");
    }
}
