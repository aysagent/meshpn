package org.meshpn.client;

/** Owns one JNI handle. UI cancellation can arrive before/during initialization. */
final class EngineSession {
    interface Backend {
        long create();
        void stop(long handle);
        void networkChanged(long handle);
        void release(long handle);
    }
    static Backend nativeBackend(){
        // Do not load the native library until create(), on the worker thread.
        return new Backend(){
            public long create(){return NativeBridge.create();}
            public void stop(long h){NativeBridge.stop(h);}
            public void networkChanged(long h){NativeBridge.networkChanged(h);}
            public void release(long h){NativeBridge.release(h);}
        };
    }
    private final Backend backend;
    private long handle;
    private boolean stopped,closed,opening;
    EngineSession(Backend backend){this.backend=backend;}
    long open(){
        synchronized(this){
            if(stopped||closed)return 0;
            if(handle!=0||opening)throw new IllegalStateException("session_already_open");
            opening=true;
        }
        long created;
        try{created=backend.create();}
        catch(RuntimeException|Error e){synchronized(this){opening=false;}throw e;}
        synchronized(this){
            opening=false;
            if(created==0)throw new IllegalStateException("native_create_failed");
            if(!stopped&&!closed){handle=created;return handle;}
        }
        // Cancellation never waits for class loading; release a late handle.
        backend.release(created);return 0;
    }
    synchronized boolean stopped(){return stopped;}
    synchronized void stop(){
        if(stopped||closed)return;
        stopped=true;if(handle!=0)backend.stop(handle);
    }
    synchronized void networkChanged(){if(!stopped&&!closed&&handle!=0)backend.networkChanged(handle);}
    synchronized void close(){
        if(closed)return;
        closed=true;long owned=handle;handle=0;
        // In particular, do not call NativeBridge again after a load failure.
        if(owned!=0)backend.release(owned);
    }
}
