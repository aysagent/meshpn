package org.meshpn.client;

final class NativeBridge {
    static { System.loadLibrary("cvpn_android"); }
    static native long create();
    static native boolean validate(String configPath);
    static native int run(long handle, String configPath, int tunFd, VpnClientService service);
    static native void stop(long handle);
    static native void networkChanged(long handle);
    static native void release(long handle);
    private NativeBridge() {}
}
