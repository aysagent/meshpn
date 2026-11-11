package org.meshpn.client;

import android.content.*;
import android.content.pm.*;
import android.net.VpnService;
import android.os.*;
import java.io.File;
import java.util.*;

/** Only our consent flow and public firmware/component metadata, never logcat. */
final class PermissionDiagnostics {
    private static String safe(String s){return s==null?"unknown":s.replaceAll("[\\p{Cntrl}]"," ").substring(0,Math.min(512,s.length()));}
    static synchronized void record(Context c,String event){
        android.content.SharedPreferences p=c.getSharedPreferences("vpn-permission-diagnostic",Context.MODE_PRIVATE);
        String old=p.getString("events","");
        java.text.SimpleDateFormat f=new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss",Locale.ROOT);f.setTimeZone(TimeZone.getTimeZone("UTC"));
        String next=old+f.format(new Date())+" UTC "+safe(event)+"\n";
        String[] lines=next.split("\n");StringBuilder bounded=new StringBuilder();
        for(int i=Math.max(0,lines.length-24);i<lines.length;i++)bounded.append(lines[i]).append('\n');
        p.edit().putString("events",bounded.toString()).apply();
    }
    static String describeIntent(Context c,Intent intent){
        StringBuilder out=new StringBuilder();
        out.append("dialog_target=").append(intent.getComponent()==null?"implicit":safe(intent.getComponent().flattenToString()));
        try{
            ResolveInfo resolved=c.getPackageManager().resolveActivity(intent,PackageManager.MATCH_DEFAULT_ONLY);
            if(resolved==null||resolved.activityInfo==null)return out.append("; resolvable=false").toString();
            ActivityInfo a=resolved.activityInfo;
            out.append("; resolved=").append(safe(a.packageName+"/"+a.name)).append("; enabled=").append(a.enabled)
                .append("; app_enabled=").append(a.applicationInfo.enabled).append("; exported=").append(a.exported);
            PackageInfo p=c.getPackageManager().getPackageInfo(a.packageName,0);
            out.append("; version=").append(safe(p.versionName)).append('/').append(p.versionCode);
        }catch(Exception e){out.append("; lookup_error=").append(e.getClass().getSimpleName());}
        return out.toString();
    }
    static String snapshot(Context c){
        StringBuilder out=new StringBuilder("VPN permission diagnostics (no system-process logs)\n");
        out.append("Manufacturer: ").append(safe(Build.MANUFACTURER)).append("\nModel: ").append(safe(Build.MODEL))
            .append("\nFirmware: ").append(safe(Build.DISPLAY)).append("\nFingerprint: ").append(safe(Build.FINGERPRINT))
            .append("\nApp UID: ").append(android.os.Process.myUid()).append("\nUTC millis: ").append(System.currentTimeMillis());
        try{
            UserManager users=(UserManager)c.getSystemService(Context.USER_SERVICE);
            out.append("\nDISALLOW_CONFIG_VPN: ").append(users==null?"unknown":users.hasUserRestriction(UserManager.DISALLOW_CONFIG_VPN));
        }catch(Exception e){out.append("\nUser restrictions error: ").append(e.getClass().getSimpleName());}
        try{
            ComponentName component=new ComponentName(c,VpnClientService.class);
            ServiceInfo service=c.getPackageManager().getServiceInfo(component,0);
            out.append("\nVPN service: enabled=").append(service.enabled).append(" exported=").append(service.exported)
                .append(" permission=").append(safe(service.permission)).append(" override=").append(c.getPackageManager().getComponentEnabledSetting(component));
        }catch(Exception e){out.append("\nVPN service lookup error: ").append(e.getClass().getSimpleName());}
        try{
            Intent intent=VpnService.prepare(c);
            out.append("\nCurrent prepare: ").append(intent==null?"granted":"confirmation_required");
            if(intent!=null)out.append('\n').append(describeIntent(c,intent));
        }catch(Exception|LinkageError e){out.append("\nCurrent prepare error: ").append(e.getClass().getSimpleName());}
        try{out.append("\n/dev/tun exists: ").append(new File("/dev/tun").exists()).append("; /dev/net/tun exists: ").append(new File("/dev/net/tun").exists());}
        catch(SecurityException e){out.append("\nTUN paths: inaccessible");}
        out.append("\nTUN path visibility is not a VpnService/kernel support test.\n\nConsent events:\n")
            .append(c.getSharedPreferences("vpn-permission-diagnostic",Context.MODE_PRIVATE).getString("events","No recorded requests.\n"));
        return out.toString();
    }
}
