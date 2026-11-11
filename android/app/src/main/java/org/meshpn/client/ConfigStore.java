package org.meshpn.client;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

final class ConfigStore {
    static SharedPreferences prefs(Context c) { return c.getSharedPreferences("settings", Context.MODE_PRIVATE); }
    static File base(Context c) { return new File(c.getNoBackupFilesDir(), "clients"); }
    static File active(Context c) throws IOException {
        String id=prefs(c).getString("active", "");
        if (!id.matches("[a-f0-9-]{36}")) throw new IOException("Сначала импортируйте конфигурацию");
        File dir=new File(base(c),id);
        if (!dir.isDirectory()) throw new IOException("Конфигурация не найдена");
        return dir;
    }
    static String read(InputStream in) throws IOException {
        if(in==null)throw new IOException("Не удалось открыть файл");
        try(InputStream source=in; ByteArrayOutputStream out=new ByteArrayOutputStream()) {
            byte[] b=new byte[4096]; int n;
            while((n=source.read(b))!=-1) {
                if(out.size()+n>Enrollment.LIMIT)throw new IOException("Файл больше 256 КиБ");
                out.write(b,0,n);
            }
            return new String(out.toByteArray(),StandardCharsets.UTF_8);
        }
    }
    static Enrollment load(Context c) throws Exception { return new Enrollment(read(new FileInputStream(new File(active(c),"bundle.json")))); }
    static File engine(Context c) throws Exception {
        return new File(active(c),prefs(c).getBoolean("profile",true)?"engine.json":"engine-base.json");
    }
    private static void write(File dir,String name,byte[] data) throws IOException {
        File file=new File(dir,name);
        if(!file.createNewFile()||!file.setReadable(false,false)||!file.setWritable(false,false)
            ||!file.setReadable(true,true)||!file.setWritable(true,true))throw new IOException("Права файла");
        try(FileOutputStream out=new FileOutputStream(file)){out.write(data);out.getFD().sync();}
    }
    private static void remove(File dir) {
        File[] children=dir.listFiles();if(children!=null)for(File f:children)f.delete();dir.delete();
    }
    static synchronized File[] saved(Context c) {
        File[] dirs=base(c).listFiles(f->f.isDirectory()&&f.getName().matches("[a-f0-9-]{36}")&&new File(f,"bundle.json").isFile()&&!new File(f,".pending").exists());
        if(dirs==null)return new File[0];
        java.util.Arrays.sort(dirs,(a,b)->a.getName().compareTo(b.getName()));return dirs;
    }
    static synchronized void select(Context c,File dir) throws Exception {
        if(VpnClientService.busy())throw new IOException("Сначала отключите VPN");
        if(!dir.getParentFile().equals(base(c))||!new File(dir,"bundle.json").isFile()||new File(dir,".pending").exists())throw new IOException("Нет конфигурации");
        String previous=prefs(c).getString("active","");boolean previousProfile=prefs(c).getBoolean("profile",true);
        if(!prefs(c).edit().putString("active",dir.getName()).putBoolean("profile",true).commit()){
            prefs(c).edit().putString("active",previous).putBoolean("profile",previousProfile).commit();
            throw new IOException("Не удалось сохранить выбор");
        }
    }
    static synchronized void setProfile(Context c,boolean enabled) throws IOException {
        if(VpnClientService.busy())throw new IOException("Сначала отключите VPN");
        boolean previous=prefs(c).getBoolean("profile",true);
        if(!prefs(c).edit().putBoolean("profile",enabled).commit()){
            prefs(c).edit().putBoolean("profile",previous).commit();
            throw new IOException("Не удалось сохранить настройку TLS-профиля");
        }
    }
    static synchronized void deleteActive(Context c) throws Exception {
        if(VpnClientService.busy())throw new IOException("Сначала отключите VPN");
        File dir=active(c);
        boolean previousAutostart=prefs(c).getBoolean("autostart",false);
        if(!prefs(c).edit().remove("active").putBoolean("autostart",false).commit()){
            prefs(c).edit().putString("active",dir.getName()).putBoolean("autostart",previousAutostart).commit();
            throw new IOException("Не удалось удалить конфигурацию");
        }
        remove(dir);
    }
    interface Validator { boolean validate(String path); }
    static Enrollment install(Context c,String text) throws Exception {return install(c,text,NativeBridge::validate);}
    static Enrollment install(Context c,String text,Validator validator) throws Exception {
        synchronized(ConfigStore.class){checkImportAllowed(c);}
        Enrollment enrollment=new Enrollment(text);
        File dir=new File(base(c),UUID.randomUUID().toString());
        if(!dir.mkdirs())throw new IOException("Не удалось создать каталог конфигурации");
        boolean committed=false;
        try {
            write(dir,".pending",new byte[0]);
            write(dir,"ca.pem",enrollment.ca);write(dir,"psk",enrollment.psk);
            if(enrollment.profile!=null)write(dir,"profile.json",enrollment.profile);
            write(dir,"engine.json",enrollment.engine(dir.getAbsolutePath(),true).toString().getBytes(StandardCharsets.UTF_8));
            write(dir,"engine-base.json",enrollment.engine(dir.getAbsolutePath(),false).toString().getBytes(StandardCharsets.UTF_8));
            if(!validator.validate(new File(dir,"engine.json").getAbsolutePath())
                || !validator.validate(new File(dir,"engine-base.json").getAbsolutePath()))
                throw new IOException("Native-проверка CA, ключа или TLS-профиля не прошла");
            // Store only client enrollment; do not retain SSH clock identities or relay keys.
            org.json.JSONObject root=new org.json.JSONObject(text);
            if(root.optString("kind").equals("clean-vpn-install-bundle"))root=root.getJSONObject("enrollment");
            org.json.JSONObject clean=new org.json.JSONObject();
            org.json.JSONObject engine=enrollment.engine("@bundle",true);
            org.json.JSONObject files=new org.json.JSONObject();
            org.json.JSONObject sourceFiles=root.getJSONObject("files");
            for(String name:new String[]{"ca.pem","psk","profile.json"})
                if(sourceFiles.has(name)&&(!name.equals("profile.json")||enrollment.profile!=null))files.put(name,sourceFiles.getString(name));
            clean.put("version",1).put("kind","clean-vpn-client-enrollment").put("name",enrollment.name)
                .put("config",engine).put("files",files).put("android_dns",new org.json.JSONArray(enrollment.dns));
            write(dir,"bundle.json",clean.toString().getBytes(StandardCharsets.UTF_8));
            synchronized(ConfigStore.class){
                // A service/another import may have started during validation.
                checkImportAllowed(c);
                if(!new File(dir,".pending").delete())throw new IOException("Не удалось завершить импорт");
                String previous=prefs(c).getString("active","");boolean previousProfile=prefs(c).getBoolean("profile",true);
                if(!prefs(c).edit().putString("active",dir.getName()).putBoolean("profile",true).commit()){
                    prefs(c).edit().putString("active",previous).putBoolean("profile",previousProfile).commit();
                    throw new IOException("Не удалось сохранить конфигурацию");
                }
                committed=true;
            }
            return enrollment;
        } finally {if(!committed)remove(dir);}
    }
    private static void checkImportAllowed(Context c) throws IOException {
        if(VpnClientService.busy())throw new IOException("Сначала отключите VPN");
        if(saved(c).length>=8)throw new IOException("Сохранено 8 конфигураций. Удалите ненужную.");
    }
}
