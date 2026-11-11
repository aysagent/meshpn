package org.meshpn.client;

import android.content.ContextWrapper;
import android.content.SharedPreferences;
import org.json.JSONObject;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public class ConfigStoreTest {
    @Rule public TemporaryFolder temp=new TemporaryFolder();
    private final MemoryPrefs prefs=new MemoryPrefs();
    private ContextWrapper context;
    @Before public void setup(){context=new ContextWrapper(null){
        @Override public File getNoBackupFilesDir(){return temp.getRoot();}
        @Override public SharedPreferences getSharedPreferences(String n,int mode){return prefs;}
    };}
    @SuppressWarnings("unchecked") private AtomicReference<EngineSession> owner() throws Exception {
        java.lang.reflect.Field f=VpnClientService.class.getDeclaredField("owner");f.setAccessible(true);
        return (AtomicReference<EngineSession>)f.get(null);
    }
    @After public void cleanup() throws Exception{owner().set(null);}
    private String bundle() throws Exception {
        JSONObject config=new JSONObject().put("version",1).put("role","client").put("address","192.0.2.10").put("port",443)
            .put("server_name","personal-cert.internal").put("peer_ipv4","10.99.0.4").put("ca","@bundle/ca.pem").put("secret_path","@bundle/psk");
        JSONObject files=new JSONObject().put("ca.pem",Base64.getEncoder().encodeToString("-----BEGIN CERTIFICATE-----\nfixture".getBytes("UTF-8")))
            .put("psk",Base64.getEncoder().encodeToString(new byte[32])).put("relay.psk","must not persist").put("profile.json","unused attachment");
        return new JSONObject().put("version",1).put("kind","clean-vpn-client-enrollment").put("name","projector").put("config",config).put("files",files).toString();
    }
    @Test public void persistedBundleContainsOnlyReferencedPacketFiles() throws Exception {
        ConfigStore.install(context,bundle(),p->true);
        File dir=ConfigStore.active(context);JSONObject saved=new JSONObject(ConfigStore.read(new FileInputStream(new File(dir,"bundle.json"))));
        assertEquals(2,saved.getJSONObject("files").length());assertEquals("10.99.0.4",ConfigStore.load(context).peer);
        assertFalse(new File(dir,".pending").exists());
    }
    @Test public void failedValidationKeepsOldConfiguration() throws Exception {
        ConfigStore.install(context,bundle(),p->true);File old=ConfigStore.active(context);
        try{ConfigStore.install(context,bundle(),p->false);fail();}catch(IOException expected){}
        assertEquals(old,ConfigStore.active(context));assertEquals(1,ConfigStore.saved(context).length);
    }
    @Test public void commitFailureRestoresPreviousInMemoryPointer() throws Exception {
        ConfigStore.install(context,bundle(),p->true);File old=ConfigStore.active(context);prefs.failNext=true;
        try{ConfigStore.install(context,bundle(),p->true);fail();}catch(IOException expected){}
        assertEquals(old,ConfigStore.active(context));assertEquals(1,ConfigStore.saved(context).length);
    }
    @Test public void failedSelectionPreservesServerAndProfile() throws Exception {
        ConfigStore.install(context,bundle(),p->true);File first=ConfigStore.active(context);
        ConfigStore.install(context,bundle(),p->true);File second=ConfigStore.active(context);
        ConfigStore.setProfile(context,false);prefs.failNext=true;
        try{ConfigStore.select(context,first);fail();}catch(IOException expected){}
        assertEquals(second,ConfigStore.active(context));assertFalse(prefs.getBoolean("profile",true));
        assertEquals(2,ConfigStore.saved(context).length);
    }
    @Test public void failedProfileChangeRestoresPreviousChoice() throws Exception {
        ConfigStore.install(context,bundle(),p->true);prefs.failNext=true;
        try{ConfigStore.setProfile(context,false);fail();}catch(IOException expected){}
        assertTrue(prefs.getBoolean("profile",false));
    }
    @Test public void failedDeletionPreservesFilesAndAutostart() throws Exception {
        ConfigStore.install(context,bundle(),p->true);File old=ConfigStore.active(context);
        prefs.edit().putBoolean("autostart",true).commit();prefs.failNext=true;
        try{ConfigStore.deleteActive(context);fail();}catch(IOException expected){}
        assertEquals(old,ConfigStore.active(context));assertTrue(prefs.getBoolean("autostart",false));
        assertTrue(new File(old,"psk").isFile());assertEquals(1,ConfigStore.saved(context).length);
    }
    @Test public void cannotSelectUnpublishedImport() throws Exception {
        ConfigStore.install(context,bundle(),p->true);File old=ConfigStore.active(context);
        File staged=new File(ConfigStore.base(context),UUID.randomUUID().toString());assertTrue(staged.mkdir());
        assertTrue(new File(staged,"bundle.json").createNewFile());assertTrue(new File(staged,".pending").createNewFile());
        try{ConfigStore.select(context,staged);fail();}catch(IOException expected){}
        assertEquals(old,ConfigStore.active(context));assertEquals(1,ConfigStore.saved(context).length);
    }
    @Test public void validationDoesNotHoldStoreLockAndStartedVpnPreventsPublication() throws Exception {
        ConfigStore.install(context,bundle(),p->true);File old=ConfigStore.active(context);
        CountDownLatch entered=new CountDownLatch(1),resume=new CountDownLatch(1);
        ExecutorService pool=Executors.newFixedThreadPool(2);String input=bundle();
        try{
            Future<?> importJob=pool.submit(()->{
                try{ConfigStore.install(context,input,p->{entered.countDown();try{if(!resume.await(3,TimeUnit.SECONDS))throw new AssertionError("timeout");}catch(InterruptedException e){throw new AssertionError(e);}return true;});fail("committed while VPN running");}
                catch(IOException expected){}catch(Exception e){throw new AssertionError(e);}
            });
            assertTrue(entered.await(1,TimeUnit.SECONDS));
            assertEquals(Integer.valueOf(1),pool.submit(()->ConfigStore.saved(context).length).get(1,TimeUnit.SECONDS));
            owner().set(new EngineSession(new EngineSessionTest.Backend()));resume.countDown();importJob.get(2,TimeUnit.SECONDS);
            assertEquals(old,ConfigStore.active(context));assertEquals(1,ConfigStore.saved(context).length);
        }finally{resume.countDown();pool.shutdownNow();}
    }
    static class MemoryPrefs implements SharedPreferences {
        final Map<String,Object> values=new HashMap<>();boolean failNext;
        public Map<String,?> getAll(){return new HashMap<>(values);}
        public String getString(String k,String d){return (String)values.getOrDefault(k,d);}
        @SuppressWarnings("unchecked") public Set<String> getStringSet(String k,Set<String> d){return (Set<String>)values.getOrDefault(k,d);}
        public int getInt(String k,int d){return (Integer)values.getOrDefault(k,d);}
        public long getLong(String k,long d){return (Long)values.getOrDefault(k,d);}
        public float getFloat(String k,float d){return (Float)values.getOrDefault(k,d);}
        public boolean getBoolean(String k,boolean d){return (Boolean)values.getOrDefault(k,d);}
        public boolean contains(String k){return values.containsKey(k);}
        public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l){}
        public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l){}
        public Editor edit(){return new Editor(){
            final Map<String,Object> changes=new HashMap<>();boolean clear;
            public Editor putString(String k,String v){changes.put(k,v);return this;}
            public Editor putStringSet(String k,Set<String> v){changes.put(k,v);return this;}
            public Editor putInt(String k,int v){changes.put(k,v);return this;}
            public Editor putLong(String k,long v){changes.put(k,v);return this;}
            public Editor putFloat(String k,float v){changes.put(k,v);return this;}
            public Editor putBoolean(String k,boolean v){changes.put(k,v);return this;}
            public Editor remove(String k){changes.put(k,null);return this;}
            public Editor clear(){clear=true;return this;}
            public void apply(){commit();}
            public boolean commit(){
                if(clear)values.clear();for(Map.Entry<String,Object> e:changes.entrySet())if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());
                if(failNext){failNext=false;return false;}return true;
            }
        };}
    }
}
