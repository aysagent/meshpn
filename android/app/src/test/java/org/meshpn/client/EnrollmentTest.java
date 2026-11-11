package org.meshpn.client;

import org.json.*;
import org.junit.Test;
import java.util.Base64;
import static org.junit.Assert.*;

public class EnrollmentTest {
    private JSONObject bundle() throws Exception {
        JSONObject c=new JSONObject().put("version",1).put("role","client").put("address","192.0.2.10").put("port",443)
            .put("server_name","personal-cert.internal").put("peer_ipv4","10.99.0.4").put("ca","@bundle/ca.pem").put("secret_path","@bundle/psk");
        JSONObject files=new JSONObject().put("ca.pem",Base64.getEncoder().encodeToString("-----BEGIN CERTIFICATE-----\nfixture".getBytes("UTF-8")))
            .put("psk",Base64.getEncoder().encodeToString(new byte[32]));
        return new JSONObject().put("version",1).put("kind","clean-vpn-client-enrollment").put("name","projector").put("config",c).put("files",files);
    }
    private void rejected(JSONObject b) throws Exception {
        try{new Enrollment(b.toString());fail("accepted invalid enrollment");}catch(Exception expected){}
    }
    @Test public void existingEnrollmentAndInstallWrapper() throws Exception {
        JSONObject b=bundle();Enrollment e=new Enrollment(b.toString());assertEquals("10.99.0.4",e.peer);assertEquals(32,e.psk.length);
        assertArrayEquals(new String[]{"1.1.1.1","8.8.8.8"},e.dns);
        assertEquals("projector",new Enrollment(new JSONObject().put("version",1).put("kind","clean-vpn-install-bundle").put("enrollment",b).toString()).name);
    }
    @Test public void comboSelectsOnlyPacketCredentials() throws Exception {
        JSONObject b=bundle(),packet=b.getJSONObject("config");
        b.put("config",new JSONObject().put("role","client").put("version",1).put("transport","combo-tls").put("boring",packet)
            .put("transparent",new JSONObject().put("secret_path","@bundle/relay.psk")));
        assertTrue(new Enrollment(b.toString()).fromCombo);
    }
    @Test public void engineUsesOnlyPrivatePathsAndDisablesLinuxDns() throws Exception {
        Enrollment e=new Enrollment(bundle().toString());JSONObject engine=e.engine("/private/app",true);
        assertEquals("/private/app/psk",engine.getString("secret_path"));assertFalse(engine.getBoolean("dns"));
        assertEquals("persistent",engine.getString("connection_mode"));assertFalse(engine.has("transport"));
    }
    @Test public void rejectsServerPathsAndTraversal() throws Exception {
        for(String p:new String[]{"/etc/secret","@bundle/../psk","@bundle/relay.psk"}){
            JSONObject b=bundle();b.getJSONObject("config").put("secret_path",p);rejected(b);
        }
    }
    @Test public void rejectsInvalidAddressAndPort() throws Exception {
        for(String ip:new String[]{"exit.example.com","127.0.0.1","0.0.0.0","1.2.3.256","01.2.3.4","224.0.0.1","::1"}){
            JSONObject b=bundle();b.getJSONObject("config").put("address",ip);rejected(b);
        }
        for(Object port:new Object[]{0,65536,443.5,"443"}){JSONObject b=bundle();b.getJSONObject("config").put("port",port);rejected(b);}
    }
    @Test public void rejectsWrongRoleTransportAndPeer() throws Exception {
        JSONObject b=bundle();b.getJSONObject("config").put("role","exit");rejected(b);
        b=bundle();b.getJSONObject("config").put("transport","transparent-tls");rejected(b);
        for(String peer:new String[]{"10.99.0.0","10.99.0.1","10.99.0.255","10.99.1.2"}){
            b=bundle();b.getJSONObject("config").put("peer_ipv4",peer);rejected(b);
        }
    }
    @Test public void rejectsMalformedOrWrongLengthKeys() throws Exception {
        for(String key:new String[]{"@@@@","AA=A","AB==","AAA=\n",Base64.getEncoder().encodeToString(new byte[31]),Base64.getEncoder().encodeToString(new byte[33])}){
            JSONObject b=bundle();b.getJSONObject("files").put("psk",key);rejected(b);
        }
    }
    @Test public void acceptsProfileAndExplicitDns() throws Exception {
        JSONObject b=bundle();b.getJSONObject("config").put("tls_profile_path","@bundle/profile.json").put("address_assignment","v1");
        b.getJSONObject("files").put("profile.json",Base64.getEncoder().encodeToString("{}".getBytes("UTF-8")));
        b.put("android_dns",new JSONArray().put("9.9.9.9"));Enrollment e=new Enrollment(b.toString());
        assertNotNull(e.profile);assertArrayEquals(new String[]{"9.9.9.9"},e.dns);
        assertEquals("v1",e.engine("/app",true).getString("address_assignment"));assertFalse(e.engine("/app",false).has("tls_profile_path"));
    }
    @Test public void rejectsDnsBypassAndBadCount() throws Exception {
        for(String server:new String[]{"localhost","::1","127.0.0.53","0.0.0.0","192.0.2.10","10.99.0.4"}){
            JSONObject b=bundle().put("android_dns",new JSONArray().put(server));rejected(b);
        }
        rejected(bundle().put("android_dns",new JSONArray()));rejected(bundle().put("android_dns","1.1.1.1"));
    }
    @Test public void decoderRoundTripsEveryByteAndPadding() throws Exception {
        for(int size=1;size<=256;size++){
            byte[] bytes=new byte[size];for(int i=0;i<size;i++)bytes[i]=(byte)i;
            assertArrayEquals(bytes,Enrollment.decode(Base64.getEncoder().encodeToString(bytes),size));
        }
    }
    @Test public void rejectsOversizedImport() throws Exception {
        JSONObject b=bundle();char[] huge=new char[Enrollment.LIMIT];java.util.Arrays.fill(huge,'a');b.put("padding",new String(huge));rejected(b);
    }
}
