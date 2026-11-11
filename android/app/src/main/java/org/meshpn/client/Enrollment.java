package org.meshpn.client;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;

/** Offline, bounded import. Bundle paths never become filesystem paths. */
final class Enrollment {
    static final int LIMIT = 256 * 1024;
    final String name, address, peer, serverName, sni, httpVersion;
    final int port;
    final boolean assignment, fromCombo;
    final byte[] ca, psk, profile;
    final String[] dns;

    private static String string(JSONObject j, String key) throws Exception {
        Object v = j.get(key);
        if (!(v instanceof String)) throw new Exception("Поле " + key + " должно быть строкой");
        return (String) v;
    }
    private static void boundedJson(String text) throws Exception {
        int depth=0;boolean quoted=false,escaped=false;
        for(int i=0;i<text.length();i++){
            char c=text.charAt(i);
            if(quoted){if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"')quoted=false;}
            else if(c=='"')quoted=true;
            else if(c=='{'||c=='['){if(++depth>64)throw new Exception("Слишком глубокая вложенность JSON");}
            else if(c=='}'||c==']'){if(--depth<0)throw new Exception("Некорректный JSON");}
        }
        if(depth!=0||quoted)throw new Exception("Некорректный JSON");
    }
    static boolean ipv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (!p.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(p) > 255) return false;
        }
        return true;
    }
    private static String host(String s) throws Exception {
        if (s.length() > 253 || !s.matches("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"))
            throw new Exception("Некорректное TLS-имя");
        return s;
    }
    // Strict RFC 4648 decoder, also available on API 23 (java.util.Base64 is not).
    static byte[] decode(String s, int limit) throws Exception {
        if (s.isEmpty() || s.length() > ((limit + 2) / 3) * 4 || s.length() % 4 != 0
            || !s.matches("[A-Za-z0-9+/]*={0,2}")) throw new Exception("Некорректный base64");
        int padding = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
        byte[] out = new byte[s.length() / 4 * 3 - padding];
        if (out.length > limit) throw new Exception("Файл слишком большой");
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int at = 0;
        for (int i = 0; i < s.length(); i += 4) {
            int a = alphabet.indexOf(s.charAt(i)), b = alphabet.indexOf(s.charAt(i+1));
            int c = s.charAt(i+2) == '=' ? 0 : alphabet.indexOf(s.charAt(i+2));
            int d = s.charAt(i+3) == '=' ? 0 : alphabet.indexOf(s.charAt(i+3));
            if (a < 0 || b < 0 || c < 0 || d < 0) throw new Exception("Некорректный base64");
            int bits = (a << 18) | (b << 12) | (c << 6) | d;
            if (at < out.length) out[at++] = (byte)(bits >> 16);
            if (at < out.length) out[at++] = (byte)(bits >> 8);
            if (at < out.length) out[at++] = (byte)bits;
            if (i+4 == s.length() && ((padding == 2 && (b & 15) != 0) || (padding == 1 && (c & 3) != 0)))
                throw new Exception("Неканонический base64");
        }
        return out;
    }
    private static byte[] attachment(JSONObject c, JSONObject files, String field, String filename, int limit) throws Exception {
        if (!string(c, field).equals("@bundle/" + filename)) throw new Exception("Нужен переносимый bundle, а не пути с сервера");
        return decode(string(files, filename), limit);
    }
    Enrollment(String text) throws Exception {
        if (text.getBytes(StandardCharsets.UTF_8).length > LIMIT) throw new Exception("Конфигурация больше 256 КиБ");
        boundedJson(text);
        JSONObject root = new JSONObject(text);
        if (root.getInt("version") != 1) throw new Exception("Неизвестная версия bundle");
        if (root.optString("kind").equals("clean-vpn-install-bundle")) root = root.getJSONObject("enrollment");
        if (root.getInt("version") != 1 || !root.optString("kind").equals("clean-vpn-client-enrollment"))
            throw new Exception("Нужен clean-vpn install bundle или client enrollment");
        String label = root.optString("name", "Клиент");
        name = label.length() <= 80 && !label.matches("(?s).*[\\p{Cntrl}].*") ? label : "Клиент";
        JSONObject c = root.getJSONObject("config"), files = root.getJSONObject("files");
        if (!c.optString("role").equals("client")) throw new Exception("Нужна конфигурация клиента");
        String transport = c.optString("transport", "boring-tls");
        fromCombo = transport.equals("combo-tls");
        if (fromCombo) c = c.getJSONObject("boring");
        else if (!transport.equals("boring-tls")) throw new Exception("Поддержан только boring-tls");
        if (c.getInt("version") != 1 || !c.optString("role").equals("client")) throw new Exception("Неверная версия клиента");
        address = string(c, "address");
        if (!ipv4(address) || address.startsWith("0.") || address.startsWith("127.") || Integer.parseInt(address.split("\\.")[0]) >= 224)
            throw new Exception("Exit должен иметь числовой unicast IPv4");
        Object portValue = c.get("port");
        if (!(portValue instanceof Number) || ((Number)portValue).doubleValue() != ((Number)portValue).intValue()) throw new Exception("Неверный порт");
        port = ((Number)portValue).intValue();
        if (port < 1 || port > 65535) throw new Exception("Неверный порт");
        peer = string(c, "peer_ipv4");
        if (!ipv4(peer) || !peer.startsWith("10.99.0.") || Integer.parseInt(peer.substring(8)) < 2 || peer.endsWith(".255"))
            throw new Exception("Нужен выделенный клиенту адрес 10.99.0.2–254");
        serverName = host(string(c, "server_name")); sni = host(c.has("sni") ? string(c, "sni") : serverName);
        httpVersion = c.optString("http_version", "2");
        if (!httpVersion.matches("2|1\\.1|auto")) throw new Exception("Неверная версия HTTP");
        assignment = c.has("address_assignment");
        if (assignment && !string(c, "address_assignment").equals("v1")) throw new Exception("Неверный режим адреса");
        ca = attachment(c, files, "ca", "ca.pem", 65536);
        if (!new String(ca, StandardCharsets.US_ASCII).contains("-----BEGIN CERTIFICATE-----")) throw new Exception("Нет CA-сертификата");
        psk = attachment(c, files, "secret_path", "psk", 32);
        if (psk.length != 32) throw new Exception("Ключ должен содержать 32 байта");
        profile = c.has("tls_profile_path") ? attachment(c, files, "tls_profile_path", "profile.json", 16384) : null;
        if (profile != null){String document=new String(profile, StandardCharsets.UTF_8);boundedJson(document);new JSONObject(document);}
        JSONArray servers = root.optJSONArray("android_dns");
        if (root.has("android_dns") && servers == null) throw new Exception("android_dns должен быть массивом");
        if (servers != null && (servers.length() < 1 || servers.length() > 3)) throw new Exception("Нужно 1–3 DNS-сервера");
        dns = servers == null ? new String[]{"1.1.1.1", "8.8.8.8"} : new String[servers.length()];
        for (int i=0;i<dns.length;i++) {
            if(servers!=null){
                Object v=servers.get(i); if (!(v instanceof String) || !ipv4((String)v)) throw new Exception("DNS должен быть числовым IPv4");
                dns[i]=(String)v;
            }
            int first=Integer.parseInt(dns[i].split("\\.")[0]);
            if(first==0||first==127||first>=224||dns[i].equals(peer)||dns[i].equals(address)) throw new Exception("DNS должен быть доступен через exit");
        }
    }
    JSONObject engine(String directory, boolean useProfile) throws Exception {
        JSONObject c = new JSONObject();
        c.put("version",1).put("role","client").put("address",address).put("port",port)
            .put("server_name",serverName).put("sni",sni).put("peer_ipv4",peer).put("tun","android")
            .put("ca",directory+"/ca.pem").put("secret_path",directory+"/psk").put("dns",false)
            .put("connection_mode","persistent").put("http_version",httpVersion);
        if (assignment) c.put("address_assignment","v1");
        if (profile != null && useProfile) c.put("tls_profile_path",directory+"/profile.json");
        return c;
    }
}
