import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const text=fs.readFileSync(new URL('../components/meshvpn_web/web_ui.h',import.meta.url),'utf8');
for(const part of text.split('static const char ').slice(1)){
  const html=part.split('\n').filter(l=>l.startsWith('"')).map(l=>JSON.parse(l.endsWith(';')?l.slice(0,-1):l)).join('');
  const ids=[...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m=>m[1]);
  assert.equal(new Set(ids).size,ids.length,'duplicate DOM id');
  for(const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g)){
    new vm.Script(script[1]);
    for(const use of script[1].matchAll(/\$\(['"]([^'"]+)['"]\)/g))
      assert(ids.includes(use[1]),'missing DOM id: '+use[1]);
    if(part.startsWith('MESHVPN_WEB_INDEX_HTML')){
      assert(html.includes('href="//meshpn.local/"'),'admin link must preserve HTTP/HTTPS');
      assert(html.includes('id="certificate-section" hidden'),'certificate controls hidden before status');
      const wgForm=html.slice(html.indexOf("<div id='vpn-wg-fields'"),html.indexOf("<button id='vpn-save'"));
      const ordered=['<h3>[Interface]</h3>','<label>PrivateKey','<label>Address','<label>DNS',
        '<h3>[Peer]</h3>','<label>PublicKey','<label>Endpoint','<label>AllowedIPs','<label>PersistentKeepalive'];
      let previous=-1;
      for(const label of ordered){const index=wgForm.indexOf(label);assert(index>previous,'WireGuard config order: '+label);previous=index;}
      assert(wgForm.includes("id='wg-allowed-ips' value='0.0.0.0/0' readonly"));
      assert(wgForm.includes("id='wg-address' maxlength='159'"),'Address must fit a CIDR/IPv6 list');
      // Exercise the production status renderer in both modes, without starting
      // the unrelated WiFi scan loop or scheduling real timers/network calls.
      const startup='poll();run(async()=>{await loadProfiles();await scanNetworks(true);})();';
      assert(script[1].includes(startup));
      const code=script[1].replace(startup,'');
      for(const https of [false,true]){
        const elements=Object.fromEntries(ids.map(id=>[id,{}]));
        const status={https_enabled:https,certificate_sha256:https?'AA:BB':null,
          https_configured:https,https_restart_required:false,admin_next_url:(https?'https':'http')+'://meshpn.local/',
          temperature_c:42,memory:{internal:{free:1024},psram:{free:2048}},
          vpn:{implemented:true,enabled:false,server:'',transport:'socket',state:'disabled'},
          leds:{user:{controllable:true,enabled:true},charge:{present:true,controllable:false,enabled:null}},
          cpu:{cores:[{id:0,load_pct:37},{id:1,load_pct:12}],tasks:[]},
          wifi:{connected:false,state:'setup'},usb:{profile:'ncm',host_ready:true},
          net:{usb_ip:'192.168.7.1',ap_active:https,ap_ssid:'MeshPN_aabbcc',ap_ip:'192.168.4.1',
            ap_channel:6,ap_clients:2,ap_napt:true},must_change_password:false};
        let accepted=true,failSave=false,saves=0,reboots=0,revoked=0,ledFail=false,ledSaves=0,statusFetches=0;
        const context=vm.createContext({
          document:{hidden:false,getElementById:id=>elements[id],addEventListener(){}},
          sessionStorage:{getItem:()=> 'test-token',removeItem:()=>revoked++},location:{protocol:https?'https:':'http:'},
          confirm:()=>accepted,
          AbortSignal:{timeout:()=>undefined},setTimeout:()=>1,clearTimeout(){},
          fetch:async (path,options)=>{
            if(path==='/api/admin/https'){
              assert.equal(options.method,'POST');
              saves++;
              if(failSave)return {ok:false,status:500,text:async()=> 'Cannot save HTTPS mode'};
              const {enabled}=JSON.parse(options.body);
              assert.equal(typeof enabled,'boolean');
              status.https_configured=enabled;status.https_restart_required=enabled!==https;
              status.admin_next_url=(enabled?'https':'http')+'://meshpn.local/';
            }else if(path==='/api/admin/leds'){
              assert.equal(options.method,'POST');assert.equal(options.headers.Authorization,'Bearer test-token');
              ledSaves++;
              if(ledFail)return {ok:false,status:500,text:async()=> 'Cannot save LED setting'};
              const payload=JSON.parse(options.body);
              assert.deepEqual(Object.keys(payload),['user_enabled']);assert.equal(typeof payload.user_enabled,'boolean');
              status.leds.user.enabled=payload.user_enabled;
            }else if(path==='/api/vpn/config'){
              assert.equal(options.method,'POST'); assert.equal(options.headers.Authorization,'Bearer test-token');
              const cfg=JSON.parse(options.body);assert(['socket','wireguard'].includes(cfg.transport));
              assert(!cfg.enabled||cfg.transport==='wireguard'||cfg.allow_plaintext);
              Object.assign(status.vpn,{enabled:cfg.enabled,transport:cfg.transport,server:cfg.server,kill_switch:cfg.kill_switch});
              if(cfg.transport==='wireguard')status.vpn.wireguard={address:cfg.wg_address.split(',')[0].split('/')[0],address_input:cfg.wg_address,dns:cfg.wg_dns,
                public_key:cfg.wg_public_key,keepalive:cfg.wg_keepalive,private_key_set:true,preshared_key_set:false};
            }else if(path==='/api/vpn/restart'||path==='/api/vpn/check'){
              assert.equal(options.method,'POST');assert.equal(options.headers.Authorization,'Bearer test-token');
            }else if(path==='/api/system/reboot'){
              assert.equal(options.method,'POST');reboots++;
            }else {assert.equal(path,'/api/status');statusFetches++;}
            return {ok:true,status:200,json:async()=>({...status})};
          }
        });
        vm.runInContext(code,context);
        await vm.runInContext('poll()',context);
        status.wifi={connected:false,state:'waiting_for_network',ssid:'iPhone hotspot',
          disconnect_reason:39,disconnect_reason_name:'association_timeout'};
        await vm.runInContext('poll()',context);
        assert.equal(elements.connection.textContent,
          'WiFi: waiting_for_network · iPhone hotspot · association_timeout (39)');
        const frozen=elements.status.textContent,fetchesBeforePause=statusFetches;
        elements['status-refresh'].onclick();
        assert.equal(elements['status-refresh'].textContent,'Resume updates');
        assert(elements['status-refresh-note'].textContent.includes('frozen'));
        status.temperature_c=99;
        await vm.runInContext('poll()',context);
        assert.equal(statusFetches,fetchesBeforePause,'paused diagnostics must not fetch');
        assert.equal(elements.status.textContent,frozen,'paused diagnostics must remain copyable');
        await elements['status-refresh'].onclick();
        assert.equal(elements['status-refresh'].textContent,'Pause updates');
        assert.equal(statusFetches,fetchesBeforePause+1,'resume refreshes immediately');
        assert(elements.status.textContent.includes('99'));
        assert(elements['vpn-summary'].textContent.includes('VPN OFF'));
        assert.equal(elements['vpn-kill-switch'].checked,true);
        assert(elements['wg-performance'].textContent.includes('waiting'));
        vm.runInContext(`renderWgPerformance({wireguard_active:{available:true,interval_ms:2000,age_sec:7,
          core_load_pct:[98,12],encrypt_us:900000,encrypt_calls:300,decrypt_us:0,decrypt_calls:0}})`,context);
        assert(elements['wg-performance'].textContent.includes('CPU0 98.0% / CPU1 12.0%'));
        assert(elements['wg-performance'].textContent.includes('Encrypt 3.000 ms/call'));
        assert(elements['wg-performance'].textContent.includes('Decrypt n/a'));
        assert(elements['wg-performance'].textContent.includes('7 s ago'));
        vm.runInContext(`renderSocketFailure({last_error:0,connected:true,socket:{last_failure:{available:true,
          reason:'rx_frame_timeout',error:116,age_sec:9,generation:2}}})`,context);
        assert(elements['socket-last-failure'].textContent.includes('rx_frame_timeout'));
        assert(elements['socket-last-failure'].textContent.includes('9 s ago'));
        vm.runInContext('renderSocketFailure({})',context);
        assert.equal(elements['socket-last-failure'].textContent,'');
        elements['vpn-server'].value='192.0.2.1:8765';elements['vpn-server'].oninput();
        elements['vpn-enabled'].checked=true;elements['vpn-enabled'].oninput();
        await vm.runInContext('poll()',context);
        assert.equal(elements['vpn-server'].value,'192.0.2.1:8765','poll preserves VPN edits');
        await elements['vpn-form'].onsubmit();assert.equal(status.vpn.enabled,false,'plaintext opt-in required');
        elements['vpn-plaintext'].checked=true;
        await elements['vpn-form'].onsubmit();assert.equal(status.vpn.enabled,true);assert.equal(reboots,0);
        elements['vpn-enabled'].checked=false;elements['vpn-enabled'].oninput();
        await elements['vpn-form'].onsubmit();assert.equal(status.vpn.enabled,false);
        assert(elements.message.textContent.includes('VPN is OFF'));
        elements['vpn-transport'].value='wireguard';elements['vpn-transport'].oninput();
        assert.equal(elements['vpn-wg-fields'].hidden,false);assert.equal(elements['vpn-socket-fields'].hidden,true);
        elements['wg-endpoint'].value='198.51.100.7:51820';elements['wg-endpoint'].oninput();
        await vm.runInContext('poll()',context);
        assert.equal(elements['wg-endpoint'].value,'198.51.100.7:51820','poll preserves endpoint edit');
        elements['wg-address'].value='10.0.0.7/24,fd42:42:42::7/64';elements['wg-dns'].value='1.1.1.1';
        elements['wg-public-key'].value='test-peer-public';elements['wg-private-key'].value='test-device-secret';
        elements['wg-psk'].value='';elements['vpn-enabled'].checked=true;elements['vpn-plaintext'].checked=false;
        await elements['vpn-form'].onsubmit();assert.equal(status.vpn.transport,'wireguard');
        assert.equal(status.vpn.server,'198.51.100.7:51820','WG uses Endpoint, not hidden socket server');
        assert.equal(elements['wg-endpoint'].value,status.vpn.server,'render saved endpoint');
        assert.equal(status.vpn.wireguard.address,'10.0.0.7','effective IPv4');
        assert.equal(elements['wg-address'].value,'10.0.0.7/24,fd42:42:42::7/64','original Address survives save and poll');
        assert.equal(elements['wg-private-key'].value,'','clear secret field after success');
        assert(!elements.status.textContent.includes('test-device-secret'),'status must not contain private key');
        assert(status.vpn.kill_switch);
        status.vpn.connected=false;status.vpn.state='handshake';await vm.runInContext('poll()',context);
        assert(elements['vpn-summary'].textContent.includes('BLOCKED'));
        assert(elements['vpn-check'].disabled);
        elements['vpn-kill-switch'].checked=false;elements['vpn-kill-switch'].oninput();
        accepted=false;await elements['vpn-form'].onsubmit();assert(status.vpn.kill_switch,'require direct fallback confirmation');
        accepted=true;await elements['vpn-form'].onsubmit();assert.equal(status.vpn.kill_switch,false);
        assert(elements['vpn-summary'].textContent.includes('DIRECT fallback'));
        status.vpn.connected=true;await vm.runInContext('poll()',context);
        assert(elements['vpn-summary'].textContent.includes('tunnel connected'));
        assert(elements['vpn-internet'].textContent.includes('not tested'));
        await elements['vpn-reconnect'].onclick();assert.equal(reboots,0);
        await elements['vpn-check'].onclick();
        status.vpn.internet_probe={tested:true,ok:true,age_sec:0,error:0};await vm.runInContext('poll()',context);
        assert(elements['vpn-internet'].textContent.includes('reachable'));
        assert(elements['vpn-internet'].textContent.includes('DNS/HTTPS not verified'));
        status.vpn.internet_probe.age_sec=61;await vm.runInContext('poll()',context);
        assert(elements['vpn-internet'].textContent.includes('outdated'));
        status.vpn.internet_probe={tested:true,ok:false,age_sec:0,error:110};await vm.runInContext('poll()',context);
        assert(elements['vpn-internet'].textContent.includes('FAILED'));
        vm.runInContext('renderVpn(null)',context);
        assert(elements['vpn-summary'].textContent.includes('unavailable'));assert(elements['vpn-check'].disabled);
        assert.equal(elements['user-led-enabled'].checked,true);
        assert.equal(elements['charge-led-enabled'].disabled,true);
        assert.equal(elements['charge-led-enabled'].indeterminate,true,'not a measured on/off state');
        elements['user-led-enabled'].checked=false;elements['user-led-enabled'].onchange();
        await vm.runInContext('poll()',context);
        assert.equal(elements['user-led-enabled'].checked,false,'poll preserves unsaved LED choice');
        ledFail=true;await elements['save-leds'].onclick();
        assert.equal(status.leds.user.enabled,true);assert.equal(elements.message.textContent,'Cannot save LED setting');
        assert.equal(elements['save-leds'].disabled,false);
        ledFail=false;await elements['save-leds'].onclick();assert.equal(ledSaves,2);
        assert.equal(status.leds.user.enabled,false);assert.equal(reboots,0);
        await vm.runInContext('poll()',context);assert.equal(elements['user-led-enabled'].checked,false);
        status.leds.user={controllable:false,enabled:null};status.leds.charge.present=false;
        await vm.runInContext('poll()',context);
        assert.equal(elements['user-led-enabled'].disabled,true);assert.equal(elements['save-leds'].disabled,true);
        assert.equal(elements['charge-led-row'].hidden,true);
        delete status.leds;await vm.runInContext('poll()',context);assert.equal(elements['save-leds'].disabled,true);
        assert.equal(elements['certificate-section'].hidden,!https);
        assert.equal(elements.fingerprint.textContent,https?'AA:BB':'');
        assert(elements.usb.textContent.includes((https?'https':'http')+'://192.168.7.1/'));
        assert.equal(elements.cpu.textContent,'CPU0 37.0% · CPU1 12.0%');
        status.cpu.cores[0].load_pct=null;
        status.cpu.cores[1].load_pct=0.14321;
        await vm.runInContext('poll()',context);
        assert.equal(elements.cpu.textContent,'CPU0 — · CPU1 0.1%');
        status.cpu.available=false;
        await vm.runInContext('poll()',context);
        assert.equal(elements.cpu.textContent,'CPU0 — · CPU1 —');
        delete status.cpu;
        await vm.runInContext('poll()',context);
        assert.equal(elements.cpu.textContent,'CPU telemetry unavailable');
        assert.equal(elements.ap.textContent,https?
          'AP: MeshPN_aabbcc · 192.168.4.1 · channel 6 · clients 2 · NAT on · admin: https://192.168.4.1/':
          'WiFi AP disabled');
        assert.equal(elements['https-enabled'].checked,https);
        assert.equal(elements['https-pending'].hidden,true);
        elements['https-enabled'].checked=!https;
        elements['https-enabled'].onchange();
        await vm.runInContext('poll()',context);
        assert.equal(elements['https-enabled'].checked,!https,'poll must not overwrite unsaved checkbox');
        accepted=false;await elements['save-https'].onclick();assert.equal(saves,0);
        accepted=true;failSave=true;await elements['save-https'].onclick();
        assert.equal(status.https_configured,https,'failed save must not change persisted mode');
        assert.equal(elements.message.textContent,'Cannot save HTTPS mode');
        assert.equal(elements['save-https'].disabled,false);
        failSave=false;await elements['save-https'].onclick();
        assert.equal(status.https_enabled,https,'save must not change active transport');
        assert.equal(status.https_configured,!https);
        assert.equal(elements['https-pending'].hidden,false);
        assert.equal(elements['https-next-url'].href,(!https?'https':'http')+'://meshpn.local/');
        accepted=false;await elements['apply-https'].onclick();assert.equal(reboots,0);
        accepted=true;await elements['apply-https'].onclick();
        assert.equal(reboots,1);assert.equal(revoked,1);
      }
    }
  }
}
console.log('Web UI JavaScript, DOM references and HTTP/HTTPS status rendering passed');
