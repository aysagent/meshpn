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
          cpu:{cores:[{id:0,load_pct:37},{id:1,load_pct:12}],tasks:[]},
          wifi:{connected:false,state:'setup'},usb:{profile:'ncm',host_ready:true},
          net:{usb_ip:'192.168.7.1',ap_active:https,ap_ssid:'MeshPN_aabbcc',ap_ip:'192.168.4.1',
            ap_channel:6,ap_clients:2,ap_napt:true},must_change_password:false};
        let accepted=true,failSave=false,saves=0,reboots=0,revoked=0;
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
            }else if(path==='/api/system/reboot'){
              assert.equal(options.method,'POST');reboots++;
            }else assert.equal(path,'/api/status');
            return {ok:true,status:200,json:async()=>({...status})};
          }
        });
        vm.runInContext(code,context);
        await vm.runInContext('poll()',context);
        assert.equal(elements['certificate-section'].hidden,!https);
        assert.equal(elements.fingerprint.textContent,https?'AA:BB':'');
        assert(elements.usb.textContent.includes((https?'https':'http')+'://192.168.7.1/'));
        assert.equal(elements.cpu.textContent,'CPU0 37% · CPU1 12%');
        assert.equal(elements.ap.textContent,https?
          'AP: MeshPN_aabbcc · 192.168.4.1 · channel 6 · clients 2 · NAT on · admin via USB only':
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
