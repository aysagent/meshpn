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
          temperature_c:42,memory:{internal:{free:1024},psram:{free:2048}},
          wifi:{connected:false,state:'setup'},usb:{profile:'ncm',host_ready:true},
          net:{usb_ip:'192.168.7.1'},must_change_password:false};
        const context=vm.createContext({
          document:{hidden:false,getElementById:id=>elements[id],addEventListener(){}},
          sessionStorage:{getItem:()=> 'test-token'},location:{protocol:https?'https:':'http:'},
          AbortSignal:{timeout:()=>undefined},setTimeout:()=>1,clearTimeout(){},
          fetch:async path=>{
            assert.equal(path,'/api/status');
            return {ok:true,status:200,json:async()=>status};
          }
        });
        vm.runInContext(code,context);
        await vm.runInContext('poll()',context);
        assert.equal(elements['certificate-section'].hidden,!https);
        assert.equal(elements.fingerprint.textContent,https?'AA:BB':'');
        assert(elements.usb.textContent.includes((https?'https':'http')+'://192.168.7.1/'));
      }
    }
  }
}
console.log('Web UI JavaScript, DOM references and HTTP/HTTPS status rendering passed');
