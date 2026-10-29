// Two installed host clients and one installed exit; disposable systemd only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {installNative} from './native-install.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_HOST_MULTI,'1');
assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:60000,maxBuffer:1024*1024}).trim();
const ip=(...a)=>run('ip',a),ctl=(...a)=>run('systemctl',a);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');
const ns=(n,f,a)=>run('ip',['netns','exec',n,f,...a]);
const put=(p,b,mode=0o600)=>{fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,b,{mode});};
const unit=(n,b)=>put('/etc/systemd/system/'+n,b,0o644);
const prop=(u,k)=>ctl('show',u,'-p',k,'--value');
const engine=n=>`native-${n}.service`,owner=n=>`native-${n}-network.service`;
const wait=async fn=>{const end=performance.now()+60000;let error;while(performance.now()<end){try{return fn();}catch(e){error=e;await delay(200);}}throw error;};
const checks=[],check=s=>{checks.push(s);console.log('HOST_MULTI_CHECK='+s);};
const combo=process.env.CVPN_HOST_MULTI_COMBO==='1';
const peers=[['one','10.99.0.2',11],['two','10.99.0.37',12]],binary='/usr/local/bin/clean-vpn-engine';
const probe=`const https=require('node:https'),fs=require('node:fs');const q=https.get({host:'198.18.0.80',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:4000},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{if(b!=='native-runtime-https-ok\\n'||r.headers['x-native-runtime-peer']!=='192.168.13.1')process.exit(2);console.log('HTTPS_OK')});});q.on('error',()=>process.exit(3));q.on('timeout',()=>q.destroy());setTimeout(()=>process.exit(4),5000).unref();`;
const https=n=>assert.equal(ns(n,'node',['-e',probe]),'HTTPS_OK');
const dns=n=>assert.equal(ns(n,'node',['--input-type=module','-e',`import {dnsProbe} from '/project/scripts/clean-vpn-native-runtime-health.mjs';await dnsProbe('9.9.9.9',53,false);await dnsProbe('9.9.9.9',53,true);console.log('DNS_OK');`]),'DNS_OK');
const relayHttps=(n,denied=false)=>assert.equal(ns(n,'node',['-e',probe.replace("host:'198.18.0.80',port:8443",`host:'${denied?'198.18.0.80':'11.22.33.44'}',port:443`)]),'HTTPS_OK');
const healthy=n=>{assert.equal(prop(engine(n),'ActiveState'),'active');https(n);https(n+'usb');dns(n);dns(n+'usb');if(combo)relayHttps(n+'usb');};
const logs=()=>{for(const n of ['one','two','exit'])try{console.log(run('journalctl',['-u',owner(n),'-u',engine(n),'--no-pager','-n','40']));}catch{}};
let success=false;
try{
  for(const n of ['one','two','oneusb','twousb','exit','origin']){ip('netns','add',n);ip('-n',n,'link','set','lo','up');}
  const link=(a,an,addr,b,bn,baddr)=>{
    ip('link','add',an,'netns',a,'type','veth','peer','name',bn,'netns',b);
    for(const [n,d,c] of [[a,an,addr],[b,bn,baddr]]){ip('-n',n,'addr','add',c,'dev',d);ip('-n',n,'link','set',d,'up');}
  };
  for(const [n,,subnet] of peers){
    link(n,'wlan0',`192.168.${subnet}.8/24`,'exit','in'+subnet,`192.168.${subnet}.1/24`);
    link(n,'usb0','192.168.7.1/24',n+'usb','gadget','192.168.7.19/24');
    ip('-n',n,'route','add','default','via',`192.168.${subnet}.1`);ip('-n',n+'usb','route','add','default','via','192.168.7.1');
    ns(n,'sysctl',['-w','net.ipv4.ip_forward=1']);
  }
  link('exit','eth0','192.168.13.1/24','origin','uplink','192.168.13.2/24');
  ip('-n','exit','route','add','default','via','192.168.13.2');ip('-n','exit','addr','add','154.62.226.216/32','dev','lo');
  ns('exit','sysctl',['-w','net.ipv4.ip_forward=1']);
  for(const addr of ['1.1.1.1','8.8.8.8','198.18.0.80',...(combo?['11.22.33.44']:[])])ip('-n','origin','addr','add',addr+'/32','dev','lo');
  for(const p of ['udp','tcp'])ns('origin','iptables',['-t','nat','-A','PREROUTING','-p',p,'--dport','53','-j','REDIRECT','--to-ports','5353']);
  fs.mkdirSync('/config',{mode:0o700});
  run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=runtime.test','-addext','subjectAltName=DNS:runtime.test','-keyout','/config/key.pem','-out','/config/cert.pem']);
  put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('/project/scripts/autostart/killswitch.sh'),0o755);
  put('/config/profile.json',fs.readFileSync('/project/fixtures/native-tls-profiles/chromium-156-bounded-cold.json'));
  const config={version:1,address:'154.62.226.216',port:443};
  if(combo)put('/config/relay.psk',randomBytes(32));
  const wrap=packet=>combo?{version:1,transport:'combo-tls',role:packet.role,boring:{...packet,...(packet.role==='client'?{sni:'relay.example'}:{})},
    transparent:{version:1,transport:'transparent-tls',role:packet.role,public_name:'relay.example',secret_path:'/config/relay.psk',
      destination_policy:{mode:'public-https',deny_ipv4:[]},listen:{ipv4:packet.role==='client'?'0.0.0.0':packet.address,port:packet.role==='client'?10443:packet.port},
      ...(packet.role==='client'?{exit:{ipv4:packet.address,port:packet.port}}:{replay_directory:'/config/never-created-replay'})}}:packet;
  for(const [n,peer_ipv4] of peers){
    put('/config/'+n+'.psk',randomBytes(32));
    put('/config/'+n+'.json',JSON.stringify(wrap({...config,role:'client',tun:'tun0',peer_ipv4,dns:true,secret_path:'/config/'+n+'.psk',server_name:'runtime.test',ca:'/config/cert.pem',tls_profile_path:'/config/profile.json'})));
    unit(n+'-guard.service',`[Service]\nType=oneshot\nRemainAfterExit=yes\nNetworkNamespacePath=/run/netns/${n}\nExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --server=154.62.226.216 --ssh-port=22 --usb-dns=1 --usb-strict=1\n`);
    put('/config/'+n+'-host.json',JSON.stringify({version:1,guard_unit:n+'-guard.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
    installNative({name:n,binary,config:'/config/'+n+'.json',hostProfile:'/config/'+n+'-host.json',apply:true});
  }
  put('/config/exit.json',JSON.stringify(wrap({...config,role:'exit',tun:'cvexit0',cert:'/config/cert.pem',key:'/config/key.pem',peers:peers.map(([n,ipv4])=>({ipv4,secret_path:'/config/'+n+'.psk'}))})));
  put('/config/exit-host.json',JSON.stringify({version:1,uplink:'eth0'}));
  installNative({name:'exit',binary,config:'/config/exit.json',exitProfile:'/config/exit-host.json',apply:true});
  for(const n of ['one','two','exit'])for(const u of [engine(n),owner(n)])put('/etc/systemd/system/'+u+'.d/lab.conf',`[Service]\nNetworkNamespacePath=/run/netns/${n}\n`,0o644);
  if(combo)put('/config/combo-origin.mjs',fs.readFileSync('/project/scripts/lib/native-runtime-lab-origin.mjs','utf8')+`\nhttps.createServer({key:fs.readFileSync('/config/key.pem'),cert:fs.readFileSync('/config/cert.pem')},(req,res)=>{res.setHeader('x-native-runtime-peer',req.socket.remoteAddress);res.end('native-runtime-https-ok\\n');}).listen(443,'0.0.0.0');\n`);
  unit('multi-origin.service','[Service]\nNetworkNamespacePath=/run/netns/origin\nExecStart=/usr/bin/node '+(combo?'/config/combo-origin.mjs':'/project/scripts/lib/native-runtime-lab-origin.mjs')+'\n');
  ctl('daemon-reload');
  for(const n of ['one','two','exit'])assert.equal(prop(owner(n),'MainPID'),'0');check('three installs remain disabled and stopped');
  ctl('start','multi-origin.service',owner('exit'),owner('one'),owner('two'));
  await wait(()=>{healthy('one');healthy('two');});check('two clients and overlapping USB subnets share one native exit with HTTPS UDP TCP DNS');
  for(const [n,addr] of peers){assert.equal(JSON.parse(ns(n,'ip',['-j','-4','addr','show','dev','tun0']))[0].addr_info[0].local,addr);assert.match(ns(n,'iptables',['-t','nat','-S']),new RegExp('--to-source '+addr.replaceAll('.','\\.')));}check('distinct native peer addresses and USB SNAT');
  if(combo){for(const [n] of peers)assert.throws(()=>relayHttps(n+'usb',true));check('combo relay serves public HTTPS; excluded HTTPS cannot downgrade to boring packet branch');}
  const unaffected=prop(engine('two'),'MainPID');ctl('stop',owner('one'));healthy('two');assert.equal(prop(engine('two'),'MainPID'),unaffected);assert.throws(()=>https('oneusb'));check('stopping first client preserves second and blocks first USB egress');
  ctl('start',owner('one'));await wait(()=>healthy('one'));healthy('two');check('first client rejoins without restarting second');
  const prior=prop(owner('one'),'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',owner('one'));
  healthy('two');await wait(()=>{assert.notEqual(prop(owner('one'),'MainPID'),prior);healthy('one');});assert.equal(prop(engine('two'),'MainPID'),unaffected);check('client owner crash recovery is isolated');
  const oldExit=prop(owner('exit'),'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',owner('exit'));
  await wait(()=>{assert.notEqual(prop(owner('exit'),'MainPID'),oldExit);healthy('one');healthy('two');});check('exit owner crash reconnects both clients with unchanged identities');
  // Incorrect key cannot claim the other assigned identity; client one stays online.
  ctl('stop',owner('two'));
  const c=JSON.parse(fs.readFileSync('/opt/clean-vpn-native/two/config.json'));(combo?c.boring:c).secret_path='/config/one.psk';put('/config/wrong-peer.json',JSON.stringify(c));
  ctl('start',owner('two'));await wait(()=>healthy('two'));ctl('stop',engine('two'));
  let rejected;try{ns('two','timeout',['8',binary,'--config','/config/wrong-peer.json','--service']);}catch(e){rejected=e;}
  assert.ok(rejected);assert.doesNotMatch(String(rejected.stdout),/"state":"ready"/);assert.match(String(rejected.stdout)+String(rejected.stderr),/tls_read|tls_peer_closed|h2_peer_end_stream|h2_stream_closed/);healthy('one');check('a key for peer one cannot authenticate peer two');
  ctl('stop',owner('two'),owner('one'),owner('exit'));
  for(const n of ['one','two','exit']){
    assert.equal(prop(owner(n),'Result'),'success');
    assert.equal(prop(engine(n),'MainPID'),'0');
    assert.ok(!JSON.parse(ip('-n',n,'-j','link')).some(l=>['tun0','cvexit0'].includes(l.ifname)));
    for(const table of ['nat','mangle','filter'])assert.doesNotMatch(ns(n,'iptables',['-t',table,'-S']),/cvpn-native-(?:exit-)?host-|clean-vpn-dns-tunnel-|clean-vpn-native-combo-|CVPN-CT-/);
  }
  for(const [n] of peers){assert.match(ns(n,'/usr/local/bin/clean-vpn-killswitch.sh',['status']),/IPv6: cvks4/);assert.throws(()=>https(n+'usb'));}
  check('all owners release TUN DNS NAT routes; both guards survive');
  if(combo){assert.ok(fs.statSync('/opt/clean-vpn-native/exit/replay/state').size>0);check('exit replay state retained after all owner and engine stops');}
  success=true;console.log('HOST_MULTI_REPORT='+JSON.stringify({schema:1,status:'passed',transport:combo?'combo-tls':'boring-tls',clients:2,exit:1,checks,peerAddresses:peers.map(p=>p[1]),scope:'real-systemd-netns-installed-host-profiles; no physical reboot or capacity claim'}));
}finally{
  if(!success)logs();
  for(const n of ['one','two','exit'])try{ctl('stop',owner(n));}catch{}
  try{ctl('stop','multi-origin.service');}catch{}
}
