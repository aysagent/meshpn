// Run only in a disposable empty Linux network+mount namespace.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {nativeExitHostNetwork} from './lib/native-exit-host-network.mjs';
import {openNativeHostStore,nativeHostScope} from './lib/native-host-store.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_EXIT_HOST,'1');assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
assert.notEqual(fs.readlinkSync('/proc/self/ns/net'),fs.readlinkSync('/proc/1/ns/net'));
const cmd=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:20000,maxBuffer:1024*1024}).trim();
const ip=(...a)=>cmd('ip',a),ipt=(...a)=>cmd('iptables',['-w','5',...a]);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);
ip('link','set','lo','up');ip('link','add','eth0','type','dummy');ip('address','add','192.0.2.1/24','dev','eth0');ip('link','set','eth0','up');
cmd('sysctl',['-w','net.ipv4.ip_forward=1']);
ipt('-N','FOREIGN_SENTINEL');ipt('-A','FORWARD','-j','FOREIGN_SENTINEL');ipt('-t','nat','-A','POSTROUTING','-s','198.51.100.0/24','-o','eth0','-j','MASQUERADE');
const snapshot=()=>({filter:ipt('-S'),nat:ipt('-t','nat','-S'),routes:ip('-N','-j','-4','route','show','table','all'),forward:cmd('sysctl',['-n','net.ipv4.ip_forward'])});
const before=snapshot();let checks=0,crashAt=null,afterTun=false,active=false,store,owner;
let config={version:1,endpoint:'192.0.2.1',port:443,uplink:'eth0',tun:'cvexit0',engine_unit:'native-test.service',network_unit:'native-test-network.service'};
const check=(name,fn)=>{fn();checks++;console.log('EXIT_HOST_CHECK '+name);};
const close=()=>store?.close();
function open(){
  store=openNativeHostStore({kind:'exit'});
  owner=nativeExitHostNetwork(config,{scope:nativeHostScope,randomId:()=>randomBytes(12).toString('hex'),
    store:{read:()=>store.read(),write:s=>{store.write(s);if(crashAt?.(s))throw Error('simulated_crash');}},
    run:(f,a)=>f==='systemctl'?(a[3]==='MainPID'?(active?'123':'0'):a[3]==='ActiveState'?(active?'active':'inactive'):config.network_unit):cmd(f,a),
    createTun:(name,alias)=>{cmd('python3',[fileURLToPath(new URL('./clean-vpn-native-tun.py',import.meta.url)),name,alias]);if(afterTun)throw Error('simulated_crash');}});
}
const baseline=()=>assert.deepEqual(snapshot(),before);
try{
  open();check('prepare and audit keep foreign rules and forwarding',()=>{owner.prepare();owner.tick();assert.match(ipt('-S'),/FOREIGN_SENTINEL/);assert.equal(snapshot().forward,'1');});
  check('running engine prevents cleanup',()=>{active=true;assert.throws(()=>owner.recover(),/native_exit_engine_running/);active=false;});
  check('same-name replacement alias is refused',()=>{const alias=JSON.parse(ip('-j','link','show','cvexit0'))[0].ifalias;ip('link','set','cvexit0','alias','foreign');assert.throws(()=>owner.recover(),/native_exit_tun_owner/);ip('link','set','cvexit0','alias',alias);});
  check('cleanup restores exact baseline',()=>{owner.recover();owner.recover();baseline();});
  check('unrelated firewall update survives scoped recovery',()=>{
    owner.prepare();ipt('-A','FOREIGN_SENTINEL','-s','203.0.113.11','-j','DROP');owner.recover();
    assert.match(ipt('-S','FOREIGN_SENTINEL'),/203\.0\.113\.11\/32/);
    ipt('-D','FOREIGN_SENTINEL','-s','203.0.113.11','-j','DROP');baseline();
  });
  check('foreign subnet route refuses before mutation',()=>{ip('route','add','10.99.0.0/24','dev','eth0');assert.throws(()=>owner.prepare(),/native_exit_peer_subnet_conflict/);ip('route','del','10.99.0.0/24','dev','eth0');baseline();});
  check('foreign TUN is never adopted',()=>{ip('tuntap','add','dev','cvexit0','mode','tun');assert.throws(()=>owner.prepare(),/native_exit_existing_tun/);ip('tuntap','del','dev','cvexit0','mode','tun');baseline();});
  check('disabled forwarding refuses without changing global setting',()=>{cmd('sysctl',['-w','net.ipv4.ip_forward=0']);assert.throws(()=>owner.prepare(),/native_exit_configured_forwarding_required/);assert.equal(snapshot().forward,'0');cmd('sysctl',['-w','net.ipv4.ip_forward=1']);baseline();});
  check('forwarding drift stops audit but recovery preserves external value',()=>{owner.prepare();cmd('sysctl',['-w','net.ipv4.ip_forward=0']);assert.throws(()=>owner.tick(),/native_exit_forwarding_changed/);owner.recover();assert.equal(snapshot().forward,'0');cmd('sysctl',['-w','net.ipv4.ip_forward=1']);baseline();});
  const previous=config;owner.prepare();close();config={...config,engine_unit:'native-next.service',network_unit:'native-next-network.service'};open();
  check('different instance cannot take active ownership',()=>assert.throws(()=>owner.recover(),/native_exit_config_owner_mismatch/));
  close();config=previous;open();owner.recover();close();config={...previous,engine_unit:'native-next.service',network_unit:'native-next-network.service'};open();
  check('new instance follows released journal',()=>{owner.recover();owner.prepare();owner.tick();owner.recover();baseline();});
  for(const point of ['intent','identity','rule1','rule2','rule3']){
    crashAt=s=>point==='intent'?s.stage==='prepared'&&!s.tun:point==='identity'?s.stage==='prepared'&&!!s.tun&&s.count===0:s.count===Number(point.at(-1));
    check('interrupt '+point,()=>assert.throws(()=>owner.prepare(),/simulated_crash/));crashAt=null;close();open();
    check('recover '+point,()=>{owner.recover();baseline();});
  }
  afterTun=true;check('interrupt persistent TUN before identity commit',()=>assert.throws(()=>owner.prepare(),/simulated_crash/));afterTun=false;close();open();
  check('recover TUN by durable alias intent',()=>{owner.recover();baseline();});
  console.log(JSON.stringify({status:'passed',checks,scope:'real netns TUN/routes/iptables; systemd state injected; no payload or physical host'}));
}finally{close();}
