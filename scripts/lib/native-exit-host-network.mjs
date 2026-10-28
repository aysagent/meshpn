// Scoped network owner for an existing IPv4 exit host. No table/policy flush,
// host DNS/default-route changes, or changes to global IP forwarding.
import assert from 'node:assert/strict';
import {isIPv4} from 'node:net';

export function validateNativeExitHost(c){
  assert.deepEqual(Object.keys(c).sort(),['version','endpoint','port','uplink','tun','engine_unit','network_unit'].sort());
  assert.equal(c.version,1);assert.ok(isIPv4(c.endpoint)&&!/^(0|127|169\.254)\./.test(c.endpoint));
  assert.ok(Number.isInteger(c.port)&&c.port>0&&c.port<65536);
  assert.match(c.uplink,/^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/);assert.notEqual(c.uplink,'lo');
  assert.match(c.tun,/^cvexit[a-z0-9]{0,8}$/);assert.notEqual(c.tun,c.uplink);
  for(const k of ['engine_unit','network_unit'])assert.match(c[k],/^[a-z][a-z0-9-]{0,63}\.service$/);
  assert.notEqual(c.engine_unit,c.network_unit);return c;
}
export function nativeExitHostRules(c,id){
  validateNativeExitHost(c);assert.match(id,/^[a-f0-9]{24}$/);
  const tag=['-m','comment','--comment','cvpn-native-exit-host-'+id];
  return [
    {table:'filter',chain:'FORWARD',spec:['-i',c.tun,'-o',c.uplink,'-s','10.99.0.0/24',...tag,'-j','ACCEPT']},
    {table:'filter',chain:'FORWARD',spec:['-i',c.uplink,'-o',c.tun,'-d','10.99.0.0/24','-m','conntrack','--ctstate','ESTABLISHED,RELATED',...tag,'-j','ACCEPT']},
    {table:'nat',chain:'POSTROUTING',spec:['-s','10.99.0.0/24','-o',c.uplink,...tag,'-j','MASQUERADE']},
  ];
}
const number=ip=>ip.split('.').reduce((n,v)=>n*256+Number(v),0);
function overlaps(cidr){
  const [addr,bits='32']=cidr.split('/');assert.ok(isIPv4(addr)&&/^\d+$/.test(bits));
  const prefix=Number(bits);assert.ok(prefix>=0&&prefix<=32);
  if(!prefix)return false;
  const span=2**(32-prefix),first=Math.floor(number(addr)/span)*span,last=first+span-1;
  return first<=number('10.99.0.255')&&last>=number('10.99.0.0');
}
const canonical=s=>s.replaceAll('"','').replace(/--ctstate ([A-Z,]+)/g,(_,v)=>'--ctstate '+v.split(',').sort().join(','))
  .split(/\s+/).reduce((out,_,i,a)=>i%2?out:[...out,a.slice(i,i+2).join(' ')],[]).sort().join(' ');
const expected=o=>canonical(['-A',o.chain,...o.spec].join(' '));

export function nativeExitHostNetwork(c,{run,store,scope,randomId,createTun}){
  validateNativeExitHost(c);
  const cmd=(f,a)=>run(f,a).trim(),ip=(...a)=>JSON.parse(cmd('ip',a));
  const prop=(u,k)=>cmd('systemctl',['show',u,'-p',k,'--value']);
  const tun=()=>ip('-j','-d','link','show').find(l=>l.ifname===c.tun);
  const ident=l=>({ifindex:l.ifindex,alias:l.ifalias,kind:l.linkinfo?.info_kind});
  const inactive=()=>{assert.equal(prop(c.engine_unit,'MainPID'),'0','native_exit_engine_running');assert.ok(['inactive','failed'].includes(prop(c.engine_unit,'ActiveState')));};
  const rules=table=>cmd('iptables',['-w','5','-t',table,'-S']).split('\n').filter(l=>l.includes('cvpn-native-exit-host-')).map(canonical);
  const validate=s=>{
    assert.deepEqual(Object.keys(s).sort(),['schema','scope','config','id','tun','uplink','firewall','count','stage'].sort());
    assert.equal(s.schema,1);assert.deepEqual(s.scope,scope());validateNativeExitHost(s.config);
    if(s.stage!=='released')assert.deepEqual(s.config,c,'native_exit_config_owner_mismatch');
    assert.match(s.id,/^[a-f0-9]{24}$/);assert.ok(['nf_tables','legacy'].includes(s.firewall));
    assert.ok(['prepared','active','restoring','released'].includes(s.stage));
    assert.ok(Number.isInteger(s.count)&&s.count>=0&&s.count<=3);
    assert.deepEqual(Object.keys(s.uplink).sort(),['ifindex','name']);assert.equal(s.uplink.name,s.config.uplink);assert.ok(Number.isInteger(s.uplink.ifindex)&&s.uplink.ifindex>0);
    if(s.tun){assert.deepEqual(Object.keys(s.tun).sort(),['alias','ifindex','kind']);assert.equal(s.tun.kind,'tun');assert.equal(s.tun.alias,'cvpn-native-exit-host-'+s.id);assert.ok(Number.isInteger(s.tun.ifindex)&&s.tun.ifindex>0);}
    if(s.stage==='active')assert.ok(s.tun&&s.count===3);
    if(s.stage==='released')assert.equal(s.count,0);
  };
  const save=s=>{validate(s);store.write(s);};
  const owned=s=>{const l=tun();if(l){assert.equal(l.linkinfo?.info_kind,'tun','native_exit_tun_type');assert.equal(l.ifalias,'cvpn-native-exit-host-'+s.id,'native_exit_tun_owner');if(s.tun)assert.deepEqual(ident(l),s.tun,'native_exit_tun_replaced');}return l;};
  const present=o=>rules(o.table).filter(l=>l===expected(o)).length===1;
  const audit=(s,all=false)=>{
    validate(s);assert.equal(cmd('iptables',['--version']).match(/\((nf_tables|legacy)\)/)?.[1],s.firewall,'native_exit_firewall_changed');owned(s);
    const intended=nativeExitHostRules(s.config,s.id).slice(0,s.count);
    for(const table of ['filter','nat']){const actual=rules(table),allowed=intended.filter(o=>o.table===table).map(expected);assert.ok(actual.every(l=>allowed.includes(l)),'native_exit_foreign_owned_rule');assert.equal(new Set(actual).size,actual.length,'native_exit_duplicate_rule');}
    if(all){assert.ok(owned(s),'native_exit_tun_missing');for(const o of intended)assert.ok(present(o),'native_exit_rule_missing');}
  };
  const preflight=()=>{
    inactive();assert.ok(!tun(),'native_exit_existing_tun');
    assert.equal(cmd('sysctl',['-n','net.ipv4.ip_forward']),'1','native_exit_configured_forwarding_required');
    const link=ip('-j','link','show').find(l=>l.ifname===c.uplink);assert.ok(link?.flags.includes('UP'),'native_exit_uplink_required');
    const routes=ip('-j','-4','route','show','table','all');
    assert.ok(routes.some(r=>r.dst===c.endpoint&&r.type==='local'),'native_exit_local_endpoint_required');
    for(const r of routes)if(r.dst&&r.dst!=='default')assert.ok(!overlaps(r.dst),'native_exit_peer_subnet_conflict');
    assert.ok(prop(c.engine_unit,'BindsTo').split(/\s+/).includes(c.network_unit),'native_exit_engine_dependency');
    for(const table of ['filter','nat'])assert.equal(rules(table).length,0,'native_exit_unowned_rules');
    return {ifindex:link.ifindex,name:c.uplink};
  };
  return {
    preflight,
    recover(){
      const s=store.read();if(!s)return;validate(s);if(s.stage==='released')return;
      inactive();audit(s);s.stage='restoring';save(s);
      const plan=nativeExitHostRules(s.config,s.id);
      while(s.count){const o=plan[s.count-1];if(present(o))cmd('iptables',['-w','5','-t',o.table,'-D',o.chain,...o.spec]);assert.ok(!present(o));s.count--;save(s);}
      if(owned(s))cmd('ip',['tuntap','del','dev',c.tun,'mode','tun']);assert.ok(!tun());s.stage='released';save(s);
      return {state:'released',hostForwardingChanged:false};
    },
    prepare(){
      const old=store.read();if(old){validate(old);assert.equal(old.stage,'released','native_exit_recovery_required');}
      const uplink=preflight(),firewall=cmd('iptables',['--version']).match(/\((nf_tables|legacy)\)/)?.[1];assert.ok(firewall);
      const s={schema:1,scope:scope(),config:structuredClone(c),id:randomId(),tun:null,uplink,firewall,count:0,stage:'prepared'};
      save(s);createTun(c.tun,'cvpn-native-exit-host-'+s.id);s.tun=ident(owned(s));save(s);
      for(const o of nativeExitHostRules(c,s.id)){s.count++;save(s);cmd('iptables',['-w','5','-t',o.table,'-I',o.chain,'1',...o.spec]);assert.ok(present(o));}
      s.stage='active';save(s);audit(s,true);return {state:'network-ready',readinessProbed:false};
    },
    tick(){
      const s=store.read();validate(s);assert.equal(s.stage,'active');audit(s,true);
      assert.equal(cmd('sysctl',['-n','net.ipv4.ip_forward']),'1','native_exit_forwarding_changed');
      const l=ip('-j','link','show').find(l=>l.ifname===c.uplink);assert.equal(l?.ifindex,s.uplink.ifindex,'native_exit_uplink_replaced');
      const t=owned(s);assert.equal(t.mtu,1400);assert.ok(t.flags.includes('UP'));
      const addresses=ip('-j','-4','address','show','dev',c.tun)[0].addr_info;assert.deepEqual(addresses.map(a=>[a.local,a.prefixlen]),[['10.99.0.1',24]]);
      return {state:l.flags.includes('LOWER_UP')?'network-ready':'waiting-uplink'};
    },
  };
}
