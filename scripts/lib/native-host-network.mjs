// Reviewed Radxa IPv4 profile. Control plane only; all payload IO stays native.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import {validateNativeComboRedirectConfig} from './native-combo-redirect-plan.mjs';
import {validateTunnelDnsAddress} from './dns-tunnel-plan.mjs';

export function validateNativeHostConfig(c) {
  assert.deepEqual(Object.keys(c).sort(), ['version','exit_ip','engine_unit','network_unit','guard_unit','guard_script', ...('peer_ipv4' in c ? ['peer_ipv4'] : []),...('combo_redirect' in c ? ['combo_redirect'] : []),...('incoming_tcp' in c ? ['incoming_tcp'] : [])].sort());
  if('incoming_tcp' in c)validateNativeIncoming(c.incoming_tcp);
  validateTunnelDnsAddress('peer_ipv4' in c ? c.peer_ipv4 : '10.99.0.2');
  if('combo_redirect' in c){const r=validateNativeComboRedirectConfig(c.combo_redirect);assert.equal(r.interface,'usb0');assert.equal(r.subnet,'192.168.7.0/24');assert.equal(r.endpoint,c.exit_ip);if(c.incoming_tcp)assert.notEqual(c.incoming_tcp.port,r.listen_port,'native_incoming_relay_port_conflict');}
  assert.equal(c.version, 1); assert.ok(isIPv4(c.exit_ip));
  assert.ok(!/^(0|127|169\.254)\./.test(c.exit_ip));
  for (const key of ['engine_unit','network_unit','guard_unit']) assert.match(c[key], /^[a-z][a-z0-9-]{0,63}\.service$/);
  assert.equal(new Set([c.engine_unit,c.network_unit,c.guard_unit]).size, 3);
  assert.match(c.guard_script, /^\/(?:usr\/local\/bin|opt\/clean-vpn-native\/[a-z0-9-]+)\/[a-zA-Z0-9_.-]+$/);
  return c;
}

export function validateNativeIncoming(c){
  assert.deepEqual(Object.keys(c).sort(),['port','source_ipv4']);
  assert.equal(c.source_ipv4,'10.99.0.1');
  assert.ok(Number.isInteger(c.port)&&c.port>=1024&&c.port<=65535);
  assert.notEqual(c.port,1053,'native_incoming_dns_port_conflict');
  return c;
}

export function nativeHostNatPlan(id, peerAddress = '10.99.0.2', incoming) {
  validateTunnelDnsAddress(peerAddress);
  assert.match(id, /^[a-f0-9]{24}$/);
  const tag = ['-m','comment','--comment','cvpn-native-host-'+id];
  if(incoming)validateNativeIncoming(incoming);
  return [
    ...[['-i','usb0','-o','tun0','-s','192.168.7.0/24'], ['-i','tun0','-o','usb0','-d','192.168.7.0/24']].map(spec => ({
      table:'mangle',chain:'FORWARD',spec:[...spec,'-p','tcp','-m','tcp','--tcp-flags','SYN,RST','SYN',...tag,'-j','TCPMSS','--set-mss','1360']})),
    {table:'nat',chain:'POSTROUTING',spec:['-s','192.168.7.0/24','-o','tun0',...tag,'-j','SNAT','--to-source',peerAddress]},
    // Inserted at position one in this order: closed first, then exact ingress
    // and established replies. No wildcard listener or LAN forwarding grant.
    ...(incoming?[
      ['-i','tun0',...tag,'-j','DROP'],
      ['-d',peerAddress+'/32','-p','tcp','-m','tcp','--dport',String(incoming.port),...tag,'-j','DROP'],
      ['-i','tun0','-s',incoming.source_ipv4+'/32','-d',peerAddress+'/32','-p','tcp','-m','tcp','--dport',String(incoming.port),...tag,'-j','ACCEPT'],
      ['-i','tun0','-m','conntrack','--ctstate','ESTABLISHED,RELATED',...tag,'-j','ACCEPT'],
    ].map(spec=>({table:'filter',chain:'INPUT',spec})):[]),
  ];
}

export function nativeHostNetwork(c, io) {
  validateNativeHostConfig(c);
  const peerAddress = c.peer_ipv4 ?? '10.99.0.2';
  const planFor=id=>nativeHostNatPlan(id,peerAddress,c.incoming_tcp);
  const {run, host, dns, redirect, store, scope, createTun, randomId} = io;
  const cmd = (f,a) => run(f,a).trim();
  const ip = (...a) => JSON.parse(cmd('ip',a));
  const prop = (u,k) => cmd('systemctl',['show',u,'-p',k,'--value']);
  const tun = () => ip('-j','-d','link','show').find(l=>l.ifname==='tun0');
  const ident = l => ({ifindex:l.ifindex,alias:l.ifalias,kind:l.linkinfo?.info_kind});
  const guard = () => {
    assert.equal(prop(c.guard_unit,'ActiveState'),'active','native_guard_inactive');
    const status=cmd(c.guard_script,['status']);
    for(const family of [4,6]) assert.ok(status.includes(`IPv${family}: cvks4:both:block:tun0:${c.exit_ip}:22`),'native_guard_profile_mismatch');
  };
  const inactive = () => {
    assert.equal(prop(c.engine_unit,'MainPID'),'0','native_engine_still_running');
    assert.ok(['inactive','failed'].includes(prop(c.engine_unit,'ActiveState')),'native_engine_not_quiesced');
  };
  const ownedTun = s => {
    const l=tun();
    if(l) {
      assert.equal(l.linkinfo?.info_kind,'tun','native_tun_type_changed');
      assert.equal(l.ifalias,'cvpn-native-host-'+s.id,'native_tun_owner_changed');
      if(s.tun) assert.deepEqual(ident(l),s.tun,'native_tun_replaced');
    }
    return l;
  };
  const validate = s => {
    assert.deepEqual(Object.keys(s).sort(),['schema','scope','config','id','tun','count','stage'].sort());
    assert.equal(s.schema,1); assert.deepEqual(s.scope,scope());validateNativeHostConfig(s.config);
    // A completed release can be followed by a fresh named installation in
    // this namespace. An unfinished owner's journal can never be adopted.
    if(s.stage!=='released')assert.deepEqual(s.config,c,'native_config_owner_mismatch');
    assert.match(s.id,/^[a-f0-9]{24}$/);
    assert.ok(['prepared','active','restoring','released'].includes(s.stage));
    const count=planFor(s.id).length;
    assert.ok(Number.isInteger(s.count)&&s.count>=0&&s.count<=count);
    if(s.tun) {assert.deepEqual(Object.keys(s.tun).sort(),['alias','ifindex','kind']);assert.ok(Number.isSafeInteger(s.tun.ifindex)&&s.tun.ifindex>0);assert.equal(s.tun.kind,'tun');assert.equal(s.tun.alias,'cvpn-native-host-'+s.id);}
    if(s.stage==='active') assert.ok(s.tun&&s.count===count);
    if(s.stage==='released') assert.equal(s.count,0);
  };
  const persist = s => {validate(s);store.write(s);};
  const natLines = table => cmd('iptables',['-w','5','-t',table,'-S']).split('\n').filter(l=>l.includes('cvpn-native-host-'));
  const canonical = s => s.replaceAll('"','').replace(/ -m tcp(?= |$)/g,'')
    .replace(/--ctstate ([A-Z,]+)/g,(_,v)=>'--ctstate '+v.split(',').sort().join(','))
    .replace(/--tcp-flags ([A-Z,]+) ([A-Z,]+)/g,(_,a,b)=>`--tcp-flags ${a.split(',').sort().join(',')} ${b.split(',').sort().join(',')}`)
    .split(/\s+/).reduce((a,v,i,all)=>i%2?a:[...a,all.slice(i,i+2).join(' ')],[]).sort().join(' ');
  const expected = o => canonical(['-A',o.chain,...o.spec].join(' '));
  const natAudit = (s, requireAll=false) => {
    const plan=planFor(s.id).slice(0,s.count);
    for(const table of ['nat','mangle','filter']) {
      const lines=natLines(table).map(canonical), allowed=plan.filter(o=>o.table===table).map(expected);
      assert.equal(new Set(lines).size,lines.length,'native_duplicate_nat');
      assert.ok(lines.every(l=>allowed.includes(l)),'native_foreign_nat');
      if(requireAll) assert.deepEqual([...lines].sort(),[...allowed].sort(),'native_missing_nat');
    }
    if(requireAll&&c.incoming_tcp){
      const wanted=plan.filter(o=>o.table==='filter').reverse().map(expected);
      const actual=cmd('iptables',['-w','5','-S','INPUT']).split('\n').filter(l=>l.startsWith('-A INPUT ')).slice(0,wanted.length).map(canonical);
      assert.deepEqual(actual,wanted,'native_incoming_rule_order');
    }
  };
  const present = o => natLines(o.table).some(l=>canonical(l)===expected(o));
  const journalScope = s => {
    if(redirect?.state&&redirect.state.stage!=='released'){
      assert.ok(c.combo_redirect,'native_unconfigured_redirect');assert.deepEqual(redirect.state.scope,s.scope);assert.deepEqual(redirect.state.config,c.combo_redirect);redirect.audit();
    }
    for(const j of [host.state,dns.state]) if(j&&j.stage!=='released') {
      assert.ok(s.tun,'native_unowned_child_journal');
      assert.equal(j.links?.tun0?.ifindex,s.tun.ifindex,'native_child_tun_mismatch');
      assert.deepEqual(j.scope,s.scope,'native_child_scope_mismatch');
    }
  };
  const preflight = () => {
    if(peerAddress!=='10.99.0.2')assert.equal(JSON.parse(cmd(c.guard_script,['capabilities'])).native_peer_dns,true,'native_guard_peer_support_required');
    guard();inactive();
    assert.ok(!tun(),'native_existing_tun_refused');
    assert.equal(cmd('sysctl',['-n','net.ipv4.ip_forward']),'1','native_configured_gateway_required');
    const usb=ip('-j','address','show','dev','usb0')[0];
    assert.ok(usb?.flags.includes('UP')&&usb.addr_info.some(a=>a.local==='192.168.7.1'&&a.prefixlen===24),'native_usb_profile_required');
    assert.ok(ip('-j','-4','address','show','dev','wlan0')[0]?.flags.includes('UP'),'native_uplink_required');
    assert.deepEqual(ip('-N','-j','-4','rule','show'),[{priority:0,src:'all',table:'255'},{priority:32766,src:'all',table:'254'},{priority:32767,src:'all',table:'253'}],'native_foreign_policy');
    const binds=prop(c.engine_unit,'BindsTo').split(/\s+/);
    assert.ok(binds.includes(c.network_unit)&&binds.includes(c.guard_unit),'native_engine_dependencies');
    redirect?.assertAvailable();
    host.assertAvailable(); assert.ok(!dns.state||dns.state.stage==='released','native_dns_recovery_required');
    for(const table of ['nat','mangle','filter']) {
      assert.equal(natLines(table).length,0,'native_unowned_nat');
      assert.ok(!cmd('iptables',['-w','5','-t',table,'-S']).includes('clean-vpn-usb-'),'native_old_snat_owner_active');
    }
  };
  const uplink = () => {
    const rows=ip('-j','-4','route','show','default');
    assert.equal(rows.length,1,'native_single_default_required');
    assert.equal(rows[0].dev,'wlan0');assert.ok(isIPv4(rows[0].gateway));
    assert.ok(!rows[0].nexthops);return rows[0].gateway;
  };
  return {
    preflight,
    recover() {
      const s=store.read(); if(!s)return;
      validate(s); if(s.stage==='released')return;
      guard();inactive();ownedTun(s);journalScope(s);natAudit(s);
      if(host.state&&host.state.stage!=='released')host.audit();
      if(dns.state&&dns.state.stage!=='released')dns.restore({apply:false});
      s.stage='restoring';persist(s);
      if(redirect?.state&&redirect.state.stage!=='released')redirect.restore();
      // Remove forwarding translation first; guard remains throughout cleanup.
      const plan=planFor(s.id);
      while(s.count){const o=plan[s.count-1];if(present(o))cmd('iptables',['-w','5','-t',o.table,'-D',o.chain,...o.spec]);assert.ok(!present(o));s.count--;persist(s);}
      if(dns.state&&dns.state.stage!=='released')dns.restore();
      if(host.state&&host.state.stage!=='released')host.restore();
      if(ownedTun(s))cmd('ip',['tuntap','del','dev','tun0','mode','tun']);
      assert.ok(!tun());guard();s.stage='released';persist(s);
    },
    prepare() {
      const old=store.read();if(old){validate(old);assert.equal(old.stage,'released','native_recovery_required');}
      preflight();const gateway=uplink();
      const s={schema:1,scope:scope(),config:structuredClone(c),id:randomId(),tun:null,count:0,stage:'prepared'};
      persist(s);createTun('tun0','cvpn-native-host-'+s.id,peerAddress);
      s.tun=ident(ownedTun(s));persist(s);
      host.begin('tun0');host.relaxRpFilter();
      host.add(c.exit_ip+'/32','wlan0',gateway);
      for(const d of ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'])host.add(d,'wlan0',gateway);
      for(const d of ['0.0.0.0/1','128.0.0.0/1'])host.add(d,'tun0');
      dns.begin({tun:'tun0',listenerAddress:peerAddress,nativeMark:true,lanSubnet:'192.168.7.0/24',lanInterface:'usb0'});
      for(const stage of ['guard','route','activate'])dns.applyStage(stage);
      dns.activate();
      if(c.combo_redirect){assert.ok(redirect);redirect.install(c.combo_redirect);}
      // Incoming endpoint guards must remain ahead of the relay's INPUT hooks.
      // Both overlays are complete before the native engine may start.
      for(const o of planFor(s.id)){s.count++;persist(s);cmd('iptables',['-w','5','-t',o.table,'-I',o.chain,'1',...o.spec]);assert.ok(present(o));}
      guard();natAudit(s,true);host.audit();s.stage='active';persist(s);
      return {state:'network-ready',readinessProbed:false};
    },
    tick() {
      const s=store.read();validate(s);assert.equal(s.stage,'active');
      if(c.combo_redirect)assert.equal(redirect.audit().stage,'active','native_redirect_inactive');
      guard();assert.ok(ownedTun(s),'native_tun_missing');journalScope(s);natAudit(s,true);
      const link=ip('-j','link','show').find(l=>l.ifname==='wlan0');
      const defaults=ip('-j','-4','route','show','default');
      // An ordinary Wi-Fi outage is not a failed installation. Retain the
      // guard/DNS/TUN and let the native engine's reconnect remain bounded.
      if(!link?.flags.includes('UP')||!link.flags.includes('LOWER_UP')||defaults.length===0)
        return {state:'waiting-uplink'};
      // Repair only the same interface/gateway. A changed lease triggers a
      // stopped-engine recovery/restart instead of mutating a live route set.
      host.repairUplink('wlan0',uplink(),c.exit_ip);host.repairTunRoutes();
      return {state:'network-ready'};
    },
  };
}
