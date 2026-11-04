#!/usr/bin/env node
// Root controller owns only exact, interface/address-scoped mDNS OUTPUT rules.
import {execFileSync,spawn} from 'node:child_process';
import {managementAccess,managementAddresses} from './lib/management-access.mjs';
import {managementMdnsTag,managementMdnsRule,parseManagementMdnsRule} from './lib/management-mdns.mjs';
import {readJson,need,hostname} from './lib/common.mjs';
need(process.platform==='linux'&&process.getuid()===0&&['up','down'].includes(process.argv[2]),'linux_root_action');
const iptables=args=>execFileSync('/usr/sbin/iptables',['-w','5',...args],{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']});
function clean(){for(const line of iptables(['-S','OUTPUT']).trim().split('\n'))if(line.includes(managementMdnsTag)){const rule=parseManagementMdnsRule(line);need(rule,'management_mdns_rule_changed');iptables(['-D','OUTPUT',...rule]);}}
clean();
if(process.argv[2]==='up'){
 const config=managementAccess(readJson('/etc/meshpn-admin/web.json').managementAccess);need(config?.mdns===true,'management_mdns_disabled');
 let child=null,current=null,timer,closing=false;
 function stop(){if(child){child.kill('SIGTERM');child=null;}current=null;clean();}
 function reconcile(){
  if(closing)return;
  const address=managementAddresses(config)[0],name=hostname(readJson('/var/lib/meshpn-admin-broker/settings.json').hostname);
  const desired=address?name+'@'+address:null;
  if(desired===current)return;
  stop();if(!address)return;
  iptables(['-I','OUTPUT','1',...managementMdnsRule(config.interface,address)]);
  current=desired;
  const launched=spawn('/opt/meshpn-admin/admin/mdns-helper',[config.interface,name,address],{stdio:['ignore','pipe','ignore']});child=launched;
  launched.stdout.on('data',data=>process.stdout.write(data));
  const failed=()=>{if(child===launched){child=null;current=null;}};
  launched.on('error',failed);launched.on('close',failed);
 }
 function tick(){try{reconcile();}catch{console.error('management_mdns_reconcile_failed');closing=true;clearInterval(timer);try{stop();}finally{process.exitCode=1;}}}
 timer=setInterval(tick,3000);tick();
 for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{closing=true;clearInterval(timer);try{stop();}catch{console.error('management_mdns_cleanup_failed');process.exitCode=1;}});
}
