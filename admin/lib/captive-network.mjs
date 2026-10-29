import {command} from './command.mjs';
import {need} from './common.mjs';
import {portalAddress as address,portalSubnet as subnet} from './captive.mjs';

// Fixed scope; neither interface nor rule arguments come from HTTP input.
const tag='meshpn-usb-captive-v1';
const flows=[['udp','53','1054'],['tcp','53','1054'],['tcp','80','18080']];
const comment=['-m','comment','--comment',tag];
export const captiveRules={
 guards:flows.map(([proto,,port])=>['filter','INPUT','-p',proto,'--dport',port,...comment,'-j','DROP']),
 allows:flows.map(([proto,original,port])=>['filter','INPUT','-i','usb0','-s',subnet,'-d',address+'/32','-p',proto,'--dport',port,'-m','conntrack','--ctstate','DNAT','--ctorigdstport',original,...comment,'-j','ACCEPT']),
 nat:flows.map(([proto,port,to])=>['nat','PREROUTING','-i','usb0','-s',subnet,...(port==='80'?['!','-d',address+'/32']:[]),'-p',proto,'--dport',port,...comment,'-j','DNAT','--to-destination',address+':'+to]),
};
export class CaptiveNetwork {
 constructor(run=command){this.run=run;}
 async ipt(args,allowFailure=false){return this.run('/usr/sbin/iptables',['-w','2',...args],{timeout:4000,allowFailure});}
 async exists([table,chain,...rule]){const r=await this.ipt(['-t',table,'-C',chain,...rule],true);need([0,1].includes(r.code),'portal_rule_check');return r.code===0;}
 async remove(r){let n=0;while(await this.exists(r)){need(++n<=8,'portal_duplicate_rules');await this.ipt(['-t',r[0],'-D',r[1],...r.slice(2)]);}}
 async add(r){if(!await this.exists(r))await this.ipt(['-t',r[0],'-I',r[1],'1',...r.slice(2)]);}
 async deleteFlows(args){const r=await this.run('/usr/sbin/conntrack',['-D','-f','ipv4',...args],{timeout:4000,allowFailure:true,captureError:true});need(r.code===0||(r.code===1&&/0 flow entries have been deleted/.test(r.err??'')),'portal_conntrack_cleanup');}
 async resetUsbDns(){
  // Otherwise a UDP tuple already translated to native DNS never encounters
  // the new offline rule. Only the selected USB subnet's port-53 DNS is reset.
  for(const proto of['udp','tcp'])await this.deleteFlows(['-p',proto,'--orig-src',subnet,'--orig-port-dst','53']);
 }
 async purge(){
  // Delete only translations into this service, never all USB or VPN flows.
  for(const[proto,original,to]of flows)await this.deleteFlows(['-p',proto,'--orig-src',subnet,'--orig-port-dst',original,'--reply-src',address,'--reply-port-src',to]);
 }
 async active(){for(const r of captiveRules.allows)await this.add(r);for(const r of captiveRules.nat)await this.add(r);}
 async inactive(){for(const r of captiveRules.nat)await this.remove(r);await this.purge();for(const r of captiveRules.allows)await this.remove(r);}
 async prepare(){await this.inactive();for(const r of captiveRules.guards)await this.add(r);}
 async down(){await this.inactive();for(const r of captiveRules.guards)await this.remove(r);}
 async reconcile(){
  // Native DNS can reinsert its PREROUTING rule during recovery. Keep the
  // offline USB exception before it, without rewriting any foreign rule.
  const {out}=await this.ipt(['-t','nat','-S','PREROUTING']);
  const rules=out.split('\n').filter(s=>s.startsWith('-A '));
  if(!rules.slice(0,3).every(s=>s.includes(tag))||rules.length<3){for(const r of captiveRules.nat)await this.remove(r);await this.active();await this.resetUsbDns();}
 }
}
