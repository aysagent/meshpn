#!/usr/bin/env node
// One owned IPv4 INPUT exception. No policy changes or table flush.
import {execFileSync} from 'node:child_process';
import {isIPv4} from 'node:net';
const [action,address,port,name,...rest]=process.argv.slice(2);
try{
 if(process.getuid()!==0||!['up','down'].includes(action)||!isIPv4(address)||!(/^[1-9][0-9]*$/.test(port)&&+port<=65535)||!/^[a-z][a-z0-9-]{0,31}$/.test(name)||rest.length)throw Error('ingress_arguments');
 const tag='clean-vpn-exit-'+name,rule=['-d',address+'/32','-p','tcp','--dport',port,'-m','comment','--comment',tag,'-j','ACCEPT'];
 const run=a=>execFileSync('/usr/sbin/iptables',['-w','5',...a],{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']});
 const owned=run(['-S','INPUT']).split('\n').filter(l=>l.includes('--comment '+tag+' '));
 let present=false;try{run(['-C','INPUT',...rule]);present=true;}catch(e){if(e.status!==1)throw e;}
 if(owned.length!==(present?1:0))throw Error('ingress_rule_changed');
 if(action==='up'&&!present)run(['-I','INPUT','1',...rule]);
 if(action==='down'&&present)run(['-D','INPUT',...rule]);
}catch{console.error('clean-vpn ingress refused; foreign rules unchanged');process.exitCode=1;}
