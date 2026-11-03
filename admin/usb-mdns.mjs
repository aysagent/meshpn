#!/usr/bin/env node
// A single owned OUTPUT exception. Never changes INPUT/FORWARD/default policy.
import {execFileSync} from 'node:child_process';
import {need,readJson} from './lib/common.mjs';
const address=readJson('/etc/meshpn-admin/broker.json',{usbAddress:'192.168.7.1'}).usbAddress;
need(['192.168.7.1','192.168.8.1'].includes(address),'usb_address');
need(process.platform==='linux'&&process.getuid()===0&&['up','down'].includes(process.argv[2]),'linux_root_action');
const rule=['-o','usb0','-s',address+'/32','-d','224.0.0.251/32','-p','udp','--sport','5353','--dport','5353','-m','comment','--comment','meshpn-admin-usb-mdns-v1','-j','ACCEPT'];
const run=a=>execFileSync('/usr/sbin/iptables',['-w','5',...a],{stdio:['ignore','pipe','pipe'],timeout:10000});
let exists;try{run(['-C','OUTPUT',...rule]);exists=true;}catch(e){if(e.status!==1)throw e;exists=false;}
if(process.argv[2]==='up'&&!exists)run(['-I','OUTPUT','1',...rule]);
if(process.argv[2]==='down'&&exists)run(['-D','OUTPUT',...rule]);
