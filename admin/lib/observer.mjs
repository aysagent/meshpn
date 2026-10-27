import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {inspectPcap} from '../../scripts/clean-vpn-pcap-fingerprints.mjs';
import {need} from './common.mjs';
import {command} from './command.mjs';
// Independent tcpdump, running as the unprivileged admin account. Its own
// systemd unit enforces the deadline even if the broker/browser disappears.
export class Observer{
 constructor({interface:iface,directory,spawnChild=spawn,run=command}){this.iface=iface;this.directory=directory;this.spawnChild=spawnChild;this.run=run;this.child=null;this.result=null;}
 start({destination,port,profile,seconds=20}){
  need(!this.child,'observer_busy',409);need(Number.isInteger(seconds)&&seconds>=5&&seconds<=60,'observer_duration');
  const file=this.directory+'/observer.pcap',fd=fs.openSync(file,'w',0o600),unit='meshpn-admin-observe-'+randomBytes(12).toString('hex')+'.service';
  this.unit=unit;this.stopping=false;
  const properties=['User=meshpn-admin','Group=meshpn-admin','Type=exec','NoNewPrivileges=yes','CapabilityBoundingSet=CAP_NET_RAW','AmbientCapabilities=CAP_NET_RAW','ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectControlGroups=yes','RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET','KillSignal=SIGINT','TimeoutStopSec=3','RuntimeMaxSec='+seconds,'TasksMax=4','MemoryMax=48M'];
  const child=this.spawnChild('/usr/bin/systemd-run',['--quiet','--pipe','--wait','--collect','--unit='+unit,...properties.flatMap(p=>['--property',p]),'/usr/bin/tcpdump','-p','-Z','meshpn-admin','-i',this.iface,'-nn','-U','-s','0','-c','5000','-w','-','host',destination,'and','tcp','port',String(port)],{stdio:['ignore','pipe','pipe']});
  let bytes=0,stderr='',failure=null;this.child=child;this.result={status:'running',seconds,endpoint:destination+':'+port};
  child.stdout.on('data',b=>{bytes+=b.length;try{if(bytes<=16*1024*1024)fs.writeSync(fd,b);else{failure='capture_limit';this.stop();}}catch{failure='capture_write_failed';this.stop();}});
  child.stderr.on('data',b=>{if(stderr.length<8192)stderr+=b.toString();});
  child.on('error',()=>{failure='capture_service_unavailable';});
  child.once('close',code=>{fs.closeSync(fd);this.child=null;this.unit=null;
   try{need(!failure,failure);need(code===0||/\d+ packets captured/.test(stderr),'capture_service_failed');const report=inspectPcap(fs.readFileSync(file),{destination,port,profile});this.result={status:'complete',serviceExit:code,bytes,report,kernelDrops:Number(/(\d+) packets dropped by kernel/.exec(stderr)?.[1]??-1),scope:'ClientHello fields from independent pcap; not browser indistinguishability',pcapAvailable:true};}
   catch(e){this.result={status:'failed',error:/^[a-z_]+$/.test(e.message)?e.message:'capture_incomplete',bytes};}
  });return this.result;
 }
 stop(){if(this.unit&&!this.stopping){this.stopping=true;void this.run('/usr/bin/systemctl',['stop',this.unit],{timeout:10000}).catch(()=>{});}return{status:this.child?'stopping':'idle'};}
}
