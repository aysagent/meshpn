import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {inspectPcap} from '../../scripts/clean-vpn-pcap-fingerprints.mjs';
import {need} from './common.mjs';
// Capture is a separate tcpdump process. Decoder consumes packet bytes, never
// native logs/effective profiles. Only the comparison target is a saved profile.
export class Observer{
 constructor({interface:iface,directory}){this.iface=iface;this.directory=directory;this.child=null;this.result=null;}
 start({destination,port,profile,seconds=20}){need(!this.child,'observer_busy',409);need(Number.isInteger(seconds)&&seconds>=5&&seconds<=60,'observer_duration');const file=this.directory+'/observer.pcap';const fd=fs.openSync(file,'w',0o600);const child=spawn('/usr/bin/tcpdump',['-i',this.iface,'-nn','-U','-s','0','-c','5000','-w','-','host',destination,'and','tcp','port',String(port)],{stdio:['ignore','pipe','pipe']});let bytes=0,stderr='';this.child=child;this.result={status:'running',seconds,endpoint:destination+':'+port};child.stdout.on('data',b=>{bytes+=b.length;if(bytes<=16*1024*1024)fs.writeSync(fd,b);else child.kill('SIGINT');});child.stderr.on('data',b=>{if(stderr.length<8192)stderr+=b.toString();});child.on('error',()=>{this.result={status:'failed',error:'tcpdump_unavailable'};});const timer=setTimeout(()=>child.kill('SIGINT'),seconds*1000);child.once('close',code=>{clearTimeout(timer);fs.closeSync(fd);this.child=null;try{need(bytes<=16*1024*1024,'capture_limit');const report=inspectPcap(fs.readFileSync(file),{destination,port,profile});this.result={status:'complete',tcpdumpExit:code,bytes,report,kernelDrops:Number(/(\d+) packets dropped by kernel/.exec(stderr)?.[1]??-1),scope:'ClientHello fields from independent pcap; not browser indistinguishability',pcapAvailable:true};}catch(e){this.result={status:'failed',error:/^[a-z_]+$/.test(e.message)?e.message:'capture_incomplete',bytes};}});return this.result;}
 stop(){this.child?.kill('SIGINT');return{status:this.child?'stopping':'idle'};}
}
