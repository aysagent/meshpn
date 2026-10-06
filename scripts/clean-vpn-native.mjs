#!/usr/bin/env node
// Experimental explicit launcher. --usb-profile opts into owned routes/DNS.
// Never installs/releases the independent guard, USB interface or SNAT service.
// Stdio is control/status ONLY. Native child opens the pre-provisioned TUN.
import { NativeEngineController } from './lib/native-engine-controller.mjs';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { prepareNativeUsb } from './lib/native-usb-control.mjs';
const args=process.argv.slice(2);
const usbProfile=args.at(-1)==='--usb-profile';if(usbProfile)args.pop();
if(args.length!==2||args[0]!=='--config'||!path.isAbsolute(args[1])){
  console.error('usage: clean-vpn-native.mjs --config /absolute/config.json (experimental; provision TUN/guard first)');
  process.exit(2);
}
const binary=fileURLToPath(new URL('../native/clean_vpn/build/clean-vpn-engine',import.meta.url));
let network;
if(usbProfile){
  console.error('native-control: preparing protected USB profile');
  const bytes=fs.readFileSync(args[1]);if(bytes.length>16384)throw Error('configuration too large');
  network=prepareNativeUsb(JSON.parse(bytes));
  console.error('native-control: profile preflight complete');
}
const engine=new NativeEngineController({binary,config:args[1]});
console.error('native-control: engine spawned');
network?.attach(engine);
let pending='',failed=false,stopping=false;
const abort=()=>{failed=true;engine.stop();};
const stop=()=>{
  if(stopping)return;stopping=true;
  // Restore while native still holds TUN: ownership audits reject linkdown
  // routes. The independent guard continues blocking direct USB egress.
  try{network?.close({restore:!failed});}catch{failed=true;}
  engine.stop();
};
engine.on('status',event=>{if(!process.stdout.write(JSON.stringify(event)+'\n'))abort();});
engine.on('diagnostic',event=>{if(!process.stdout.write(JSON.stringify(event)+'\n'))abort();});
engine.on('fault',abort);
engine.on('exit',({code,signal,incompleteStatus})=>{
  console.error(`native-control: engine exited code=${code} signal=${signal}`);
  try{network?.close({restore:!failed&&!signal&&code===0&&!incompleteStatus});}catch{failed=true;}
  process.exitCode=failed||signal||code!==0||incompleteStatus?1:0;
  process.stdin.pause();process.stdin.unref?.();
});
process.stdout.on('error',abort);
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{
  pending+=chunk;if(pending.length>4096)return abort();
  for(;;){
    const end=pending.indexOf('\n');if(end<0)break;
    const line=pending.slice(0,end);pending=pending.slice(end+1);
    try{
      const c=JSON.parse(line);
      if(c?.op==='status'&&Object.keys(c).length===1)engine.status();
      else if(c?.op==='stop'&&Object.keys(c).length===1)stop();
      else if(c?.op==='uplink'&&Object.keys(c).length===2&&typeof c.ready==='boolean')engine.uplink(c.ready);
      else abort();
    }catch{abort();}
  }
});
process.stdin.on('end',()=>{if(pending)failed=true;stop();});
process.stdin.on('error',abort);
process.on('SIGINT',stop);process.on('SIGTERM',stop);
