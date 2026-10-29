// Linux integration: process signals can execute in a worker, not only main.
// Run under TSan with halt_on_error=1 and inspect its log_path as well.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
test('native worker-directed SIGHUP and SIGTERM synchronize with main reactor',{timeout:30000},async t=>{
 assert.equal(process.platform,'linux','Linux tgkill integration requires isolated Linux runner');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-signal-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.mkdirSync(dir+'/replay',{mode:0o700});fs.writeFileSync(dir+'/psk',randomBytes(32),{mode:0o600});
 const reserve=net.createServer();reserve.listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
 const config={version:1,transport:'transparent-tls',role:'exit',listen:{ipv4:'127.0.0.1',port},public_name:'relay.example',destinations:[{ipv4:'127.0.0.1',port:1}],replay_directory:dir+'/replay',peers:[{id:'signal-test',secret_path:dir+'/psk'}]};
 fs.writeFileSync(dir+'/exit.json',JSON.stringify(config),{mode:0o600});
 execFileSync(build+'/clean-vpn-engine',['--init-transparent-replay',dir+'/exit.json'],{stdio:'pipe'});
 const child=spawn(build+'/clean-vpn-engine',['--config',dir+'/exit.json','--service']);const done=once(child,'close');let stdout='',stderr='';
 child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);t.after(()=>child.kill('SIGKILL'));
 const events=()=>stdout.split('\n').filter(Boolean).flatMap(l=>{try{return[JSON.parse(l)];}catch{return[];}});
 const wait=async predicate=>{for(let n=0;n<500;n++){if(predicate())return;assert.equal(child.exitCode,null,stderr);await new Promise(r=>setTimeout(r,10));}assert.fail('native signal event deadline: '+stderr);};
 await wait(()=>events().some(e=>e.state==='listening'));
 const threads=fs.readdirSync(`/proc/${child.pid}/task`).map(Number).filter(id=>id!==child.pid).filter(id=>{const status=fs.readFileSync(`/proc/${child.pid}/task/${id}/status`,'utf8'),mask=status.match(/^SigBlk:\s*([0-9a-f]+)$/mi);return mask&&(BigInt('0x'+mask[1])&0x4001n)===0n;});assert.ok(threads.length,'real relay worker required');
 const worker=threads[0];
 const helper=dir+'/tgkill';
 fs.writeFileSync(helper+'.c','#define _GNU_SOURCE\n#include <sys/syscall.h>\n#include <unistd.h>\n#include <stdlib.h>\nint main(int argc,char**argv){if(argc!=4)return 2;return syscall(SYS_tgkill,atoi(argv[1]),atoi(argv[2]),atoi(argv[3]))==0?0:1;}\n');
 execFileSync(process.env.CC??'cc',[helper+'.c','-o',helper],{stdio:'pipe'});
 const signal=number=>execFileSync(helper,[String(child.pid),String(worker),String(number)],{stdio:'pipe'});
 for(let revision=1;revision<=8;revision++){signal(1);await wait(()=>events().some(e=>e.event==='peer_reload'&&e.revision===revision&&e.status==='applied'));}
 signal(15);const [code]=await done;assert.equal(code,0,stderr);assert.doesNotMatch(stderr,/ThreadSanitizer|runtime error:/);
});
