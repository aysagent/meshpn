// Same-boot private ownership journal with a lifetime process lock.
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import path from 'node:path';
export const nativeHostScope=()=>({boot:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim(),net:fs.readlinkSync('/proc/self/ns/net'),user:fs.readlinkSync('/proc/self/ns/user')});
export function readNativePrivate(file,limit=16384){
  assert.equal(fs.realpathSync(file),file,'native_symlink_path');
  for(let parent=path.dirname(file);;parent=path.dirname(parent)){
    const s=fs.lstatSync(parent);assert.ok(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===0&&(!(s.mode&0o022)||(s.mode&0o1000)),'native_untrusted_parent');
    if(parent==='/')break;
  }
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{const s=fs.fstatSync(fd);assert.ok(s.isFile()&&s.uid===0&&s.nlink===1&&(s.mode&0o777)===0o600&&s.size>0&&s.size<=limit,'native_private_file');return JSON.parse(fs.readFileSync(fd,'utf8'));}finally{fs.closeSync(fd);}
}
export function openNativeHostStore({kind='client'}={}){
  assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
  assert.ok(['client','exit'].includes(kind));
  const dir=(kind==='exit'?'/run/clean-vpn-native-exit-host-':'/run/clean-vpn-native-host-')+nativeHostScope().net.match(/\d+/)[0];
  const parent=fs.lstatSync('/run');assert.ok(parent.isDirectory()&&!parent.isSymbolicLink()&&parent.uid===0&&!(parent.mode&0o022));
  try{fs.mkdirSync(dir,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}
  const d=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
  let lock;
  try{
    const s=fs.fstatSync(d);assert.ok(s.uid===0&&(s.mode&0o777)===0o700);
    lock=fs.openSync(dir+'/lock',fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK,0o600);
    const l=fs.fstatSync(lock);assert.ok(l.isFile()&&l.uid===0&&l.nlink===1&&(l.mode&0o777)===0o600);
    execFileSync('flock',['-n','3'],{stdio:['ignore','pipe','pipe',lock],timeout:10000});
  }catch(e){if(lock!==undefined)fs.closeSync(lock);fs.closeSync(d);throw e;}
  return {
    lock,
    read(){try{return readNativePrivate(dir+'/journal.json');}catch(e){if(e.code==='ENOENT')return null;throw e;}},
    write(value){const b=JSON.stringify(value);assert.ok(Buffer.byteLength(b)<=16384);const tmp=dir+'/tmp-'+randomBytes(12).toString('hex');const fd=fs.openSync(tmp,'wx',0o600);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(tmp,dir+'/journal.json');fs.fsyncSync(d);},
    close(){fs.closeSync(lock);fs.closeSync(d);},
  };
}
