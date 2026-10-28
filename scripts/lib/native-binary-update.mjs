// Binary-only transactions. Callers serialize operations and supply the service
// adapter. Config, keys, replay and network policy are never rewritten here.
import fs from 'node:fs';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
const need = (v, code) => {if (!v) throw Error(code);};
export const binaryDigest = b => createHash('sha256').update(b).digest('hex');
const digest = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
export function syncDir(dir) {const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function ownedDirectory(dir) {
  need(path.isAbsolute(dir) && fs.realpathSync(dir) === dir, 'release_directory_path');
  for(let p=dir;;p=path.dirname(p)) {
    const s=fs.lstatSync(p);
    need(s.isDirectory() && !s.isSymbolicLink() && [process.getuid(),fs.statSync('/').uid].includes(s.uid) &&
      (!(s.mode&0o022)||(p!==dir&&(s.mode&0o1000))), 'release_directory_permissions');
    if(p==='/')break;
  }
}
export function readOwned(file, limit=65536, optional=false) {
  ownedDirectory(path.dirname(file));
  let fd;
  try {fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);}
  catch(e){if(optional&&e.code==='ENOENT')return null;throw e;}
  try {const s=fs.fstatSync(fd);need(s.isFile()&&s.uid===process.getuid()&&!(s.mode&0o022)&&s.size<=limit,'release_file_permissions');return fs.readFileSync(fd);}
  finally{fs.closeSync(fd);}
}
export function writeDurable(file, value, mode=0o600) {
  ownedDirectory(path.dirname(file));
  const temp=file+'.'+randomUUID()+'.new', fd=fs.openSync(temp,'wx',mode);
  try {
    try{fs.fchmodSync(fd,mode);fs.writeFileSync(fd,value);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
    fs.renameSync(temp,file);syncDir(path.dirname(file));
  } finally {if(fs.existsSync(temp)){fs.unlinkSync(temp);syncDir(path.dirname(file));}}
}
function remove(file){fs.unlinkSync(file);syncDir(path.dirname(file));}
const json=value=>JSON.stringify(value,null,2)+'\n';
const parse=file=>JSON.parse(readOwned(file));
export class NativeBinaryUpdate {
  constructor(bundle, service, {fault=()=>{}}={}) {
    ownedDirectory(bundle);this.bundle=bundle;this.service=service;this.fault=fault;
    this.dir=bundle+'/binary-updates';ownedDirectory(this.dir);
    this.binding=parse(this.dir+'/binding.json');
    need(this.binding.schema===1&&this.binding.bundle===bundle&&Array.isArray(this.binding.protectedFiles)&&
      this.binding.protectedFiles.every(p=>typeof p==='string'&&path.isAbsolute(p)), 'release_binding');
    this.journal=this.dir+'/transaction.json';this.receipt=this.dir+'/active.json';
  }
  static initialize(bundle, protectedFiles) {
    ownedDirectory(bundle);
    const engine=readOwned(bundle+'/engine',64*1024*1024), sha=binaryDigest(engine);
    const dir=bundle+'/binary-updates';fs.mkdirSync(dir,{mode:0o700});syncDir(bundle);
    fs.mkdirSync(dir+'/releases',{mode:0o700});syncDir(dir);
    writeDurable(dir+'/binding.json',json({schema:1,bundle,protectedFiles}));
    writeDurable(dir+'/releases/'+sha,engine,0o555);
    writeDurable(dir+'/active.json',json({schema:1,sha256:sha}));
    return sha;
  }
  inventory(){return this.binding.protectedFiles.map(file=>({file,sha256:binaryDigest(readOwned(file,1024*1024)),mode:fs.lstatSync(file).mode&0o777}));}
  artifact(sha){need(digest(sha),'release_digest');const b=readOwned(this.dir+'/releases/'+sha,64*1024*1024);need(binaryDigest(b)===sha,'release_artifact_changed');return b;}
  current(){const r=parse(this.receipt);need(r.schema===1&&digest(r.sha256),'release_receipt');return r.sha256;}
  pending(){const b=readOwned(this.journal,65536,true);if(b===null)return null;const j=JSON.parse(b);
    need(j.schema===1&&['prepared','rollback','committed'].includes(j.phase)&&digest(j.before)&&digest(j.after)&&
      typeof j.running==='boolean'&&Array.isArray(j.inventory),'release_journal');return j;}
  verify(j, committed=false) {
    need(JSON.stringify(this.inventory())===JSON.stringify(j.inventory),'release_config_or_unit_changed');
    const active=this.current(), engine=binaryDigest(readOwned(this.bundle+'/engine',64*1024*1024));
    const allowed=committed?[j.after]:[j.before,j.after];
    need(allowed.includes(active)&&allowed.includes(engine),'release_external_binary_change');
    this.artifact(j.before);this.artifact(j.after);
  }
  select(sha){writeDurable(this.bundle+'/engine',this.artifact(sha),0o755);this.fault('binary-written');
    writeDurable(this.receipt,json({schema:1,sha256:sha}));this.fault('receipt-written');}
  async recover({boot=false}={}) {
    const j=this.pending();if(!j)return{status:'none'};
    this.verify(j,j.phase==='committed');
    if(j.phase==='committed'){remove(this.journal);return{status:'committed',sha256:j.after};}
    if(boot)need(!await this.service.running(),'release_boot_engine_running');
    j.phase='rollback';writeDurable(this.journal,json(j));
    if(!boot)await this.service.stop();
    this.verify(j);this.select(j.before);
    if(j.running&&!boot){await this.service.guard();await this.service.start();await this.service.ready();}
    remove(this.journal);return{status:'rolled-back',sha256:j.before,restarted:j.running&&!boot};
  }
  async apply(binary, expected) {
    need(!this.pending(),'release_recovery_required');need(digest(expected),'release_expected_digest');
    const bytes=readOwned(binary,64*1024*1024);need(binaryDigest(bytes)===expected,'release_candidate_digest');
    const before=this.current();need(binaryDigest(readOwned(this.bundle+'/engine',64*1024*1024))===before,'release_external_binary_change');
    this.artifact(before);
    if(before!==expected){const disk=fs.statfsSync(this.dir),largest=Math.max(bytes.length,fs.statSync(this.bundle+'/engine').size);
      need(disk.bavail*disk.bsize>=3*largest+1024*1024,'release_insufficient_disk');}
    const dest=this.dir+'/releases/'+expected;
    if(fs.existsSync(dest))this.artifact(expected);else writeDurable(dest,bytes,0o555);
    // Execute only the exact verified, immutable candidate, not its source path.
    await this.service.validate(dest);
    if(before===expected)return{status:'unchanged',sha256:before};
    const running=await this.service.running();if(running)await this.service.guard();
    const j={schema:1,phase:'prepared',before,after:expected,running,inventory:this.inventory()};
    writeDurable(this.journal,json(j));
    try {
      this.fault('prepared');
      if(running)await this.service.stop();this.fault('stopped');
      this.verify(j);this.select(expected);
      if(running){await this.service.guard();await this.service.start();await this.service.ready();}
      this.fault('activated');this.verify(j,true);
      j.phase='committed';writeDurable(this.journal,json(j));this.fault('committed');
    } catch(e) {
      const result=await this.recover();if(result.status==='committed')return{status:'updated',sha256:expected,restarted:running};
      throw Object.assign(Error('release_failed_rolled_back'),{cause:e});
    }
    remove(this.journal);return{status:'updated',sha256:expected,restarted:running,requiresStart:!running};
  }
}
