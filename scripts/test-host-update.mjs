import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { withStoppedHostService } from './lib/host-uninstall.mjs';
import { updateHostService, switchHostWrapper, checkHostUpdateUnits, inspectHostRelease } from './lib/host-update.mjs';

const installer = readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
const guardSource = readFileSync(new URL('./autostart/killswitch.sh', import.meta.url), 'utf8');
const mainPath='/etc/systemd/system/clean-vpn.service', guardPath='/etc/systemd/system/clean-vpn-killswitch.service';
const wrapperPath='/usr/local/bin/clean-vpn-run.sh', scriptPath='/usr/local/bin/clean-vpn-killswitch.sh';
const main = installer.split('cat > "$UNIT_PATH" <<EOF\n')[1].split('\nEOF')[0]
  .replaceAll('$SERVICE_NAME','clean-vpn').replaceAll('$RUN_SH',wrapperPath)
  .replace('${KS_DEPS}', 'Requires=clean-vpn-killswitch.service\nAfter=clean-vpn-killswitch.service');
const guard = installer.split('cat > "$KS_UNIT_PATH" <<EOF\n')[1].split('\nEOF')[0]
  .replace('$KS_GATE_MARKER', '').replace('$KS_STOP', `${scriptPath} down --tun=tun0`)
  .replaceAll('$SERVICE_NAME','clean-vpn').replaceAll('$KS_SH',scriptPath)
  .replace('$KS_UP_ARGS','up --scope=both --ipv6=block --tun=tun0 --ssh-port=22 --server=198.51.100.2');
const wrapper = '#!/usr/bin/env bash\n# generated\nset -euo pipefail\nexport PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin"\ncd "/old"\nexec "/usr/bin/node" "/old/scripts/clean-vpn.js" --role=client --split-default --type=tls --server=198.51.100.2:443 \n';
function fixture({stage='released', lockError=false, stopError=false, stillActive=false, absentGuard=false,
  mutateFiles=false, mutateRelease=false, publishError=false, reload=false, override='', guardActive=true,
  wrapperText=wrapper, mainText=main, guardText=guard, scriptText=guardSource}={}) {
  const files=new Map([[mainPath,mainText],[guardPath,guardText],[wrapperPath,wrapperText],[scriptPath,scriptText]]);
  const calls=[], held=new Set(); let published=0, stopped=false, scans=0;
  const io={ lstatSync:()=>({isFile:()=>true,isSymbolicLink:()=>false}), statSync:()=>({dev:1,ino:1}), readFileSync:p=>files.get(p) };
  const run=(file,args,opts)=>{
    calls.push([file,...args].join(' '));
    if(args.includes('stop')) { if(stopError)throw Error('stop failed'); stopped=true; return ''; }
    if(args.includes('show')) {
      const isGuard=args.includes('clean-vpn-killswitch.service');
      if(args.includes('--value')) {
        if(args.includes('--property=FragmentPath'))return isGuard?guardPath:mainPath;
        if(args.includes('--property=NeedDaemonReload'))return reload?'yes':'no';
        return override;
      }
      return Object.entries({LoadState:'loaded',ActiveState:isGuard?(guardActive?'active':'inactive'):(stopped&&!stillActive?'inactive':'active'),
        PartOf:'',BindsTo:'',NetworkNamespacePath:'',PrivateNetwork:'no',PrivateUsers:'no',RootDirectory:'',RootImage:'',
        BindPaths:'',BindReadOnlyPaths:'',TemporaryFileSystem:'',Requires:'',Requisite:'',Conflicts:'',PropagatesStopTo:'',StopWhenUnneeded:'no'})
        .map(([k,v])=>`${k}=${v}`).join('\n');
    }
    assert.equal(file,scriptPath); assert.deepEqual(args,['status']); assert.equal(held.size,3);
    assert.deepEqual(opts.lockDescriptors,[10,11,12]);
    return [4,6].map(n=>`[clean-vpn-killswitch] IPv${n}: ${absentGuard?'absent':'cvks2:both:block:tun0:198.51.100.2:22'}`).join('\n');
  };
  const options={release:'/new',guardSource, log(){}, read(p){
    if(mutateFiles&&stopped&&p===wrapperPath)return 'changed'; return files.get(p);
  }, inspectRelease(){ return {sha256: mutateRelease&&scans++?'changed':'a'.repeat(64)}; },
  lifecycle(o, action){return withStoppedHostService({...o,io,run,open:[0,1,2].map(n=>()=>{
    if(lockError&&n===1)throw Error('busy'); held.add(n); return {state:{stage},lockDescriptors:[10+n],release(){held.delete(n);}};
  })},action);},
  publish(p,before,after){ assert.equal(held.size,3); assert.equal(stopped,true); if(publishError)throw Error('disk full');
    assert.equal(p,wrapperPath); assert.equal(before,wrapper); files.set(p,after); published++; return {backupDirectory:'/backup'}; }
  };
  return { options, calls, held, files, get published(){return published;} };
}
test('release switch preserves argv/node and changes only cwd/entrypoint',()=>{
  const n=switchHostWrapper(wrapper,'/new'); assert.equal(n.serverIp,'198.51.100.2');
  assert.equal(n.contents,wrapper.replace('cd "/old"','cd "/new"').replace('"/old/scripts/','"/new/scripts/'));
  assert.equal(checkHostUpdateUnits('clean-vpn',main,guard),'cvks2:both:block:tun0:198.51.100.2:22');
  assert.equal(checkHostUpdateUnits('clean-vpn', main, guard.replace('--server=198.51.100.2', '--server=198.51.100.2 --usb-dns=1')),
    'cvks3:both:block:tun0:198.51.100.2:22');
  assert.equal(checkHostUpdateUnits('clean-vpn', main, guard.replace('--server=198.51.100.2', '--server=198.51.100.2 --usb-dns=1 --usb-strict=1')),
    'cvks4:both:block:tun0:198.51.100.2:22');
  assert.throws(() => checkHostUpdateUnits('clean-vpn', main, guard.replace('--server=198.51.100.2', '--server=198.51.100.2 --usb-strict=1')));
  assert.throws(() => checkHostUpdateUnits('clean-vpn', main, guard.replace('--server=198.51.100.2', '--server=198.51.100.2 --usb-dns=0')));
});
test('networkd update template requires retain-rules stop only with explicit marker', () => {
  const gated = '# clean-vpn-networkd-gate-v1\n' + guard.replace(`ExecStop=${scriptPath} down --tun=tun0`, 'ExecStop=/bin/true');
  assert.equal(checkHostUpdateUnits('clean-vpn', main, gated), 'cvks2:both:block:tun0:198.51.100.2:22');
  assert.throws(() => checkHostUpdateUnits('clean-vpn', main, gated.replace('# clean-vpn-networkd-gate-v1\n', '')));
  assert.throws(() => checkHostUpdateUnits('clean-vpn', main, '# clean-vpn-networkd-gate-v1\n' + guard));
});
for(const [name, source, release] of [
  ['same',wrapper,'/old'],['nested',wrapper,'/old/new'],['relative',wrapper,'new'],['parent',wrapper,'/'],
  ['interpreter',wrapper.replace('env bash','python'),'/new'],['shell',wrapper.replace('--type=tls','--type=$(id)'),'/new'],
  ['custom DNS',wrapper.replace('--type=tls','--dns-state-dir=/other'),'/new'],
  ['exit',wrapper.replace('--role=client','--role=exit'),'/new'],['duplicate',wrapper.replace('--type=tls','--type=tls --type=tls'),'/new'],
  ['extra command',wrapper+'id\n','/new']])test(`wrapper rejects ${name}`,()=>assert.throws(()=>switchHostWrapper(source,release)));
test('updater holds released locks through publish; never starts service or removes guard',()=>{
  const f=fixture(), result=updateHostService(f.options);
  assert.equal(result.status,'updated-stopped'); assert.equal(result.startPerformed,false); assert.equal(f.published,1);
  assert.equal(f.held.size,0); assert.deepEqual(f.files.get(mainPath),main); assert.deepEqual(f.files.get(guardPath),guard);
  assert.ok(!f.calls.some(c=>/ down| disable| daemon-reload| restart| start |stop clean-vpn-killswitch/.test(c)));
});
for(const scenario of [{stage:'active'},{stage:'restoring'},{stage:'parked'},{lockError:true},{stopError:true},
  {stillActive:true},{absentGuard:true},{mutateFiles:true},{mutateRelease:true},{publishError:true}])
  test(`updater refusal preserves guard and releases locks ${JSON.stringify(scenario)}`,()=>{
    const f=fixture(scenario); assert.throws(()=>updateHostService(f.options)); assert.equal(f.published,0); assert.equal(f.held.size,0);
    assert.ok(!f.calls.some(c=>/ down| disable| restart|stop clean-vpn-killswitch/.test(c)));
  });
for(const scenario of [{reload:true},{guardActive:false},{scriptText:'other'},{mainText:main+'\nExecStop=bad'},
  {guardText:guard.replace('--scope=both','--scope=fwd')},{wrapperText:wrapper.replace('--server=198.51.100.2','--server=192.0.2.3')}])
  test(`unsupported update refuses before stop ${JSON.stringify(Object.keys(scenario))}`,()=>{
    const f=fixture(scenario); assert.throws(()=>updateHostService(f.options)); assert.equal(f.published,0);
    assert.ok(!f.calls.some(c=>c.includes(' stop ')));
  });
test('release inventory rejects unsafe roots without running code',()=>{
  for(const path of ['/tmp','/','relative','/not/../normalized','/does-not-exist-731']) assert.throws(()=>inspectHostRelease(path));
});
