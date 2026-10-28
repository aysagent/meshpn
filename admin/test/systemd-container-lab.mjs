#!/usr/bin/env node
// Isolated Podman fixture: no published ports, host network, host PID namespace,
// host bus, host /etc, or physical nodes. NET_ADMIN/SYS_ADMIN belong only to the
// disposable systemd fixture; frontend has no capabilities and a read-only root.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {randomBytes, createHash} from 'node:crypto';
const root = fileURLToPath(new URL('../../', import.meta.url));
const connection = 'meshpn-clean-vpn-lab-root';
const id = 'mpn-admin-lab-' + randomBytes(5).toString('hex');
const host = id + '-host', web = id + '-web', shared = id + '-shared', webState = id + '-state';
const context = fs.mkdtempSync(path.join(os.tmpdir(), id + '-'));
const podman = (args, opts = {}) => execFileSync('podman', ['--connection', connection, ...args], {encoding: 'utf8', timeout: 120000, maxBuffer: 4*1024*1024, ...opts});
const delay = ms => new Promise(r => setTimeout(r, ms));
const image = 'localhost/meshpn-admin-systemd-lab:local', frontend = 'localhost/meshpn-admin-lab-web:local';
const created = {host: false, web: false, shared: false, state: false};
try {
  assert.equal(podman(['info','--format={{.Host.OS}}/{{.Host.Arch}}']).trim(), 'linux/arm64');
  // Explicit allowlist: never send .git, certificates, untracked user files or
  // the rest of the repository as a container build context.
  const tracked=execFileSync('git',['ls-files','-z'],{cwd:root,encoding:'utf8'}).split('\0').filter(Boolean);
  for(const file of tracked.filter(f=>f.startsWith('admin/')||f.startsWith('scripts/lib/')||f.startsWith('fixtures/native-tls-profiles/')||f==='scripts/clean-vpn-pcap-fingerprints.mjs')) {
    assert(!fs.lstatSync(path.join(root,file)).isSymbolicLink());
    fs.mkdirSync(path.dirname(path.join(context,file)),{recursive:true});fs.copyFileSync(path.join(root,file),path.join(context,file));
  }
  fs.copyFileSync(path.join(root,'native/clean_vpn/socket_test.cc'), path.join(context,'socket_test.cc'));
  console.log('Building disposable systemd fixture and unprivileged frontend');
  podman(['build','-t',image,'-f',path.join(context,'admin/test/systemd-host.Containerfile'),context], {stdio: 'inherit', timeout: 1200000});
  podman(['build','-t',frontend,'-f',path.join(context,'admin/containers/Containerfile'),context], {stdio: 'inherit', timeout: 1200000});
  podman(['volume','create',shared]); created.shared = true;
  podman(['volume','create',webState]); created.state = true;
  podman(['run','-d','--name',host,'--network=none','--systemd=always','--cap-add=SYS_ADMIN','--cap-add=NET_ADMIN','--cap-add=NET_RAW',
    '--device=/dev/net/tun','--pids-limit=256','--memory=768m','--tmpfs=/run','--tmpfs=/tmp',
    '-v',shared+':/shared','-v',webState+':/shared/web',image]); created.host = true;
  for (let i=0;;i++) {
    try {if(podman(['exec',host,'systemctl','show','dbus.service','-p','ActiveState','--value']).trim()==='active')break;} catch {}
    assert(i<60,'systemd_fixture_not_ready'); await delay(500);
  }
  // A UNIX stream also has a process security label: filesystem permissions
  // alone do not allow connectto across different SELinux MCS categories.
  const label=JSON.parse(podman(['inspect',host]))[0].ProcessLabel;
  const securityLabel=label ? label.split(':').slice(3).join(':') : null;
  console.log('Fixture process label: '+label);
  if(securityLabel)assert.match(securityLabel,/^s0(?::c\d+(?:,c\d+)*)?$/);
  podman(['run','-d','--name',web,'--network=container:'+host,'--user=65534:65534','--read-only','--cap-drop=ALL',
    '--security-opt=no-new-privileges','--pids-limit=32','--memory=192m','--tmpfs=/tmp:rw,size=16m',
    ...(securityLabel?['--security-opt=label=level:'+securityLabel,'--security-opt=label=type:container_init_t']:[]),
    '-v',shared+':/shared:ro','-v',webState+':/shared/web:rw',frontend,'/bin/sh','-c',
    'while [ ! -S /shared/socket/broker.sock ] || [ ! -f /shared/web.json ]; do sleep 0.2; done; node admin/test/frontend-preflight.mjs && exec node admin/server.mjs /shared/web.json']); created.web = true;
  podman(['exec',host,'systemctl','start','--no-block','native-lab-driver.service']);
  console.log('Real API → broker → systemd → native client/exit; fault matrix running');
  for(let i=0;;i++) {
    const state = podman(['exec',host,'systemctl','show','native-lab-driver.service','-p','ActiveState','--value']).trim();
    if(state==='inactive'||state==='failed')break;
    assert(i<150,'lab_deadline'); await delay(2000);
  }
  const journal = podman(['exec',host,'journalctl','--no-pager','-u','native-lab-driver.service']); console.log(journal);
  const result = JSON.parse(podman(['exec',host,'cat','/shared/result.json']));
  assert.equal(result.passed,true,'fixture_failed');
  const inspected = JSON.parse(podman(['inspect',web]))[0];
  assert.equal(inspected.Config.User, '65534:65534'); assert.equal(inspected.HostConfig.ReadonlyRootfs,true);
  // inspect represents an empty capability set as null on some Podman builds.
  // Verify the running frontend's kernel credentials, not just launch options.
  const processStatus=podman(['exec',web,'cat','/proc/1/status']);
  for(const cap of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])assert.match(processStatus,new RegExp('^'+cap+':\\s+0+$','m'));
  assert.match(processStatus,/^NoNewPrivs:\s+1$/m);assert.match(processStatus,/^Uid:\s+65534\s+65534\s+65534\s+65534$/m);
  assert(inspected.HostConfig.SecurityOpt.includes('no-new-privileges'));
  const engineHash = podman(['exec',host,'sha256sum','/native/clean-vpn-engine']).split(' ')[0];
  const report={status:'passed',kind:'meshpn-admin-real-container-lab',realFrontend:true,realBroker:true,systemdPid1:true,
    realNativeTls:true,realTun:true,hostNetwork:false,publishedPorts:false,frontendUid:65534,frontendCapabilities:[],
    engineSha256:engineHash,brokerSha256:createHash('sha256').update(fs.readFileSync(path.join(root,'admin/broker.mjs'))).digest('hex'),
    checks:journal.split('\n').flatMap(l=>l.match(/NATIVE_ADMIN_([A-Z_]+)_PASS/)?.[1]??[]),
    limitations:['fixture-firewall-adapter','fixture-native-units-disable-ProtectControlGroups-and-PSI','fixture-shared-container_init_t-SELinux-domain-not-host-policy-validation','veth-not-physical-USB','no-reboot','cached-arm64-engine-not-rebuilt','not-physical-Radxa-WAN']};
  assert.deepEqual([...report.checks].sort(), ['USB_PROXY','AUTH','REAL_NATIVE_DATA','SETTINGS_APPLY','TLS_FAILURE_ROLLBACK',
    'STOPPED_STAYS_STOPPED','BROKER_CRASH_ROLLBACK','GUARD_REMAINS','CLEANUP'].sort());
  const output = path.join(root,'admin/test/last-container-report.json');
  fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n'); console.log(JSON.stringify(report));
} catch(e) {
  if(created.host)try{console.error(podman(['logs','--tail=80',host]));}catch{}
  if(created.web)try{console.error(podman(['logs','--tail=30',web]));}catch{}
  throw e;
} finally {
  for(const [name,key] of [[web,'web'],[host,'host']])if(created[key])try{podman(['rm','-f',name]);}catch(e){console.error('Cleanup failed: '+name);}
  for(const [name,key] of [[webState,'state'],[shared,'shared']])if(created[key])try{podman(['volume','rm',name]);}catch(e){console.error('Cleanup failed: '+name);}
  fs.rmSync(context,{recursive:true,force:true});
}
