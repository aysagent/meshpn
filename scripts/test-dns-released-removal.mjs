import assert from 'node:assert/strict';
import test from 'node:test';
import { lstat, writeFile, rename, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { deploymentHarness } from './fixtures/dns-deployment-harness.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { readDnsReleasedRemoval, validateDnsReleasedRemoval, validateDnsReleasedObservation } from './lib/dns-released-removal.mjs';
import { removeInstalledReleasedDnsDeployment } from './lib/dns-installed-removal.mjs';

const policy = { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'nf_tables',
  input: { schema: 1, client: 'vps2', id: 'a'.repeat(32) } };
const policyText = `${JSON.stringify(policy)}\n`;
const observation = { schema: 1, kind: 'clean-vpn-dns-released-deployment-check', releasedInactive: true,
  systemSettingsChanged: false, dnsQueriesSent: 0, activationAuthorized: false, uninstallAuthorized: false,
  historySha256: 'd'.repeat(64) };
async function fixture(t) {
  const setup = `
    options.deploymentDirectory='/data/deployment';
    if(options.operation==='install') {
      const {dirname}=await import('node:path');
      const {compileDnsClientDeploymentFiles}=await import('/project/scripts/lib/dns-deployment-files.mjs');
      const {dnsDeployment}=await import('/project/scripts/lib/dns-deployment.mjs');
      const domainPolicy={schema:1,denySuffixes:['internal']};
      const files=compileDnsClientDeploymentFiles({bundle:await readFile(options.source+'/bundle.json','utf8'),secret:Buffer.alloc(32,0x5a),
        guard:${JSON.stringify(policy)},
        adapter:{schema:1,exitIp:'93.184.216.36',exitPort:443,publicName:'relay.example',listenPort:1053,readyName:'example.com',domainPolicy,
          upstream:{schema:1,transport:'doh',hostname:'resolver.example',port:443,path:'/dns-query',bootstrap:{addresses:['93.184.216.35']},trust:{mode:'bundled'}}},
        config:{schema:1,kind:'clean-vpn-dns-client',client:'vps2',uplink:'eth0',networkFile:{path:'/run/systemd/network/10-netplan-eth0.network',sha256:'c'.repeat(64)},adapterPort:1053,readyName:'example.com',domainPolicy}});
      await mkdir(options.deploymentDirectory,{mode:0o700});
      for(const file of files) await mkdir(dirname(options.root+file.path),{recursive:true,mode:0o700});
      const r=await dnsDeployment({...options,directory:options.deploymentDirectory,files,lockFd,assertInactive:async()=>true});
      console.log(JSON.stringify(r)); process.exit(0);
    }
    options.inspectReleased=async()=>({...${JSON.stringify(observation)},
      historySha256:options.historySha256??${JSON.stringify(observation.historySha256)},releasedInactive:options.inactive!==false});
  `;
  const h = await deploymentHarness(t, { moduleName: 'dns-released-removal', entry: 'removeReleasedDnsDeployment', setup });
  await h.ok('install');
  return { ...h, opt: join(h.root, 'etc/clean-vpn/dns/client-opt-in.json'),
    policy: join(h.root, 'etc/clean-vpn/dns/guard-policy.json'), deployment: join(h.base, 'data/deployment') };
}
const absent = (path) => assert.rejects(lstat(path), { code: 'ENOENT' });
test('released rollback binds exact policy/history, revokes files before code, and retains code archive', async (t) => {
  const h = await fixture(t);
  const r = await h.ok('remove', '', { policyText }); assert.equal(r.stage, 'removed');
  assert.equal(r.runtimeHistoryRetained, true); assert.equal(r.servicesStoppedByThisOperation, false);
  assert.equal(r.codeRetainedInArchive, true); await absent(h.target); await absent(h.opt); await absent(h.policy);
  await lstat(join(h.deployment, 'code/retired/bundle.json'));
  assert.deepEqual(await h.ok('recover'), r); assert.deepEqual(await h.ok('inspect'), r);
  const record = await readDnsReleasedRemoval(h.directory); assert.equal(record.policyText, policyText);
  assert.equal(record.historySha256, observation.historySha256); assert.equal(record.stage, 'removed');
  assert.equal(JSON.stringify(record).includes(Buffer.alloc(32, 0x5a).toString('hex')), false);
});
for (const [name, extra] of [['wrong policy', { policyText: policyText.replace('nf_tables', 'legacy') }],
  ['active OS', { policyText, inactive: false }], ['no policy', {}], ['no lock', { policyText, withoutLock: true }]])
  test(`released rollback refuses ${name} before revoking opt-in`, async (t) => {
    const h = await fixture(t); assert.notEqual((await h.run('remove', '', extra)).code, 0);
    await lstat(h.opt); await absent(join(h.directory, 'journal.json'));
  });
test('changed history after opt-in removal blocks the next file and any resume under that history', async (t) => {
  const h = await fixture(t);
  const r = await h.run('remove', `if(point==='deployment:files:file-12:removed') options.historySha256='e'.repeat(64);`, { policyText });
  assert.notEqual(r.code, 0); await absent(h.opt); await lstat(h.policy);
  await lstat(join(h.root, 'etc/clean-vpn/dns/client.json')); await lstat(h.target);
  assert.equal((await readDnsReleasedRemoval(h.directory)).stage, 'removing');
  assert.notEqual((await h.run('recover', '', { historySha256: 'e'.repeat(64) })).code, 0);
  await lstat(h.policy);
});
test('changed removal intent is preserved, not overwritten after the next checkpoint', async (t) => {
  const h = await fixture(t);
  assert.notEqual((await h.run('remove', `if(point==='deployment:files:file-12:removed') {
    const p=options.directory+'/journal.json',r=JSON.parse(await readFile(p));r.historySha256='e'.repeat(64);await writeFile(p,JSON.stringify(r));
  }`, { policyText })).code, 0);
  await lstat(h.policy); assert.equal((await readDnsReleasedRemoval(h.directory)).historySha256, 'e'.repeat(64));
});
test('recover without removal intent cannot initiate an uninstall', async (t) => {
  const h = await fixture(t); assert.notEqual((await h.run('recover', '', { policyText })).code, 0); await lstat(h.opt);
});
test('uncommitted intent staging is retained for review and cannot be adopted', async (t) => {
  const h = await fixture(t);
  assert.notEqual((await h.run('remove', `if(point==='removing:file-synced') throw new Error('CUT');`, { policyText })).code, 0);
  const files = await readdir(h.directory); assert.equal(files.length, 1); assert.match(files[0], /^journal-[a-f0-9]+\.tmp$/);
  for (const op of ['remove', 'recover']) assert.notEqual((await h.run(op, '', { policyText })).code, 0);
  assert.deepEqual(await readdir(h.directory), files); await lstat(h.opt);
});
test('removal journal cannot overlap the original deployment', async (t) => {
  const h = await fixture(t);
  assert.notEqual((await h.run('remove', '', { policyText, directory: '/data/deployment/files' })).code, 0);
  await lstat(h.opt); await absent(join(h.directory, 'journal.json'));
});
test('foreign code/config drift refuses removal intent and keeps opt-in', async (t) => {
  const h = await fixture(t); await writeFile(join(h.target, 'scripts/dns-client.mjs'), '// foreign');
  assert.notEqual((await h.run('remove', '', { policyText })).code, 0); await lstat(h.opt);
  await absent(join(h.directory, 'journal.json'));
});
test('strict removal metadata excludes credentials, arbitrary commands and fabricated OS status', async () => {
  assert.equal(validateDnsReleasedObservation(observation), observation.historySha256);
  for (const [key, value] of [['historySha256', 'x'], ['releasedInactive', false], ['systemSettingsChanged', true],
    ['dnsQueriesSent', 1], ['uninstallAuthorized', true], ['kind', 'other']])
    assert.throws(() => validateDnsReleasedObservation({ ...observation, [key]: value }));
  await assert.rejects(removeInstalledReleasedDnsDeployment({ commands: { run() {} }, operation: 'remove' }), /checked DNS system commands/);
});
for (const point of ['removing:dir-synced', 'deployment:files:file-12:removed',
  'deployment:files:file-4:removed', 'deployment:removing-code:dir-synced', 'deployment:code:bundle:retired'])
  test(`real SIGKILL resumes released removal without original config/key/source at ${point}`, async (t) => {
    const h = await fixture(t);
    const child = spawn('/usr/bin/unshare', h.args('remove',
      `if(point===${JSON.stringify(point)}) {process.stdout.write('CUT\\n');await new Promise(()=>setInterval(()=>{},1000));}`, { policyText }),
    { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', error = ''; child.stdout.on('data', (b) => { output += b; }); child.stderr.on('data', (b) => { error += b; });
    const closed = once(child, 'close'), timer = setTimeout(() => child.kill('SIGKILL'), 20000);
    try {
      await new Promise((resolve, reject) => {
        const check = () => { if (output.includes('CUT\n')) resolve(); };
        child.stdout.on('data', check); check(); child.once('close', () => reject(new Error(`no checkpoint: ${error}`)));
      });
      assert.equal((await runCommand('/usr/bin/flock', ['-n', '-E', '75', h.lock, '/usr/bin/true'])).code, 75);
      child.kill('SIGKILL'); assert.deepEqual(await closed, [null, 'SIGKILL']);
    } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await closed; }
    await rename(h.source, join(h.base, 'data/source-unavailable'));
    assert.equal((await h.ok('recover')).stage, 'removed'); await absent(h.opt); await absent(h.target);
    const record = await readDnsReleasedRemoval(h.directory);
    for (const mutate of [(v) => { v.stage = 'active'; }, (v) => { v.secret = 'bad'; }, (v) => { v.policyText = '{}'; }]) {
      const v = structuredClone(record); mutate(v); assert.throws(() => validateDnsReleasedRemoval(v));
    }
  });
