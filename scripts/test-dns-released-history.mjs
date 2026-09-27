import assert from 'node:assert/strict';
import test from 'node:test';
import { assertReleasedDnsHistory } from './lib/dns-released-history.mjs';
import { inspectReleasedDnsDeployment } from './lib/dns-deployment-inactive.mjs';
import { deploymentHarness } from './fixtures/dns-deployment-harness.mjs';

const context = { scope: { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' },
  bootId: '11111111-1111-4111-8111-111111111111', busId: 'b'.repeat(32), owner: ':1.10' };
const input = { schema: 1, client: 'vps2', id: 'a'.repeat(32) };
const options = { input, context, firewallBackend: 'nf_tables', guardIdentity: '1:4' };
const fixture = () => {
  const id = 'c'.repeat(32), name = `cvdns${id.slice(0, 8)}`;
  return { transaction: { schema: 1, backend: 'coupled-dns-namespace', id, name, context: structuredClone(context),
    port: 1053, phase: 'released', original: null, level: 0, pending: false, direction: 'restore' },
  link: { schema: 1, backend: 'owned-dns-link-namespace', id, name, context: structuredClone(context), ifindex: null, stage: 'released' },
  guard: { schema: 1, backend: 'client-dns-guard', input: structuredClone(input), stage: 'released',
    context: { bootId: context.bootId, netns: context.scope.net, directoryIdentity: '1:4',
      firewall: { ipv4: 'nf_tables', ipv6: 'nf_tables' }, usb: null } } };
};
test('released evidence permits disabled-before-link-creation, and distinct guard/transaction IDs', () => {
  assertReleasedDnsHistory(fixture(), options);
});
for (const [name, mutate] of [
  ['unfinished transaction', (v) => { v.transaction.phase = 'unlink'; }],
  ['pending setter', (v) => { v.transaction.pending = true; }],
  ['applied settings', (v) => { v.transaction.level = 1; }],
  ['wrong direction', (v) => { v.transaction.direction = 'apply'; }],
  ['unfinished link', (v) => { v.link.stage = 'deleted'; }],
  ['other link', (v) => { v.link.id = 'd'.repeat(32); v.link.name = 'cvdnsdddddddd'; }],
  ['other child context', (v) => { v.link.context.owner = ':1.11'; }],
  ['active guard', (v) => { v.guard.stage = 'active'; }],
  ['releasing guard', (v) => { v.guard.stage = 'releasing'; }],
  ['different guard policy', (v) => { v.guard.input.id = 'd'.repeat(32); }],
  ['old guard boot', (v) => { v.guard.context.bootId = '22222222-2222-4222-8222-222222222222'; }],
  ['old guard namespace', (v) => { v.guard.context.netns = 'net:[9]'; }],
  ['replaced guard directory', (v) => { v.guard.context.directoryIdentity = '1:99'; }],
  ['different firewall backend', (v) => { v.guard.context.firewall = { ipv4: 'legacy', ipv6: 'legacy' }; }],
]) test(`released history refuses ${name}`, () => {
  const v = fixture(); mutate(v); assert.throws(() => assertReleasedDnsHistory(v, options));
});
for (const [name, mutate] of [
  ['boot', (v) => { v.context.bootId = '22222222-2222-4222-8222-222222222222'; }],
  ['bus', (v) => { v.context.busId = 'e'.repeat(32); }],
  ['resolved owner', (v) => { v.context.owner = ':1.12'; }],
  ['network namespace', (v) => { v.context.scope.net = 'net:[90]'; }],
  ['mount namespace', (v) => { v.context.scope.mnt = 'mnt:[90]'; }],
  ['PID namespace', (v) => { v.context.scope.pid = 'pid:[90]'; }],
]) test(`released journals cannot be adopted into a different ${name}`, () => {
  const v = structuredClone(options); mutate(v); assert.throws(() => assertReleasedDnsHistory(fixture(), v));
});
test('saved original link requires the same child incarnation', async () => {
  const { ownedLinkSpec } = await import('./lib/dns-owned-link-journal.mjs');
  const v = fixture(); v.transaction.original = { ...ownedLinkSpec(v.transaction), ifindex: 7,
    dns: { DNSEx: [], Domains: [], DefaultRoute: false }, addrgen: 'eui64' }; v.link.ifindex = 7;
  assertReleasedDnsHistory(v, options); v.link.ifindex = 8;
  assert.throws(() => assertReleasedDnsHistory(v, options));
});
test('released collector rejects forged commands before OS access', async () => {
  let called = false;
  await assert.rejects(inspectReleasedDnsDeployment({ commands: { run: () => { called = true; } } }), /checked DNS system commands/);
  assert.equal(called, false);
});

const setup = `
  const {lstat,chmod,symlink,link,rename,unlink} = await import('node:fs/promises');
  for (const suffix of ['transaction','transaction/link','guard']) await mkdir(options.directory+'/'+suffix,{mode:0o700});
  const v=${JSON.stringify(fixture())}, s=await lstat(options.directory+'/guard');
  v.guard.context.directoryIdentity=s.dev+':'+s.ino;
  for (const [key,suffix] of [['transaction','transaction'],['link','transaction/link'],['guard','guard']])
    await writeFile(options.directory+'/'+suffix+'/journal.json',JSON.stringify(v[key]),{mode:0o600});
  const path=options.directory+'/guard/journal.json';
  if(options.fault==='missing') await unlink(path);
  if(options.fault==='public') await chmod(path,0o644);
  if(options.fault==='directory-mode') await chmod(options.directory+'/guard',0o755);
  if(options.fault==='parent-mode') await chmod('/data',0o777);
  if(options.fault==='hardlink') await link(path,options.directory+'/second-link');
  if(options.fault==='symlink') { await rename(path,path+'.original'); await symlink(path+'.original',path); }
  if(options.fault==='directory-symlink') { await rename(options.directory+'/guard',options.directory+'/other'); await symlink('other',options.directory+'/guard'); }
  if(options.fault==='oversize') await writeFile(path,' '.repeat(8193));
  if(options.fault==='malformed') await writeFile(path,'{}');
  if(options.fault==='active') { v.guard.stage='active'; await writeFile(path,JSON.stringify(v.guard)); }
`;
test('private root-owned history is read unchanged with pinned directory identities', async (t) => {
  const h = await deploymentHarness(t, { moduleName: 'dns-released-history', entry: 'readReleasedDnsHistory', setup });
  const result = await h.ok('inspect', '', options);
  assert.equal(result.history.transaction.phase, 'released'); assert.equal(result.history.guard.stage, 'released');
  assert.equal(result.history.guard.context.directoryIdentity,
    `${result.metadata['/data/journal/guard'].dev}:${result.metadata['/data/journal/guard'].ino}`);
});
for (const fault of ['missing', 'public', 'directory-mode', 'parent-mode', 'hardlink', 'symlink',
  'directory-symlink', 'oversize', 'malformed', 'active']) test(`private history refuses ${fault}`, async (t) => {
  const h = await deploymentHarness(t, { moduleName: 'dns-released-history', entry: 'readReleasedDnsHistory', setup });
  const result = await h.run('inspect', '', { ...options, fault }); assert.notEqual(result.code, 0);
  assert.equal(result.reason, null);
});
