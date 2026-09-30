import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { assertFreshHostInstall } from './lib/host-install-check.mjs';

function fixture({ present = -1, errorCode = 'ENOENT', metadata = {}, failCommand = false } = {}) {
  const paths = [], commands = [];
  return { paths, commands, options: {
    io: { lstatSync(path) { paths.push(path); if (paths.length - 1 === present) return {};
      throw Object.assign(Error('read failure'), {code:errorCode}); } },
    run(file, args, options) {
      commands.push([file, args]); assert.equal(file, 'systemctl'); assert.equal(args[1], 'show');
      assert.equal(options.timeoutMs, 20000); if (failCommand) throw Error('manager unavailable');
      return Object.entries({ LoadState:'not-found', ActiveState:'inactive', FragmentPath:'', DropInPaths:'',
        ...metadata }).map(([k,v])=>`${k}=${v}`).join('\n');
    },
  } };
}
test('fresh installer gate reads installation/gate paths and two absent unit states', () => {
  const f=fixture(); assert.equal(assertFreshHostInstall(f.options).status, 'fresh-install-only');
  assert.equal(f.paths.length, 6); assert.equal(f.commands.length, 2);
});
for (let present=0; present<6; present++) test(`any existing entry (including dangling symlink) refuses: ${present}`, () => {
  const f=fixture({present}); assert.throws(()=>assertFreshHostInstall(f.options), /in-place update refused/);
  assert.equal(f.commands.length, 0);
});
for (const metadata of [{LoadState:'loaded'}, {LoadState:'masked'}, {LoadState:'error'}, {ActiveState:'active'},
  {ActiveState:'failed'}, {FragmentPath:'/usr/lib/systemd/system/clean-vpn.service'}, {DropInPaths:'/run/override.conf'}])
  test(`installer refuses existing or ambiguous unit: ${JSON.stringify(metadata)}`, () => {
    const f=fixture({metadata}); assert.throws(()=>assertFreshHostInstall(f.options), /in-place update refused/);
  });
test('filesystem and manager errors fail closed', () => {
  for (const options of [{errorCode:'EACCES'}, {errorCode:'EIO'}, {failCommand:true}]) {
    const f=fixture(options); assert.throws(()=>assertFreshHostInstall(f.options));
  }
  assert.throws(()=>assertFreshHostInstall({...fixture().options, run:()=>''}));
});
test('service name validation precedes reads', () => {
  for (const service of ['', '../other', '-flag', 'x'.repeat(201)]) {
    const f=fixture(); assert.throws(()=>assertFreshHostInstall({...f.options, service})); assert.equal(f.paths.length, 0);
  }
});
test('shell installer runs refusal before resolver, writes, and service operations; no removal branch', () => {
  const source=readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  const gate=source.indexOf('"$NODE_BIN" "$REPO_ROOT/scripts/clean-vpn-install-check.mjs"');
  assert.ok(gate>0);
  for (const marker of ['getent ahostsv4', 'cat > "$RUN_SH"', 'install -m', 'systemctl daemon-reload'])
    assert.ok(gate<source.indexOf(marker));
  assert.doesNotMatch(source, /disable --now|rm -f|"\$KS_SH" down/);
});
