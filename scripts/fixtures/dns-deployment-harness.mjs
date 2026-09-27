import assert from 'node:assert/strict';
import { mkdtemp, mkdir, chmod, writeFile, lstat, realpath, rm, copyFile, readlink } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { runCommand } from '../lib/transparent-acceptance.mjs';

const hash = (v) => createHash('sha256').update(v).digest('hex');
export async function deploymentHarness(t, { moduleName = 'dns-deployment-bundle', entry = 'dnsDeploymentBundle', setup = '' } = {}) {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-bundle-')));
  t.after(() => rm(base, { recursive: true, force: true }));
  const data = join(base, 'data'), jail = join(base, 'jail'); await mkdir(data); await mkdir(jail); await chmod(jail, 0o755);
  const root = join(data, 'root'), directory = join(data, 'journal'), source = join(data, 'source'), lock = join(data, 'lock');
  for (const path of [root, directory, source, join(root, 'opt'), join(source, 'scripts'), join(source, 'scripts/lib')]) {
    await mkdir(path, { mode: 0o755 }); await chmod(path, path === directory ? 0o700 : 0o755);
  }
  await writeFile(lock, '', { mode: 0o600 });
  const files = {};
  for (const path of ['scripts/dns-client.mjs', 'scripts/dns-boot-guard.mjs', 'scripts/dns-exit-adapter.mjs', 'scripts/lib/dns-installed-authority.mjs']) {
    const body = `// ${path}\nexport const fixture = true;\n`; files[path] = hash(body);
    await writeFile(join(source, path), body, { mode: 0o644 }); await chmod(join(source, path), 0o644);
  }
  const manifest = JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-code-bundle', files });
  await writeFile(join(source, 'bundle.json'), manifest, { mode: 0o644 }); await chmod(join(source, 'bundle.json'), 0o644);
  // The execution environment maps system files to nobody, not root. Exercise
  // the REAL root-pinned runner in a tiny private chroot/user+mount+PID namespace;
  // never relax its production ownership check just for the fixture.
  const binds = [[data, '/data'], [fileURLToPath(new URL('..', import.meta.url)), '/project/scripts'],
    [process.execPath, '/usr/bin/node'], ['/dev/null', '/dev/null']];
  const libraries = new Set();
  for (const binary of ['/usr/bin/mv', '/usr/bin/flock', process.execPath]) {
    const r = await runCommand('/usr/bin/ldd', [binary]); assert.equal(r.code, 0, r.stderr);
    for (const line of r.stdout.split('\n')) { const path = /(?:=>\s+|^\s*)(\/\S+)\s+\(/.exec(line)?.[1]; if (path) libraries.add(path); }
  }
  for (const p of libraries) binds.push([p, p]);
  for (const [from, to] of binds) {
    await mkdir(dirname(join(jail, to)), { recursive: true, mode: 0o755 });
    if ((await lstat(from)).isDirectory()) await mkdir(join(jail, to), { mode: 0o755 });
    else await writeFile(join(jail, to), '');
  }
  await mkdir(join(jail, 'proc')); await copyFile('/usr/bin/mv', join(jail, 'usr/bin/mv'));
  await copyFile('/usr/bin/flock', join(jail, 'usr/bin/flock'));
  await chmod(join(jail, 'usr/bin/mv'), 0o755); await chmod(join(jail, 'usr/bin/flock'), 0o755);
  const namespace = await readlink('/proc/self/ns/mnt');
  const bootstrap = `import assert from 'node:assert/strict'; import {readlink} from 'node:fs/promises';
    import {execFileSync} from 'node:child_process';
    const p=JSON.parse(process.argv[1]); assert.notEqual(await readlink('/proc/self/ns/mnt'),p.namespace);
    for(const [from,to] of p.binds) {
      execFileSync('/usr/bin/mount',['--bind',from,p.jail+to]);
      if(!to.startsWith('/data') && to!=='/dev/null') execFileSync('/usr/bin/mount',['-o','remount,bind,ro',p.jail+to]);
    }
    execFileSync('/usr/bin/mount',['-t','proc','proc',p.jail+'/proc']);
    execFileSync('/usr/sbin/chroot',[p.jail,...process.argv.slice(2)],{stdio:'inherit'});`;
  const options = { root: '/data/root', directory: '/data/journal', source: '/data/source', expectedSha256: hash(manifest) };
  const args = (operation, hook = '', extra = {}) => {
    const js = `import assert from 'node:assert/strict'; import { ${entry} } from ${JSON.stringify('file:///project/scripts/lib/' + moduleName + '.mjs')};
      import { readFile,readdir,mkdir,writeFile } from 'node:fs/promises';
      let lockFd;
      for (const n of await readdir('/proc/self/fdinfo')) {
        try { if ((await readFile('/proc/self/fdinfo/'+n,'utf8')).includes('FLOCK')) lockFd=Number(n); }
        catch(e) { if(e.code!=='ENOENT') throw e; }
      }
      const options=JSON.parse(process.argv[1]);
      process.umask(0o077);\n      ${setup}
      let inactiveChecks=0;
      const result=await ${entry}({...options,lockFd:options.withoutLock?undefined:lockFd,assertInactive:async()=>{inactiveChecks++; return options.inactive!==false;},
        checkpoint:async(point)=>{${hook}}}); console.log(JSON.stringify({...result,...(options.countInactive?{inactiveChecks}:{})}));`;
    return ['--user', '--map-root-user', '--mount', '--propagation', 'private', '--net', '--pid', '--fork', '--kill-child=SIGKILL',
      process.execPath, '--input-type=module', '-e', bootstrap,
      JSON.stringify({ jail, binds: extra.crossMount ? [...binds, [directory, '/data/journal']] : binds, namespace }),
      '/usr/bin/flock', '-n', '-E', '75', '-F', '/data/lock', '/usr/bin/node', '--input-type=module', '-e', js, JSON.stringify({ ...options, operation, ...extra })];
  };
  const run = (op, hook, extra) => runCommand('/usr/bin/unshare', args(op, hook, extra), { timeoutMs: 15000 });
  const ok = async (op, hook, extra) => { const r = await run(op, hook, extra); assert.equal(r.code, 0, r.stderr); assert.equal(r.reason, null); return JSON.parse(r.stdout); };
  return { base, root, directory, source, lock, options, args, run, ok, target: join(root, 'opt/clean-vpn') };
}
