/** Test-only CDP/BiDi driver. No TLS verification bypass or browser profile cloning. */
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { mkdir, writeFile, access } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const exec = (file, args, options = {}) => promisify(execFile)(file, args, {
  timeout: 15_000, maxBuffer: 1024 * 1024, ...options,
});

export function child(file, args, options = {}) {
  const proc = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'], detached: true, ...options });
  let output = '', ended = false;
  // Capture bounded diagnostics, never browser debug dumps or TLS key logs.
  const listeners = new Set();
  for (const stream of [proc.stdout, proc.stderr]) stream.on('data', (data) => {
    output = (output + data).slice(-64 * 1024);
    for (const notify of listeners) notify();
  });
  let failure;
  proc.on('error', (e) => { failure = e; });
  const closed = new Promise((resolve) => proc.once('close', () => {
    ended = true; for (const notify of listeners) notify(); resolve();
  }));
  return {
    proc,
    async waitFor(pattern, ms = 20_000) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => done(new Error(`process readiness timeout: ${file}`)), ms);
        const done = (error, match) => {
          clearTimeout(timer); listeners.delete(check); error ? reject(error) : resolve(match);
        };
        const check = () => {
          const match = pattern.exec(output);
          if (match) done(null, match);
          else if (ended) done(failure ?? new Error(`process exited before ready: ${file}\n${output}`));
        };
        listeners.add(check); check();
      });
    },
    async stop(signal = 'SIGTERM') {
      if (ended) return;
      if (!proc.pid) { await closed; return; }
      const kill = (sig) => { try { process.kill(-proc.pid, sig); } catch (error) { if (error.code !== 'ESRCH') throw error; } };
      kill(signal);
      const timer = setTimeout(() => kill('SIGKILL'), 5000);
      await closed; clearTimeout(timer);
    },
  };
}

async function protocol(url) {
  const socket = new WebSocket(url);
  const pending = new Map();
  let next = 0;
  function failAll() {
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('browser protocol closed')); }
    pending.clear();
  }
  socket.addEventListener('close', failAll);
  socket.addEventListener('error', failAll);
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id); clearTimeout(entry.timer);
    if (message.error || message.type === 'error') entry.reject(new Error(JSON.stringify(message)));
    else entry.resolve(message.result);
  });
  try { await once(socket, 'open', { signal: AbortSignal.timeout(5000) }); }
  catch (error) { socket.close(); throw error; }
  return {
    call(method, params = {}, sessionId) {
      const id = ++next;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`browser command timeout: ${method}`)); }, 15_000);
        pending.set(id, { resolve, reject, timer });
        socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      });
    },
    close() { failAll(); socket.close(); },
  };
}

export async function launchBrowser(kind, { directory, proxy, trusted, caPath, onProcess = () => {} }) {
  const executable = process.env[kind === 'chrome' ? 'MESHPN_BROWSER_CHROME' : 'MESHPN_BROWSER_FIREFOX'];
  if (!executable) throw new Error(`Set MESHPN_BROWSER_${kind.toUpperCase()} to the real browser executable`);
  const profile = join(directory, 'profile');
  const db = kind === 'chrome' ? join(directory, 'nssdb') : profile;
  await mkdir(profile, { recursive: true, mode: 0o700 });
  await mkdir(db, { recursive: true, mode: 0o700 });
  const certutil = process.env.MESHPN_CERTUTIL || 'certutil';
  await exec(certutil, ['-N', '--empty-password', '-d', `sql:${db}`]);
  if (trusted) await exec(certutil, ['-A', '-d', `sql:${db}`, '-n', 'meshpn-loopback-test-only', '-t', 'C,,', '-i', caPath]);
  let proc, rpc;
  try {
    if (kind === 'chrome') {
      // Chrome prefers an existing legacy NSS database even over XDG_DATA_HOME.
      // Overlay it ONLY in the child's private mount namespace. Never edit it.
      const legacy = join(homedir(), '.pki/nssdb');
      let hasLegacy = true;
      try { await access(legacy); } catch { hasLegacy = false; }
      const xdg = join(directory, 'xdg');
      await mkdir(join(xdg, 'pki/nssdb'), { recursive: true, mode: 0o700 });
      const mountTarget = hasLegacy ? legacy : join(xdg, 'pki/nssdb');
      proc = child('unshare', ['--user', '--map-current-user', '--mount', '--keep-caps',
        'sh', '-eu', '-c', 'mount --bind "$1" "$2"; shift 2; exec "$@"', 'browser-nss', db, mountTarget,
        executable, '--headless=new', `--user-data-dir=${profile}`, '--remote-debugging-port=0',
        '--remote-debugging-address=127.0.0.1', `--proxy-server=http://127.0.0.1:${proxy.port}`,
        '--proxy-bypass-list=<-loopback>', '--disable-background-networking', '--no-first-run', '--no-default-browser-check', 'about:blank'],
      { env: { ...process.env, XDG_DATA_HOME: xdg } });
      onProcess(proc);
      const match = await proc.waitFor(/DevTools listening on (ws:\/\/127\.0\.0\.1:\d+\/\S+)/);
      rpc = await protocol(match[1]);
      const version = await rpc.call('Browser.getVersion');
      const { targetId } = await rpc.call('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await rpc.call('Target.attachToTarget', { targetId, flatten: true });
      await rpc.call('Page.enable', {}, sessionId);
      return { version: version.product,
        async navigate(url) {
          const result = await rpc.call('Page.navigate', { url }, sessionId);
          if (result.errorText) throw new Error(result.errorText);
        },
        async evaluate(expression) {
          const result = await rpc.call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
          if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
          return result.result.value;
        },
        async close() { rpc.close(); await proc.stop(); },
      };
    }
    const prefs = {
      'network.proxy.type': 1, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': proxy.port,
      'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': proxy.port,
      'network.proxy.no_proxies_on': '', 'network.proxy.allow_hijacking_localhost': true,
      'network.captive-portal-service.enabled': false, 'network.connectivity-service.enabled': false,
      'datareporting.policy.dataSubmissionEnabled': false, 'browser.shell.checkDefaultBrowser': false,
      'security.enterprise_roots.enabled': false,
    };
    await writeFile(join(profile, 'user.js'), Object.entries(prefs).map(([key, value]) =>
      `user_pref(${JSON.stringify(key)}, ${JSON.stringify(value)});`).join('\n'), { mode: 0o600 });
    proc = child(executable, ['--headless', '--no-remote', '--profile', profile, '--remote-debugging-port', '0']);
    onProcess(proc);
    const match = await proc.waitFor(/WebDriver BiDi listening on (ws:\/\/127\.0\.0\.1:\d+)/);
    rpc = await protocol(`${match[1]}/session`);
    const session = await rpc.call('session.new', { capabilities: { alwaysMatch: { acceptInsecureCerts: false } } });
    const { context } = await rpc.call('browsingContext.create', { type: 'tab' });
    return { version: `Firefox/${session.capabilities.browserVersion}`,
      navigate: (url) => rpc.call('browsingContext.navigate', { context, url, wait: 'complete' }),
      async evaluate(expression) {
        const result = await rpc.call('script.evaluate', { expression: `(async () => JSON.stringify(await (${expression})))()`, target: { context }, awaitPromise: true });
        if (result.type !== 'success') throw new Error(JSON.stringify(result));
        return JSON.parse(result.result.value);
      },
      async close() { rpc.close(); await proc.stop(); },
    };
  } catch (error) { rpc?.close(); await proc?.stop(); throw error; }
}
