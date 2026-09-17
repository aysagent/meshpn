import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');

function npmWithFakeSsh(script, args, extraEnv = {}) {
  const tmp = mkdtempSync(join(tmpdir(), 'meshpn-remote-test-'));
  try {
    writeFileSync(join(tmp, 'ssh'), '#!/bin/sh\nprintf "ARG:%s\\n" "$@"\n', { mode: 0o755 });
    const result = spawnSync('npm', ['run', '--silent', script, ...args], {
      cwd: root,
      env: { ...process.env, ...extraEnv, PATH: `${tmp}:${process.env.PATH}` },
      encoding: 'utf8',
      timeout: 10000,
    });
    assert.ifError(result.error);
    return {
      ...result,
      sshArgs: result.stdout.split('\n').filter(line => line.startsWith('ARG:')).map(line => line.slice(4)),
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

test('Mac command accepts npm positional target and binds server loopback', () => {
  const result = npmWithFakeSsh('device:remote', ['tunneluser@example.test']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.sshArgs, [
    '-N', '-T', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=3', '-R', '127.0.0.1:22022:127.0.0.1:22',
    '--', 'tunneluser@example.test',
  ]);
});

test('Linux command accepts Mac user and forwards a remote command', () => {
  const result = npmWithFakeSsh('device:remote:connect', [
    'macuser', 'cd ~/dev/home/meshpn && npm run device:flash',
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.sshArgs, [
    '-p', '22022', '-o', 'ConnectTimeout=5', '-o',
    'HostKeyAlias=meshpn-mac-via-tunnel', '--', 'macuser@127.0.0.1',
    'cd ~/dev/home/meshpn && npm run device:flash',
  ]);
});

test('both sides use the same custom port', () => {
  const env = { MESHPN_REMOTE_PORT: '23022' };
  const tunnel = npmWithFakeSsh('device:remote', ['user@example.test'], env);
  const connect = npmWithFakeSsh('device:remote:connect', ['macuser'], env);
  assert.equal(tunnel.status, 0, tunnel.stderr);
  assert.equal(connect.status, 0, connect.stderr);
  assert(tunnel.sshArgs.includes('127.0.0.1:23022:127.0.0.1:22'));
  assert.deepEqual(connect.sshArgs.slice(0, 2), ['-p', '23022']);
});

test('Linux command can force a tty for an interactive monitor', () => {
  const result = npmWithFakeSsh('device:remote:connect', ['macuser', 'npm run device:monitor'], {
    MESHPN_REMOTE_TTY: '1',
  });
  assert.equal(result.status, 0, result.stderr);
  assert(result.sshArgs.includes('-t'));
});

test('rejects malformed SSH target before starting ssh', () => {
  const result = npmWithFakeSsh('device:remote', ['-oProxyCommand=bad']);
  assert.equal(result.status, 2);
  assert.deepEqual(result.sshArgs, []);
});
