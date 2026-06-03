import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { waitForLog } from './log-wait.mjs';
import { runBidirectionalProbes } from './probe-bidir.mjs';
import {
  assertNoRoutingMutation,
  snapshotFirewallText,
  snapshotRoutesText,
} from './route-guard.mjs';
import { waitForVpnTunPair, cleanupStaleVpnUtuns } from './tun-detect.mjs';
import { killProcessGroupGracefulThenForce } from './cleanup-darwin.mjs';
import { cleanVpnJs } from './preflight.mjs';

/** @param {number} pid */
export function killTree(pid) {
  killProcessGroupGracefulThenForce(pid, 2500);
}

/**
 * @param {string[]} extraArgs
 * @param {{ nodeArgs?: string[], env?: Record<string, string> }} [opts]
 */
export function spawnCleanVpn(extraArgs, opts = {}) {
  const nodeArgs = [...(opts.nodeArgs || []), cleanVpnJs, ...extraArgs];
  const env = {
    ...process.env,
    PATH: process.env.PATH,
    CLEAN_VPN_SKIP_CLIENT_ROUTES: '1',
    CLEAN_VPN_TRANSPORT_TEST: '1',
    ...(opts.env || {}),
  };
  const child = spawn(process.execPath, nodeArgs, {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  return child;
}

/**
 * @param {import('./matrix.mjs').TransportCase} testCase
 * @param {{ verbose?: boolean }} opts
 */
export async function runCase(testCase, opts = {}) {
  const started = Date.now();
  if (testCase.skipReason) {
    return {
      id: testCase.id,
      tier: testCase.tier,
      skipped: true,
      skipReason: testCase.skipReason,
      durationMs: 0,
    };
  }

  const routesBefore = snapshotRoutesText();
  const fwBefore = snapshotFirewallText();
  cleanupStaleVpnUtuns({ verbose: Boolean(opts.verbose) });

  /** @type {import('child_process').ChildProcess|null} */
  let exitProc = null;
  /** @type {import('child_process').ChildProcess|null} */
  let clientProc = null;

  try {
    exitProc = spawnCleanVpn(testCase.exitArgs, {
      nodeArgs: testCase.nodeExperimentalQuic ? ['--experimental-quic'] : [],
    });
    if (!exitProc.stdout || !exitProc.stderr) throw new Error('exit stdio missing');
    const exitLog = /** @type {import('stream').Readable} */ (
      /** @type {unknown} */ (exitProc.stdout)
    );
    exitLog.on('data', (c) => {
      if (opts.verbose) process.stdout.write(`[exit:${testCase.id}] ${c}`);
    });
    exitProc.stderr.on('data', (c) => {
      if (opts.verbose) process.stderr.write(`[exit:${testCase.id}] ${c}`);
    });

    await waitForLog(exitLog, /TUN|tun|utun|NAT|listening|8765|8443|8450|9876/i, 30000);

    clientProc = spawnCleanVpn(testCase.clientArgs, {
      nodeArgs: testCase.nodeExperimentalQuic ? ['--experimental-quic'] : [],
    });
    if (!clientProc.stdout || !clientProc.stderr) throw new Error('client stdio missing');
    const clientLog = /** @type {import('stream').Readable} */ (
      /** @type {unknown} */ (clientProc.stdout)
    );
    clientLog.on('data', (c) => {
      if (opts.verbose) process.stdout.write(`[client:${testCase.id}] ${c}`);
    });
    clientProc.stderr.on('data', (c) => {
      if (opts.verbose) process.stderr.write(`[client:${testCase.id}] ${c}`);
    });

    await Promise.race([
      waitForLog(clientLog, testCase.readyPattern, testCase.clientTimeoutMs || 45000),
      new Promise((_, rej) =>
        setTimeout(
          () => rej(new Error('client ready timeout')),
          testCase.clientTimeoutMs || 45000,
        ),
      ),
    ]).catch(async () => {
      /* lazy transports: still try probes */
    });

    const { exitTun, clientTun } = await waitForVpnTunPair(20000);

    assertNoRoutingMutation(
      routesBefore,
      snapshotRoutesText(),
      fwBefore,
      snapshotFirewallText(),
    );

    await new Promise((r) => setTimeout(r, 500));
    await runBidirectionalProbes({
      prefix: `[${testCase.id}]`,
      clientLog,
      exitLog,
    });

    if (opts.keepAlive) {
      await new Promise((r) => setTimeout(r, 6000));
      await runBidirectionalProbes({
        prefix: `[${testCase.id}:keep-alive]`,
        clientLog,
        exitLog,
      });
    }

    return {
      id: testCase.id,
      tier: testCase.tier,
      transport: testCase.transport,
      variant: testCase.variant,
      topology: testCase.topology,
      ping: true,
      curl: true,
      c2e: true,
      e2c: true,
      durationMs: Date.now() - started,
      exitTun,
      clientTun,
    };
  } catch (err) {
    return {
      id: testCase.id,
      tier: testCase.tier,
      transport: testCase.transport,
      error: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - started,
    };
  } finally {
    if (exitProc?.pid) killTree(exitProc.pid);
    if (clientProc?.pid) killTree(clientProc.pid);
    await new Promise((r) => setTimeout(r, 500));
    cleanupStaleVpnUtuns({ verbose: Boolean(opts.verbose) });
  }
}
