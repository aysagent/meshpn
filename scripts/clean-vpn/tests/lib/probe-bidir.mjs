import { waitForLog } from './log-wait.mjs';

const C2E_PING = /transport-test OK ping client→exit/;
const C2E_CURL = /transport-test OK curl client→exit/;
const E2C_PING = /transport-test OK ping exit→client/;
const E2C_CURL = /transport-test OK curl exit→client/;
const FAIL = /transport-test FAIL/;

/**
 * @param {import('stream').Readable} stream
 * @param {string} role
 * @returns {Promise<never>}
 */
function watchFail(stream, role) {
  return new Promise((_, reject) => {
    /** @type {string} */
    let buf = '';
    const onData = (chunk) => {
      buf += chunk.toString();
      if (buf.length > 128_000) buf = buf.slice(-64_000);
      if (!FAIL.test(buf)) return;
      stream.off('data', onData);
      const line = buf.split('\n').find((l) => FAIL.test(l)) ?? 'transport-test FAIL';
      const tail = buf.slice(buf.indexOf(line));
      reject(new Error(`${role}: ${tail.trim().slice(0, 500)}`));
    };
    stream.on('data', onData);
  });
}

/**
 * @param {import('stream').Readable} clientLog
 * @param {import('stream').Readable} exitLog
 * @param {{ timeoutMs?: number, prefix?: string }} [opts]
 */
export async function waitForInProcessTransportProbes(clientLog, exitLog, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 55000;
  const prefix = opts.prefix ? `${opts.prefix} ` : '';
  const log = (msg) => process.stdout.write(`${prefix}${msg}\n`);

  const waitOne = (stream, re, label) =>
    waitForLog(stream, re, timeoutMs).then(() => {
      log(`[probe] saw ${label}`);
    });

  const okAll = Promise.all([
    waitOne(clientLog, C2E_PING, 'ping c2e'),
    waitOne(clientLog, C2E_CURL, 'curl c2e'),
    waitOne(exitLog, E2C_PING, 'ping e2c'),
    waitOne(exitLog, E2C_CURL, 'curl e2c'),
  ]);

  await Promise.race([
    okAll,
    watchFail(clientLog, 'client'),
    watchFail(exitLog, 'exit'),
  ]);

  return { c2e: true, e2c: true };
}

/**
 * @param {{ prefix?: string, clientLog: import('stream').Readable, exitLog: import('stream').Readable }} p
 */
export async function runBidirectionalProbes(p) {
  return waitForInProcessTransportProbes(p.clientLog, p.exitLog, {
    prefix: p.prefix,
    timeoutMs: 55000,
  });
}

export { probePing, probeCurl } from './probe-external.mjs';
