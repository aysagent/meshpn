import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { teardownUtunDarwin } from './net-darwin.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UTUN_HELPER_PATH = path.join(__dirname, '../../../helpers/utun-helper');

/**
 * @param {string} [_preferredName]
 * @returns {Promise<{ tun: object, name: string }>}
 */
export function openTunDarwin(_preferredName) {
  if (!fs.existsSync(UTUN_HELPER_PATH)) {
    return Promise.reject(
      new Error(`utun-helper не найден (${UTUN_HELPER_PATH}). Соберите: cd helpers && make`),
    );
  }

  return new Promise((resolve, reject) => {
    const helper = spawn(UTUN_HELPER_PATH, [], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    /** @type {string|null} */
    let ifname = null;
    /** @type {Buffer[]} */
    let stdoutChunks = [];
    let stdoutLen = 0;
    /** @type {((batch: ArrayBuffer[]) => void) | null} */
    let readCb = null;
    let closed = false;

    const flushPackets = () => {
      if (!readCb) return;
      /** @type {ArrayBuffer[]} */
      const batch = [];
      while (stdoutLen >= 4) {
        const lenBuf = Buffer.concat(stdoutChunks);
        const pktLen = lenBuf.readUInt32BE(0);
        if (pktLen <= 0 || pktLen > 65535) {
          stdoutChunks = [];
          stdoutLen = 0;
          break;
        }
        if (stdoutLen < 4 + pktLen) break;
        const frame = lenBuf.subarray(0, 4 + pktLen);
        stdoutChunks = [lenBuf.subarray(4 + pktLen)];
        stdoutLen = stdoutChunks[0]?.length ?? 0;
        batch.push(frame.subarray(4).buffer.slice(0));
      }
      if (batch.length) readCb(batch);
    };

    const fail = (err) => {
      if (closed) return;
      closed = true;
      try {
        helper.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      reject(err);
    };

    helper.stderr.on('data', (data) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        const t = line.trim();
        if (!t || t.startsWith('ERROR:') || t.startsWith('UTUN:')) continue;
        if (/^utun\d+$/.test(t) && !ifname) {
          ifname = t;
          const tun = {
            ifname,
            write(/** @type {Buffer} */ buf) {
              if (closed || !helper.stdin.writable || !buf?.length) return;
              const hdr = Buffer.allocUnsafe(4);
              hdr.writeUInt32BE(buf.length, 0);
              helper.stdin.write(Buffer.concat([hdr, buf]));
            },
            startRead(/** @type {(batch: ArrayBuffer[]) => void} */ cb) {
              readCb = cb;
              flushPackets();
            },
            close() {
              if (closed) return;
              closed = true;
              readCb = null;
              teardownUtunDarwin(ifname);
              try {
                helper.stdin.end();
              } catch {
                /* ignore */
              }
              try {
                helper.kill('SIGTERM');
              } catch {
                /* ignore */
              }
            },
          };
          resolve({ tun, name: ifname });
        }
      }
    });

    helper.stdout.on('data', (chunk) => {
      stdoutChunks.push(Buffer.from(chunk));
      stdoutLen += chunk.length;
      flushPackets();
    });

    helper.on('error', fail);

    helper.on('close', (code) => {
      if (!ifname && !closed) {
        fail(new Error(`utun-helper exited before interface name (code ${code})`));
      }
    });

    setTimeout(() => {
      if (!ifname && !closed) {
        fail(new Error('Timeout: utun-helper не вернул имя интерфейса'));
      }
    }, 5000);
  });
}

export function originalDstIpv4FromFdDarwin() {
  throw new Error(
    'SO_ORIGINAL_DST / iptables REDIRECT доступны только на Linux; на macOS используйте --tunnel-peer',
  );
}
