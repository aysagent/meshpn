#!/usr/bin/env node
/** Local capture page; an operator supplies metadata and an already trusted cert. */
import fs from 'node:fs';
import { startBrowserCapture } from './lib/native-browser-capture-server.mjs';

export function readCaptureFile(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > limit) throw Error('capture_file');
    const bytes = Buffer.alloc(limit + 1); let count = 0, n;
    while ((n = fs.readSync(fd, bytes, count, bytes.length - count, null)) > 0) {
      count += n; if (count > limit) throw Error('capture_file_limit');
    }
    return bytes.subarray(0, count);
  } finally { fs.closeSync(fd); }
}

export async function main(args) {
  if (args.length !== 3) throw Error('usage');
  const [metadata, cert, key] = args;
  const server = await startBrowserCapture({ metadata: JSON.parse(readCaptureFile(metadata, 8192)),
    cert: readCaptureFile(cert, 65536), key: readCaptureFile(key, 65536) });
  console.log(JSON.stringify({ mode: 'loopback-only', url: server.url, bundleUrl: server.bundleUrl,
    expiresSeconds: 180, systemSettingsChanged: false, note: 'Download bundle before expiry; memory only; no profile activation.' }));
  const stop = () => { void server.close(); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  return server;
}

import { pathToFileURL } from 'node:url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(() => {
    console.error('Usage: node scripts/clean-vpn-native-browser-capture.mjs METADATA.json CERT.pem KEY.pem (bounded regular files; localhost certificate required)');
    process.exitCode = 1;
  });
}
