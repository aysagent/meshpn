import fs from 'fs';
import path from 'path';

const REL = '.cursor/debug-7c8e2b.log';
const ENDPOINT = 'http://127.0.0.1:7709/ingest/1c653f46-f2d0-4f49-8f87-b95e3ce070bf';

/** NDJSON в cwd/.cursor/ + ingest (локальный Cursor). */
export function sessionDebugLog(entry) {
  const payload = { sessionId: '7c8e2b', timestamp: Date.now(), ...entry };
  try {
    const dir = path.join(process.cwd(), '.cursor');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(process.cwd(), REL), `${JSON.stringify(payload)}\n`);
  } catch {
    /* ignore */
  }
  fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Debug-Session-Id': '7c8e2b' },
    body: JSON.stringify(payload),
  }).catch(() => {});
}
