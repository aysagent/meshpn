/** Consume documented test events, not the version-dependent human TAP/spec output. */
import { basename } from 'node:path';

export default async function* reporter(events) {
  const counts = { tests: 0, passed: 0, failed: 0, skipped: 0, todo: 0 };
  const files = new Set(), failures = [];
  for await (const { type, data } of events) {
    if (type !== 'test:pass' && type !== 'test:fail') continue;
    if (data.file) files.add(basename(data.file));
    const flagged = (value) => value !== undefined && value !== false;
    if (flagged(data.skip)) counts.skipped++;
    if (flagged(data.todo)) counts.todo++;
    if (data.details?.type === 'suite') continue;
    counts.tests++;
    if (type === 'test:pass') counts.passed++;
    else {
      counts.failed++;
      if (failures.length < 64) failures.push({ file: basename(data.file ?? 'unknown'), name: String(data.name).slice(0, 256) });
    }
    // Deliberately omit stdout, stderr, error objects, TLS/session bytes and stacks.
  }
  yield `NODE_RESULT ${JSON.stringify({ schema: 1, counts, files: [...files].sort(), failures })}\n`;
}
