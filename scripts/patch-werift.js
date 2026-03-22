#!/usr/bin/env node
/**
 * Patch werift-sctp SCTP constants for better throughput.
 *
 * Usage:
 *   node scripts/patch-werift.js          # apply patch
 *   node scripts/patch-werift.js --revert # restore originals
 *   node scripts/patch-werift.js --status # show current values
 *
 * After patching, re-run tests on BOTH server and client:
 *   node scripts/stepwise-test.js server --step 1
 *   node scripts/stepwise-test.js client <ip> --step 1
 *   node scripts/stepwise-test.js server --step 7
 *   node scripts/stepwise-test.js client <ip> --step 7
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCTP_FILE = path.join(__dirname, '..', 'node_modules', 'werift-sctp', 'lib', 'sctp', 'src', 'sctp.js');

const PATCHES = [
  {
    name: 'USERDATA_MAX_LENGTH',
    original: 'const USERDATA_MAX_LENGTH = 1200;',
    patched:  'const USERDATA_MAX_LENGTH = 8000;',
  },
  {
    name: 'SCTP_SACK_DELAY_MS',
    original: 'const SCTP_SACK_DELAY_MS = 200;',
    patched:  'const SCTP_SACK_DELAY_MS = 10;',
  },
  {
    name: 'SCTP_RTO_INITIAL',
    original: 'const SCTP_RTO_INITIAL = 3;',
    patched:  'const SCTP_RTO_INITIAL = 1;',
  },
  {
    name: 'advertisedRwnd (receiver window)',
    original: 'value: 1024 * 1024',
    patched:  'value: 4 * 1024 * 1024',
    context: 'advertisedRwnd',
  },
];

function readFile() {
  if (!fs.existsSync(SCTP_FILE)) {
    console.error(`File not found: ${SCTP_FILE}`);
    console.error('Run npm install first.');
    process.exit(1);
  }
  return fs.readFileSync(SCTP_FILE, 'utf8');
}

function showStatus() {
  const content = readFile();
  console.log('\n=== werift-sctp SCTP constants ===\n');
  for (const p of PATCHES) {
    const hasOriginal = content.includes(p.original);
    const hasPatched = content.includes(p.patched);
    const status = hasPatched ? 'PATCHED' : hasOriginal ? 'ORIGINAL' : 'UNKNOWN';
    console.log(`  ${p.name}: ${status}`);
    if (hasPatched) console.log(`    -> ${p.patched}`);
    else if (hasOriginal) console.log(`    -> ${p.original}`);
  }
  console.log('');
}

function applyPatch() {
  let content = readFile();
  let applied = 0;

  for (const p of PATCHES) {
    if (content.includes(p.patched)) {
      console.log(`  ${p.name}: already patched, skipping`);
      continue;
    }
    if (!content.includes(p.original)) {
      console.warn(`  ${p.name}: original pattern not found, skipping`);
      continue;
    }

    if (p.context) {
      const idx = content.indexOf(p.context);
      const searchStart = Math.max(0, idx - 200);
      const searchEnd = Math.min(content.length, idx + 200);
      const region = content.substring(searchStart, searchEnd);
      if (region.includes(p.original)) {
        content = content.substring(0, searchStart) +
          region.replace(p.original, p.patched) +
          content.substring(searchEnd);
        console.log(`  ${p.name}: ${p.original} -> ${p.patched}`);
        applied++;
      } else {
        console.warn(`  ${p.name}: pattern not found near context '${p.context}'`);
      }
    } else {
      content = content.replace(p.original, p.patched);
      console.log(`  ${p.name}: ${p.original} -> ${p.patched}`);
      applied++;
    }
  }

  if (applied > 0) {
    fs.writeFileSync(SCTP_FILE, content);
    console.log(`\nPatched ${applied} value(s). Remember to patch on BOTH server and client!`);
  } else {
    console.log('\nNothing to patch.');
  }
}

function revert() {
  let content = readFile();
  let reverted = 0;

  for (const p of PATCHES) {
    if (content.includes(p.original)) {
      console.log(`  ${p.name}: already original, skipping`);
      continue;
    }
    if (!content.includes(p.patched)) {
      console.warn(`  ${p.name}: patched pattern not found, skipping`);
      continue;
    }

    if (p.context) {
      const idx = content.indexOf(p.context);
      const searchStart = Math.max(0, idx - 200);
      const searchEnd = Math.min(content.length, idx + 200);
      const region = content.substring(searchStart, searchEnd);
      if (region.includes(p.patched)) {
        content = content.substring(0, searchStart) +
          region.replace(p.patched, p.original) +
          content.substring(searchEnd);
        console.log(`  ${p.name}: ${p.patched} -> ${p.original}`);
        reverted++;
      }
    } else {
      content = content.replace(p.patched, p.original);
      console.log(`  ${p.name}: ${p.patched} -> ${p.original}`);
      reverted++;
    }
  }

  if (reverted > 0) {
    fs.writeFileSync(SCTP_FILE, content);
    console.log(`\nReverted ${reverted} value(s).`);
  } else {
    console.log('\nNothing to revert.');
  }
}

const cmd = process.argv[2];

if (cmd === '--status') {
  showStatus();
} else if (cmd === '--revert') {
  console.log('\nReverting werift-sctp patches...\n');
  revert();
  showStatus();
} else {
  console.log('\nApplying werift-sctp patches for throughput...\n');
  applyPatch();
  showStatus();
}
