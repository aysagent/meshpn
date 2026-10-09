#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const script = new URL('./ipfs-incident-collector.sh', import.meta.url);
const source = readFileSync(script, 'utf8');

test('collector is a strict Bash script with a help-first argument path', () => {
  assert.match(source, /^#!\/usr\/bin\/env bash\n/);
  assert.match(source, /set -uo pipefail/);
  assert.match(source, /-h\|--help\) cv_usage; exit 0/);
});

test('help documents collection cost and evidence sensitivity', () => {
  assert.match(source, /read-only live-triage evidence/i);
  assert.match(source, /--no-deep/);
  assert.match(source, /Do not paste or upload/i);
});

test('collector explicitly avoids destructive and remote operations', () => {
  assert.doesNotMatch(source, /^\s*(?:sudo\s+)?systemctl\s+(?:start|stop|restart|enable|disable|mask|unmask)\b/m);
  assert.doesNotMatch(source, /^\s*(?:sudo\s+)?(?:rm|unlink|shred|kill|pkill|killall)\b/m);
  assert.doesNotMatch(source, /curl[^\n]+https?:\/\/(?!127\.0\.0\.1)/);
  assert.doesNotMatch(source, /\/usr\/local\/bin\/ipfs(?:\s|$).*\b(?:pin|repo|id|config|daemon)\b/m);
});

test('collector retains provenance and separates private evidence', () => {
  assert.match(source, /collector-actions\.tsv/);
  assert.match(source, /SHA256SUMS/);
  assert.match(source, /private-evidence/);
  assert.match(source, /ssh-ip-summary\.txt/);
  assert.match(source, /ipfs-repo-sha256/);
  assert.match(source, /PASTE_FOR_REVIEW/);
});
