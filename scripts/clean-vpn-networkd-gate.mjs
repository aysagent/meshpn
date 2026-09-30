#!/usr/bin/env node
/** Installer-internal explicit opt-in, never invoked by inspection scripts. */
import assert from 'node:assert/strict';
import { prepareNetworkdGate, assertNetworkdClientArgs } from './lib/host-networkd-gate.mjs';
assert.ok(process.argv.length >= 3);
const match = /^--prepare=([A-Za-z0-9_][A-Za-z0-9._-]*)$/.exec(process.argv[2]); assert.ok(match, 'explicit --prepare=SERVICE required');
assertNetworkdClientArgs(process.argv.slice(3));
assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0, 'root required');
console.log(JSON.stringify(prepareNetworkdGate({ service: match[1] })));
