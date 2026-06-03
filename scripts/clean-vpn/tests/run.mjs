#!/usr/bin/env node
/**
 * Transport smoke tests: clean-vpn client ↔ exit, TUN probes (no split-default).
 * Usage: sudo env PATH=$PATH node scripts/clean-vpn/tests/run.mjs --tier=1
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { expandCases } from './lib/matrix.mjs';
import { runCase } from './lib/harness.mjs';
import { ensureTlsFixtureDir, runPreflight, boringHelper } from './lib/preflight.mjs';
import { buildTurnIceConfig } from './lib/turn-config.mjs';
import { cleanupStaleVpnUtuns } from './lib/tun-detect.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  /** @type {Record<string, string|boolean|number>} */
  const out = {
    tier: 1,
    tierMax: null,
    variant: 'base',
    topology: 'exit-listens',
    suite: 'smoke',
    verbose: false,
    json: null,
    transport: null,
    turn: null,
    cleanupOnly: false,
  };
  for (const a of argv) {
    if (a === '--verbose') out.verbose = true;
    else if (a === '--cleanup-only') out.cleanupOnly = true;
    else if (a.startsWith('--tier=')) out.tier = parseInt(a.slice(7), 10);
    else if (a.startsWith('--tier-max=')) out.tierMax = parseInt(a.slice(11), 10);
    else if (a.startsWith('--variant=')) out.variant = a.slice(10);
    else if (a.startsWith('--topology=')) out.topology = a.slice(11);
    else if (a.startsWith('--suite=')) out.suite = a.slice(8);
    else if (a.startsWith('--json=')) out.json = a.slice(7);
    else if (a.startsWith('--transport=')) out.transport = a.slice(12);
    else if (a.startsWith('--turn=')) out.turn = a.slice(7);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.cleanupOnly) {
    if (process.platform !== 'darwin') {
      console.log('[cleanup] nothing to do (not darwin)');
      process.exit(0);
    }
    const { cleanupStaleVpnUtunsDarwin } = await import('./lib/cleanup-darwin.mjs');
    const r = cleanupStaleVpnUtunsDarwin({ verbose: true });
    if (r.ok) {
      console.log('[cleanup] OK — test utun removed');
      process.exit(0);
    }
    console.error(`[cleanup] incomplete — still: ${r.remaining.join(', ') || '(none named)'}`);
    console.error('[cleanup] try: sudo pgrep -lf utun-helper; sudo pgrep -lf clean-vpn.js');
    process.exit(1);
  }

  const skipTier3 = process.env.SKIP_TIER3 === '1';

  if (args.turn) {
    const cfg = buildTurnIceConfig(String(args.turn));
    fs.mkdirSync(path.join(__dirname, 'config'), { recursive: true });
    fs.writeFileSync(
      path.join(__dirname, 'config/test-ice-relay.json'),
      `${JSON.stringify(cfg, null, 2)}\n`,
    );
  }

  const pre = await runPreflight({
    skipTier3,
    turn: args.turn ? String(args.turn) : null,
  });
  for (const w of pre.warnings) console.warn(`[preflight] ${w}`);
  if (!pre.ok) {
    console.error('[preflight] failed:', pre.errors.join('; '));
    process.exit(2);
  }

  const tlsDir = ensureTlsFixtureDir();
  const tierMax = args.tierMax ?? args.tier;
  const cases = expandCases({
    tlsDir,
    tierMax,
    transport: args.transport ? String(args.transport) : undefined,
    variant: String(args.variant),
    topology: String(args.topology),
    suite: String(args.suite),
    turn: args.turn ? String(args.turn) : null,
    skipTier3,
    boringHelper: pre.boringHelperExists,
  }).filter((c) => c.tier >= args.tier && c.tier <= tierMax);

  console.log(`[clean-vpn-transport-test] ${cases.length} case(s), platform=${process.platform}`);

  cleanupStaleVpnUtuns({ verbose: Boolean(args.verbose) });

  /** @type {unknown[]} */
  const results = [];
  let failed = 0;
  let skipped = 0;

  for (const c of cases) {
    process.stdout.write(`\n=== ${c.id} (tier ${c.tier}) ===\n`);
    const r = await runCase(c, {
      verbose: Boolean(args.verbose),
      keepAlive: args.suite === 'keep-alive',
    });
    results.push(r);
    if (r.skipped) {
      skipped += 1;
      console.log(`SKIP ${c.id}: ${r.skipReason}`);
    } else if (r.error) {
      failed += 1;
      console.error(`FAIL ${c.id}: ${r.error}`);
    } else {
      console.log(`PASS ${c.id} (${r.durationMs}ms) tun ${r.clientTun} ↔ ${r.exitTun}`);
    }
  }

  const summary = { failed, skipped, passed: results.length - failed - skipped, results };
  console.log('\n--- summary ---', summary.failed ? 'FAILED' : 'OK', summary);

  if (args.json) {
    fs.writeFileSync(String(args.json), `${JSON.stringify(summary, null, 2)}\n`);
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
