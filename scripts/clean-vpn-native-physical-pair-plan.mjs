#!/usr/bin/env node
import { collectNativePhysicalPairPlan, parseNativePhysicalPairArgs } from './lib/native-physical-pair-plan.mjs';

try {
  const options = parseNativePhysicalPairArgs(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: node scripts/clean-vpn-native-physical-pair-plan.mjs --client=/absolute/client-preflight.txt --exit=/absolute/exit-preflight.txt\nOffline composition of two fresh native combo physical preflights. Accepts raw JSON or the exact BEGIN/END wrapper. No commands, probes or system changes.');
  } else {
    const report = collectNativePhysicalPairPlan(options);
    console.log('=== CLEAN-VPN NATIVE PHYSICAL PAIR PLAN BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN NATIVE PHYSICAL PAIR PLAN END ===');
    if (report.status !== 'ready-for-human-approved-transient-design') process.exitCode = 1;
  }
} catch (error) {
  const safe = /^[a-z0-9 _-]+$/.test(error?.message ?? '') ? error.message.replaceAll(' ', '_') : 'invalid_reports_or_arguments';
  console.error(`NATIVE_PHYSICAL_PAIR_PLAN_FAILED: ${safe}; see --help. No settings changed.`);
  process.exitCode = 1;
}
