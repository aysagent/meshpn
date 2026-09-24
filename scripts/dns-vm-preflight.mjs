#!/usr/bin/env node
import { dnsVmPreflight, dnsVmPreflightOptions } from './lib/dns-vm-preflight.mjs';
const args = process.argv.slice(2);
try {
  if (args.length === 1 && args[0] === '--help') console.log('Usage: node scripts/dns-vm-preflight.mjs [--qemu=/absolute/path] [--kernel=/absolute/path] [--initrd=/absolute/path] [--disk=/absolute/path]\nMetadata-only. No download, installation, VM launch, disk writes or use of host initramfs.');
  else console.log(JSON.stringify(await dnsVmPreflight(dnsVmPreflightOptions(args)), null, 2));
} catch { console.error('DNS_VM_PREFLIGHT_REFUSED'); process.exitCode = 1; }
