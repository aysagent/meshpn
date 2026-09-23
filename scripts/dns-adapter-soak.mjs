#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dnsSoakMain } from './transparent-dns-soak.mjs';
import { adapterSoakOptions, assertAdapterSoakResult } from './lib/dns-adapter-soak.mjs';
import { runAdapterSoak } from './lib/dns-adapter-soak-workload.mjs';

dnsSoakMain({ parse: adapterSoakOptions, validate: assertAdapterSoakResult, run: runAdapterSoak,
  entry: fileURLToPath(import.meta.url), adapter: true,
}).catch(() => { console.error('[dns-soak] FAILED (arguments, report path or namespace)'); process.exitCode = 1; });
