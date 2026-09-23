#!/usr/bin/env node
/** One bounded acceptance command; fixed local suites, no installation or deployment. */
import { open, mkdtemp } from 'node:fs/promises';
import { tmpdir, release } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TEST_FILES, parseOptions, cleanEnvironment, runCommand, resultLines,
  nodeSummary, browserSummary, repeatMatrix } from './lib/transparent-acceptance.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const options = parseOptions(process.argv.slice(2));
if (options.help) {
  console.log(`Usage: node scripts/transparent-acceptance.mjs [--suite=full|node] [--repeat=1..3] [--report=/new/path.json]
Default: full Node + Chrome + Firefox matrix once. No skips, retries-to-green or downloads.
Node-only is explicitly partial acceptance. Existing report files are never overwritten.
Report defaults to a private meshpn-acceptance-* directory under the OS temp directory.
Requires Linux, Node 22+, Go 1.24+, OpenSSL 3, stdbuf; full also requires browser lab tools.
MESHPN_ECH_GO, MESHPN_BROWSER_CHROME, MESHPN_BROWSER_FIREFOX, MESHPN_CERTUTIL,
MESHPN_TSHARK, MESHPN_TCPDUMP select the same tools as the underlying tests.`);
} else {
  const path = options.report ? resolve(options.report) : join(await mkdtemp(join(tmpdir(), 'meshpn-acceptance-')), 'report.json');
  // Reserve before executing anything; refuse symlinks/existing files as well.
  const reportFile = await open(path, 'wx', 0o600);
  const report = { schema: 1, suite: options.suite, requestedRepeats: options.repeat, fullAcceptance: false,
    startedAt: new Date().toISOString(), status: 'failed', platform: { os: process.platform, arch: process.arch, kernel: release() },
    runtime: { node: process.version, embeddedOpenSSL: process.versions.openssl },
    repository: {}, tools: {}, results: [], limitations: ['loopback-only', 'not-production-certification', 'not-long-duration-soak'] };
  const controller = new AbortController(), abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const env = cleanEnvironment(process.env);
  const run = (file, args, extra) => runCommand(file, args, { cwd: root, env, signal: controller.signal, ...extra });
  console.log(`[acceptance] ${options.suite}, repeat=${options.repeat}; report=${path}`);
  try {
    if (process.platform !== 'linux' || Number(process.versions.node.split('.')[0]) < 22) throw new Error('Linux and Node 22+ required');
    const git = await run('git', ['rev-parse', 'HEAD']);
    const dirty = await run('git', ['status', '--porcelain'], { maxBytes: 256 * 1024 });
    if (git.code !== 0 || git.reason || dirty.code !== 0 || dirty.reason) throw new Error('repository provenance unavailable');
    report.repository = { revision: git.stdout.trim(), dirty: Boolean(dirty.stdout.trim()), testFiles: TEST_FILES };
    const probes = [
      ['go', env.MESHPN_ECH_GO || 'go', ['version'], /^go version go1\.(?:2[4-9]|[3-9]\d)\./],
      ['openssl', 'openssl', ['version'], /^OpenSSL 3\./],
      ['stdbuf', 'stdbuf', ['--version'], /GNU coreutils/],
    ];
    if (options.suite === 'full') probes.push(
      ['chrome', env.MESHPN_BROWSER_CHROME, ['--version'], /(?:Chrome|Chromium)/],
      ['firefox', env.MESHPN_BROWSER_FIREFOX, ['--version'], /Firefox/],
      ['certutil', env.MESHPN_CERTUTIL || 'certutil', ['-H'], /Add a certificate to the database/],
      ['tcpdump', env.MESHPN_TCPDUMP || 'tcpdump', ['--version'], /tcpdump version/],
      ['tshark', env.MESHPN_TSHARK || 'tshark', ['--version'], /TShark \(Wireshark\)/],
      ['unshare', 'unshare', ['--version'], /util-linux/], ['mount', 'mount', ['--version'], /util-linux/],
      ['ip', 'ip', ['-Version'], /iproute2/],
    );
    for (const [name, executable, args, match] of probes) {
      if (!executable) { report.tools[name] = { status: 'missing' }; throw new Error(`missing ${name} executable setting`); }
      const result = await run(executable, args);
      const output = result.stdout + result.stderr;
      const available = !result.reason && (result.code === 0 || (name === 'certutil' && result.code === 1)) && match.test(output);
      report.tools[name] = { status: available ? 'available' : 'failed', executable,
        version: available && name !== 'certutil' ? output.split('\n').find((line) => match.test(line))?.slice(0, 256) : null,
        ...(name === 'certutil' ? { note: 'No version flag; NSS certutil -H capability check only' } : {}) };
      if (!available) throw new Error(`preflight failed: ${name} (${result.reason ?? result.code})`);
    }
    const matrix = await repeatMatrix(options, async (stage) => {
      console.log(`[acceptance] starting ${stage}`);
      const result = stage === 'node'
        ? await run(process.execPath, ['--test', '--test-reporter=./scripts/lib/acceptance-reporter.mjs',
          ...TEST_FILES.map((file) => `scripts/${file}`)], { timeoutMs: 180_000, maxBytes: 4 * 1024 * 1024 })
        : await run(process.execPath, ['scripts/transparent-browser-lab.mjs'], { timeoutMs: 240_000, maxBytes: 4 * 1024 * 1024 });
      const record = { status: result.reason === 'aborted' ? 'aborted' : 'failed', exitCode: result.code,
        signal: result.signal, durationMs: result.durationMs, reason: result.reason };
      try {
        if (stage === 'node') {
          // Retain structured diagnostics even on a failing suite, never raw process output.
          const rows = resultLines(result.stdout, 'NODE_RESULT');
          if (rows.length === 1) record.summary = rows[0];
          nodeSummary(result.stdout);
        } else {
          record.scenarios = resultLines(result.stdout, 'BROWSER_RESULT');
          browserSummary(result.stdout);
        }
        if (result.code === 0 && !result.reason && !result.signal) record.status = 'passed';
        else record.reason ??= 'nonzero-exit';
      } catch { record.reason ??= `incomplete-or-failed-${stage}-results`; }
      return record;
    }, controller.signal, (result) => console.log(`[acceptance] ${result.iteration}/${options.repeat} ${result.stage}: ${result.status}`));
    report.results = matrix.results; report.status = matrix.status;
    report.fullAcceptance = options.suite === 'full' && report.status === 'passed';
  } catch (error) {
    report.status = controller.signal.aborted ? 'aborted' : 'failed';
    report.error = String(error.message).slice(0, 256);
  } finally {
    if (controller.signal.aborted) { report.status = 'aborted'; report.fullAcceptance = false; }
    report.finishedAt = new Date().toISOString();
    try { await reportFile.writeFile(`${JSON.stringify(report, null, 2)}\n`); }
    finally { await reportFile.close(); process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
  }
  console.log(`[acceptance] ${report.status.toUpperCase()} ${report.fullAcceptance ? 'full acceptance' : 'NOT full acceptance'}; report=${path}`);
  process.exitCode = report.status === 'passed' ? 0 : 1;
}
