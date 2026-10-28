import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root = new URL('../', import.meta.url);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-sdio-tx-'));
try {
  const original = new URL('managed_components/espressif__esp_hosted/host/drivers/transport/sdio/sdio_drv.c', root);
  const generated = path.join(dir, 'sdio.c');
  execFileSync('python3', [new URL('scripts/patch-esp-hosted-sdio.py', root).pathname, original.pathname, generated], {stdio: 'inherit'});
  const source = fs.readFileSync(generated, 'utf8');
  const cache = source.indexOf('bool meshvpn_hosted_dma_cache_snapshot(');
  const cacheEnd = source.indexOf('\n}', cache);
  if (cache < 0 || cacheEnd < cache) throw Error('DMA cache snapshot missing');
  fs.writeFileSync(path.join(dir, 'sdio-cache.inc'), source.slice(cache, cacheEnd + 2));
  const cacheBinary = path.join(dir, 'cache-test');
  execFileSync(process.env.CC || 'cc', ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-DH_USE_MEMPOOL=1',
    '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined', '-I' + dir,
    new URL('tests/test_hosted_dma_cache.c', root).pathname, '-o', cacheBinary], {stdio: 'inherit'});
  execFileSync(cacheBinary, {stdio: 'inherit'});
  const offset = source.indexOf('\nint esp_hosted_tx(');
  if (offset < 0) throw Error('Pinned SDIO TX function not found');
  fs.writeFileSync(path.join(dir, 'sdio-tx.inc'), source.slice(offset));
  const credits = source.indexOf('static int sdio_is_write_buffer_available(');
  const write = source.indexOf('static void sdio_write_task(', credits);
  if (credits < 0 || write < credits) throw Error('Pinned SDIO credit function not found');
  fs.writeFileSync(path.join(dir, 'sdio-credit.inc'), source.slice(credits, write));
  const rx = source.lastIndexOf('static void sdio_read_task(');
  const rxLoop = source.indexOf('\tfor (;;) {', rx);
  const rxEnd = source.indexOf('\n}', rxLoop);
  if (rx < 0 || rxLoop < rx || rxEnd < rxLoop) throw Error('Pinned SDIO RX loop not found');
  fs.writeFileSync(path.join(dir, 'sdio-rx-loop.inc'), source.slice(rxLoop, rxEnd));
  const binary = path.join(dir, 'test');
  execFileSync(process.env.CC || 'cc', ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined', '-I' + dir,
    new URL('tests/test_hosted_sdio_tx.c', root).pathname, '-o', binary], {stdio: 'inherit'});
  execFileSync(binary, {stdio: 'inherit'});
  const rxBinary = path.join(dir, 'rx-test');
  execFileSync(process.env.CC || 'cc', ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined', '-I' + dir,
    new URL('tests/test_hosted_sdio_rx_poll.c', root).pathname, '-o', rxBinary], {stdio: 'inherit'});
  execFileSync(rxBinary, {stdio: 'inherit'});
} finally {
  fs.rmSync(dir, {recursive: true, force: true});
}
