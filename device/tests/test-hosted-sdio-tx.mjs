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
  const offset = source.indexOf('\nint esp_hosted_tx(');
  if (offset < 0) throw Error('Pinned SDIO TX function not found');
  fs.writeFileSync(path.join(dir, 'sdio-tx.inc'), source.slice(offset));
  const credits = source.indexOf('static int sdio_is_write_buffer_available(');
  const write = source.indexOf('static void sdio_write_task(', credits);
  if (credits < 0 || write < credits) throw Error('Pinned SDIO credit function not found');
  fs.writeFileSync(path.join(dir, 'sdio-credit.inc'), source.slice(credits, write));
  const binary = path.join(dir, 'test');
  execFileSync(process.env.CC || 'cc', ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined', '-I' + dir,
    new URL('tests/test_hosted_sdio_tx.c', root).pathname, '-o', binary], {stdio: 'inherit'});
  execFileSync(binary, {stdio: 'inherit'});
} finally {
  fs.rmSync(dir, {recursive: true, force: true});
}
