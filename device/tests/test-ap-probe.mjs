import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root = new URL('../', import.meta.url), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-ap-probe-'));
try {
  const source = fs.readFileSync(new URL('components/meshvpn_net/meshvpn_ap_probe.c', root), 'utf8');
  fs.writeFileSync(path.join(dir, 'ap-probe.inc'), source.split('\n').filter(s => !s.startsWith('#include')).join('\n'));
  const binary = path.join(dir, 'test');
  execFileSync(process.env.CC || 'cc', ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined', '-I' + dir,
    '-I' + new URL('tests/usb_stubs', root).pathname, '-I' + new URL('components/meshvpn_net/include', root).pathname,
    '-I' + new URL('components/meshvpn_vpn/include', root).pathname,
    new URL('tests/test_ap_probe.c', root).pathname,
    new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c', root).pathname, '-o', binary], {stdio: 'inherit'});
  execFileSync(binary, {stdio: 'inherit'});
} finally { fs.rmSync(dir, {recursive: true, force: true}); }
