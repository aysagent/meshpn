import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
const idf = process.env.IDF_PATH;
if (!idf) throw Error('Set IDF_PATH for the real lwIP checksum helper');
const source = fs.readFileSync(path.join(idf,'components/lwip/lwip/src/core/ipv4/ip4_napt.c'),'utf8');
const a = source.indexOf('static void\nchecksumadjust('), b = source.indexOf('static void\nip_napt_send_rst(',a);
if (a < 0 || b < a) throw Error('Upstream NAPT checksum helper changed');
const dir = fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-napt-icmp-'));
fs.writeFileSync(path.join(dir,'napt-checksum.inc'),source.slice(a,b));
const root = new URL('../',import.meta.url), file = new URL('tests/test_napt_icmp.c',root).pathname;
const binary = path.join(dir,'test');
execFileSync(process.env.CC || 'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=undefined',
  '-I'+dir,'-I'+new URL('components/meshvpn_vpn/include',root).pathname,file,
  new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,'-o',binary],{stdio:'inherit'});
execFileSync(binary,{stdio:'inherit'});
