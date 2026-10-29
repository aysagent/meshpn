import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {createLabPKI} from '../scripts/create-vpn-lab-pki.mjs';
import {clientPKI} from './helpers/client-pki.mjs';
const root=new URL('../',import.meta.url),idf=process.env.IDF_PATH,libs=process.argv[2];
if(!idf||!libs)throw Error('Set IDF_PATH and pass host mbedTLS library directory');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-client-identity-')),pki=path.join(dir,'pki');
await createLabPKI(pki);clientPKI(pki);
const source=fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn_client_identity.c',root),'utf8');
fs.writeFileSync(path.join(dir,'client-identity-production.inc'),source.replace(/^#include .*$/gm,''));
const bin=path.join(dir,'test');
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+dir,...['tests/stubs','components/meshvpn_vpn/include'].map(p=>'-I'+new URL(p,root).pathname),
 '-I'+path.join(idf,'components/mbedtls/mbedtls/include'),new URL('tests/test_vpn_client_identity.c',root).pathname,
 ...['libmbedx509.a','libmbedcrypto.a'].map(p=>path.join(libs,p)),'-o',bin],{stdio:'inherit'});
execFileSync(bin,['client.pem','client.key','wrong.key','ca.pem','valid.pem'].map(p=>path.join(pki,p)),{stdio:'inherit'});
