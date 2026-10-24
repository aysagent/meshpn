import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url),dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-sdio-rx-'));
const original=new URL('managed_components/espressif__esp_hosted/host/drivers/transport/sdio/sdio_drv.c',root);
if(!fs.existsSync(original))throw Error('Resolve P4 managed components before the SDIO ownership test');
const generated=path.join(dir,'sdio.c');
execFileSync('python3',[new URL('scripts/patch-esp-hosted-sdio.py',root).pathname,original.pathname,generated],{stdio:'inherit'});
const source=fs.readFileSync(generated,'utf8');
function slice(from,to,start=0){const a=source.indexOf(from,start),b=source.indexOf(to,a);if(a<0||b<a)throw Error(from);return source.slice(a,b);}
const push=slice('static esp_err_t sdio_push_pkt_to_queue(','/**\n * These function definitions');
const stream=source.indexOf('#else // H_SDIO_HOST_STREAMING_MODE');
const rx=slice('static esp_err_t sdio_push_data_to_queue(','#endif',stream);
fs.writeFileSync(path.join(dir,'sdio-rx.inc'),push+rx);
const binary=path.join(dir,'test');
execFileSync(process.env.CC||'cc',['-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=undefined',
  '-I'+dir,new URL('tests/test_sdio_psram.c',root).pathname,'-o',binary],{stdio:'inherit'});
execFileSync(binary,{stdio:'inherit'});
