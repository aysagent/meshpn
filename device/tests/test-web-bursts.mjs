import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { cleanBursts } from '../scripts/perf-bursts.mjs';

// Compile the actual route handler with only HTTP/auth/allocation boundaries
// stubbed. Check JSON syntax/schema, ring order, fail-closed auth and PSRAM OOM.
const root=new URL('../',import.meta.url);
const source=await readFile(new URL('components/meshvpn_web/meshvpn_web.c',root),'utf8');
const start=source.indexOf('static esp_err_t handler_usb_bursts(');
const end=source.indexOf('static int64_t local_download_now',start);
assert(start>=0&&end>start);
const dir=await mkdtemp(path.join(tmpdir(),'meshpn-burst-json-'));
try {
  const harness=`
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meshvpn_usb_tx_queue.h"
typedef int httpd_req_t;
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
static unsigned allocations, fail_alloc, responses, errors;
static bool authorized=true, available=true;
static uint64_t latest;
static esp_err_t meshvpn_web_require_auth(httpd_req_t *req)
{ (void)req; return authorized?ESP_OK:ESP_FAIL; }
static void *heap_caps_malloc(size_t n,unsigned caps)
{ assert(caps==3); return ++allocations==fail_alloc?NULL:malloc(n); }
static esp_err_t error(httpd_req_t *req,const char *status,const char *msg)
{ (void)req;(void)msg;assert(!strcmp(status,"503 Service Unavailable"));errors++;return ESP_FAIL; }
static void httpd_resp_set_type(httpd_req_t *req,const char *type)
{ (void)req;assert(!strcmp(type,"application/json")); }
static esp_err_t httpd_resp_send(httpd_req_t *req,const char *buf,size_t len)
{ (void)req;assert(strlen(buf)==len);puts(buf);responses++;return ESP_OK; }
void meshvpn_usb_tx_burst_get_stats(meshvpn_usb_burst_stats_t *s)
{
    memset(s,0,sizeof(*s));s->available=available;s->session_id=123;
    s->sampled_us=UINT64_C(8000000000000);s->latest_seq=latest;s->full=latest;s->submitted=latest*2;
    for(uint64_t seq=latest>32?latest-31:1;seq<=latest;seq++) {
        meshvpn_usb_burst_record_t *r=&s->records[(seq-1)%32];
        *r=(meshvpn_usb_burst_record_t){.seq=seq,.window_us=seq*1000,.first_full_us=seq*1000+1,
            .submitted=2,.full=1,.epoch=UINT32_MAX,.in_use=8,.worker_active=true,.worker_waiting=true,
            .ncm_available=true,.ncm_free=0,.ncm_ready=5,.ncm_active=true,.ncm_glue=false,
            .ncm_sampled_us=seq*1000,.ncm_captured_us=seq*1000+2};
    }
}
${source.slice(start,end)}
int main(void) {
    httpd_req_t req=0;
    authorized=false;assert(handler_usb_bursts(&req)==ESP_FAIL && !allocations && !responses);
    authorized=true;
    for(unsigned i=1;i<=2;i++) {
        allocations=0;fail_alloc=i;assert(handler_usb_bursts(&req)==ESP_FAIL && !responses);
    }
    assert(errors==2);fail_alloc=0;
    available=false;assert(handler_usb_bursts(&req)==ESP_OK);
    available=true;assert(handler_usb_bursts(&req)==ESP_OK);
    latest=1;assert(handler_usb_bursts(&req)==ESP_OK);
    latest=39;assert(handler_usb_bursts(&req)==ESP_OK);
    assert(responses==4);return 0;
}`;
  const file=path.join(dir,'handler.c'),bin=path.join(dir,'handler');
  await writeFile(file,harness);
  execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror',
    '-I'+new URL('tests/usb_stubs/',root).pathname,
    '-I'+new URL('components/meshvpn_usb/include/',root).pathname,file,'-o',bin],{stdio:'pipe'});
  const snapshots=execFileSync(bin,{encoding:'utf8'}).trim().split('\n').map(s=>cleanBursts(JSON.parse(s)));
  assert.equal(snapshots.length,4);assert.equal(snapshots[0].available,false);
  assert.equal(snapshots[1].records.length,0);assert.equal(snapshots[2].records[0].seq,1);
  assert.equal(snapshots[3].records.length,32);assert.equal(snapshots[3].records[0].seq,8);
  assert.equal(snapshots[3].records.at(-1).seq,39);
  console.log('USB burst HTTP handler: authentication, PSRAM OOM, actual JSON schema and ring order passed');
} finally { await rm(dir,{recursive:true,force:true}); }
