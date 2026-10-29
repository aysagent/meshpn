import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const source = fs.readFileSync(new URL('../components/meshvpn_net/meshvpn_net.c', import.meta.url), 'utf8');
const start = source.indexOf('#if CONFIG_IDF_TARGET_ESP32P4\n    /* ESP-IoT-Bridge');
const end = source.indexOf('#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_USB)', start);
if (start < 0 || end < start) throw Error('Production radio initialization not found');
const startup = source.match(/#if [^\n]+\n    err = esp_wifi_start\(\);\n    if \(err != ESP_OK\) return err;\n#endif/);
if (!startup) throw Error('Production Wi-Fi start block not found');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-p4-mode-'));
try {
  const code = `
#include <assert.h>
#include <stdio.h>
#define CONFIG_IDF_TARGET_ESP32P4 1
#define ESP_OK 0
#define ESP_ERR_NO_MEM 1
#define WIFI_STORAGE_RAM 1
#define WIFI_MODE_STA 1
#define WIFI_MODE_APSTA 3
#define WIFI_INIT_CONFIG_DEFAULT() 0
typedef int wifi_init_config_t;
typedef int esp_err_t;
static int sta, ap, ap_calls, mode, storage, fail_ap, starts, start_error;
static int *s_sta_netif, *s_ap_netif;
static int esp_wifi_init(wifi_init_config_t *c) { (void)c; return 0; }
static int esp_wifi_set_storage(int value) { storage=value; return 0; }
static int *esp_netif_create_default_wifi_sta(void) { return &sta; }
static int *esp_netif_create_default_wifi_ap(void) { ap_calls++; return fail_ap ? NULL : &ap; }
static int esp_wifi_set_mode(int value) { mode=value; return 0; }
static int esp_wifi_start(void) { starts++; return start_error; }
static int initialize(void) {
${source.slice(start, end)}
${startup[0]}
return ESP_OK; }
int main(void) {
 assert(initialize()==ESP_OK && s_sta_netif==&sta && storage==WIFI_STORAGE_RAM && starts==1);
#ifdef CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP
 assert(mode==WIFI_MODE_APSTA && ap_calls==1 && s_ap_netif==&ap);
 mode=0; fail_ap=1; assert(initialize()==ESP_ERR_NO_MEM && mode==0);
#else
 assert(mode==WIFI_MODE_STA && ap_calls==0 && s_ap_netif==NULL);
#endif
 fail_ap=0; start_error=42; assert(initialize()==42 && starts==2);
 puts("P4 radio mode follows AP-enabled/disabled build configuration");
}
`;
  const file = path.join(dir, 'test.c'); fs.writeFileSync(file, code);
  for (const enabled of [false, true]) {
    const binary = path.join(dir, String(enabled));
    execFileSync(process.env.CC || 'cc', ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
      '-fsanitize=address,undefined', ...(enabled ? ['-DCONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP=1'] : []),
      file, '-o', binary], {stdio:'inherit'});
    execFileSync(binary, [], {stdio:'inherit'});
  }
} finally { fs.rmSync(dir, {recursive:true, force:true}); }
