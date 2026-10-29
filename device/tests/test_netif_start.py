"""Execute the patched SDK start callback with a small lwIP lifecycle model."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patch_netif', ROOT / 'scripts/patch-netif-start.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class StartTests(unittest.TestCase):
    def test_source_drift(self):
        with self.assertRaises(ValueError):
            m.patch('unknown sdk')

    def test_duplicate_disconnected_start_and_real_restart(self):
        idf = Path(os.environ.get('IDF_PATH', str(Path.home() / 'esp/esp-idf-meshpn-v5.5.5')))
        source = (idf / 'components/esp_netif/lwip/esp_netif_lwip.c').read_text()
        source = m.patch(source)
        with self.assertRaises(ValueError):
            m.patch(source)
        callback = source.split('static esp_err_t esp_netif_start_api(esp_netif_api_msg_t *msg)\n{', 1)[1].split('\nesp_err_t esp_netif_start(', 1)[0]
        callback = 'static esp_err_t esp_netif_start_api(esp_netif_api_msg_t *msg)\n{' + callback
        up = source.split('static esp_err_t esp_netif_up_api(esp_netif_api_msg_t *msg)\n{', 1)[1].split('\nesp_err_t esp_netif_up(', 1)[0]
        callback += 'static esp_err_t esp_netif_up_api(esp_netif_api_msg_t *msg)\n{' + up
        harness = r'''
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#define CONFIG_LWIP_IPV4 1
#define ESP_OK 0
#define ESP_ERR_NOT_SUPPORTED -1
#define ESP_ERR_INVALID_STATE -2
#define ESP_NETIF_FLAG_GARP 1
#define ESP_NETIF_FLAG_AUTOUP 2
#define ESP_NETIF_DHCP_SERVER 4
#define ESP_NETIF_DHCP_CLIENT 8
#define ESP_NETIF_DHCP_STOPPED 0
#define ESP_NETIF_STARTED 1
#define ESP_NETIF_IS_POINT2POINT_TYPE(a,b) 0
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_ERROR_CHECK(x) assert((x)==ESP_OK)
#define LOG_NETIF_DISABLED_AND_DO(name, action) do { action; } while(0)
typedef int esp_err_t;
struct netif {struct netif *next; int up, igmp;};
static struct netif *netif_list;
typedef int ip4_addr_t;
typedef struct {int ip,netmask,gw;} ip_info_t;
typedef struct {struct netif *lwip_netif; unsigned flags; int dhcpc_status; const char *if_key; ip_info_t *ip_info;} esp_netif_t;
typedef struct {esp_netif_t *esp_netif;} esp_netif_api_msg_t;
static int adds, routes;
static int esp_netif_config_sanity_check(esp_netif_t *n) {return n ? 0 : -1;}
static int esp_netif_lwip_add(esp_netif_t *n) {
  for(struct netif *p=netif_list;p;p=p->next) assert(p!=n->lwip_netif);
  n->lwip_netif->next=netif_list;netif_list=n->lwip_netif;n->lwip_netif->igmp=1;adds++;return 0;
}
static void netif_set_addr(struct netif *n,ip4_addr_t *ip,ip4_addr_t *mask,ip4_addr_t *gw)
{assert(n->igmp);(void)ip;(void)mask;(void)gw;}
static void netif_set_up(struct netif *n) {n->up=1;}
static void netif_set_link_up(struct netif *n) {(void)n;}
static void esp_netif_update_default_netif(esp_netif_t *n,int action) {(void)n;(void)action;routes++;}
'''
        main = r'''
int main(void) {
 struct netif sta={0},ap={0};
 ip_info_t ip={0};
 esp_netif_t s={&sta,ESP_NETIF_DHCP_CLIENT,1,"WIFI_STA_DEF",&ip},a={&ap,ESP_NETIF_FLAG_AUTOUP,0,"AP",&ip};
 esp_netif_api_msg_t sm={&s},am={&a};
 assert(esp_netif_start_api(&sm)==0 && adds==1 && !sta.up);
 assert(esp_netif_start_api(&am)==0 && adds==2 && ap.up && routes==1);
 assert(esp_netif_start_api(&sm)==0 && adds==2 && !sta.up && routes==1);
 sta.up=1;
 assert(esp_netif_start_api(&sm)==0 && adds==2 && routes==1);
 assert(esp_netif_start_api(&am)==0 && adds==2 && routes==1);
 // STOP removes STA from the list; the allocated pointer remains for restart.
 ap.next=0;sta.next=0;sta.up=0;
 assert(esp_netif_start_api(&sm)==0 && adds==3 && !sta.up);
 assert(esp_netif_start_api(&sm)==0 && adds==3);
 // Observed Hosted STOP -> CONNECTED without START. Must restore list/IGMP
 // before netif_set_addr/up; never reset an already registered interface.
 netif_list=&ap;ap.next=0;sta.next=0;sta.up=0;sta.igmp=0;
 assert(esp_netif_up_api(&sm)==0 && adds==4 && sta.up && sta.igmp && netif_list==&sta);
 assert(esp_netif_up_api(&sm)==0 && adds==4);
 assert(esp_netif_start_api(&sm)==0 && adds==4);
 assert(esp_netif_up_api(&am)==0 && adds==4);
 esp_netif_api_msg_t invalid={0};assert(esp_netif_up_api(&invalid)==ESP_ERR_INVALID_STATE);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'test.c'; binary=Path(tmp)/'test'
            src.write_text(harness+callback+main)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(src),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

if __name__ == '__main__':
    unittest.main()
