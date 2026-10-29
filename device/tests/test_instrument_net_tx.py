import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('txpatch', root / 'scripts/instrument-net-tx.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
idf = Path(os.environ.get('IDF_PATH', Path.home() / 'esp/esp-idf-meshpn-v5.5.5'))
wlanif = (idf / 'components/esp_netif/lwip/netif/wlanif.c').read_text()
sockets = (idf / 'components/lwip/lwip/src/api/sockets.c').read_text()


class Tests(unittest.TestCase):
    def test_guards(self):
        for kind, source in [('wlanif', wlanif), ('sockets', sockets)]:
            with self.assertRaises(ValueError): m.patch('', kind)
            with self.assertRaises(ValueError): m.patch(m.patch(source, kind), kind)

    def test_failure_hooks_keep_ownership_and_returns(self):
        text = m.patch(wlanif, 'wlanif')
        begin = text.index('static err_t low_level_output(')
        end = text.index('\n}', begin) + 2
        code = r'''
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#define ERR_OK 0
#define ERR_MEM -1
#define ERR_BUF -2
#define ERR_ARG -3
#define ERR_IF -4
#define ESP_OK 0
#define ESP_FAIL 1
#define ESP_ERR_NO_MEM 2
#define ESP_ERR_ESP_NETIF_TX_FAILED 3
#define ESP_ERR_INVALID_ARG 4
#define LWIP_DEBUGF(a,b) ((void)0)
#define PBUF_RAW_TX 0
#define PBUF_RAM 0
typedef int err_t;
typedef int esp_err_t;
typedef int esp_netif_t;
struct pbuf { struct pbuf *next; void *payload; unsigned len,tot_len; };
struct netif { char name[2]; esp_netif_t *state; };
static bool oom;
static unsigned events[5][3], frees, sends, copies;
static int driver_error;
static struct pbuf scratch;
static void meshvpn_tx_failure(unsigned stage,unsigned ifx,unsigned size,int error) {
 assert(size==1200 && error);events[stage][ifx]++;
}
static struct pbuf *pbuf_alloc(int layer,unsigned len,int type) {
 assert(!layer && !type && len==1200);scratch.len=len;return oom?NULL:&scratch;
}
static void pbuf_copy(struct pbuf *q,struct pbuf *p) {assert(q==&scratch && p!=q);copies++;}
static void pbuf_free(struct pbuf *q) {assert(q==&scratch);frees++;}
static int esp_netif_transmit_wrap(esp_netif_t *n,void *payload,unsigned len,struct pbuf *q) {
 (void)payload;assert(n && len==1200 && q);sends++;return driver_error;
}
'''+text[begin:end]+r'''
int main(void) {
 esp_netif_t state=0;struct netif n={{'s','t'},&state};struct pbuf p={.len=1200,.tot_len=1200};
 assert(low_level_output(&n,&p)==ERR_OK && sends==1 && !frees);
 driver_error=ESP_ERR_NO_MEM;
 assert(low_level_output(&n,&p)==ERR_MEM && events[2][0]==1 && !frees);
 driver_error=ESP_ERR_ESP_NETIF_TX_FAILED;n.name[0]='a';n.name[1]='p';
 p.next=&scratch;
 assert(low_level_output(&n,&p)==ERR_BUF && events[3][1]==1 && frees==1 && copies==1);
 oom=true;
 assert(low_level_output(&n,&p)==ERR_MEM && events[1][1]==1 && frees==1 && sends==3);
 n.state=NULL;
 assert(low_level_output(&n,&p)==ERR_IF && sends==3);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'test.c'; p.write_text(code)
            binary = str(Path(d)/'test')
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p), '-o', binary], check=True)
            subprocess.run([binary], check=True)

    def test_socket_only_allocation_failure(self):
        patched = m.patch(sockets, 'sockets')
        self.assertEqual(patched.count('meshvpn_tx_failure(0, 2, short_size, ERR_MEM);'), 1)
        # Removing the failure-only addition must recover the exact pinned source.
        restored = patched.split('\n', 1)[1].replace('    meshvpn_tx_failure(0, 2, short_size, ERR_MEM);\n', '')
        self.assertEqual(restored, sockets)


if __name__ == '__main__': unittest.main()
