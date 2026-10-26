import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('rxpatch', root / 'scripts/instrument-wifi-rx.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
idf = Path(os.environ.get('IDF_PATH', Path.home() / 'esp/esp-idf-meshpn-v5.5.5'))
source = (idf / 'components/esp_netif/lwip/netif/wlanif.c').read_text()


class Tests(unittest.TestCase):
    def test_version_guard(self):
        with self.assertRaises(ValueError):
            m.patch(source.replace('pbuf_free(p);', 'changed_free(p);'))

    def test_real_receive_ownership_and_diagnostics(self):
        text = m.patch(source)
        start = text.index('esp_netif_recv_ret_t wlanif_input(')
        brace = text.index('{', start)
        depth, end = 1, brace + 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        body = text[start:end]
        stub = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define unlikely(x) (x)
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM -2
#define ERR_OK 0
#define NETIF_DEBUG 0
#define LWIP_DEBUGF(a,b) ((void)0)
#define PBUF_RAW 0
#define PBUF_RAM 0
#if RETURN_ERRORS
typedef int esp_netif_recv_ret_t;
#define ESP_NETIF_OPTIONAL_RETURN_CODE(x) (x)
#else
typedef void esp_netif_recv_ret_t;
#define ESP_NETIF_OPTIONAL_RETURN_CODE(x)
#endif
typedef struct {int unused;} esp_netif_t;
struct pbuf {void *payload,*eb;};
struct netif {char name[2];void *state;bool up;int(*input)(struct pbuf*,struct netif*);};
static unsigned counts[2][5],frees,live;
static bool oom,reject;
static struct pbuf *held;
static bool netif_is_up(struct netif *n){return n->up;}
static void meshvpn_hosted_rx_netif(unsigned ifx,unsigned stage,unsigned bytes)
{assert(bytes==32);if(ifx<2)counts[ifx][stage]++;}
static void esp_netif_free_rx_buffer(esp_netif_t *n,void *eb){assert(n&&eb);frees++;}
#ifdef CONFIG_LWIP_L2_TO_L3_COPY
static struct pbuf *pbuf_alloc(int layer,size_t len,int type)
{assert(layer==0&&type==0&&len==32);if(oom)return NULL;struct pbuf*p=calloc(1,sizeof(*p));assert(p);p->payload=malloc(len);assert(p->payload);live++;return p;}
#else
static struct pbuf *esp_pbuf_allocate(esp_netif_t *n,void *buffer,size_t len,void *eb)
{assert(n&&buffer&&len==32);if(oom)return NULL;struct pbuf*p=calloc(1,sizeof(*p));assert(p);p->payload=buffer;p->eb=eb;live++;return p;}
#endif
static void pbuf_free(struct pbuf*p){assert(p&&live);if(p->eb)frees++;else free(p->payload);free(p);live--;}
static int input(struct pbuf*p,struct netif*n){assert(n);if(reject)return -1;held=p;return 0;}
'''
        main = r'''
static void run(struct netif *n,void *buffer,void *eb,int expected){
#if RETURN_ERRORS
 assert(wlanif_input(n,buffer,32,eb)==expected);
#else
 (void)expected;wlanif_input(n,buffer,32,eb);
#endif
}
int main(void){
 char packet[32]={0};esp_netif_t state;struct netif n={{'s','t'},&state,true,input};
 run(&n,packet,packet,ESP_OK);assert(counts[0][0]==1&&counts[0][4]==1&&held);pbuf_free(held);assert(frees==1&&!live);
 memset(counts,0,sizeof(counts));frees=0;reject=true;
 run(&n,packet,packet,ESP_FAIL);assert(counts[0][0]==1&&counts[0][3]==1&&frees==1&&!live);reject=false;
 memset(counts,0,sizeof(counts));frees=0;oom=true;n.name[0]='a';n.name[1]='p';
 run(&n,packet,packet,ESP_ERR_NO_MEM);assert(counts[1][0]==1&&counts[1][2]==1&&frees==1&&!live);oom=false;
 memset(counts,0,sizeof(counts));frees=0;n.up=false;
 run(&n,packet,packet,ESP_FAIL);assert(counts[1][0]==1&&counts[1][1]==1&&frees==1&&!live);
 frees=0;run(&n,NULL,NULL,ESP_FAIL);assert(!frees&&!live);
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='meshpn-wifi-rx-') as d:
            p = Path(d) / 'test.c'
            p.write_text(stub + body + main)
            for copying in [0, 1]:
                for errors in [0, 1]:
                    cmd = [os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                           '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
                           '-DRETURN_ERRORS=' + str(errors)]
                    if copying:
                        cmd.append('-DCONFIG_LWIP_L2_TO_L3_COPY=1')
                    binary = Path(d) / ('rx-' + str(copying) + '-' + str(errors))
                    subprocess.run(cmd + [str(p), '-o', str(binary)], check=True)
                    subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    unittest.main()
