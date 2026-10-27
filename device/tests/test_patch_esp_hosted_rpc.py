"""Exercise pinned RPC getters against distinct interfaces and missing responses."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("patch_hosted_rpc", ROOT / "scripts/patch-esp-hosted-rpc.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = ROOT / "managed_components/espressif__esp_hosted/host/drivers/rpc/wrap/rpc_wrap.c"

HARNESS = r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
#define SUCCESS 0
#define FAILURE -1
typedef int wifi_interface_t;
typedef struct { int resp_event_status; union { struct { int ifx; uint8_t protocol_bitmap; } wifi_protocol; } u; } ctrl_cmd_t;
static ctrl_cmd_t request, response;
static int sent, status;
static ctrl_cmd_t *new_req(void) { memset(&request, 0, sizeof(request)); return &request; }
#define RPC_DEFAULT_REQ() new_req()
static ctrl_cmd_t *wifi_get_protocol(ctrl_cmd_t *req) {
    sent++;
    response.resp_event_status=status;
    response.u.wifi_protocol.protocol_bitmap=req->u.wifi_protocol.ifx==1 ? 3 : 71;
    return &response;
}
static int rpc_rsp_callback(ctrl_cmd_t *resp) { return resp->resp_event_status; }
%s
int main(void) {
    uint8_t protocol=99;
    assert(rpc_wifi_get_protocol(0,&protocol)==0 && protocol==71);
    assert(rpc_wifi_get_protocol(1,&protocol)==0 && protocol==3);
    assert(sent==2);
    assert(rpc_wifi_get_protocol(1,0)==FAILURE && sent==2);
    status=123; protocol=99;
    assert(rpc_wifi_get_protocol(1,&protocol)==123 && protocol==99);
    return 0;
}
'''

RESPONSE_HARNESS = r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
#define SUCCESS 0
#define FAILURE -1
#define ESP_WIFI_MAX_CONN_NUM 3
typedef int wifi_interface_t;
typedef struct { unsigned char bytes[128]; } wifi_config_t;
typedef struct {
    uint8_t mac[6]; int rssi;
    unsigned phy_11b,phy_11g,phy_11n,phy_lr,phy_11ax,is_mesh_child,reserved;
} client_t;
typedef struct { client_t sta[ESP_WIFI_MAX_CONN_NUM]; int num; } wifi_sta_list_t;
typedef struct {
    int resp_event_status;
    union {
        struct { int iface; wifi_config_t u; } wifi_config;
        wifi_sta_list_t wifi_ap_sta_list;
    } u;
} ctrl_cmd_t;
static ctrl_cmd_t request,response;
static int scenario,callbacks,requests,last_iface;
static ctrl_cmd_t *new_req(void) { memset(&request,0,sizeof(request));return &request; }
#define RPC_DEFAULT_REQ() new_req()
static struct { void *(*_h_memcpy)(void*,const void*,size_t); } funcs={memcpy};
static struct { typeof(funcs)* funcs; } g_h={&funcs};
static ctrl_cmd_t *reply(void) {
    requests++;
    if(scenario==2)return 0;
    memset(&response,0,sizeof(response));response.resp_event_status=scenario?123:0;
    return &response;
}
static ctrl_cmd_t *wifi_get_config(ctrl_cmd_t *req) {
    last_iface=req->u.wifi_config.iface;ctrl_cmd_t *r=reply();
    if(r)memset(&r->u.wifi_config.u,0x45,sizeof(wifi_config_t));
    return r;
}
static ctrl_cmd_t *wifi_ap_get_sta_list(ctrl_cmd_t *req) {
    (void)req;ctrl_cmd_t *r=reply();
    if(r){r->u.wifi_ap_sta_list.num=1;r->u.wifi_ap_sta_list.sta[0].rssi=-42;r->u.wifi_ap_sta_list.sta[0].mac[0]=2;}
    return r;
}
static int rpc_rsp_callback(ctrl_cmd_t *r) {
    callbacks++;int result=r?r->resp_event_status:FAILURE;
    if(r)memset(r,0xdd,sizeof(*r)); /* Response released by real callback. */
    return result;
}
%s
int main(void) {
    wifi_config_t cfg,unchanged_cfg;
    wifi_sta_list_t clients,unchanged_clients;
    memset(&cfg,0xa5,sizeof(cfg));
    assert(rpc_wifi_get_config(1,&cfg)==0 && last_iface==1 && cfg.bytes[0]==0x45 && cfg.bytes[127]==0x45);
    assert(rpc_wifi_ap_get_sta_list(&clients)==0 && clients.num==1 && clients.sta[0].rssi==-42 && clients.sta[0].mac[0]==2);
    for(scenario=1;scenario<=2;scenario++){
        memset(&cfg,0xa5,sizeof(cfg));unchanged_cfg=cfg;
        memset(&clients,0xa5,sizeof(clients));unchanged_clients=clients;
        int expected=scenario==1?123:FAILURE;
        assert(rpc_wifi_get_config(0,&cfg)==expected && last_iface==0);
        assert(!memcmp(&cfg,&unchanged_cfg,sizeof(cfg)));
        assert(rpc_wifi_ap_get_sta_list(&clients)==expected);
        assert(!memcmp(&clients,&unchanged_clients,sizeof(clients)));
    }
    int previous=requests;
    assert(rpc_wifi_get_config(0,0)==FAILURE && rpc_wifi_ap_get_sta_list(0)==FAILURE);
    assert(requests==previous && callbacks==6);
    return 0;
}
'''

PS_HARNESS = r'''
#include <assert.h>
#include <string.h>
#define SUCCESS 0
#define FAILURE -1
typedef int wifi_ps_type_t;
typedef struct {
    int resp_event_status;
    union { struct { wifi_ps_type_t ps_mode; } wifi_ps; } u;
} ctrl_cmd_t;
static ctrl_cmd_t request,response;
static int scenario,requests,callbacks;
#define RPC_DEFAULT_REQ() (&request)
static ctrl_cmd_t *wifi_get_ps(ctrl_cmd_t *req) {
    assert(req==&request); requests++;
    if(scenario==2)return 0;
    response.resp_event_status=scenario?123:SUCCESS;
    response.u.wifi_ps.ps_mode=2;
    return &response;
}
static int rpc_rsp_callback(ctrl_cmd_t *r) {
    callbacks++;
    int result=r?r->resp_event_status:FAILURE;
    if(r)memset(r,0xdd,sizeof(*r));
    return result;
}
%s
int main(void) {
    /* Repeated timeouts and driver failures must preserve caller storage and
     * still release each response exactly once; then recovery must work. */
    for(int cycle=0;cycle<100;cycle++) {
        for(scenario=0;scenario<3;scenario++) {
            wifi_ps_type_t mode=99;
            int expected=scenario==0?SUCCESS:scenario==1?123:FAILURE;
            assert(rpc_wifi_get_ps(&mode)==expected);
            assert(mode==(scenario==0?2:99));
        }
    }
    assert(requests==300 && callbacks==300);
    assert(rpc_wifi_get_ps(0)==FAILURE);
    assert(requests==300 && callbacks==300);
    return 0;
}
'''


class HostedProtocolTests(unittest.TestCase):
    def test_power_save_timeout_failure_and_recovery(self):
        source=module.patch(SOURCE.read_text())
        start=source.index("int rpc_wifi_get_ps(")
        end=source.index("\n}",start)+2
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/"power-save.c";binary=Path(directory)/"power-save"
            c.write_text(PS_HARNESS % source[start:end])
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                            "-fsanitize=address,undefined",str(c),"-o",str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

    def test_missing_and_failed_responses(self):
        source=module.patch(SOURCE.read_text())
        functions=[]
        for name in ("rpc_wifi_get_config", "rpc_wifi_ap_get_sta_list"):
            start=source.index("int " + name + "(")
            end=source.index("\n}",start)+2
            functions.append(source[start:end])
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/"responses.c";binary=Path(directory)/"responses"
            c.write_text(RESPONSE_HARNESS % "\n".join(functions))
            subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",
                            "-fsanitize=address,undefined",str(c),"-o",str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

    def test_sta_ap_selection_and_error(self):
        self.assertTrue(SOURCE.exists(), "Fetch the pinned managed components before running this integration test")
        source=module.patch(SOURCE.read_text())
        start=source.index("int rpc_wifi_get_protocol(")
        end=source.index("\n}",start)+2
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/"getter.c";binary=Path(directory)/"getter"
            c.write_text(HARNESS % source[start:end])
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(c),"-o",str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

    def test_unrecognized_dependency_fails_closed(self):
        for source in ("changed source", "\tresp = wifi_get_protocol(req);\n"*2):
            with self.assertRaises(ValueError):module.patch(source)


if __name__ == "__main__":unittest.main()
