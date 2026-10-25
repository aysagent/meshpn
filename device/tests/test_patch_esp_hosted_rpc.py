"""Exercise the real pinned RPC getter against distinct STA/AP responses."""
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


class HostedProtocolTests(unittest.TestCase):
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
