"""Run the real patched synchronous RPC functions with concurrent callers."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("patch_rpc_core", ROOT / "scripts/patch-esp-hosted-rpc-core.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = ROOT / "managed_components/espressif__esp_hosted/host/drivers/rpc/core/rpc_core.c"

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SUCCESS 0
#define FAILURE -1
#define CALLBACK_SET_SUCCESS 0
#define CALLBACK_NOT_REGISTERED -3
#define RPC_ID__Req_Base 0x100
#define RPC_ID__Resp_Base 0x200
#define RPC_ID__Resp_Max 0x300
#define DEFAULT_RPC_RSP_TIMEOUT 1
#define HOSTED_BLOCK_MAX -1
#define MAX_SYNC_RPC_TRANSACTIONS 8
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGV(...) ((void)0)
typedef struct cmd {
    uint32_t uid,msg_id; int rsp_timeout_sec,msg_type;
    void *rx_sem,*rpc_rsp_cb,*app_free_buff_hdl;
    void (*app_free_buff_func)(void*);
} ctrl_cmd_t;
#define RPC_TYPE__Req 1
static void cleanup(ctrl_cmd_t *r) {
    if(r){if(r->app_free_buff_func)r->app_free_buff_func(r->app_free_buff_hdl);free(r);}
}
#define CLEANUP_APP_MSG(r) cleanup(r)
#define HOSTED_FREE(r) free(r)
#define H_FREE_PTR_WITH_FUNC(f,h) do{if((h)&&(f)){(f)(h);(h)=NULL;}}while(0)
typedef struct {uint32_t uid;void *sem;ctrl_cmd_t *response;uint32_t response_id;} sync_rsp_t;
static sync_rsp_t sync_rsp_table[MAX_SYNC_RPC_TRANSACTIONS];
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static void *sync_rsp_mutex=&mutex,*rpc_tx_q;
static uint32_t uid;
typedef struct {pthread_mutex_t m;pthread_cond_t c;int posted;} test_sem_t;
static atomic_int sem_created,sem_destroyed;
static int fail_sem,fail_queue;
static void *create_sem(int n){
    (void)n;if(fail_sem)return NULL;
    test_sem_t *s=calloc(1,sizeof(*s));assert(s);
    pthread_mutex_init(&s->m,0);pthread_cond_init(&s->c,0);s->posted=1;sem_created++;return s;
}
static int take_sem(void *p,int timeout){
    test_sem_t *s=p;assert(s);pthread_mutex_lock(&s->m);
    if(!timeout && !s->posted){pthread_mutex_unlock(&s->m);return -2;}
    while(timeout>0 && !s->posted)pthread_cond_wait(&s->c,&s->m);
    int ret=s->posted?0:-2;s->posted=0;pthread_mutex_unlock(&s->m);return ret;
}
static int give_sem(void *p){test_sem_t *s=p;assert(s);pthread_mutex_lock(&s->m);s->posted=1;pthread_cond_signal(&s->c);pthread_mutex_unlock(&s->m);return 0;}
static int destroy_sem(void *p){test_sem_t *s=p;assert(s);pthread_mutex_destroy(&s->m);pthread_cond_destroy(&s->c);free(s);sem_destroyed++;return 0;}
static int lock_mutex(void *p,int t){(void)t;return pthread_mutex_lock(p);}
static int unlock_mutex(void *p){return pthread_mutex_unlock(p);}
static int queue_item(void *q,void *p,int t){(void)q;(void)p;(void)t;return fail_queue?-1:0;}
static struct {
 void *(*_h_create_semaphore)(int);
 int (*_h_get_semaphore)(void*,int),(*_h_post_semaphore)(void*),(*_h_destroy_semaphore)(void*);
 int (*_h_lock_mutex)(void*,int),(*_h_unlock_mutex)(void*),(*_h_queue_item)(void*,void*,int);
} funcs={create_sem,take_sem,give_sem,destroy_sem,lock_mutex,unlock_mutex,queue_item};
static struct {typeof(funcs)*funcs;} g_h={&funcs};
static void rpc_tx_ind(void){}
static int wait_for_sync_response(ctrl_cmd_t*);
%s
static ctrl_cmd_t *new_request(void){ctrl_cmd_t *r=calloc(1,sizeof(*r));assert(r);r->msg_id=0x11d;assert(!rpc_send_req(r));return r;}
static ctrl_cmd_t *new_response(ctrl_cmd_t *r){ctrl_cmd_t *p=calloc(1,sizeof(*p));assert(p);p->uid=r->uid;p->msg_id=r->msg_id+0x100;return p;}
static void expect(ctrl_cmd_t *r,ctrl_cmd_t *p){int n=-1;assert(get_response(&n,r)==p);assert(n==(p?(int)sizeof(*p):0));assert(!r->rx_sem);free(r);cleanup(p);}
static void *concurrent(void *unused){
    (void)unused;
    for(int i=0;i<1000;i++){
        ctrl_cmd_t *r=new_request(),*p=new_response(r);
        assert(!post_sync_resp_sem(p));expect(r,p);
    }
    return NULL;
}
typedef struct {ctrl_cmd_t *request,*response;int timeout;} race_t;
static void *waiter(void *p){race_t *r=p;r->request->rsp_timeout_sec=r->timeout;expect(r->request,r->response);return NULL;}
static void *boundary_waiter(void *p){
    ctrl_cmd_t *r=p;int n=0;r->rsp_timeout_sec=-1;
    ctrl_cmd_t *got=get_response(&n,r);if(got)assert(got->uid==r->uid);
    free(r);cleanup(got);return NULL;
}
int main(void){
    ctrl_cmd_t *a=new_request(),*b=new_request(),*ra=new_response(a),*rb=new_response(b);
    assert(a->uid!=b->uid);assert(!post_sync_resp_sem(ra));assert(!post_sync_resp_sem(rb));
    expect(b,rb);expect(a,ra); /* Reverse caller scheduling. */
    a=new_request();ra=new_response(a);rb=new_response(a);
    assert(!post_sync_resp_sem(ra));assert(post_sync_resp_sem(rb));cleanup(rb);expect(a,ra);
    a=new_request();ra=new_response(a);ra->msg_id++;
    assert(post_sync_resp_sem(ra));ra->msg_id--;assert(!post_sync_resp_sem(ra));expect(a,ra);
    a=new_request();ra=new_response(a);a->rsp_timeout_sec=-1;expect(a,NULL);
    assert(post_sync_resp_sem(ra));cleanup(ra); /* Late reply never occupies another slot. */
    a=new_request();ra=new_response(a);assert(!post_sync_resp_sem(ra));a->rsp_timeout_sec=-1;expect(a,ra);
    fail_sem=1;a=calloc(1,sizeof(*a));a->msg_id=0x11d;assert(rpc_send_req(a));fail_sem=0;
    fail_queue=1;a=calloc(1,sizeof(*a));a->msg_id=0x11d;assert(rpc_send_req(a));fail_queue=0;
    ctrl_cmd_t *pending[MAX_SYNC_RPC_TRANSACTIONS];
    for(unsigned i=0;i<MAX_SYNC_RPC_TRANSACTIONS;i++)pending[i]=new_request();
    a=calloc(1,sizeof(*a));a->msg_id=0x11d;assert(rpc_send_req(a));
    for(unsigned i=0;i<MAX_SYNC_RPC_TRANSACTIONS;i++){a=pending[i];ra=new_response(a);assert(!post_sync_resp_sem(ra));expect(a,ra);}
    uid=UINT32_MAX;a=new_request();assert(a->uid==1);ra=new_response(a);assert(!post_sync_resp_sem(ra));expect(a,ra);
    /* A separate waiting task may run immediately when RX gives its semaphore. */
    for(unsigned i=0;i<200;i++){
        a=new_request();ra=new_response(a);race_t r={a,ra,1};pthread_t t;
        assert(!pthread_create(&t,0,waiter,&r));assert(!post_sync_resp_sem(ra));pthread_join(t,0);
    }
    /* Timeout removal races a late RX delivery: either owner must free it once. */
    for(unsigned i=0;i<200;i++){
        a=new_request();ra=new_response(a);pthread_t t;
        assert(!pthread_create(&t,0,boundary_waiter,a));
        if(post_sync_resp_sem(ra))cleanup(ra);
        pthread_join(t,0);
    }
    pthread_t threads[4];
    for(int i=0;i<4;i++)assert(!pthread_create(&threads[i],0,concurrent,0));
    for(int i=0;i<4;i++)pthread_join(threads[i],0);
    for(unsigned i=0;i<MAX_SYNC_RPC_TRANSACTIONS;i++)assert(!sync_rsp_table[i].uid&&!sync_rsp_table[i].response);
    assert(sem_created==sem_destroyed);
    puts("RPC response correlation, late/duplicate reply, allocation/queue failure, concurrency: PASS");
}
'''


class HostedRpcCoreTests(unittest.TestCase):
    def test_wifi_init_wire_compatibility(self):
        hosted = ROOT / "managed_components/espressif__esp_hosted/common"
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "wifi-init"
            subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined",
                            "-I" + str(ROOT / "components/meshvpn_wifi/include"),
                            "-I" + str(hosted / "proto"),
                            "-I" + str(hosted / "protobuf-c"),
                            str(ROOT / "tests/test_hosted_wifi_init.c"),
                            str(hosted / "proto/esp_hosted_rpc.pb-c.c"),
                            str(hosted / "protobuf-c/protobuf-c/protobuf-c.c"),
                            "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=10)

    def test_failed_submit_does_not_read_freed_request(self):
        slave_if = SOURCE.parent.parent / "slaveif/rpc_slave_if.c"
        source = module.patch_slave_if(slave_if.read_text())
        macro = source[source.index("#define RPC_SEND_REQ"):source.index("int rpc_slaveif_init")]
        harness = r'''
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#define SUCCESS 0
#define RPC_ID__Req_GetMACAddress 0x101
#define TAG "test"
#define ESP_LOGE(tag,fmt,...) fprintf(stderr,fmt,__VA_ARGS__)
typedef struct {unsigned msg_id;void *rpc_rsp_cb;} ctrl_cmd_t;
static int rpc_send_req(ctrl_cmd_t *r){free(r);return -1;}
static ctrl_cmd_t *rpc_wait_and_parse_sync_resp(ctrl_cmd_t *r){free(r);return NULL;}
%s
static ctrl_cmd_t *call(ctrl_cmd_t *req){RPC_SEND_REQ(RPC_ID__Req_GetMACAddress);RPC_DECODE_RSP_IF_NOT_ASYNC();}
int main(void){assert(!call(calloc(1,sizeof(ctrl_cmd_t))));}
'''
        with tempfile.TemporaryDirectory() as directory:
            c = Path(directory) / "failure.c"
            binary = Path(directory) / "failure"
            c.write_text(harness % macro)
            subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(c), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=10)

    def test_real_transaction_functions(self):
        source = module.patch(SOURCE.read_text())
        functions = []
        for name in ("static ctrl_cmd_t * get_response", "static int post_sync_resp_sem",
                     "static int set_sync_resp_sem", "static int wait_for_sync_response", "int rpc_send_req"):
            start = source.index(name + "(")
            # Ignore a forward declaration.
            if source.index(";", start) < source.index("\n{", start):
                start = source.index(name + "(", source.index(";", start) + 1)
            end = source.index("\n}", start) + 2
            functions.append(source[start:end])
        with tempfile.TemporaryDirectory() as directory:
            c = Path(directory) / "core.c"
            binary = Path(directory) / "core"
            c.write_text(HARNESS % "\n".join(functions))
            subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
                            "-fsanitize=address,undefined", str(c), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=30)

    def test_unrecognized_dependency_fails_closed(self):
        with self.assertRaises(ValueError):
            module.patch("different dependency")


if __name__ == "__main__":
    unittest.main()
