#!/usr/bin/env python3
"""Correlate synchronous ESP-Hosted 1.4.7 responses without a shared FIFO."""
import argparse
from pathlib import Path


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("ESP-Hosted RPC core changed; re-audit the transaction patch")
    return source.replace(old, new, 1)


def replace_function(source: str, signature: str, body: str) -> str:
    start = source.index(signature + "\n{")
    end = source.index("\n}", start) + 2
    return source[:start] + signature + "\n{\n" + body.strip() + "\n}" + source[end:]


def patch(source: str) -> str:
    source = '#include "meshvpn_hosted_wifi_init.h"\n' + source
    source = replace_once(source, "\tRpc   req = {0};",
                          "\tRpc   req = {0};\n\tmeshvpn_hosted_wifi_init_extra_t wifi_init_extra;")
    source = replace_once(source, "\t/* 3. Protobuf msg size */", '''
    if (req.msg_id == RPC_ID__Req_WifiInit) {
        const wifi_init_config_t *cfg = &app_req->u.wifi_init_config;
        const int32_t extra[4] = {cfg->rx_mgmt_buf_type, cfg->rx_mgmt_buf_num,
                                 cfg->tx_hetb_queue_num, cfg->dump_hesigb_enable};
        meshvpn_hosted_wifi_init_extend(req.req_wifi_init->cfg, &wifi_init_extra, extra);
        ESP_LOGI(TAG, "Wi-Fi init extras: rx_mgmt_type=%d rx_mgmt_count=%d tx_hetb=%d hesigb=%d",
                 (int)extra[0], (int)extra[1], (int)extra[2], (int)extra[3]);
    }
\t/* 3. Protobuf msg size */''')
    source = replace_once(source, "\tvoid * sem;\n} sync_rsp_t;",
                          "\tvoid * sem;\n\tctrl_cmd_t *response;\n\tuint32_t response_id;\n} sync_rsp_t;")
    source = replace_once(source, "static uint32_t uid = 0;",
                          "static uint32_t uid = 0;\nstatic void *sync_rsp_mutex;")
    source = replace_once(source, "static int is_sync_resp_sem_available(uint32_t uid);\n", "")
    start = source.index("static int is_sync_resp_sem_available(uint32_t uid)\n{")
    end = source.index("\n}", start) + 2
    source = source[:start] + source[end:]

    # The response remains in the transaction slot until its caller takes it.
    # Holding this mutex around give/removal prevents giving a deleted semaphore.
    source = replace_function(source, "static int post_sync_resp_sem(ctrl_cmd_t *app_resp)", r'''
    int ret = CALLBACK_NOT_REGISTERED;
    if (!app_resp || !app_resp->uid) return ret;
    g_h.funcs->_h_lock_mutex(sync_rsp_mutex, HOSTED_BLOCK_MAX);
    for (int i = 0; i < MAX_SYNC_RPC_TRANSACTIONS; i++) {
        sync_rsp_t *slot = &sync_rsp_table[i];
        if (slot->uid == app_resp->uid && slot->sem && !slot->response &&
                slot->response_id == app_resp->msg_id) {
            slot->response = app_resp;
            ret = g_h.funcs->_h_post_semaphore(slot->sem);
            if (ret != SUCCESS) slot->response = NULL;
            break;
        }
    }
    g_h.funcs->_h_unlock_mutex(sync_rsp_mutex);
    return ret;
''')
    source = replace_function(source, "static int set_sync_resp_sem(ctrl_cmd_t *app_req)", r'''
    int expected = app_req->msg_id - RPC_ID__Req_Base + RPC_ID__Resp_Base;
    if (app_req->rpc_rsp_cb || app_req->rx_sem ||
            expected <= RPC_ID__Resp_Base || expected >= RPC_ID__Resp_Max)
        return CALLBACK_NOT_REGISTERED;
    void *sem = g_h.funcs->_h_create_semaphore(1);
    if (!sem) return CALLBACK_NOT_REGISTERED;
    g_h.funcs->_h_get_semaphore(sem, 0);
    g_h.funcs->_h_lock_mutex(sync_rsp_mutex, HOSTED_BLOCK_MAX);
    for (int i = 0; i < MAX_SYNC_RPC_TRANSACTIONS; i++) {
        if (!sync_rsp_table[i].uid) {
            sync_rsp_table[i] = (sync_rsp_t){
                .uid = app_req->uid, .sem = sem, .response_id = expected,
            };
            app_req->rx_sem = sem;
            g_h.funcs->_h_unlock_mutex(sync_rsp_mutex);
            return CALLBACK_SET_SUCCESS;
        }
    }
    g_h.funcs->_h_unlock_mutex(sync_rsp_mutex);
    g_h.funcs->_h_destroy_semaphore(sem);
    return CALLBACK_NOT_REGISTERED;
''')
    source = replace_function(source, "static int wait_for_sync_response(ctrl_cmd_t *app_req)", r'''
    if (!app_req->rx_sem) return CALLBACK_NOT_REGISTERED;
    int timeout = app_req->rsp_timeout_sec ? app_req->rsp_timeout_sec : DEFAULT_RPC_RSP_TIMEOUT;
    return g_h.funcs->_h_get_semaphore(app_req->rx_sem, timeout);
''')
    # Both success and timeout consume/remove the slot under the same lock as RX.
    # On the timeout boundary an already delivered response is still usable.
    source = replace_function(source, "static ctrl_cmd_t * get_response(int *read_len, ctrl_cmd_t *app_req)", r'''
    if (!read_len || !app_req) return NULL;
    *read_len = 0;
    int ret = wait_for_sync_response(app_req);
    ctrl_cmd_t *response = NULL;
    void *sem = NULL;
    g_h.funcs->_h_lock_mutex(sync_rsp_mutex, HOSTED_BLOCK_MAX);
    for (int i = 0; i < MAX_SYNC_RPC_TRANSACTIONS; i++) {
        if (sync_rsp_table[i].uid == app_req->uid) {
            response = sync_rsp_table[i].response;
            sem = sync_rsp_table[i].sem;
            sync_rsp_table[i] = (sync_rsp_t){0};
            break;
        }
    }
    app_req->rx_sem = NULL;
    g_h.funcs->_h_unlock_mutex(sync_rsp_mutex);
    if (sem) g_h.funcs->_h_destroy_semaphore(sem);
    if (response) *read_len = sizeof(*response);
    else if (ret) ESP_LOGW(TAG, "No sync response for uid %ld", app_req->uid);
    return response;
''')

    # Do not enqueue orphaned/duplicate/late responses, which used to poison
    # the next transaction or fill the receive queue indefinitely.
    start = source.index("\t\t// same as process_rpc_rx_msg() for failed condition")
    end = source.index("\n\t}\n\nfail_req2:", start)
    source = source[:start] + '''\t\tapp_resp->uid = app_req->uid;
        sync_error_response = app_resp;''' + source[end:]
    source = replace_once(source, "\tint32_t   failure_status = 0;",
                          "\tint32_t   failure_status = 0;\n\tctrl_cmd_t *sync_error_response = NULL;")
    # Waking a synchronous caller transfers request ownership back to it. Finish
    # the TX failure cleanup before that caller can free the request.
    source = replace_once(source, "\tRPC_FREE_BUFFS();\n\treturn FAILURE;",
                          "\tRPC_FREE_BUFFS();\n"
                          "\tif (sync_error_response && post_sync_resp_sem(sync_error_response) != SUCCESS) {\n"
                          "\t\tCLEANUP_APP_MSG(sync_error_response);\n\t}\n\treturn FAILURE;")
    start = source.index("\t\t\telem.buf = app_resp;", source.index("static int process_rpc_rx_msg("))
    end = source.index("\n\t\t}\n\n\t} else {", start)
    source = source[:start] + '''            if (post_sync_resp_sem(app_resp) != SUCCESS) {
                CLEANUP_APP_MSG(app_resp);
            }''' + source[end:]
    source = replace_once(source, "\n\tesp_queue_elem_t elem = {0};\n\tctrl_cmd_t *app_resp = NULL;",
                          "\n\tctrl_cmd_t *app_resp = NULL;")
    source = replace_once(source, "\tuid++;\n\t// handle rollover in uid value\n\tif (!uid)\n\t\tuid++;\n\tapp_req->uid = uid;",
                          "\tg_h.funcs->_h_lock_mutex(sync_rsp_mutex, HOSTED_BLOCK_MAX);\n"
                          "\tuid++;\n\tif (!uid) uid++;\n\tapp_req->uid = uid;\n"
                          "\tg_h.funcs->_h_unlock_mutex(sync_rsp_mutex);")
    # Remove registered slots when submitting to the TX queue fails.
    source = replace_once(source, "fail_req:\n\tif (app_req->rx_sem)\n\t\tg_h.funcs->_h_destroy_semaphore(app_req->rx_sem);",
                          '''fail_req:
    g_h.funcs->_h_lock_mutex(sync_rsp_mutex, HOSTED_BLOCK_MAX);
    for (int i = 0; i < MAX_SYNC_RPC_TRANSACTIONS; i++) {
        if (sync_rsp_table[i].uid == app_req->uid) {
            CLEANUP_APP_MSG(sync_rsp_table[i].response);
            sync_rsp_table[i] = (sync_rsp_t){0};
            break;
        }
    }
    g_h.funcs->_h_unlock_mutex(sync_rsp_mutex);
    if (app_req->rx_sem) g_h.funcs->_h_destroy_semaphore(app_req->rx_sem);''')
    source = replace_once(source, "int rpc_core_init(void)\n{\n\tint ret = SUCCESS;",
                          '''int rpc_core_init(void)
{
    int ret = SUCCESS;
    if (!is_rpc_lib_state(RPC_LIB_STATE_INACTIVE)) return FAILURE;
    sync_rsp_mutex = g_h.funcs->_h_create_mutex();
    if (!sync_rsp_mutex) return FAILURE;
    set_rpc_lib_state(RPC_LIB_STATE_INIT);''')
    source = replace_once(source, "\n\treturn ret;\n}\n\n/* Init hosted rpc lib */",
                          '''
    for (int i = 0; i < MAX_SYNC_RPC_TRANSACTIONS; i++) {
        CLEANUP_APP_MSG(sync_rsp_table[i].response);
        if (sync_rsp_table[i].sem)
            g_h.funcs->_h_destroy_semaphore(sync_rsp_table[i].sem);
        sync_rsp_table[i] = (sync_rsp_t){0};
    }
    if (sync_rsp_mutex) g_h.funcs->_h_destroy_mutex(sync_rsp_mutex);
    sync_rsp_mutex = NULL;
    return ret;
}

/* Init hosted rpc lib */''')
    return source


def patch_slave_if(source: str) -> str:
    # rpc_send_req owns/frees req on failure; do not log through that pointer.
    return replace_once(source,
                        'ESP_LOGE(TAG,"Failed to send control req 0x%x\\n", req->msg_id);',
                        'ESP_LOGE(TAG,"Failed to send control req 0x%x\\n", (unsigned)(msGiD));')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--kind", choices=("core", "slave-if"), default="core")
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("output must not overwrite managed_components")
    result = (patch if args.kind == "core" else patch_slave_if)(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != result:
        args.output.write_text(result)
