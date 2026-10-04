// Test-only adapter: drive the real on_poll() with local datagrams, no TUN/root.
#include <node_api.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

static int lab_fault = 0, lab_fault_index = -1, lab_create_index = 0;
static napi_status lab_create_arraybuffer(napi_env env, size_t n, void** data, napi_value* out) {
  if (lab_fault == 1 && lab_create_index++ == lab_fault_index) return napi_generic_failure;
  return napi_create_arraybuffer(env, n, data, out);
}
static napi_status lab_set_element(napi_env env, napi_value arr, uint32_t index, napi_value value) {
  if (lab_fault == 2 && static_cast<int>(index) == lab_fault_index) return napi_generic_failure;
  return napi_set_element(env, arr, index, value);
}
namespace { static napi_value lab_inject(napi_env env, napi_callback_info info); }
#define napi_create_arraybuffer lab_create_arraybuffer
#define napi_set_element lab_set_element
#include MESHPN_TUN_SOURCE
#undef napi_create_arraybuffer
#undef napi_set_element

namespace {
static napi_value lab_inject(napi_env env, napi_callback_info info) {
  size_t argc = 4; napi_value args[4];
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  uint32_t count = 0;
  if (argc != 4 || napi_get_array_length(env, args[0], &count) != napi_ok || count > kMaxBatch) {
    napi_throw_error(env, nullptr, "invalid fixture arguments"); return nullptr;
  }
  napi_get_value_int32(env, args[2], &lab_fault);
  napi_get_value_int32(env, args[3], &lab_fault_index); lab_create_index = 0;
  int pair[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, pair) != 0) {
    napi_throw_error(env, nullptr, "socketpair"); return nullptr;
  }
  for (uint32_t i = 0; i < count; i++) {
    napi_value packet; void* data; size_t size;
    napi_get_element(env, args[0], i, &packet);
    if (napi_get_buffer_info(env, packet, &data, &size) != napi_ok || size == 0 || size > kMaxPkt
        || send(pair[1], data, size, 0) != static_cast<ssize_t>(size)) {
      close(pair[0]); close(pair[1]); napi_throw_error(env, nullptr, "fixture send"); return nullptr;
    }
  }
  TunSession session; session.fd = pair[0]; session.env = env;
  napi_create_reference(env, args[1], 1, &session.read_cb_ref);
  session.poll.data = &session;
  on_poll(&session.poll, 0, UV_READABLE);
  napi_delete_reference(env, session.read_cb_ref);
  close(pair[0]); close(pair[1]); lab_fault = 0;
  // A double return to the pool must fail now, not corrupt a later packet.
  for (size_t i = 0; i < g_pkt_pool_n; i++) for (size_t j = i + 1; j < g_pkt_pool_n; j++) {
    if (g_pkt_pool[i] == g_pkt_pool[j]) {
      napi_throw_error(env, nullptr, "duplicate pool pointer"); return nullptr;
    }
  }
  napi_value out; napi_get_undefined(env, &out); return out;
}
}
