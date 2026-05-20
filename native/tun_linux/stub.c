#include <node_api.h>

static napi_value OpenStub(napi_env env, napi_callback_info info) {
  napi_throw_error(env, NULL, "tun_linux: только Linux (соберите addon на Linux)");
  return NULL;
}

static napi_value OriginalDstStub(napi_env env, napi_callback_info info) {
  napi_throw_error(env, NULL, "tun_linux.originalDstIpv4FromFd только на Linux с NETFILTER iptables REDIRECT");
  return NULL;
}

static napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "open", NAPI_AUTO_LENGTH, OpenStub, NULL, &fn);
  napi_set_named_property(env, exports, "open", fn);
  napi_value fn_od;
  napi_create_function(env, "originalDstIpv4FromFd", NAPI_AUTO_LENGTH, OriginalDstStub, NULL, &fn_od);
  napi_set_named_property(env, exports, "originalDstIpv4FromFd", fn_od);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
