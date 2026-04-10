#include <node_api.h>

static napi_value OpenStub(napi_env env, napi_callback_info info) {
  napi_throw_error(env, NULL, "tun_linux: только Linux (соберите addon на Linux)");
  return NULL;
}

static napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "open", NAPI_AUTO_LENGTH, OpenStub, NULL, &fn);
  napi_set_named_property(env, exports, "open", fn);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
