#include <node_api.h>

static napi_value OpenStub(napi_env env, napi_callback_info info) {
  napi_throw_error(env, nullptr, "tun_linux: только Linux (соберите addon на Linux)");
  return nullptr;
}

static napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "open", NAPI_AUTO_LENGTH, OpenStub, nullptr, &fn);
  napi_set_named_property(env, exports, "open", fn);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
