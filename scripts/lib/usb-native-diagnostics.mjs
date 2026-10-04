/** Build-time instrumentation of a disposable VM copy; production addon untouched. */
import assert from 'node:assert/strict';
export function instrumentTunMemory(source) {
  const replace = (before, after) => {
    assert.equal(source.split(before).length, 2, 'unique native diagnostic anchor: ' + before);
    source = source.replace(before, after);
  };
  replace('#include <node_api.h>', '#include <node_api.h>\n#include <malloc.h>');
  replace('static size_t g_pkt_pool_n = 0;', `static size_t g_pkt_pool_n = 0;
static size_t lab_alloc = 0, lab_free = 0, lab_in_use = 0, lab_peak = 0;
static size_t lab_external = 0, lab_finalized = 0;`);
  replace('return g_pkt_pool[--g_pkt_pool_n];', 'lab_in_use++; if (lab_in_use > lab_peak) lab_peak = lab_in_use;\n    return g_pkt_pool[--g_pkt_pool_n];');
  replace('return malloc(kMaxPkt);', `void* p = malloc(kMaxPkt);
  if (p) { lab_alloc++; lab_in_use++; if (lab_in_use > lab_peak) lab_peak = lab_in_use; }
  return p;`);
  replace('if (g_pkt_pool_n < kGlobalPoolCap)', 'lab_in_use--;\n  if (g_pkt_pool_n < kGlobalPoolCap)');
  replace('free(p);', 'lab_free++; free(p);');
  replace('pkt_pool_release(data);', 'lab_finalized++; pkt_pool_release(data);');
  replace('if (napi_set_element(env, arr, static_cast<uint32_t>(i), ab)', 'lab_external++;\n    if (napi_set_element(env, arr, static_cast<uint32_t>(i), ab)');
  replace('static napi_value init(napi_env env, napi_value exports) {', `
static napi_value lab_memory(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value arg; bool trim = false;
  napi_get_cb_info(env, info, &argc, &arg, nullptr, nullptr);
  if (argc) napi_get_value_bool(env, arg, &trim);
  int trimmed = trim ? malloc_trim(0) : -1;
  struct mallinfo2 m = mallinfo2();
  napi_value out; napi_create_object(env, &out);
  auto put = [&](const char* name, double n) {
    napi_value v; napi_create_double(env, n, &v); napi_set_named_property(env, out, name, v);
  };
  std::lock_guard<std::mutex> lock(g_pkt_pool_mu);
  put("allocations", lab_alloc); put("frees", lab_free);
  put("inUse", lab_in_use); put("peakInUse", lab_peak); put("pool", g_pkt_pool_n);
  put("backingBytes", (lab_alloc - lab_free) * kMaxPkt);
  put("externalCreated", lab_external); put("externalFinalized", lab_finalized);
  put("arena", m.arena); put("uordblks", m.uordblks); put("fordblks", m.fordblks);
  put("hblkhd", m.hblkhd); put("keepcost", m.keepcost); put("trimmed", trimmed);
  return out;
}
static napi_value init(napi_env env, napi_value exports) {
  napi_value lab; napi_create_function(env, "labMemoryStats", NAPI_AUTO_LENGTH, lab_memory, nullptr, &lab);
  napi_set_named_property(env, exports, "labMemoryStats", lab);`);
  return source;
}
