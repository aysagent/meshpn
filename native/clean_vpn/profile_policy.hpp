#pragma once
#include <nlohmann/json.hpp>
#include <array>
#include <cstdint>
#include <set>
namespace cvpn::profile_policy {
inline const std::set<uint16_t> tls12_ciphers={49195,49196,49199,49200,52392,52393};
inline const std::set<uint16_t> signatures={0x0401,0x0501,0x0601,0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0807,0x0904,0x0905,0x0906};
// Policy envelope only. Version-dependent presence/order and group/key-share
// combinations still require Profile::first_flight's exact prewire check.
inline const std::set<uint16_t> extensions={0,5,10,11,13,16,18,21,23,27,43,45,51,17613,65037,65281};
inline constexpr uint32_t window_min=65535,window_max=1048576;
struct Setting {int id;uint32_t min,max;bool required;const char* error;};
inline constexpr std::array<Setting,6> settings={{{1,0,65536,false,"profile_h2_hpack"},
  {2,0,0,true,"profile_h2_push"},{3,1,1,true,"profile_h2_streams"},
  {4,window_min,window_max,true,"profile_h2_window"},{5,16384,16384,false,"profile_h2_frame"},
  {6,1024,8192,true,"profile_h2_headers"}}};
inline nlohmann::json describe() {
  using json=nlohmann::json;json rules=json::array();
  for(const auto& r:settings)rules.push_back({{"id",r.id},{"min",r.min},{"max",r.max},{"required",r.required}});
  return {{"schema",1},{"id","bounded-cold-v1"},{"scope","policy-envelope-not-native-validation"},
    {"tls",{{"tls13_cipher_suites",{4865,4866,4867}},{"tls12_cipher_suites",tls12_ciphers},
      {"signature_algorithms",signatures},{"extension_types",extensions},{"certificate_compression",{2}},
      {"alps_codepoint",17613},{"group_combinations","require-native-prewire-check"}}},
    {"http2",{{"settings",rules},{"settings_frames",1},{"duplicate_settings",false},
      {"connection_window",{{"min",window_min},{"max",window_max}}}}},
    {"application",{{"fixed_native_carrier",true},{"browser_navigation_emulation",false},{"exporter_psk_required",true}}},
    {"activation",{{"automatic",false},{"native_check_config_required",true},{"independent_wire_check_required",true}}}};
}
}
