// Project native events explicitly. Journals and stdout are never returned raw.
const phases=['redirect','client_hello','authorization','upstream_connect','tls_prefix','encrypted_stream','dispatch','internal'];
const reasons=new Set(`combo_accept combo_boring_queue combo_cancelled combo_config combo_endpoint combo_hello_eof combo_hello_limit combo_hello_timeout
combo_listener combo_nonblocking combo_peek combo_poll combo_public_name combo_relay_limit combo_replay_required combo_role
combo_sni combo_unknown_name hello_ciphers hello_compression hello_extension hello_extensions hello_incomplete hello_length
hello_limit hello_reader_state hello_record hello_record_boundary hello_record_count hello_record_resize hello_replacement hello_session_id
hello_sni hello_sni_missing hello_structure hello_type hello_versions queue_limit relay_accept relay_alert
relay_cancelled relay_ccs relay_clock_rollback relay_config relay_config_fields relay_connect relay_crypto relay_destination
relay_destination_denied relay_destination_local relay_destination_port relay_drain_timeout relay_duplicate_destination relay_duplicate_key relay_duplicate_prefix relay_endpoint_config
relay_exit_required relay_failed relay_global_limit relay_handshake_eof relay_handshake_timeout relay_hello_binding relay_hello_eof relay_hello_limit
relay_hello_state relay_idle_timeout relay_init_exit_only relay_interleaved_handshake relay_internal relay_lifetime_timeout relay_limits relay_listen_address
relay_listener relay_listener_nonblocking relay_not_redirected relay_original_destination relay_peer_config relay_peer_id relay_peer_limit relay_peer_replay_exists_or_create_failed
relay_peer_revoked relay_policy_config relay_policy_conflict relay_policy_interfaces relay_policy_prefix relay_poll relay_public_name relay_queue_limit
relay_quota_config relay_record relay_record_count relay_record_type relay_recv relay_reload_replay_path_changed relay_replay_commit relay_replay_config
relay_replay_corrupt relay_replay_directory relay_replay_exists relay_replay_failed relay_replay_file relay_replay_full relay_replay_locked relay_replay_path
relay_replay_pending relay_replay_read relay_replay_scope_or_format relay_replay_sync relay_replay_write relay_replayed relay_retry_boundary relay_retry_identity
relay_retry_sequence relay_retry_version relay_role relay_secret_path relay_self_destination relay_send relay_sequence relay_server_boundary
relay_server_hello relay_server_version relay_shutdown relay_socket relay_socket_error relay_socket_option relay_socket_timeout relay_token_auth
relay_token_encoding relay_token_expired relay_token_format relay_token_hostname relay_token_hostname_limit relay_token_suffix`.split(/\s+/));
const number=x=>Number.isSafeInteger(x)&&x>=0;
const packetReasons=new Set(`address_mode address_offer_auth address_offer_format address_offer_hmac address_offer_ipv4 address_offer_mismatch address_offer_missing address_offer_purpose
auth_clock_skew auth_deadline auth_rejected cancelled connect connect_deadline connect_socket data_before_auth
discovery_incomplete discovery_payload duplicate_header early_end exporter h1_chunk_invalid h1_chunk_limit h1_control_limit
h1_extra_message h1_framing_invalid h1_headers_invalid h1_host_invalid h1_peer_end_stream h1_ping_timeout h1_protocol_invalid h1_trailers_forbidden
h1_truncated_record h2_alps_invalid h2_bad_client_magic h2_callback_failure h2_flooded h2_goaway_error h2_goaway_no_error h2_invalid_frame
h2_local_goaway_error h2_local_reset_error h2_no_memory h2_peer_end_stream h2_ping_timeout h2_required h2_reset_error h2_reset_no_error
h2_stream_closed h2_stream_error headers_limit hmac http2_error http2_receive http_alpn_required http_version_mismatch
invalid_frame_length invalid_ipv4 peer_address peer_busy peer_destination poll profile_hello_write queue_consume
queue_limit request_invalid socket_error tcp_nodelay timeout tls_handshake tls_identity tls_peer_closed
tls_read tls_sni tls_socket tls_verify_expired tls_verify_failed tls_verify_name tls_verify_not_yet_valid tls_verify_untrusted
tls_write tun_write unexpected_headers vpn_response_rejected`.split(/\s+/));
const counters=(value,keys)=>Object.fromEntries(keys.filter(k=>number(value?.[k])).map(k=>[k,value[k]]));
export function projectEngineDiagnostics(event){
 if(!event||event.version!==1||event.event!=='diagnostics'||event.diagnostics?.schema!==1||event.diagnostics.scope!=='process-lifetime-sampled')return null;
 const d=event.diagnostics,out={schema:1,scope:'process-lifetime-sampled'};
 if(d.packet&&typeof d.packet==='object'){
  out.packet=counters(d.packet,['ready_events','session_ends']);const end=d.packet.last_end;
  out.packet.lastEnd=end&&number(end.monotonic_ms)?{code:packetReasons.has(end.code)?end.code:'packet_failure',monotonicMs:end.monotonic_ms}:null;
 }
 if(d.relay&&typeof d.relay==='object'){
  const relay=counters(d.relay,['accepted','completed','failed','rejected','admission_dropped','active','pending','peak_queue_bytes','backpressure_polls','packet_selected','relay_selected']);
  if(typeof d.relay.broken==='boolean')relay.broken=d.relay.broken;
  relay.failuresByPhase=counters(d.relay.failures_by_phase,phases);
  const f=d.relay.last_failure;
  relay.lastFailure=f&&phases.includes(f.phase)&&number(f.monotonic_ms)?{code:reasons.has(f.code)?f.code:'relay_internal',phase:f.phase,monotonicMs:f.monotonic_ms}:null;
  out.relay=relay;
 }
 for(const [key,target] of [['dns','dns'],['private_dns','privateDns']])if(d[key]&&typeof d[key]==='object')out[target]=counters(d[key],['queries','answers','servfail','private_queries','upstream_attempts','upstream_errors','upstream_timeouts']);
 return Object.keys(out).length>2?out:null;
}
export function publicEngineDiagnostics(value={}){
 const out={status:['sampled','stale','stopped','unavailable'].includes(value.status)?value.status:'unavailable'};
 if(number(value.ageMs))out.ageMs=value.ageMs;
 const packet=value.packet?{...value.packet,last_end:value.packet.lastEnd?{code:value.packet.lastEnd.code,monotonic_ms:value.packet.lastEnd.monotonicMs}:null}:undefined;
 const relay=value.relay?{...value.relay,failures_by_phase:value.relay.failuresByPhase,last_failure:value.relay.lastFailure?{code:value.relay.lastFailure.code,phase:value.relay.lastFailure.phase,monotonic_ms:value.relay.lastFailure.monotonicMs}:null}:undefined;
 const data=projectEngineDiagnostics({version:1,event:'diagnostics',diagnostics:{schema:value.schema,scope:value.scope,packet,relay,dns:value.dns,private_dns:value.privateDns}});
 return{...out,...(data??{})};
}
// Controllers retain a strict metadata contract. UI projection alone is not
// permission to accept arbitrary extra fields on an engine control channel.
const object=x=>x&&typeof x==='object'&&!Array.isArray(x);
const keys=(x,wanted)=>object(x)&&Object.keys(x).length===wanted.length&&wanted.every(k=>Object.hasOwn(x,k));
const rawEnd=(value,relay)=>value===null||(keys(value,relay?['code','phase','monotonic_ms']:['code','monotonic_ms'])&&
 number(value.monotonic_ms)&&(relay?reasons:packetReasons).has(value.code)&&(!relay||phases.includes(value.phase)));
export function validNativeDiagnostics(e){
 if(!object(e)||e.version!==1||e.event!=='diagnostics'||typeof e.state!=='string'||!/^[a-z0-9_]{1,64}$/.test(e.state))return false;
 const base=['version','event','state','diagnostics'],packet=['generation','tx_packets','rx_packets','dropped_packets'];
 if(!keys(e,base)&&!(keys(e,[...base,...packet])&&packet.every(k=>number(e[k]))))return false;
 const d=e.diagnostics;if(!object(d)||d.schema!==1||d.scope!=='process-lifetime-sampled'||Object.keys(d).some(k=>!['schema','scope','packet','relay','dns','private_dns'].includes(k)))return false;
 if(!['packet','relay','dns','private_dns'].some(k=>Object.hasOwn(d,k)))return false;
 if(Object.hasOwn(d,'packet')&&(!keys(d.packet,['ready_events','session_ends','last_end'])||!number(d.packet.ready_events)||!number(d.packet.session_ends)||!rawEnd(d.packet.last_end,false)))return false;
 if(Object.hasOwn(d,'relay')){
  const common=['admission_dropped','active','pending','broken','failures_by_phase','last_failure'];
  const listener=['accepted','completed','failed','peak_queue_bytes','backpressure_polls'],exit=['packet_selected','relay_selected','rejected'];
  if(!keys(d.relay,[...common,...listener])&&!keys(d.relay,[...common,...exit]))return false;
  if(typeof d.relay.broken!=='boolean'||!rawEnd(d.relay.last_failure,true)||!keys(d.relay.failures_by_phase,phases)||!phases.every(k=>number(d.relay.failures_by_phase[k])))return false;
  if(!Object.entries(d.relay).every(([k,v])=>['broken','failures_by_phase','last_failure'].includes(k)||number(v)))return false;
 }
 const dnsFields=['queries','answers','servfail','private_queries','upstream_attempts','upstream_errors','upstream_timeouts'];
 for(const key of ['dns','private_dns'])if(Object.hasOwn(d,key)&&(!keys(d[key],dnsFields)||!dnsFields.every(k=>number(d[key][k]))))return false;
 return Buffer.byteLength(JSON.stringify(e))<4096;
}
