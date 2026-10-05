/** Fixed-vocabulary metadata only. No raw stderr/argv/headers/packet bodies. */
const states = new Set(`starting idle listening connecting handshake ready uplink_ready waiting_uplink stopped dns_failed
cancelled connect_deadline poll connect_socket connect accept tcp_nodelay tls_socket tls_sni tls_identity tls_handshake
tls_verify_name tls_verify_expired tls_verify_not_yet_valid tls_verify_untrusted tls_verify_failed
h2_callback_failure h2_send_callback_failure h2_goaway_no_error h2_goaway_error h2_reset_no_error h2_reset_error
h2_peer_end_stream h2_invalid_frame h2_stream_closed h2_stream_error tls_peer_closed h2_flooded h2_no_memory h2_bad_client_magic
h2_local_goaway_error h2_local_reset_error
h2_required exporter hmac http2_error unexpected_headers headers_limit duplicate_header request_invalid auth_rejected
early_end vpn_response_rejected data_before_auth peer_address session_rejected_or_closed auth_deadline h2_ping_timeout
random tls_write tls_read http2_receive tun_write tun_read invalid_ipv4 invalid_frame_length queue_limit queue_consume`.split(/\s+/));
const markers = new Map([
  ['native-control: preparing protected USB profile', 'profile_preparing'],
  ['native-control: profile preflight complete', 'profile_preflight_complete'],
  ['native-control: engine spawned', 'engine_spawned'],
  ['native-control: owned routes ready', 'routes_ready'],
  ['native-control: DNS guard/routes ready', 'dns_guard_ready'],
  ['native-control: DNS active', 'dns_active'],
]);
const fields = ['version', 'event', 'state', 'generation', 'tx_packets', 'rx_packets', 'dropped_packets'];
export function trialDiagnostics(now = () => performance.now()) {
  const started = now(), events = [], stages = [];
  let omittedEvents = 0, lastState = null, readySeen = false;
  const atMs = () => Math.max(0, Math.round(now() - started));
  return {
    state(value) {
      if (!value || Array.isArray(value) || Object.keys(value).length !== fields.length
        || fields.some(k => !(k in value)) || value.version !== 1 || !['state', 'status'].includes(value.event)
        || typeof value.state !== 'string' || !/^[a-z0-9_]{1,64}$/.test(value.state)
        || fields.slice(3).some(k => !Number.isSafeInteger(value[k]) || value[k] < 0)) throw Error('invalid_native_status');
      lastState = states.has(value.state) ? value.state : 'unknown';
      readySeen ||= lastState === 'ready';
      events.push({ atMs: atMs(), event: value.event, state: lastState, generation: value.generation,
        txPackets: value.tx_packets, rxPackets: value.rx_packets, droppedPackets: value.dropped_packets });
      if (events.length > 48) { events.shift(); omittedEvents++; }
      return lastState;
    },
    stderrLine(line) {
      const stage = markers.get(line);
      if (stage && !stages.some(s => s.stage === stage)) stages.push({ atMs: atMs(), stage });
      return stage;
    },
    snapshot() { return { lastState, readySeen, omittedEvents,
      events: events.map(e => ({ ...e })), stages: stages.map(s => ({ ...s })) }; },
  };
}
