export const wifiTxCounterFields = ['calls','copy_calls','ref_calls','accepted','bytes_accepted',
  'no_mem','invalid_arg','not_ready','tx_disallow','post_failed','other_error','call_us',
  'call_le_100us','call_100_1000us','call_1_5ms','call_gt_5ms'];

const pick=(v,keys)=>Object.fromEntries(keys.filter(k=>v?.[k]!==undefined).map(k=>[k,v[k]]));
export function cleanWifiDiagnostics(wifi) {
  const r=wifi?.radio;
  return {
    tx:{...pick(wifi?.tx,['available','buffer_type','static_buffer_count','dynamic_buffer_count','cache_buffer_count','amsdu_enabled',
      'ampdu_enabled','ampdu_ba_window','ampdu_rx_enabled','ampdu_rx_ba_window','iram_opt_enabled',
      'extra_iram_opt_enabled','rx_iram_opt_enabled','lwip_iram_opt_enabled']),...Object.fromEntries(['sta','ap'].map(k=>
      [k,pick(wifi?.tx?.[k],[...wifiTxCounterFields,'call_max_us','last_error'])]))},
    radio:{...pick(r,['sampled_us','primary_channel','secondary_channel','power_save',
      'sta_bandwidth_mhz','ap_bandwidth_mhz','clients_available']),
      uplink:pick(r?.uplink,['available','rssi','primary_channel','secondary_channel','phy_11n']),
      clients:(Array.isArray(r?.clients)?r.clients:[]).slice(0,10).map(c=>
        pick(c,['index','rssi','phy_11b','phy_11g','phy_11n','phy_lr']))}
  };
}

export function validateWifiTxExperiment(tx) {
  if(!tx?.available)return 'AP upload diagnostics require Wi-Fi TX telemetry; flash current firmware first.';
  if(tx.buffer_type!=='static'||tx.static_buffer_count!==24||tx.cache_buffer_count!==128||tx.amsdu_enabled!==false||
    tx.ampdu_enabled!==true||tx.ampdu_ba_window!==12||tx.ampdu_rx_enabled!==true||tx.ampdu_rx_ba_window!==24||
    tx.iram_opt_enabled!==true||tx.extra_iram_opt_enabled!==true||tx.rx_iram_opt_enabled!==true||tx.lwip_iram_opt_enabled!==true)
    return `AP extra-IRAM A/B requires Wi-Fi TX static=24, cache=128, A-MSDU=false, A-MPDU TX/RX=true, BA=12/24, IRAM Wi-Fi/extra/RX/lwIP=true; got type=${tx.buffer_type??'n/a'}, static=${tx.static_buffer_count??'n/a'}, cache=${tx.cache_buffer_count??'n/a'}, A-MSDU=${tx.amsdu_enabled??'n/a'}, A-MPDU TX/RX=${tx.ampdu_enabled??'n/a'}/${tx.ampdu_rx_enabled??'n/a'}, BA=${tx.ampdu_ba_window??'n/a'}/${tx.ampdu_rx_ba_window??'n/a'}, IRAM=${tx.iram_opt_enabled??'n/a'}/${tx.extra_iram_opt_enabled??'n/a'}/${tx.rx_iram_opt_enabled??'n/a'}/${tx.lwip_iram_opt_enabled??'n/a'}. Flash current firmware first.`;
  return null;
}

export function wifiMarkdown(records) {
  if(!records.some(r=>r.batch_wifi?.after?.tx?.available||
    Number.isFinite(r.batch_counters?.['wifi.tx.sta.calls'])))return [];
  const batches=[...new Map(records.map(r=>[r.id,r])).values()];
  const f=v=>Number.isFinite(v)?v.toFixed(2):'n/a';
  const n=v=>Number.isFinite(v)?String(v):'n/a';
  const lines=['','## Wi-Fi driver handoff by batch','',
    'STA TX = board → router; AP TX = board → AP client. Device-wide completed API calls, including admin/ACK traffic; not radio delivery, MAC retries, or flow-specific packet loss. Both copy/reference paths are instrumented. Timing includes driver call and scheduling, excludes later radio work; instrumentation adds overhead. Histograms are disjoint; missing/reset windows remain n/a. Lifetime maxima/last errors are retained only in status snapshots.','',
    '| Test | Interface | Calls | Accepted | No memory | Not ready | Disallowed | Post failed | Invalid / other | Mean µs | ≤100µs / 100–1000µs / 1–5ms / >5ms |',
    '|---|---|---:|---:|---:|---:|---:|---:|---|---:|---|'];
  const config=batches.map(r=>r.batch_wifi?.after?.tx).find(t=>t?.available);
  if(config)lines.splice(3,0,`TX buffers: type=${config.buffer_type??'n/a'}, static=${n(config.static_buffer_count)}, dynamic=${n(config.dynamic_buffer_count)}, cache=${n(config.cache_buffer_count)}, A-MSDU=${typeof config.amsdu_enabled==='boolean'?config.amsdu_enabled:'n/a'}, A-MPDU TX/RX=${typeof config.ampdu_enabled==='boolean'?config.ampdu_enabled:'n/a'}/${typeof config.ampdu_rx_enabled==='boolean'?config.ampdu_rx_enabled:'n/a'}, BA=${n(config.ampdu_ba_window)}/${n(config.ampdu_rx_ba_window)}, IRAM Wi-Fi/extra/RX/lwIP=${['iram_opt_enabled','extra_iram_opt_enabled','rx_iram_opt_enabled','lwip_iram_opt_enabled'].map(k=>typeof config[k]==='boolean'?config[k]:'n/a').join('/')}.`,'');
  for(const r of batches)for(const iface of ['sta','ap']) {
    const v=k=>r.batch_counters?.[`wifi.tx.${iface}.${k}`];
    lines.push(`| ${r.id} | ${iface} | ${n(v('calls'))} | ${n(v('accepted'))} | ${n(v('no_mem'))} | ${n(v('not_ready'))} | ${n(v('tx_disallow'))} | ${n(v('post_failed'))} | ${n(v('invalid_arg'))} / ${n(v('other_error'))} | ${f(Number.isFinite(v('call_us'))&&v('calls')>0?v('call_us')/v('calls'):null)} | ${['call_le_100us','call_100_1000us','call_1_5ms','call_gt_5ms'].map(k=>n(v(k))).join(' / ')} |`);
  }
  lines.push('','## Wi-Fi radio snapshots','',
    'After each batch (before/after retained in JSON; periodic samples in status.ndjson). Bandwidth is the interface API value, NOT per-packet negotiated width. Secondary channel: 0=none, 1=above, 2=below. Peer PHY flags are capabilities, NOT current MCS/rate. Client indices are snapshot-local, not stable identities. No scans or settings changes.','',
    '| Test | Channel / secondary | STA / AP MHz | Power save enum | Uplink RSSI dBm | AP clients: index, RSSI dBm, 11n |',
    '|---|---|---|---|---:|---|');
  for(const r of batches) {
    const s=r.batch_wifi?.after?.radio;
    const peers=s?.clients_available?s.clients.map(c=>`${n(c.index)}: ${n(c.rssi)}, ${typeof c.phy_11n==='boolean'?c.phy_11n:'n/a'}`).join('; ')||'none':'n/a';
    lines.push(`| ${r.id} | ${n(s?.primary_channel)} / ${n(s?.secondary_channel)} | ${n(s?.sta_bandwidth_mhz)} / ${n(s?.ap_bandwidth_mhz)} | ${n(s?.power_save)} | ${n(s?.uplink?.available?s.uplink.rssi:null)} | ${peers} |`);
  }
  return lines;
}
