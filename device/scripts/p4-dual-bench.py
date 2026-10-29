#!/usr/bin/env python3
"""Two P4 RF bench, USB control, automatic STA profile restoration.

Mac Wi-Fi/routes are never modified. In peer mode only CLIENT joins the other
P4 AP; DUT stays on the home uplink. A local Mac receiver verifies the observed
source is DUT's STA (NAT), so local loopback cannot pass as AP+STA forwarding.
Run --restore JOURNAL after interrupted power/process loss before a new run.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import time

BASE = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, BASE / 'scripts' / file)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


perf = module('p4_perf', 'perf-p4-paths.py')
net = module('p4_net', 'p4-net-peer.py')
CATALOG = json.loads((BASE / 'boards/development.json').read_text())
NAMES = dict(stamp='m5_stamp_p4_c6', waveshare='waveshare_esp32_p4_wifi6')


def wait(board, predicate, seconds=65, observe=None):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = board.api('/api/status')
        if observe: observe(last)
        if predicate(last): return last
        time.sleep(1)
    raise TimeoutError('Wi-Fi state deadline: ' + last['wifi']['state'])


def save(path, value):
    tmp = path.with_suffix('.tmp')
    perf.private_json(tmp, value); os.replace(tmp, path)


def wan_transfer(interface):
    """Keep partial bytes/time on failure; only a complete body gets a rate."""
    command = ['/usr/bin/curl', '--noproxy', '*', '-4', '--interface', interface,
               '--connect-timeout', '10', '--max-time', '60', '--max-filesize', '8388608',
               '-fsS', '-o', '/dev/null', '-w', '%{http_code}|%{size_download}|%{time_total}',
               'https://speed.cloudflare.com/__down?bytes=8388608']
    row = dict(complete=False, bytes=0, mbps=None,
               scope='Public CDN; includes home ISP/CDN and client USB limits')
    try:
        result = subprocess.run(command, timeout=65, text=True, capture_output=True)
        row['curl_exit'] = result.returncode
        row['error'] = result.stderr.strip()[:1024] or None
        code, size, seconds = result.stdout.strip().split('|')
        row.update(http_code=int(code), bytes=int(size), seconds=float(seconds))
        row['complete'] = result.returncode == 0 and row['http_code'] == 200 and row['bytes'] == 8388608 and row['seconds'] > 0
        if row['complete']: row['mbps'] = row['bytes'] * 8 / row['seconds'] / 1e6
    except (subprocess.TimeoutExpired, ValueError) as error:
        row['error'] = str(error)[:1024]
    return row


def restore(path, journal):
    board = perf.Board(journal['address'])
    s = board.api('/api/status')
    if s['board'] != journal['board']: raise RuntimeError('Restoration identity mismatch')
    try: board.api('/api/diag/net-bench', {'cancel': True})
    except Exception: pass
    original = journal['original']
    # After a crash during profile creation, infer ownership only from the new
    # id and exact intended SSID. Never delete any pre-existing profile.
    profiles = board.api('/api/wifi/profiles')['profiles']
    owned = [p['id'] for p in profiles if p['id'] not in journal['previous_ids'] and
             p['ssid'] == journal.get('temporary_ssid')]
    board.api('/api/wifi/select', {'pause': True} if original['paused'] else
              {'id': original['profile_id']})
    if not original['paused']:
        wait(board, lambda s: s['wifi']['connected'] and s['wifi']['profile_id'] == original['profile_id'])
    for identifier in owned:
        board.api('/api/wifi/profiles', {'id': identifier, 'delete': True})
    # Select is a one-shot preference, not a persistent pinned/automatic mode.
    # Restore the actual original connection; replaying a previous selection
    # could reconnect a network that had already failed and fallen back.
    journal['restored'] = True; journal['restored_at'] = time.time(); save(path, journal)


def save_link_attempt(out, repeat, direction, row, dut):
    """Keep failed/partial transfers and trace errors before raising/restore."""
    save(out / ('link-' + str(repeat) + '-' + direction + '.json'), row)
    try:
        trace = dut.api('/api/diag/sta-tcp?interface=ap')
    except Exception as e:
        trace = {'available': False, 'error': type(e).__name__ + ': ' + str(e)}
    save(out / ('ap-trace-' + str(repeat) + '-' + direction + '.json'), trace)
    if not row['complete']:
        raise RuntimeError('RF link transfer failed: ' + json.dumps(row))


def run(args):
    profile = CATALOG[NAMES[args.client]]
    other = 'stamp' if args.client == 'waveshare' else 'waveshare'
    dut_profile = CATALOG[NAMES[other]]
    board, dut = perf.Board(profile['usb']), perf.Board(dut_profile['usb'])
    out = Path(args.out); out.mkdir(mode=0o700, parents=False, exist_ok=False)
    path = out / 'restore.json'
    before, dut_before = board.api('/api/status'), dut.api('/api/status')
    for s, expected, name in [(before, NAMES[args.client], profile), (dut_before, NAMES[other], dut_profile)]:
        if s['board'] != expected or s['net']['usb_ip'] != name['usb']:
            raise RuntimeError('Board identity mismatch')
        if s['vpn']['enabled'] or not s['wifi']['connected']:
            raise RuntimeError('Both boards must be connected with VPN off')
    original = {k: before['wifi'][k] for k in ['paused', 'profile_id']}
    profiles = board.api('/api/wifi/profiles')['profiles']
    journal = dict(board=before['board'], address=profile['usb'], original=original,
                   previous_ids=[p['id'] for p in profiles], restored=False,
                   temporary_ssid=dut_before['net']['ap_ssid'] if args.role in ('peer','link','wan') else None)
    save(path, journal)
    perf.private_json(out/'before-client.json', before); perf.private_json(out/'before-dut.json', dut_before)
    peer = None
    try:
        if args.role in ('peer','link','wan'):
            ssid = journal['temporary_ssid']
            existing = [p for p in profiles if p['ssid'] == ssid and p['enabled']]
            if existing:
                board.api('/api/wifi/select', {'id': existing[0]['id']})
            else:
                password = os.environ.get('MESHPN_BENCH_AP_PASSWORD', 'meshpn-test')
                board.api('/api/wifi/profiles', dict(ssid=ssid, password=password, security=1,
                          priority=-999, enabled=True, hidden=False, connect=True))
            def connection_sample(s):
                with open(out/'association.ndjson','a') as f:
                    f.write(json.dumps(dict(at=time.time(),wifi={k:s['wifi'].get(k) for k in
                        ['state','profile_id','ssid','ip','connected','associated','disconnect_reason_name',
                         'association_events','disconnect_events']}))+'\n')
            connected = wait(board, lambda s: s['wifi']['connected'] and s['wifi']['ssid'] == ssid,
                             observe=connection_sample)
            if connected['wifi']['ip'].rsplit('.',1)[0] != dut_before['net']['ap_ip'].rsplit('.',1)[0]:
                raise RuntimeError('Client did not obtain DUT AP subnet')
            time.sleep(5)
        if args.role in ('link','wan'):
            interfaces=json.loads(subprocess.check_output(['node','-e',
                "console.log(JSON.stringify(Object.entries(require('os').networkInterfaces()).flatMap(([name,a])=>a.filter(x=>x.family==='IPv4'&&!x.internal).map(x=>({name,address:x.address})))))"],text=True))
            interfaces=[x for x in interfaces if x['address'].rsplit('.',1)[0]==profile['usb'].rsplit('.',1)[0]]
            if len(interfaces)!=1:raise RuntimeError('Expected exactly one client USB interface')
            interface=interfaces[0];records=[]
            for repeat in range(args.repeats):
                for direction in (['down','up'] if args.role=='link' else ['down']):
                    start=dut.api('/api/status')
                    if args.role=='link':
                        row=dut.transfer(dut_before['net']['ap_ip'],direction,time.monotonic()+60,
                                         source=interface['address'],iface=interface['name'],nodelay=bool(args.nodelay))
                        save_link_attempt(out, repeat, direction, row, dut)
                        if direction=='up' and row['receipt']['link']!='ap':raise RuntimeError('Not AP ingress')
                    else:
                        row = wan_transfer(interface['name'])
                        save(out/('wan-'+str(repeat)+'.json'), row)
                        if not row['complete']: raise RuntimeError('Incomplete WAN response: '+json.dumps(row))
                    if args.role != 'link':
                        save(out/('ap-trace-'+str(repeat)+'-'+direction+'.json'),dut.api('/api/diag/sta-tcp?interface=ap'))
                    finish=dut.api('/api/status')
                    if finish['net']['ap_ip4_rx']<=start['net']['ap_ip4_rx']:raise RuntimeError('No AP ingress')
                    records.append(dict(repeat=repeat,direction=direction,transfer=row,
                        before=perf.clean(start),after=perf.clean(finish),client=perf.clean(board.api('/api/status'))))
                    save(out/'result.json',records)
                    print(json.dumps(dict(role=args.role,client=args.client,dut=other,repeat=repeat,direction=direction,mbps=row['mbps'])),flush=True)
                    time.sleep(args.gap)
            return
        expected_source = dut_before['wifi']['ip'] if args.role == 'peer' else before['wifi']['ip']
        peer = net.Peer(args.host, [expected_source])
        records = []
        for repeat in range(args.repeats):
            for protocol, rate in [('tcp', 8000)] + [('udp', r*1000) for r in args.rates]:
                for direction in ['up', 'down']:
                    before_test = dut.api('/api/status')
                    start = board.api('/api/diag/net-bench', dict(target=args.host, port=peer.port,
                        seconds=args.seconds, rate_kbps=rate, protocol=protocol, direction=direction))
                    nonce = start['nonce']; end = time.monotonic() + args.seconds + 12
                    while time.monotonic() < end:
                        time.sleep(1)
                        status = board.api('/api/diag/net-bench')
                        with open(out/'status.ndjson', 'a') as f:
                            f.write(json.dumps(dict(at=time.time(), nonce=nonce, bench=status,
                                client=perf.clean(board.api('/api/status')),
                                dut=perf.clean(dut.api('/api/status'))))+'\n')
                        if status['nonce'] != nonce: raise RuntimeError('Benchmark superseded')
                        if not status['running']: break
                    if status['running']: raise TimeoutError('Benchmark exceeded bound')
                    time.sleep(1)
                    receipt = peer.snapshot(nonce)
                    after_test = dut.api('/api/status')
                    if status['error'] or not receipt or receipt['source'][0] != expected_source:
                        raise RuntimeError('Data path failed: '+json.dumps(dict(device=status,peer=receipt)))
                    if args.role == 'peer' and after_test['net']['ap_ip4_rx'] <= before_test['net']['ap_ip4_rx']:
                        raise RuntimeError('No DUT AP ingress: invalid path')
                    receiver_bytes = status['bytes'] if direction == 'down' else receipt['bytes']
                    # Fixed request duration, no optimistic first/last-packet rate.
                    row = dict(repeat=repeat, role=args.role, client=args.client, dut=other,
                               protocol=protocol,direction=direction,target_mbps=rate/1000,
                               receiver_mbps=receiver_bytes*8/args.seconds/1e6,
                               device=status,peer=receipt)
                    records.append(row); save(out/'result.json', records)
                    print(json.dumps({k:v for k,v in row.items() if k not in ['device','peer']}),flush=True)
                    time.sleep(args.gap)
    except BaseException as error:
        save(out/'failure.json',dict(error=str(error),at=time.time()))
        for label,api in [('client',board),('dut',dut)]:
            try:
                save(out/('failed-'+label+'.json'),api.api('/api/status'))
                save(out/('failed-'+label+'-ap-trace.json'),api.api('/api/diag/sta-tcp?interface=ap'))
            except Exception: pass
        raise
    finally:
        if peer: peer.close()
        # SIGTERM during cleanup must not skip restoration.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        restore(path, journal)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--client',choices=list(NAMES),default='waveshare')
    p.add_argument('--role',choices=['direct','peer','link','wan'],default='peer')
    p.add_argument('--nodelay',type=int,choices=[0,1],default=1,
                   help='link HTTP download socket TCP_NODELAY; 0 allows coalescing; not a radio setting')
    p.add_argument('--host');p.add_argument('--out')
    p.add_argument('--seconds',type=int,default=10);p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--rates',type=int,nargs='*',default=[4,8,12,16,20,24,32])
    p.add_argument('--gap',type=float,default=2)
    p.add_argument('--restore',type=Path)
    a=p.parse_args()
    if not 1<=a.seconds<=60 or not 1<=a.repeats<=100 or any(r<1 or r>32 for r in a.rates) or not 0<=a.gap<=60:
        p.error('bounded seconds/repeats/rates/gap required')
    if not a.restore and (not a.out or (a.role in ('peer','direct') and not a.host)):p.error('--host and --out required')
    lock=BASE/'perf-results'/'dual-bench.lock'
    with open(lock,'a') as f:
        fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.restore:restore(a.restore,json.loads(a.restore.read_text()));return
        for path in (BASE/'perf-results').glob('*/restore.json'):
            if not json.loads(path.read_text()).get('restored'):
                raise RuntimeError('Restore previous run first: '+str(path))
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        os.umask(0o077)
        run(a)


if __name__=='__main__':main()
