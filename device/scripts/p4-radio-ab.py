#!/usr/bin/env python3
"""Frozen A/B/A P4 radio builds, MAC-bound flash and profile recovery.
Default is an offline plan. --execute is explicit; never changes Mac networking.
Run from an activated ESP-IDF 5.5.5 environment for execution (not planning).
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[1]

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, BASE/'scripts'/file)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

dual = module('radio_ab_dual', 'p4-dual-bench.py')
flash = module('radio_ab_flash', 'flash-device.py')
FLAG = 'CONFIG_MESHVPN_P4_STA_DISABLE_11AX'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def bound_usb_mac(binding):
    # Same derivation as meshvpn_net.c, from NCM's ESP_MAC_ETH serial.
    mac = bytearray.fromhex(binding['serial']);mac[0] |= 2;mac[5] = (mac[5]+1)&255
    return ':'.join(f'{v:02x}' for v in mac)

def config(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1); values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]] = 'n'
    return values

def artifact(path, board):
    path = Path(path).resolve()
    identity = json.loads((path/'meshvpn-board.json').read_text())
    if identity != dict(board=board, target='esp32p4', profile='ncm'):
        raise ValueError('Build identity mismatch: '+str(path))
    flash.preflight_p4_build(path)
    words = shlex.split((path/'flash_args').read_text())
    files = ['sdkconfig', 'meshvpn-board.json', 'flash_args', 'flasher_args.json', 'project_description.json']
    for i, word in enumerate(words):
        if word.startswith('0x'):
            int(word, 16)
            file = (path/words[i+1]).resolve()
            # Frozen artifacts must be self-contained, no external mutable bins.
            files.append(str(file.relative_to(path)))
    if 'meshvpn_device.bin' not in files: raise ValueError('Missing app in flash_args')
    return dict(path=str(path), files={f:digest(path/f) for f in files})

def verify(item):
    for file, sha in item['files'].items():
        if digest(Path(item['path'])/file) != sha: raise RuntimeError('Frozen build changed: '+file)

def freeze(item, destination):
    verify(item)
    for file in item['files']:
        target=destination/file;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(Path(item['path'])/file,target)
    frozen=dict(item,path=str(destination));verify(frozen);return frozen

def plan(args):
    board = dual.NAMES[args.client]
    a, b = artifact(args.a_build, board), artifact(args.b_build, board)
    ac, bc = config(Path(a['path'])/'sdkconfig'), config(Path(b['path'])/'sdkconfig')
    changed = {k for k in ac.keys() | bc.keys() if ac.get(k) != bc.get(k)}
    if changed != {FLAG} or ac.get(FLAG) != 'n' or bc.get(FLAG) != 'y':
        raise ValueError('A/B must differ only in STA_DISABLE_11AX: A=n, B=y; got '+str(sorted(changed)))
    descriptions = [json.loads((Path(x['path'])/'project_description.json').read_text()) for x in (a,b)]
    # IDF 5.5 project_description calls its SDK version git_revision (not idf_ver).
    if any(not descriptions[0].get(k) or descriptions[0].get(k) != descriptions[1].get(k) for k in ('project_version','git_revision')):
        raise ValueError('A/B project/SDK versions differ; build from one checkout')
    return dict(schema=1, client=args.client, board=board, a=a, b=b,
                radio_interface=args.radio_interface, seconds=args.seconds, rates=args.rates,
                repeats=args.repeats, phases=['A1','B','A2'], restored=False,
                scope='P4-generated radio peer; not phone internet or AP+STA forwarding')

def run_flash_command(cmd):
    # A deadline must stop esptool too, before a recovery flash opens the port.
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        stdout,stderr=p.communicate(timeout=180)
        return subprocess.CompletedProcess(cmd,p.returncode,stdout,stderr)
    except BaseException:
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGKILL);p.communicate()
        raise

def flash_build(journal, item, out, label):
    verify(item)
    current = flash.load_binding(flash.binding_path(BASE, journal['board']), 'esp32p4', journal['board'])
    if current != journal['binding']: raise RuntimeError('Board binding changed during experiment')
    cmd = [sys.executable, str(BASE/'scripts/flash-device.py'), '--device-dir', str(BASE),
           '--build-dir', item['path'], '--board', journal['board'], '--target','esp32p4','--profile','ncm']
    # Only a busy port is retried; identity/security failures never pick another port.
    for attempt in range(21):
        result = run_flash_command(cmd)
        (out/f'{label}-flash-{attempt}.log').write_text(result.stdout+result.stderr)
        if result.returncode == 0: return
        busy = 'resource busy' in (result.stdout+result.stderr).lower()
        if not busy or attempt == 20: raise RuntimeError(f'{label} flash failed; see saved log')
        time.sleep(30)

def select_original(journal):
    board = dual.perf.Board(journal['address'])
    state = board.api('/api/status')
    if state['board'] != journal['board'] or dual.usb_identity(state) != journal['usb_mac']:
        raise RuntimeError('API board/MAC mismatch after flash')
    board.api('/api/wifi/select', {'id':journal['original_profile']})
    dual.wait(board, lambda s: s['wifi']['connected'] and s['wifi']['profile_id']==journal['original_profile'], seconds=90)
    return board

def recover(journal, out, flash_fn=flash_build, select_fn=select_original):
    # Baseline firmware first; unfinished child journal then removes only owned profiles.
    flash_fn(journal, journal['a'], out, 'restore-A')
    for path in dual.pending_journals(out): dual.restore(path, json.loads(path.read_text()))
    board = select_fn(journal)
    state = board.api('/api/status')
    if state['vpn']['enabled']: raise RuntimeError('VPN enabled during experiment; refusing to overwrite its settings')
    dual.save(out/'restored-status.json', dual.perf.clean(state))
    journal['restored'] = True; dual.save(out/'radio-ab.json', journal)

def summarize(out):
    groups = {}
    for phase in ('A1','B','A2'):
        file = out/phase/'result.json'
        if not file.exists(): continue
        for r in json.loads(file.read_text()):
            key = (phase,r['protocol'],r['direction'],r.get('target_mbps'))
            g = groups.setdefault(key,dict(successful=0,failed=0,rates=[]))
            if r.get('complete') and isinstance(r.get('receiver_mbps'),(int,float)):
                g['successful']+=1;g['rates'].append(r['receiver_mbps'])
            else:g['failed']+=1
    return [dict(phase=k[0],protocol=k[1],direction=k[2],target_mbps=k[3],successful=v['successful'],failed=v['failed'],
                 receiver_median=statistics.median(v['rates']) if v['rates'] else None) for k,v in groups.items()]

def comparisons(rows, repeats):
    groups={}
    for row in rows:
        key=(row['protocol'],row['direction'],row['target_mbps'])
        groups.setdefault(key,{})[row['phase']]=row
    out=[]
    for key,phases in groups.items():
        eligible=repeats>=3 and all(p in phases and phases[p]['successful']==repeats and
            not phases[p]['failed'] and phases[p]['receiver_median']>0 for p in ('A1','B','A2'))
        out.append(dict(protocol=key[0],direction=key[1],target_mbps=key[2],eligible=eligible,
            b_over_a1=phases['B']['receiver_median']/phases['A1']['receiver_median'] if eligible else None,
            a2_over_a1=phases['A2']['receiver_median']/phases['A1']['receiver_median'] if eligible else None,
            note='Check A2/A1 for drift; ratios are not proof of causation' if eligible else 'Incomplete/failed phases or fewer than three repeats; no improvement claim'))
    return out

def run(journal, out, lock, flash_fn=flash_build, bench_fn=None):
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    journal['a']=freeze(journal['a'],out/'frozen-A')
    journal['b']=freeze(journal['b'],out/'frozen-B')
    profile = dual.CATALOG[journal['board']]
    journal['binding'] = flash.load_binding(flash.binding_path(BASE,journal['board']),'esp32p4',journal['board'])
    before = dual.perf.Board(profile['usb']).api('/api/status')
    if before['board']!=journal['board'] or dual.usb_identity(before)!=bound_usb_mac(journal['binding']) or before['vpn']['enabled'] or not before['wifi']['connected']:
        raise RuntimeError('Client must match board, have USB MAC, home Wi-Fi connected and VPN off')
    # Check the other board before disturbing either one's USB.
    other = dual.NAMES['stamp' if journal['client']=='waveshare' else 'waveshare']
    peer = dual.perf.Board(dual.CATALOG[other]['usb']).api('/api/status')
    peer_binding=flash.load_binding(flash.binding_path(BASE,other),'esp32p4',other)
    if peer['board']!=other or dual.usb_identity(peer)!=bound_usb_mac(peer_binding) or peer['vpn']['enabled'] or not peer['wifi']['connected']:
        raise RuntimeError('Peer board must be online with VPN off')
    journal.update(address=profile['usb'],usb_mac=dual.usb_identity(before),peer_usb_mac=dual.usb_identity(peer),original_profile=before['wifi']['profile_id'])
    dual.save(out/'radio-ab.json',journal)
    dual.save(out/'before.json',dual.perf.clean(before))
    try:
        for phase in journal['phases']:
            journal['phase']=phase;dual.save(out/'radio-ab.json',journal)
            item=journal['b'] if phase=='B' else journal['a']
            flash_fn(journal,item,out,phase)
            board=select_original(journal)
            status=board.api('/api/status')
            protocol=status['wifi']['radio']['sta_protocol']
            if not protocol.get('available') or protocol.get('802_11ax') != (phase!='B'):
                raise RuntimeError('C6 protocol readback does not match phase '+phase)
            cmd=[sys.executable,str(BASE/'scripts/p4-dual-bench.py'),'--client',journal['client'],'--role','radio',
                 '--expected-client-mac',journal['usb_mac'],'--expected-dut-mac',journal['peer_usb_mac'],
                 '--radio-interface',journal['radio_interface'],'--protocols','udp','--seconds',str(journal['seconds']),
                 '--rates',*[str(v) for v in journal['rates']],'--repeats',str(journal['repeats']),'--out',str(out/phase)]
            env=dict(os.environ,MESHPN_DUAL_LOCK_FD=str(lock.fileno()))
            with (out/(phase+'-bench.log')).open('w') as log:
                if bench_fn: bench_fn(cmd)
                else: subprocess.run(cmd,env=env,pass_fds=(lock.fileno(),),stdout=log,stderr=subprocess.STDOUT,check=True,
                                     timeout=journal['repeats']*len(journal['rates'])*2*(journal['seconds']+20)+240)
    except BaseException as error:
        journal['error']=type(error).__name__+': '+str(error);raise
    finally:
        signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
        try: recover(journal,out,flash_fn)
        except BaseException as error: journal['restore_error']=str(error);journal['restored']=False;raise
        finally:
            dual.save(out/'radio-ab.json',journal)
            rows=summarize(out)
            dual.save(out/'summary.json',dict(runs=rows,comparisons=comparisons(rows,journal['repeats'])))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--client',choices=['stamp','waveshare'],default='waveshare')
    p.add_argument('--a-build',type=Path);p.add_argument('--b-build',type=Path)
    p.add_argument('--out',type=Path);p.add_argument('--execute',action='store_true')
    p.add_argument('--restore',type=Path)
    p.add_argument('--radio-interface',choices=['sta','ap'],default='sta')
    p.add_argument('--seconds',type=int,default=5);p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--rates',type=int,nargs='+',default=[1,4,8,12,16])
    args=p.parse_args()
    if not 1<=args.seconds<=60 or not 1<=args.repeats<=10 or not args.rates or any(v<1 or v>32 for v in args.rates):p.error('Invalid bounded test parameters')
    if args.restore:
        out=args.restore.resolve().parent;j=json.loads(args.restore.read_text())
    else:
        if not args.a_build or not args.b_build:p.error('--a-build and --b-build required')
        j=plan(args)
        if not args.execute:print(json.dumps(j,indent=2));return
        if not args.out:p.error('--out required with --execute')
        out=args.out.resolve()
    if not out.is_relative_to((BASE/'perf-results').resolve()):
        p.error('Execution/recovery artifacts must be under device/perf-results for crash discovery')
    # flash-device imports serial only on execution. No SDK/USB/network needed for planning.
    os.umask(0o077)
    with dual.acquire_lock(BASE/'perf-results'/'dual-bench.lock') as lock:
        if args.restore:recover(j,out);return
        pending=list(dual.pending_journals(BASE/'perf-results'))
        pending += list(dual.pending_ab_journals(BASE/'perf-results'))
        if pending:raise RuntimeError('Restore previous run first: '+str(pending[0]))
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        run(j,out,lock)

if __name__=='__main__':main()
