#!/usr/bin/env python3
"""Static evidence only: individual stack frames are not call-chain peaks."""
import json,pathlib,subprocess,sys
build,out=map(pathlib.Path,sys.argv[1:]);desc=json.loads((build/'project_description.json').read_text())
rows=[]
for p in build.rglob('*.su'):
    for line in p.read_text().splitlines():
        a=line.rsplit('\t',2)
        if len(a)==3 and a[1].isdigit(): rows.append({'symbol_location':a[0],'frame_bytes':int(a[1]),'kind':a[2]})
rows.sort(key=lambda r:r['frame_bytes'],reverse=True)
nm = 'xtensa-esp32s3-elf-nm' if desc['target']=='esp32s3' else 'riscv32-esp-elf-nm'
symbols = subprocess.check_output([nm, '-C', '--defined-only', str(build/'meshpn_tls_feasibility.elf')], text=True).splitlines()
client_frames = {}
for name in ['encrypt_cpa<3', 'mlkem_decap_no_self_test<3', 'X25519MLKEM768KeyShare::Generate']:
    def matches_frame(row):
        symbol = row['symbol_location']
        if name.endswith('<3'):
            return name[:-2]+'(' in symbol and '[with int RANK = 3]' in symbol
        return name in symbol
    client_frames[name] = {
        'compiled_frames': [r for r in rows if matches_frame(r)],
        'linked_symbol_evidence': [line for line in symbols if name in line],
    }
result={'target':desc['target'],'scope':'Standalone image, not product delta; compiled stack frames include potentially unlinked functions, exclude callees, dynamic heap and concurrent tasks',
 'binary_bytes':(build/'meshpn_tls_feasibility.bin').stat().st_size,'largest_compiled_frames':rows[:30],
 'mlkem_client_frames':client_frames}
out.write_text(json.dumps(result,indent=2)+'\n')
