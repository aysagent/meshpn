#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import re
import socket
import subprocess
import tempfile
base=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('peer',base/'scripts/p4-net-peer.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='meshpn-bench-') as tmp:
    source=(base/'components/meshvpn_net/meshvpn_net_bench.c').read_text()
    Path(tmp,'bench-production.inc').write_text(re.sub(r'^#include .*$', '', source, flags=re.M))
    binary=str(Path(tmp,'test'))
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-pthread',
        '-I'+tmp,'-I'+str(base/'tests/stubs'),'-I'+str(base/'components/meshvpn_net/include'),
        str(base/'tests/test_net_bench.c'),'-o',binary],check=True)
    peer=m.Peer('127.0.0.1',['127.0.0.1'])
    # Listener cases use distinct ephemeral ports. Reserve the range first.
    held=[]
    for attempt in range(100):
        for s in held:s.close()
        held=[]
        probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
        if port>65527:continue
        try:
            for offset in range(1,9):
                s=socket.socket();held.append(s);s.bind(('127.0.0.1',port+offset))
            break
        except OSError:continue
    else:raise RuntimeError('No free local port range for bounded listener tests')
    for s in held:s.close()
    try:subprocess.run([binary,str(peer.port),str(port)],check=True,timeout=40)
    finally:peer.close()
