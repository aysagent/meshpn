# Based on lwip-tcpip/lwip PR110's deterministic harness, commit
# 580d4e7f34ba3685e59da99e834ba976274ce150 (BSD; COPYING).
# Exercise the actual ESP-IDF TCP sources; do not modify the SDK checkout.
from pathlib import Path
import subprocess,tempfile,shutil,os
here=Path(__file__).resolve().parent
source=Path(os.environ.get('IDF_PATH','/Users/yurich/esp/esp-idf-meshpn-v5.5.5'))/'components/lwip/lwip/src'
for enabled,burst in ((0,0),(1,0),(1,1)):
 with tempfile.TemporaryDirectory(prefix='meshpn-sack-core-') as tmp:
  root=Path(tmp);shutil.copytree(source,root/'src')
  if enabled:
   for name in ['tcp_in.c','tcp_out.c','tcp.c']:
    path=root/'src/core'/name
    if name=='tcp_in.c':subprocess.run(['python3',str(here.parent/'patch.py'),str(path),str(path)],check=True)
    subprocess.run(['python3',str(here.parent/'partial.py'),str(path),str(path)],check=True)
    if burst and name!='tcp.c':subprocess.run(['python3',str(here.parent/'burst.py'),str(path),str(path)],check=True)
  files=list((root/'src/core').glob('*.c'))+list((root/'src/core/ipv4').glob('*.c'))+[root/'src/netif/ethernet.c']
  exe=root/'test'
  subprocess.run(['cc','-std=c99','-O0','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',f'-DLWIP_TCP_PARTIAL_ACK_RECOVERY={enabled}',f'-DMESHPN_EXPERIMENT_BURST={burst}','-I'+str(here),'-I'+str(root/'src/include'),str(here/'recovery.c'),*map(str,files),'-o',str(exe)],check=True)
  subprocess.run([str(exe)],check=True,timeout=15)
