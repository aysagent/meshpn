#!/usr/bin/env python3
"""Opt-in real Linux netns capture test. Run only in a disposable privileged container."""
import os,fcntl,struct,subprocess,socket,time,json,pathlib,tempfile
helper=str(pathlib.Path(__file__).with_name('clean-vpn-native-dns-capture.py'))
parent=os.readlink('/proc/self/ns/net')
if '--inside' not in __import__('sys').argv:
 r=subprocess.run(['unshare','--net','python3',__file__,'--inside',parent]);raise SystemExit(r.returncode)
parent=__import__('sys').argv[-1]
fd=os.open('/dev/net/tun',os.O_RDWR);fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',b'cvpw0',0x1001))
for cmd in [['ip','link','set','lo','up'],['ip','addr','add','10.99.0.1/24','dev','cvpw0'],['ip','link','set','cvpw0','up']]:subprocess.run(cmd,check=True)
d=tempfile.mkdtemp();os.chmod(d,0o700)
p=subprocess.Popen(['python3',helper,'--parent-netns',parent,'--directory',d,'--seconds','3'],stdout=subprocess.PIPE,text=True)
assert 'dns_capture_ready' in p.stdout.readline()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('127.0.0.1',1055))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'fixture',('127.0.0.1',1055));q,a=u.recvfrom(100);u.sendto(q,a)
s.sendto(b'fixture',('10.99.0.2',1055));s.sendto(b'excluded',('10.99.0.2',53))
t=socket.socket();t.bind(('127.0.0.1',1055));t.listen();c=socket.socket();c.connect(t.getsockname());a,_=t.accept();c.sendall(b'fixture');a.recv(100);a.close();c.close();t.close()
out=p.communicate(timeout=8)[0];assert p.returncode==0;print(out.strip())
for name in ['lo','cvpw0']:
 b=pathlib.Path(d,name+'.pcap').read_bytes();assert struct.unpack('<I',b[20:24])[0]==101;n=0;at=24;protocols=set()
 while at<len(b):
  secs,usecs,inc,orig=struct.unpack('<IIII',b[at:at+16]);at+=16;pkt=b[at:at+inc];at+=inc;assert inc==orig;ihl=(pkt[0]&15)*4;ports=struct.unpack('!HH',pkt[ihl:ihl+4]);assert 1055 in ports;protocols.add(pkt[9]);n+=1
 assert n>0
 if name=='lo':assert protocols=={6,17}
 print(json.dumps({'interface':name,'packets':n,'protocols':sorted(protocols),'mode':oct(pathlib.Path(d,name+'.pcap').stat().st_mode&511)}))
# Refusal must happen before opening files in original PID1 namespace.
r=subprocess.run(['python3',helper,'--parent-netns',os.readlink('/proc/self/ns/net'),'--directory',d],capture_output=True,text=True);assert r.returncode and 'host_namespace_refused' in r.stderr
print('REAL_CAPTURE_PASS')
