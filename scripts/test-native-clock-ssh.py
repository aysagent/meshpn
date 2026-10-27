"""Disposable Linux container test: real SSH/pinning/restrictions, no clock set.

Run only in an isolated container with OpenSSH server and its usual setuid/
setgid capabilities; no NET_ADMIN or SYS_TIME. The forced command is a fixture
clock protocol server. Production serve()'s NTP gate has separate unit tests.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

spec=importlib.util.spec_from_file_location('clock',Path(__file__).with_name('clean-vpn-native-clock.py'))
clock=importlib.util.module_from_spec(spec);spec.loader.exec_module(clock)

class SshTests(unittest.TestCase):
    def setUp(self):
        if os.environ.get('CVPN_DISPOSABLE_CLOCK_SSH_LAB')!='1' or sys.platform!='linux' or os.geteuid()!=0:
            self.fail('Run in disposable Linux container with CVPN_DISPOSABLE_CLOCK_SSH_LAB=1, not on a host')
        # This image locks root entirely. Permit public-key-only fixture login;
        # '*' is not a usable password and sshd also disables password auth.
        subprocess.run(['/usr/sbin/usermod','--password','*','root'],check=True)
        self.tmp=tempfile.TemporaryDirectory(prefix='cvpn-clock-ssh-',dir='/root');self.addCleanup(self.tmp.cleanup)
        d=Path(self.tmp.name);self.dir=d
        for name in ['host','identity','wrong']:
            subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(d/name)],check=True)
        s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
        (d/'server.py').write_text('''import json,os,sys,time
if os.environ.get('SSH_ORIGINAL_COMMAND') != 'clean-vpn-clock-v1': sys.exit(1)
nonce=sys.stdin.readline(128).strip()
print(json.dumps(dict(version=1,nonce=nonce,unix_seconds=int(time.time()),synchronized=True)))
''')
        (d/'authorized').write_text('restrict,command="/usr/bin/python3 -I '+str(d/'server.py')+'" '+(d/'identity.pub').read_text())
        os.chmod(d/'authorized',0o600)
        (d/'known').write_text('clean-vpn-clock '+ ' '.join((d/'host.pub').read_text().split()[:2])+'\n');os.chmod(d/'known',0o600)
        self.c=dict(version=1,host='127.0.0.1',port=port,user='root',identity=str(d/'identity'),known_hosts=str(d/'known'),state_dir=str(d/'state'),consumer_unit='clean-vpn.service')
        # /run/sshd is inside the explicitly disposable container only.
        Path('/run/sshd').mkdir(mode=0o755,exist_ok=True)
        config=d/'sshd.conf'
        config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {d}/host
PidFile {d}/pid
AuthorizedKeysFile {d}/authorized
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin forced-commands-only
AllowUsers root
UseDNS no
LogLevel VERBOSE
''')
        subprocess.run(['/usr/sbin/sshd','-t','-f',str(config)],check=True)
        log=open(d/'sshd.log','w');self.addCleanup(log.close)
        self.server=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(config)],stdout=log,stderr=log)
        def cleanup():
            self.server.terminate();self.server.wait(timeout=5)
        self.addCleanup(cleanup)
        deadline=time.monotonic()+3
        while True:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:
                if time.monotonic()>deadline:self.fail((d/'sshd.log').read_text())
                time.sleep(.02)

    def test_fresh_response_over_pinned_ssh(self):
        try:
            report=clock.probe(clock.validate_config(self.c))
        except Exception:
            print((self.dir/'sshd.log').read_text(),file=sys.stderr)
            raise
        self.assertFalse(report['needsCorrection']);self.assertEqual(report['trustedFloor'],0)
        self.assertFalse((self.dir/'state').exists(),'probe must not write state')

    def test_wrong_pin_and_wrong_identity_rejected(self):
        original=(self.dir/'known').read_bytes()
        (self.dir/'known').write_text('clean-vpn-clock '+' '.join((self.dir/'wrong.pub').read_text().split()[:2])+'\n')
        with self.assertRaisesRegex(ValueError,'authenticated_clock_query_failed'):clock.probe(self.c)
        (self.dir/'known').write_bytes(original)
        with self.assertRaisesRegex(ValueError,'authenticated_clock_query_failed'):clock.probe({**self.c,'identity':str(self.dir/'wrong')})

    def test_key_cannot_execute_shell_command_or_forward(self):
        args=clock.ssh_args(self.c);args[-1]='touch '+str(self.dir/'unexpected')
        result=subprocess.run(args,input=b'a'*64+b'\n',capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertFalse((self.dir/'unexpected').exists())
        args=clock.ssh_args(self.c)
        args[-2:-2]=['-W',f'127.0.0.1:{self.c["port"]}'];args.pop()
        result=subprocess.run(args,input=b'',capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertIn(b'administratively prohibited',result.stderr)

    def test_stale_nonce_unsynchronized_and_oversized_reply_rejected(self):
        original=(self.dir/'server.py').read_text()
        for old,new,reason in [
            ('nonce=nonce','nonce="b"*64','clock_nonce_or_version_mismatch'),
            ('synchronized=True','synchronized=False','exit_clock_not_synchronized'),
        ]:
            (self.dir/'server.py').write_text(original.replace(old,new))
            with self.assertRaisesRegex(ValueError,reason):clock.probe(self.c)
        (self.dir/'server.py').write_text('print("x"*1024)\n')
        with self.assertRaisesRegex(ValueError,'clock_response_too_large'):clock.probe(self.c)

if __name__=='__main__':unittest.main()
