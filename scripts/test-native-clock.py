"""Clock control policy tests; never change the host clock or invoke real SSH."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('clock', Path(__file__).with_name('clean-vpn-native-clock.py'))
clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)

class ClockTests(unittest.TestCase):
    nonce = 'a' * 64
    epoch = 1793100000
    boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cvpn-clock-')
        self.addCleanup(self.tmp.cleanup)
        self.c = {'state_dir': str(Path(self.tmp.name).resolve()), 'consumer_unit': 'clean-vpn.service'}
        os.chmod(self.c['state_dir'], 0o700)

    def test_update_lock_blocks_competing_update_and_pending_journal(self):
        import fcntl
        directory = Path(self.c['state_dir']) / 'binary-updates'
        directory.mkdir(mode=0o700)
        lock = directory / 'operation.lock'
        lock.touch(mode=0o600)
        self.c['update_directory'] = str(directory)
        with lock.open('rb') as updater:
            fcntl.flock(updater, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with clock.update_lock(self.c): pass
        with clock.update_lock(self.c):
            with lock.open('rb') as updater:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(updater, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (directory / 'transaction.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'binary_update_recovery_required'):
            with clock.update_lock(self.c): pass
        (directory / 'transaction.json').unlink()
        lock.unlink(); lock.symlink_to('/dev/null')
        with self.assertRaises(OSError):
            with clock.update_lock(self.c): pass

    def response(self, **overrides):
        return json.dumps(dict(version=1, nonce=self.nonce, unix_seconds=self.epoch, synchronized=True, **overrides)).encode()

    def test_response_validation_and_actual_offset(self):
        aligned = clock.validate_response(self.response(), self.nonce, .1, self.epoch, self.epoch+.1)
        self.assertFalse(aligned['needsCorrection'])
        behind = clock.validate_response(self.response(), self.nonce, .1, self.epoch-46800, self.epoch-46799.9)
        self.assertTrue(behind['needsCorrection'])
        self.assertGreater(behind['offsetSeconds'], 46000)
        for data, nonce, elapsed, before, after, floor in [
            (self.response(), 'b'*64, .1, self.epoch, self.epoch+.1, 0),
            (self.response(), self.nonce, 5.1, self.epoch, self.epoch+5.1, 0),
            (self.response(), self.nonce, .1, self.epoch, self.epoch+100, 0),
            (self.response(), self.nonce, .1, self.epoch, self.epoch+.1, self.epoch+6),
            (b'x'*513, self.nonce, .1, self.epoch, self.epoch+.1, 0),
        ]:
            with self.subTest(data=data[:20], nonce=nonce, elapsed=elapsed, floor=floor):
                with self.assertRaises(ValueError):
                    clock.validate_response(data, nonce, elapsed, before, after, floor)
        for field, value in [('synchronized',False),('unix_seconds',True),('version',True),('unix_seconds',0)]:
            r=json.loads(self.response());r[field]=value
            with self.assertRaises(ValueError):
                clock.validate_response(json.dumps(r),self.nonce,.1,self.epoch,self.epoch+.1)
        with self.assertRaisesRegex(ValueError,'duplicate_json_key'):
            clock.strict_json('{"version":1,"version":1}')

    def test_no_clock_trigger_for_success_timeouts_or_wrong_keys(self):
        for reason in [None,'ready','starting','connecting','connect_deadline','auth_rejected','auth_deadline',
                       'tls_handshake','tls_verify_name','tls_verify_untrusted','vpn_response_rejected','tls_peer_closed']:
            with self.subTest(reason=reason), patch.object(clock,'probe') as probe, patch.object(clock,'consumer_stopped') as stopped:
                with self.assertRaisesRegex(ValueError,'clock_failure_required'):
                    clock.apply_locked(self.c,reason,self.boot)
                probe.assert_not_called();stopped.assert_not_called()
        self.assertFalse((Path(self.c['state_dir'])/'attempt.json').exists())

    def test_attempt_persists_across_restart_and_even_failed_query(self):
        with patch.object(clock,'consumer_stopped'), patch.object(clock,'probe',side_effect=ValueError('ssh_failed')) as probe:
            with self.assertRaisesRegex(ValueError,'ssh_failed'):
                clock.apply_locked(self.c,'auth_clock_skew',self.boot)
            with self.assertRaisesRegex(ValueError,'clock_attempt_already_consumed'):
                clock.apply_locked(self.c,'tls_verify_expired',self.boot)
            self.assertEqual(probe.call_count,1)
        clock.claim_attempt(self.c,'tls_verify_not_yet_valid','bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee')

    def report(self, correction):
        return dict(needsCorrection=correction, remoteUnixSeconds=self.epoch, trustedFloor=0)

    def test_expired_certificate_with_correct_clock_never_sets_time(self):
        with patch.object(clock,'consumer_stopped'), patch.object(clock,'probe',return_value=self.report(False)), patch.object(clock.subprocess,'run') as run:
            r=clock.apply_locked(self.c,'tls_verify_expired',self.boot)
            run.assert_not_called();self.assertFalse(r['systemClockChanged'])
        self.assertEqual(clock.floor_read(self.c), self.epoch)

    def test_genuine_clock_error_sets_only_authenticated_current_time(self):
        with patch.object(clock,'consumer_stopped') as stopped, patch.object(clock,'probe',return_value=self.report(True)), patch.object(clock.subprocess,'run') as run:
            r=clock.apply_locked(self.c,'auth_clock_skew',self.boot)
            self.assertTrue(r['systemClockChanged']);self.assertEqual(stopped.call_count,2)
            self.assertEqual(run.call_args.args[0],['/usr/bin/date','--utc','--set=@'+str(self.epoch)])

    def test_running_consumer_blocks_query_or_change(self):
        for responses in [[ValueError('consumer_still_running')],[None,ValueError('consumer_still_running')]]:
            with self.subTest(responses=responses), patch.object(clock,'consumer_stopped',side_effect=responses), patch.object(clock,'probe',return_value=self.report(True)), patch.object(clock.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'consumer_still_running'):
                    clock.apply_locked(self.c,'auth_clock_skew',self.boot)
                run.assert_not_called()

    def test_pin_and_ssh_options_do_not_inherit_trust(self):
        import base64
        pin=b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'x'*32
        line=b'clean-vpn-clock ssh-ed25519 '+base64.b64encode(pin)
        self.assertEqual(len(clock.host_pin(line)),64)
        for bad in [line+b'\n'+line,line.replace(b'clean-vpn-clock',b'*'),b'@cert-authority '+line]:
            with self.assertRaises(ValueError):clock.host_pin(bad)
        c=dict(host='192.0.2.1',port=22,user='cvpn-clock',identity='/identity',known_hosts='/pin')
        args=clock.ssh_args(c)
        for option in ['StrictHostKeyChecking=yes','IdentityAgent=none','GlobalKnownHostsFile=/dev/null','ControlPath=none','ClearAllForwardings=yes','UpdateHostKeys=no']:
            self.assertIn(option,args)
        self.assertEqual(args[-1],clock.COMMAND)

    def test_unsafe_state_or_lower_trusted_time_refused(self):
        clock.save_floor(self.c,self.epoch)
        os.chmod(Path(self.c['state_dir'])/'last-good.json',0o666)
        with self.assertRaisesRegex(ValueError,'unsafe_file'):clock.floor_read(self.c)
        with self.assertRaisesRegex(ValueError,'clock_failure_required'):clock.claim_attempt(self.c,'auth_rejected',self.boot)

    def test_pending_systemd_restart_is_not_stopped(self):
        for data in [b'MainPID=0\nActiveState=activating\nSubState=auto-restart\nJob=\n',
                     b'MainPID=123\nActiveState=active\nSubState=running\nJob=\n',
                     b'MainPID=0\nActiveState=inactive\nSubState=dead\nJob=123 /job\n']:
            with patch.object(clock.subprocess,'check_output',return_value=data):
                with self.assertRaisesRegex(ValueError,'consumer_still_running'):clock.consumer_stopped(self.c)
        with patch.object(clock.subprocess,'check_output',return_value=b'MainPID=0\nActiveState=inactive\nSubState=dead\nJob=\n'):
            clock.consumer_stopped(self.c)

    def test_server_requires_forced_command_valid_nonce_and_synchronized_clock(self):
        import io
        import types
        stdin=types.SimpleNamespace(buffer=io.BytesIO((self.nonce+'\n').encode()))
        with patch.dict(clock.os.environ,{'SSH_ORIGINAL_COMMAND':'id'}),patch.object(clock.sys,'stdin',stdin),patch.object(clock.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'forced_command_required'):clock.serve()
            run.assert_not_called()
        for answer in [b'no\n',b'',b'yes yes\n']:
            stdin=types.SimpleNamespace(buffer=io.BytesIO((self.nonce+'\n').encode()))
            with patch.dict(clock.os.environ,{'SSH_ORIGINAL_COMMAND':clock.COMMAND}),patch.object(clock.sys,'stdin',stdin),patch.object(clock.subprocess,'run',return_value=types.SimpleNamespace(stdout=answer)):
                with self.assertRaisesRegex(ValueError,'exit_clock_not_synchronized'):clock.serve()
        stdin=types.SimpleNamespace(buffer=io.BytesIO((self.nonce+'\n').encode()))
        output=io.StringIO()
        with patch.dict(clock.os.environ,{'SSH_ORIGINAL_COMMAND':clock.COMMAND}),patch.object(clock.sys,'stdin',stdin),patch.object(clock.sys,'stdout',output),patch.object(clock.subprocess,'run',return_value=types.SimpleNamespace(stdout=b'yes\n')),patch.object(clock.time,'time',return_value=self.epoch):
            clock.serve()
        self.assertEqual(json.loads(output.getvalue()),dict(version=1,nonce=self.nonce,unix_seconds=self.epoch,synchronized=True))

    def test_slow_state_check_or_concurrent_ntp_update_prevents_set(self):
        for ticks, walls, reason in [([0,5],[self.epoch],'clock_response_stale'),
                                     ([0,.1],[self.epoch,self.epoch+20],'local_clock_changed_before_apply')]:
            # Different test boot IDs allow independent attempts in this fixture.
            boot='cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee' if len(walls)==1 else self.boot
            with patch.object(clock,'consumer_stopped'),patch.object(clock,'probe',return_value=self.report(True)),patch.object(clock.time,'monotonic',side_effect=ticks),patch.object(clock.time,'time',side_effect=walls),patch.object(clock.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,reason):clock.apply_locked(self.c,'auth_clock_skew',boot)
                run.assert_not_called()

    def test_recovery_accepts_only_completed_native_time_exit(self):
        state=dict(MainPID='0',ActiveState='failed',SubState='failed',Job='',Result='exit-code',ExecMainCode='1',ExecMainStatus='75',InvocationID='a'*32)
        for status,reason in clock.EXIT_FAILURES.items():
            with patch.object(clock,'unit_state',return_value={**state,'ExecMainStatus':status}):
                self.assertEqual(clock.failed_invocation(self.c),(reason,'a'*32))
        for change in [dict(ExecMainStatus='1'),dict(ExecMainCode='2'),dict(Result='timeout'),dict(MainPID='15'),dict(ActiveState='active'),dict(SubState='auto-restart'),dict(Job='1 /job')]:
            with patch.object(clock,'unit_state',return_value={**state,**change}):
                self.assertIsNone(clock.failed_invocation(self.c))

    def test_changed_failed_invocation_refuses_probe_or_clock_write(self):
        with patch.object(clock,'consumer_stopped'),patch.object(clock,'probe') as probe:
            with self.assertRaisesRegex(ValueError,'consumer_failure_changed'):
                clock.apply_locked(self.c,'auth_clock_skew',self.boot,lambda:clock.require(False,'consumer_failure_changed'))
            probe.assert_not_called()

if __name__ == '__main__':
    unittest.main()
