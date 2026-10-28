"""Execute the production CMake guard against valid and stale sdkconfig values."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

GUARD = Path(__file__).parents[1] / 'cmake/board-identity.cmake'


class BoardIdentityTests(unittest.TestCase):
    def check(self, overrides=None, revision='1', error=None):
        values = dict(MESHVPN_BOARD='m5_stamp_p4_c6', MESHVPN_BOARD_TARGET='esp32p4',
                      IDF_TARGET='esp32p4', CONFIG_MESHVPN_BOARD_M5_STAMP_P4_C6='y',
                      MESHVPN_USB_PROFILE='ncm', CONFIG_MESHVPN_USB_PROFILE_NCM='y',
                      CONFIG_TINYUSB_NET_MODE_NCM='y', CONFIG_TINYUSB_CDC_ENABLED='y',
                      CONFIG_TINYUSB_CDC_COUNT='1', CONFIG_TINYUSB_RHPORT_HS='y',
                      CONFIG_ESP32P4_SELECTS_REV_LESS_V3='y', CONFIG_ESP32P4_REV_MIN_FULL='100')
        values.update(overrides or {})
        with tempfile.TemporaryDirectory() as tmp:
            identity = Path(tmp, 'meshvpn-board.json')
            identity.write_text('{"stale":true}')
            script = Path(tmp, 'guard.cmake')
            script.write_text(''.join(f'set({k} "{v}")\n' for k, v in values.items()) +
                              f'set(CMAKE_BINARY_DIR "{tmp}")\ninclude("{GUARD}")\n')
            result = subprocess.run(['cmake', '-P', str(script)], capture_output=True,
                                    text=True, env=dict(os.environ, P4_REVISION=revision))
            if error:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                self.assertFalse(identity.exists(), 'failed configure must remove stale identity')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(identity.read_text()), dict(
                    board=values['MESHVPN_BOARD'], target=values['IDF_TARGET'],
                    profile=values['MESHVPN_USB_PROFILE']))

    def test_valid_revision_families(self):
        self.check()
        self.check(dict(CONFIG_ESP32P4_SELECTS_REV_LESS_V3='n', CONFIG_ESP32P4_REV_MIN_FULL='300'), revision='3')

    def test_wrong_profile_or_tinyusb_mode(self):
        self.check(dict(CONFIG_MESHVPN_USB_PROFILE_NCM='n'), error='USB profile')
        self.check(dict(CONFIG_TINYUSB_NET_MODE_NCM='n'), error='TinyUSB NCM')
        self.check(dict(CONFIG_TINYUSB_CDC_ENABLED='n'), error='exactly one CDC')
        self.check(dict(CONFIG_TINYUSB_CDC_COUNT='2'), error='exactly one CDC')

    def test_p4_phy_and_revision_mismatch(self):
        self.check(dict(CONFIG_TINYUSB_RHPORT_HS='n'), error='USB HS controller')
        self.check(revision='3', error='revision family')
        self.check(dict(CONFIG_ESP32P4_SELECTS_REV_LESS_V3='n', CONFIG_ESP32P4_REV_MIN_FULL='300'), error='revision family')
        self.check(revision='2', error='must be 1 or 3')

    def test_wrong_board_and_target(self):
        self.check(dict(CONFIG_MESHVPN_BOARD_M5_STAMP_P4_C6='n'), error='sdkconfig board')
        self.check(dict(IDF_TARGET='esp32s3'), error='sdkconfig target')

    def test_xiao_and_waveshare(self):
        self.check(dict(MESHVPN_BOARD='xiao_esp32s3', MESHVPN_BOARD_TARGET='esp32s3',
                        IDF_TARGET='esp32s3', CONFIG_MESHVPN_BOARD_XIAO_ESP32S3='y',
                        CONFIG_TINYUSB_RHPORT_HS='n'))
        self.check(dict(MESHVPN_BOARD='waveshare_esp32_p4_wifi6',
                        CONFIG_MESHVPN_BOARD_WAVESHARE_ESP32_P4_WIFI6='y'))

    def test_other_profiles_use_their_actual_config(self):
        for profile in ('ecm', 'rndis'):
            self.check({'MESHVPN_USB_PROFILE': profile,
                        f'CONFIG_MESHVPN_USB_PROFILE_{profile.upper()}': 'y',
                        'CONFIG_TINYUSB_NET_MODE_ECM_RNDIS': 'y'})
        self.check(dict(MESHVPN_USB_PROFILE='invalid'), error='Unsupported USB profile')


if __name__ == '__main__':
    unittest.main()
