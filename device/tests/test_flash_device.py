import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import subprocess
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("flash_device", Path(__file__).parents[1] / "scripts/flash-device.py")
flash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flash)


def port(name, identity=flash.APP, location="1-2:1.0"):
    return NS(device=name, vid=identity[0], pid=identity[1], location=location)


class FlashTests(unittest.TestCase):
    def setUp(self):
        self.app = port("/dev/cu.app")
        self.rom = port("/dev/cu.rom", flash.ROM, "1-2:1.1")
        self.args = NS(port=None, target="esp32s3", device_dir="device", build_dir="build",
                       profile="ncm", monitor=False)

    def test_only_supported_usb_ports_are_autoselected(self):
        unrelated = port("/dev/cu.other", (1, 2))
        self.assertIs(flash.select_port([unrelated, self.app], None, "esp32s3"), self.app)
        with self.assertRaises(RuntimeError):
            flash.select_port([unrelated], None, "esp32s3")

    def test_ambiguous_requires_explicit_port(self):
        other = port("/dev/cu.second")
        with self.assertRaises(RuntimeError):
            flash.select_port([self.app, other], None, "esp32s3")
        self.assertIs(flash.select_port([self.app, other], other.device, "esp32s3"), other)

    def test_missing_explicit_port_does_not_fall_back(self):
        with self.assertRaises(RuntimeError):
            flash.select_port([self.app], "/dev/missing", "esp32s3")

    def test_p4_hs_is_not_a_programming_port(self):
        for explicit in [None, self.app.device]:
            with self.assertRaises(RuntimeError):
                flash.select_port([self.app], explicit, "esp32p4")

    def test_matches_physical_location_not_device_name(self):
        other = port("/dev/wrong", flash.ROM, "2-9:1.0")
        self.assertIs(flash.wait_port(self.app, flash.ROM, lambda: [other, self.rom]), self.rom)

    def test_same_name_different_identity_is_not_bootloader(self):
        clock = iter([0, 0, 31])
        with self.assertRaisesRegex(RuntimeError, "Timed out"):
            flash.wait_port(self.app, flash.ROM, lambda: [self.app],
                            clock=lambda: next(clock), sleep=lambda _: None)

    def test_missing_location_does_not_guess(self):
        self.app.location = None
        with self.assertRaises(RuntimeError):
            flash.wait_port(self.app, flash.ROM, lambda: [self.rom])

    def test_ambiguous_reenumeration_fails(self):
        with self.assertRaises(RuntimeError):
            flash.wait_port(self.app, flash.ROM, lambda: [self.rom, self.rom])

    def test_touch_sequence(self):
        events = []

        class Connection:
            def __setattr__(self, key, value):
                events.append((key, value))

            def __enter__(self):
                return self

            def __exit__(self, *args):
                events.append("closed")

        factory = Mock(return_value=Connection())
        flash.touch(self.app, factory, sleep=lambda _: None)
        factory.assert_called_once_with(self.app.device, baudrate=115200, timeout=1, exclusive=True)
        self.assertEqual(events, [("dtr", True), ("baudrate", 1200), ("dtr", False), "closed"])

    def test_flash_and_monitor_use_rediscovered_ports(self):
        app_after = port("/dev/cu.new-app")
        wait = Mock(side_effect=[self.rom, app_after])
        run = Mock()
        self.args.monitor = True
        with patch.object(flash, "touch") as touch:
            flash.flash(self.args, lambda: [self.app], Mock(), run=run, wait=wait)
        touch.assert_called_once()
        self.assertEqual(run.call_args_list[0].args[0][-3:], ["-p", self.rom.device, "flash"])
        self.assertEqual(run.call_args_list[1].args[0][-3:], ["-p", app_after.device, "monitor"])

    def test_rom_already_present_is_not_touched(self):
        with patch.object(flash, "touch") as touch:
            flash.flash(self.args, lambda: [self.rom], Mock(), run=Mock(), wait=Mock(return_value=self.app))
        touch.assert_not_called()

    def recovery(self, ports, manifest='{"extra_esptool_args":{"chip":"esp32s3","after":"hard_reset"}}'):
        wait = Mock(side_effect=[flash.ApplicationUSBTimeout("application absent"), self.app])
        run = Mock()
        with patch.object(Path, "read_text", return_value=manifest):
            result = flash.application_port(self.args, self.rom, lambda: ports, run, wait)
        return result, run, wait

    def test_latched_boot_gets_one_watchdog_reset_on_same_port(self):
        renamed = port("/dev/cu.renamed-rom", flash.ROM)
        result, run, wait = self.recovery([renamed])
        self.assertIs(result, self.app)
        run.assert_called_once_with([
            flash.sys.executable, "-m", "esptool", "--chip", "esp32s3", "--port", renamed.device,
            "--before", "no_reset", "--after", "watchdog_reset", "--no-stub", "read_mac"], check=True)
        self.assertEqual(wait.call_count, 2)

    def test_late_application_is_not_reset(self):
        result, run, _ = self.recovery([self.app])
        self.assertIs(result, self.app)
        run.assert_not_called()

    def test_recovery_never_resets_missing_other_or_ambiguous_board(self):
        other = port("/dev/cu.other", flash.ROM, "2-9:1.0")
        for ports in [[], [other], [self.rom, self.rom], [self.app, self.rom]]:
            with self.subTest(ports=ports):
                run = Mock()
                with self.assertRaises(flash.ApplicationUSBTimeout):
                    flash.application_port(self.args, self.rom, lambda: ports, run,
                                           Mock(side_effect=flash.ApplicationUSBTimeout("absent")))
                run.assert_not_called()

    def test_recovery_respects_manifest_reset_policy(self):
        for manifest in ['{}', 'null', 'broken',
                         '{"extra_esptool_args":{"chip":"esp32s3","after":"no_reset"}}',
                         '{"extra_esptool_args":{"chip":"esp32p4","after":"hard_reset"}}']:
            with self.subTest(manifest=manifest), self.assertRaises(flash.ApplicationUSBTimeout):
                self.recovery([self.rom], manifest)

    def test_recovery_without_manifest_does_not_reset(self):
        run = Mock()
        with patch.object(Path, "read_text", side_effect=FileNotFoundError), self.assertRaises(flash.ApplicationUSBTimeout):
            flash.application_port(self.args, self.rom, lambda: [self.rom], run,
                                   Mock(side_effect=flash.ApplicationUSBTimeout("absent")))
        run.assert_not_called()

    def test_failed_recovery_is_not_repeated_and_monitor_does_not_start(self):
        self.args.monitor = True
        run = Mock()
        wait = Mock(side_effect=flash.ApplicationUSBTimeout("absent"))
        with patch.object(Path, "read_text", return_value='{"extra_esptool_args":{"chip":"esp32s3","after":"hard_reset"}}'):
            with self.assertRaises(flash.ApplicationUSBTimeout):
                flash.flash(self.args, lambda: [self.rom], Mock(), run=run, wait=wait)
        self.assertEqual(run.call_count, 2)  # flash, reset; no reflash or monitor
        self.assertEqual(wait.call_count, 2)

    def test_non_timeout_errors_do_not_trigger_recovery(self):
        run = Mock()
        with self.assertRaisesRegex(RuntimeError, "Ambiguous"):
            flash.application_port(self.args, self.rom, lambda: [self.rom], run,
                                   Mock(side_effect=RuntimeError("Ambiguous")))
        run.assert_not_called()

    def test_watchdog_command_failure_stops_before_monitor(self):
        self.args.monitor = True
        run = Mock(side_effect=[None, subprocess.CalledProcessError(1, "esptool")])
        wait = Mock(side_effect=flash.ApplicationUSBTimeout("absent"))
        with patch.object(Path, "read_text", return_value='{"extra_esptool_args":{"chip":"esp32s3","after":"hard_reset"}}'):
            with self.assertRaises(subprocess.CalledProcessError):
                flash.flash(self.args, lambda: [self.rom], Mock(), run=run, wait=wait)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(wait.call_count, 1)

    def test_serial_busy_stops_before_flash(self):
        run = Mock()
        with patch.object(flash, "touch", side_effect=OSError("busy")):
            with self.assertRaises(OSError):
                flash.flash(self.args, lambda: [self.app], Mock(), run=run)
        run.assert_not_called()

    def test_old_firmware_timeout_never_flashes_another_port(self):
        run = Mock()
        with patch.object(flash, "touch"):
            with self.assertRaises(RuntimeError):
                flash.flash(self.args, lambda: [self.app], Mock(), run=run,
                            wait=Mock(side_effect=RuntimeError("timeout")))
        run.assert_not_called()

    def test_no_location_stops_before_reset(self):
        self.app.location = None
        with patch.object(flash, "touch") as touch:
            with self.assertRaises(RuntimeError):
                flash.flash(self.args, lambda: [self.app], Mock())
        touch.assert_not_called()

    def test_flash_failure_does_not_start_monitor(self):
        self.args.monitor = True
        run = Mock(side_effect=subprocess.CalledProcessError(1, "idf.py"))
        wait = Mock()
        with self.assertRaises(subprocess.CalledProcessError):
            flash.flash(self.args, lambda: [self.rom], Mock(), run=run, wait=wait)
        self.assertEqual(run.call_count, 1)
        wait.assert_not_called()

    def test_p4_uart_keeps_standard_reset(self):
        self.args.target = "esp32p4"
        uart = port("/dev/cu.wchusbserial", (0x1A86, 0x55D4))
        wait = Mock()
        with patch.object(flash, "touch") as touch:
            flash.flash(self.args, lambda: [uart], Mock(), run=Mock(), wait=wait)
        touch.assert_not_called()
        wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
