import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("flash_device", Path(__file__).parents[1] / "scripts/flash-device.py")
flash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flash)
real_rom_mac = flash.rom_mac
verified_spec = importlib.util.spec_from_file_location("p4_verified", Path(__file__).parents[1] / "scripts/flash-p4-verified.py")
verified = importlib.util.module_from_spec(verified_spec)
verified_spec.loader.exec_module(verified)


def port(name, identity=flash.APP, location="1-2:1.0", product=None,
         manufacturer=None, serial_number=None):
    if identity == flash.APP:
        product = product or flash.S3_PRODUCT
        manufacturer = manufacturer or ("MeshPN" if product == flash.P4_PRODUCT else "Espressif Systems")
        serial_number = serial_number or "E8F60AE395D0"
    return NS(device=name, vid=identity[0], pid=identity[1], location=location,
              product=product, manufacturer=manufacturer, serial_number=serial_number)


class FlashTests(unittest.TestCase):
    def setUp(self):
        self.app = port("/dev/cu.app")
        self.rom = port("/dev/cu.rom", flash.ROM, "1-2:1.1")
        self.args = NS(port=None, target="esp32s3", device_dir="device", build_dir="build",
                       profile="ncm", monitor=False)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.args.binding_file = str(Path(temporary.name) / "binding.json")
        self.args.build_dir = temporary.name
        Path(self.args.binding_file).write_text('{"target":"esp32s3","serial":"E8F60AE395D0"}')
        rom_mac_patch = patch.object(flash, "rom_mac", return_value="E8F60AE395D0")
        rom_mac_patch.start()
        self.addCleanup(rom_mac_patch.stop)

    def test_only_supported_usb_ports_are_autoselected(self):
        unrelated = port("/dev/cu.other", (1, 2))
        self.assertIs(flash.select_port([unrelated, self.app], None, "esp32s3"), self.app)
        with self.assertRaises(RuntimeError):
            flash.select_port([unrelated], None, "esp32s3")
        camic = port("/dev/cu.camic", product="Camic ESP32-S3 NCM", manufacturer="Camic")
        self.assertIs(flash.select_port([camic, self.app], None, "esp32s3"), self.app)
        with self.assertRaises(RuntimeError):
            flash.select_port([camic], camic.device, "esp32s3")

    def test_ambiguous_requires_explicit_port(self):
        other = port("/dev/cu.second")
        with self.assertRaises(RuntimeError):
            flash.select_port([self.app, other], None, "esp32s3")
        self.assertIs(flash.select_port([self.app, other], other.device, "esp32s3"), other)

    def test_missing_explicit_port_does_not_fall_back(self):
        with self.assertRaises(RuntimeError):
            flash.select_port([self.app], "/dev/missing", "esp32s3")

    def test_p4_rom_and_app_can_be_selected_on_hs_connector(self):
        p4_rom = port("/dev/cu.p4rom", flash.P4_ROM)
        p4_app = port("/dev/cu.p4app", product="MeshPN ESP32-P4 HS NCM")
        self.assertIs(flash.select_port([p4_rom], None, "esp32p4"), p4_rom)
        self.assertIs(flash.select_port([p4_app], None, "esp32p4"), p4_app)
        camic = port("/dev/cu.camic", product="Camic ESP32-S3 NCM", manufacturer="Camic")
        self.assertIs(flash.select_port([camic, p4_app], None, "esp32p4"), p4_app)
        self.assertIs(flash.select_port([camic, p4_rom], None, "esp32p4"), p4_rom)
        for wrong in [self.app, self.rom]:
            with self.assertRaises(RuntimeError):
                flash.select_port([wrong], wrong.device, "esp32p4")

    def test_p4_app_touches_same_location_and_waits_for_p4_rom(self):
        self.args.target = "esp32p4"
        Path(self.args.binding_file).write_text('{"target":"esp32p4","serial":"E8F60AE395D0"}')
        Path(self.args.build_dir, "flash_args").write_text("0x10000 meshvpn_device.bin\n")
        app = port("/dev/cu.p4app", product="MeshPN ESP32-P4 HS NCM")
        rom = port("/dev/cu.p4rom", flash.P4_ROM)
        returned = port("/dev/cu.newapp", product="MeshPN ESP32-P4 HS NCM")
        wait = Mock(side_effect=[rom, returned])
        run = Mock()
        with patch.object(flash, "touch") as touch, patch.object(flash, "rom_mac", return_value="E8F60AE395D0") as read_rom_mac:
            flash.flash(self.args, lambda: [app], Mock(), run=run, wait=wait)
        touch.assert_called_once()
        read_rom_mac.assert_not_called()
        self.assertEqual(wait.call_args_list[0].args[1], flash.P4_ROM)
        self.assertEqual(run.call_args_list[0].args[0][-2:], ["write_flash", "@flash_args"])
        self.assertEqual(run.call_args_list[0].kwargs["cwd"], self.args.build_dir)
        self.assertEqual(wait.call_args_list[1].args[1], flash.APP)

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
        (Path(self.args.build_dir) / "flasher_args.json").write_text('{"extra_esptool_args":{"chip":"esp32s3","after":"hard_reset"}}')
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
        (Path(self.args.build_dir) / "flasher_args.json").write_text('{"extra_esptool_args":{"chip":"esp32s3","after":"hard_reset"}}')
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

    def test_p4_uart_is_rejected_before_any_reset_or_flash(self):
        self.args.target = "esp32p4"
        uart = port("/dev/cu.wchusbserial", (0x1A86, 0x55D4))
        run = Mock()
        with patch.object(flash, "touch") as touch:
            with self.assertRaises(RuntimeError):
                flash.flash(self.args, lambda: [uart], Mock(), run=run)
        touch.assert_not_called()
        run.assert_not_called()

    def test_p4_binding_rejects_other_app_and_rom_before_flash(self):
        self.args.target = "esp32p4"
        Path(self.args.binding_file).write_text('{"target":"esp32p4","serial":"E8F60AE395D0"}')
        app = port("/dev/cu.p4app", product=flash.P4_PRODUCT, serial_number="ABCDEF123456")
        run = Mock()
        with patch.object(flash, "touch") as touch, self.assertRaisesRegex(RuntimeError, "not the bound"):
            flash.flash(self.args, lambda: [app], Mock(), run=run)
        touch.assert_not_called()
        rom = port("/dev/cu.p4rom", flash.P4_ROM)
        Path(self.args.build_dir, "flash_args").write_text("0x10000 meshvpn_device.bin\n")
        run.side_effect = subprocess.CalledProcessError(1, "verified ROM helper")
        wait = Mock()
        with self.assertRaises(subprocess.CalledProcessError):
            flash.flash(self.args, lambda: [rom], Mock(), run=run, wait=wait)
        command = run.call_args.args[0]
        self.assertTrue(command[1].endswith("flash-p4-verified.py"))
        self.assertEqual(command[command.index("--expected-mac") + 1], "E8F60AE395D0")
        wait.assert_not_called()

    def test_p4_verified_rom_uses_same_open_connection(self):
        Path(self.args.build_dir, "flash_args").write_text("0x10000 meshvpn_device.bin\n")
        chip = Mock()
        chip.read_mac.return_value = bytes.fromhex("E8F60AE395D0")
        events = []
        chip.connect.side_effect = lambda mode: events.append("connect")
        chip.read_mac.side_effect = lambda: events.append("verify") or bytes.fromhex("E8F60AE395D0")
        chip._port.close.side_effect = lambda: events.append("close")
        factory = Mock(return_value=chip)
        def write(argv, esp):
            self.assertIs(esp, chip)
            self.assertEqual(argv[-2:], ["write_flash", "@flash_args"])
            self.assertEqual(Path.cwd(), Path(self.args.build_dir).resolve())
            events.append("write")
        before = Path.cwd()
        verified.write_verified("/dev/cu.p4rom", "E8F60AE395D0", self.args.build_dir, factory, write)
        factory.assert_called_once_with("/dev/cu.p4rom", 115200)
        self.assertEqual(events, ["connect", "verify", "write", "close"])
        self.assertEqual(Path.cwd(), before)

    def test_p4_wrong_rom_mac_never_writes_and_closes_port(self):
        Path(self.args.build_dir, "flash_args").write_text("0x10000 meshvpn_device.bin\n")
        chip = Mock()
        chip.read_mac.return_value = bytes.fromhex("ABCDEF123456")
        write = Mock()
        with self.assertRaisesRegex(RuntimeError, "ROM MAC"):
            verified.write_verified("/dev/cu.p4rom", "E8F60AE395D0", self.args.build_dir, Mock(return_value=chip), write)
        write.assert_not_called()
        chip._port.close.assert_called_once()

    def test_p4_write_failure_closes_verified_connection(self):
        Path(self.args.build_dir, "flash_args").write_text("0x10000 meshvpn_device.bin\n")
        chip = Mock()
        chip.read_mac.return_value = bytes.fromhex("E8F60AE395D0")
        before = Path.cwd()
        with self.assertRaisesRegex(RuntimeError, "write interrupted"):
            verified.write_verified("/dev/cu.p4rom", "E8F60AE395D0", self.args.build_dir,
                                    Mock(return_value=chip), Mock(side_effect=RuntimeError("write interrupted")))
        self.assertEqual(Path.cwd(), before)
        chip._port.close.assert_called_once()

    def test_s3_rom_mac_rejects_camic_even_if_already_in_download_mode(self):
        run = Mock()
        with patch.object(flash, "rom_mac", return_value="AC276EA857D0"), self.assertRaisesRegex(RuntimeError, "ROM MAC"):
            flash.flash(self.args, lambda: [self.rom], Mock(), run=run)
        run.assert_not_called()

    def test_s3_bind_reads_rom_mac_then_restores_app(self):
        Path(self.args.binding_file).unlink()
        run = Mock()
        wait = Mock(side_effect=[self.rom, self.app])
        with patch.object(flash, "touch") as touch:
            flash.bind(self.args, lambda: [self.app], Mock(), run=run, wait=wait)
        touch.assert_called_once()
        self.assertEqual(flash.load_binding(self.args.binding_file, "esp32s3")["serial"], "E8F60AE395D0")
        self.assertEqual(run.call_args.args[0][-2:], ["--no-stub", "read_mac"])

    def test_rom_mac_is_read_only_and_must_be_present(self):
        run = Mock(return_value=NS(stdout="Chip is ESP32-P4\nMAC: e8:f6:0a:e3:95:d0\n"))
        self.assertEqual(real_rom_mac(self.rom, "esp32p4", run), "E8F60AE395D0")
        command = run.call_args.args[0]
        self.assertIn("no_reset", command)
        self.assertNotIn("write_flash", command)
        with self.assertRaisesRegex(RuntimeError, "Cannot verify ROM MAC"):
            real_rom_mac(self.rom, "esp32p4", Mock(return_value=NS(stdout="Chip is ESP32-P4")))


if __name__ == "__main__":
    unittest.main()
