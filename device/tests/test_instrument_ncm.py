import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/instrument-ncm.py"
spec = importlib.util.spec_from_file_location("instrument_ncm", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = ROOT / "managed_components/espressif__tinyusb/src/class/net/ncm_device.c"


class InstrumentationTests(unittest.TestCase):
    def test_unknown_source_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "re-audit"):
            module.instrument(b"unknown source")

    @unittest.skipUnless(SOURCE.exists(), "install device managed dependencies to test pinned driver")
    def test_generated_copy_is_repeatable_and_original_unchanged(self):
        original = SOURCE.read_bytes()
        generated = module.instrument(original)
        self.assertIn("state.free += ncm_interface.xmit_free_ntb[i] != NULL", generated)
        self.assertIn("MESH_NCM_COMPLETE_ERROR", generated)
        self.assertIn("MESH_NCM_ZLP_ERROR", generated)
        self.assertEqual(generated.count("mesh_ncm_observe(MESH_NCM_BUSY, 0, 0)"), 1)
        self.assertEqual(generated.count("usbd_edpt_xfer("), original.decode().count("usbd_edpt_xfer("))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ncm_device.c"
            subprocess.run(["python3", str(SCRIPT), str(SOURCE), str(output)], check=True)
            self.assertEqual(output.read_text(), generated)
            timestamp = output.stat().st_mtime_ns
            subprocess.run(["python3", str(SCRIPT), str(SOURCE), str(output)], check=True)
            self.assertEqual(timestamp, output.stat().st_mtime_ns)
        self.assertEqual(SOURCE.read_bytes(), original)
        result = subprocess.run(["python3", str(SCRIPT), str(SOURCE), str(SOURCE)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(SOURCE.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
