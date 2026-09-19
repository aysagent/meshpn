import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts" / "patch-lwip-napt.py"
SPEC = importlib.util.spec_from_file_location("patch_lwip_napt", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PatchLwipNaptTests(unittest.TestCase):
    def test_exact_retransmit_bypasses_rst_eviction(self):
        source = (
            "static void x(void) { ip_napt_send_rst(t->dest, 0, 0, 0, 0, 0); }\n"
            + MODULE.ANCHOR
            + "    ip_napt_free(t);\n    ip_napt_insert(t);\n  }\n"
        )
        result = MODULE.patch(source)
        self.assertIn("t->dest == dest && t->dport == dport", result)
        self.assertIn("return t->mport", result)
        self.assertEqual(result.count("ip_napt_free(t)"), 1)

    def test_unknown_source_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.patch("not lwip")


if __name__ == "__main__":
    unittest.main()
