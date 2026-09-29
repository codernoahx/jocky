import tempfile
import unittest
from pathlib import Path
from jocky.runtime import execute

class RuntimeTests(unittest.TestCase):
    def test_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.txt"
            p.write_text("hello", encoding="utf-8")
            report = execute({"language": "JOCKY", "profile": "test", "actions": [{"op": "hash", "path": str(p), "algorithm": "sha256"}]})
            self.assertTrue(report["hashes"][0]["ok"])
            self.assertEqual(report["hashes"][0]["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

if __name__ == "__main__":
    unittest.main()
