import unittest
from jocky.parser import parse, to_ir

class ParserTests(unittest.TestCase):
    def test_basic_program(self):
        ir = to_ir(parse('''
JOCKY 0.1
profile "test"
collect host
collect processes
hash "/tmp/a" sha256
scan_dir "/tmp" max_depth=2
output "json"
'''))
        self.assertEqual(ir["profile"], "test")
        self.assertEqual(len(ir["actions"]), 4)

    def test_missing_header(self):
        with self.assertRaises(ValueError):
            parse("collect host")

if __name__ == "__main__":
    unittest.main()
