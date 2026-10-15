"""Настоящий CMAC файла, который нельзя прочитать целиком при лимите памяти."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC


@unittest.skipUnless(sys.platform.startswith("linux"), "лимит RLIMIT_AS проверяется в Linux/WSL")
class MemoryLimitedCmacTests(unittest.TestCase):
    def test_real_file_larger_than_available_address_space(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        reference = ReferenceCMAC.new(key, ciphermod=AES)
        chunk = bytes(range(256)) * 32
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "large.bin"
            with source.open("wb") as destination:
                for _ in range(1024):
                    destination.write(chunk)
                    reference.update(chunk)
            program = """
import resource
import sys
from pathlib import Path
from cryptocore.mac import cmac_file

source = Path(sys.argv[1])
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
status = Path('/proc/self/status').read_text()
current = next(int(line.split()[1]) * 1024 for line in status.splitlines() if line.startswith('VmSize:'))
resource.setrlimit(resource.RLIMIT_AS, (current + 4 * 1024 * 1024, current + 4 * 1024 * 1024))
try:
    with source.open('rb') as stream:
        payload = stream.read()
except MemoryError:
    pass
else:
    raise AssertionError('файл неожиданно помещается в доступную память')
print(cmac_file(source, key))
"""
            result = subprocess.run([sys.executable, "-c", program, str(source)],
                                    capture_output=True, text=True, check=False, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), reference.hexdigest())


if __name__ == "__main__":
    unittest.main()
