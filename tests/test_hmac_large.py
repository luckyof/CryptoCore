"""Реальный потоковый HMAC при недостатке памяти для чтения файла целиком."""

import hashlib
import hmac
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "лимит RLIMIT_AS проверяется в Linux/WSL")
class MemoryLimitedHmacTests(unittest.TestCase):
    def test_real_file_larger_than_remaining_address_space(self):
        # 8 МиБ реальных данных; дочернему процессу доступно лишь 4 МиБ сверх его VmSize.
        key = bytes(range(32))
        reference = hmac.new(key, digestmod=hashlib.sha256)
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
from cryptocore.mac import hmac_file

source = Path(sys.argv[1])
key = bytes(range(32))
status = Path('/proc/self/status').read_text()
current = next(int(line.split()[1]) * 1024 for line in status.splitlines() if line.startswith('VmSize:'))
limit = current + 4 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
try:
    with source.open('rb') as stream:
        payload = stream.read()
except MemoryError:
    pass
else:
    raise AssertionError('файл неожиданно помещается в доступную память')
print(hmac_file(source, key))
"""
            completed = subprocess.run(
                [sys.executable, "-c", program, str(source)],
                capture_output=True, text=True, check=False, timeout=180,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), reference.hexdigest())


if __name__ == "__main__":
    unittest.main()
