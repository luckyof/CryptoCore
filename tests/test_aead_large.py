"""Реальный AAD больше доступной памяти: GCM и Encrypt-then-MAC."""

import hashlib
import hmac
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from Crypto.Cipher import AES
from cryptocore.aead import EncryptThenMAC


@unittest.skipUnless(sys.platform.startswith("linux"), "лимит RLIMIT_AS проверяется в Linux/WSL")
class MemoryLimitedAadTests(unittest.TestCase):
    def test_real_large_aad_under_memory_limit(self):
        key = bytes.fromhex("f3a19c742de805b69147ca30856ef2bd")
        nonce, iv = bytes(range(12)), bytes(range(16))
        message = b"authenticated plaintext" * 37
        reference = AES.new(key, AES.MODE_GCM, nonce=nonce)
        scheme = EncryptThenMAC(key)
        body = scheme.encrypt(message, iv=iv)[:-32]
        mac = hmac.new(scheme._authentication, body, hashlib.sha256)
        chunk = bytes(range(256)) * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aad = root / "large-aad.bin"
            source = root / "source.bin"
            source.write_bytes(message)
            with aad.open("wb") as destination:
                for _ in range(1024):
                    destination.write(chunk)
                    reference.update(chunk)
                    mac.update(chunk)
            ciphertext, tag = reference.encrypt_and_digest(message)
            expected_gcm = nonce + ciphertext + tag
            expected_etm = body + mac.digest()
            program = """
import resource
import sys
from pathlib import Path
from cryptocore.aead import EncryptThenMAC, process_gcm_file

root = Path(sys.argv[1])
key = bytes.fromhex('f3a19c742de805b69147ca30856ef2bd')
nonce, iv = bytes(range(12)), bytes(range(16))
message = b'authenticated plaintext' * 37
scheme = EncryptThenMAC(key)
status = Path('/proc/self/status').read_text()
current = next(int(line.split()[1]) * 1024 for line in status.splitlines() if line.startswith('VmSize:'))
resource.setrlimit(resource.RLIMIT_AS, (current + 4 * 1024 * 1024, current + 4 * 1024 * 1024))
try:
    with (root / 'large-aad.bin').open('rb') as aad:
        payload = aad.read()
except MemoryError:
    pass
else:
    raise AssertionError('AAD неожиданно помещается в доступную память')
with (root / 'large-aad.bin').open('rb') as aad:
    process_gcm_file(root / 'source.bin', root / 'cipher.bin', key, True, aad, nonce)
assert (root / 'cipher.bin').read_bytes() == bytes.fromhex(sys.argv[2])
with (root / 'large-aad.bin').open('rb') as aad:
    process_gcm_file(root / 'cipher.bin', root / 'restored.bin', key, False, aad)
assert (root / 'restored.bin').read_bytes() == message
with (root / 'large-aad.bin').open('rb') as aad:
    ciphertext = scheme.encrypt(message, aad, iv)
assert ciphertext == bytes.fromhex(sys.argv[3])
with (root / 'large-aad.bin').open('rb') as aad:
    assert scheme.decrypt(ciphertext, aad) == message
print('OK: GCM и Encrypt-then-MAC, AAD 8 МиБ при свободных 4 МиБ')
"""
            result = subprocess.run(
                [sys.executable, "-c", program, str(root), expected_gcm.hex(), expected_etm.hex()],
                capture_output=True, text=True, encoding="utf-8", check=False, timeout=240,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("OK:", result.stdout)


if __name__ == "__main__":
    unittest.main()
