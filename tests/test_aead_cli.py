"""Файловая приёмка спринта 6: AAD, безопасные отказы и атомарная запись."""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES

from cryptocore.aead import process_gcm_file
from cryptocore.cli import main
from cryptocore.modes.gcm import encrypt_gcm


KEY = bytes.fromhex("f3a19c742de805b69147ca30856ef2bd")
NONCE = bytes(range(12))


class AeadCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "данные.bin"
        self.encrypted = self.root / "cipher.bin"
        self.restored = self.root / "restored.bin"
        self.aad_file = self.root / "metadata.bin"
        self.data = bytes(range(256)) * 40 + b"tail"
        self.source.write_bytes(self.data)
        self.aad = bytes(range(251)) * 50 + b"metadata"
        self.aad_file.write_bytes(self.aad)

    def args(self, mode, encrypting, source=None, output=None, *extra):
        return ["--algorithm", "aes", "--mode", mode,
                "--encrypt" if encrypting else "--decrypt", "--key", KEY.hex(),
                "--input", str(source or (self.source if encrypting else self.encrypted)),
                "--output", str(output or (self.encrypted if encrypting else self.restored)), *extra]

    def invoke(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_gcm_streams_source_and_binary_aad_file(self):
        with patch("cryptocore.cli.read_binary_file") as full_read:
            with patch("cryptocore.cli.generate_random_bytes", return_value=NONCE):
                self.assertEqual(self.invoke(self.args("gcm", True) + ["--aad-file", str(self.aad_file)]), (0, "", ""))
            self.assertEqual(self.invoke(self.args("gcm", False) + ["--aad-file", str(self.aad_file)]), (0, "", ""))
            full_read.assert_not_called()
        self.assertEqual(self.restored.read_bytes(), self.data)
        reference = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
        reference.update(self.aad)
        ciphertext, tag = reference.encrypt_and_digest(self.data)
        self.assertEqual(self.encrypted.read_bytes(), NONCE + ciphertext + tag)

    def test_wrong_aad_key_nonce_ciphertext_tag_and_truncation_preserve_output(self):
        encrypted = NONCE + encrypt_gcm(b"secret", KEY, NONCE, b"aad")
        self.encrypted.write_bytes(encrypted)
        base = self.args("gcm", False) + ["--aad", b"aad".hex()]
        cases = []
        for byte in (0, 12, len(encrypted) - 1):
            changed = bytearray(encrypted)
            changed[byte] ^= 1
            cases.append((bytes(changed), base))
        cases.extend((encrypted[:size], base) for size in (0, 11, 12, 27, len(encrypted) - 1))
        wrong_key = list(base)
        wrong_key[wrong_key.index("--key") + 1] = (b"x" * 16).hex()
        cases.extend(((encrypted, wrong_key), (encrypted, self.args("gcm", False) + ["--aad", "ff"])))
        for payload, arguments in cases:
            self.encrypted.write_bytes(payload)
            for exists in (False, True):
                with self.subTest(length=len(payload), exists=exists):
                    if exists:
                        self.restored.write_bytes(b"keep")
                    else:
                        self.restored.unlink(missing_ok=True)
                    before = set(self.root.iterdir())
                    code, stdout, stderr = self.invoke(arguments)
                    self.assertEqual(code, 1)
                    self.assertEqual(stdout, "")
                    self.assertIn("аутентификация не пройдена", stderr)
                    self.assertEqual(set(self.root.iterdir()), before)
                    self.assertEqual(self.restored.read_bytes() if exists else self.restored.exists(), b"keep" if exists else False)

    def test_etm_cli_all_modes_and_aad_file(self):
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
            with self.subTest(mode=mode):
                options = ["--etm-mode", mode, "--aad-file", str(self.aad_file)]
                self.assertEqual(self.invoke(self.args("etm", True) + options), (0, "", ""))
                self.assertEqual(self.invoke(self.args("etm", False) + options), (0, "", ""))
                self.assertEqual(self.restored.read_bytes(), self.data)
                self.aad_file.write_bytes(self.aad + b"x")
                code, stdout, stderr = self.invoke(self.args("etm", False) + options)
                self.assertEqual((code, stdout), (1, ""))
                self.assertIn("аутентификация не пройдена", stderr)
                self.assertEqual(self.restored.read_bytes(), self.data)
                self.aad_file.write_bytes(self.aad)

    def test_argument_combinations_and_invalid_aad(self):
        cases = (
            self.args("gcm", True) + ["--aad", "aa", "--aad-file", str(self.aad_file)],
            self.args("cbc", True) + ["--aad-file", str(self.aad_file)],
            self.args("gcm", True) + ["--etm-mode", "ctr"],
            self.args("etm", False) + ["--nonce", NONCE.hex()],
            self.args("gcm", True) + ["--nonce", NONCE.hex()],
            self.args("gcm", True) + ["--aad", "wrongaad123"],
        )
        for arguments in cases:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                main(arguments)
            self.assertEqual(failure.exception.code, 2)

    def test_aad_file_path_collision_and_missing_file(self):
        for mode in ("gcm", "etm"):
            code, stdout, stderr = self.invoke(self.args(mode, True, output=self.aad_file)
                                             + ["--aad-file", str(self.aad_file)])
            self.assertEqual(code, 1)
            self.assertEqual(self.aad_file.read_bytes(), self.aad)
            self.assertFalse(self.encrypted.exists())
            self.assertEqual(self.invoke(self.args(mode, True) + ["--aad-file", str(self.root / "missing.bin")])[0], 1)
            self.assertFalse(self.encrypted.exists())

    def test_aad_hard_link_is_not_overwritten(self):
        alias = self.root / "alias.bin"
        os.link(self.aad_file, alias)
        self.assertEqual(self.invoke(self.args("gcm", True, output=alias) + ["--aad-file", str(self.aad_file)])[0], 1)
        self.assertEqual(self.aad_file.read_bytes(), self.aad)

    def test_atomic_result_keeps_existing_file_on_io_or_key_save_failure(self):
        self.restored.write_bytes(b"keep")
        before = set(self.root.iterdir())
        with patch("cryptocore.aead.gcm_file.os.replace", side_effect=OSError("ошибка записи")):
            self.assertEqual(self.invoke(self.args("gcm", True, output=self.restored))[0], 1)
        self.assertEqual(self.restored.read_bytes(), b"keep")
        self.assertEqual(set(self.root.iterdir()), before)
        with self.assertRaises(OSError):
            process_gcm_file(self.source, self.restored, KEY, True,
                             before_commit=lambda: (_ for _ in ()).throw(OSError("ошибка ключа")))
        self.assertEqual(self.restored.read_bytes(), b"keep")
        self.assertEqual(set(self.root.iterdir()), before)

    def test_in_place_gcm_roundtrip(self):
        self.assertEqual(self.invoke(self.args("gcm", True, output=self.source)), (0, "", ""))
        self.assertNotEqual(self.source.read_bytes(), self.data)
        self.assertEqual(self.invoke(self.args("gcm", False, source=self.source, output=self.source)), (0, "", ""))
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_cli_generates_thousand_unique_nonce_headers(self):
        self.source.write_bytes(b"")
        seen = set()
        for _ in range(1000):
            self.assertEqual(self.invoke(self.args("gcm", True)), (0, "", ""))
            data = self.encrypted.read_bytes()
            self.assertEqual(len(data), 28)
            seen.add(data[:12])
        self.assertEqual(len(seen), 1000)

    def test_process_exit_status_wrong_aad(self):
        self.assertEqual(self.invoke(self.args("gcm", True) + ["--aad", "aa"])[0], 0)
        result = subprocess.run([sys.executable, "-m", "cryptocore", *self.args("gcm", False), "--aad", "bb"],
                                capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("аутентификация не пройдена", result.stderr)
        self.assertFalse(self.restored.exists())


if __name__ == "__main__":
    unittest.main()
