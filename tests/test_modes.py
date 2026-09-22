"""Проверки режимов, файлового формата и совместимости с OpenSSL."""

import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cryptocore.cli import main
from cryptocore.errors import CryptoCoreError
from cryptocore.modes.feedback import MODES

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SIZES = (0, 1, 15, 16, 17, 31, 32, 33, 257)


def reference(mode, iv):
    if mode == "ctr":
        return AES.new(KEY, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    options = {"segment_size": 128} if mode == "cfb" else {}
    return AES.new(KEY, getattr(AES, "MODE_" + mode.upper()), iv=iv, **options)


class ModeTests(unittest.TestCase):
    def test_reference_and_round_trip(self):
        for mode, (encrypt, decrypt) in MODES.items():
            for size in SIZES:
                with self.subTest(mode=mode, size=size):
                    data = bytes(i % 256 for i in range(size))
                    encrypted = encrypt(data, KEY, IV)
                    expected = reference(mode, IV).encrypt(pad(data, 16) if mode == "cbc" else data)
                    self.assertEqual(encrypted, expected)
                    self.assertEqual(decrypt(expected, KEY, IV), data)
                    self.assertEqual(len(encrypted), ((size // 16 + 1) * 16) if mode == "cbc" else size)

    def test_invalid_iv_and_key(self):
        for operations in MODES.values():
            for operation in operations:
                for iv in (b"", b"x" * 15, b"x" * 17, "x" * 16):
                    with self.subTest(operation=operation.__name__, iv=iv):
                        with self.assertRaises(CryptoCoreError):
                            operation(b"x" * 16, KEY, iv)
                with self.assertRaises(CryptoCoreError):
                    operation(b"x" * 16, b"short", IV)

    def test_ctr_carry_and_wrap(self):
        encrypt, _ = MODES["ctr"]
        for iv in (bytes.fromhex("00" * 15 + "ff"), b"\xff" * 16):
            self.assertEqual(encrypt(b"x" * 49, KEY, iv), reference("ctr", iv).encrypt(b"x" * 49))

    def test_cbc_invalid_length_and_padding(self):
        decrypt = MODES["cbc"][1]
        for data in (b"", b"x", b"x" * 17):
            with self.assertRaises(CryptoCoreError):
                decrypt(data, KEY, IV)
        malformed = AES.new(KEY, AES.MODE_CBC, iv=IV).encrypt(b"x" * 15 + b"\x00")
        with self.assertRaises(CryptoCoreError):
            decrypt(malformed, KEY, IV)


class FileModeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.bin"
        self.output = self.root / "output.bin"

    def args(self, mode, operation, *extra):
        return ["--algorithm", "aes", "--mode", mode, operation, "--key", KEY.hex(),
                "--input", str(self.source), "--output", str(self.output), *extra]

    def test_iv_header_and_explicit_iv(self):
        for mode in MODES:
            for size in SIZES:
                with self.subTest(mode=mode, size=size):
                    data = bytes(i % 256 for i in range(size))
                    self.source.write_bytes(data)
                    with patch("cryptocore.cli.os.urandom", return_value=IV) as random:
                        self.assertEqual(main(self.args(mode, "--encrypt")), 0)
                        random.assert_called_once_with(16)
                    envelope = self.output.read_bytes()
                    self.assertEqual(envelope, IV + MODES[mode][0](data, KEY, IV))
                    self.source.write_bytes(envelope)
                    self.assertEqual(main(self.args(mode, "--decrypt")), 0)
                    self.assertEqual(self.output.read_bytes(), data)
                    self.source.write_bytes(envelope[16:])
                    self.assertEqual(main(self.args(mode, "--decrypt", "--iv", IV.hex())), 0)
                    self.assertEqual(self.output.read_bytes(), data)

    def test_short_header_preserves_output(self):
        for mode in MODES:
            for size in (0, 1, 15):
                self.source.write_bytes(b"x" * size)
                self.output.write_bytes(b"keep")
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(main(self.args(mode, "--decrypt")), 1)
                self.assertIn("16 байт IV", errors.getvalue())
                self.assertEqual(self.output.read_bytes(), b"keep")

    def test_invalid_iv_arguments(self):
        for mode, operation, iv in (
            ("cbc", "--encrypt", IV.hex()), ("ecb", "--decrypt", IV.hex()),
            ("cbc", "--decrypt", "1234"), ("ctr", "--decrypt", "z" * 32),
            ("cfb", "--decrypt", " " * 32),
        ):
            with self.subTest(mode=mode, operation=operation, iv=iv):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main(self.args(mode, operation, "--iv", iv))
                self.assertEqual(error.exception.code, 2)

    def test_random_generation_failure_preserves_output(self):
        self.source.write_bytes(b"data")
        self.output.write_bytes(b"keep")
        with patch("cryptocore.cli.os.urandom", side_effect=OSError("failure")):
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(self.args("cbc", "--encrypt")), 1)
        self.assertIn("не удалось сгенерировать", errors.getvalue())
        self.assertEqual(self.output.read_bytes(), b"keep")


def find_openssl():
    configured = os.environ.get("OPENSSL")
    if configured:
        return configured
    found = shutil.which("openssl")
    if found:
        return found
    bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    return str(bundled) if bundled.is_file() else None


class OpenSSLTests(unittest.TestCase):
    def test_both_directions_for_all_modes(self):
        openssl = find_openssl()
        if not openssl:
            self.skipTest("OpenSSL не найден: добавьте его в PATH или задайте OPENSSL")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, restored = (root / name for name in ("source", "encrypted", "restored"))
            for mode in MODES:
                for size in SIZES:
                    with self.subTest(mode=mode, size=size):
                        data = bytes(i % 256 for i in range(size))
                        source.write_bytes(data)
                        base = [sys.executable, "-m", "cryptocore", "--algorithm", "aes",
                                "--mode", mode, "--key", KEY.hex()]
                        subprocess.run(base + ["--encrypt", "--input", str(source),
                                               "--output", str(encrypted)], check=True, capture_output=True)
                        envelope = encrypted.read_bytes()
                        decrypted = subprocess.run(
                            [openssl, "enc", "-aes-128-" + mode, "-d", "-K", KEY.hex(),
                             "-iv", envelope[:16].hex()], input=envelope[16:],
                            check=True, capture_output=True).stdout
                        self.assertEqual(decrypted, data)
                        raw = subprocess.run(
                            [openssl, "enc", "-aes-128-" + mode, "-K", KEY.hex(), "-iv", IV.hex()],
                            input=data, check=True, capture_output=True).stdout
                        encrypted.write_bytes(raw)
                        subprocess.run(base + ["--decrypt", "--iv", IV.hex(), "--input",
                                               str(encrypted), "--output", str(restored)],
                                       check=True, capture_output=True)
                        self.assertEqual(restored.read_bytes(), data)
