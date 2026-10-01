"""Приёмка замечаний: AEAD, padding oracle, CTR и защищённые ключевые файлы."""

import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES

from cryptocore.authentication import hmac_sha256, derive_keys
from cryptocore.cli import main
from cryptocore.csprng import generate_random_bytes, sample_entropy
from cryptocore.errors import AuthenticationError, CryptoCoreError, InvalidPaddingError
from cryptocore.key_files import load_key_file, save_key_file
from cryptocore.modes.ecb import _pkcs7_pad, _pkcs7_unpad
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm, AUTH_ERROR
from cryptocore.modes.authenticated import (
    encrypt_cbc_hmac, decrypt_cbc_hmac, encrypt_ctr_hmac, decrypt_ctr_hmac,
    transform_ctr_nonce,
)


KEY = bytes.fromhex("f3a19c742de805b69147ca30856ef2bd")
NONCE = bytes(range(12))
IV = bytes(range(16))


class GcmTests(unittest.TestCase):
    def test_nist_known_answers(self):
        key = b"\x00" * 16
        nonce = b"\x00" * 12
        self.assertEqual(encrypt_gcm(b"", key, nonce).hex(),
                         "58e2fccefa7e3061367f1d57a4e7455a")
        result = encrypt_gcm(b"\x00" * 16, key, nonce)
        self.assertEqual(result.hex(), "0388dace60b6a392f328c2b971b2fe78"
                                      "ab6e47d42cec13bdf53a67b21257bddf")
        self.assertEqual(decrypt_gcm(result, key, nonce), b"\x00" * 16)

    def test_reference_varied_nonce_aad_and_partial_blocks(self):
        for nonce_size in (1, 8, 12, 16, 19):
            for size in (0, 1, 15, 16, 17, 129):
                for aad in (b"", b"metadata", bytes(range(255))):
                    with self.subTest(nonce_size=nonce_size, size=size, aad=len(aad)):
                        nonce = bytes(range(nonce_size))
                        data = bytes(index % 251 for index in range(size))
                        reference = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
                        reference.update(aad)
                        ciphertext, tag = reference.encrypt_and_digest(data)
                        ours = encrypt_gcm(data, KEY, nonce, aad)
                        self.assertEqual(ours, ciphertext + tag)
                        self.assertEqual(decrypt_gcm(ours, KEY, nonce, aad), data)

    def test_wrong_key_aad_nonce_and_each_bit_of_ciphertext_and_tag(self):
        data = encrypt_gcm(b"secret", KEY, NONCE, b"aad")
        for index in range(len(data) * 8):
            changed = bytearray(data)
            changed[index // 8] ^= 1 << (index % 8)
            with self.assertRaises(AuthenticationError):
                decrypt_gcm(bytes(changed), KEY, NONCE, b"aad")
        for key, nonce, aad in ((b"x" * 16, NONCE, b"aad"),
                                (KEY, b"x" * 12, b"aad"), (KEY, NONCE, b"bad")):
            with self.assertRaises(AuthenticationError):
                decrypt_gcm(data, key, nonce, aad)
        with patch("cryptocore.modes.gcm._transform") as transform:
            with self.assertRaises(AuthenticationError):
                decrypt_gcm(data, KEY, NONCE, b"bad")
            transform.assert_not_called()


class CbcOracleTests(unittest.TestCase):
    def test_padding_all_valid_sizes_and_corruption_positions(self):
        for size in range(16):
            message = b"a" * size
            padded = _pkcs7_pad(message)
            self.assertEqual(_pkcs7_unpad(padded), message)
            for index in range(size, 16):
                changed = bytearray(padded)
                changed[index] ^= 0x80
                with self.assertRaises(InvalidPaddingError):
                    _pkcs7_unpad(bytes(changed))
        for last in (0, 17, 255):
            with self.assertRaises(InvalidPaddingError):
                _pkcs7_unpad(b"a" * 15 + bytes([last]))

    def test_hmac_rfc4231_and_independent_reference(self):
        self.assertEqual(hmac_sha256(b"\x0b" * 20, b"Hi There").hex(),
                         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        for key in (b"", KEY, b"k" * 131):
            self.assertEqual(hmac_sha256(key, b"test"),
                             hmac.new(key, b"test", hashlib.sha256).digest())
        encryption, authentication = derive_keys(KEY, b"CBC")
        self.assertNotEqual(encryption, authentication[:16])
        self.assertNotEqual(derive_keys(KEY, b"CBC"), derive_keys(KEY, b"CTR"))

    def test_tampering_never_reaches_cbc_or_padding(self):
        protected = encrypt_cbc_hmac(b"secret message", KEY, IV, b"aad")
        self.assertEqual(decrypt_cbc_hmac(protected, KEY, b"aad"), b"secret message")
        with patch("cryptocore.modes.authenticated.decrypt_cbc") as decrypt:
            for index in range(len(protected)):
                changed = bytearray(protected)
                changed[index] ^= 1
                with self.assertRaisesRegex(AuthenticationError, AUTH_ERROR):
                    decrypt_cbc_hmac(bytes(changed), KEY, b"aad")
            for data in (b"", protected[:-1], protected + b"x"):
                with self.assertRaises(AuthenticationError):
                    decrypt_cbc_hmac(data, KEY, b"aad")
            decrypt.assert_not_called()


class CtrSecurityTests(unittest.TestCase):
    def test_nonce_counter_reference_and_overflow(self):
        data = bytes(range(255))
        reference = AES.new(KEY, AES.MODE_CTR, nonce=NONCE, initial_value=9)
        self.assertEqual(transform_ctr_nonce(data, KEY, NONCE, 9), reference.encrypt(data))
        self.assertEqual(len(transform_ctr_nonce(b"x" * 16, KEY, NONCE, (1 << 32) - 1)), 16)
        with self.assertRaisesRegex(CryptoCoreError, "исчерпан счётчик"):
            transform_ctr_nonce(b"x" * 17, KEY, NONCE, (1 << 32) - 1)

    def test_rotation_roundtrip_and_authenticated_order(self):
        data = b"abcdefghij" * 5
        nonces = [index.to_bytes(12, "big") for index in range(4)]
        with patch("cryptocore.modes.authenticated.generate_random_bytes", side_effect=nonces) as random:
            protected = encrypt_ctr_hmac(data, KEY, b"aad", segment_size=16)
        self.assertEqual(random.call_count, 4)
        self.assertEqual(decrypt_ctr_hmac(protected, KEY, b"aad"), data)
        self.assertEqual(protected[49:61], nonces[0])
        self.assertEqual(protected[109:121], nonces[1])
        reordered = protected[:49] + protected[109:169] + protected[49:109] + protected[169:]
        for changed in (reordered, protected[:-1], protected + b"x"):
            with self.assertRaises(AuthenticationError):
                decrypt_ctr_hmac(changed, KEY, b"aad")
        with patch("cryptocore.modes.authenticated.transform_ctr_nonce") as transform:
            changed = protected[:-1] + bytes([protected[-1] ^ 1])
            with self.assertRaises(AuthenticationError):
                decrypt_ctr_hmac(changed, KEY, b"aad")
            transform.assert_not_called()

    def test_every_byte_is_authenticated_and_empty_message(self):
        data = encrypt_ctr_hmac(b"message", KEY, b"aad", segment_size=4)
        for index in range(len(data)):
            changed = bytearray(data)
            changed[index] ^= 1
            with self.assertRaises(AuthenticationError):
                decrypt_ctr_hmac(bytes(changed), KEY, b"aad")
        empty = encrypt_ctr_hmac(b"", KEY)
        self.assertEqual(decrypt_ctr_hmac(empty, KEY), b"")
        with self.assertRaises(AuthenticationError):
            decrypt_ctr_hmac(empty, b"x" * 16)

    def test_rng_repeat_fails_closed(self):
        with patch("cryptocore.modes.authenticated.generate_random_bytes", return_value=NONCE):
            with self.assertRaisesRegex(CryptoCoreError, "повтор nonce"):
                encrypt_ctr_hmac(b"ab", KEY, segment_size=1)


class KeyFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key_path = self.root / "secret.key"

    def test_secure_creation_loading_and_no_overwrite(self):
        save_key_file(self.key_path, KEY)
        self.assertEqual(load_key_file(self.key_path), KEY)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        with self.assertRaises(CryptoCoreError):
            save_key_file(self.key_path, b"x" * 16)
        self.assertEqual(load_key_file(self.key_path), KEY)

    def test_invalid_and_missing_files(self):
        with self.assertRaises(CryptoCoreError):
            load_key_file(self.key_path)
        for data in (b"", b"z" * 32, b"00", b"0" * 129, KEY.hex().encode() + b"\nextra"):
            self.key_path.write_bytes(data)
            if os.name != "nt":
                self.key_path.chmod(0o600)
            with self.assertRaises(CryptoCoreError):
                load_key_file(self.key_path)

    @unittest.skipUnless(os.name == "nt", "проверка отказа ACL относится к Windows")
    def test_windows_acl_failure_does_not_leave_key(self):
        with patch("cryptocore.key_files._restrict_windows_access", side_effect=OSError("ACL")):
            with self.assertRaises(CryptoCoreError):
                save_key_file(self.key_path, KEY)
        self.assertFalse(self.key_path.exists())

    @unittest.skipUnless(os.name == "nt", "ACL Windows проверяется только в Windows")
    def test_windows_acl_has_only_owner_and_no_inheritance(self):
        save_key_file(self.key_path, KEY)
        quoted_path = str(self.key_path).replace("'", "''")
        command = (
            "$acl = [System.IO.File]::GetAccessControl('" + quoted_path + "'); "
            "$sidType = [System.Security.Principal.SecurityIdentifier]; "
            "[pscustomobject]@{Protected=$acl.AreAccessRulesProtected; "
            "Owner=$acl.GetOwner($sidType).Value; "
            "Sids=@($acl.Access | ForEach-Object {$_.IdentityReference.Translate($sidType).Value})} "
            "| ConvertTo-Json -Compress"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        result = json.loads(completed.stdout)
        self.assertTrue(result["Protected"])
        self.assertEqual(result["Sids"], [result["Owner"]])

    @unittest.skipIf(os.name == "nt", "права POSIX проверяются в Linux/WSL")
    def test_posix_rejects_public_key_permissions_and_links(self):
        save_key_file(self.key_path, KEY)
        self.key_path.chmod(0o644)
        with self.assertRaises(CryptoCoreError):
            load_key_file(self.key_path)
        link = self.root / "link.key"
        link.symlink_to(self.key_path)
        with self.assertRaises(CryptoCoreError):
            load_key_file(link)


class SecurityCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key_path = self.root / "secret.key"
        self.source = self.root / "plain.bin"
        self.encrypted = self.root / "encrypted.bin"
        self.restored = self.root / "restored.bin"
        self.source.write_bytes(b"secret" * 5)

    def args(self, mode, operation, source, output, *extra):
        return ["--algorithm", "aes", "--mode", mode, operation,
                "--input", str(source), "--output", str(output), *extra]

    def test_save_key_no_stdout_and_key_file_roundtrip(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(self.args("gcm", "--encrypt", self.source, self.encrypted,
                                    "--save-key", str(self.key_path)))
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(main(self.args("gcm", "--decrypt", self.encrypted, self.restored,
                                       "--key-file", str(self.key_path))), 0)
        self.assertEqual(self.restored.read_bytes(), self.source.read_bytes())

    def test_all_authenticated_modes_fail_without_touching_output(self):
        for mode in ("gcm", "cbc-hmac", "ctr-hmac"):
            args = ("--key", KEY.hex(), "--aad", "abcd")
            self.assertEqual(main(self.args(mode, "--encrypt", self.source, self.encrypted, *args)), 0)
            valid = self.encrypted.read_bytes()
            for modified in (valid[:-1], valid[:-1] + bytes([valid[-1] ^ 1])):
                self.encrypted.write_bytes(modified)
                self.restored.write_bytes(b"keep")
                with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as errors:
                    status = main(self.args(mode, "--decrypt", self.encrypted, self.restored, *args))
                self.assertEqual(status, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn("аутентификация не пройдена", errors.getvalue())
                self.assertEqual(self.restored.read_bytes(), b"keep")
                self.restored.unlink()
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(self.args(mode, "--decrypt", self.encrypted, self.restored, *args)), 1)
                self.assertFalse(self.restored.exists())
            self.encrypted.write_bytes(valid)
            self.assertEqual(main(self.args(mode, "--decrypt", self.encrypted, self.restored, *args)), 0)
            self.assertEqual(self.restored.read_bytes(), self.source.read_bytes())

    def test_gcm_explicit_nonce_and_ctr_segment_cli(self):
        raw = encrypt_gcm(b"abc", KEY, NONCE)
        self.encrypted.write_bytes(raw)
        self.assertEqual(main(self.args("gcm", "--decrypt", self.encrypted, self.restored,
                                       "--key", KEY.hex(), "--nonce", NONCE.hex())), 0)
        self.assertEqual(self.restored.read_bytes(), b"abc")
        self.assertEqual(main(self.args("ctr-hmac", "--encrypt", self.source, self.encrypted,
                                       "--key", KEY.hex(), "--ctr-segment-size", "7")), 0)
        self.assertEqual(main(self.args("ctr-hmac", "--decrypt", self.encrypted, self.restored,
                                       "--key", KEY.hex())), 0)
        self.assertEqual(self.restored.read_bytes(), self.source.read_bytes())

    def test_invalid_combinations_and_path_collision(self):
        base = self.args("ecb", "--encrypt", self.source, self.encrypted)
        for options in (("--key", KEY.hex(), "--key-file", str(self.key_path)),
                        ("--key", KEY.hex(), "--save-key", str(self.key_path)),
                        ("--aad", "aa"), ("--ctr-segment-size", "0")):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(base + list(options))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(base + ["--save-key", str(self.source)]), 1)
        self.assertEqual(self.source.read_bytes(), b"secret" * 5)

    def test_key_save_failure_and_hard_link_never_overwrite_key_or_ciphertext(self):
        save_key_file(self.key_path, KEY)
        self.encrypted.write_bytes(b"keep")
        with contextlib.redirect_stderr(io.StringIO()):
            status = main(self.args("gcm", "--encrypt", self.source, self.encrypted,
                                    "--save-key", str(self.key_path)))
        self.assertEqual(status, 1)
        self.assertEqual(self.encrypted.read_bytes(), b"keep")
        alias = self.root / "alias.bin"
        os.link(self.key_path, alias)
        with contextlib.redirect_stderr(io.StringIO()):
            status = main(self.args("gcm", "--encrypt", self.source, alias,
                                    "--key-file", str(self.key_path)))
        self.assertEqual(status, 1)
        self.assertEqual(load_key_file(self.key_path), KEY)


class RandomSourceStatisticsTests(unittest.TestCase):
    def test_shannon_entropy_distribution_and_nonce_uniqueness(self):
        self.assertEqual(sample_entropy(b"a" * 1024), 0.0)
        self.assertEqual(sample_entropy(bytes(range(256))), 8.0)
        self.assertGreater(sample_entropy(generate_random_bytes(65536)), 7.95)
        self.assertEqual(len({generate_random_bytes(12) for _ in range(1000)}), 1000)


if __name__ == "__main__":
    unittest.main()
