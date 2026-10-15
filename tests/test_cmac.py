"""NIST SP 800-38B: подключи, полные теги и потоковый AES-CMAC."""

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC

from cryptocore.errors import CryptoCoreError, InvalidKeyError
from cryptocore.mac import CMAC, cmac_aes, cmac_file, cmac_stream, read_expected_cmac, verify_cmac
from cryptocore.mac.cmac import _double


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
MESSAGE = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
VECTORS = (
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (20, "7d85449ea6ea19c823a7bf78837dfade"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
)


def reference(data, key=KEY):
    return ReferenceCMAC.new(key, msg=data, ciphermod=AES).digest()


class CmacTests(unittest.TestCase):
    def test_nist_examples_and_rfc4493_vectors(self):
        # NIST AES_CMAC.pdf: 0/16/20/64 байта; RFC 4493 также задаёт 40 байт.
        for size, tag in VECTORS:
            with self.subTest(size=size):
                self.assertEqual(cmac_aes(KEY, MESSAGE[:size]).hex(), tag)
                self.assertEqual(CMAC(KEY).compute(MESSAGE[:size]), tag)
                self.assertEqual(reference(MESSAGE[:size]).hex(), tag)

    def test_nist_subkeys_and_field_reduction(self):
        mac = CMAC(KEY)
        self.assertEqual(mac._k1.hex(), "fbeed618357133667c85e08f7236a8de")
        self.assertEqual(mac._k2.hex(), "f7ddac306ae266ccf90bc11ee46d513b")
        self.assertEqual(_double(bytes(16)), bytes(16))
        self.assertEqual(_double(bytes.fromhex("80" + "00" * 15)), bytes.fromhex("00" * 15 + "87"))
        self.assertEqual(_double(bytes.fromhex("00" * 15 + "01")), bytes.fromhex("00" * 15 + "02"))

    def test_block_boundaries_and_incremental_updates(self):
        for key in (KEY, bytes(16), bytes(range(16))):
            for size in (0, 1, 15, 16, 17, 20, 31, 32, 33, 40, 63, 64, 65, 8191, 8192, 8193):
                data = bytes(index % 251 for index in range(size))
                for chunk_size in (1, 7, 15, 16, 17, 8192):
                    with self.subTest(key=key.hex(), size=size, chunk_size=chunk_size):
                        mac = CMAC(key)
                        for offset in range(0, len(data), chunk_size):
                            self.assertIs(mac.update(data[offset:offset + chunk_size]), mac)
                            self.assertLessEqual(len(mac._buffer), 16)
                        self.assertEqual(mac.digest(), reference(data, key))

    def test_digest_and_compute_preserve_streaming_state(self):
        for prefix in (b"", b"x", b"x" * 16, b"x" * 32):
            with self.subTest(size=len(prefix)):
                mac = CMAC(KEY).update(prefix)
                self.assertEqual(mac.digest(), reference(prefix))
                self.assertEqual(mac.hexdigest(), reference(prefix).hex())
                self.assertEqual(mac.compute(b"other"), reference(b"other").hex())
                mac.update(b"")
                self.assertEqual(mac.digest(), reference(prefix))
                mac.update(b"suffix")
                self.assertEqual(mac.digest(), reference(prefix + b"suffix"))

    def test_bytes_like_keys_and_data(self):
        for key in (KEY, bytearray(KEY), memoryview(KEY)):
            for data in (MESSAGE, bytearray(MESSAGE), memoryview(MESSAGE)):
                self.assertEqual(cmac_aes(key, data), reference(MESSAGE))

    def test_invalid_keys_and_data_are_reported_in_russian(self):
        for key in (None, "key", 16, b"", b"x" * 15, b"x" * 17, b"x" * 24, b"x" * 32):
            with self.subTest(key=key), self.assertRaises(InvalidKeyError):
                CMAC(key)
        for data in (None, "", "data", 0, [1, 2]):
            with self.subTest(data=data), self.assertRaisesRegex(TypeError, "байтовой последовательностью"):
                CMAC(KEY).update(data)

    def test_verify_full_tag_and_each_bit_tamper(self):
        tag = cmac_aes(KEY, MESSAGE)
        with patch("cryptocore.mac.file_mac.compare_digest", return_value=True) as compare:
            self.assertTrue(verify_cmac(tag.hex().upper(), tag))
            compare.assert_called_once_with(tag, tag)
        for index in range(128):
            changed = bytearray(tag)
            changed[index // 8] ^= 1 << (index % 8)
            self.assertFalse(verify_cmac(tag.hex(), bytes(changed)))
        for actual, expected in (("", tag), (tag.hex()[:-2], tag), ("gg" * 16, tag),
                                  (tag.hex(), tag[:-1]), (tag.hex(), tag * 2)):
            with self.assertRaises(ValueError):
                verify_cmac(actual, expected)


class CmacFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "данные.bin"

    def test_file_for_all_known_vectors(self):
        for size, expected in VECTORS:
            self.source.write_bytes(MESSAGE[:size])
            self.assertEqual(cmac_file(self.source, KEY), expected)

    def test_stream_reads_bounded_chunks_and_handles_short_reads(self):
        class ShortStream(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.requests = []

            def read(self, size=-1):
                self.requests.append(size)
                return super().read(min(size, 17))

        data = MESSAGE * 301
        source = ShortStream(data)
        self.assertEqual(cmac_stream(source, KEY), reference(data).hex())
        self.assertEqual(set(source.requests), {8192})

    def test_invalid_chunk_sizes_and_file_errors(self):
        for size in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                cmac_stream(io.BytesIO(), KEY, size)
        with self.assertRaisesRegex(CryptoCoreError, "входной файл не найден"):
            cmac_file(self.source, KEY)
        with self.assertRaises(CryptoCoreError):
            cmac_file(self.root, KEY)
        with patch.object(Path, "open", side_effect=PermissionError):
            with self.assertRaisesRegex(CryptoCoreError, "нет прав на чтение"):
                cmac_file(self.source, KEY)

    def test_expected_tag_format_and_rejection_of_truncated_or_hmac_tags(self):
        tag = cmac_aes(KEY, MESSAGE)
        for text in (tag.hex(), tag.hex() + " имя с пробелами.bin\n",
                     "\ufeff\n\t" + tag.hex().upper() + "\tignored.bin\n\n"):
            self.source.write_text(text, encoding="utf-8")
            self.assertEqual(read_expected_cmac(self.source), tag)
        for text in ("", " \n", tag.hex()[:-2], tag.hex() + "00", tag.hex() * 2,
                     "gg" * 16, tag.hex() + "\n" + tag.hex(), "x" * 65537):
            self.source.write_text(text, encoding="utf-8")
            with self.assertRaises(CryptoCoreError):
                read_expected_cmac(self.source)
        self.source.write_bytes(b"\xff")
        with self.assertRaisesRegex(CryptoCoreError, "ожидаемого CMAC"):
            read_expected_cmac(self.source)
        with self.assertRaises(CryptoCoreError):
            read_expected_cmac(self.root / "missing.txt")


if __name__ == "__main__":
    unittest.main()
