"""Векторы RFC 4231 и проверки потокового HMAC-SHA256."""

import hashlib
import hmac
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptocore.authentication import hmac_sha256 as legacy_hmac
from cryptocore.errors import CryptoCoreError
from cryptocore.mac import HMAC, hmac_sha256, hmac_file, hmac_stream, read_expected_hmac, verify_hmac


class HmacVectorTests(unittest.TestCase):
    def test_rfc_4231_full_vectors(self):
        vectors = (
            (b"\x0b" * 20, b"Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (b"\xaa" * 20, b"\xdd" * 50,
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (bytes(range(1, 26)), b"\xcd" * 50,
             "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            (b"\xaa" * 131,
             b"This is a test using a larger than block-size key and a larger than block-size data. "
             b"The key needs to be hashed before being used by the HMAC algorithm.",
             "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
        )
        for number, (key, data, expected) in enumerate(vectors, 1):
            with self.subTest(vector=number):
                self.assertEqual(HMAC(key).compute(data), expected)
                self.assertEqual(hmac_sha256(key, data).hex(), expected)

    def test_rfc_4231_truncated_vector_prefix(self):
        # Вектор 5 задаёт только первые 128 бит; CLI всегда использует полный тег.
        self.assertEqual(
            hmac_sha256(b"\x0c" * 20, b"Test With Truncation")[:16].hex(),
            "a3b6167473100ee06e0c796c2955552b",
        )

    def test_key_lengths_and_message_boundaries_against_reference(self):
        for key_size in (0, 1, 16, 32, 63, 64, 65, 100, 131, 1024):
            key = bytes(index % 251 for index in range(key_size))
            for size in (0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 8193):
                with self.subTest(key_size=key_size, size=size):
                    data = bytes(index % 256 for index in range(size))
                    mac = HMAC(key)
                    for offset in range(0, size, 17):
                        self.assertIs(mac.update(data[offset:offset + 17]), mac)
                    self.assertEqual(mac.digest(), hmac.new(key, data, hashlib.sha256).digest())

    def test_digest_and_compute_do_not_destroy_streaming_state(self):
        mac = HMAC(b"key").update(b"abc")
        expected = hmac.new(b"key", b"abc", hashlib.sha256).digest()
        self.assertEqual(mac.digest(), expected)
        self.assertEqual(mac.hexdigest(), expected.hex())
        self.assertEqual(mac.compute(b"other"), hmac.new(b"key", b"other", hashlib.sha256).hexdigest())
        self.assertEqual(mac.digest(), expected)
        mac.update(b"def")
        self.assertEqual(mac.digest(), hmac.new(b"key", b"abcdef", hashlib.sha256).digest())

    def test_bytes_like_keys_and_messages(self):
        for key in (b"key", bytearray(b"key"), memoryview(b"key")):
            for data in (b"abc", bytearray(b"abc"), memoryview(b"abc")):
                self.assertEqual(hmac_sha256(key, data), hmac.new(b"key", b"abc", hashlib.sha256).digest())

    def test_invalid_types_and_algorithm_are_rejected_in_russian(self):
        for value in (None, 0, "", "key", [1, 2]):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "байтовой последовательностью"):
                    HMAC(value)
                with self.assertRaisesRegex(TypeError, "байтовой последовательностью"):
                    HMAC(b"key").update(value)
        with self.assertRaisesRegex(ValueError, "только алгоритм sha256"):
            HMAC(b"key", "sha3-256")

    def test_authentication_module_keeps_backward_compatible_function(self):
        self.assertIs(legacy_hmac, hmac_sha256)
        self.assertEqual(legacy_hmac(b"key", b"abc"), hmac.new(b"key", b"abc", hashlib.sha256).digest())

    def test_verification_uses_constant_time_comparison_primitive(self):
        tag = hmac_sha256(b"key", b"message")
        with patch("cryptocore.mac.file_mac.compare_digest", wraps=hmac.compare_digest) as compare:
            self.assertTrue(verify_hmac(tag.hex().upper(), tag))
            self.assertFalse(verify_hmac(tag.hex(), bytes(32)))
        self.assertEqual(compare.call_count, 2)
        for value in ("", "00", "g" * 64):
            with self.assertRaisesRegex(ValueError, "полные 32-байтные"):
                verify_hmac(value, tag)
        with self.assertRaises(ValueError):
            verify_hmac(tag.hex(), tag[:16])


class HmacFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "данные.bin"

    def test_empty_and_binary_file(self):
        for data in (b"", bytes(range(256)) * 37):
            with self.subTest(size=len(data)):
                self.source.write_bytes(data)
                self.assertEqual(hmac_file(self.source, b"key"), hmac.new(b"key", data, hashlib.sha256).hexdigest())

    def test_fixed_size_reads_and_short_reads(self):
        class ObservedStream(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.requests = []

            def read(self, size=-1):
                self.requests.append(size)
                return super().read(min(size, 103))

        data = bytes(range(256)) * 73
        stream = ObservedStream(data)
        self.assertEqual(hmac_stream(stream, b"key"), hmac.new(b"key", data, hashlib.sha256).hexdigest())
        self.assertEqual(set(stream.requests), {8192})

    def test_invalid_chunk_size(self):
        for size in (0, -1, 1.5, True):
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, "положительным целым"):
                hmac_stream(io.BytesIO(), b"key", size)

    def test_virtual_large_stream_checks_io_without_claiming_crypto_result(self):
        # Проверка только ввода-вывода; настоящий HMAC при лимите памяти — в test_hmac_large.
        total = 1024 ** 3 + 17

        class VirtualStream:
            remaining = total

            def read(self, size):
                amount = min(size, self.remaining)
                self.remaining -= amount
                return bytes(amount)

        class Counter:
            consumed = 0

            def update(self, data):
                self.consumed += len(data)

            def hexdigest(self):
                return f"{self.consumed:064x}"

        counter = Counter()
        with patch("cryptocore.mac.file_mac.HMAC", return_value=counter):
            self.assertEqual(hmac_stream(VirtualStream(), b"key", 1024 * 1024), f"{total:064x}")
        self.assertEqual(counter.consumed, total)

    def test_file_errors_are_clear(self):
        with self.assertRaisesRegex(CryptoCoreError, "входной файл не найден"):
            hmac_file(self.source, b"key")
        with self.assertRaises(CryptoCoreError):
            hmac_file(self.root, b"key")
        with patch.object(Path, "open", side_effect=PermissionError):
            with self.assertRaisesRegex(CryptoCoreError, "нет прав на чтение"):
                hmac_file(self.source, b"key")

    def test_expected_tag_formats(self):
        tag = hmac_sha256(b"key", b"message")
        for text in (
            tag.hex(), tag.hex() + " данные с пробелами.txt\n",
            "\n\t" + tag.hex().upper() + "\tдругое имя.txt\n\n", "\ufeff" + tag.hex() + " -\n",
        ):
            with self.subTest(text=text):
                self.source.write_text(text, encoding="utf-8")
                self.assertEqual(read_expected_hmac(self.source), tag)

    def test_malformed_tag_files(self):
        tag = "ab" * 32
        for text in ("", "  \n", "g" * 64, tag[:32], tag + "00", tag + "\n" + tag, "x" * 65537):
            with self.subTest(size=len(text)):
                self.source.write_text(text, encoding="utf-8")
                with self.assertRaises(CryptoCoreError):
                    read_expected_hmac(self.source)
        self.source.write_bytes(b"\xff")
        with self.assertRaisesRegex(CryptoCoreError, "не удалось прочитать"):
            read_expected_hmac(self.source)
        with self.assertRaises(CryptoCoreError):
            read_expected_hmac(self.root / "missing.txt")


if __name__ == "__main__":
    unittest.main()
