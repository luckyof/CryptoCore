"""Векторы, потоковая обработка и свойства собственных хеш-функций."""

import hashlib
import io
import unittest
from unittest.mock import patch

from cryptocore.hashes import SHA256, SHA3_256, create_hash
from cryptocore.hashes.file_hash import hash_stream


class KnownAnswerTests(unittest.TestCase):
    def test_sha256_nist_vectors(self):
        vectors = (
            (b"", "e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            (b"a" * 1_000_000,
             "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        )
        for data, expected in vectors:
            with self.subTest(size=len(data)):
                self.assertEqual(SHA256.hash(data), expected)

    def test_sha3_256_nist_vectors(self):
        vectors = (
            (b"", "a7ffc6f8bf1ed76651c14756a061d662"
                  "f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd"
                     "855f086e3e9d525b46bfe24511431532"),
            (b"a" * 1_000_000,
             "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
        )
        for data, expected in vectors:
            with self.subTest(size=len(data)):
                self.assertEqual(SHA3_256.hash(data), expected)


class StreamingHashTests(unittest.TestCase):
    def test_block_boundaries_and_incremental_updates(self):
        sizes = (0, 1, 55, 56, 63, 64, 65, 135, 136, 137, 4097)
        algorithms = (
            (SHA256, hashlib.sha256),
            (SHA3_256, hashlib.sha3_256),
        )
        for implementation, reference in algorithms:
            for size in sizes:
                with self.subTest(algorithm=implementation.name, size=size):
                    data = bytes(index % 251 for index in range(size))
                    hasher = implementation()
                    for offset in range(0, len(data), 7):
                        hasher.update(data[offset:offset + 7])
                    self.assertEqual(hasher.hexdigest(), reference(data).hexdigest())

    def test_digest_does_not_destroy_state(self):
        for implementation, reference in (
            (SHA256, hashlib.sha256),
            (SHA3_256, hashlib.sha3_256),
        ):
            with self.subTest(algorithm=implementation.name):
                hasher = implementation(b"abc")
                self.assertEqual(hasher.digest(), reference(b"abc").digest())
                self.assertEqual(hasher.hexdigest(), reference(b"abc").hexdigest())
                hasher.update(b"def")
                self.assertEqual(hasher.hexdigest(), reference(b"abcdef").hexdigest())

    def test_bytearray_and_memoryview_are_supported(self):
        self.assertEqual(SHA256(bytearray(b"abc")).hexdigest(), hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(
            SHA3_256(memoryview(b"abc")).hexdigest(),
            hashlib.sha3_256(b"abc").hexdigest(),
        )

    def test_non_bytes_are_rejected_in_russian(self):
        for implementation in (SHA256, SHA3_256):
            with self.subTest(algorithm=implementation.name):
                with self.assertRaisesRegex(TypeError, "байтовой последовательностью"):
                    implementation().update("abc")

    def test_factory(self):
        self.assertIsInstance(create_hash("sha256"), SHA256)
        self.assertIsInstance(create_hash("sha3-256"), SHA3_256)
        with self.assertRaisesRegex(ValueError, "неподдерживаемый алгоритм"):
            create_hash("md5")

    def test_stream_reads_fixed_size_chunks(self):
        class ObservedStream(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.requested_sizes = []

            def read(self, size=-1):
                self.requested_sizes.append(size)
                return super().read(size)

        data = bytes(range(256)) * 100
        stream = ObservedStream(data)
        self.assertEqual(hash_stream(stream, "sha256"), hashlib.sha256(data).hexdigest())
        self.assertTrue(stream.requested_sizes)
        self.assertEqual(set(stream.requested_sizes), {8192})

    def test_virtual_file_larger_than_one_gibibyte_is_streamed(self):
        total_size = 1024 ** 3 + 1

        class VirtualLargeStream:
            def __init__(self, size):
                self.remaining = size

            def read(self, size):
                amount = min(size, self.remaining)
                self.remaining -= amount
                return b"\x00" * amount

        class CountingHash:
            def __init__(self):
                self.total = 0

            def update(self, data):
                self.total += len(data)

            def hexdigest(self):
                return f"{self.total:064x}"

        counter = CountingHash()
        with patch("cryptocore.hashes.file_hash.create_hash", return_value=counter):
            result = hash_stream(VirtualLargeStream(total_size), "sha256", 1024 * 1024)
        self.assertEqual(counter.total, total_size)
        self.assertEqual(result, f"{total_size:064x}")

    def test_invalid_chunk_size(self):
        for size in (0, -1, 1.5, True):
            with self.subTest(size=size), self.assertRaises(ValueError):
                hash_stream(io.BytesIO(), "sha256", size)


class AvalancheEffectTests(unittest.TestCase):
    def test_one_changed_bit_changes_about_half_of_digest(self):
        original = bytearray(b"CryptoCore avalanche test")
        changed = bytearray(original)
        changed[0] ^= 0x01
        for implementation in (SHA256, SHA3_256):
            with self.subTest(algorithm=implementation.name):
                first = implementation(original).digest()
                second = implementation(changed).digest()
                changed_bits = sum((left ^ right).bit_count()
                                   for left, right in zip(first, second))
                self.assertGreater(changed_bits, 100)
                self.assertLess(changed_bits, 156)


if __name__ == "__main__":
    unittest.main()
