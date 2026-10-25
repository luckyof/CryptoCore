"""PBKDF2-HMAC-SHA256, кеширование HMAC и иерархия ключей спринта 7."""

import hashlib
import hmac
import unittest
from unittest.mock import patch

from cryptocore import SHA256, HMAC, pbkdf2_hmac_sha256, derive_key
from cryptocore.kdf.pbkdf2 import MAX_LENGTH


class Pbkdf2Tests(unittest.TestCase):
    def test_rfc7914_sha256_vectors(self):
        # RFC 7914, раздел 11: именно PBKDF2-HMAC-SHA256, а не scrypt.
        for password, salt, iterations, expected in (
            (b"passwd", b"salt", 1,
             "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
             "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
            (b"Password", b"NaCl", 80000,
             "4ddcd8f60b98be21830cee5ef22701f9"
             "641a4418d04c0414aeff08876b34ab56"
             "a1d425a1225833549adb841b51c9b317"
             "6a272bdebba1d078478f62b397f33c8d"),
        ):
            with self.subTest(iterations=iterations):
                self.assertEqual(pbkdf2_hmac_sha256(password, salt, iterations, 64).hex(), expected)

    def test_known_sha256_answers_and_rfc6070_distinction(self):
        expected = (
            (1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            (2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            (4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
        )
        for iterations, tag in expected:
            self.assertEqual(pbkdf2_hmac_sha256(b"password", b"salt", iterations, 32).hex(), tag)
        result = pbkdf2_hmac_sha256(b"password", b"salt", 1, 20)
        self.assertNotEqual(result.hex(), "0c60c80f961f0e71f3a9b524af6012062fe037a6")

    def test_rfc6070_inputs_recomputed_for_sha256(self):
        # Входы RFC 6070 применимы, но его SHA1-ответы не являются SHA256-векторами.
        for password, salt, count, length in (
            (b"password", b"salt", 1, 20), (b"password", b"salt", 2, 20),
            (b"password", b"salt", 4096, 20),
            (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25),
            (b"pass\x00word", b"sa\x00lt", 4096, 16),
        ):
            with self.subTest(count=count, length=length):
                self.assertEqual(pbkdf2_hmac_sha256(password, salt, count, length),
                                 hashlib.pbkdf2_hmac("sha256", password, salt, count, length))

    def test_every_length_1_to_100(self):
        for length in range(1, 101):
            with self.subTest(length=length):
                result = pbkdf2_hmac_sha256(b"password", b"salt", 2, length)
                self.assertEqual(len(result), length)
                self.assertEqual(result, hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 2, length))

    def test_empty_long_binary_passwords_and_salts(self):
        for size in (0, 1, 63, 64, 65, 1024, 8193):
            password = bytes(index % 256 for index in range(size))
            salt = b"\x00\xff" + password
            self.assertEqual(pbkdf2_hmac_sha256(password, salt, 3, 65),
                             hashlib.pbkdf2_hmac("sha256", password, salt, 3, 65))
        self.assertEqual(pbkdf2_hmac_sha256(b"", b"", 1, 32), hashlib.pbkdf2_hmac("sha256", b"", b"", 1, 32))

    def test_unicode_password_and_mutable_byte_sources(self):
        password, salt = "пароль 😀", b"salt"
        expected = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 2, 33)
        self.assertEqual(pbkdf2_hmac_sha256(password, salt, 2, 33), expected)
        self.assertEqual(pbkdf2_hmac_sha256(bytearray(password.encode()), memoryview(salt), 2, 33), expected)

    def test_determinism_and_parameter_changes(self):
        baseline = pbkdf2_hmac_sha256(b"password", b"salt", 3, 32)
        self.assertEqual(baseline, pbkdf2_hmac_sha256(b"password", b"salt", 3, 32))
        for password, salt, count in ((b"Password", b"salt", 3), (b"password", b"Salt", 3), (b"password", b"salt", 4)):
            self.assertNotEqual(baseline, pbkdf2_hmac_sha256(password, salt, count, 32))

    def test_reject_invalid_counts_lengths_and_types(self):
        for count in (0, -1, True, 1.5, "2"):
            with self.assertRaises(ValueError):
                pbkdf2_hmac_sha256(b"p", b"s", count, 32)
        for length in (0, -1, True, 1.5, "32", MAX_LENGTH + 1):
            with self.assertRaises(ValueError):
                pbkdf2_hmac_sha256(b"p", b"s", 1, length)
        for password, salt in ((None, b"s"), (1, b"s"), (b"p", "salt"), (b"p", None)):
            with self.assertRaises(TypeError):
                pbkdf2_hmac_sha256(password, salt, 1, 32)

    def test_one_hmac_key_preparation_for_multiple_blocks_and_iterations(self):
        with patch("cryptocore.kdf.pbkdf2.HMAC", wraps=HMAC) as factory:
            result = pbkdf2_hmac_sha256(b"password", b"salt", 7, 65)
            factory.assert_called_once_with(b"password")
        self.assertEqual(result, hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 7, 65))


class KeyHierarchyTests(unittest.TestCase):
    def test_literal_context_counter_formula(self):
        master = bytes(range(32))
        for length in (1, 16, 32, 33, 64, 65, 100, 257):
            for context in ("encryption", "authentication", "контекст 😀"):
                expected = b"".join(hmac.new(master, context.encode("utf-8") + i.to_bytes(4, "big"), hashlib.sha256).digest()
                                    for i in range(1, (length + 31) // 32 + 1))[:length]
                self.assertEqual(derive_key(master, context, length), expected)

    def test_context_separation_determinism_and_prefix(self):
        master = b"master key" * 10
        key = derive_key(master, "encryption", 65)
        self.assertEqual(key, derive_key(master, "encryption", 65))
        self.assertEqual(key[:16], derive_key(master, "encryption", 16))
        self.assertNotEqual(key, derive_key(master, "authentication", 65))
        self.assertNotEqual(key, derive_key(master, "encryption/other", 65))
        self.assertNotEqual(key, derive_key(master + b"x", "encryption", 65))

    def test_invalid_hierarchy_parameters(self):
        for master, context, length in ((b"", "label", 32), (b"key", "", 32), (b"key", b"label", 32),
                                         (b"key", "label", 0), (b"key", "label", MAX_LENGTH + 1)):
            with self.assertRaises(ValueError):
                derive_key(master, context, length)
        with self.assertRaises(TypeError):
            derive_key("key", "label", 32)


class CachedHmacTests(unittest.TestCase):
    def test_sha256_copy_is_independent_including_partial_buffer(self):
        original = SHA256(b"a" * 70)
        first, second = original.copy(), original.copy()
        first.update(b"x")
        second.update(b"y")
        self.assertEqual(original.digest(), hashlib.sha256(b"a" * 70).digest())
        self.assertEqual(first.digest(), hashlib.sha256(b"a" * 70 + b"x").digest())
        self.assertEqual(second.digest(), hashlib.sha256(b"a" * 70 + b"y").digest())
        self.assertIsNot(first._buffer, original._buffer)
        self.assertIsNot(first._state, original._state)

    def test_precomputed_hmac_templates_reduce_compression_calls(self):
        with patch.object(SHA256, "_compress", wraps=SHA256._compress) as compress:
            mac = HMAC(b"password")
            self.assertEqual(compress.call_count, 2)
            for _ in range(3):
                result = mac.digest_message(b"x" * 32)
            self.assertEqual(compress.call_count, 8)
        self.assertEqual(result, hmac.new(b"password", b"x" * 32, hashlib.sha256).digest())

    def test_cached_messages_do_not_modify_stream_state_or_each_other(self):
        for key in (b"", b"key", b"k" * 65, b"k" * 1024):
            mac = HMAC(key).update(b"prefix")
            for size in (0, 1, 32, 55, 56, 63, 64, 65, 1024):
                message = bytes(index % 251 for index in range(size))
                self.assertEqual(mac.digest_message(message), hmac.new(key, message, hashlib.sha256).digest())
            self.assertEqual(mac.digest(), hmac.new(key, b"prefix", hashlib.sha256).digest())
            mac.update(b"suffix")
            self.assertEqual(mac.digest(), hmac.new(key, b"prefixsuffix", hashlib.sha256).digest())


if __name__ == "__main__":
    unittest.main()
