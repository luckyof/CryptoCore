import unittest

from Crypto.Cipher import AES

from cryptocore.errors import InvalidCiphertextError, InvalidKeyError, InvalidPaddingError
from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb


class EcbTests(unittest.TestCase):
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_round_trip_for_boundary_sizes(self) -> None:
        for size in (0, 1, 15, 16, 17, 31, 32, 1024):
            with self.subTest(size=size):
                plaintext = bytes(index % 256 for index in range(size))
                ciphertext = encrypt_ecb(plaintext, self.key)
                self.assertEqual(len(ciphertext) % 16, 0)
                self.assertGreater(len(ciphertext), len(plaintext))
                self.assertEqual(decrypt_ecb(ciphertext, self.key), plaintext)

    def test_binary_data_round_trip(self) -> None:
        plaintext = bytes(range(256)) + b"\x00\xff\x00\xff"
        self.assertEqual(decrypt_ecb(encrypt_ecb(plaintext, self.key), self.key), plaintext)

    def test_first_block_matches_nist_aes_vector(self) -> None:
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_block = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(encrypt_ecb(plaintext, self.key)[:16], expected_block)

    def test_full_padding_block_is_added(self) -> None:
        self.assertEqual(len(encrypt_ecb(b"A" * 16, self.key)), 32)

    def test_invalid_key_length_is_rejected(self) -> None:
        with self.assertRaises(InvalidKeyError):
            encrypt_ecb(b"data", b"short")

    def test_empty_or_partial_ciphertext_is_rejected(self) -> None:
        for ciphertext in (b"", b"x" * 15, b"x" * 17):
            with self.subTest(length=len(ciphertext)):
                with self.assertRaises(InvalidCiphertextError):
                    decrypt_ecb(ciphertext, self.key)

    def test_invalid_padding_is_rejected(self) -> None:
        raw_cipher = AES.new(self.key, AES.MODE_ECB)
        invalid_ciphertext = raw_cipher.encrypt(b"A" * 15 + b"\x00")
        with self.assertRaises(InvalidPaddingError):
            decrypt_ecb(invalid_ciphertext, self.key)

    def test_wrong_key_does_not_recover_plaintext(self) -> None:
        ciphertext = encrypt_ecb(b"sensitive test data", self.key)
        wrong_key = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
        try:
            recovered = decrypt_ecb(ciphertext, wrong_key)
        except InvalidPaddingError:
            return
        self.assertNotEqual(recovered, b"sensitive test data")


if __name__ == "__main__":
    unittest.main()

