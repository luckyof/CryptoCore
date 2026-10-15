"""Приёмка спринта 6: NIST GCM, потоковые AAD и Encrypt-then-MAC."""

import hashlib
import hmac
import io
import random
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES

from cryptocore.aead import GCM, EncryptThenMAC, encrypt_gcm_stream, decrypt_gcm_stream
from cryptocore.aead.etm import ETM_MODES, HEADER_SIZE
from cryptocore.errors import AuthenticationError, CryptoCoreError
from cryptocore.modes.feedback import MODES
from cryptocore.modes.gcm import (
    GHASH, GCMAuthenticator, GCTR, MAX_AAD_SIZE, MAX_DATA_SIZE,
    _multiply, encrypt_gcm, decrypt_gcm,
)


KEY = bytes.fromhex("f3a19c742de805b69147ca30856ef2bd")
NONCE = bytes(range(12))
IV = bytes(range(16))


class GcmVectorTests(unittest.TestCase):
    def test_nist_published_examples_with_varied_aad_and_plaintext(self):
        # NIST AES_GCM.pdf: примеры 1–5, AES-128 и полный 128-битный тег.
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                            "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")
        plaintext = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                                  "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        ciphertext = bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                                   "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
        vectors = (
            (b"", b"", b"", "3247184b3c4f69a44dbcd22887bbb418"),
            (plaintext, b"", ciphertext, "4d5c2af327cd64a62cf35abd2ba6fab4"),
            (b"", aad, b"", "5f91d77123ef5eb9997913849b8dc1e9"),
            (plaintext, aad, ciphertext, "64c0232904af398a5b67c10b53a5024d"),
            (plaintext[:60], aad[:20], ciphertext[:60], "f07c2528eea2fca1211f905e1b6a881b"),
        )
        for number, (message, associated, expected, tag) in enumerate(vectors, 1):
            with self.subTest(nist_example=number):
                result = encrypt_gcm(message, key, nonce, associated)
                self.assertEqual(result, expected + bytes.fromhex(tag))
                chunks = (associated[offset:offset + 3] for offset in range(0, len(associated), 3))
                self.assertEqual(decrypt_gcm(result, key, nonce, chunks), message)

    def test_table_multiplication_matches_bitwise_field_reference(self):
        generator = random.Random(600)
        for hash_key in (0, 1, 1 << 127, (1 << 128) - 1, generator.getrandbits(128)):
            multiplier = GHASH(hash_key)
            for value in (0, 1, 1 << 127, (1 << 128) - 1, *(generator.getrandbits(128) for _ in range(100))):
                self.assertEqual(multiplier.multiply(value), _multiply(value, hash_key))

    def test_fragmented_aad_and_ciphertext_match_reference(self):
        data = bytes(range(256)) * 5 + b"end"
        aad = bytes(range(253)) * 3 + b"metadata"
        for nonce_size in (1, 8, 12, 16, 33):
            nonce = bytes(range(nonce_size))
            reference = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
            reference.update(aad)
            ciphertext, tag = reference.encrypt_and_digest(data)
            for size in (1, 7, 15, 16, 17, 1024):
                with self.subTest(nonce_size=nonce_size, chunk_size=size):
                    auth = GCMAuthenticator(KEY, nonce)
                    for offset in range(0, len(aad), size):
                        auth.update_aad(aad[offset:offset + size])
                    counter = GCTR(auth.cipher, auth.initial)
                    ours = bytearray()
                    for offset in range(0, len(data), size):
                        chunk = counter.transform(data[offset:offset + size])
                        ours.extend(chunk)
                        auth.update_ciphertext(chunk)
                    self.assertEqual(bytes(ours), ciphertext)
                    self.assertEqual(auth.digest(), tag)
                    self.assertEqual(auth.digest(), tag)

    def test_aad_can_be_binary_stream_or_one_pass_iterator(self):
        aad = b"associated" * 1000
        result = encrypt_gcm(b"payload", KEY, NONCE, aad)
        self.assertEqual(encrypt_gcm(b"payload", KEY, NONCE, io.BytesIO(aad)), result)
        self.assertEqual(encrypt_gcm(b"payload", KEY, NONCE, iter((aad[:3], b"", aad[3:]))), result)
        for invalid in (None, 123, "text", iter((b"valid", "invalid"))):
            with self.subTest(source=invalid), self.assertRaises(CryptoCoreError):
                encrypt_gcm(b"payload", KEY, NONCE, invalid)

    def test_context_order_and_limits(self):
        auth = GCMAuthenticator(KEY, NONCE)
        auth.update_ciphertext(b"x")
        with self.assertRaises(CryptoCoreError):
            auth.update_aad(b"late")
        auth.digest()
        with self.assertRaises(CryptoCoreError):
            auth.update_ciphertext(b"late")
        auth = GCMAuthenticator(KEY, NONCE)
        auth._aad_size = MAX_AAD_SIZE
        with self.assertRaisesRegex(CryptoCoreError, "длина AAD"):
            auth.update_aad(b"x")
        auth._data_size = MAX_DATA_SIZE
        with self.assertRaisesRegex(CryptoCoreError, "предел GCM"):
            auth.update_ciphertext(b"x")
        counter = GCTR(auth.cipher, auth.initial)
        counter._size = MAX_DATA_SIZE
        with self.assertRaises(CryptoCoreError):
            counter.transform(b"x")
        with self.assertRaises(CryptoCoreError):
            GCMAuthenticator(KEY, b"")

    def test_public_gcm_api_and_thousand_fresh_nonces(self):
        cipher = GCM(KEY)
        seen = set()
        for _ in range(1000):
            result = cipher.encrypt(b"payload", b"aad")
            self.assertEqual(len(cipher.nonce), 12)
            seen.add(result[:12])
            self.assertEqual(GCM(KEY).decrypt(result, b"aad"), b"payload")
        self.assertEqual(len(seen), 1000)
        fixed = GCM(KEY, b"12345678")
        result = fixed.encrypt(b"payload")
        self.assertEqual(GCM(KEY, b"12345678").decrypt(result), b"payload")
        with self.assertRaisesRegex(CryptoCoreError, "повторно"):
            fixed.encrypt(b"another")
        with self.assertRaises(AuthenticationError):
            GCM(KEY, b"87654321").decrypt(result)


class GcmStreamTests(unittest.TestCase):
    def test_stream_format_and_roundtrip_at_chunk_boundaries(self):
        for size in (0, 1, 15, 16, 17, 8191, 8192, 8193):
            data = bytes(index % 251 for index in range(size))
            for chunk_size in (1, 7, 16, 8192):
                with self.subTest(size=size, chunk_size=chunk_size):
                    encrypted = io.BytesIO()
                    encrypt_gcm_stream(io.BytesIO(data), encrypted, KEY, NONCE, io.BytesIO(b"aad"), chunk_size)
                    self.assertEqual(encrypted.getvalue(), NONCE + encrypt_gcm(data, KEY, NONCE, b"aad"))
                    restored = io.BytesIO()
                    decrypt_gcm_stream(io.BytesIO(encrypted.getvalue()), restored, KEY, aad=b"aad", chunk_size=chunk_size)
                    self.assertEqual(restored.getvalue(), data)

    def test_bad_tag_or_aad_never_decrypts_or_writes(self):
        encrypted = NONCE + encrypt_gcm(b"secret" * 50, KEY, NONCE, b"aad")
        for payload, key, aad in ((encrypted[:-1] + bytes([encrypted[-1] ^ 1]), KEY, b"aad"),
                                   (encrypted, KEY, b"wrong"), (encrypted, b"x" * 16, b"aad")):
            with self.subTest(aad=aad):
                destination = io.BytesIO(b"keep")
                with patch("cryptocore.aead.gcm_file.GCTR") as transform:
                    with self.assertRaises(AuthenticationError):
                        decrypt_gcm_stream(io.BytesIO(payload), destination, key, aad=aad)
                    transform.assert_not_called()
                self.assertEqual(destination.getvalue(), b"keep")

    def test_short_reads_and_nonseekable_input(self):
        class ShortReadStream(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 3))

            def seek(self, *args):
                raise AssertionError("входной поток не должен перематываться")

        data = b"binary payload" * 17
        aad = b"some metadata" * 31
        encrypted = io.BytesIO()
        encrypt_gcm_stream(ShortReadStream(data), encrypted, KEY, NONCE, ShortReadStream(aad))
        restored = io.BytesIO()
        decrypt_gcm_stream(ShortReadStream(encrypted.getvalue()), restored, KEY, aad=ShortReadStream(aad))
        self.assertEqual(restored.getvalue(), data)

    def test_explicit_nonce_and_truncated_formats(self):
        data = encrypt_gcm(b"abc", KEY, NONCE)
        restored = io.BytesIO()
        decrypt_gcm_stream(io.BytesIO(data), restored, KEY, nonce=NONCE)
        self.assertEqual(restored.getvalue(), b"abc")
        for size in range(28):
            with self.subTest(size=size), self.assertRaises(AuthenticationError):
                decrypt_gcm_stream(io.BytesIO(bytes(size)), io.BytesIO(), KEY)
        for size in (0, -1, True, 1.5):
            with self.assertRaises(CryptoCoreError):
                encrypt_gcm_stream(io.BytesIO(), io.BytesIO(), KEY, NONCE, chunk_size=size)

    def test_stream_snapshot_prevents_second_read_of_mutable_input(self):
        class OnePassStream(io.BytesIO):
            def seek(self, *args):
                raise AssertionError("нельзя расшифровывать заново прочитанный изменяемый источник")

        ciphertext = NONCE + encrypt_gcm(b"sensitive", KEY, NONCE)
        output = io.BytesIO()
        decrypt_gcm_stream(OnePassStream(ciphertext), output, KEY)
        self.assertEqual(output.getvalue(), b"sensitive")


class EncryptThenMacTests(unittest.TestCase):
    def test_all_modes_roundtrip_with_aad_and_empty_payload(self):
        for mode in ETM_MODES:
            for data in (b"", b"x", bytes(range(256))):
                with self.subTest(mode=mode, size=len(data)):
                    cipher = EncryptThenMAC(KEY, mode)
                    result = cipher.encrypt(data, b"aad", None if mode == "ecb" else IV)
                    self.assertEqual(cipher.decrypt(result, io.BytesIO(b"aad")), data)

    def test_distinct_keys_and_literal_ciphertext_then_aad_hmac(self):
        cipher = EncryptThenMAC(KEY)
        self.assertNotEqual(cipher._encryption, cipher._authentication[:16])
        data = cipher.encrypt(b"message", b"aad", IV)
        body, tag = data[:-32], data[-32:]
        self.assertEqual(tag, hmac.new(cipher._authentication, body + b"aad", hashlib.sha256).digest())
        self.assertEqual(body[HEADER_SIZE:], MODES["ctr"][0](b"message", cipher._encryption, IV))
        other = EncryptThenMAC(KEY, "cbc")
        self.assertNotEqual(cipher._encryption, other._encryption)
        self.assertNotEqual(cipher._authentication, other._authentication)

    def test_every_bit_tamper_fails_before_decryption(self):
        for mode in ("ctr", "cbc"):
            cipher = EncryptThenMAC(KEY, mode)
            data = cipher.encrypt(b"message", b"aad", IV)
            with patch.dict(MODES, {mode: (MODES[mode][0], unittest.mock.Mock())}):
                for index in range(len(data) * 8):
                    changed = bytearray(data)
                    changed[index // 8] ^= 1 << (index % 8)
                    with self.assertRaises(AuthenticationError):
                        cipher.decrypt(bytes(changed), b"aad")
                MODES[mode][1].assert_not_called()

    def test_wrong_key_mode_aad_truncation_and_appending(self):
        cipher = EncryptThenMAC(KEY)
        data = cipher.encrypt(b"message", b"aad", IV)
        for scheme, payload, aad in ((cipher, data, b"bad"), (EncryptThenMAC(b"x" * 16), data, b"aad"),
                                      (EncryptThenMAC(KEY, "cbc"), data, b"aad"),
                                      (cipher, data[:-1], b"aad"), (cipher, data + b"x", b"aad")):
            with self.assertRaises(AuthenticationError):
                scheme.decrypt(payload, aad)

    def test_authenticated_length_prevents_aad_boundary_shift(self):
        cipher = EncryptThenMAC(KEY)
        data = cipher.encrypt(b"message", b"aad", IV)
        body, tag = data[:-32], data[-32:]
        # MAC-input остаётся тем же, но изменённая граница C/AAD должна отвергаться.
        with self.assertRaises(AuthenticationError):
            cipher.decrypt(body[:-1] + tag, body[-1:] + b"aad")

    def test_unknown_mode_and_ecb_iv_rejected(self):
        with self.assertRaises(CryptoCoreError):
            EncryptThenMAC(KEY, "gcm")
        with self.assertRaises(CryptoCoreError):
            EncryptThenMAC(KEY, "ecb").encrypt(b"x", iv=IV)


if __name__ == "__main__":
    unittest.main()
