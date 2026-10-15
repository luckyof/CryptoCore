"""Независимая сверка GCM с OpenSSL EVP: openssl enc не поддерживает AEAD."""

import ctypes
import ctypes.util
import os
from pathlib import Path
import unittest

from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm


class OpenSslGcm:
    """Минимальная обёртка EVP только для тестов; не используется в приложении."""

    def __init__(self):
        library = os.environ.get("OPENSSL_LIBCRYPTO") or ctypes.util.find_library("crypto")
        bundled = Path("C:/Program Files/Git/mingw64/bin/libcrypto-3-x64.dll")
        if not library and bundled.is_file():
            library = str(bundled)
        if not library:
            raise unittest.SkipTest("библиотека OpenSSL libcrypto не найдена")
        try:
            self.library = ctypes.CDLL(library)
            pointer, integer = ctypes.c_void_p, ctypes.c_int
            self._bind("EVP_CIPHER_CTX_new", [], pointer)
            self._bind("EVP_CIPHER_CTX_free", [pointer], None)
            self._bind("EVP_aes_128_gcm", [], pointer)
            self._bind("EVP_CIPHER_CTX_ctrl", [pointer, integer, integer, pointer], integer)
            for prefix in ("Encrypt", "Decrypt"):
                self._bind(f"EVP_{prefix}Init_ex", [pointer] * 5, integer)
                self._bind(f"EVP_{prefix}Update", [pointer, pointer, ctypes.POINTER(integer), pointer, integer], integer)
                self._bind(f"EVP_{prefix}Final_ex", [pointer, pointer, ctypes.POINTER(integer)], integer)
        except (OSError, AttributeError) as error:
            raise unittest.SkipTest(f"OpenSSL EVP GCM недоступен: {error}") from error

    def _bind(self, name, arguments, result):
        function = getattr(self.library, name)
        function.argtypes = arguments
        function.restype = result

    @staticmethod
    def _success(value):
        if value != 1:
            raise AssertionError("операция OpenSSL EVP завершилась ошибкой")

    def transform(self, key, nonce, aad, data, encrypting, tag=None):
        context = self.library.EVP_CIPHER_CTX_new()
        if not context:
            raise AssertionError("OpenSSL не выделил контекст EVP")
        try:
            prefix = "Encrypt" if encrypting else "Decrypt"
            init = getattr(self.library, f"EVP_{prefix}Init_ex")
            update = getattr(self.library, f"EVP_{prefix}Update")
            final = getattr(self.library, f"EVP_{prefix}Final_ex")
            ctrl = self.library.EVP_CIPHER_CTX_ctrl
            self._success(init(context, self.library.EVP_aes_128_gcm(), None, None, None))
            self._success(ctrl(context, 0x9, len(nonce), None))  # EVP_CTRL_GCM_SET_IVLEN
            key_buffer, nonce_buffer = ctypes.create_string_buffer(key), ctypes.create_string_buffer(nonce)
            self._success(init(context, None, None, key_buffer, nonce_buffer))
            length = ctypes.c_int()
            if aad:
                aad_buffer = ctypes.create_string_buffer(aad)
                self._success(update(context, None, ctypes.byref(length), aad_buffer, len(aad)))
            result = ctypes.create_string_buffer(len(data) + 32)
            data_buffer = ctypes.create_string_buffer(data)
            self._success(update(context, result, ctypes.byref(length), data_buffer, len(data)))
            produced = length.value
            if not encrypting:
                tag_buffer = ctypes.create_string_buffer(tag)
                self._success(ctrl(context, 0x11, 16, tag_buffer))  # EVP_CTRL_GCM_SET_TAG
            status = final(context, ctypes.byref(result, produced), ctypes.byref(length))
            if not encrypting and status != 1:
                raise ValueError("OpenSSL отверг тег аутентификации")
            self._success(status)
            payload = result.raw[:produced + length.value]
            if encrypting:
                tag_buffer = ctypes.create_string_buffer(16)
                self._success(ctrl(context, 0x10, 16, tag_buffer))  # EVP_CTRL_GCM_GET_TAG
                return payload + tag_buffer.raw
            return payload
        finally:
            self.library.EVP_CIPHER_CTX_free(context)


class OpenSslGcmTests(unittest.TestCase):
    def test_both_directions_varied_nonce_aad_and_payload(self):
        openssl = OpenSslGcm()
        key = bytes.fromhex("f3a19c742de805b69147ca30856ef2bd")
        for nonce_size in (8, 12, 16):
            nonce = bytes(range(nonce_size))
            for aad in (b"", b"metadata", bytes(range(255))):
                for size in (0, 1, 15, 16, 17, 255):
                    with self.subTest(nonce_size=nonce_size, aad_size=len(aad), size=size):
                        message = bytes(index % 251 for index in range(size))
                        ours = encrypt_gcm(message, key, nonce, aad)
                        reference = openssl.transform(key, nonce, aad, message, True)
                        self.assertEqual(ours, reference)
                        self.assertEqual(decrypt_gcm(reference, key, nonce, aad), message)
                        self.assertEqual(openssl.transform(key, nonce, aad, ours[:-16], False, ours[-16:]), message)
        wrong_tag = bytes([ours[-16] ^ 1]) + ours[-15:]
        with self.assertRaises(ValueError):
            openssl.transform(key, nonce, aad, ours[:-16], False, wrong_tag)


if __name__ == "__main__":
    unittest.main()
