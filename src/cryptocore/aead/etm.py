"""Общая схема Encrypt-then-MAC для режимов первых спринтов."""

from hmac import compare_digest

from cryptocore.authentication import derive_keys
from cryptocore.csprng import generate_random_bytes
from cryptocore.errors import AuthenticationError, CryptoCoreError
from cryptocore.mac import HMAC
from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
from cryptocore.modes.feedback import MODES
from cryptocore.modes.gcm import AADSource, AUTH_ERROR, iter_aad


ETM_MODES = ("ecb", "cbc", "cfb", "ofb", "ctr")
MAGIC = b"CETM\x01"
HEADER_SIZE = 30


class EncryptThenMAC:
    """C ∥ HMAC(K_m, C ∥ AAD), где C включает однозначный заголовок и IV."""

    def __init__(self, master_key: bytes, mode: str = "ctr") -> None:
        if mode not in ETM_MODES:
            raise CryptoCoreError("Encrypt-then-MAC поддерживает ecb, cbc, cfb, ofb и ctr")
        self.mode = mode
        self._mode_id = ETM_MODES.index(mode)
        self._encryption, self._authentication = derive_keys(
            master_key, b"CryptoCore-EtM-v1/" + mode.encode("ascii"),
        )

    def _tag(self, body: bytes, aad: AADSource) -> bytes:
        mac = HMAC(self._authentication).update(body)
        for chunk in iter_aad(aad):
            mac.update(chunk)
        return mac.digest()

    def encrypt(self, plaintext: bytes, aad: AADSource = b"", iv: bytes = None) -> bytes:
        if self.mode == "ecb":
            if iv is not None:
                raise CryptoCoreError("ECB в Encrypt-then-MAC не использует IV")
            iv = bytes(16)
            ciphertext = encrypt_ecb(plaintext, self._encryption)
        else:
            iv = generate_random_bytes(16) if iv is None else iv
            ciphertext = MODES[self.mode][0](plaintext, self._encryption, iv)
        # Длина внутри аутентифицированного заголовка фиксирует границу C/AAD.
        body = MAGIC + bytes([self._mode_id]) + iv + len(ciphertext).to_bytes(8, "big") + ciphertext
        return body + self._tag(body, aad)

    def decrypt(self, data: bytes, aad: AADSource = b"") -> bytes:
        if len(data) < HEADER_SIZE + 32:
            raise AuthenticationError(AUTH_ERROR)
        body, tag = data[:-32], data[-32:]
        if not compare_digest(self._tag(body, aad), tag):
            raise AuthenticationError(AUTH_ERROR)
        if (body[:5] != MAGIC or body[5] != self._mode_id
                or int.from_bytes(body[22:30], "big") != len(body) - HEADER_SIZE):
            raise AuthenticationError(AUTH_ERROR)
        try:
            if self.mode == "ecb":
                if body[6:22] != bytes(16):
                    raise AuthenticationError(AUTH_ERROR)
                return decrypt_ecb(body[HEADER_SIZE:], self._encryption)
            return MODES[self.mode][1](body[HEADER_SIZE:], self._encryption, body[6:22])
        except CryptoCoreError as error:
            raise AuthenticationError(AUTH_ERROR) from error
