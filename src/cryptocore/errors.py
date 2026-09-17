"""Исключения приложения CryptoCore."""


class CryptoCoreError(Exception):
    """Базовый класс ошибок, которые необходимо показать пользователю CLI."""


class InvalidKeyError(CryptoCoreError):
    """Ключ не соответствует требованиям AES-128."""


class InvalidCiphertextError(CryptoCoreError):
    """Шифротекст не может быть корректным входом для AES-ECB."""


class InvalidPaddingError(CryptoCoreError):
    """Расшифрованные данные содержат некорректное дополнение PKCS#7."""
