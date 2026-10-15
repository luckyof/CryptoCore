"""Общие интерфейсы AEAD и безопасная потоковая работа с GCM-файлами."""

from cryptocore.modes.gcm import GCM
from .etm import EncryptThenMAC
from .gcm_file import encrypt_gcm_stream, decrypt_gcm_stream, process_gcm_file

__all__ = ["GCM", "EncryptThenMAC", "encrypt_gcm_stream", "decrypt_gcm_stream", "process_gcm_file"]
