"""
Реализация HMAC (Hash-based Message Authentication Code)
Согласно RFC 2104, использует SHA-256 из Sprint 4
"""

import struct
from src.hash.sha256 import SHA256


class HMAC:
    """Реализация HMAC с поддержкой ключей переменной длины"""

    BLOCK_SIZE = 64  # Размер блока для SHA-256 (в байтах)

    def __init__(self, key, hash_algorithm='sha256'):
        """
        Инициализация HMAC

        Args:
            key: ключ в виде bytes или hex строки
            hash_algorithm: используемая хеш-функция (поддерживается только sha256)
        """
        if isinstance(key, str):
            # Преобразуем hex строку в bytes
            self.key = bytes.fromhex(key)
        else:
            self.key = key

        self.hash_algorithm = hash_algorithm.lower()

        if self.hash_algorithm != 'sha256':
            raise ValueError(f"Неподдерживаемый алгоритм: {self.hash_algorithm}")

        # Определяем хеш-класс
        self.hash_class = SHA256

        # Обработка ключа согласно RFC 2104
        self._process_key()

        # Вычисляем ipad и opad
        self.ipad = bytes(x ^ 0x36 for x in self.key)
        self.opad = bytes(x ^ 0x5c for x in self.key)

        # Инициализируем хеш-объект
        self.inner_hash = None
        self.outer_hash = None

    def _process_key(self):
        """Обработка ключа согласно RFC 2104"""
        key_len = len(self.key)

        # 1. Если ключ длиннее размера блока, хешируем его
        if key_len > self.BLOCK_SIZE:
            # Создаем новый экземпляр SHA256 для хеширования ключа
            hash_obj = self.hash_class()
            hash_obj.update(self.key)
            self.key = hash_obj.digest()
            key_len = len(self.key)

        # 2. Если ключ короче размера блока, дополняем нулями
        if key_len < self.BLOCK_SIZE:
            self.key += b'\x00' * (self.BLOCK_SIZE - key_len)

    def reset(self):
        """Сброс состояния HMAC для нового сообщения"""
        self.inner_hash = None
        self.outer_hash = None

    def update(self, data):
        """
        Добавление данных для HMAC (инкрементальное)

        Args:
            data: данные для добавления (bytes)
        """
        if not isinstance(data, bytes):
            raise TypeError("Данные должны быть в формате bytes")

        # Если это первый вызов update, начинаем вычисление inner hash
        if self.inner_hash is None:
            self.inner_hash = self.hash_class()
            self.inner_hash.update(self.ipad)

        # Добавляем данные к inner hash
        self.inner_hash.update(data)

    def finalize(self):
        """Завершение вычисления HMAC и возврат результата"""
        # Если update не вызывался, inner_hash будет None
        if self.inner_hash is None:
            # Создаем inner hash с ipad
            self.inner_hash = self.hash_class()
            self.inner_hash.update(self.ipad)

        # Получаем внутренний хеш
        inner_hash_digest = self.inner_hash.digest()

        # Вычисляем внешний хеш: hash(opad || inner_hash)
        self.outer_hash = self.hash_class()
        self.outer_hash.update(self.opad)
        self.outer_hash.update(inner_hash_digest)

        return self.outer_hash.digest()

    def compute(self, message):
        """
        Вычисление HMAC для сообщения

        Args:
            message: сообщение (bytes или str)

        Returns:
            bytes: HMAC в бинарном формате
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        self.reset()
        self.update(message)
        return self.finalize()

    def hexdigest(self, message=None):
        """
        Получение HMAC в hex формате

        Args:
            message: опциональное сообщение для вычисления

        Returns:
            str: HMAC в hex формате
        """
        if message is not None:
            hmac_bytes = self.compute(message)
        else:
            hmac_bytes = self.finalize()

        return hmac_bytes.hex()

    def verify(self, message, expected_hmac):
        """
        Проверка HMAC

        Args:
            message: сообщение для проверки
            expected_hmac: ожидаемый HMAC (bytes или hex строка)

        Returns:
            bool: True если HMAC совпадает
        """
        if isinstance(expected_hmac, str):
            expected_hmac = bytes.fromhex(expected_hmac)

        computed_hmac = self.compute(message)
        return computed_hmac == expected_hmac


def compute_hmac(key, message, hash_algo='sha256'):
    """
    Упрощенная функция для вычисления HMAC

    Args:
        key: ключ (bytes или hex строка)
        message: сообщение (bytes или str)
        hash_algo: алгоритм хеширования

    Returns:
        str: HMAC в hex формате
    """
    hmac = HMAC(key, hash_algo)
    return hmac.hexdigest(message)