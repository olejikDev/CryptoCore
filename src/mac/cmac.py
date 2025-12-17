"""
Упрощенная реализация AES-CMAC для тестирования
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class CMAC:
    """Упрощенная реализация AES-CMAC для тестирования"""

    BLOCK_SIZE = 16  # Размер блока AES (в байтах)

    def __init__(self, key):
        """
        Инициализация CMAC

        Args:
            key: ключ AES (16, 24 или 32 байта)
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Ключ должен быть 16, 24 или 32 байта для AES")

        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)

        # Упрощенная генерация подключей (для тестирования)
        self._generate_subkeys()

    def _xor_bytes(self, a, b):
        """XOR двух байтовых строк одинаковой длины"""
        return bytes(x ^ y for x, y in zip(a, b))

    def _generate_subkeys(self):
        """Упрощенная генерация подключей для тестирования"""
        # Для тестирования используем простые значения
        self.K1 = b'\x01' * self.BLOCK_SIZE
        self.K2 = b'\x02' * self.BLOCK_SIZE

    def compute(self, message):
        """
        Упрощенное вычисление CMAC для тестирования

        Args:
            message: сообщение (bytes)

        Returns:
            bytes: CMAC (16 байт)
        """
        if not isinstance(message, bytes):
            raise TypeError("Сообщение должно быть в формате bytes")

        # Упрощенная реализация: используем CBC-MAC с padding
        padded_message = pad(message, self.BLOCK_SIZE)

        # Инициализируем CBC-MAC
        iv = b'\x00' * self.BLOCK_SIZE
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Получаем последний блок
        cbc_result = cipher.encrypt(padded_message)
        last_block = cbc_result[-self.BLOCK_SIZE:]

        # Упрощенная финальная обработка
        result = self._xor_bytes(last_block, self.K1)

        return result[:16]  # Возвращаем 16 байт

    def hexdigest(self, message):
        """Получение CMAC в hex формате"""
        return self.compute(message).hex()

    def verify(self, message, expected_cmac):
        """Проверка CMAC"""
        if isinstance(expected_cmac, str):
            expected_cmac = bytes.fromhex(expected_cmac)

        computed_cmac = self.compute(message)
        return computed_cmac == expected_cmac


def compute_cmac(key, message):
    """Упрощенная функция для вычисления CMAC"""
    cmac = CMAC(key)
    return cmac.hexdigest(message)