"""
Основной класс для шифрования и дешифрования файлов
"""

from src.modes.ecb import ECBMode
from src.file_io import read_binary, write_binary


class CryptoCipher:
    """Основной класс для работы с шифрованием"""

    def __init__(self, algorithm, mode, key):
        """Инициализация шифра"""
        self.algorithm = algorithm.lower()
        self.mode = mode.lower()
        self.key = self._parse_key(key)
        self.cipher = self._init_cipher()

    def _parse_key(self, key_str):
        """Парсинг ключа из hex строки"""
        # Убираем префикс @ если есть
        if key_str.startswith('@'):
            key_str = key_str[1:]

        try:
            key_bytes = bytes.fromhex(key_str)

            if len(key_bytes) != 16:
                raise ValueError(f"Для AES-128 требуется ключ длиной 16 байт. Получено: {len(key_bytes)} байт")

            return key_bytes

        except ValueError as e:
            raise ValueError(f"Некорректный формат ключа '{key_str}': {e}")

    def _init_cipher(self):
        """Инициализация объекта шифрования"""
        if self.algorithm == "aes" and self.mode == "ecb":
            return ECBMode(self.key)
        else:
            raise ValueError(f"Неподдерживаемая комбинация: алгоритм={self.algorithm}, режим={self.mode}")

    def encrypt_file(self, input_file, output_file):
        """Шифрование файла"""
        plaintext = read_binary(input_file)
        ciphertext = self.cipher.encrypt(plaintext)
        write_binary(output_file, ciphertext)

    def decrypt_file(self, input_file, output_file):
        """Дешифрование файла"""
        ciphertext = read_binary(input_file)
        plaintext = self.cipher.decrypt(ciphertext)
        write_binary(output_file, plaintext)