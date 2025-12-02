"""
Реализация режима Electronic Codebook (ECB) для AES
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class ECBMode:
    """Класс для работы с режимом ECB"""

    def __init__(self, key):
        """Инициализация ECB режима"""
        if len(key) != 16:
            raise ValueError(f"Некорректная длина ключа: {len(key)} байт. Для AES-128 требуется 16 байт.")

        self.key = key
        self.block_size = AES.block_size  # 16 байт

    def encrypt(self, plaintext):
        """Шифрование данных в режиме ECB"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        # Добавляем padding по стандарту PKCS#7
        padded_data = pad(plaintext, self.block_size)

        # Создаем объект шифра AES
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Шифруем
        ciphertext = cipher.encrypt(padded_data)

        return ciphertext

    def decrypt(self, ciphertext):
        """Дешифрование данных в режиме ECB"""
        if not ciphertext:
            raise ValueError("Нельзя дешифровать пустые данные")

        # Проверяем, что длина кратна размеру блока
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Длина зашифрованных данных ({len(ciphertext)} байт) должна быть кратна {self.block_size} байтам")

        # Создаем объект дешифра AES
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Дешифруем
        padded_plaintext = cipher.decrypt(ciphertext)

        # Удаляем padding по стандарту PKCS#7
        plaintext = unpad(padded_plaintext, self.block_size)

        return plaintext