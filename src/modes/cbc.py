"""
Реализация режима Cipher Block Chaining (CBC) для AES
С РУЧНОЙ реализацией chaining механизма (требование CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


class CBCMode:
    """Класс для работы с режимом CBC с ручной реализацией chaining"""

    def __init__(self, key, iv=None):
        if len(key) != 16:
            raise ValueError("Ключ должен быть 16 байт для AES-128")
        self.key = key
        self.block_size = AES.block_size

        # Создаем AES примитив для шифрования блоков
        self.aes_primitive = AES.new(self.key, AES.MODE_ECB)

        if iv:
            if len(iv) != 16:
                raise ValueError("IV должен быть 16 байт")
            self.iv = iv
        else:
            self.iv = os.urandom(16)

    def encrypt(self, plaintext):
        """Шифрование с ручной реализацией CBC chaining"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        # 1. Padding
        padded_data = pad(plaintext, self.block_size)

        # 2. Ручная реализация CBC
        ciphertext = b""
        previous_block = self.iv  # Начинаем с IV

        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]

            # 3. XOR с предыдущим блоком (или IV для первого)
            xored_block = bytes(a ^ b for a, b in zip(block, previous_block))

            # 4. Шифрование блока AES примитивом
            encrypted_block = self.aes_primitive.encrypt(xored_block)

            # 5. Сохраняем для следующего блока
            previous_block = encrypted_block
            ciphertext += encrypted_block

        return self.iv + ciphertext

    def decrypt(self, data):
        """Дешифрование с ручной реализацией CBC chaining"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        # Разделяем IV и ciphertext
        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие. Минимум {self.block_size} байт (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        # Проверяем длину ciphertext
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Длина ciphertext должна быть кратна {self.block_size}")

        # 1. Ручная реализация CBC дешифрования
        plaintext = b""
        previous_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 2. Дешифрование блока AES примитивом
            decrypted_block = self.aes_primitive.decrypt(block)

            # 3. XOR с предыдущим блоком (или IV для первого)
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))

            # 4. Сохраняем текущий ciphertext блок для следующей итерации
            previous_block = block
            plaintext += plain_block

        # 5. Удаление padding
        return unpad(plaintext, self.block_size)