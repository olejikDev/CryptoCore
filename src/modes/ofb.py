"""
Реализация режима Output Feedback (OFB) для AES
С РУЧНОЙ реализацией stream cipher (требование CRY-2 Sprint 2)
"""

import os
from Crypto.Cipher import AES


class OFBMode:
    """Класс для работы с режимом OFB с ручной реализацией"""

    def __init__(self, key, iv=None):
        if len(key) != 16:
            raise ValueError(f"Некорректная длина ключа: {len(key)} байт. Для AES-128 требуется 16 байт.")

        self.key = key
        self.block_size = AES.block_size

        # Создаем AES примитив
        self.aes_primitive = AES.new(self.key, AES.MODE_ECB)

        if iv:
            if len(iv) != 16:
                raise ValueError(f"IV должен быть 16 байт. Получено: {len(iv)} байт")
            self.iv = iv
        else:
            self.iv = os.urandom(16)

    def encrypt(self, plaintext):
        """Шифрование с ручной реализацией OFB (keystream независим от plaintext)"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        ciphertext = b""
        feedback = self.iv  # Начинаем с IV

        # Генерируем keystream блоками
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Генерируем keystream блок (шифруем feedback)
            keystream_block = self.aes_primitive.encrypt(feedback)

            # 2. Обновляем feedback для следующего блока
            feedback = keystream_block

            # 3. XOR plaintext с keystream
            if len(block) < self.block_size:
                # Частичный блок
                encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
                ciphertext += encrypted_block
            else:
                encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block))
                ciphertext += encrypted_block

        return self.iv + ciphertext

    def decrypt(self, data):
        """Дешифрование OFB (такое же как шифрование)"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие для OFB режима. Минимум {self.block_size} байт (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        plaintext = b""
        feedback = iv

        # Генерируем тот же keystream
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Генерируем keystream блок
            keystream_block = self.aes_primitive.encrypt(feedback)

            # 2. Обновляем feedback
            feedback = keystream_block

            # 3. XOR ciphertext с keystream
            if len(block) < self.block_size:
                decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
                plaintext += decrypted_block
            else:
                decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block))
                plaintext += decrypted_block

        return plaintext