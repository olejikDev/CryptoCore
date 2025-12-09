"""
Реализация режима Cipher Feedback (CFB) для AES
С РУЧНОЙ реализацией stream cipher (требование CRY-2 Sprint 2)
CFB требует данные, кратные размеру блока (16 байт)
"""

import os
from Crypto.Cipher import AES


class CFBMode:
    """Класс для работы с режимом CFB с ручной реализацией"""

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
        """Шифрование с ручной реализацией CFB (stream cipher)
        Требование: данные должны быть кратны размеру блока (16 байт)
        """
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        # ⚠️ ИСПРАВЛЕНО: Проверка, что данные кратны размеру блока
        if len(plaintext) % self.block_size != 0:
            raise ValueError(f"CFB режим требует данные, кратные {self.block_size} байтам. "
                           f"Получено: {len(plaintext)} байт")

        ciphertext = b""
        shift_register = self.iv  # Начинаем с IV

        # Обрабатываем данные блоками по 16 байт
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Шифруем содержимое shift register
            keystream = self.aes_primitive.encrypt(shift_register)

            # 2. XOR с plaintext для получения ciphertext
            # ⚠️ ИСПРАВЛЕНО: Убрана обработка partial blocks
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext += encrypted_block

            # 3. Обновляем shift register (в CFB это ciphertext блок)
            shift_register = encrypted_block

        return self.iv + ciphertext

    def decrypt(self, data):
        """Дешифрование с ручной реализацией CFB
        Требование: данные должны быть кратны размеру блока (16 байт)
        """
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие для CFB режима. Минимум {self.block_size} байт (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        # ⚠️ ИСПРАВЛЕНО: Проверка, что ciphertext кратен размеру блока
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Ciphertext для CFB режима должен быть кратен {self.block_size} байтам. "
                           f"Получено: {len(ciphertext)} байт")

        plaintext = b""
        shift_register = iv

        # Обрабатываем ciphertext блоками
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Шифруем содержимое shift register
            keystream = self.aes_primitive.encrypt(shift_register)

            # 2. XOR с ciphertext для получения plaintext
            # ⚠️ ИСПРАВЛЕНО: Убрана обработка partial blocks
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext += decrypted_block

            # 3. Обновляем shift register (в CFB это ciphertext блок)
            shift_register = block

        return plaintext