"""
Реализация режима Counter (CTR) для AES
С РУЧНОЙ реализацией counter механизма (требование CRY-2 Sprint 2)
"""

import os
from Crypto.Cipher import AES


class CTRMode:
    """Класс для работы с режимом CTR с ручной реализацией counter"""

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
            # Генерируем случайный nonce (первые 8 байт)
            self.iv = os.urandom(16)

    def _increment_counter(self, counter_bytes):
        """Инкремент счетчика (big-endian)"""
        # Преобразуем bytes в int, инкрементируем, обратно в bytes
        counter_int = int.from_bytes(counter_bytes, byteorder='big')
        counter_int += 1
        return counter_int.to_bytes(len(counter_bytes), byteorder='big')

    def encrypt(self, plaintext):
        """Шифрование с ручной реализацией CTR"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        ciphertext = b""
        # Используем IV как начальное значение счетчика
        counter = self.iv

        # Обрабатываем данные блоками
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Шифруем текущее значение счетчика
            keystream_block = self.aes_primitive.encrypt(counter)

            # 2. Инкрементируем счетчик для следующего блока
            counter = self._increment_counter(counter)

            # 3. XOR plaintext с keystream
            if len(block) < self.block_size:
                encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
                ciphertext += encrypted_block
            else:
                encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block))
                ciphertext += encrypted_block

        return self.iv + ciphertext

    def decrypt(self, data):
        """Дешифрование CTR (такое же как шифрование)"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие для CTR режима. Минимум {self.block_size} байт (nonce)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        plaintext = b""
        counter = iv

        # Генерируем тот же keystream
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Шифруем текущее значение счетчика
            keystream_block = self.aes_primitive.encrypt(counter)

            # 2. Инкрементируем счетчик
            counter = self._increment_counter(counter)

            # 3. XOR ciphertext с keystream
            if len(block) < self.block_size:
                decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
                plaintext += decrypted_block
            else:
                decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block))
                plaintext += decrypted_block

        return plaintext