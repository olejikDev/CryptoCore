"""
Реализация режима Output Feedback (OFB) для AES
С РУЧНОЙ реализацией stream cipher (требование CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from src.csprng import generate_random_bytes


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
            # спользуем CSPRNG для генерации IV
            self.iv = generate_random_bytes(16)

    def encrypt(self, plaintext):
        """Шифрование с ручной реализацией OFB (keystream независим от plaintext)"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        ciphertext = b""
        feedback = self.iv  # Начинаем с IV

        # Генерируем keystream и шифруем
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Генерируем keystream блок (шифруем feedback)
            keystream_block = self.aes_primitive.encrypt(feedback)

            # 2. XOR plaintext с keystream
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += encrypted_block

            # 3. Обновляем feedback для следующего блока (keystream)
            feedback = keystream_block

        return self.iv + ciphertext

    def decrypt(self, data, remove_padding=False):  # Добавляем remove_padding для совместимости
        """Дешифрование OFB (такое же как шифрование)"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие для OFB режима. Минимум {self.block_size} байт (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        plaintext = b""
        feedback = iv

        # Генерируем тот же keystream и дешифруем
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Генерируем keystream блок
            keystream_block = self.aes_primitive.encrypt(feedback)

            # 2. XOR ciphertext с keystream
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            plaintext += decrypted_block

            # 3. Обновляем feedback
            feedback = keystream_block

        # OFB - потоковый режим, padding не используется
        # remove_padding игнорируется, но параметр оставлен для совместимости
        return plaintext

