"""
Реализация режима Cipher Feedback (CFB) для AES
С РУЧНОЙ реализацией stream cipher (требование CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from src.csprng import generate_random_bytes


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
            # Используем CSPRNG для генерации IV
            self.iv = generate_random_bytes(16)

    def encrypt(self, plaintext):
        """Шифрование с ручной реализацией CFB (stream cipher)"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        ciphertext = b""
        shift_register = self.iv  # Начинаем с IV

        # Обрабатываем данные блоками
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Шифруем содержимое shift register
            keystream = self.aes_primitive.encrypt(shift_register)

            # 2. XOR с plaintext для получения ciphertext
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext += encrypted_block

            # 3. Обновляем shift register
            # В CFB shift register обновляется ciphertext блоком, дополненным если нужно
            if len(encrypted_block) == self.block_size:
                shift_register = encrypted_block
            else:
                # Если блок не полный, дополняем из предыдущего shift register
                shift_register = encrypted_block + shift_register[len(encrypted_block):]

        return self.iv + ciphertext

    def decrypt(self, data, remove_padding=False):  # Добавляем remove_padding для совместимости
        """Дешифрование с ручной реализацией CFB"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие для CFB режима. Минимум {self.block_size} байт (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        plaintext = b""
        shift_register = iv

        # Обрабатываем ciphertext блоками
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Шифруем содержимое shift register
            keystream = self.aes_primitive.encrypt(shift_register)

            # 2. XOR с ciphertext для получения plaintext
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext += decrypted_block

            # 3. Обновляем shift register
            # В CFB при дешифровании shift register обновляется ciphertext блоком
            if len(block) == self.block_size:
                shift_register = block
            else:
                shift_register = block + shift_register[len(block):]

        # CFB - потоковый режим, padding не используется
        # remove_padding игнорируется, но параметр оставлен для совместимости
        return plaintext