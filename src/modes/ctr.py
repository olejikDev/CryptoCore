"""
Реализация режима Counter (CTR) для AES
С РУЧНОЙ реализацией counter механизма (требование CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from src.csprng import generate_random_bytes


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
            self.nonce = iv[:8]  # Первые 8 байт - nonce
            self.counter = int.from_bytes(iv[8:], 'big')  # Последние 8 байт - счетчик
        else:
            # Используем CSPRNG для генерации nonce
            self.nonce = generate_random_bytes(8)
            self.counter = 0

    def _get_counter_bytes(self):
        """Получить текущее значение счетчика в виде байтов"""
        return self.nonce + self.counter.to_bytes(8, 'big')

    def encrypt(self, plaintext):
        """Шифрование с ручной реализацией CTR"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        ciphertext = b""
        current_counter = self.counter

        # Шифруем данные
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Получаем текущее значение счетчика
            counter_bytes = self.nonce + current_counter.to_bytes(8, 'big')

            # 2. Шифруем счетчик для получения keystream
            keystream_block = self.aes_primitive.encrypt(counter_bytes)

            # 3. XOR plaintext с keystream
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += encrypted_block

            # 4. Инкрементируем счетчик
            current_counter += 1

        # Сохраняем начальный counter для IV
        iv = self.nonce + self.counter.to_bytes(8, 'big')
        return iv + ciphertext

    def decrypt(self, data, remove_padding=False):  # Добавляем remove_padding для совместимости
        """Дешифрование CTR (такое же как шифрование)"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие для CTR режима. Минимум {self.block_size} байт (nonce+counter)")

        # Извлекаем nonce и начальный счетчик
        iv = data[:16]
        nonce = iv[:8]
        initial_counter = int.from_bytes(iv[8:], 'big')
        ciphertext = data[16:]

        plaintext = b""
        current_counter = initial_counter

        # Дешифруем данные
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Получаем текущее значение счетчика
            counter_bytes = nonce + current_counter.to_bytes(8, 'big')

            # 2. Шифруем счетчик для получения keystream
            keystream_block = self.aes_primitive.encrypt(counter_bytes)

            # 3. XOR ciphertext с keystream
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            plaintext += decrypted_block

            # 4. Инкрементируем счетчик
            current_counter += 1

        # CTR - потоковый режим, padding не используется
        # remove_padding игнорируется, но параметр оставлен для совместимости
        return plaintext


# ===== ДОБАВИТЬ ЭТО В КОНЕЦ ФАЙЛА =====
CTR = CTRMode  # Псевдоним для обратной совместимости

__all__ = ['CTRMode', 'CTR']