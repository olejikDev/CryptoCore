"""
Реализация режима Electronic Codebook (ECB) для AES
С РУЧНОЙ обработкой блоков (требование CRY-3 Sprint 1)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class ECBMode:
    """Класс для работы с режимом ECB с ручной обработкой блоков"""

    def __init__(self, key):
        """Инициализация ECB режима"""
        if len(key) != 16:
            raise ValueError(f"Некорректная длина ключа: {len(key)} байт. Для AES-128 требуется 16 байт.")

        self.key = key
        self.block_size = AES.block_size  # 16 байт
        # Создаем AES примитив для шифрования/дешифрования отдельных блоков
        self.aes_primitive = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        """Шифрование данных в режиме ECB с РУЧНОЙ обработкой блоков"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        # 1. Добавляем padding по стандарту PKCS#7
        padded_data = pad(plaintext, self.block_size)

        # 2. РУЧНОЕ разделение на блоки и обработка каждого блока
        ciphertext = b""

        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]

            # 3. Вызов AES примитива для каждого блока отдельно
            encrypted_block = self.aes_primitive.encrypt(block)

            # 4. Сборка результатов
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, ciphertext):
        """Дешифрование данных в режиме ECB с РУЧНОЙ обработкой блоков"""
        if not ciphertext:
            raise ValueError("Нельзя дешифровать пустые данные")

        # Проверяем, что длина кратна размеру блока
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Длина зашифрованных данных ({len(ciphertext)} байт) должна быть кратна {self.block_size} байтам")

        # 1. РУЧНОЕ разделение на блоки
        padded_plaintext = b""

        # 2. Обработка каждого блока по отдельности
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 3. Вызов AES примитива для каждого блока
            decrypted_block = self.aes_primitive.decrypt(block)

            # 4. Сборка результатов
            padded_plaintext += decrypted_block

        # 5. Удаление padding
        plaintext = unpad(padded_plaintext, self.block_size)

        return plaintext