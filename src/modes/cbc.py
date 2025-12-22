"""
Реализация режима Cipher Block Chaining (CBC) для AES
С РУЧНОЙ реализацией chaining механизма (требование CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from src.csprng import generate_random_bytes


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
            # спользуем CSPRNG для генерации IV
            self.iv = generate_random_bytes(16)

    def encrypt(self, plaintext, use_padding=True):
        """Шифрование с ручной реализацией CBC chaining"""
        if not plaintext:
            raise ValueError("Нельзя шифровать пустые данные")

        # 1. Padding (только если use_padding=True)
        if use_padding:
            padded_data = pad(plaintext, self.block_size)
        else:
            padded_data = plaintext
            # Для потоковых режимов без padding, длина должна быть кратна блоку
            if len(padded_data) % self.block_size != 0:
                raise ValueError(f"Для режима без padding длина должна быть кратна {self.block_size}")

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

    def decrypt(self, data, remove_padding=True):
        """Дешифрование с ручной реализацией CBC chaining"""
        if not data:
            raise ValueError("Нельзя дешифровать пустые данные")

        # Разделяем IV и ciphertext
        if len(data) < self.block_size:
            raise ValueError(f"Данные слишком короткие. Минимум {self.block_size} байт (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

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

        # 5. Удаление padding (если требуется)
        if remove_padding and len(plaintext) > 0:
            try:
                # ВАЖНО: OpenSSL использует PKCS#7 padding
                # Проверяем последний байт
                last_byte = plaintext[-1]

                print(f"[DEBUG CBC] Длина plaintext до удаления padding: {len(plaintext)}")
                print(f"[DEBUG CBC] Последний байт: 0x{last_byte:02x} ({last_byte})")

                # PKCS#7 padding: последние N байт все равны N, где 1 <= N <= 16
                if 1 <= last_byte <= self.block_size:
                    # Проверяем что все последние last_byte байт равны last_byte
                    expected_padding = bytes([last_byte]) * last_byte
                    actual_padding = plaintext[-last_byte:]

                    print(f"[DEBUG CBC] Ожидаемый padding: {expected_padding.hex()}")
                    print(f"[DEBUG CBC] Фактический padding: {actual_padding.hex()}")

                    if actual_padding == expected_padding:
                        # Это valid PKCS#7 padding, удаляем его
                        result = plaintext[:-last_byte]
                        print(f"[DEBUG CBC] Padding удален, новая длина: {len(result)}")
                        return result
                    else:
                        print(f"[DEBUG CBC] Padding не совпадает!")

                # Если не PKCS#7, пробуем стандартный unpad из pycryptodome
                from Crypto.Util.Padding import unpad
                try:
                    result = unpad(plaintext, self.block_size)
                    print(f"[DEBUG CBC] спользован unpad, новая длина: {len(result)}")
                    return result
                except ValueError as e:
                    print(f"[DEBUG CBC] unpad не сработал: {e}")
                    # Если и это не работает, данные могут быть уже без padding

            except Exception as e:
                # Если ошибка, логируем и возвращаем как есть
                print(f"[DEBUG CBC] Ошибка при удалении padding: {e}")

        print(f"[DEBUG CBC] Padding не удален, возвращаем как есть: {len(plaintext)} байт")
        return plaintext

