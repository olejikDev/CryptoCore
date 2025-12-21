import os
import struct
from src.cipher import AES

class AuthenticationError(Exception):
    """Исключение для ошибок аутентификации GCM"""
    pass

class GCM:
    def __init__(self, key, nonce=None):
        """
        Инициализация GCM с ключом и nonce
        
        Args:
            key (bytes): Ключ AES (16, 24 или 32 байта)
            nonce (bytes): Nonce (рекомендуется 12 байт)
        """
        self.aes = AES(key)
        self.key = key
        
        # Стандартный размер nonce для GCM - 12 байт
        if nonce is None:
            self.nonce = os.urandom(12)
        else:
            self.nonce = nonce
        
        # Предвычисленная таблица для умножения в GF(2^128)
        self._precompute_table()
        
        # Константы
        self.block_size = 16  # Размер блока AES
        
    def _precompute_table(self):
        """Предвычисление таблицы для умножения в GF(2^128)"""
        # Используем полином: x^128 + x^7 + x^2 + x + 1
        self.r = 0xE1000000000000000000000000000000
        self.table = [0] * 16
        
        # H = E_K(0^128)
        h = self._bytes_to_int(self.aes.encrypt_block(bytes(16)))
        
        # Предвычисление таблицы
        self.table[0] = 0
        self.table[1] = h
        
        for i in range(2, 16, 2):
            # Умножение на 2
            self.table[i] = self._mul2(self.table[i // 2])
            self.table[i + 1] = self._int_xor(self.table[i], self.table[1])
    
    def _bytes_to_int(self, data):
        """Конвертация байтов в целое число (big-endian)"""
        return int.from_bytes(data, byteorder='big')
    
    def _int_to_bytes(self, num, length=16):
        """Конвертация целого числа в байты (big-endian)"""
        return num.to_bytes(length, byteorder='big')
    
    def _int_xor(self, a, b):
        """XOR двух целых чисел"""
        return a ^ b
    
    def _mul2(self, x):
        """Умножение на 2 в GF(2^128)"""
        if x & (1 << 127):
            return ((x << 1) & ((1 << 128) - 1)) ^ self.r
        else:
            return (x << 1) & ((1 << 128) - 1)
    
    def _mul_gf(self, x, y):
        """Умножение в GF(2^128) с использованием предвычисленной таблицы"""
        z = 0
        
        # Алгоритм умножения с предвычисленной таблицей
        for i in range(0, 128, 8):
            # Получаем байт из x (начиная со старшего)
            byte_val = (x >> (120 - i)) & 0xFF
            z = self._int_xor(z, self.table[byte_val >> 4] << 4)
            z = self._mul2(z)
            z = self._int_xor(z, self.table[byte_val & 0x0F])
            if i < 120:
                for _ in range(8):
                    z = self._mul2(z)
        
        return z
    
    def _ghash(self, aad, ciphertext):
        """Вычисление GHASH"""
        # Подготовка данных
        len_aad = len(aad)
        len_ct = len(ciphertext)
        
        # Выравнивание данных до границы 16 байт
        aad_padded = aad + bytes((-len_aad) % 16)
        ct_padded = ciphertext + bytes((-len_ct) % 16)
        
        # Инициализация
        y = 0
        
        # Обработка AAD
        for i in range(0, len(aad_padded), 16):
            block = aad_padded[i:i + 16]
            y = self._int_xor(y, self._bytes_to_int(block))
            y = self._mul_gf(y, self.table[1])
        
        # Обработка ciphertext
        for i in range(0, len(ct_padded), 16):
            block = ct_padded[i:i + 16]
            y = self._int_xor(y, self._bytes_to_int(block))
            y = self._mul_gf(y, self.table[1])
        
        # Добавление длин (64 бита каждая)
        len_block = struct.pack('>QQ', len_aad * 8, len_ct * 8)
        y = self._int_xor(y, self._bytes_to_int(len_block))
        y = self._mul_gf(y, self.table[1])
        
        return y
    
    def _generate_initial_counter(self):
        """Генерация начального значения счётчика из nonce"""
        if len(self.nonce) == 12:
            # Для 12-байтного nonce: J0 = nonce || 0x00000001
            j0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            # Для других размеров nonce: GHASH(nonce || padding)
            nonce_padded = self.nonce + bytes((-len(self.nonce)) % 16 + 8)
            len_block = struct.pack('>Q', len(self.nonce) * 8)
            j0 = self._ghash(b'', nonce_padded + len_block)
            j0 = self._int_to_bytes(j0)
        
        return j0
    
    def encrypt(self, plaintext, aad=b""):
        """
        Шифрование с аутентификацией
        
        Args:
            plaintext (bytes): Данные для шифрования
            aad (bytes): Ассоциированные данные (не шифруются)
        
        Returns:
            bytes: nonce + ciphertext + tag
        """
        # Генерация начального счётчика
        j0 = self._generate_initial_counter()
        
        # Генерация ключа для GHASH (H)
        h = self.aes.encrypt_block(bytes(16))
        h_int = self._bytes_to_int(h)
        self.table[1] = h_int
        self._precompute_table()  # Пересчёт таблицы с правильным H
        
        # Шифрование в CTR режиме
        ctr = self._bytes_to_int(j0[:12]) << 32 | 2
        ciphertext = bytearray()
        
        for i in range(0, len(plaintext), self.block_size):
            # Увеличение счётчика
            ctr_block = (ctr + (i // self.block_size)).to_bytes(16, 'big')
            keystream = self.aes.encrypt_block(ctr_block)
            
            # XOR с открытым текстом
            block = plaintext[i:i + self.block_size]
            encrypted = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(encrypted)
        
        ciphertext = bytes(ciphertext)
        
        # Вычисление тега аутентификации
        s = self.aes.encrypt_block(j0)
        s_int = self._bytes_to_int(s)
        
        ghash_result = self._ghash(aad, ciphertext)
        tag_int = self._int_xor(ghash_result, s_int)
        tag = self._int_to_bytes(tag_int)[:16]  # Обрезаем до 16 байт
        
        # Возвращаем nonce + ciphertext + tag
        return self.nonce + ciphertext + tag
    
    def decrypt(self, data, aad=b""):
        """
        Расшифрование с проверкой аутентификации
        
        Args:
            data (bytes): nonce + ciphertext + tag
            aad (bytes): Ассоциированные данные
        
        Returns:
            bytes: Расшифрованный текст
        
        Raises:
            AuthenticationError: Если аутентификация не удалась
        """
        if len(data) < 12 + 16:  # minimum: nonce(12) + tag(16)
            raise AuthenticationError("Данные слишком короткие")
        
        # Извлечение компонентов
        nonce = data[:12]
        tag = data[-16:]
        ciphertext = data[12:-16]
        
        # Установка nonce для проверки
        self.nonce = nonce
        
        # Генерация начального счётчика
        j0 = self._generate_initial_counter()
        
        # Генерация ключа для GHASH (H)
        h = self.aes.encrypt_block(bytes(16))
        h_int = self._bytes_to_int(h)
        self.table[1] = h_int
        self._precompute_table()
        
        # Вычисление ожидаемого тега
        s = self.aes.encrypt_block(j0)
        s_int = self._bytes_to_int(s)
        
        ghash_result = self._ghash(aad, ciphertext)
        expected_tag_int = self._int_xor(ghash_result, s_int)
        expected_tag = self._int_to_bytes(expected_tag_int)[:16]
        
        # Проверка тега (постоянная по времени)
        if not self._constant_time_compare(tag, expected_tag):
            raise AuthenticationError("Ошибка аутентификации: неверный тег")
        
        # Расшифрование в CTR режиме
        ctr = self._bytes_to_int(j0[:12]) << 32 | 2
        plaintext = bytearray()
        
        for i in range(0, len(ciphertext), self.block_size):
            # Увеличение счётчика
            ctr_block = (ctr + (i // self.block_size)).to_bytes(16, 'big')
            keystream = self.aes.encrypt_block(ctr_block)
            
            # XOR с шифртекстом
            block = ciphertext[i:i + self.block_size]
            decrypted = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext.extend(decrypted)
        
        return bytes(plaintext)
    
    def _constant_time_compare(self, a, b):
        """Сравнение с постоянным временем для предотвращения timing attacks"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0