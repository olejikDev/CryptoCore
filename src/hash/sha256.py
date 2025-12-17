"""
Реализация SHA-256 с нуля
Sprint 4: Следование NIST FIPS 180-4
Полностью ручная реализация без использования сторонних библиотек
"""

import struct


class SHA256:
    """Реализация SHA-256 хеш-функции с нуля"""

    # Начальные значения (первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
    INITIAL_HASH = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Константы (первые 32 бита дробных частей кубических корней первых 64 простых чисел)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        """Инициализация SHA-256"""
        self.hash_values = self.INITIAL_HASH[:]  # Текущие значения хеша (H0-H7)
        self.message_length = 0  # Длина сообщения в битах
        self.buffer = bytearray()  # Буфер для неполных блоков
        self.block_size = 64  # Размер блока в байтах (512 бит)

    def reset(self):
        """Сброс состояния для повторного использования"""
        self.hash_values = self.INITIAL_HASH[:]
        self.message_length = 0
        self.buffer = bytearray()

    @staticmethod
    def _right_rotate(x, n):
        """Циклический сдвиг вправо 32-битного числа"""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _ch(x, y, z):
        """Функция выбора (Choice)"""
        return (x & y) ^ (~x & z)

    @staticmethod
    def _maj(x, y, z):
        """Функция большинства (Majority)"""
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def _sigma0(x):
        """Функция σ0"""
        return (SHA256._right_rotate(x, 7) ^
                SHA256._right_rotate(x, 18) ^
                (x >> 3))

    @staticmethod
    def _sigma1(x):
        """Функция σ1"""
        return (SHA256._right_rotate(x, 17) ^
                SHA256._right_rotate(x, 19) ^
                (x >> 10))

    @staticmethod
    def _capital_sigma0(x):
        """Функция Σ0"""
        return (SHA256._right_rotate(x, 2) ^
                SHA256._right_rotate(x, 13) ^
                SHA256._right_rotate(x, 22))

    @staticmethod
    def _capital_sigma1(x):
        """Функция Σ1"""
        return (SHA256._right_rotate(x, 6) ^
                SHA256._right_rotate(x, 11) ^
                SHA256._right_rotate(x, 25))

    def _process_block(self, block):
        """Обработка одного 512-битного блока"""
        if len(block) != self.block_size:
            raise ValueError(f"Блок должен быть {self.block_size} байт, получено {len(block)}")

        # 1. Подготовка расписания сообщений (message schedule)
        w = [0] * 64

        # Первые 16 слов из блока (big-endian)
        for i in range(16):
            w[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

        # Остальные 48 слов
        for i in range(16, 64):
            s0 = self._sigma0(w[i - 15])
            s1 = self._sigma1(w[i - 2])
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        # 2. Инициализация рабочих переменных
        a, b, c, d, e, f, g, h = self.hash_values

        # 3. Главный цикл сжатия (64 раунда)
        for i in range(64):
            t1 = (h + self._capital_sigma1(e) + self._ch(e, f, g) +
                  self.K[i] + w[i]) & 0xFFFFFFFF
            t2 = (self._capital_sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        # 4. Добавление сжатого блока к текущему хешу
        self.hash_values[0] = (self.hash_values[0] + a) & 0xFFFFFFFF
        self.hash_values[1] = (self.hash_values[1] + b) & 0xFFFFFFFF
        self.hash_values[2] = (self.hash_values[2] + c) & 0xFFFFFFFF
        self.hash_values[3] = (self.hash_values[3] + d) & 0xFFFFFFFF
        self.hash_values[4] = (self.hash_values[4] + e) & 0xFFFFFFFF
        self.hash_values[5] = (self.hash_values[5] + f) & 0xFFFFFFFF
        self.hash_values[6] = (self.hash_values[6] + g) & 0xFFFFFFFF
        self.hash_values[7] = (self.hash_values[7] + h) & 0xFFFFFFFF

    def _pad_message(self):
        """Добавление padding по стандарту SHA-256"""
        # Длина сообщения в битах
        bit_length = self.message_length * 8

        # Добавляем бит '1' (0x80)
        padding = bytearray([0x80])

        # Добавляем нули до тех пор, пока длина не станет 448 бит (56 байт) по модулю 512
        # Текущая длина в байтах с учетом добавленного 0x80
        current_length = len(self.buffer) + len(padding)

        # Нужно добавить k нулей, где (l + 1 + k) ≡ 448 mod 512
        # l - исходная длина, 1 - байт 0x80
        # Преобразуем: k = (448 - (l + 1)) mod 512
        # Но так как мы работаем с байтами: k_zero_bytes = (56 - ((l + 1) % 64)) % 64

        k_zero_bytes = (56 - (current_length % 64)) % 64
        if k_zero_bytes < 0:
            k_zero_bytes += 64

        padding.extend([0] * k_zero_bytes)

        # Добавляем длину сообщения в битах как 64-битное big-endian число
        padding.extend(struct.pack('>Q', bit_length))

        return padding

    def update(self, data):
        """
        Добавление данных для хеширования
        Поддерживает инкрементальное хеширование
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Добавляем данные в буфер
        self.buffer.extend(data)
        self.message_length += len(data)

        # Обрабатываем полные блоки
        while len(self.buffer) >= self.block_size:
            block = bytes(self.buffer[:self.block_size])
            self._process_block(block)
            del self.buffer[:self.block_size]

    def digest(self):
        """Возвращает финальный хеш в бинарном формате"""
        # Сохраняем текущее состояние
        temp_hash = self.hash_values[:]
        temp_buffer = self.buffer[:]
        temp_length = self.message_length

        # Добавляем padding
        padding = self._pad_message()
        self.update(padding)  # Используем update для правильной обработки padding

        # Формируем результат
        result = bytearray()
        for h_val in self.hash_values:
            result.extend(struct.pack('>I', h_val))

        # Восстанавливаем состояние (на случай если продолжим update)
        self.hash_values = temp_hash
        self.buffer = temp_buffer
        self.message_length = temp_length

        return bytes(result)

    def hexdigest(self):
        """Возвращает финальный хеш в hex формате (нижний регистр)"""
        return self.digest().hex().lower()

    @staticmethod
    def hash(data):
        """Удобный метод для однократного хеширования"""
        sha = SHA256()
        sha.update(data)
        return sha.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """
        Хеширование файла чанками
        chunk_size: размер чанка в байтах
        """
        import os

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        # Сбрасываем состояние для нового файла
        self.__init__()

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                self.update(chunk)

        return self.hexdigest()


# Тестирование при прямом запуске
if __name__ == "__main__":
    print("=== ТЕСТ SHA-256 ===")

    # Тестовые векторы из NIST
    test_cases = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]

    all_pass = True
    for i, (input_str, expected) in enumerate(test_cases):
        result = SHA256.hash(input_str)
        if result == expected:
            print(f"✅ Тест {i + 1} пройден")
        else:
            print(f"❌ Тест {i + 1} не пройден")
            print(f"   Вход: '{input_str[:30]}{'...' if len(input_str) > 30 else ''}'")
            print(f"   Ожидалось: {expected}")
            print(f"   Получено:  {result}")
            all_pass = False

    if all_pass:
        print("\n✅ Все тесты SHA-256 пройдены!")
    else:
        print("\n❌ Некоторые тесты не пройдены")