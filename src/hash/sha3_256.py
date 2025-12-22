"""
Реализация SHA3-256 с нуля
Sprint 4: Следование NIST FIPS 202 (Keccak sponge construction)
"""

import struct


class SHA3_256:
    """Реализация SHA3-256 хеш-функции с нуля"""

    # Параметры для SHA3-256
    RATE = 1088  # Скорость (r) в битах = 136 байт
    CAPACITY = 512  # Емкость (c) в битах
    OUTPUT_SIZE = 256  # Размер выхода в битах = 32 байта
    BLOCK_SIZE = 136  # Размер блока в байтах (RATE/8)

    # Константы для Keccak-f[1600]
    ROUND_CONSTANTS = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    ROTATION_OFFSETS = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

    def __init__(self):
        """нициализация SHA3-256"""
        # Состояние Keccak (5x5 матрица 64-битных слов)
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self._is_finalized = False

    def reset(self):
        """Сброс состояния для повторного использования"""
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self._is_finalized = False
        if hasattr(self, '_final_hash'):
            delattr(self, '_final_hash')

    @staticmethod
    def _rotate_left_64(x, n):
        """Циклический сдвиг 64-битного числа влево"""
        n = n % 64
        return ((x << n) & ((1 << 64) - 1)) | (x >> (64 - n))

    def _theta(self):
        """Функция θ (theta)"""
        c = [0] * 5
        d = [0] * 5

        # Вычисляем столбцовые суммы
        for x in range(5):
            c[x] = (self.state[x][0] ^ self.state[x][1] ^
                    self.state[x][2] ^ self.state[x][3] ^
                    self.state[x][4])

        # Вычисляем d
        for x in range(5):
            d[x] = c[(x - 1) % 5] ^ self._rotate_left_64(c[(x + 1) % 5], 1)

        # Применяем к состоянию
        for x in range(5):
            for y in range(5):
                self.state[x][y] ^= d[x]

    def _rho_pi(self):
        """Функции ρ (rho) и π (pi)"""
        new_state = [[0] * 5 for _ in range(5)]

        for x in range(5):
            for y in range(5):
                # Применяем π перестановку
                new_x = y
                new_y = (2 * x + 3 * y) % 5

                # Применяем ρ сдвиг
                rotated = self._rotate_left_64(
                    self.state[x][y],
                    self.ROTATION_OFFSETS[x][y]
                )
                new_state[new_x][new_y] = rotated

        self.state = new_state

    def _chi(self):
        """Функция χ (chi)"""
        new_state = [[0] * 5 for _ in range(5)]

        for x in range(5):
            for y in range(5):
                new_state[x][y] = (self.state[x][y] ^
                                   ((~self.state[(x + 1) % 5][y]) &
                                    self.state[(x + 2) % 5][y]))

        self.state = new_state

    def _iota(self, round_idx):
        """Функция ι (iota) - добавление round constant"""
        self.state[0][0] ^= self.ROUND_CONSTANTS[round_idx]

    def _keccak_f(self):
        """Функция перестановки Keccak-f[1600] (24 раунда)"""
        for round_idx in range(24):
            self._theta()
            self._rho_pi()
            self._chi()
            self._iota(round_idx)

    def _absorb_block(self, block):
        """Поглощение блока в состояние"""
        # Блок должен быть 136 байт для SHA3-256
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Блок должен быть {self.BLOCK_SIZE} байт, получено {len(block)}")

        # Преобразуем блок в 64-битные слова и XOR с состоянием
        for i in range(self.BLOCK_SIZE // 8):  # 136/8 = 17 слов
            # Вычисляем позицию в состоянии (5x5)
            pos = i
            x = pos % 5
            y = pos // 5

            # звлекаем слово из блока (little-endian)
            word_bytes = block[i * 8:(i + 1) * 8]
            word = struct.unpack('<Q', word_bytes)[0]

            # XOR с состоянием
            self.state[x][y] ^= word

    def _pad(self, length):
        """Добавление padding для SHA-3"""
        # SHA-3 использует multi-rate padding
        # Формула: M || 0x06 || 0x00... || 0x80

        block_size = self.BLOCK_SIZE
        padding_length = block_size - (length % block_size)

        if padding_length == 1:
            # Специальный случай: нужно добавить новый блок
            padding = bytearray([0x86])  # 0x06 | 0x80
        elif padding_length == 2:
            padding = bytearray([0x06, 0x80])
        else:
            padding = bytearray([0x06])
            padding.extend([0] * (padding_length - 2))
            padding.append(0x80)

        return padding

    def update(self, data):
        """Добавление данных для хеширования"""
        if self._is_finalized:
            raise RuntimeError("Хеш уже финализирован")

        if isinstance(data, str):
            data = data.encode('utf-8')

        self.buffer.extend(data)

        # Поглощаем полные блоки
        while len(self.buffer) >= self.BLOCK_SIZE:
            block = bytes(self.buffer[:self.BLOCK_SIZE])
            self._absorb_block(block)
            self._keccak_f()
            del self.buffer[:self.BLOCK_SIZE]

    def digest(self):
        """Возвращает финальный хеш в бинарном формате"""
        if self._is_finalized:
            # Возвращаем кэшированный результат
            return self._final_hash

        # Добавляем padding
        padding = self._pad(len(self.buffer))
        self.buffer.extend(padding)

        # Поглощаем последний блок
        if len(self.buffer) != self.BLOCK_SIZE:
            raise ValueError(f"После padding длина должна быть {self.BLOCK_SIZE}, получено {len(self.buffer)}")

        block = bytes(self.buffer[:self.BLOCK_SIZE])
        self._absorb_block(block)
        self._keccak_f()

        # Выжимаем результат (squeezing phase)
        result = bytearray()
        output_bytes = self.OUTPUT_SIZE // 8  # 32 байта
        bytes_extracted = 0

        while bytes_extracted < output_bytes:
            # Преобразуем часть состояния в байты
            for y in range(5):
                for x in range(5):
                    if bytes_extracted >= output_bytes:
                        break

                    # Конвертируем слово в байты (little-endian)
                    word_bytes = struct.pack('<Q', self.state[x][y])

                    # Добавляем сколько нужно байт
                    bytes_needed = min(8, output_bytes - bytes_extracted)
                    result.extend(word_bytes[:bytes_needed])
                    bytes_extracted += bytes_needed

            if bytes_extracted < output_bytes:
                self._keccak_f()

        # Кэшируем результат
        self._final_hash = bytes(result[:output_bytes])
        self._is_finalized = True

        return self._final_hash

    def hexdigest(self):
        """Возвращает финальный хеш в hex формате (нижний регистр)"""
        return self.digest().hex().lower()

    @staticmethod
    def hash(data):
        """Удобный метод для однократного хеширования"""
        sha3 = SHA3_256()
        sha3.update(data)
        return sha3.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """Хеширование файла чанками"""
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


# Быстрый тест функции
if __name__ == "__main__":
    print("=== ТЕСТ SHA3-256 ===")

    # Тест 1: Пустая строка
    sha3 = SHA3_256()
    result = sha3.hash("")
    expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    print(f"Пустая строка: {result == expected} {result}")

    # Тест 2: "abc"
    sha3 = SHA3_256()
    result = sha3.hash("abc")
    expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    print(f"'abc': {result == expected} {result}")

