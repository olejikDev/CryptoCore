"""
Основной класс для работы с хеш-функциями
Sprint 4: Управление различными алгоритмами хеширования
"""

import os
from .sha256 import SHA256
from .sha3_256 import SHA3_256


class HashCore:
    """Основной класс для работы с хеш-функциями"""

    SUPPORTED_ALGORITHMS = {
        'sha256': SHA256,
        'sha3-256': SHA3_256,
    }

    def __init__(self, algorithm='sha256'):
        """нициализация хеш-алгоритма"""
        algorithm = algorithm.lower()

        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Неподдерживаемый алгоритм: {algorithm}. "
                             f"Поддерживается: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}")

        self.algorithm_name = algorithm
        self.hasher = self.SUPPORTED_ALGORITHMS[algorithm]()

    def hash_data(self, data):
        """Хеширование данных"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.hasher.update(data)
        return self.hasher.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """
        Хеширование файла чанками

        Args:
            filepath: путь к файлу
            chunk_size: размер чанка в байтах

        Returns:
            str: hex хеш файла
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        if not os.path.isfile(filepath):
            raise ValueError(f"'{filepath}' не является файлом")

        return self.hasher.hash_file(filepath, chunk_size)

    def hash_file_incremental(self, filepath, chunk_size=8192):
        """
        нкрементальное хеширование файла (генератор)
        Полезно для прогресс-баров
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        file_size = os.path.getsize(filepath)
        bytes_processed = 0

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                self.hasher.update(chunk)
                bytes_processed += len(chunk)

                # Возвращаем прогресс
                yield bytes_processed / file_size if file_size > 0 else 1.0

        return self.hasher.hexdigest()

