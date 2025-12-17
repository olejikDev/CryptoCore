"""
Основной класс для шифрования и дешифрования файлов
Sprint 4: Обновлено для правильной работы режимов
"""

from src.modes.ecb import ECBMode
from src.modes.cbc import CBCMode
from src.modes.cfb import CFBMode
from src.modes.ofb import OFBMode
from src.modes.ctr import CTRMode
from src.file_io import read_binary, write_binary
from src.csprng import generate_aes_key, generate_aes_key_hex


class CryptoCipher:
    """Основной класс для работы с шифрованием"""

    def __init__(self, algorithm, mode, key=None, iv=None):
        """Инициализация шифра"""
        self.algorithm = algorithm.lower()
        self.mode = mode.lower()
        self.auto_generated_key = None

        # Sprint 3: Обработка ключа (может быть None для auto-generation)
        self.key = self._process_key(key)
        self.iv = self._parse_iv(iv) if iv else None

        # Сохраняем оригинальный режим для определения padding
        self.original_mode = mode.lower()

        self.cipher = self._init_cipher()

    def _process_key(self, key_str):
        """
        Обработка ключа:
        - Если передан ключ, парсим его
        - Если None, генерируем случайный ключ
        """
        if key_str:
            # Используем переданный ключ
            return self._parse_key(key_str)
        else:
            # Sprint 3: Генерация случайного ключа
            self.auto_generated_key = generate_aes_key()
            return self.auto_generated_key

    def _parse_key(self, key_str):
        """Парсинг ключа из hex строки"""
        # Убираем префикс @ если есть
        if key_str.startswith('@'):
            key_str = key_str[1:]

        try:
            key_bytes = bytes.fromhex(key_str)

            if len(key_bytes) != 16:
                raise ValueError(f"Для AES-128 требуется ключ длиной 16 байт. Получено: {len(key_bytes)} байт")

            return key_bytes

        except ValueError as e:
            raise ValueError(f"Некорректный формат ключа '{key_str}': {e}")

    def _parse_iv(self, iv_str):
        """Парсинг IV из hex строки"""
        try:
            iv_bytes = bytes.fromhex(iv_str)

            if len(iv_bytes) != 16:
                raise ValueError(f"IV должен быть длиной 16 байт. Получено: {len(iv_bytes)} байт")

            return iv_bytes

        except ValueError as e:
            raise ValueError(f"Некорректный формат IV '{iv_str}': {e}")

    def _init_cipher(self):
        """Инициализация объекта шифрования"""
        if self.algorithm != "aes":
            raise ValueError(f"Неподдерживаемый алгоритм: {self.algorithm}")

        mode_classes = {
            'ecb': ECBMode,
            'cbc': CBCMode,
            'cfb': CFBMode,
            'ofb': OFBMode,
            'ctr': CTRMode
        }

        if self.mode not in mode_classes:
            raise ValueError(f"Неподдерживаемый режим: {self.mode}")

        cipher_class = mode_classes[self.mode]

        # Для ECB не нужен IV
        if self.mode == 'ecb':
            return cipher_class(self.key)
        else:
            # Для остальных режимов передаем IV (может быть None)
            return cipher_class(self.key, self.iv)

    def get_auto_generated_key_hex(self):
        """
        Получить auto-generated ключ в hex формате

        Returns:
            str: hex строка ключа или None если ключ не был auto-generated
        """
        if self.auto_generated_key:
            return self.auto_generated_key.hex()
        return None

    def encrypt_file(self, input_file, output_file):
        """Шифрование файла"""
        plaintext = read_binary(input_file)
        ciphertext = self.cipher.encrypt(plaintext)
        write_binary(output_file, ciphertext)

    def decrypt_file(self, input_file, output_file):
        """Дешифрование файла"""
        ciphertext = read_binary(input_file)
        plaintext = self._decrypt_data(ciphertext)
        write_binary(output_file, plaintext)

    def _decrypt_data(self, ciphertext):
        """Дешифрование данных с учетом режима"""
        # Для ECB
        if self.mode == 'ecb':
            return self.cipher.decrypt(ciphertext, remove_padding=True)

        # Для режимов с IV
        if self.iv:
            # Если IV был передан в командной строке
            if self.mode == 'cbc':
                # Для CBC пробуем с padding, если не получается - без padding
                try:
                    return self.cipher.decrypt(ciphertext, remove_padding=True)
                except:
                    return self.cipher.decrypt(ciphertext, remove_padding=False)
            else:
                # CFB, OFB, CTR - потоковые режимы без padding
                return self.cipher.decrypt(ciphertext, remove_padding=False)
        else:
            # Если IV не был передан, читаем его из начала файла
            if len(ciphertext) < 16:
                raise ValueError(
                    f"Файл слишком короткий для получения IV. Требуется минимум 16 байт, получено: {len(ciphertext)} байт")

            # Читаем IV из файла
            file_iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]

            # Создаем новый cipher с IV из файла
            mode_classes = {
                'cbc': CBCMode,
                'cfb': CFBMode,
                'ofb': OFBMode,
                'ctr': CTRMode
            }

            cipher_class = mode_classes[self.mode]
            cipher = cipher_class(self.key, file_iv)

            # Для CBC пробуем с padding, если не получается - без padding
            if self.mode == 'cbc':
                try:
                    return cipher.decrypt(actual_ciphertext, remove_padding=True)
                except:
                    return cipher.decrypt(actual_ciphertext, remove_padding=False)
            else:
                # CFB, OFB, CTR - потоковые режимы без padding
                return cipher.decrypt(actual_ciphertext, remove_padding=False)