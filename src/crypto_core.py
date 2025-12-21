#!/usr/bin/env python3
"""
Основной класс для шифрования и дешифрования файлов
Sprint 6: Добавлена поддержка GCM и AEAD
"""

import sys
import os
from typing import Optional

# Импорты из существующих модулей
from src.modes.ecb import ECBMode
from src.modes.cbc import CBCMode
from src.modes.cfb import CFBMode
from src.modes.ofb import OFBMode
from src.modes.ctr import CTRMode
from src.modes.gcm import GCM, AuthenticationError
from src.aead import EncryptThenMAC, AuthenticationError
from src.file_io import FileHandler, read_file_safe, write_file_safe
from src.csprng import generate_random_bytes, generate_aes_key, generate_aes_key_hex


class CryptoCipher:
    """Основной класс для работы с шифрованием"""

    def __init__(self, algorithm, mode, key=None, iv=None, aad=None):
        """Инициализация шифра"""
        self.algorithm = algorithm.lower()
        self.mode = mode.lower()
        self.auto_generated_key = None
        self.aad = aad or b""

        # Sprint 3: Обработка ключа (может быть None для auto-generation)
        self.key = self._process_key(key)

        # Для GCM используем nonce (12 байт), для других режимов IV (16 байт)
        if self.mode == 'gcm':
            self.nonce = self._parse_nonce(iv) if iv else None
            self.iv = self.nonce  # Для совместимости
        else:
            self.iv = self._parse_iv(iv) if iv else None
            self.nonce = None

        # Сохраняем оригинальный режим
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
            self.auto_generated_key = generate_random_bytes(16)
            print(f"[INFO] Generated random key: {self.auto_generated_key.hex()}")
            return self.auto_generated_key

    def _parse_key(self, key_str):
        """Парсинг ключа из hex строки"""
        # Убираем префикс @ если есть
        if key_str.startswith('@'):
            key_str = key_str[1:]

        try:
            key_bytes = bytes.fromhex(key_str)

            if len(key_bytes) not in [16, 24, 32]:
                print(f"WARNING: AES key should be 16, 24, or 32 bytes, got {len(key_bytes)}",
                      file=sys.stderr)

            return key_bytes

        except ValueError as e:
            raise ValueError(f"Некорректный формат ключа '{key_str}': {e}")

    def _parse_iv(self, iv_str):
        """Парсинг IV из hex строки (16 байт для CBC, CFB, OFB, CTR)"""
        try:
            iv_bytes = bytes.fromhex(iv_str)
            if len(iv_bytes) != 16 and self.mode != 'gcm':
                print(f"WARNING: IV should be 16 bytes for {self.mode}, got {len(iv_bytes)}",
                      file=sys.stderr)
            return iv_bytes
        except ValueError as e:
            raise ValueError(f"Некорректный формат IV '{iv_str}': {e}")

    def _parse_nonce(self, nonce_str):
        """Парсинг nonce из hex строки (12 байт для GCM)"""
        try:
            nonce_bytes = bytes.fromhex(nonce_str)
            if len(nonce_bytes) != 12:
                print(f"WARNING: GCM nonce is recommended to be 12 bytes, got {len(nonce_bytes)}",
                      file=sys.stderr)
            return nonce_bytes
        except ValueError as e:
            raise ValueError(f"Некорректный формат nonce '{nonce_str}': {e}")

    def _init_cipher(self):
        """Инициализация объекта шифрования"""
        if self.algorithm != "aes":
            raise ValueError(f"Неподдерживаемый алгоритм: {self.algorithm}")

        mode_classes = {
            'ecb': ECBMode,
            'cbc': CBCMode,
            'cfb': CFBMode,
            'ofb': OFBMode,
            'ctr': CTRMode,
            'gcm': GCM,
            'aead': EncryptThenMAC
        }

        if self.mode not in mode_classes:
            raise ValueError(f"Неподдерживаемый режим: {self.mode}")

        cipher_class = mode_classes[self.mode]

        # Для GCM используем nonce
        if self.mode == 'gcm':
            return cipher_class(self.key, self.nonce)

        # Для AEAD используем master key и AAD
        if self.mode == 'aead':
            # AEAD требует отдельные ключи для шифрования и MAC
            enc_key, mac_key = EncryptThenMAC.derive_keys(self.key)
            return cipher_class(enc_key, mac_key, cipher_mode='ctr')

        # Для ECB не нужен IV
        if self.mode == 'ecb':
            return cipher_class(self.key)

        # Для остальных режимов передаем IV
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
        try:
            # Читаем входной файл
            plaintext = read_file_safe(input_file)

            print(f"[INFO] Encrypting {len(plaintext)} bytes with {self.mode.upper()} mode")

            # Handle different modes
            if self.mode == 'gcm':
                # GCM encryption with AAD
                ciphertext = self.cipher.encrypt(plaintext, self.aad)
                print(f"[INFO] GCM nonce: {self.cipher.nonce.hex()}")
                print(f"[INFO] AAD length: {len(self.aad)} bytes")

            elif self.mode == 'aead':
                # Encrypt-then-MAC
                ciphertext = self.cipher.encrypt(plaintext, self.aad)

            else:
                # Traditional modes (ECB, CBC, CFB, OFB, CTR)
                ciphertext = self.cipher.encrypt(plaintext)

                # Для режимов с IV (кроме ECB) выводим IV
                if self.mode in ['cbc', 'cfb', 'ofb', 'ctr'] and hasattr(self.cipher, 'iv'):
                    print(f"[INFO] IV: {self.cipher.iv.hex()}")

            # Записываем результат
            write_file_safe(output_file, ciphertext)

            print(f"[SUCCESS] Encryption completed. Output: {output_file}")

            # Return generated key if any
            return self.get_auto_generated_key_hex()

        except Exception as e:
            print(f"ERROR: Encryption failed: {e}", file=sys.stderr)
            sys.exit(1)

    def decrypt_file(self, input_file, output_file):
        """Дешифрование файла"""
        try:
            # Читаем входной файл
            ciphertext = read_file_safe(input_file)

            print(f"[INFO] Decrypting {len(ciphertext)} bytes with {self.mode.upper()} mode")

            # Handle different modes
            if self.mode == 'gcm':
                # GCM decryption with authentication
                try:
                    # Для GCM nonce либо предоставлен, либо читается из файла
                    if self.nonce:
                        # Nonce предоставлен явно
                        plaintext = self.cipher.decrypt(ciphertext, self.aad)
                    else:
                        # Nonce читается из файла (первые 12 байт)
                        if len(ciphertext) < 12:
                            raise ValueError("File too short for GCM nonce")

                        # Создаем новый GCM объект с nonce из файла
                        file_nonce = ciphertext[:12]
                        actual_ciphertext = ciphertext[12:]

                        gcm = GCM(self.key, file_nonce)
                        plaintext = gcm.decrypt(actual_ciphertext, self.aad)

                    print(f"[SUCCESS] GCM authentication successful")

                except AuthenticationError as e:
                    print(f"ERROR: Authentication failed: {e}", file=sys.stderr)

                    # Clean up output file on auth failure
                    FileHandler.cleanup_on_failure(output_file)

                    sys.exit(1)

            elif self.mode == 'aead':
                # Decrypt-and-verify with AEAD
                try:
                    plaintext = self.cipher.decrypt(ciphertext, self.aad)
                    print(f"[SUCCESS] AEAD authentication successful")
                except Exception as e:
                    print(f"ERROR: Authentication failed: {e}", file=sys.stderr)
                    FileHandler.cleanup_on_failure(output_file)
                    sys.exit(1)

            else:
                # Traditional modes decryption
                plaintext = self._decrypt_data(ciphertext)

            # Записываем результат
            write_file_safe(output_file, plaintext)

            print(f"[SUCCESS] Decryption completed. Output: {output_file}")

        except Exception as e:
            print(f"ERROR: Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)

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


# ===== УТИЛИТЫ ДЛЯ ФАЙЛОВОГО ВВОДА/ВЫВОДА =====
def read_binary(filepath: str) -> bytes:
    """Чтение файла в бинарном режиме (для обратной совместимости)"""
    return read_file_safe(filepath)

def write_binary(filepath: str, data: bytes) -> None:
    """Запись файла в бинарном режиме (для обратной совместимости)"""
    write_file_safe(filepath, data)


# ===== ТЕСТИРОВАНИЕ =====
def test_crypto_core():
    """Тестирование CryptoCipher"""
    print("Testing CryptoCipher...")

    # Test key generation
    test_key = generate_aes_key()
    print(f"1. Generated test key: {test_key.hex()}")

    # Test GCM mode
    try:
        gcm = GCM(test_key)
        test_data = b"Hello, GCM World!"
        test_aad = b"authenticated data"

        encrypted = gcm.encrypt(test_data, test_aad)
        decrypted = gcm.decrypt(encrypted, test_aad)

        assert decrypted == test_data
        print("2. ✓ GCM encryption/decryption test passed")

    except Exception as e:
        print(f"2. ✗ GCM test failed: {e}")

    print("\n[+] CryptoCipher tests completed")


if __name__ == "__main__":
    test_crypto_core()