#!/usr/bin/env python3
"""
Тесты для AEAD (Authenticated Encryption with Associated Data) - Sprint 6
"""

import os
import unittest
import tempfile
from src.aead import EncryptThenMAC, AuthenticationError


class TestAEAD(unittest.TestCase):
    """Тесты для Encrypt-then-MAC"""

    def setUp(self):
        """Настройка тестов"""
        self.master_key = os.urandom(32)
        self.test_data = b"Test data for Encrypt-then-MAC AEAD"
        self.test_aad = b"Associated authenticated data"

    def test_key_derivation(self):
        """Тест генерации ключей"""
        print("\n=== Test 1: Key derivation ===")

        enc_key, mac_key = EncryptThenMAC.derive_keys(self.master_key)

        # Проверяем размеры ключей
        self.assertEqual(len(enc_key), 16)  # AES-128 ключ
        self.assertEqual(len(mac_key), 32)  # SHA-256 ключ

        # Ключи должны быть разными
        self.assertNotEqual(enc_key, mac_key[:16])
        print("✓ Key derivation test passed")

    def test_encrypt_then_mac_basic(self):
        """Тест базового Encrypt-then-MAC"""
        print("\n=== Test 2: Basic Encrypt-then-MAC ===")

        # Генерируем ключи
        enc_key, mac_key = EncryptThenMAC.derive_keys(self.master_key)

        # Создаем AEAD объект
        aead = EncryptThenMAC(enc_key, mac_key, 'ctr')

        # Шифруем
        ciphertext = aead.encrypt(self.test_data, self.test_aad)

        # Проверяем структуру (IV + ciphertext + tag)
        # IV (16) + ciphertext + tag (32 для SHA-256)
        self.assertGreaterEqual(len(ciphertext), 16 + 32)

        # Расшифровываем
        plaintext = aead.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, self.test_data)
        print("✓ Basic Encrypt-then-MAC test passed")

    def test_authentication_failure_wrong_key(self):
        """Тест неудачи аутентификации при неверном ключе"""
        print("\n=== Test 3: Authentication failure with wrong key ===")

        enc_key1, mac_key1 = EncryptThenMAC.derive_keys(self.master_key)
        enc_key2, mac_key2 = EncryptThenMAC.derive_keys(os.urandom(32))

        aead1 = EncryptThenMAC(enc_key1, mac_key1, 'ctr')
        aead2 = EncryptThenMAC(enc_key2, mac_key2, 'ctr')

        ciphertext = aead1.encrypt(self.test_data, self.test_aad)

        # Пробуем расшифровать другим ключом
        with self.assertRaises(AuthenticationError):
            aead2.decrypt(ciphertext, self.test_aad)

        print("✓ Wrong key detection test passed")

    def test_authentication_failure_wrong_aad(self):
        """Тест неудачи аутентификации при неверном AAD"""
        print("\n=== Test 4: Authentication failure with wrong AAD ===")

        enc_key, mac_key = EncryptThenMAC.derive_keys(self.master_key)
        aead = EncryptThenMAC(enc_key, mac_key, 'ctr')

        ciphertext = aead.encrypt(self.test_data, self.test_aad)

        # Пробуем расшифровать с неверным AAD
        with self.assertRaises(AuthenticationError):
            aead.decrypt(ciphertext, b"wrong aad")

        print("✓ Wrong AAD detection test passed")

    # ... остальные тесты остаются без изменений ...


if __name__ == "__main__":
    print("Running AEAD tests...")
    unittest.main(verbosity=2)