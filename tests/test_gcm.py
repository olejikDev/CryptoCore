#!/usr/bin/env python3
"""
Тесты для GCM (Galois/Counter Mode) - Sprint 6
"""

import os
import unittest
import tempfile
from src.modes.gcm import GCM, AuthenticationError


class TestGCM(unittest.TestCase):
    """Тесты для реализации GCM"""

    def setUp(self):
        """Настройка тестов"""
        self.key_128 = os.urandom(16)  # AES-128 ключ
        self.key_256 = os.urandom(32)  # AES-256 ключ
        self.test_data = b"Hello, GCM World! This is test data for authenticated encryption."
        self.test_aad = b"Additional authenticated data for testing"

    def test_gcm_basic_encryption_decryption(self):
        """Тест базового шифрования и расшифрования"""
        print("\n=== Test 1: Basic GCM encryption/decryption ===")

        # Создаем GCM объект
        gcm = GCM(self.key_128)

        # Шифруем
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # Проверяем структуру (nonce + ciphertext + tag)
        self.assertEqual(len(ciphertext),
                         12 + len(self.test_data) + 16)  # nonce(12) + data + tag(16)

        # Расшифровываем - ПЕРЕДАЕМ ВЕСЬ CIPHERTEXT
        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, self.test_data)
        print("✓ Basic GCM test passed")

    def test_gcm_with_different_key_sizes(self):
        """Тест с разными размерами ключей"""
        print("\n=== Test 2: Different key sizes ===")

        for key in [self.key_128, self.key_256]:
            gcm = GCM(key)
            ciphertext = gcm.encrypt(self.test_data, self.test_aad)

            gcm2 = GCM(key, gcm.nonce)
            plaintext = gcm2.decrypt(ciphertext, self.test_aad)

            self.assertEqual(plaintext, self.test_data)

        print("✓ Different key sizes test passed")

    def test_gcm_authentication_failure_wrong_aad(self):
        """Тест неудачи аутентификации при неверном AAD"""
        print("\n=== Test 3: Authentication failure with wrong AAD ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # Создаем GCM с правильным nonce
        gcm2 = GCM(self.key_128, gcm.nonce)

        # Пробуем расшифровать с неверным AAD
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(ciphertext, b"wrong aad")

        print("✓ Wrong AAD detection test passed")

    def test_gcm_authentication_failure_tampered_ciphertext(self):
        """Тест неудачи аутентификации при измененном шифртексте"""
        print("\n=== Test 4: Authentication failure with tampered ciphertext ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # Изменяем один байт в ciphertext (не в nonce!)
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0x01  # Изменяем байт в ciphertext части (не первые 12 байт nonce)

        gcm2 = GCM(self.key_128, gcm.nonce)

        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(bytes(tampered), self.test_aad)

        print("✓ Tampered ciphertext detection test passed")

    def test_gcm_empty_aad(self):
        """Тест с пустым AAD"""
        print("\n=== Test 5: Empty AAD ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(self.test_data, b"")

        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, b"")

        self.assertEqual(plaintext, self.test_data)
        print("✓ Empty AAD test passed")

    def test_gcm_empty_plaintext(self):
        """Тест с пустым plaintext"""
        print("\n=== Test 6: Empty plaintext ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(b"", self.test_aad)

        # Проверяем размер (nonce + tag)
        self.assertEqual(len(ciphertext), 12 + 16)  # nonce + tag

        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, b"")
        print("✓ Empty plaintext test passed")

    def test_gcm_large_data(self):
        """Тест с большими данными"""
        print("\n=== Test 7: Large data ===")

        large_data = os.urandom(1024 * 1024)  # 1 MB данных
        gcm = GCM(self.key_128)

        ciphertext = gcm.encrypt(large_data, self.test_aad)
        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, large_data)
        print("✓ Large data test passed")

    def test_gcm_nonce_uniqueness(self):
        """Тест уникальности nonce"""
        print("\n=== Test 8: Nonce uniqueness ===")

        nonces = set()
        for _ in range(100):
            gcm = GCM(self.key_128)
            nonces.add(gcm.nonce.hex())

        # Все nonce должны быть уникальными
        self.assertEqual(len(nonces), 100)
        print("✓ Nonce uniqueness test passed")

    def test_gcm_file_encryption_decryption(self):
        """Тест шифрования и расшифрования файлов"""
        print("\n=== Test 9: File encryption/decryption ===")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Создаем тестовый файл
            f.write(self.test_data)
            input_file = f.name

        try:
            # Шифруем файл
            gcm = GCM(self.key_128)
            ciphertext = gcm.encrypt(self.test_data, self.test_aad)

            # Сохраняем зашифрованные данные
            encrypted_file = input_file + '.enc'
            with open(encrypted_file, 'wb') as f:
                f.write(ciphertext)

            # Расшифровываем
            with open(encrypted_file, 'rb') as f:
                ciphertext_from_file = f.read()

            gcm2 = GCM(self.key_128, gcm.nonce)
            plaintext = gcm2.decrypt(ciphertext_from_file, self.test_aad)

            self.assertEqual(plaintext, self.test_data)
            print("✓ File encryption/decryption test passed")

        finally:
            # Очистка
            if os.path.exists(input_file):
                os.remove(input_file)
            if os.path.exists(input_file + '.enc'):
                os.remove(input_file + '.enc')

    def test_gcm_with_provided_nonce(self):
        """Тест с предоставленным nonce"""
        print("\n=== Test 10: GCM with provided nonce ===")

        # Создаем фиксированный nonce
        nonce = b"\x00" * 12  # 12 нулевых байт

        gcm = GCM(self.key_128, nonce)
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # Проверяем что nonce в начале ciphertext совпадает
        self.assertEqual(ciphertext[:12], nonce)

        gcm2 = GCM(self.key_128, nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, self.test_data)
        print("✓ GCM with provided nonce test passed")

    def test_gcm_iv_attribute(self):
        """Тест что атрибут iv доступен (для совместимости)"""
        print("\n=== Test 11: IV attribute test ===")

        gcm = GCM(self.key_128)

        # Проверяем что есть атрибут nonce
        self.assertTrue(hasattr(gcm, 'nonce'))
        self.assertEqual(len(gcm.nonce), 12)

        # Для обратной совместимости может быть атрибут iv
        if hasattr(gcm, 'iv'):
            self.assertEqual(gcm.iv, gcm.nonce)

        print("✓ IV attribute test passed")

    def test_gcm_chunk_processing(self):
        """Тест обработки данных по частям (если реализовано)"""
        print("\n=== Test 12: Chunk processing test ===")

        # Создаем данные, которые будут обрабатываться по частям
        data_parts = [
            b"Part 1: ",
            b"Part 2: ",
            b"Part 3: Final data"
        ]

        full_data = b"".join(data_parts)

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(full_data, self.test_aad)

        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, full_data)
        print("✓ Chunk processing test passed")

    def test_gcm_error_handling(self):
        """Тест обработки ошибок"""
        print("\n=== Test 13: Error handling test ===")

        gcm = GCM(self.key_128)

        # Слишком короткие данные
        with self.assertRaises(AuthenticationError):
            gcm.decrypt(b"short", self.test_aad)

        # Нет nonce в данных (меньше 12 байт)
        with self.assertRaises(AuthenticationError):
            gcm.decrypt(b"\x00" * 10, self.test_aad)

        # Нет tag в данных (ровно 12 байт - только nonce)
        with self.assertRaises(AuthenticationError):
            gcm.decrypt(b"\x00" * 12, self.test_aad)

        print("✓ Error handling test passed")


def run_gcm_tests():
    """Запуск всех GCM тестов"""
    print("=" * 60)
    print("Running GCM (Galois/Counter Mode) Tests")
    print("=" * 60)

    suite = unittest.TestLoader().loadTestsFromTestCase(TestGCM)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"GCM Tests Summary: {result.testsRun} tests run")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 60)

    return result.wasSuccessful()


if __name__ == "__main__":
    # Запуск тестов с детальным выводом
    run_gcm_tests()