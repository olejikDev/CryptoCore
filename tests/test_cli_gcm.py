#!/usr/bin/env python3
"""
Интеграционные тесты для CLI с GCM
"""

import os
import subprocess
import tempfile
import unittest


class TestCLIGCM(unittest.TestCase):
    """Тесты CLI с GCM режимом"""

    def setUp(self):
        """Настройка тестов"""
        self.test_data = b"Test data for CLI GCM testing"
        self.key = "00112233445566778899aabbccddeeff"
        self.aad = "aabbccddeeff00112233445566778899"

    def run_command(self, cmd):
        """Запуск команды и возврат результата"""
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        return result.returncode, result.stdout, result.stderr

    def test_cli_gcm_encrypt_decrypt(self):
        """Тест CLI: GCM шифрование и расшифрование"""
        print("\n=== Test 1: CLI GCM encryption/decryption ===")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as plain_file:
            plain_file.write(self.test_data)
            plain_path = plain_file.name

        encrypted_path = plain_path + '.enc'
        decrypted_path = plain_path + '.dec'

        try:
            # 1. Шифрование
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --encrypt \
                  --key {self.key} --input {plain_path} --output {encrypted_path} \
                  --aad {self.aad}"

            returncode, stdout, stderr = self.run_command(cmd)
            print(f"Encryption command: {cmd}")
            print(f"Return code: {returncode}")
            print(f"Stdout: {stdout}")
            print(f"Stderr: {stderr}")

            self.assertEqual(returncode, 0, f"Encryption failed: {stderr}")
            self.assertTrue(os.path.exists(encrypted_path))

            # 2. Дешифрование
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --decrypt \
                  --key {self.key} --input {encrypted_path} --output {decrypted_path} \
                  --aad {self.aad}"

            returncode, stdout, stderr = self.run_command(cmd)
            print(f"\nDecryption command: {cmd}")
            print(f"Return code: {returncode}")
            print(f"Stdout: {stdout}")
            print(f"Stderr: {stderr}")

            self.assertEqual(returncode, 0, f"Decryption failed: {stderr}")
            self.assertTrue(os.path.exists(decrypted_path))

            # 3. Проверка данных
            with open(decrypted_path, 'rb') as f:
                decrypted_data = f.read()

            self.assertEqual(decrypted_data, self.test_data)
            print("✓ CLI GCM encryption/decryption test passed")

        finally:
            # Очистка
            for path in [plain_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.remove(path)

    def test_cli_gcm_auth_failure(self):
        """Тест CLI: неудача аутентификации GCM"""
        print("\n=== Test 2: CLI GCM authentication failure ===")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as plain_file:
            plain_file.write(self.test_data)
            plain_path = plain_file.name

        encrypted_path = plain_path + '.enc'
        decrypted_path = plain_path + '.dec'

        try:
            # 1. Шифрование с правильным AAD
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --encrypt \
                  --key {self.key} --input {plain_path} --output {encrypted_path} \
                  --aad {self.aad}"

            self.run_command(cmd)

            # 2. Пробуем дешифровать с неправильным AAD
            wrong_aad = "ffffffffffffffffffffffffffffffff"
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --decrypt \
                  --key {self.key} --input {encrypted_path} --output {decrypted_path} \
                  --aad {wrong_aad}"

            returncode, stdout, stderr = self.run_command(cmd)

            # Должен быть ненулевой код возврата при неудачной аутентификации
            self.assertNotEqual(returncode, 0,
                                "Should fail with wrong AAD but didn't")

            # Файл не должен быть создан
            self.assertFalse(os.path.exists(decrypted_path),
                             "Output file should not be created on auth failure")

            print("✓ CLI GCM authentication failure test passed")

        finally:
            # Очистка
            for path in [plain_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.remove(path)


if __name__ == "__main__":
    print("Running CLI GCM tests...")
    unittest.main(verbosity=2)