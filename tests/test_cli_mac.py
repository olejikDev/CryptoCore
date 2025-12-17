"""
Тестирование CLI команды HMAC/CMAC
"""

import unittest
import os
import tempfile
import subprocess
import sys


class TestCLIMAC(unittest.TestCase):
    """Тесты CLI для HMAC и CMAC"""

    def setUp(self):
        """Создание тестовых файлов"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")

        with open(self.test_file, 'w') as f:
            f.write("Test data for MAC verification\n")

        # Путь к cryptocore.py
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.cryptocore_path = os.path.join(self.project_root, "cryptocore.py")

    def tearDown(self):
        """Очистка"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_cryptocore(self, args):
        """Запуск cryptocore с аргументами"""
        cmd = [sys.executable, self.cryptocore_path] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.project_root
        )
        return result

    def test_hmac_generation(self):
        """Генерация HMAC через CLI"""
        key = "00112233445566778899aabbccddeeff"

        result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file
        ])

        # Проверяем, что команда выполнилась успешно
        self.assertEqual(result.returncode, 0)
        # Проверяем формат вывода: hex_hash filename
        self.assertTrue(" " in result.stdout.strip())
        self.assertTrue(self.test_file in result.stdout)

    def test_hmac_generation_with_output(self):
        """Генерация HMAC с записью в файл"""
        key = "00112233445566778899aabbccddeeff"
        hmac_file = os.path.join(self.temp_dir, "test.hmac")

        result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        self.assertEqual(result.returncode, 0)

        # Проверяем, что файл создан
        self.assertTrue(os.path.exists(hmac_file))

        # Проверяем содержимое файла
        with open(hmac_file, 'r') as f:
            content = f.read().strip()
            self.assertTrue(" " in content)
            self.assertTrue(self.test_file in content)

    def test_hmac_verification_success(self):
        """Успешная проверка HMAC"""
        key = "00112233445566778899aabbccddeeff"

        # Сначала генерируем HMAC
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        gen_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        self.assertEqual(gen_result.returncode, 0)

        # Проверяем HMAC
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # Проверяем, что верификация прошла успешно
        self.assertEqual(verify_result.returncode, 0)
        self.assertIn("verification successful", verify_result.stderr)

    def test_hmac_verification_failure(self):
        """Неуспешная проверка HMAC (измененный файл)"""
        key = "00112233445566778899aabbccddeeff"

        # Создаем HMAC для оригинального файла
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        # Изменяем файл
        with open(self.test_file, 'a') as f:
            f.write("\nTampered!")

        # Пытаемся проверить с измененным файлом
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # Проверка должна провалиться
        self.assertNotEqual(verify_result.returncode, 0)
        self.assertIn("verification failed", verify_result.stderr)

    def test_hmac_wrong_key(self):
        """Проверка с неправильным ключом"""
        key1 = "00112233445566778899aabbccddeeff"
        key2 = "ffeeddccbbaa99887766554433221100"

        # Генерируем HMAC с key1
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key1,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        # Пытаемся проверить с key2
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key2,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # Проверка должна провалиться
        self.assertNotEqual(verify_result.returncode, 0)


if __name__ == '__main__':
    unittest.main()