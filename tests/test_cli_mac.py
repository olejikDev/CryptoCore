#!/usr/bin/env python3
"""
Интеграционные тесты для HMAC через CLI
"""

import os
import subprocess
import tempfile
import unittest


class TestCLIMAC(unittest.TestCase):
    """Тесты HMAC через CLI"""

    def setUp(self):
        """Настройка тестов"""
        # Создаем временную директорию для тестов
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")

        # Записываем тестовые данные
        with open(self.test_file, "w") as f:
            f.write("This is test data for HMAC testing.\n")
            f.write("Multiple lines to ensure proper hashing.\n")

    def tearDown(self):
        """Очистка после тестов"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_cryptocore(self, args):
        """Запуск cryptocore с аргументами"""
        # Используем cryptocore.py в корне проекта
        cmd = ["python", "cryptocore.py"] + args

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

        # Проверяем формат вывода
        output_lines = result.stdout.strip().split('\n')
        self.assertTrue(len(output_lines) > 0)

        # HMAC должен быть hex строкой + имя файла
        hmac_line = output_lines[0]
        hmac_parts = hmac_line.split()
        self.assertEqual(len(hmac_parts), 2)

        # Проверяем что HMAC - hex строка (64 символа для SHA-256)
        hmac_hex = hmac_parts[0]
        self.assertEqual(len(hmac_hex), 64)

        # Проверяем что имя файла правильное
        self.assertEqual(hmac_parts[1], self.test_file)

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

        # Проверяем что файл создан
        self.assertTrue(os.path.exists(hmac_file))

        # Читаем файл и проверяем формат
        with open(hmac_file, 'r') as f:
            hmac_content = f.read().strip()

        hmac_parts = hmac_content.split()
        self.assertEqual(len(hmac_parts), 2)
        self.assertEqual(len(hmac_parts[0]), 64)  # SHA-256 hex длина

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

        # Теперь проверяем
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # Проверка должна пройти успешно
        self.assertEqual(verify_result.returncode, 0)
        self.assertIn("verification successful", verify_result.stdout.lower())

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
        self.assertIn("verification failed", verify_result.stderr.lower())

    def test_hmac_wrong_key(self):
        """Проверка с неправильным ключом"""
        key1 = "00112233445566778899aabbccddeeff"
        key2 = "ffeeccbbaa99887766554433221100ff"

        # Генерируем HMAC с первым ключом
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key1,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        # Пытаемся проверить с другим ключом
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


if __name__ == "__main__":
    print("Running CLI MAC tests...")
    unittest.main(verbosity=2)