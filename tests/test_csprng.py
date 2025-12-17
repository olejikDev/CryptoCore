#!/usr/bin/env python3
"""
Тесты для модуля CSPRNG (Sprint 3)
Требования TEST-1, TEST-2, TEST-4
"""

import sys
import os
import tempfile
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.csprng import generate_random_bytes, generate_random_hex


def test_key_uniqueness():
    """
    Тест уникальности сгенерированных ключей
    Требование TEST-2: 1000 уникальных ключей
    """
    print("=== Тест уникальности ключей (TEST-2) ===")

    key_set = set()
    num_keys = 1000

    for i in range(num_keys):
        if i % 100 == 0:
            print(f"  Генерация ключа {i + 1}/{num_keys}...")

        # Генерируем 16-байтный ключ
        key = generate_random_bytes(16)
        key_hex = key.hex()

        # Проверка на уникальность
        if key_hex in key_set:
            print(f"[-] Найден дубликат ключа: {key_hex}")
            return False

        key_set.add(key_hex)

    print(f"[+] Успешно сгенерировано {len(key_set)} уникальных ключей")
    assert len(key_set) == num_keys, f"Ожидалось {num_keys} уникальных ключей, получено {len(key_set)}"


def test_basic_distribution():
    """
    Базовый тест распределения битов
    Требование TEST-4: проверка энтропии
    """
    print("=== Тест распределения битов (TEST-4) ===")

    num_samples = 1000
    total_bits = 0
    ones_count = 0

    for i in range(num_samples):
        if i % 100 == 0:
            print(f"  Анализ образца {i + 1}/{num_samples}...")

        # Генерируем 16 байт (128 бит)
        random_bytes = generate_random_bytes(16)

        # Подсчет единичных битов
        for byte in random_bytes:
            ones_count += bin(byte).count("1")
            total_bits += 8

    # Вычисляем процент единиц
    ones_percentage = (ones_count / total_bits) * 100

    print(f"[+] Всего битов: {total_bits:,}")
    print(f"[+] Единичных битов: {ones_count:,} ({ones_percentage:.2f}%)")

    # Проверяем, что процент близок к 50%
    # Для истинно случайных данных ожидается ~50%
    if 45 <= ones_percentage <= 55:
        print(f"[+] Распределение битов соответствует ожиданиям (~50%)")
        return True
    else:
        print(f"[-] Распределение битов не соответствует ожиданиям: {ones_percentage:.2f}%")
        return False


def test_key_generation_integration():
    """
    Интеграционный тест с генерацией ключа
    Требование TEST-1: шифрование без ключа -> дешифрование с printed key
    """
    print("=== Интеграционный тест (TEST-1) ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Создаем тестовый файл
        plain_file = os.path.join(tmpdir, "plain.txt")
        with open(plain_file, "wb") as f:
            f.write(b"Test data for CryptoCore with auto-generated key\n" * 10)

        # Шифруем без ключа
        enc_file = os.path.join(tmpdir, "encrypted.bin")
        cmd = [
            sys.executable, "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "cbc",
            "-encrypt",
            "-input", plain_file,
            "-output", enc_file
        ]

        print("Запуск шифрования без ключа...")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[-] Ошибка шифрования: {result.stderr}")
            return False

        # Извлекаем сгенерированный ключ из вывода
        output_lines = result.stdout.split('\n')
        generated_key = None
        for line in output_lines:
            if "Сгенерирован случайный ключ:" in line:
                generated_key = line.split(":")[1].strip()
                break

        if not generated_key:
            print("[-] Не удалось найти сгенерированный ключ в выводе")
            print(f"Вывод программы: {result.stdout[:500]}...")
            return False

        print(f"[+] Ключ сгенерирован: {generated_key}")

        # Дешифруем с сгенерированным ключом
        dec_file = os.path.join(tmpdir, "decrypted.txt")
        cmd = [
            sys.executable, "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "cbc",
            "-decrypt",
            "-key", f"@{generated_key}",
            "-input", enc_file,
            "-output", dec_file
        ]

        print("Запуск дешифрования с сгенерированным ключом...")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[-] Ошибка дешифрования: {result.stderr}")
            return False

        # Сравниваем файлы
        with open(plain_file, "rb") as f1, open(dec_file, "rb") as f2:
            original = f1.read()
            decrypted = f2.read()

            if original == decrypted:
                print("[+] Интеграционный тест пройден успешно!")
                print(f"   Оригинал: {len(original)} байт")
                print(f"   Расшифровано: {len(decrypted)} байт")
                return True
            else:
                print("[-] Файлы не совпадают после дешифрования")

                # Поиск различий
                min_len = min(len(original), len(decrypted))
                for i in range(min_len):
                    if original[i] != decrypted[i]:
                        print(f"   Первое различие на позиции {i}: 0x{original[i]:02x} vs 0x{decrypted[i]:02x}")
                        break

                if len(original) != len(decrypted):
                    print(f"   Разная длина: {len(original)} vs {len(decrypted)} байт")

                return False


def test_nist_preparation():
    """
    Подготовка файла для тестирования NIST STS
    Требование TEST-3: генерация большого файла для NIST тестов
    """
    print("=== Подготовка файла для NIST тестов (TEST-3) ===")

    total_size = 10_000_000  # 10 MB
    output_file = "nist_test_data.bin"

    print(f"Генерация {total_size} байтов случайных данных...")

    with open(output_file, 'wb') as f:
        bytes_written = 0
        chunk_size = 4096

        while bytes_written < total_size:
            if bytes_written % (1024 * 1024) == 0:
                print(f"  Сгенерировано {bytes_written / 1024 / 1024:.1f} MB...")

            # Вычисляем размер текущего чанка
            current_chunk_size = min(chunk_size, total_size - bytes_written)

            # Генерируем случайные данные
            random_chunk = generate_random_bytes(current_chunk_size)

            # Записываем в файл
            f.write(random_chunk)
            bytes_written += current_chunk_size

    print(f"[+] Файл {output_file} успешно создан ({bytes_written:,} байтов)")
    print(f"\n[+] Инструкции для запуска NIST STS:")
    print(f"1. Скачайте NIST Statistical Test Suite с https://csrc.nist.gov/projects/random-bit-generation")
    print(f"2. Запустите: ./assess {total_size // 8}")
    print(f"3. Укажите путь к файлу: {output_file}")
    print(f"4. Следуйте инструкциям программы")

    return True


def test_error_handling():
    """Тест обработки ошибок CSPRNG"""
    print("=== Тест обработки ошибок ===")

    # Тест 1: Отрицательное количество байтов
    try:
        generate_random_bytes(-1)
        print("[-] Не сгенерирована ошибка для отрицательного значения")
        return False
    except ValueError:
        print("[+] Корректно обработана ошибка для отрицательного значения")

    # Тест 2: Нулевое количество байтов
    try:
        generate_random_bytes(0)
        print("[-] Не сгенерирована ошибка для нулевого значения")
        return False
    except ValueError:
        print("[+] Корректно обработана ошибка для нулевого значения")

    # Тест 3: Корректная генерация
    try:
        result = generate_random_bytes(16)
        if len(result) == 16:
            print("[+] Корректно сгенерировано 16 байтов")
        else:
            print(f"[-] Неправильная длина: {len(result)} байтов")
            return False
    except Exception as e:
        print(f"[-] Неожиданная ошибка: {e}")
        return False

    return True


def main():
    """Основная функция тестирования"""
    print("=" * 70)
    print("ТЕСТЫ CSPRNG (Sprint 3)")
    print("Требования TEST-1, TEST-2, TEST-3, TEST-4")
    print("=" * 70)

    tests = [
        ("Обработка ошибок", test_error_handling),
        ("Уникальность ключей (TEST-2)", test_key_uniqueness),
        ("Распределение битов (TEST-4)", test_basic_distribution),
        ("Интеграция с CryptoCore (TEST-1)", test_key_generation_integration),
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"[-] Ошибка при выполнении теста: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False

    # Опционально: подготовка NIST тестов
    print("\n--- Подготовка NIST тестов (TEST-3, опционально) ---")
    try:
        test_nist_preparation()
        print("[+] Файл для NIST тестов подготовлен")
    except Exception as e:
        print(f"[-] Ошибка при подготовке NIST тестов: {e}")
        print("  (Это не влияет на общий результат тестов)")

    # Итоги
    print("\n" + "=" * 70)
    print("ИТОГИ ТЕСТИРОВАНИЯ CSPRNG")
    print("=" * 70)

    all_passed = True
    for test_name, passed in results.items():
        status = "✅ УСПЕХ" if passed else "❌ ОШИБКА"
        print(f"{test_name:40} : {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n[+] ВСЕ ТЕСТЫ SPRINT 3 ПРОЙДЕНЫ!")
        print("    • TEST-1: Key Generation Test ✓")
        print("    • TEST-2: Uniqueness Test ✓")
        print("    • TEST-4: Basic Distribution Test ✓")
        print("    • TEST-3: NIST тесты подготовлены ✓")
        sys.exit(0)
    else:
        print("\n[-] НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        sys.exit(1)


if __name__ == "__main__":
    main()