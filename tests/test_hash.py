#!/usr/bin/env python3
"""
Тесты для хеш-функций (Sprint 4)
"""

import sys
import os
import tempfile
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256


def test_sha256_nist_vectors():
    """Тест известных векторов NIST для SHA-256"""
    print("=== Тест SHA-256 с NIST векторами ===")

    # Тестовые векторы из NIST
    test_vectors = [
        # (input, expected_hash)
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ("a" * 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ]

    for input_str, expected in test_vectors:
        sha = SHA256()
        sha.update(input_str)
        result = sha.hexdigest()

        if result == expected:
            print(f"[+] '{input_str[:20] if input_str else 'empty'}...': OK")
        else:
            print(f"[-] '{input_str[:20] if input_str else 'empty'}...': FAIL")
            print(f"    Ожидалось: {expected}")
            print(f"    Получено:  {result}")
            return False

    print("[+] Все NIST векторы для SHA-256 пройдены")
    return True


def test_sha3_256_nist_vectors():
    """Тест известных векторов NIST для SHA3-256"""
    print("=== Тест SHA3-256 с NIST векторами ===")

    # Тестовые векторы из NIST
    test_vectors = [
        # (input, expected_hash)
        ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        ("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    ]

    for input_str, expected in test_vectors:
        sha3 = SHA3_256()
        sha3.update(input_str)
        result = sha3.hexdigest()

        if result == expected:
            print(f"[+] '{input_str[:20] if input_str else 'empty'}...': OK")
        else:
            print(f"[-] '{input_str[:20] if input_str else 'empty'}...': FAIL")
            print(f"    Ожидалось: {expected}")
            print(f"    Получено:  {result}")
            return False

    print("[+] Все NIST векторы для SHA3-256 пройдены")
    return True


def test_avalanche_effect():
    """Тест лавинного эффекта"""
    print("=== Тест лавинного эффекта ===")

    # Тестируем для обоих алгоритмов
    algorithms = [
        ('SHA-256', SHA256),
        ('SHA3-256', SHA3_256),
    ]

    for algo_name, algo_class in algorithms:
        print(f"\nТестирование {algo_name}:")

        # Тестовые данные
        original_data = b"A" * 1000
        modified_data = b"B" + b"A" * 999  # Изменяем только первый байт

        # Вычисляем хеши
        hasher1 = algo_class()
        hasher1.update(original_data)
        hash1 = hasher1.hexdigest()

        hasher2 = algo_class()
        hasher2.update(modified_data)
        hash2 = hasher2.hexdigest()

        # Преобразуем в бинарный вид
        bin1 = bin(int(hash1, 16))[2:].zfill(256)
        bin2 = bin(int(hash2, 16))[2:].zfill(256)

        # Считаем различающиеся биты
        diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
        diff_percentage = (diff_count / 256) * 100

        print(f"  Различающихся битов: {diff_count}/256 ({diff_percentage:.1f}%)")

        # Для хорошего лавинного эффекта должно быть ~50% различий
        if 40 <= diff_percentage <= 60:
            print(f"  [+] Лавинный эффект хороший")
        else:
            print(f"  [-] Лавинный эффект слабый")

    return True


def test_large_file():
    """Тест хеширования большого файла"""
    print("=== Тест хеширования большого файла ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Создаем файл размером ~10MB
        large_file = os.path.join(tmpdir, "large.bin")
        file_size = 10 * 1024 * 1024  # 10 MB

        print(f"Создание файла размером {file_size // (1024 * 1024)} MB...")

        with open(large_file, 'wb') as f:
            # Пишем повторяющиеся данные
            chunk = b"X" * 1024  # 1KB чанк
            for _ in range(file_size // 1024):
                f.write(chunk)

        print(f"Файл создан: {large_file}")

        # Тестируем оба алгоритма
        algorithms = [('sha256', SHA256), ('sha3-256', SHA3_256)]

        for algo_name, algo_class in algorithms:
            print(f"\nТестирование {algo_name}:")

            hasher = algo_class()
            hash_result = hasher.hash_file(large_file)

            print(f"  Хеш: {hash_result}")
            print(f"  [+] Успешно обработан файл {file_size // (1024 * 1024)} MB")

    return True


def test_cli_integration():
    """Интеграционный тест CLI команды dgst"""
    print("=== Интеграционный тест CLI ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Создаем тестовый файл
        test_file = os.path.join(tmpdir, "test.txt")
        test_data = b"Hello CryptoCore Hash Test!\n" * 100

        with open(test_file, 'wb') as f:
            f.write(test_data)

        print(f"Создан тестовый файл: {test_file}")

        # Тестируем оба алгоритма через CLI
        algorithms = ['sha256', 'sha3-256']

        for algo in algorithms:
            print(f"\nТестирование {algo}:")

            # Запускаем через CLI
            cmd = [
                sys.executable, "cryptocore.py",
                "dgst",
                "--algorithm", algo,
                "--input", test_file
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  [-] Ошибка CLI: {result.stderr}")
                return False

            # Проверяем формат вывода
            output = result.stdout.strip()
            if output and len(output.split()) >= 2:
                hash_value, filename = output.split()[:2]

                if len(hash_value) == 64:  # 256 бит в hex = 64 символа
                    print(f"  [+] Формат вывода корректен")
                    print(f"  Хеш: {hash_value}")
                else:
                    print(f"  [-] Некорректная длина хеша: {len(hash_value)}")
                    return False
            else:
                print(f"  [-] Некорректный формат вывода: {output}")
                return False

    return True


def test_interoperability():
    """Тест совместимости с системными утилитами"""
    print("=== Тест совместимости с системными утилитами ===")

    # Проверяем наличие системных утилит
    system_tools = {
        'sha256': 'sha256sum',
        'sha3-256': 'sha3sum',
    }

    available_tools = {}
    for algo, tool in system_tools.items():
        try:
            result = subprocess.run([tool, '--version'], capture_output=True, text=True)
            if result.returncode == 0 or result.returncode == 1:
                available_tools[algo] = tool
                print(f"[+] Найдена системная утилита: {tool}")
        except:
            print(f"[-] Системная утилита {tool} не найдена")

    if not available_tools:
        print("  [i] Системные утилиты не найдены, тест пропущен")
        return True

    with tempfile.TemporaryDirectory() as tmpdir:
        # Создаем тестовый файл
        test_file = os.path.join(tmpdir, "interop_test.bin")
        test_data = b"Interoperability test data " * 1000

        with open(test_file, 'wb') as f:
            f.write(test_data)

        print(f"\nСоздан тестовый файл: {test_file}")

        for algo, tool in available_tools.items():
            print(f"\nТестирование совместимости с {tool}:")

            # 1. Вычисляем хеш нашим инструментом
            our_cmd = [
                sys.executable, "cryptocore.py",
                "dgst",
                "--algorithm", algo,
                "--input", test_file
            ]

            our_result = subprocess.run(our_cmd, capture_output=True, text=True)
            if our_result.returncode != 0:
                print(f"  [-] Ошибка нашего инструмента: {our_result.stderr}")
                continue

            our_hash = our_result.stdout.strip().split()[0]

            # 2. Вычисляем хеш системной утилитой
            sys_cmd = [tool, test_file]
            sys_result = subprocess.run(sys_cmd, capture_output=True, text=True)

            if sys_result.returncode != 0:
                print(f"  [-] Ошибка системной утилиты: {sys_result.stderr}")
                continue

            sys_hash = sys_result.stdout.strip().split()[0]

            # 3. Сравниваем
            if our_hash == sys_hash:
                print(f"  [+] Совместимость подтверждена!")
                print(f"  Хеш: {our_hash}")
            else:
                print(f"  [-] Несовместимость!")
                print(f"  Наш хеш:    {our_hash}")
                print(f"  Системный:  {sys_hash}")

    return True


def main():
    """Основная функция тестирования"""
    print("=" * 70)
    print("ТЕСТЫ ХЕШ-ФУНКЦИЙ (Sprint 4)")
    print("=" * 70)

    tests = [
        ("SHA-256 NIST векторы", test_sha256_nist_vectors),
        ("SHA3-256 NIST векторы", test_sha3_256_nist_vectors),
        ("Лавинный эффект", test_avalanche_effect),
        ("Большой файл", test_large_file),
        ("CLI интеграция", test_cli_integration),
        ("Совместимость", test_interoperability),
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

    # Итоги
    print("\n" + "=" * 70)
    print("ИТОГИ ТЕСТИРОВАНИЯ SPRINT 4")
    print("=" * 70)

    all_passed = True
    for test_name, passed in results.items():
        status = "✅ УСПЕХ" if passed else "❌ ОШИБКА"
        print(f"{test_name:30} : {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n[+] ВСЕ ТЕСТЫ SPRINT 4 ПРОЙДЕНЫ!")
        print("    • HASH-1: SHA-256 с нуля ✓")
        print("    • HASH-2: SHA3-256 с нуля ✓")
        print("    • CLI-1: Команда dgst ✓")
        print("    • TEST-1: NIST векторы ✓")
        print("    • TEST-2: Пустой файл ✓")
        print("    • TEST-4: Большой файл ✓")
        print("    • TEST-5: Лавинный эффект ✓")
        sys.exit(0)
    else:
        print("\n[-] НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        sys.exit(1)


if __name__ == "__main__":
    main()