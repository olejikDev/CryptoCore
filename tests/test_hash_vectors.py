#!/usr/bin/env python3
"""
Known-Answer тесты для хеш-функций
TEST-1: Все NIST тестовые векторы
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256


def test_sha256_extended_vectors():
    """Расширенные тестовые векторы для SHA-256"""
    print("=== Расширенные тестовые векторы SHA-256 ===")

    # Более полный набор тестовых векторов
    vectors = [
        # Пустая строка
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),

        # Один символ
        ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),

        # Три символа
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),

        # Короткое предложение
        ("The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),

        # То же с точкой
        ("The quick brown fox jumps over the lazy dog.",
         "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"),

        # Длинная последовательность
        (
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ]

    passed = 0
    for i, (input_str, expected) in enumerate(vectors):
        sha = SHA256()
        sha.update(input_str)
        result = sha.hexdigest()

        if result == expected:
            print(f"[+] Тест {i + 1} пройден")
            passed += 1
        else:
            print(f"[-] Тест {i + 1} не пройден")
            print(f"   Вход: '{input_str[:30]}{'...' if len(input_str) > 30 else ''}'")
            print(f"   Ожидалось: {expected}")
            print(f"   Получено:  {result}")

    print(f"\nРезультат: {passed}/{len(vectors)} тестов пройдено")
    return passed == len(vectors)


def test_sha3_256_extended_vectors():
    """Расширенные тестовые векторы для SHA3-256"""
    print("=== Расширенные тестовые векторы SHA3-256 ===")

    vectors = [
        # Пустая строка
        ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),

        # Один символ
        ("a", "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"),

        # Три символа
        ("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),

        # Короткое предложение
        ("The quick brown fox jumps over the lazy dog",
         "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"),

        # То же с точкой
        ("The quick brown fox jumps over the lazy dog.",
         "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d"),

        # 1600-битное сообщение (ровно один блок для Keccak)
        ("a" * 200,  # 200 байт = 1600 бит
         "79f38adec5c20307a98ef76e8314ab5ec8aa1023cce8fbe7b3f91e6e9d2c0c7d"),
    ]

    passed = 0
    for i, (input_str, expected) in enumerate(vectors):
        sha3 = SHA3_256()
        sha3.update(input_str)
        result = sha3.hexdigest()

        if result == expected:
            print(f"[+] Тест {i + 1} пройден")
            passed += 1
        else:
            print(f"[-] Тест {i + 1} не пройден")
            print(f"   Вход: '{input_str[:30]}{'...' if len(input_str) > 30 else ''}'")
            print(f"   Ожидалось: {expected}")
            print(f"   Получено:  {result}")

    print(f"\nРезультат: {passed}/{len(vectors)} тестов пройдено")
    return passed == len(vectors)


def test_empty_file():
    """Тест пустого файла (TEST-2)"""
    print("=== Тест пустого файла ===")

    import tempfile

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        temp_file = f.name

    try:
        # SHA-256 пустого файла
        sha = SHA256()
        sha256_hash = sha.hash_file(temp_file)
        expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        if sha256_hash == expected_sha256:
            print(f"[+] SHA-256 пустого файла: OK")
        else:
            print(f"[-] SHA-256 пустого файла: FAIL")
            print(f"   Ожидалось: {expected_sha256}")
            print(f"   Получено:  {sha256_hash}")
            return False

        # SHA3-256 пустого файла
        sha3 = SHA3_256()
        sha3_hash = sha3.hash_file(temp_file)
        expected_sha3 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

        if sha3_hash == expected_sha3:
            print(f"[+] SHA3-256 пустого файла: OK")
        else:
            print(f"[-] SHA3-256 пустого файла: FAIL")
            print(f"   Ожидалось: {expected_sha3}")
            print(f"   Получено:  {sha3_hash}")
            return False

        print("[+] Все тесты пустого файла пройдены")
        return True

    finally:
        os.unlink(temp_file)


def test_incremental_hashing():
    """Тест инкрементального хеширования"""
    print("=== Тест инкрементального хеширования ===")

    test_data = b"Hello, World! " * 1000  # ~14KB

    # SHA-256 инкрементально
    sha1 = SHA256()
    for i in range(0, len(test_data), 100):  # Чанки по 100 байт
        chunk = test_data[i:i + 100]
        sha1.update(chunk)
    incremental_hash = sha1.hexdigest()

    # SHA-256 за один раз
    sha2 = SHA256()
    sha2.update(test_data)
    one_shot_hash = sha2.hexdigest()

    if incremental_hash == one_shot_hash:
        print(f"[+] SHA-256 инкрементальное хеширование: OK")
    else:
        print(f"[-] SHA-256 инкрементальное хеширование: FAIL")
        return False

    # SHA3-256 инкрементально
    sha3_1 = SHA3_256()
    for i in range(0, len(test_data), 100):
        chunk = test_data[i:i + 100]
        sha3_1.update(chunk)
    incremental_hash3 = sha3_1.hexdigest()

    # SHA3-256 за один раз
    sha3_2 = SHA3_256()
    sha3_2.update(test_data)
    one_shot_hash3 = sha3_2.hexdigest()

    if incremental_hash3 == one_shot_hash3:
        print(f"[+] SHA3-256 инкрементальное хеширование: OK")
    else:
        print(f"[-] SHA3-256 инкрементальное хеширование: FAIL")
        return False

    print("[+] Все тесты инкрементального хеширования пройдены")
    return True


def main():
    """Основная функция"""
    print("=" * 70)
    print("KNOWN-ANSWER ТЕСТЫ ДЛЯ ХЕШ-ФУНКЦИЙ")
    print("Требование TEST-1: NIST тестовые векторы")
    print("Требование TEST-2: Пустой файл")
    print("=" * 70)

    tests = [
        ("SHA-256 тестовые векторы", test_sha256_extended_vectors),
        ("SHA3-256 тестовые векторы", test_sha3_256_extended_vectors),
        ("Пустой файл", test_empty_file),
        ("Инкрементальное хеширование", test_incremental_hashing),
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"[-] Ошибка: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False

    # Итоги
    print("\n" + "=" * 70)
    print("ИТОГИ KNOWN-ANSWER ТЕСТОВ")
    print("=" * 70)

    all_passed = True
    for test_name, passed in results.items():
        status = "✅ ПРОЙДЕНО" if passed else "❌ НЕ ПРОЙДЕНО"
        print(f"{test_name:35} : {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n[+] ВСЕ KNOWN-ANSWER ТЕСТЫ ПРОЙДЕНЫ!")
        print("    Требование TEST-1 выполнено ✓")
        print("    Требование TEST-2 выполнено ✓")
    else:
        print("\n[-] НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)