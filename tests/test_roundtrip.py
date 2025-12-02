"""
Тест для проверки полного цикла шифрование-дешифрование
"""

import os
import subprocess
import sys


def run_command(cmd):
    """Запуск команды и проверка результата"""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Ошибка: {result.stderr}")
        return False
    return True


def test_roundtrip():
    """Тест шифрование -> дешифрование"""
    print("=== Тест CryptoCore (шифрование-дешифрование) ===")

    # Параметры теста
    key = "@00112233445566778899aabbccddeeff"
    plain_file = "test_roundtrip_plain.txt"
    enc_file = "test_roundtrip_enc.bin"
    dec_file = "test_roundtrip_dec.txt"

    try:
        # 1. Создаем тестовый файл
        test_data = b"Hello CryptoCore! This is a round-trip test. " * 5
        with open(plain_file, "wb") as f:
            f.write(test_data)
        print(f"1. Создан тестовый файл: {plain_file} ({len(test_data)} байт)")

        # 2. Шифруем
        print("2. Шифруем...")
        encrypt_cmd = [
            sys.executable, "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "ecb",
            "-encrypt",
            "-key", key,
            "-input", plain_file,
            "-output", enc_file
        ]

        if not run_command(encrypt_cmd):
            return False
        print(f"   Зашифровано в: {enc_file}")

        # 3. Дешифруем
        print("3. Дешифруем...")
        decrypt_cmd = [
            sys.executable, "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "ecb",
            "-decrypt",
            "-key", key,
            "-input", enc_file,
            "-output", dec_file
        ]

        if not run_command(decrypt_cmd):
            return False
        print(f"   Расшифровано в: {dec_file}")

        # 4. Сравниваем
        print("4. Сравниваем файлы...")
        with open(plain_file, "rb") as f1, open(dec_file, "rb") as f2:
            original = f1.read()
            decrypted = f2.read()

            if original == decrypted:
                print(f"✅ ТЕСТ ПРОЙДЕН!")
                print(f"   Файлы идентичны ({len(original)} байт)")
                return True
            else:
                print("❌ ТЕСТ НЕ ПРОЙДЕН: файлы различаются")
                return False

    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

    finally:
        # 5. Очистка
        print("5. Очистка тестовых файлов...")
        for f in [plain_file, enc_file, dec_file]:
            if os.path.exists(f):
                os.remove(f)


def test_cli_validation():
    """Тест валидации CLI аргументов"""
    print("\n=== Тест валидации CLI ===")

    tests = [
        # (команда, ожидаемый_код_ошибки, описание)
        (["python", "cryptocore.py"], 1, "Нет обязательных аргументов"),
        (["python", "cryptocore.py", "-encrypt", "-decrypt"], 1, "Оба флага -encrypt и -decrypt"),
        (["python", "cryptocore.py", "-algorithm", "des", "-mode", "ecb", "-encrypt"], 1, "Неподдерживаемый алгоритм"),
    ]

    all_passed = True
    for cmd, expected_code, description in tests:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == expected_code:
            print(f"✅ {description}")
        else:
            print(f"❌ {description}")
            all_passed = False

    return all_passed


if __name__ == "__main__":
    # Основной тест
    test1 = test_roundtrip()

    # Тест валидации
    test2 = test_cli_validation()

    # Итог
    print("\n" + "=" * 50)
    if test1 and test2:
        print("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        sys.exit(0)
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        sys.exit(1)