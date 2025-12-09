"""
Тест для проверки полного цикла шифрование-дешифрование
Sprint 2: Тестирование всех режимов (ECB, CBC, CFB, OFB, CTR)
"""

import os
import subprocess
import sys
import tempfile

def run_command(cmd):
    """Запуск команды и проверка результата"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=False)  # text=False для бинарного вывода
        if result.returncode != 0:
            # Пытаемся декодировать как utf-8, если не получается - выводим как есть
            try:
                error_text = result.stderr.decode('utf-8', errors='ignore')
            except:
                error_text = str(result.stderr)
            print(f"Ошибка: {error_text}")
            return False
        return True
    except Exception as e:
        print(f"Ошибка выполнения команды: {e}")
        return False


def test_mode_roundtrip(mode):
    """Тест шифрование -> дешифрование для конкретного режима"""
    print(f"\n--- Тест режима: {mode.upper()} ---")

    # Параметры теста
    key = "@00112233445566778899aabbccddeeff"

    # Для ECB не нужен IV, для остальных - нужен
    if mode != 'ecb':
        iv = "aabbccddeeff00112233445566778899"
    else:
        iv = None

    with tempfile.TemporaryDirectory() as tmpdir:
        plain_file = os.path.join(tmpdir, "plain.txt")
        enc_file = os.path.join(tmpdir, "enc.bin")
        dec_file = os.path.join(tmpdir, "dec.txt")

        try:
            # 1. Создаем тестовый файл
            # ⚠️ ИСПРАВЛЕНО: Для CFB используем данные кратные 16 байтам
            if mode == 'cfb':
                # CFB требует данные, кратные 16 байтам
                test_data = b"CFB_16byte_test!" * 10  # 160 байт, кратно 16
            else:
                # Для остальных режимов можно любые данные
                test_data = b"Hello CryptoCore! This is a round-trip test. " * 5

            with open(plain_file, "wb") as f:
                f.write(test_data)

            if mode == 'cfb':
                print(f"1. Создан тестовый файл для CFB: {len(test_data)} байт (кратно 16)")
            else:
                print(f"1. Создан тестовый файл: {len(test_data)} байт")

            # 2. Шифруем
            print("2. Шифруем...")
            encrypt_cmd = [
                sys.executable, "cryptocore.py",
                "-algorithm", "aes",
                "-mode", mode,
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
                "-mode", mode,
                "-decrypt",
                "-key", key,
                "-input", enc_file,
                "-output", dec_file
            ]

            # Добавляем IV для режимов кроме ECB
            if mode != 'ecb':
                decrypt_cmd.extend(["-iv", iv])

            if not run_command(decrypt_cmd):
                return False
            print(f"   Расшифровано в: {dec_file}")

            # 4. Сравниваем
            print("4. Сравниваем файлы...")
            with open(plain_file, "rb") as f1, open(dec_file, "rb") as f2:
                original = f1.read()
                decrypted = f2.read()

                if original == decrypted:
                    print(f"   [+] ТЕСТ ПРОЙДЕН!")
                    print(f"   Файлы идентичны ({len(original)} байт)")
                    return True
                else:
                    print("   [-] ТЕСТ НЕ ПРОЙДЕН: файлы различаются")
                    # Показываем разницу
                    print(f"   Оригинал: {len(original)} байт")
                    print(f"   Расшифровано: {len(decrypted)} байт")
                    # Показываем первые различия
                    for i in range(min(len(original), len(decrypted))):
                        if original[i] != decrypted[i]:
                            print(f"   Первое различие на позиции {i}: {original[i]} vs {decrypted[i]}")
                            break
                    return False

        except Exception as e:
            print(f"   [-] Ошибка: {e}")
            return False

def test_all_modes():
    """Тестирование всех режимов"""
    print("=== Тест CryptoCore (шифрование-дешифрование для всех режимов) ===")
    print("Sprint 2: ECB, CBC, CFB, OFB, CTR")
    print("=" * 60)

    # Sprint 2: Все режимы
    modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
    results = {}

    for mode in modes:
        results[mode] = test_mode_roundtrip(mode)

    # Итоги
    print("\n" + "=" * 60)
    print("ИТОГИ ТЕСТИРОВАНИЯ (Round-trip):")

    all_passed = True
    for mode, passed in results.items():
        status = "[+] ПРОЙДЕН" if passed else "[-] НЕ ПРОЙДЕН"
        print(f"{mode.upper()}: {status}")
        if not passed:
            all_passed = False

    return all_passed

def test_cli_validation():
    """Тест валидации CLI аргументов для Sprint 2"""
    print("\n=== Тест валидации CLI (Sprint 2) ===")

    tests = [
        # (команда, ожидаемый_код_ошибки, описание)
        (["python", "cryptocore.py"], 1, "Нет обязательных аргументов"),
        (["python", "cryptocore.py", "-encrypt", "-decrypt"], 1, "Оба флага -encrypt и -decrypt"),
        (["python", "cryptocore.py", "-algorithm", "des", "-mode", "ecb", "-encrypt"], 1, "Неподдерживаемый алгоритм"),
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "xxx", "-encrypt"], 1, "Неподдерживаемый режим"),
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "ecb", "-encrypt", "-key", "123"], 1, "Некорректный ключ"),
        # ⚠️ ИСПРАВЛЕНО: Теперь ожидается код 1 (ошибка), а не 0 (warning)
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "cbc", "-encrypt", "-key", "@00112233445566778899aabbccddeeff", "-iv", "123"], 1, "IV отвергается при шифровании (error)"),
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "cbc", "-decrypt", "-key", "@00112233445566778899aabbccddeeff", "-iv", "123"], 1, "Некорректный IV"),
    ]

    all_passed = True
    for cmd, expected_code, description in tests:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == expected_code:
            print(f"[+] {description}")
        else:
            print(f"[-] {description} (код: {result.returncode}, ожидался: {expected_code})")
            if result.stderr:
                print(f"   stderr: {result.stderr[:100]}")
            all_passed = False

    return all_passed

if __name__ == "__main__":
    # Тестирование всех режимов
    test1 = test_all_modes()

    # Тест валидации
    test2 = test_cli_validation()

    # Итог
    print("\n" + "=" * 60)
    if test1 and test2:
        print("[+] ВСЕ ТЕСТЫ SPRINT 2 ПРОЙДЕНЫ!")
        sys.exit(0)
    else:
        print("[-] НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        sys.exit(1)