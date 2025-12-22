#!/usr/bin/env python3
"""
Тесты совместимости CryptoCore с OpenSSL
Sprint 2: Режимы CBC, CFB, OFB, CTR
Требования TEST-2, TEST-3: совместимость в обоих направлениях
"""

import os
import sys
import tempfile
import subprocess
import hashlib
import binascii

# Добавляем путь к src
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def check_openssl():
    """Проверить наличие OpenSSL"""
    try:
        result = subprocess.run(['openssl', 'version'],
                                capture_output=True, text=True, shell=True)
        return result.returncode == 0
    except:
        return False


def get_file_hash(filepath):
    """Получить SHA256 хеш файла"""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def compare_files_with_debug(file1, file2):
    """Сравнить два файла с подробной отладкой"""
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            content1 = f1.read()
            content2 = f2.read()

            print(f"  [DEBUG] {os.path.basename(file1)}: {len(content1)} байт")
            print(f"  [DEBUG] {os.path.basename(file2)}: {len(content2)} байт")

            if len(content1) != len(content2):
                print(f"  [DEBUG] Разная длина: {len(content1)} vs {len(content2)}")

            # Покажем первые 32 байта для сравнения
            print(f"  [DEBUG] Первые 32 байта файла 1: {binascii.hexlify(content1[:32])}")
            print(f"  [DEBUG] Первые 32 байта файла 2: {binascii.hexlify(content2[:32])}")

            # Прямое сравнение
            if content1 == content2:
                return True, f"Файлы идентичны ({len(content1)} байт)"

            # Поиск первого различия
            min_len = min(len(content1), len(content2))
            for i in range(min_len):
                if content1[i] != content2[i]:
                    return False, f"Различие на позиции {i}: 0x{content1[i]:02x} vs 0x{content2[i]:02x}"
                    break

            if len(content1) != len(content2):
                return False, f"Разная длина: {len(content1)} vs {len(content2)} байт"
            return False, "Файлы разные"

    except Exception as e:
        return False, f"Ошибка сравнения: {e}"


def test_openssl_compatibility():
    """Основной тест совместимости с OpenSSL"""

    print("=" * 70)
    print("ТЕСТЫ СОВМЕСТМОСТ CRYPTOCORE С OPENSSL")
    print("Sprint 2: Режимы CBC, CFB, OFB, CTR")
    print("=" * 70)

    # Тестовые данные
    test_key = "000102030405060708090a0b0c0d0e0f"
    test_iv = "00000000000000000000000000000000"

    print(f"[INFO] Ключ: {test_key}")
    print(f"[INFO] IV: {test_iv}")

    # Проверяем OpenSSL
    has_openssl = check_openssl()
    if not has_openssl:
        print("[-] OpenSSL не найден в системе")
        print("[!] Установите OpenSSL для полного тестирования")
        print("[+] Будут выполнены только демонстрационные тесты")
        return False

    # Тестируемые режимы
    modes = ['cbc', 'cfb', 'ofb', 'ctr']

    results = {}

    for mode in modes:
        print(f"\n{'=' * 40}")
        print(f"Тестируем режим: {mode.upper()}")
        print('=' * 40)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Создаем тестовый файл
            test_file = os.path.join(tmpdir, "test.txt")
            test_content = b"Test data for CryptoCore OpenSSL compatibility check\n" * 10

            with open(test_file, 'wb') as f:
                f.write(test_content)

            test_size = len(test_content)
            print(f"Тестовый файл: {test_size} байт")
            print(f"Первые 32 байта теста: {binascii.hexlify(test_content[:32])}")

            # 1. Тест: CryptoCore -> OpenSSL
            print(f"\n1. Тест CryptoCore -> OpenSSL")
            print("-" * 30)

            # Шифруем с помощью CryptoCore
            crypto_enc = os.path.join(tmpdir, f"crypto_enc_{mode}.bin")

            # Команда CryptoCore для шифрования
            cmd = [
                sys.executable, 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', mode,
                '-encrypt',
                '-key', f'@{test_key}',
                '-iv', test_iv,
                '-input', test_file,
                '-output', crypto_enc
            ]

            print(f"[DEBUG] Команда CryptoCore шифрование: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  ❌ Ошибка шифрования CryptoCore: {result.stderr[:200]}")
                results[mode] = {'crypto_to_openssl': False, 'openssl_to_crypto': False}
                continue

            print(f"  ✅ Зашифровано с помощью CryptoCore")

            # Проверяем размер зашифрованного файла
            crypto_enc_size = os.path.getsize(crypto_enc)
            print(f"  [DEBUG] Размер crypto_enc: {crypto_enc_size} байт")

            with open(crypto_enc, 'rb') as f:
                crypto_data = f.read()
                print(f"  [DEBUG] Первые 32 байта crypto_enc: {binascii.hexlify(crypto_data[:32])}")

            # Для CBC/CFB/OFB/CTR IV в начале файла
            if len(crypto_data) >= 16:
                file_iv = crypto_data[:16].hex()
                crypto_ciphertext = crypto_data[16:]
                print(f"  [DEBUG] IV из файла: {file_iv}")
                print(f"  [DEBUG] Ожидаемый IV: {test_iv}")
                print(f"  [DEBUG] Длина ciphertext: {len(crypto_ciphertext)} байт")

                # Сохраняем ciphertext без IV для OpenSSL
                openssl_input = os.path.join(tmpdir, f"crypto_ciphertext_{mode}.bin")
                with open(openssl_input, 'wb') as f:
                    f.write(crypto_ciphertext)
            else:
                print(f"  ❌ Слишком короткий зашифрованный файл")
                results[mode] = {'crypto_to_openssl': False, 'openssl_to_crypto': False}
                continue

            # Дешифруем с помощью OpenSSL
            openssl_dec = os.path.join(tmpdir, f"openssl_dec_{mode}.txt")

            # Команда OpenSSL для дешифрования
            openssl_cmd = f'openssl enc -aes-128-{mode} -d -K {test_key} -iv {test_iv} -in "{openssl_input}" -out "{openssl_dec}"'
            print(f"[DEBUG] Команда OpenSSL дешифрование: {openssl_cmd}")

            result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  ❌ Ошибка дешифрования OpenSSL: {result.stderr[:200]}")
                crypto_to_openssl = False
            else:
                # Сравниваем файлы
                same, message = compare_files_with_debug(test_file, openssl_dec)
                if same:
                    print(f"  ✅ CryptoCore -> OpenSSL: УСПЕХ")
                    crypto_to_openssl = True
                else:
                    print(f"  ❌ CryptoCore -> OpenSSL: {message}")
                    crypto_to_openssl = False

            # 2. Тест: OpenSSL -> CryptoCore
            print(f"\n2. Тест OpenSSL -> CryptoCore")
            print("-" * 30)

            # Шифруем с помощью OpenSSL
            openssl_enc = os.path.join(tmpdir, f"openssl_enc_{mode}.bin")

            # Команда OpenSSL для шифрования
            openssl_cmd = f'openssl enc -aes-128-{mode} -K {test_key} -iv {test_iv} -in "{test_file}" -out "{openssl_enc}"'
            print(f"[DEBUG] Команда OpenSSL шифрование: {openssl_cmd}")

            result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  ❌ Ошибка шифрования OpenSSL: {result.stderr[:200]}")
                openssl_to_crypto = False
            else:
                print(f"  ✅ Зашифровано с помощью OpenSSL")

                # Проверяем размер файла OpenSSL
                openssl_enc_size = os.path.getsize(openssl_enc)
                print(f"  [DEBUG] Размер openssl_enc: {openssl_enc_size} байт")

                with open(openssl_enc, 'rb') as f:
                    openssl_data = f.read()
                    print(f"  [DEBUG] Первые 32 байта openssl_enc: {binascii.hexlify(openssl_data[:32])}")

                # OpenSSL НЕ записывает IV в файл, нужно создать файл с IV для CryptoCore
                crypto_input = os.path.join(tmpdir, f"openssl_for_crypto_{mode}.bin")

                # Создаем файл в формате CryptoCore: IV + ciphertext
                with open(crypto_input, 'wb') as f:
                    if mode != 'ecb':
                        # Добавляем IV, который использовался при шифровании
                        f.write(bytes.fromhex(test_iv))
                    f.write(openssl_data)  # Ciphertext от OpenSSL

                print(f"  [DEBUG] Создан файл для CryptoCore: {os.path.getsize(crypto_input)} байт")
                with open(crypto_input, 'rb') as f:
                    crypto_input_data = f.read()
                    print(f"  [DEBUG] Первые 32 байта crypto_input: {binascii.hexlify(crypto_input_data[:32])}")

                # Дешифруем с помощью CryptoCore
                crypto_dec = os.path.join(tmpdir, f"crypto_dec_{mode}.txt")

                cmd = [
                    sys.executable, 'cryptocore.py',
                    '-algorithm', 'aes',
                    '-mode', mode,
                    '-decrypt',
                    '-key', f'@{test_key}',
                    '-input', crypto_input,  # Файл уже содержит IV в начале
                    '-output', crypto_dec
                ]

                print(f"[DEBUG] Команда CryptoCore дешифрование: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    print(f"  ❌ Ошибка дешифрования CryptoCore: {result.stderr[:200]}")
                    openssl_to_crypto = False
                else:
                    # Сравниваем файлы
                    same, message = compare_files_with_debug(test_file, crypto_dec)
                    if same:
                        print(f"  ✅ OpenSSL -> CryptoCore: УСПЕХ")
                        openssl_to_crypto = True
                    else:
                        print(f"  ❌ OpenSSL -> CryptoCore: {message}")
                        openssl_to_crypto = False

            results[mode] = {
                'crypto_to_openssl': crypto_to_openssl,
                'openssl_to_crypto': openssl_to_crypto
            }

    # тоги
    print("\n" + "=" * 70)
    print("ТОГ ТЕСТРОВАНЯ СОВМЕСТМОСТ")
    print("=" * 70)

    all_passed = True

    for mode in modes:
        result = results.get(mode, {})
        crypto_to_openssl = result.get('crypto_to_openssl', False)
        openssl_to_crypto = result.get('openssl_to_crypto', False)

        status = "✅ УСПЕХ" if crypto_to_openssl and openssl_to_crypto else "❌ ОШБКА"
        print(f"{mode.upper():5} : {status}")

        if crypto_to_openssl:
            print(f"       • CryptoCore -> OpenSSL: ✅")
        else:
            print(f"       • CryptoCore -> OpenSSL: ❌")
            all_passed = False

        if openssl_to_crypto:
            print(f"       • OpenSSL -> CryptoCore: ✅")
        else:
            print(f"       • OpenSSL -> CryptoCore: ❌")
            all_passed = False

    print("\n" + "=" * 70)

    if all_passed:
        print("🎉 ВСЕ ТЕСТЫ СОВМЕСТМОСТ ПРОЙДЕНЫ!")
        print("CryptoCore полностью совместим с OpenSSL!")
        return True
    else:
        print("⚠️ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        print("Проблемы с совместимостью в одном или обоих направлениях")
        return False


def main():
    """Основная функция"""
    try:
        # Проверяем OpenSSL
        has_openssl = check_openssl()

        if not has_openssl:
            print("=" * 70)
            print("OPENSSL НЕ НАЙДЕН")
            print("=" * 70)
            print("Для полного тестирования установите OpenSSL:")
            print("1. Скачайте: https://slproweb.com/download/Win64OpenSSL-3_3_2.exe")
            print("2. Установите с добавлением в PATH")
            print("3. Перезапустите PyCharm")
            print("\n[ЗАПУСКАЮ ВНУТРЕННЕ ТЕСТЫ]")
            return

        success = test_openssl_compatibility()
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n\nТестирование прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Неожиданная ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

