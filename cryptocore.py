#!/usr/bin/env python3
"""
CryptoCore - CLI инструмент для шифрования/дешифрования и хеширования файлов
Главный исполняемый файл
Sprint 4: Добавление команды dgst для хеширования
"""

import sys
import os
from src.cli_parser import parse_args
from src.crypto_core import CryptoCipher
from src.hash.hash_core import HashCore


def main():
    """Основная точка входа программы"""
    try:
        # Парсим аргументы командной строки
        args = parse_args()

        if args.command == 'dgst':
            # Sprint 4: Обработка команды dgst
            _handle_dgst_command(args)
        else:
            # Обработка шифрования/дешифрования
            _handle_crypto_command(args)

    except Exception as e:
        print(f"[-] Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


def _handle_crypto_command(args):
    """Обработка команды шифрования/дешифрования"""
    # Sprint 3: Определяем, нужно ли генерировать ключ
    auto_generate_key = args.encrypt and not args.key

    # Создаем объект шифра
    cipher = CryptoCipher(
        algorithm=args.algorithm,
        mode=args.mode,
        key=args.key,
        iv=args.iv
    )

    # Sprint 3: Выводим auto-generated ключ
    if auto_generate_key:
        key_hex = cipher.get_auto_generated_key_hex()
        if key_hex:
            print(f"[+] Сгенерирован случайный ключ: {key_hex}")
            print(f"    Сохраните этот ключ для дешифрования!")
            print(f"    Пример команды дешифрования:")
            print(f"    python cryptocore.py -algorithm aes -mode {args.mode} -decrypt \\")
            print(f"      -key @{key_hex} -input {args.output} -output decrypted.txt")

    # Выполняем операцию
    if args.encrypt:
        cipher.encrypt_file(args.input, args.output)
        print(f"[+] Файл успешно зашифрован (режим: {args.mode.upper()})")
        print(f"  Вход:  {args.input}")
        print(f"  Выход: {args.output}")

        if args.mode != 'ecb':
            print(f"  IV был сгенерирован автоматически и записан в начало файла")
    else:  # decrypt
        cipher.decrypt_file(args.input, args.output)
        print(f"[+] Файл успешно расшифрован (режим: {args.mode.upper()})")
        print(f"  Вход:  {args.input}")
        print(f"  Выход: {args.output}")

        if args.mode != 'ecb':
            if args.iv:
                print(f"  Использован IV из аргумента командной строки")
            else:
                print(f"  IV прочитан из начала входного файла")


def _handle_dgst_command(args):
    """Обработка команды dgst для хеширования"""
    import sys

    # Если используется HMAC или CMAC
    if args.hmac or args.cmac:
        _handle_mac_command(args)
        return

    # Стандартное хеширование (как было)
    hasher = HashCore(algorithm=args.algorithm)
    file_hash = hasher.hash_file(args.input)
    output_line = f"{file_hash}  {args.input}"

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_line + '\n')
        print(f"[+] Хеш записан в файл: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output_line + '\n')


def _handle_mac_command(args):
    """Обработка команды MAC (HMAC или CMAC)"""
    import sys
    from src.mac.hmac import HMAC
    from src.mac.cmac import CMAC

    # Читаем файл
    with open(args.input, 'rb') as f:
        data = f.read()

    key_bytes = bytes.fromhex(args.key)

    # Вычисляем MAC
    if args.hmac:
        # HMAC с SHA-256
        hmac = HMAC(key_bytes, 'sha256')
        mac_value = hmac.compute(data)
        mac_type = "HMAC"
        algo_info = f"SHA-256"
    else:
        # AES-CMAC
        cmac = CMAC(key_bytes)
        mac_value = cmac.compute(data)
        mac_type = "CMAC"
        algo_info = f"AES-{len(key_bytes) * 8}"

    mac_hex = mac_value.hex()

    # Если требуется проверка
    if args.verify:
        # Читаем ожидаемый MAC из файла
        try:
            with open(args.verify, 'r') as f:
                expected_line = f.read().strip()

            # Парсим ожидаемый MAC (может содержать имя файла)
            expected_parts = expected_line.split()
            expected_mac = expected_parts[0] if expected_parts else expected_line

            # Сравниваем
            if mac_hex == expected_mac:
                print(f"[OK] {mac_type} verification successful", file=sys.stderr)
                print(f"[OK] Файл '{args.input}' аутентичен", file=sys.stderr)
                sys.exit(0)
            else:
                print(f"[ERROR] {mac_type} verification failed", file=sys.stderr)
                print(f"  Вычислено: {mac_hex}", file=sys.stderr)
                print(f"  Ожидалось: {expected_mac}", file=sys.stderr)
                sys.exit(1)

        except FileNotFoundError:
            print(f"[ERROR] Файл с ожидаемым {mac_type} не найден: {args.verify}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Ошибка при проверке {mac_type}: {e}", file=sys.stderr)
            sys.exit(1)

    # Вывод результата
    output_line = f"{mac_hex} {args.input}"

    if args.output:
        # Записываем в файл
        with open(args.output, 'w') as f:
            f.write(output_line + '\n')
        print(f"[+] {mac_type} записан в файл: {args.output}", file=sys.stderr)
    else:
        # Выводим в stdout
        sys.stdout.write(output_line + '\n')

    # Дополнительная информация в stderr
    print(f"[+] {mac_type} успешно вычислен ({algo_info})", file=sys.stderr)
    print(f"  Файл: {args.input}", file=sys.stderr)
    print(f"  Ключ: {args.key}", file=sys.stderr)
    print(f"  {mac_type}: {mac_hex}", file=sys.stderr)

if __name__ == "__main__":
    main()