#!/usr/bin/env python3
"""
CryptoCore - CLI инструмент для шифрования/дешифрования файлов
Главный исполняемый файл
Sprint 3: Поддержка auto-generated ключей через CSPRNG
"""

import sys
from src.cli_parser import parse_args
from src.crypto_core import CryptoCipher


def main():
    """Основная точка входа программы"""
    try:
        # Парсим аргументы командной строки
        args = parse_args()

        # Sprint 3: Определяем, нужно ли генерировать ключ
        # Если шифруем и ключ не указан - генерируем
        auto_generate_key = args.encrypt and not args.key

        # Создаем объект шифра
        cipher = CryptoCipher(
            algorithm=args.algorithm,
            mode=args.mode,
            key=args.key,
            iv=args.iv
        )

        # Sprint 3: Выводим auto-generated ключ (требование CLI-3)
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

            # Sprint 2: Только для не-ECB режимов выводим информацию об IV
            if args.mode != 'ecb':
                print(f"  IV был сгенерирован автоматически и записан в начало файла")
        else:  # decrypt
            cipher.decrypt_file(args.input, args.output)
            print(f"[+] Файл успешно расшифрован (режим: {args.mode.upper()})")
            print(f"  Вход:  {args.input}")
            print(f"  Выход: {args.output}")

            # Sprint 2: Информация об IV для не-ECB режимов
            if args.mode != 'ecb':
                if args.iv:
                    print(f"  Использован IV из аргумента командной строки")
                else:
                    print(f"  IV прочитан из начала входного файла")

    except Exception as e:
        print(f"[-] Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()