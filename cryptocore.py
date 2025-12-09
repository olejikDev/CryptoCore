#!/usr/bin/env python3
"""
CryptoCore - CLI инструмент для шифрования/дешифрования файлов
Главный исполняемый файл
Sprint 2: Поддержка ECB, CBC, CFB, OFB, CTR режимов
"""

import sys
from src.cli_parser import parse_args
from src.crypto_core import CryptoCipher


def main():
    """Основная точка входа программы"""
    try:
        # Парсим аргументы командной строки
        args = parse_args()

        # Создаем объект шифра
        cipher = CryptoCipher(
            algorithm=args.algorithm,
            mode=args.mode,
            key=args.key,
            iv=args.iv
        )

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