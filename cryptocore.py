#!/usr/bin/env python3
"""
CryptoCore - CLI инструмент для шифрования/дешифрования файлов
Главный исполняемый файл
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
            key=args.key
        )

        # Выполняем операцию
        if args.encrypt:
            cipher.encrypt_file(args.input, args.output)
            print(f"✓ Файл успешно зашифрован")
            print(f"  Вход:  {args.input}")
            print(f"  Выход: {args.output}")
        else:  # decrypt
            cipher.decrypt_file(args.input, args.output)
            print(f"✓ Файл успешно расшифрован")
            print(f"  Вход:  {args.input}")
            print(f"  Выход: {args.output}")

    except Exception as e:
        print(f"✗ Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()