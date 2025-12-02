"""
Парсер аргументов командной строки для CryptoCore
"""

import argparse
import os
import re
import sys


def parse_args():
    """Разбор и валидация аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="CryptoCore - инструмент для шифрования и дешифрования файлов с использованием AES-128 в режиме ECB",
        add_help=False
    )

    parser.add_argument(
        "-algorithm",
        type=str,
        required=True,
        help="Алгоритм шифрования (поддерживается только 'aes')"
    )

    parser.add_argument(
        "-mode",
        type=str,
        required=True,
        help="Режим работы (поддерживается только 'ecb')"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-encrypt", action="store_true", help="Выполнить шифрование файла")
    group.add_argument("-decrypt", action="store_true", help="Выполнить дешифрование файла")

    parser.add_argument(
        "-key",
        type=str,
        required=True,
        help="Ключ шифрования в формате hex (16 байт = 32 hex символа)"
    )

    parser.add_argument(
        "-input",
        type=str,
        required=True,
        help="Путь к входному файлу"
    )

    parser.add_argument(
        "-output",
        type=str,
        required=False,
        help="Путь к выходному файлу (если не указан, будет сгенерирован автоматически)"
    )

    parser.add_argument("-h", "--help", action="help", help="Показать это сообщение помощи")

    args = parser.parse_args()

    validate_args(args)

    if not args.output:
        args.output = generate_output_filename(args.input, args.encrypt)

    return args


def validate_args(args):
    """Валидация всех аргументов"""

    if args.algorithm.lower() != "aes":
        print_error(f"Неподдерживаемый алгоритм: '{args.algorithm}'. Поддерживается только 'aes'.")

    if args.mode.lower() != "ecb":
        print_error(f"Неподдерживаемый режим: '{args.mode}'. Поддерживается только 'ecb'.")

    validate_key(args.key)
    validate_input_file(args.input)


def validate_key(key):
    """Валидация ключа"""
    clean_key = key.lstrip('@')

    if len(clean_key) != 32:
        print_error(f"Некорректная длина ключа: {len(clean_key)} символов. Требуется 32 hex символа (16 байт).")

    hex_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
    if not hex_pattern.match(clean_key):
        print_error(f"Ключ должен содержать только hex символы (0-9, a-f, A-F).")


def validate_input_file(filepath):
    """Валидация входного файла"""
    if not os.path.exists(filepath):
        print_error(f"Входной файл не найден: '{filepath}'")

    if not os.path.isfile(filepath):
        print_error(f"'{filepath}' не является файлом")

    if not os.access(filepath, os.R_OK):
        print_error(f"Нет прав на чтение файла: '{filepath}'")


def generate_output_filename(input_file, is_encrypt):
    """Генерация имени выходного файла по умолчанию"""
    if is_encrypt:
        return f"{input_file}.enc"
    else:
        if input_file.endswith('.enc'):
            return f"{input_file[:-4]}.dec"
        else:
            return f"{input_file}.dec"


def print_error(message):
    """Вывод ошибки и завершение программы"""
    print(f"Ошибка: {message}", file=sys.stderr)
    sys.exit(1)