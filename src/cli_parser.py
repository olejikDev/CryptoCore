"""
Парсер аргументов командной строки для CryptoCore
Sprint 4: Добавление команды dgst для хеширования
"""

import argparse
import os
import re
import sys


def parse_args():
    """Разбор и валидация аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="CryptoCore - инструмент для шифрования, дешифрования и хеширования файлов",
        add_help=False,
        usage="cryptocore <command> [options]\n\n"
              "Команды:\n"
              "  Для шифрования/дешифрования: cryptocore [options]\n"
              "  Для хеширования: cryptocore dgst [options]"
    )

    # Субпарсеры для разных команд
    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')

    # 1. Парсер для шифрования/дешифрования (существующий функционал)
    crypto_parser = subparsers.add_parser('crypto', add_help=False)
    _add_crypto_args(crypto_parser)

    # 2. Парсер для хеширования (новый в Sprint 4)
    dgst_parser = subparsers.add_parser('dgst', add_help=False)
    _add_dgst_args(dgst_parser)

    # Для обратной совместимости: если первым аргументом не является команда,
    # предполагаем, что это аргументы для шифрования
    if len(sys.argv) > 1 and sys.argv[1] not in ['crypto', 'dgst']:
        # Вставляем 'crypto' как первую команду
        sys.argv.insert(1, 'crypto')

    args = parser.parse_args()

    # Валидация в зависимости от команды
    if args.command == 'dgst':
        validate_dgst_args(args)
    else:
        # По умолчанию для шифрования/дешифрования
        args.command = 'crypto'
        validate_crypto_args(args)

    # Генерация имени файла по умолчанию для шифрования
    if args.command == 'crypto' and not args.output:
        args.output = generate_output_filename(args.input, args.encrypt)

    return args


def _add_crypto_args(parser):
    """Добавление аргументов для шифрования/дешифрования"""
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
        help="Режим работы (поддерживается: 'ecb', 'cbc', 'cfb', 'ofb', 'ctr')"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-encrypt", action="store_true", help="Выполнить шифрование файла")
    group.add_argument("-decrypt", action="store_true", help="Выполнить дешифрование файла")

    parser.add_argument(
        "-key",
        type=str,
        required=False,
        help="Ключ шифрования в формате hex (16 байт = 32 hex символа). "
             "Если не указан при шифровании, будет сгенерирован случайный ключ. "
             "При дешифровании ключ обязателен."
    )

    parser.add_argument(
        "-iv",
        type=str,
        required=False,
        help="Вектор инициализации в формате hex (16 байт = 32 hex символа). "
             "Требуется только при дешифровании в режимах CBC, CFB, OFB, CTR "
             "если IV не записан в начале файла"
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


def _add_dgst_args(parser):
    """Добавление аргументов для команды dgst"""
    parser.add_argument(
        "--algorithm",
        type=str,
        required=True,
        choices=['sha256', 'sha3-256'],
        help="Алгоритм хеширования (sha256, sha3-256)"
    )

    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Путь к файлу для хеширования"
    )

    parser.add_argument(
        "--output",
        type=str,
        required=False,
        help="Путь к файлу для записи хеша (если не указан, хеш выводится в stdout)"
    )

    # Sprint 5: Добавляем аргументы для HMAC
    parser.add_argument(
        "--hmac",
        action="store_true",
        help="Включить режим HMAC для аутентификации сообщений"
    )

    parser.add_argument(
        "--key",
        type=str,
        required=False,
        help="Ключ для HMAC в формате hex (обязателен при использовании --hmac)"
    )

    parser.add_argument(
        "--verify",
        type=str,
        required=False,
        help="Путь к файлу с ожидаемым HMAC для проверки"
    )

    parser.add_argument(
        "--cmac",
        action="store_true",
        help="Использовать AES-CMAC вместо HMAC (требует --key)"
    )

    parser.add_argument("-h", "--help", action="help", help="Показать сообщение помощи для команды dgst")

def validate_crypto_args(args):
    """Валидация аргументов для шифрования/дешифрования"""
    # Существующая валидация из предыдущих спринтов
    if args.algorithm.lower() != "aes":
        print_error(f"Неподдерживаемый алгоритм: '{args.algorithm}'. Поддерживается только 'aes'.")

    valid_modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
    if args.mode.lower() not in valid_modes:
        print_error(f"Неподдерживаемый режим: '{args.mode}'. Поддерживается: {', '.join(valid_modes)}.")

    # Sprint 3: Проверка ключа
    if args.key:
        validate_key(args.key)
        check_weak_key(args.key)
    elif args.encrypt:
        pass  # Ключ будет сгенерирован
    else:
        print_error("Ключ обязателен для дешифрования. Используйте -key для указания ключа.")

    if args.iv:
        validate_iv(args.iv)

    if args.mode.lower() == 'ecb' and args.iv:
        print_error("Аргумент --iv не поддерживается в режиме ECB.")

    validate_input_file(args.input)


def validate_dgst_args(args):
    """Валидация аргументов для команды dgst"""
    validate_input_file(args.input)

    # Проверяем, что файл существует и доступен для чтения
    if not os.path.exists(args.input):
        print_error(f"Входной файл не найден: '{args.input}'")

    if not os.access(args.input, os.R_OK):
        print_error(f"Нет прав на чтение файла: '{args.input}'")

    # Sprint 5: Валидация аргументов HMAC
    if args.hmac or args.cmac:
        if not args.key:
            print_error("Аргумент --key обязателен при использовании --hmac или --cmac")

        # Проверяем формат ключа
        try:
            key_bytes = bytes.fromhex(args.key)
            if args.hmac and len(key_bytes) == 0:
                print_error("Ключ для HMAC не может быть пустым")
        except ValueError:
            print_error(f"Некорректный формат ключа: '{args.key}'. Ожидается hex строка")

        # CMAC требует ключ AES
        if args.cmac and len(key_bytes) not in [16, 24, 32]:
            print_error("Для AES-CMAC ключ должен быть 16, 24 или 32 байта (32, 48 или 64 hex символа)")

    # Проверяем, что не указаны одновременно hmac и cmac
    if args.hmac and args.cmac:
        print_error("Нельзя использовать одновременно --hmac и --cmac. Выберите один вариант")


def validate_key(key):
    """Валидация ключа шифрования"""
    clean_key = key.lstrip('@')

    if len(clean_key) != 32:
        print_error(f"Некорректная длина ключа: {len(clean_key)} символов. Требуется 32 hex символа (16 байт).")

    hex_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
    if not hex_pattern.match(clean_key):
        print_error(f"Ключ должен содержать только hex символы (0-9, a-f, A-F).")


def validate_iv(iv):
    """Валидация вектора инициализации"""
    if len(iv) != 32:
        print_error(f"Некорректная длина IV: {len(iv)} символов. Требуется 32 hex символа (16 байт).")

    hex_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
    if not hex_pattern.match(iv):
        print_error(f"IV должен содержать только hex символы (0-9, a-f, A-F).")


def check_weak_key(key_str):
    """Проверка слабых ключей (требование CLI-5 Sprint 3)"""
    clean_key = key_str.lstrip('@')

    try:
        key_bytes = bytes.fromhex(clean_key)

        # Проверка на все нули
        if all(b == 0 for b in key_bytes):
            print(f"[!] Предупреждение: Используется слабый ключ (все нули)")

        # Проверка на последовательные байты
        is_sequential = True
        for i in range(1, len(key_bytes)):
            if key_bytes[i] != key_bytes[i-1] + 1:
                is_sequential = False
                break

        if is_sequential:
            print(f"[!] Предупреждение: Используется слабый ключ (последовательные байты)")

        # Проверка на одинаковые байты
        if all(b == key_bytes[0] for b in key_bytes):
            print(f"[!] Предупреждение: Используется слабый ключ (все байты одинаковые)")

    except:
        pass  # Если не можем проверить, пропускаем


def validate_input_file(filepath):
    """Валидация входного файла"""
    if filepath != '-' and not os.path.exists(filepath):
        print_error(f"Входной файл не найден: '{filepath}'")

    if filepath != '-' and not os.path.isfile(filepath):
        print_error(f"'{filepath}' не является файлом")

    if filepath != '-' and not os.access(filepath, os.R_OK):
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