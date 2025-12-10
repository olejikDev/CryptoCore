#!/usr/bin/env python3
"""
Скрипт для подготовки и запуска NIST тестов
Требование TEST-3: запуск NIST Statistical Test Suite
"""

import os
import sys
import subprocess
import argparse

# Добавляем путь к src для импорта модулей
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from src.csprng import generate_random_bytes
except ImportError:
    print("Ошибка: Не удалось импортировать модуль csprng")
    print("Убедитесь, что вы запускаете скрипт из корневой директории проекта")
    sys.exit(1)


def generate_nist_test_file(size_mb, output_file):
    """
    Генерация файла для NIST тестов

    Args:
        size_mb: размер файла в мегабайтах
        output_file: путь к выходному файлу
    """
    print(f"Генерация файла размером {size_mb} MB для NIST тестов...")

    total_size = size_mb * 1024 * 1024

    try:
        with open(output_file, 'wb') as f:
            bytes_written = 0
            chunk_size = 4096

            while bytes_written < total_size:
                # Отображение прогресса
                if bytes_written % (5 * 1024 * 1024) == 0 and bytes_written > 0:
                    progress = (bytes_written / total_size) * 100
                    print(f"  Прогресс: {progress:.1f}% ({bytes_written / 1024 / 1024:.1f} MB / {size_mb} MB)")

                # Вычисляем размер текущего чанка
                current_chunk_size = min(chunk_size, total_size - bytes_written)

                # Генерируем случайные данные
                random_chunk = generate_random_bytes(current_chunk_size)

                # Записываем в файл
                f.write(random_chunk)
                bytes_written += current_chunk_size

        print(f"[+] Файл создан: {output_file}")
        print(f"    Размер: {bytes_written:,} байтов ({bytes_written / 1024 / 1024:.2f} MB)")
        print(f"    SHA-256: ", end="")

        # Вычисляем хэш для проверки
        import hashlib
        with open(output_file, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            print(file_hash.hexdigest())

        return True

    except Exception as e:
        print(f"[-] Ошибка при создании файла: {e}")
        return False


def check_nist_installed():
    """Проверка, установлен ли NIST STS"""
    nist_paths = [
        "sts-2.1.2/assess",
        "STS/assess",
        "assess"
    ]

    for path in nist_paths:
        if os.path.exists(path):
            print(f"[+] Найден NIST STS: {path}")
            return path

    print("[!] NIST STS не найден в стандартных путях")
    return None


def run_nist_tests(data_file, nist_path):
    """
    Запуск NIST тестов

    Args:
        data_file: путь к тестовому файлу
        nist_path: путь к исполняемому файлу NIST STS
    """
    print(f"\nЗапуск NIST тестов для файла: {data_file}")

    # Получаем размер файла в битах
    file_size = os.path.getsize(data_file)
    bit_length = file_size * 8

    print(f"Размер файла: {file_size:,} байтов ({bit_length:,} бит)")

    # Команда для запуска NIST STS
    cmd = [nist_path, str(bit_length)]

    print(f"\nКоманда для запуска: {' '.join(cmd)}")
    print("\nПосле запуска NIST STS:")
    print("1. Введите путь к тестовому файлу")
    print("2. Выберите '0' для всех тестов")
    print("3. Настройте параметры по умолчанию")
    print("4. Дождитесь завершения тестов")
    print("5. Результаты будут в папке 'experiments/'")

    # Запрос на запуск
    response = input("\nЗапустить NIST STS сейчас? (y/n): ")
    if response.lower() == 'y':
        try:
            subprocess.run(cmd, cwd=os.path.dirname(nist_path) or '.')
        except Exception as e:
            print(f"Ошибка при запуске NIST STS: {e}")
    else:
        print("\nВы можете запустить NIST STS вручную:")
        print(f"cd {os.path.dirname(nist_path) or '.'}")
        print(f"./assess {bit_length}")


def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(
        description="Подготовка данных и запуск NIST Statistical Test Suite"
    )

    parser.add_argument(
        "--size",
        type=int,
        default=10,
        help="Размер тестового файла в мегабайтах (по умолчанию: 10)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="nist_test_data.bin",
        help="Имя выходного файла (по умолчанию: nist_test_data.bin)"
    )

    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="Только сгенерировать файл, не запускать NIST STS"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("ПОДГОТОВКА К NIST STATISTICAL TEST SUITE")
    print("Требование TEST-3: Проверка CSPRNG с помощью NIST STS")
    print("=" * 70)

    # 1. Генерация тестового файла
    print("\n[1/3] Генерация тестового файла...")
    if not generate_nist_test_file(args.size, args.output):
        sys.exit(1)

    # 2. Проверка наличия NIST STS
    print("\n[2/3] Поиск NIST STS...")
    nist_path = check_nist_installed()

    if not nist_path:
        print("\n[!] NIST STS не установлен")
        print("\nИнструкции по установке:")
        print("1. Скачайте NIST Statistical Test Suite:")
        print("   https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software")
        print("2. Распакуйте архив:")
        print("   tar -xzf sts-2.1.2.tar.gz")
        print("3. Перейдите в директорию и скомпилируйте:")
        print("   cd sts-2.1.2")
        print("   make")
        print("4. Исполняемый файл будет в sts-2.1.2/assess")

    # 3. Запуск NIST STS (если не указан --generate-only)
    if not args.generate_only and nist_path:
        print("\n[3/3] Запуск NIST STS...")
        run_nist_tests(args.output, nist_path)
    elif args.generate_only:
        print("\n[3/3] Генерация завершена. NIST STS не запущен (--generate-only)")
    else:
        print("\n[3/3] NIST STS не найден, запуск невозможен")

    # Информация об анализе результатов
    print("\n" + "=" * 70)
    print("АНАЛИЗ РЕЗУЛЬТАТОВ NIST STS")
    print("=" * 70)
    print("\nКритерии успеха для CSPRNG:")
    print("1. Большинство тестов должно иметь p-value ≥ 0.01")
    print("2. Процент успешных тестов должен быть ≥ 95%")
    print("3. Небольшое количество сбоев статистически ожидаемо")
    print("\nТесты, которые выполняет NIST STS:")
    print("1. Frequency (Monobit) Test")
    print("2. Frequency Test within a Block")
    print("3. Runs Test")
    print("4. Test for the Longest Run of Ones in a Block")
    print("5. Binary Matrix Rank Test")
    print("6. Discrete Fourier Transform (Spectral) Test")
    print("7. Non-overlapping Template Matching Test")
    print("8. Overlapping Template Matching Test")
    print("9. Maurer's Universal Statistical Test")
    print("10. Linear Complexity Test")
    print("11. Serial Test")
    print("12. Approximate Entropy Test")
    print("13. Cumulative Sums (Cusum) Test")
    print("14. Random Excursions Test")
    print("15. Random Excursions Variant Test")
    print("\nРезультаты будут сохранены в experiments/AlgorithmTesting/finalAnalysisReport.txt")


if __name__ == "__main__":
    main()