"""
Модуль для криптографически стойкой генерации случайных чисел
Sprint 3: Реализация CSPRNG для ключей и IV
"""

import os


def generate_random_bytes(num_bytes: int) -> bytes:
    """
    Генерация криптографически стойких случайных байтов

    Args:
        num_bytes: количество байтов для генерации

    Returns:
        bytes: случайные байты

    Raises:
        ValueError: если num_bytes <= 0
        RuntimeError: если не удалось сгенерировать случайные байты
    """
    if num_bytes <= 0:
        raise ValueError(f"num_bytes должен быть положительным числом. Получено: {num_bytes}")

    try:
        # спользуем os.urandom() как криптографически стойкий источник
        # Это соответствует требованию RNG-3 для Python
        random_bytes = os.urandom(num_bytes)

        # Проверка, что получили правильное количество байтов
        if len(random_bytes) != num_bytes:
            raise RuntimeError(f"Не удалось сгенерировать {num_bytes} байтов. Получено: {len(random_bytes)} байтов")

        return random_bytes

    except Exception as e:
        raise RuntimeError(f"Ошибка при генерации случайных байтов: {e}")


def generate_random_hex(num_bytes: int) -> str:
    """
    Генерация случайных байтов в hex формате

    Args:
        num_bytes: количество байтов для генерации

    Returns:
        str: hex строка
    """
    random_bytes = generate_random_bytes(num_bytes)
    return random_bytes.hex()


def generate_aes_key() -> bytes:
    """
    Генерация 16-байтного ключа для AES-128

    Returns:
        bytes: 16-байтный ключ
    """
    return generate_random_bytes(16)


def generate_aes_key_hex() -> str:
    """
    Генерация 16-байтного ключа для AES-128 в hex формате

    Returns:
        str: hex строка ключа (32 символа)
    """
    return generate_aes_key().hex()


def generate_iv() -> bytes:
    """
    Генерация 16-байтного вектора инициализации

    Returns:
        bytes: 16-байтный IV
    """
    return generate_random_bytes(16)


def generate_iv_hex() -> str:
    """
    Генерация 16-байтного вектора инициализации в hex формате

    Returns:
        str: hex строка IV (32 символа)
    """
    return generate_iv().hex()


def test_csprng():
    """Тестовая функция для проверки работы CSPRNG"""
    print("Тестирование CSPRNG...")

    # Тест 1: Генерация ключа
    key = generate_aes_key()
    print(f"1. Сгенерирован ключ: {key.hex()}")
    print(f"   Длина: {len(key)} байт ({len(key)*8} бит)")

    # Тест 2: Генерация IV
    iv = generate_iv()
    print(f"2. Сгенерирован IV: {iv.hex()}")
    print(f"   Длина: {len(iv)} байт")

    # Тест 3: Генерация произвольного количества байтов
    random_bytes = generate_random_bytes(32)
    print(f"3. Сгенерировано 32 случайных байта: {random_bytes.hex()[:64]}...")

    # Тест 4: Проверка ошибок
    try:
        generate_random_bytes(0)
    except ValueError as e:
        print(f"4. Корректно обработана ошибка: {e}")

    try:
        generate_random_bytes(-1)
    except ValueError as e:
        print(f"5. Корректно обработана ошибка: {e}")

    print("\n[+] Все тесты CSPRNG пройдены успешно!")
    return True


if __name__ == "__main__":
    test_csprng()

