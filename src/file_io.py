"""
Модуль для операций ввода-вывода файлов
"""

import os


def read_binary(filepath):
    """Чтение файла в бинарном режиме"""
    try:
        with open(filepath, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл не найден: {filepath}")
    except PermissionError:
        raise PermissionError(f"Нет прав на чтение файла: {filepath}")
    except IOError as e:
        raise IOError(f"Ошибка при чтении файла {filepath}: {e}")


def write_binary(filepath, data):
    """Запись данных в файл в бинарном режиме"""
    try:
        # Создаем директорию если её нет
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        with open(filepath, 'wb') as file:
            file.write(data)
    except PermissionError:
        raise PermissionError(f"Нет прав на запись в файл: {filepath}")
    except IOError as e:
        raise IOError(f"Ошибка при записи файла {filepath}: {e}")