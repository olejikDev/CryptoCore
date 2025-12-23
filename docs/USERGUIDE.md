# CryptoCore — Руководство пользователя

## 1. Клонирование репозитория

```bash

git clone https://github.com/olejikDev/CryptoCore.git
```

### Зачем: Эта команда скачивает исходный код библиотеки с GitHub в вашу локальную систему.

### Результат: Создаётся папка cryptocore со всем кодом проекта.

## 2. Обновление списка пакетов (только для Linux/macOS)

```bash

sudo apt update
```

### Зачем: Обновляет список доступных пакетов в системе (если вы используете Debian/Ubuntu). Это гарантирует, что вы установите последние версии зависимостей.

## 3. Переход в папку проекта

```bash

cd CryptoCore
```

### Зачем: Перемещает вас в корневую папку проекта, где находятся setup.py, cryptocore.py и другие ключевые файлы.

## 4. Создание виртуального окружения

```bash

python3 -m venv venv
```

### Зачем: Создаёт изолированную среду Python для проекта. Это позволяет:

а) Устанавливать зависимости без конфликтов с системными пакетами.

б) Чисто тестировать и разрабатывать.

в) Легко удалить проект позже.

## 5. Активация виртуального окружения

```bash

source venv/bin/activate
```

### Зачем: Активирует созданное окружение. Теперь все команды python и pip будут работать внутри него.

## 6. Установка библиотеки в режиме разработки

```bash

pip install .
```

### Зачем: Устанавливает библиотеку cryptocore в ваше виртуальное окружение в редактируемом режиме. Это значит:

а) Все модули становятся доступны для импорта.

б) Изменения в коде сразу применяются без переустановки.

в) Устанавливаются зависимости из requirements.txt и setup.py.

## 7. Запуск полного тестирования

```bash

python -m pytest tests/ -v
```

### Зачем: Запускает все тесты библиотеки для проверки корректности работы.

# Устранение неполадок

## 1. Ошибка "command not found"

### Убедитесь, что виртуальное окружение активировано (см. шаг 5).

## 2. Ошибки при установке

### Проверьте версию Python (Требуется Python 3.8 или выше):

```bash

python --version
```

### Для установки:

```bash

sudo apt update
sudo apt install python3-venv python3-pip python3-full
```

python3-venv — для создания виртуальных окружений

python3-pip — для установки Python-пакетов

python3-full — устанавливает Python 3 с дополнительными пакетами (включая последнюю стабильную версию)

После установки повторно проверьте версию

## 3. Ошибки в тестах

### Если тесты не проходят, убедитесь, что вы выполнили все шаги и установили все зависимости.

## Тестирование

### Запуск тестов:
```bash
# Активация виртуального окружения
source venv/bin/activate

# Переход в директорию проекта
cd src

# Тестирование Key Derivation (Sprint 7)
python -m pytest tests/test_pbkdf2.py -v
python -m pytest tests/test_hkdf.py -v

# Тестирование GCM (Sprint 6)
python -m pytest tests/test_gcm.py -v

# Тестирование HMAC (Sprint 5)
python -m pytest tests/test_mac.py -v

# Тестирование SHA-256 (Sprint 4)
python -m pytest tests/test_hash.py -v

# Полный набор тестов
python -m pytest tests/ -v

# Тестирование ecb (Sprint 1)
python -m pytest tests/test_roundtrip.py -v

# Шифрование
python src/crypto_core.py -algorithm aes -mode ecb -encrypt -key @00112233445566778899aabbccddeeff -input plain.txt -output cipher.bin

# Дешифрование ecb
python src/crypto_core.py -algorithm aes -mode ecb -decrypt -key @00112233445566778899aabbccddeeff -input cipher.bin -output decrypted.txt

# Шифрование с CryptoCore
python cryptocore.py encrypt --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input test.txt --output test_encrypted.bin

# Дешифрование с CryptoCore
python cryptocore.py encrypt --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input test_encrypted.bin --output test_decrypted.txt

# Сравнение
Get-Item test.txt, decrypted.txt | Format-Table Name, Length -AutoSize
```

