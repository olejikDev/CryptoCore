# CryptoCore — API документация

---

### CryptoCore — это криптографическая библиотека на Python, предоставляющая полный набор функций для безопасной работы с данными.

### Основные возможности:
- Шифрование: AES-128/192/256 в режимах ECB, CBC, CFB, OFB, CTR, GCM
- Аутентифицированное шифрование: GCM и Encrypt-then-MAC (AEAD)
- Хеширование: SHA-256 и SHA3-256
- Аутентификация сообщений: HMAC-SHA256
- Получение ключей: PBKDF2-HMAC-SHA256 и HKDF

### Архитектура модулей:
```
src/
├── cipher.py # Шифрование
│ └── modes/ # Режимы работы AES
│ ├── cbc.py, cfb.py, ofb.py, ctr.py
│ ├── gcm.py # GCM с аутентификацией
├── aead.py # Encrypt-then-MAC AEAD
├── crypto_core.py 
├── hash/ # Хеш-функции
├── kdf/ # Получение ключей
├── mac/ # HMAC
├── file_io.py # Работа с файлами
└── cli_parser.py # Парсер командной строки
```

---


## Режимы CBC, CFB, OFB, CTR

Все эти режимы наследуются от BaseMode и имеют одинаковый интерфейс

CBC, ECB: Требует паддинг, использует IV

CFB, OFB, CTR: Потоковые режимы, не требуют паддинга, используют IV

### GCM (Galois/Counter Mode): gcm.py

Что делает: Аутентифицированное шифрование с использованием GCM.

Методы:

`encrypt(plaintext: bytes, iv: bytes = None, aad: bytes = b"") -> bytes`
Шифрует данные с аутентификацией.

Параметры:

plaintext: Данные для шифрования

iv: 12-байтный nonce (генерируется автоматически если None)

aad: Дополнительные аутентифицированные данные

Возвращает:

bytes: 12-байтный nonce + ciphertext + 16-байтный тег

`decrypt(data: bytes, iv: bytes = None, aad: bytes = b"") -> bytes`
Дешифрует и проверяет аутентификацию данных.

Параметры:

data: Данные в формате nonce + ciphertext + tag

iv: Nonce (если не включён в data)

aad: Те же AAD данные, что при шифровании

Возвращает:

bytes: Расшифрованные данные

Выбрасывает:

AuthenticationError: если аутентификация не пройдена

### Encrypt-then-MAC AEAD: aead.py

Класс `AEAD_EncryptThenMAC(key, mode='ctr', hash_algo='sha256')`

Что делает: AEAD конструкция Encrypt-then-Mac.

key: Основной ключ

mode: Режим шифрования ('ctr' или 'cbc')

hash_algo: Алгоритм хеширования (только 'sha256')

Особенности:

Автоматически создаёт отдельные ключи для шифрования и MAC

Использует HMAC-SHA256 для аутентификации

Методы:

`encrypt(plaintext, aad=b"", iv=None) -> bytes`
Шифрует данные и вычисляет MAC.

`decrypt(data, aad=b"", iv=None) -> bytes`
Проверяет MAC и дешифрует данные.

---

## Модуль cryptocore.hash — хеш-функции

Класс `SHA256()`

Что делает: Вычисляет SHA-256 хеш.

Методы:

`update(data: bytes)`
Добавляет данные для хеширования.

`digest() -> bytes`
Возвращает итоговый хеш в бинарном формате.

`hexdigest() -> str`
Возвращает итоговый хеш в hex формате.

SHA3-256: sha3_256.py
Аналогичный интерфейс для `SHA3-256`.


##  Модуль cryptocore.mac — аутентификация сообщений

 HMAC-SHA256: hmac.py

Класс `HMAC(key, hash_function='sha256')`

Что делает: Вычисляет HMAC с использованием SHA-256.

Методы:

`compute(message: bytes) -> str`
Вычисляет HMAC и возвращает hex строку.

`compute_bytes(message: bytes) -> bytes`
Вычисляет HMAC и возвращает байты.

`compute_file(file_path: str, chunk_size=8192) -> str`
Вычисляет HMAC для файла (обрабатывает большие файлы).

`verify(message: bytes, hmac_to_check: str) -> bool`
Проверяет HMAC.

---

##  Модуль cryptocore.kdf — получение ключей

###  PBKDF2-HMAC-SHA256: pbkdf2.py

#### Функция `pbkdf2_hmac_sha256(password, salt, iterations, dklen)`

Что делает: Генерирует ключ из пароля с использованием PBKDF2.

Параметры:

password: Пароль (bytes или str)

salt: Соль (bytes или str)

iterations: Количество итераций

dklen: Длина получаемого ключа в байтах

Возвращает:

bytes: Производный ключ

### HKDF для иерархии ключей: hkdf.py

#### Функция `derive_key(master_key: bytes, context: str, length: int = 32) -> bytes`

Что делает: Создаёт ключ из мастер-ключа для определённого контекста.


###  Криптостойкий ГСЧ: csprng.py

#### Функция `generate_random_bytes(num_bytes: int) -> bytes`

Что делает: Генерирует криптостойкие случайные байты.


##  Модуль `cryptocore.file_io` — работа с файлами

Что делает: Читает файл чанками (генератор).

Зачем: Для обработки больших файлов без загрузки в память целиком.
