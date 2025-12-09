# CryptoCore

Инструмент командной строки для шифрования и дешифрования AES-128 в режиме ECB.

## Установка

Установите Python 3.8+ и pip.
pip install -r requirements.txt

## Шифрование
python src/crypto_core.py -algorithm aes -mode ecb -encrypt \
  -key @00112233445566778899aabbccddeeff \
  -input plain.txt -output cipher.bin

## Дешифрование
python src/crypto_core.py -algorithm aes -mode ecb -decrypt \
  -key @00112233445566778899aabbccddeeff \
  -input cipher.bin -output decrypted.txt

## Тест шифрование-дешифрование:
python tests/test_roundtrip.py

# Sprint 2

Реализация конфиденциальных режимов работы AES-128: CBC, CFB, OFB, CTR.

### Доступные значения для `--mode`:
- `cbc` - Cipher Block Chaining (требует padding)
- `cfb` - Cipher Feedback (потоковый, без padding)  
- `ofb` - Output Feedback (потоковый, без padding)
- `ctr` - Counter (потоковый, без padding)

## Обработка IV

### При шифровании:
- IV генерируется автоматически (`os.urandom(16)`)
- IV записывается в начало файла
- Аргумент `-iv` **не принимается** при шифровании

### При дешифровании:
1. **С указанным IV:** `-iv AABBCCDDEEFF00112233445566778899`
2. **Без IV:** читается из первых 16 байт файла

### Формат файла:
<16-байтный IV><шифротекст>

## Примеры использования
Шифрование (CBC режим):
python cryptocore.py -algorithm aes -mode cbc -encrypt \
  -key @00112233445566778899aabbccddeeff \
  -input plain.txt -output cipher.bin

Дешифрование с указанным IV:

python cryptocore.py -algorithm aes -mode cbc -decrypt \
  -key @00112233445566778899aabbccddeeff \
  -iv aabbccddeeff00112233445566778899 \
  -input cipher.bin -output decrypted.txt

Дешифрование с IV из файла:

python cryptocore.py -algorithm aes -mode cbc -decrypt \
  -key @00112233445566778899aabbccddeeff \
  -input cipher_with_iv.bin -output decrypted.txt

Тестирование совместимости с OpenSSL (Требование TEST-4)
Предварительные требования

openssl version
Автоматические тесты

# Полные тесты совместимости
python tests/test_openssl_interop.py

# Round-trip тесты
python tests/test_roundtrip.py
Ручное тестирование совместимости
Тест 1: CryptoCore → OpenSSL (Требование TEST-2)

# Шифруем с помощью CryptoCore (CBC режим)
python cryptocore.py -algorithm aes -mode cbc -encrypt \
  -key @000102030405060708090a0b0c0d0e0f \
  -input plain.txt -output cipher.bin

# Извлекаем IV из первых 16 байт
dd if=cipher.bin of=iv.bin bs=16 count=1

# Извлекаем ciphertext (пропускаем IV)
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1

# Дешифруем с помощью OpenSSL
openssl enc -aes-128-cbc -d \
  -K 000102030405060708090a0b0c0d0e0f \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext_only.bin -out decrypted.txt

# Проверяем совпадение
diff plain.txt decrypted.txt
Тест 2: OpenSSL → CryptoCore (Требование TEST-3)

# Шифруем с помощью OpenSSL (CBC режим)
openssl enc -aes-128-cbc \
  -K 000102030405060708090a0b0c0d0e0f \
  -iv AABBCCDDEEFF00112233445566778899 \
  -in plain.txt -out openssl_cipher.bin

#  Дешифруем с помощью CryptoCore
python cryptocore.py -algorithm aes -mode cbc -decrypt \
  -key @000102030405060708090a0b0c0d0e0f \
  -iv AABBCCDDEEFF00112233445566778899 \
  -input openssl_cipher.bin -output decrypted.txt

