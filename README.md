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

