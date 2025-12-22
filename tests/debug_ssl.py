#!/usr/bin/env python3
"""
Диагностика реальной проблемы OpenSSL ↔ CryptoCore
"""

import os
import sys
import tempfile
import subprocess
import binascii


def hexdump(data, offset=0):
    """Простой hex dump"""
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'{offset + i:08x}: {hex_str:<48} {ascii_str}')
    return '\n'.join(result)


def main():
    print("=" * 80)
    print("ДЕТАЛЬНАЯ ДАГНОСТКА OPENSSL ↔ CRYPTOCORE")
    print("=" * 80)

    key_hex = "000102030405060708090a0b0c0d0e0f"
    iv_hex = "00000000000000000000000000000000"

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Создаем МАЛЕНЬКЙ тестовый файл (3 байта)
        test_file = os.path.join(tmpdir, "test.txt")
        test_data = b"ABC"  # 3 байта: 0x41 0x42 0x43
        with open(test_file, 'wb') as f:
            f.write(test_data)

        print(f"Тестовые данные: {len(test_data)} байт")
        print(f"Hex: {test_data.hex()}")
        print(f"ASCII: {test_data.decode('ascii', errors='replace')}")

        # 2. Шифруем через OpenSSL
        print("\n" + "-" * 40)
        print("1. OpenSSL шифрование (CBC):")
        openssl_enc = os.path.join(tmpdir, "openssl_enc.bin")

        cmd = f'openssl enc -aes-128-cbc -K {key_hex} -iv {iv_hex} -in "{test_file}" -out "{openssl_enc}"'
        print(f"Команда: {cmd}")

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Ошибка OpenSSL: {result.stderr}")
            return

        with open(openssl_enc, 'rb') as f:
            openssl_data = f.read()

        print(f"\nOpenSSL создал файл: {len(openssl_data)} байт")
        print(hexdump(openssl_data))

        # 3. Шифруем через CryptoCore
        print("\n" + "-" * 40)
        print("2. CryptoCore шифрование (CBC):")
        crypto_enc = os.path.join(tmpdir, "crypto_enc.bin")

        cmd = [
            sys.executable, 'cryptocore.py',
            '-algorithm', 'aes',
            '-mode', 'cbc',
            '-encrypt',
            '-key', f'@{key_hex}',
            '-iv', iv_hex,
            '-input', test_file,
            '-output', crypto_enc
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Ошибка CryptoCore: {result.stderr}")
            return

        with open(crypto_enc, 'rb') as f:
            crypto_data = f.read()

        print(f"\nCryptoCore создал файл: {len(crypto_data)} байт")
        print(hexdump(crypto_data))

        # 4. Сравниваем
        print("\n" + "-" * 40)
        print("3. СРАВНЕНЕ:")

        # CryptoCore: первые 16 байт - IV, затем ciphertext
        crypto_iv = crypto_data[:16]
        crypto_ciphertext = crypto_data[16:]

        print(f"CryptoCore IV: {crypto_iv.hex()}")
        print(f"CryptoCore ciphertext ({len(crypto_ciphertext)} байт):")
        print(hexdump(crypto_ciphertext))

        print(f"\nOpenSSL ciphertext ({len(openssl_data)} байт):")
        print(hexdump(openssl_data))

        # 5. Пробуем дешифровать OpenSSL файл через CryptoCore
        print("\n" + "-" * 40)
        print("4. Дешифрование OpenSSL файла через CryptoCore:")

        # Создаем файл с IV + ciphertext для CryptoCore
        crypto_input = os.path.join(tmpdir, "for_crypto.bin")
        with open(crypto_input, 'wb') as f:
            f.write(bytes.fromhex(iv_hex))  # IV
            f.write(openssl_data)  # Ciphertext от OpenSSL

        crypto_dec = os.path.join(tmpdir, "crypto_dec.txt")

        cmd = [
            sys.executable, 'cryptocore.py',
            '-algorithm', 'aes',
            '-mode', 'cbc',
            '-decrypt',
            '-key', f'@{key_hex}',
            '-input', crypto_input,
            '-output', crypto_dec
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Ошибка дешифрования: {result.stderr}")
        else:
            with open(crypto_dec, 'rb') as f:
                decrypted = f.read()

            print(f"\nДешифровано: {len(decrypted)} байт")
            print(f"Hex: {decrypted.hex()}")
            print(f"ASCII: {decrypted.decode('ascii', errors='replace')}")

            if decrypted == test_data:
                print("✅ УСПЕХ! Файлы совпадают!")
            else:
                print("❌ ОШБКА! Файлы разные!")

                # Покажем разницу
                print(f"\nОжидалось: {test_data.hex()} ({test_data})")
                print(f"Получено:  {decrypted.hex()} ({decrypted})")

                # Попробуем без padding
                print("\nПопробуем получить raw данные...")

                # Вызовем напрямую CBC класс
                sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
                from src.modes.cbc import CBCMode

                cipher = CBCMode(bytes.fromhex(key_hex), bytes.fromhex(iv_hex))
                with open(crypto_input, 'rb') as f:
                    crypto_input_data = f.read()
                raw_decrypted = cipher.decrypt(crypto_input_data, remove_padding=False)

                print(f"\nRaw дешифрование (без удаления padding):")
                print(f"Длина: {len(raw_decrypted)} байт")
                print(f"Hex: {raw_decrypted.hex()}")
                print(f"Последние байты: {raw_decrypted[-16:].hex()}")

                # Проверим padding
                if len(raw_decrypted) > 0:
                    last_byte = raw_decrypted[-1]
                    print(f"\nПоследний байт: 0x{last_byte:02x} ({last_byte})")

                    # Если это PKCS#7 padding, последние N байт должны быть N
                    if 1 <= last_byte <= 16:
                        padding = raw_decrypted[-last_byte:]
                        if all(b == last_byte for b in padding):
                            print(f"✅ Найден PKCS#7 padding: {last_byte} байт")
                            data_without_padding = raw_decrypted[:-last_byte]
                            print(f"Данные без padding: {data_without_padding.hex()}")
                            if data_without_padding == test_data:
                                print("✅ Данные совпадают после удаления padding!")
                            else:
                                print("❌ Данные не совпадают даже после удаления padding")


if __name__ == "__main__":
    main()

