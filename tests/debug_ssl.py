#!/usr/bin/env python3
"""
Р”РёР°РіРЅРѕСЃС‚РёРєР° СЂРµР°Р»СЊРЅРѕР№ РїСЂРѕР±Р»РµРјС‹ OpenSSL в†” CryptoCore
"""

import os
import sys
import tempfile
import subprocess
import binascii


def hexdump(data, offset=0):
    """РџСЂРѕСЃС‚РѕР№ hex dump"""
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'{offset + i:08x}: {hex_str:<48} {ascii_str}')
    return '\n'.join(result)


def main():
    print("=" * 80)
    print("Р”Р•РўРђР›Р¬РќРђРЇ Р”РРђР“РќРћРЎРўРРљРђ OPENSSL в†” CRYPTOCORE")
    print("=" * 80)

    key_hex = "000102030405060708090a0b0c0d0e0f"
    iv_hex = "00000000000000000000000000000000"

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. РЎРѕР·РґР°РµРј РњРђР›Р•РќР¬РљРР™ С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р» (3 Р±Р°Р№С‚Р°)
        test_file = os.path.join(tmpdir, "test.txt")
        test_data = b"ABC"  # 3 Р±Р°Р№С‚Р°: 0x41 0x42 0x43
        with open(test_file, 'wb') as f:
            f.write(test_data)

        print(f"РўРµСЃС‚РѕРІС‹Рµ РґР°РЅРЅС‹Рµ: {len(test_data)} Р±Р°Р№С‚")
        print(f"Hex: {test_data.hex()}")
        print(f"ASCII: {test_data.decode('ascii', errors='replace')}")

        # 2. РЁРёС„СЂСѓРµРј С‡РµСЂРµР· OpenSSL
        print("\n" + "-" * 40)
        print("1. OpenSSL С€РёС„СЂРѕРІР°РЅРёРµ (CBC):")
        openssl_enc = os.path.join(tmpdir, "openssl_enc.bin")

        cmd = f'openssl enc -aes-128-cbc -K {key_hex} -iv {iv_hex} -in "{test_file}" -out "{openssl_enc}"'
        print(f"РљРѕРјР°РЅРґР°: {cmd}")

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"РћС€РёР±РєР° OpenSSL: {result.stderr}")
            return

        with open(openssl_enc, 'rb') as f:
            openssl_data = f.read()

        print(f"\nOpenSSL СЃРѕР·РґР°Р» С„Р°Р№Р»: {len(openssl_data)} Р±Р°Р№С‚")
        print(hexdump(openssl_data))

        # 3. РЁРёС„СЂСѓРµРј С‡РµСЂРµР· CryptoCore
        print("\n" + "-" * 40)
        print("2. CryptoCore С€РёС„СЂРѕРІР°РЅРёРµ (CBC):")
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
            print(f"РћС€РёР±РєР° CryptoCore: {result.stderr}")
            return

        with open(crypto_enc, 'rb') as f:
            crypto_data = f.read()

        print(f"\nCryptoCore СЃРѕР·РґР°Р» С„Р°Р№Р»: {len(crypto_data)} Р±Р°Р№С‚")
        print(hexdump(crypto_data))

        # 4. РЎСЂР°РІРЅРёРІР°РµРј
        print("\n" + "-" * 40)
        print("3. РЎР РђР’РќР•РќРР•:")

        # CryptoCore: РїРµСЂРІС‹Рµ 16 Р±Р°Р№С‚ - IV, Р·Р°С‚РµРј ciphertext
        crypto_iv = crypto_data[:16]
        crypto_ciphertext = crypto_data[16:]

        print(f"CryptoCore IV: {crypto_iv.hex()}")
        print(f"CryptoCore ciphertext ({len(crypto_ciphertext)} Р±Р°Р№С‚):")
        print(hexdump(crypto_ciphertext))

        print(f"\nOpenSSL ciphertext ({len(openssl_data)} Р±Р°Р№С‚):")
        print(hexdump(openssl_data))

        # 5. РџСЂРѕР±СѓРµРј РґРµС€РёС„СЂРѕРІР°С‚СЊ OpenSSL С„Р°Р№Р» С‡РµСЂРµР· CryptoCore
        print("\n" + "-" * 40)
        print("4. Р”РµС€РёС„СЂРѕРІР°РЅРёРµ OpenSSL С„Р°Р№Р»Р° С‡РµСЂРµР· CryptoCore:")

        # РЎРѕР·РґР°РµРј С„Р°Р№Р» СЃ IV + ciphertext РґР»СЏ CryptoCore
        crypto_input = os.path.join(tmpdir, "for_crypto.bin")
        with open(crypto_input, 'wb') as f:
            f.write(bytes.fromhex(iv_hex))  # IV
            f.write(openssl_data)  # Ciphertext РѕС‚ OpenSSL

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
            print(f"РћС€РёР±РєР° РґРµС€РёС„СЂРѕРІР°РЅРёСЏ: {result.stderr}")
        else:
            with open(crypto_dec, 'rb') as f:
                decrypted = f.read()

            print(f"\nР”РµС€РёС„СЂРѕРІР°РЅРѕ: {len(decrypted)} Р±Р°Р№С‚")
            print(f"Hex: {decrypted.hex()}")
            print(f"ASCII: {decrypted.decode('ascii', errors='replace')}")

            if decrypted == test_data:
                print("вњ… РЈРЎРџР•РҐ! Р¤Р°Р№Р»С‹ СЃРѕРІРїР°РґР°СЋС‚!")
            else:
                print("вќЊ РћРЁРР‘РљРђ! Р¤Р°Р№Р»С‹ СЂР°Р·РЅС‹Рµ!")

                # РџРѕРєР°Р¶РµРј СЂР°Р·РЅРёС†Сѓ
                print(f"\nРћР¶РёРґР°Р»РѕСЃСЊ: {test_data.hex()} ({test_data})")
                print(f"РџРѕР»СѓС‡РµРЅРѕ:  {decrypted.hex()} ({decrypted})")

                # РџРѕРїСЂРѕР±СѓРµРј Р±РµР· padding
                print("\nРџРѕРїСЂРѕР±СѓРµРј РїРѕР»СѓС‡РёС‚СЊ raw РґР°РЅРЅС‹Рµ...")

                # Р’С‹Р·РѕРІРµРј РЅР°РїСЂСЏРјСѓСЋ CBC РєР»Р°СЃСЃ
                sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
                from src.modes.cbc import CBCMode

                cipher = CBCMode(bytes.fromhex(key_hex), bytes.fromhex(iv_hex))
                with open(crypto_input, 'rb') as f:
                    crypto_input_data = f.read()
                raw_decrypted = cipher.decrypt(crypto_input_data, remove_padding=False)

                print(f"\nRaw РґРµС€РёС„СЂРѕРІР°РЅРёРµ (Р±РµР· СѓРґР°Р»РµРЅРёСЏ padding):")
                print(f"Р”Р»РёРЅР°: {len(raw_decrypted)} Р±Р°Р№С‚")
                print(f"Hex: {raw_decrypted.hex()}")
                print(f"РџРѕСЃР»РµРґРЅРёРµ Р±Р°Р№С‚С‹: {raw_decrypted[-16:].hex()}")

                # РџСЂРѕРІРµСЂРёРј padding
                if len(raw_decrypted) > 0:
                    last_byte = raw_decrypted[-1]
                    print(f"\nРџРѕСЃР»РµРґРЅРёР№ Р±Р°Р№С‚: 0x{last_byte:02x} ({last_byte})")

                    # Р•СЃР»Рё СЌС‚Рѕ PKCS#7 padding, РїРѕСЃР»РµРґРЅРёРµ N Р±Р°Р№С‚ РґРѕР»Р¶РЅС‹ Р±С‹С‚СЊ N
                    if 1 <= last_byte <= 16:
                        padding = raw_decrypted[-last_byte:]
                        if all(b == last_byte for b in padding):
                            print(f"вњ… РќР°Р№РґРµРЅ PKCS#7 padding: {last_byte} Р±Р°Р№С‚")
                            data_without_padding = raw_decrypted[:-last_byte]
                            print(f"Р”Р°РЅРЅС‹Рµ Р±РµР· padding: {data_without_padding.hex()}")
                            if data_without_padding == test_data:
                                print("вњ… Р”Р°РЅРЅС‹Рµ СЃРѕРІРїР°РґР°СЋС‚ РїРѕСЃР»Рµ СѓРґР°Р»РµРЅРёСЏ padding!")
                            else:
                                print("вќЊ Р”Р°РЅРЅС‹Рµ РЅРµ СЃРѕРІРїР°РґР°СЋС‚ РґР°Р¶Рµ РїРѕСЃР»Рµ СѓРґР°Р»РµРЅРёСЏ padding")


if __name__ == "__main__":
    main()

