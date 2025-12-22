#!/usr/bin/env python3
"""
РўРµСЃС‚С‹ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё CryptoCore СЃ OpenSSL
Sprint 2: Р РµР¶РёРјС‹ CBC, CFB, OFB, CTR
РўСЂРµР±РѕРІР°РЅРёСЏ TEST-2, TEST-3: СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚СЊ РІ РѕР±РѕРёС… РЅР°РїСЂР°РІР»РµРЅРёСЏС…
"""

import os
import sys
import tempfile
import subprocess
import hashlib
import binascii

# Р”РѕР±Р°РІР»СЏРµРј РїСѓС‚СЊ Рє src
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def check_openssl():
    """РџСЂРѕРІРµСЂРёС‚СЊ РЅР°Р»РёС‡РёРµ OpenSSL"""
    try:
        result = subprocess.run(['openssl', 'version'],
                                capture_output=True, text=True, shell=True)
        return result.returncode == 0
    except:
        return False


def get_file_hash(filepath):
    """РџРѕР»СѓС‡РёС‚СЊ SHA256 С…РµС€ С„Р°Р№Р»Р°"""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def compare_files_with_debug(file1, file2):
    """РЎСЂР°РІРЅРёС‚СЊ РґРІР° С„Р°Р№Р»Р° СЃ РїРѕРґСЂРѕР±РЅРѕР№ РѕС‚Р»Р°РґРєРѕР№"""
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            content1 = f1.read()
            content2 = f2.read()

            print(f"  [DEBUG] {os.path.basename(file1)}: {len(content1)} Р±Р°Р№С‚")
            print(f"  [DEBUG] {os.path.basename(file2)}: {len(content2)} Р±Р°Р№С‚")

            if len(content1) != len(content2):
                print(f"  [DEBUG] Р Р°Р·РЅР°СЏ РґР»РёРЅР°: {len(content1)} vs {len(content2)}")

            # РџРѕРєР°Р¶РµРј РїРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° РґР»СЏ СЃСЂР°РІРЅРµРЅРёСЏ
            print(f"  [DEBUG] РџРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° С„Р°Р№Р»Р° 1: {binascii.hexlify(content1[:32])}")
            print(f"  [DEBUG] РџРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° С„Р°Р№Р»Р° 2: {binascii.hexlify(content2[:32])}")

            # РџСЂСЏРјРѕРµ СЃСЂР°РІРЅРµРЅРёРµ
            if content1 == content2:
                return True, f"Р¤Р°Р№Р»С‹ РёРґРµРЅС‚РёС‡РЅС‹ ({len(content1)} Р±Р°Р№С‚)"

            # РџРѕРёСЃРє РїРµСЂРІРѕРіРѕ СЂР°Р·Р»РёС‡РёСЏ
            min_len = min(len(content1), len(content2))
            for i in range(min_len):
                if content1[i] != content2[i]:
                    return False, f"Р Р°Р·Р»РёС‡РёРµ РЅР° РїРѕР·РёС†РёРё {i}: 0x{content1[i]:02x} vs 0x{content2[i]:02x}"
                    break

            if len(content1) != len(content2):
                return False, f"Р Р°Р·РЅР°СЏ РґР»РёРЅР°: {len(content1)} vs {len(content2)} Р±Р°Р№С‚"
            return False, "Р¤Р°Р№Р»С‹ СЂР°Р·РЅС‹Рµ"

    except Exception as e:
        return False, f"РћС€РёР±РєР° СЃСЂР°РІРЅРµРЅРёСЏ: {e}"


def test_openssl_compatibility():
    """РћСЃРЅРѕРІРЅРѕР№ С‚РµСЃС‚ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё СЃ OpenSSL"""

    print("=" * 70)
    print("РўР•РЎРўР« РЎРћР’РњР•РЎРўРРњРћРЎРўР CRYPTOCORE РЎ OPENSSL")
    print("Sprint 2: Р РµР¶РёРјС‹ CBC, CFB, OFB, CTR")
    print("=" * 70)

    # РўРµСЃС‚РѕРІС‹Рµ РґР°РЅРЅС‹Рµ
    test_key = "000102030405060708090a0b0c0d0e0f"
    test_iv = "00000000000000000000000000000000"

    print(f"[INFO] РљР»СЋС‡: {test_key}")
    print(f"[INFO] IV: {test_iv}")

    # РџСЂРѕРІРµСЂСЏРµРј OpenSSL
    has_openssl = check_openssl()
    if not has_openssl:
        print("[-] OpenSSL РЅРµ РЅР°Р№РґРµРЅ РІ СЃРёСЃС‚РµРјРµ")
        print("[!] РЈСЃС‚Р°РЅРѕРІРёС‚Рµ OpenSSL РґР»СЏ РїРѕР»РЅРѕРіРѕ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ")
        print("[+] Р‘СѓРґСѓС‚ РІС‹РїРѕР»РЅРµРЅС‹ С‚РѕР»СЊРєРѕ РґРµРјРѕРЅСЃС‚СЂР°С†РёРѕРЅРЅС‹Рµ С‚РµСЃС‚С‹")
        return False

    # РўРµСЃС‚РёСЂСѓРµРјС‹Рµ СЂРµР¶РёРјС‹
    modes = ['cbc', 'cfb', 'ofb', 'ctr']

    results = {}

    for mode in modes:
        print(f"\n{'=' * 40}")
        print(f"РўРµСЃС‚РёСЂСѓРµРј СЂРµР¶РёРј: {mode.upper()}")
        print('=' * 40)

        with tempfile.TemporaryDirectory() as tmpdir:
            # РЎРѕР·РґР°РµРј С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»
            test_file = os.path.join(tmpdir, "test.txt")
            test_content = b"Test data for CryptoCore OpenSSL compatibility check\n" * 10

            with open(test_file, 'wb') as f:
                f.write(test_content)

            test_size = len(test_content)
            print(f"РўРµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»: {test_size} Р±Р°Р№С‚")
            print(f"РџРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° С‚РµСЃС‚Р°: {binascii.hexlify(test_content[:32])}")

            # 1. РўРµСЃС‚: CryptoCore -> OpenSSL
            print(f"\n1. РўРµСЃС‚ CryptoCore -> OpenSSL")
            print("-" * 30)

            # РЁРёС„СЂСѓРµРј СЃ РїРѕРјРѕС‰СЊСЋ CryptoCore
            crypto_enc = os.path.join(tmpdir, f"crypto_enc_{mode}.bin")

            # РљРѕРјР°РЅРґР° CryptoCore РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ
            cmd = [
                sys.executable, 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', mode,
                '-encrypt',
                '-key', f'@{test_key}',
                '-iv', test_iv,
                '-input', test_file,
                '-output', crypto_enc
            ]

            print(f"[DEBUG] РљРѕРјР°РЅРґР° CryptoCore С€РёС„СЂРѕРІР°РЅРёРµ: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  вќЊ РћС€РёР±РєР° С€РёС„СЂРѕРІР°РЅРёСЏ CryptoCore: {result.stderr[:200]}")
                results[mode] = {'crypto_to_openssl': False, 'openssl_to_crypto': False}
                continue

            print(f"  вњ… Р—Р°С€РёС„СЂРѕРІР°РЅРѕ СЃ РїРѕРјРѕС‰СЊСЋ CryptoCore")

            # РџСЂРѕРІРµСЂСЏРµРј СЂР°Р·РјРµСЂ Р·Р°С€РёС„СЂРѕРІР°РЅРЅРѕРіРѕ С„Р°Р№Р»Р°
            crypto_enc_size = os.path.getsize(crypto_enc)
            print(f"  [DEBUG] Р Р°Р·РјРµСЂ crypto_enc: {crypto_enc_size} Р±Р°Р№С‚")

            with open(crypto_enc, 'rb') as f:
                crypto_data = f.read()
                print(f"  [DEBUG] РџРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° crypto_enc: {binascii.hexlify(crypto_data[:32])}")

            # Р”Р»СЏ CBC/CFB/OFB/CTR IV РІ РЅР°С‡Р°Р»Рµ С„Р°Р№Р»Р°
            if len(crypto_data) >= 16:
                file_iv = crypto_data[:16].hex()
                crypto_ciphertext = crypto_data[16:]
                print(f"  [DEBUG] IV РёР· С„Р°Р№Р»Р°: {file_iv}")
                print(f"  [DEBUG] РћР¶РёРґР°РµРјС‹Р№ IV: {test_iv}")
                print(f"  [DEBUG] Р”Р»РёРЅР° ciphertext: {len(crypto_ciphertext)} Р±Р°Р№С‚")

                # РЎРѕС…СЂР°РЅСЏРµРј ciphertext Р±РµР· IV РґР»СЏ OpenSSL
                openssl_input = os.path.join(tmpdir, f"crypto_ciphertext_{mode}.bin")
                with open(openssl_input, 'wb') as f:
                    f.write(crypto_ciphertext)
            else:
                print(f"  вќЊ РЎР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёР№ Р·Р°С€РёС„СЂРѕРІР°РЅРЅС‹Р№ С„Р°Р№Р»")
                results[mode] = {'crypto_to_openssl': False, 'openssl_to_crypto': False}
                continue

            # Р”РµС€РёС„СЂСѓРµРј СЃ РїРѕРјРѕС‰СЊСЋ OpenSSL
            openssl_dec = os.path.join(tmpdir, f"openssl_dec_{mode}.txt")

            # РљРѕРјР°РЅРґР° OpenSSL РґР»СЏ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ
            openssl_cmd = f'openssl enc -aes-128-{mode} -d -K {test_key} -iv {test_iv} -in "{openssl_input}" -out "{openssl_dec}"'
            print(f"[DEBUG] РљРѕРјР°РЅРґР° OpenSSL РґРµС€РёС„СЂРѕРІР°РЅРёРµ: {openssl_cmd}")

            result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  вќЊ РћС€РёР±РєР° РґРµС€РёС„СЂРѕРІР°РЅРёСЏ OpenSSL: {result.stderr[:200]}")
                crypto_to_openssl = False
            else:
                # РЎСЂР°РІРЅРёРІР°РµРј С„Р°Р№Р»С‹
                same, message = compare_files_with_debug(test_file, openssl_dec)
                if same:
                    print(f"  вњ… CryptoCore -> OpenSSL: РЈРЎРџР•РҐ")
                    crypto_to_openssl = True
                else:
                    print(f"  вќЊ CryptoCore -> OpenSSL: {message}")
                    crypto_to_openssl = False

            # 2. РўРµСЃС‚: OpenSSL -> CryptoCore
            print(f"\n2. РўРµСЃС‚ OpenSSL -> CryptoCore")
            print("-" * 30)

            # РЁРёС„СЂСѓРµРј СЃ РїРѕРјРѕС‰СЊСЋ OpenSSL
            openssl_enc = os.path.join(tmpdir, f"openssl_enc_{mode}.bin")

            # РљРѕРјР°РЅРґР° OpenSSL РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ
            openssl_cmd = f'openssl enc -aes-128-{mode} -K {test_key} -iv {test_iv} -in "{test_file}" -out "{openssl_enc}"'
            print(f"[DEBUG] РљРѕРјР°РЅРґР° OpenSSL С€РёС„СЂРѕРІР°РЅРёРµ: {openssl_cmd}")

            result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  вќЊ РћС€РёР±РєР° С€РёС„СЂРѕРІР°РЅРёСЏ OpenSSL: {result.stderr[:200]}")
                openssl_to_crypto = False
            else:
                print(f"  вњ… Р—Р°С€РёС„СЂРѕРІР°РЅРѕ СЃ РїРѕРјРѕС‰СЊСЋ OpenSSL")

                # РџСЂРѕРІРµСЂСЏРµРј СЂР°Р·РјРµСЂ С„Р°Р№Р»Р° OpenSSL
                openssl_enc_size = os.path.getsize(openssl_enc)
                print(f"  [DEBUG] Р Р°Р·РјРµСЂ openssl_enc: {openssl_enc_size} Р±Р°Р№С‚")

                with open(openssl_enc, 'rb') as f:
                    openssl_data = f.read()
                    print(f"  [DEBUG] РџРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° openssl_enc: {binascii.hexlify(openssl_data[:32])}")

                # OpenSSL РќР• Р·Р°РїРёСЃС‹РІР°РµС‚ IV РІ С„Р°Р№Р», РЅСѓР¶РЅРѕ СЃРѕР·РґР°С‚СЊ С„Р°Р№Р» СЃ IV РґР»СЏ CryptoCore
                crypto_input = os.path.join(tmpdir, f"openssl_for_crypto_{mode}.bin")

                # РЎРѕР·РґР°РµРј С„Р°Р№Р» РІ С„РѕСЂРјР°С‚Рµ CryptoCore: IV + ciphertext
                with open(crypto_input, 'wb') as f:
                    if mode != 'ecb':
                        # Р”РѕР±Р°РІР»СЏРµРј IV, РєРѕС‚РѕСЂС‹Р№ РёСЃРїРѕР»СЊР·РѕРІР°Р»СЃСЏ РїСЂРё С€РёС„СЂРѕРІР°РЅРёРё
                        f.write(bytes.fromhex(test_iv))
                    f.write(openssl_data)  # Ciphertext РѕС‚ OpenSSL

                print(f"  [DEBUG] РЎРѕР·РґР°РЅ С„Р°Р№Р» РґР»СЏ CryptoCore: {os.path.getsize(crypto_input)} Р±Р°Р№С‚")
                with open(crypto_input, 'rb') as f:
                    crypto_input_data = f.read()
                    print(f"  [DEBUG] РџРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р° crypto_input: {binascii.hexlify(crypto_input_data[:32])}")

                # Р”РµС€РёС„СЂСѓРµРј СЃ РїРѕРјРѕС‰СЊСЋ CryptoCore
                crypto_dec = os.path.join(tmpdir, f"crypto_dec_{mode}.txt")

                cmd = [
                    sys.executable, 'cryptocore.py',
                    '-algorithm', 'aes',
                    '-mode', mode,
                    '-decrypt',
                    '-key', f'@{test_key}',
                    '-input', crypto_input,  # Р¤Р°Р№Р» СѓР¶Рµ СЃРѕРґРµСЂР¶РёС‚ IV РІ РЅР°С‡Р°Р»Рµ
                    '-output', crypto_dec
                ]

                print(f"[DEBUG] РљРѕРјР°РЅРґР° CryptoCore РґРµС€РёС„СЂРѕРІР°РЅРёРµ: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    print(f"  вќЊ РћС€РёР±РєР° РґРµС€РёС„СЂРѕРІР°РЅРёСЏ CryptoCore: {result.stderr[:200]}")
                    openssl_to_crypto = False
                else:
                    # РЎСЂР°РІРЅРёРІР°РµРј С„Р°Р№Р»С‹
                    same, message = compare_files_with_debug(test_file, crypto_dec)
                    if same:
                        print(f"  вњ… OpenSSL -> CryptoCore: РЈРЎРџР•РҐ")
                        openssl_to_crypto = True
                    else:
                        print(f"  вќЊ OpenSSL -> CryptoCore: {message}")
                        openssl_to_crypto = False

            results[mode] = {
                'crypto_to_openssl': crypto_to_openssl,
                'openssl_to_crypto': openssl_to_crypto
            }

    # РС‚РѕРіРё
    print("\n" + "=" * 70)
    print("РРўРћР“Р РўР•РЎРўРР РћР’РђРќРРЇ РЎРћР’РњР•РЎРўРРњРћРЎРўР")
    print("=" * 70)

    all_passed = True

    for mode in modes:
        result = results.get(mode, {})
        crypto_to_openssl = result.get('crypto_to_openssl', False)
        openssl_to_crypto = result.get('openssl_to_crypto', False)

        status = "вњ… РЈРЎРџР•РҐ" if crypto_to_openssl and openssl_to_crypto else "вќЊ РћРЁРР‘РљРђ"
        print(f"{mode.upper():5} : {status}")

        if crypto_to_openssl:
            print(f"       вЂў CryptoCore -> OpenSSL: вњ…")
        else:
            print(f"       вЂў CryptoCore -> OpenSSL: вќЊ")
            all_passed = False

        if openssl_to_crypto:
            print(f"       вЂў OpenSSL -> CryptoCore: вњ…")
        else:
            print(f"       вЂў OpenSSL -> CryptoCore: вќЊ")
            all_passed = False

    print("\n" + "=" * 70)

    if all_passed:
        print("рџЋ‰ Р’РЎР• РўР•РЎРўР« РЎРћР’РњР•РЎРўРРњРћРЎРўР РџР РћР™Р”Р•РќР«!")
        print("CryptoCore РїРѕР»РЅРѕСЃС‚СЊСЋ СЃРѕРІРјРµСЃС‚РёРј СЃ OpenSSL!")
        return True
    else:
        print("вљ пёЏ РќР•РљРћРўРћР Р«Р• РўР•РЎРўР« РќР• РџР РћР™Р”Р•РќР«")
        print("РџСЂРѕР±Р»РµРјС‹ СЃ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚СЊСЋ РІ РѕРґРЅРѕРј РёР»Рё РѕР±РѕРёС… РЅР°РїСЂР°РІР»РµРЅРёСЏС…")
        return False


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С„СѓРЅРєС†РёСЏ"""
    try:
        # РџСЂРѕРІРµСЂСЏРµРј OpenSSL
        has_openssl = check_openssl()

        if not has_openssl:
            print("=" * 70)
            print("OPENSSL РќР• РќРђР™Р”Р•Рќ")
            print("=" * 70)
            print("Р”Р»СЏ РїРѕР»РЅРѕРіРѕ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ СѓСЃС‚Р°РЅРѕРІРёС‚Рµ OpenSSL:")
            print("1. РЎРєР°С‡Р°Р№С‚Рµ: https://slproweb.com/download/Win64OpenSSL-3_3_2.exe")
            print("2. РЈСЃС‚Р°РЅРѕРІРёС‚Рµ СЃ РґРѕР±Р°РІР»РµРЅРёРµРј РІ PATH")
            print("3. РџРµСЂРµР·Р°РїСѓСЃС‚РёС‚Рµ PyCharm")
            print("\n[Р—РђРџРЈРЎРљРђР® Р’РќРЈРўР Р•РќРќРР• РўР•РЎРўР«]")
            return

        success = test_openssl_compatibility()
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n\nРўРµСЃС‚РёСЂРѕРІР°РЅРёРµ РїСЂРµСЂРІР°РЅРѕ РїРѕР»СЊР·РѕРІР°С‚РµР»РµРј")
        sys.exit(1)
    except Exception as e:
        print(f"\nвќЊ РќРµРѕР¶РёРґР°РЅРЅР°СЏ РѕС€РёР±РєР°: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

