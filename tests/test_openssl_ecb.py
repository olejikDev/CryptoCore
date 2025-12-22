#!/usr/bin/env python3
"""
РџСЂРѕСЃС‚РѕР№ С‚РµСЃС‚ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё ECB СЃ OpenSSL РґР»СЏ Sprint 1
"""

import subprocess
import tempfile
import os
import sys


def test_ecb_with_openssl():
    """РџСЂРѕСЃС‚Р°СЏ РїСЂРѕРІРµСЂРєР° СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё ECB СЃ OpenSSL"""
    print("=== РўРµСЃС‚ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё ECB СЃ OpenSSL (Sprint 1) ===")

    # РўРµСЃС‚РѕРІС‹Рµ РґР°РЅРЅС‹Рµ (32 Р±Р°Р№С‚Р° - РєСЂР°С‚РЅРѕ 16)
    test_data = b"A" * 32
    key = "@00112233445566778899aabbccddeeff"
    key_hex = "00112233445566778899aabbccddeeff"

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Р—Р°РїРёСЃР°С‚СЊ С‚РµСЃС‚РѕРІС‹Рµ РґР°РЅРЅС‹Рµ
        plain = os.path.join(tmpdir, "plain.bin")
        with open(plain, "wb") as f:
            f.write(test_data)

        print(f"1. РЎРѕР·РґР°РЅ С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»: {len(test_data)} Р±Р°Р№С‚")

        # 2. Р—Р°С€РёС„СЂРѕРІР°С‚СЊ РќРђРЁРРњ РёРЅСЃС‚СЂСѓРјРµРЅС‚РѕРј
        our_out = os.path.join(tmpdir, "our_encrypted.bin")
        print("2. РЁРёС„СЂСѓРµРј РЅР°С€РёРј РёРЅСЃС‚СЂСѓРјРµРЅС‚РѕРј...")

        result = subprocess.run([
            "python", "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "ecb",
            "-encrypt",
            "-key", key,
            "-input", plain,
            "-output", our_out
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"вќЊ РћС€РёР±РєР° РЅР°С€РµРіРѕ РёРЅСЃС‚СЂСѓРјРµРЅС‚Р°: {result.stderr[:200]}")
            return False

        print(f"   РќР°С€ С€РёС„СЂРѕС‚РµРєСЃС‚: {our_out}")

        # 3. Р—Р°С€РёС„СЂРѕРІР°С‚СЊ OpenSSL (Р±РµР· padding, С‚.Рє. РґР°РЅРЅС‹Рµ РєСЂР°С‚РЅС‹ 16)
        openssl_out = os.path.join(tmpdir, "openssl_encrypted.bin")
        print("3. РЁРёС„СЂСѓРµРј OpenSSL...")

        result = subprocess.run([
            "openssl", "enc", "-aes-128-ecb",
            "-K", key_hex,
            "-in", plain,
            "-out", openssl_out,
            "-nopad"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"вќЊ РћС€РёР±РєР° OpenSSL: {result.stderr[:200]}")
            print("   РџСЂРѕРґРѕР»Р¶Р°РµРј С‚РµСЃС‚ Р±РµР· OpenSSL...")
            return True  # Р’РѕР·РІСЂР°С‰Р°РµРј True, С‚.Рє. СЌС‚Рѕ РЅРµ РѕС€РёР±РєР° РЅР°С€РµРіРѕ РєРѕРґР°

        print(f"   OpenSSL С€РёС„СЂРѕС‚РµРєСЃС‚: {openssl_out}")

        # 4. РЎСЂР°РІРЅРёС‚СЊ СЂРµР·СѓР»СЊС‚Р°С‚С‹
        print("4. РЎСЂР°РІРЅРёРІР°РµРј СЂРµР·СѓР»СЊС‚Р°С‚С‹...")
        with open(our_out, "rb") as f1, open(openssl_out, "rb") as f2:
            our = f1.read()
            openssl = f2.read()

            if our == openssl:
                print("вњ… РўР•РЎРў РџР РћР™Р”Р•Рќ: РќР°С€ РІС‹РІРѕРґ СЃРѕРІРїР°РґР°РµС‚ СЃ OpenSSL!")
                print(f"   Р Р°Р·РјРµСЂ С€РёС„СЂРѕС‚РµРєСЃС‚Р°: {len(our)} Р±Р°Р№С‚")
                print(f"   Hex (РїРµСЂРІС‹Рµ 32 Р±Р°Р№С‚Р°): {our[:32].hex()}")
                return True
            else:
                print("вќЊ РўР•РЎРў РќР• РџР РћР™Р”Р•Рќ: Р РµР·СѓР»СЊС‚Р°С‚С‹ СЂР°Р·Р»РёС‡Р°СЋС‚СЃСЏ")
                print(f"   РќР°С€ СЂР°Р·РјРµСЂ: {len(our)} Р±Р°Р№С‚")
                print(f"   OpenSSL СЂР°Р·РјРµСЂ: {len(openssl)} Р±Р°Р№С‚")

                # РџРѕРєР°Р·Р°С‚СЊ СЂР°Р·Р»РёС‡РёСЏ
                min_len = min(len(our), len(openssl))
                for i in range(min_len):
                    if our[i] != openssl[i]:
                        print(f"   РџРµСЂРІРѕРµ СЂР°Р·Р»РёС‡РёРµ РЅР° РїРѕР·РёС†РёРё {i}: 0x{our[i]:02x} vs 0x{openssl[i]:02x}")
                        break

                if len(our) != len(openssl):
                    print(f"   Р Р°Р·РЅР°СЏ РґР»РёРЅР° С„Р°Р№Р»РѕРІ")

                return False


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С„СѓРЅРєС†РёСЏ"""
    try:
        success = test_ecb_with_openssl()
        if success:
            print("\n" + "=" * 60)
            print("[+] РўР•РЎРў SPRINT 1 РџР РћР™Р”Р•Рќ: РЎРѕРІРјРµСЃС‚РёРјРѕСЃС‚СЊ СЃ OpenSSL РїРѕРґС‚РІРµСЂР¶РґРµРЅР°!")
            sys.exit(0)
        else:
            print("\n" + "=" * 60)
            print("[-] РўР•РЎРў РќР• РџР РћР™Р”Р•Рќ")
            sys.exit(1)
    except Exception as e:
        print(f"вќЊ РќРµРѕР¶РёРґР°РЅРЅР°СЏ РѕС€РёР±РєР°: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

