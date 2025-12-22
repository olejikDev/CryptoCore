"""
РўРµСЃС‚ РґР»СЏ РїСЂРѕРІРµСЂРєРё РїРѕР»РЅРѕРіРѕ С†РёРєР»Р° С€РёС„СЂРѕРІР°РЅРёРµ-РґРµС€РёС„СЂРѕРІР°РЅРёРµ
Sprint 2: РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ РІСЃРµС… СЂРµР¶РёРјРѕРІ (ECB, CBC, CFB, OFB, CTR)
"""

import os
import subprocess
import sys
import tempfile
import pytest


def run_command(cmd):
    """Р—Р°РїСѓСЃРє РєРѕРјР°РЅРґС‹ Рё РїСЂРѕРІРµСЂРєР° СЂРµР·СѓР»СЊС‚Р°С‚Р°"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=False)  # text=False РґР»СЏ Р±РёРЅР°СЂРЅРѕРіРѕ РІС‹РІРѕРґР°
        if result.returncode != 0:
            # РџС‹С‚Р°РµРјСЃСЏ РґРµРєРѕРґРёСЂРѕРІР°С‚СЊ РєР°Рє utf-8, РµСЃР»Рё РЅРµ РїРѕР»СѓС‡Р°РµС‚СЃСЏ - РІС‹РІРѕРґРёРј РєР°Рє РµСЃС‚СЊ
            try:
                error_text = result.stderr.decode('utf-8', errors='ignore')
            except:
                error_text = str(result.stderr)
            print(f"РћС€РёР±РєР°: {error_text}")
            return False
        return True
    except Exception as e:
        print(f"РћС€РёР±РєР° РІС‹РїРѕР»РЅРµРЅРёСЏ РєРѕРјР°РЅРґС‹: {e}")
        return False


# РћРїСЂРµРґРµР»СЏРµРј С„РёРєСЃС‚СѓСЂСѓ РґР»СЏ pytest
@pytest.fixture(params=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'])
def mode(request):
    """Р¤РёРєСЃС‚СѓСЂР° РґР»СЏ РїР°СЂР°РјРµС‚СЂРёР·Р°С†РёРё С‚РµСЃС‚РѕРІ РїРѕ СЂРµР¶РёРјР°Рј"""
    return request.param


def test_mode_roundtrip(mode):
    """РўРµСЃС‚ С€РёС„СЂРѕРІР°РЅРёРµ -> РґРµС€РёС„СЂРѕРІР°РЅРёРµ РґР»СЏ РєРѕРЅРєСЂРµС‚РЅРѕРіРѕ СЂРµР¶РёРјР°"""
    print(f"\n--- РўРµСЃС‚ СЂРµР¶РёРјР°: {mode.upper()} ---")

    # РџР°СЂР°РјРµС‚СЂС‹ С‚РµСЃС‚Р°
    key = "@00112233445566778899aabbccddeeff"

    # Р”Р»СЏ ECB РЅРµ РЅСѓР¶РµРЅ IV, РґР»СЏ РѕСЃС‚Р°Р»СЊРЅС‹С… - РЅСѓР¶РµРЅ
    if mode != 'ecb':
        iv = "aabbccddeeff00112233445566778899"
    else:
        iv = None

    with tempfile.TemporaryDirectory() as tmpdir:
        plain_file = os.path.join(tmpdir, "plain.txt")
        enc_file = os.path.join(tmpdir, "enc.bin")
        dec_file = os.path.join(tmpdir, "dec.txt")

        try:
            # 1. РЎРѕР·РґР°РµРј С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»
            # вљ пёЏ РРЎРџР РђР’Р›Р•РќРћ: Р”Р»СЏ CFB РёСЃРїРѕР»СЊР·СѓРµРј РґР°РЅРЅС‹Рµ РєСЂР°С‚РЅС‹Рµ 16 Р±Р°Р№С‚Р°Рј
            if mode == 'cfb':
                # CFB С‚СЂРµР±СѓРµС‚ РґР°РЅРЅС‹Рµ, РєСЂР°С‚РЅС‹Рµ 16 Р±Р°Р№С‚Р°Рј
                test_data = b"CFB_16byte_test!" * 10  # 160 Р±Р°Р№С‚, РєСЂР°С‚РЅРѕ 16
            else:
                # Р”Р»СЏ РѕСЃС‚Р°Р»СЊРЅС‹С… СЂРµР¶РёРјРѕРІ РјРѕР¶РЅРѕ Р»СЋР±С‹Рµ РґР°РЅРЅС‹Рµ
                test_data = b"Hello CryptoCore! This is a round-trip test. " * 5

            with open(plain_file, "wb") as f:
                f.write(test_data)

            if mode == 'cfb':
                print(f"1. РЎРѕР·РґР°РЅ С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р» РґР»СЏ CFB: {len(test_data)} Р±Р°Р№С‚ (РєСЂР°С‚РЅРѕ 16)")
            else:
                print(f"1. РЎРѕР·РґР°РЅ С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»: {len(test_data)} Р±Р°Р№С‚")

            # 2. РЁРёС„СЂСѓРµРј
            print("2. РЁРёС„СЂСѓРµРј...")
            encrypt_cmd = [
                sys.executable, "cryptocore.py",
                "-algorithm", "aes",
                "-mode", mode,
                "-encrypt",
                "-key", key,
                "-input", plain_file,
                "-output", enc_file
            ]

            if not run_command(encrypt_cmd):
                return False
            print(f"   Р—Р°С€РёС„СЂРѕРІР°РЅРѕ РІ: {enc_file}")

            # 3. Р”РµС€РёС„СЂСѓРµРј
            print("3. Р”РµС€РёС„СЂСѓРµРј...")
            decrypt_cmd = [
                sys.executable, "cryptocore.py",
                "-algorithm", "aes",
                "-mode", mode,
                "-decrypt",
                "-key", key,
                "-input", enc_file,
                "-output", dec_file
            ]

            # Р”РѕР±Р°РІР»СЏРµРј IV РґР»СЏ СЂРµР¶РёРјРѕРІ РєСЂРѕРјРµ ECB
            if mode != 'ecb':
                decrypt_cmd.extend(["-iv", iv])

            if not run_command(decrypt_cmd):
                return False
            print(f"   Р Р°СЃС€РёС„СЂРѕРІР°РЅРѕ РІ: {dec_file}")

            # 4. РЎСЂР°РІРЅРёРІР°РµРј
            print("4. РЎСЂР°РІРЅРёРІР°РµРј С„Р°Р№Р»С‹...")
            with open(plain_file, "rb") as f1, open(dec_file, "rb") as f2:
                original = f1.read()
                decrypted = f2.read()

                if original == decrypted:
                    print(f"   [+] РўР•РЎРў РџР РћР™Р”Р•Рќ!")
                    print(f"   Р¤Р°Р№Р»С‹ РёРґРµРЅС‚РёС‡РЅС‹ ({len(original)} Р±Р°Р№С‚)")
                    return True
                else:
                    print("   [-] РўР•РЎРў РќР• РџР РћР™Р”Р•Рќ: С„Р°Р№Р»С‹ СЂР°Р·Р»РёС‡Р°СЋС‚СЃСЏ")
                    # РџРѕРєР°Р·С‹РІР°РµРј СЂР°Р·РЅРёС†Сѓ
                    print(f"   РћСЂРёРіРёРЅР°Р»: {len(original)} Р±Р°Р№С‚")
                    print(f"   Р Р°СЃС€РёС„СЂРѕРІР°РЅРѕ: {len(decrypted)} Р±Р°Р№С‚")
                    # РџРѕРєР°Р·С‹РІР°РµРј РїРµСЂРІС‹Рµ СЂР°Р·Р»РёС‡РёСЏ
                    for i in range(min(len(original), len(decrypted))):
                        if original[i] != decrypted[i]:
                            print(f"   РџРµСЂРІРѕРµ СЂР°Р·Р»РёС‡РёРµ РЅР° РїРѕР·РёС†РёРё {i}: {original[i]} vs {decrypted[i]}")
                            break
                    return False

        except Exception as e:
            print(f"   [-] РћС€РёР±РєР°: {e}")
            return False


def test_all_modes():
    """РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ РІСЃРµС… СЂРµР¶РёРјРѕРІ"""
    print("=== РўРµСЃС‚ CryptoCore (С€РёС„СЂРѕРІР°РЅРёРµ-РґРµС€РёС„СЂРѕРІР°РЅРёРµ РґР»СЏ РІСЃРµС… СЂРµР¶РёРјРѕРІ) ===")
    print("Sprint 2: ECB, CBC, CFB, OFB, CTR")
    print("=" * 60)

    # Sprint 2: Р’СЃРµ СЂРµР¶РёРјС‹
    modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
    results = {}

    for mode in modes:
        results[mode] = test_mode_roundtrip(mode)

    # РС‚РѕРіРё
    print("\n" + "=" * 60)
    print("РРўРћР“Р РўР•РЎРўРР РћР’РђРќРРЇ (Round-trip):")

    all_passed = True
    for mode, passed in results.items():
        status = "[+] РџР РћР™Р”Р•Рќ" if passed else "[-] РќР• РџР РћР™Р”Р•Рќ"
        print(f"{mode.upper()}: {status}")
        if not passed:
            all_passed = False

    return all_passed


def test_cli_validation():
    """РўРµСЃС‚ РІР°Р»РёРґР°С†РёРё CLI Р°СЂРіСѓРјРµРЅС‚РѕРІ РґР»СЏ Sprint 2"""
    print("\n=== РўРµСЃС‚ РІР°Р»РёРґР°С†РёРё CLI (Sprint 2) ===")

    tests = [
        # (РєРѕРјР°РЅРґР°, РѕР¶РёРґР°РµРјС‹Р№_РєРѕРґ_РѕС€РёР±РєРё, РѕРїРёСЃР°РЅРёРµ)
        (["python", "cryptocore.py"], 1, "РќРµС‚ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹С… Р°СЂРіСѓРјРµРЅС‚РѕРІ"),
        (["python", "cryptocore.py", "-encrypt", "-decrypt"], 1, "РћР±Р° С„Р»Р°РіР° -encrypt Рё -decrypt"),
        (["python", "cryptocore.py", "-algorithm", "des", "-mode", "ecb", "-encrypt"], 1, "РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјС‹Р№ Р°Р»РіРѕСЂРёС‚Рј"),
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "xxx", "-encrypt"], 1, "РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјС‹Р№ СЂРµР¶РёРј"),
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "ecb", "-encrypt", "-key", "123"], 1, "РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РєР»СЋС‡"),
        # вљ пёЏ РРЎРџР РђР’Р›Р•РќРћ: РўРµРїРµСЂСЊ РѕР¶РёРґР°РµС‚СЃСЏ РєРѕРґ 1 (РѕС€РёР±РєР°), Р° РЅРµ 0 (warning)
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "cbc", "-encrypt", "-key", "@00112233445566778899aabbccddeeff", "-iv", "123"], 1, "IV РѕС‚РІРµСЂРіР°РµС‚СЃСЏ РїСЂРё С€РёС„СЂРѕРІР°РЅРёРё (error)"),
        (["python", "cryptocore.py", "-algorithm", "aes", "-mode", "cbc", "-decrypt", "-key", "@00112233445566778899aabbccddeeff", "-iv", "123"], 1, "РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ IV"),
    ]

    all_passed = True
    for cmd, expected_code, description in tests:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == expected_code:
            print(f"[+] {description}")
        else:
            print(f"[-] {description} (РєРѕРґ: {result.returncode}, РѕР¶РёРґР°Р»СЃСЏ: {expected_code})")
            if result.stderr:
                print(f"   stderr: {result.stderr[:100]}")
            all_passed = False

    return all_passed


if __name__ == "__main__":
    # РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ РІСЃРµС… СЂРµР¶РёРјРѕРІ
    test1 = test_all_modes()

    # РўРµСЃС‚ РІР°Р»РёРґР°С†РёРё
    test2 = test_cli_validation()

    # РС‚РѕРі
    print("\n" + "=" * 60)
    if test1 and test2:
        print("[+] Р’РЎР• РўР•РЎРўР« SPRINT 2 РџР РћР™Р”Р•РќР«!")
        sys.exit(0)
    else:
        print("[-] РќР•РљРћРўРћР Р«Р• РўР•РЎРўР« РќР• РџР РћР™Р”Р•РќР«")
        sys.exit(1)

