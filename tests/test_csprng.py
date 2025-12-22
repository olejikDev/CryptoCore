#!/usr/bin/env python3
"""
РўРµСЃС‚С‹ РґР»СЏ РјРѕРґСѓР»СЏ CSPRNG (Sprint 3)
РўСЂРµР±РѕРІР°РЅРёСЏ TEST-1, TEST-2, TEST-4
"""

import sys
import os
import tempfile
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.csprng import generate_random_bytes, generate_random_hex


def test_key_uniqueness():
    """
    РўРµСЃС‚ СѓРЅРёРєР°Р»СЊРЅРѕСЃС‚Рё СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹С… РєР»СЋС‡РµР№
    РўСЂРµР±РѕРІР°РЅРёРµ TEST-2: 1000 СѓРЅРёРєР°Р»СЊРЅС‹С… РєР»СЋС‡РµР№
    """
    print("=== РўРµСЃС‚ СѓРЅРёРєР°Р»СЊРЅРѕСЃС‚Рё РєР»СЋС‡РµР№ (TEST-2) ===")

    key_set = set()
    num_keys = 1000

    for i in range(num_keys):
        if i % 100 == 0:
            print(f"  Р“РµРЅРµСЂР°С†РёСЏ РєР»СЋС‡Р° {i + 1}/{num_keys}...")

        # Р“РµРЅРµСЂРёСЂСѓРµРј 16-Р±Р°Р№С‚РЅС‹Р№ РєР»СЋС‡
        key = generate_random_bytes(16)
        key_hex = key.hex()

        # РџСЂРѕРІРµСЂРєР° РЅР° СѓРЅРёРєР°Р»СЊРЅРѕСЃС‚СЊ
        if key_hex in key_set:
            print(f"[-] РќР°Р№РґРµРЅ РґСѓР±Р»РёРєР°С‚ РєР»СЋС‡Р°: {key_hex}")
            return False

        key_set.add(key_hex)

    print(f"[+] РЈСЃРїРµС€РЅРѕ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРѕ {len(key_set)} СѓРЅРёРєР°Р»СЊРЅС‹С… РєР»СЋС‡РµР№")
    assert len(key_set) == num_keys, f"РћР¶РёРґР°Р»РѕСЃСЊ {num_keys} СѓРЅРёРєР°Р»СЊРЅС‹С… РєР»СЋС‡РµР№, РїРѕР»СѓС‡РµРЅРѕ {len(key_set)}"


def test_basic_distribution():
    """
    Р‘Р°Р·РѕРІС‹Р№ С‚РµСЃС‚ СЂР°СЃРїСЂРµРґРµР»РµРЅРёСЏ Р±РёС‚РѕРІ
    РўСЂРµР±РѕРІР°РЅРёРµ TEST-4: РїСЂРѕРІРµСЂРєР° СЌРЅС‚СЂРѕРїРёРё
    """
    print("=== РўРµСЃС‚ СЂР°СЃРїСЂРµРґРµР»РµРЅРёСЏ Р±РёС‚РѕРІ (TEST-4) ===")

    num_samples = 1000
    total_bits = 0
    ones_count = 0

    for i in range(num_samples):
        if i % 100 == 0:
            print(f"  РђРЅР°Р»РёР· РѕР±СЂР°Р·С†Р° {i + 1}/{num_samples}...")

        # Р“РµРЅРµСЂРёСЂСѓРµРј 16 Р±Р°Р№С‚ (128 Р±РёС‚)
        random_bytes = generate_random_bytes(16)

        # РџРѕРґСЃС‡РµС‚ РµРґРёРЅРёС‡РЅС‹С… Р±РёС‚РѕРІ
        for byte in random_bytes:
            ones_count += bin(byte).count("1")
            total_bits += 8

    # Р’С‹С‡РёСЃР»СЏРµРј РїСЂРѕС†РµРЅС‚ РµРґРёРЅРёС†
    ones_percentage = (ones_count / total_bits) * 100

    print(f"[+] Р’СЃРµРіРѕ Р±РёС‚РѕРІ: {total_bits:,}")
    print(f"[+] Р•РґРёРЅРёС‡РЅС‹С… Р±РёС‚РѕРІ: {ones_count:,} ({ones_percentage:.2f}%)")

    # РџСЂРѕРІРµСЂСЏРµРј, С‡С‚Рѕ РїСЂРѕС†РµРЅС‚ Р±Р»РёР·РѕРє Рє 50%
    # Р”Р»СЏ РёСЃС‚РёРЅРЅРѕ СЃР»СѓС‡Р°Р№РЅС‹С… РґР°РЅРЅС‹С… РѕР¶РёРґР°РµС‚СЃСЏ ~50%
    if 45 <= ones_percentage <= 55:
        print(f"[+] Р Р°СЃРїСЂРµРґРµР»РµРЅРёРµ Р±РёС‚РѕРІ СЃРѕРѕС‚РІРµС‚СЃС‚РІСѓРµС‚ РѕР¶РёРґР°РЅРёСЏРј (~50%)")
        return True
    else:
        print(f"[-] Р Р°СЃРїСЂРµРґРµР»РµРЅРёРµ Р±РёС‚РѕРІ РЅРµ СЃРѕРѕС‚РІРµС‚СЃС‚РІСѓРµС‚ РѕР¶РёРґР°РЅРёСЏРј: {ones_percentage:.2f}%")
        return False


def test_key_generation_integration():
    """
    РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Р№ С‚РµСЃС‚ СЃ РіРµРЅРµСЂР°С†РёРµР№ РєР»СЋС‡Р°
    РўСЂРµР±РѕРІР°РЅРёРµ TEST-1: С€РёС„СЂРѕРІР°РЅРёРµ Р±РµР· РєР»СЋС‡Р° -> РґРµС€РёС„СЂРѕРІР°РЅРёРµ СЃ printed key
    """
    print("=== РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Р№ С‚РµСЃС‚ (TEST-1) ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        # РЎРѕР·РґР°РµРј С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»
        plain_file = os.path.join(tmpdir, "plain.txt")
        with open(plain_file, "wb") as f:
            f.write(b"Test data for CryptoCore with auto-generated key\n" * 10)

        # РЁРёС„СЂСѓРµРј Р±РµР· РєР»СЋС‡Р°
        enc_file = os.path.join(tmpdir, "encrypted.bin")
        cmd = [
            sys.executable, "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "cbc",
            "-encrypt",
            "-input", plain_file,
            "-output", enc_file
        ]

        print("Р—Р°РїСѓСЃРє С€РёС„СЂРѕРІР°РЅРёСЏ Р±РµР· РєР»СЋС‡Р°...")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[-] РћС€РёР±РєР° С€РёС„СЂРѕРІР°РЅРёСЏ: {result.stderr}")
            return False

        # РР·РІР»РµРєР°РµРј СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹Р№ РєР»СЋС‡ РёР· РІС‹РІРѕРґР°
        output_lines = result.stdout.split('\n')
        generated_key = None
        for line in output_lines:
            if "РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅ СЃР»СѓС‡Р°Р№РЅС‹Р№ РєР»СЋС‡:" in line:
                generated_key = line.split(":")[1].strip()
                break

        if not generated_key:
            print("[-] РќРµ СѓРґР°Р»РѕСЃСЊ РЅР°Р№С‚Рё СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹Р№ РєР»СЋС‡ РІ РІС‹РІРѕРґРµ")
            print(f"Р’С‹РІРѕРґ РїСЂРѕРіСЂР°РјРјС‹: {result.stdout[:500]}...")
            return False

        print(f"[+] РљР»СЋС‡ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅ: {generated_key}")

        # Р”РµС€РёС„СЂСѓРµРј СЃ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹Рј РєР»СЋС‡РѕРј
        dec_file = os.path.join(tmpdir, "decrypted.txt")
        cmd = [
            sys.executable, "cryptocore.py",
            "-algorithm", "aes",
            "-mode", "cbc",
            "-decrypt",
            "-key", f"@{generated_key}",
            "-input", enc_file,
            "-output", dec_file
        ]

        print("Р—Р°РїСѓСЃРє РґРµС€РёС„СЂРѕРІР°РЅРёСЏ СЃ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹Рј РєР»СЋС‡РѕРј...")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[-] РћС€РёР±РєР° РґРµС€РёС„СЂРѕРІР°РЅРёСЏ: {result.stderr}")
            return False

        # РЎСЂР°РІРЅРёРІР°РµРј С„Р°Р№Р»С‹
        with open(plain_file, "rb") as f1, open(dec_file, "rb") as f2:
            original = f1.read()
            decrypted = f2.read()

            if original == decrypted:
                print("[+] РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Р№ С‚РµСЃС‚ РїСЂРѕР№РґРµРЅ СѓСЃРїРµС€РЅРѕ!")
                print(f"   РћСЂРёРіРёРЅР°Р»: {len(original)} Р±Р°Р№С‚")
                print(f"   Р Р°СЃС€РёС„СЂРѕРІР°РЅРѕ: {len(decrypted)} Р±Р°Р№С‚")
                return True
            else:
                print("[-] Р¤Р°Р№Р»С‹ РЅРµ СЃРѕРІРїР°РґР°СЋС‚ РїРѕСЃР»Рµ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ")

                # РџРѕРёСЃРє СЂР°Р·Р»РёС‡РёР№
                min_len = min(len(original), len(decrypted))
                for i in range(min_len):
                    if original[i] != decrypted[i]:
                        print(f"   РџРµСЂРІРѕРµ СЂР°Р·Р»РёС‡РёРµ РЅР° РїРѕР·РёС†РёРё {i}: 0x{original[i]:02x} vs 0x{decrypted[i]:02x}")
                        break

                if len(original) != len(decrypted):
                    print(f"   Р Р°Р·РЅР°СЏ РґР»РёРЅР°: {len(original)} vs {len(decrypted)} Р±Р°Р№С‚")

                return False


def test_nist_preparation():
    """
    РџРѕРґРіРѕС‚РѕРІРєР° С„Р°Р№Р»Р° РґР»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ NIST STS
    РўСЂРµР±РѕРІР°РЅРёРµ TEST-3: РіРµРЅРµСЂР°С†РёСЏ Р±РѕР»СЊС€РѕРіРѕ С„Р°Р№Р»Р° РґР»СЏ NIST С‚РµСЃС‚РѕРІ
    """
    print("=== РџРѕРґРіРѕС‚РѕРІРєР° С„Р°Р№Р»Р° РґР»СЏ NIST С‚РµСЃС‚РѕРІ (TEST-3) ===")

    total_size = 10_000_000  # 10 MB
    output_file = "nist_test_data.bin"

    print(f"Р“РµРЅРµСЂР°С†РёСЏ {total_size} Р±Р°Р№С‚РѕРІ СЃР»СѓС‡Р°Р№РЅС‹С… РґР°РЅРЅС‹С…...")

    with open(output_file, 'wb') as f:
        bytes_written = 0
        chunk_size = 4096

        while bytes_written < total_size:
            if bytes_written % (1024 * 1024) == 0:
                print(f"  РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅРѕ {bytes_written / 1024 / 1024:.1f} MB...")

            # Р’С‹С‡РёСЃР»СЏРµРј СЂР°Р·РјРµСЂ С‚РµРєСѓС‰РµРіРѕ С‡Р°РЅРєР°
            current_chunk_size = min(chunk_size, total_size - bytes_written)

            # Р“РµРЅРµСЂРёСЂСѓРµРј СЃР»СѓС‡Р°Р№РЅС‹Рµ РґР°РЅРЅС‹Рµ
            random_chunk = generate_random_bytes(current_chunk_size)

            # Р—Р°РїРёСЃС‹РІР°РµРј РІ С„Р°Р№Р»
            f.write(random_chunk)
            bytes_written += current_chunk_size

    print(f"[+] Р¤Р°Р№Р» {output_file} СѓСЃРїРµС€РЅРѕ СЃРѕР·РґР°РЅ ({bytes_written:,} Р±Р°Р№С‚РѕРІ)")
    print(f"\n[+] РРЅСЃС‚СЂСѓРєС†РёРё РґР»СЏ Р·Р°РїСѓСЃРєР° NIST STS:")
    print(f"1. РЎРєР°С‡Р°Р№С‚Рµ NIST Statistical Test Suite СЃ https://csrc.nist.gov/projects/random-bit-generation")
    print(f"2. Р—Р°РїСѓСЃС‚РёС‚Рµ: ./assess {total_size // 8}")
    print(f"3. РЈРєР°Р¶РёС‚Рµ РїСѓС‚СЊ Рє С„Р°Р№Р»Сѓ: {output_file}")
    print(f"4. РЎР»РµРґСѓР№С‚Рµ РёРЅСЃС‚СЂСѓРєС†РёСЏРј РїСЂРѕРіСЂР°РјРјС‹")

    return True


def test_error_handling():
    """РўРµСЃС‚ РѕР±СЂР°Р±РѕС‚РєРё РѕС€РёР±РѕРє CSPRNG"""
    print("=== РўРµСЃС‚ РѕР±СЂР°Р±РѕС‚РєРё РѕС€РёР±РѕРє ===")

    # РўРµСЃС‚ 1: РћС‚СЂРёС†Р°С‚РµР»СЊРЅРѕРµ РєРѕР»РёС‡РµСЃС‚РІРѕ Р±Р°Р№С‚РѕРІ
    try:
        generate_random_bytes(-1)
        print("[-] РќРµ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅР° РѕС€РёР±РєР° РґР»СЏ РѕС‚СЂРёС†Р°С‚РµР»СЊРЅРѕРіРѕ Р·РЅР°С‡РµРЅРёСЏ")
        return False
    except ValueError:
        print("[+] РљРѕСЂСЂРµРєС‚РЅРѕ РѕР±СЂР°Р±РѕС‚Р°РЅР° РѕС€РёР±РєР° РґР»СЏ РѕС‚СЂРёС†Р°С‚РµР»СЊРЅРѕРіРѕ Р·РЅР°С‡РµРЅРёСЏ")

    # РўРµСЃС‚ 2: РќСѓР»РµРІРѕРµ РєРѕР»РёС‡РµСЃС‚РІРѕ Р±Р°Р№С‚РѕРІ
    try:
        generate_random_bytes(0)
        print("[-] РќРµ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅР° РѕС€РёР±РєР° РґР»СЏ РЅСѓР»РµРІРѕРіРѕ Р·РЅР°С‡РµРЅРёСЏ")
        return False
    except ValueError:
        print("[+] РљРѕСЂСЂРµРєС‚РЅРѕ РѕР±СЂР°Р±РѕС‚Р°РЅР° РѕС€РёР±РєР° РґР»СЏ РЅСѓР»РµРІРѕРіРѕ Р·РЅР°С‡РµРЅРёСЏ")

    # РўРµСЃС‚ 3: РљРѕСЂСЂРµРєС‚РЅР°СЏ РіРµРЅРµСЂР°С†РёСЏ
    try:
        result = generate_random_bytes(16)
        if len(result) == 16:
            print("[+] РљРѕСЂСЂРµРєС‚РЅРѕ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРѕ 16 Р±Р°Р№С‚РѕРІ")
        else:
            print(f"[-] РќРµРїСЂР°РІРёР»СЊРЅР°СЏ РґР»РёРЅР°: {len(result)} Р±Р°Р№С‚РѕРІ")
            return False
    except Exception as e:
        print(f"[-] РќРµРѕР¶РёРґР°РЅРЅР°СЏ РѕС€РёР±РєР°: {e}")
        return False

    return True


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С„СѓРЅРєС†РёСЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ"""
    print("=" * 70)
    print("РўР•РЎРўР« CSPRNG (Sprint 3)")
    print("РўСЂРµР±РѕРІР°РЅРёСЏ TEST-1, TEST-2, TEST-3, TEST-4")
    print("=" * 70)

    tests = [
        ("РћР±СЂР°Р±РѕС‚РєР° РѕС€РёР±РѕРє", test_error_handling),
        ("РЈРЅРёРєР°Р»СЊРЅРѕСЃС‚СЊ РєР»СЋС‡РµР№ (TEST-2)", test_key_uniqueness),
        ("Р Р°СЃРїСЂРµРґРµР»РµРЅРёРµ Р±РёС‚РѕРІ (TEST-4)", test_basic_distribution),
        ("РРЅС‚РµРіСЂР°С†РёСЏ СЃ CryptoCore (TEST-1)", test_key_generation_integration),
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"[-] РћС€РёР±РєР° РїСЂРё РІС‹РїРѕР»РЅРµРЅРёРё С‚РµСЃС‚Р°: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False

    # РћРїС†РёРѕРЅР°Р»СЊРЅРѕ: РїРѕРґРіРѕС‚РѕРІРєР° NIST С‚РµСЃС‚РѕРІ
    print("\n--- РџРѕРґРіРѕС‚РѕРІРєР° NIST С‚РµСЃС‚РѕРІ (TEST-3, РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ) ---")
    try:
        test_nist_preparation()
        print("[+] Р¤Р°Р№Р» РґР»СЏ NIST С‚РµСЃС‚РѕРІ РїРѕРґРіРѕС‚РѕРІР»РµРЅ")
    except Exception as e:
        print(f"[-] РћС€РёР±РєР° РїСЂРё РїРѕРґРіРѕС‚РѕРІРєРµ NIST С‚РµСЃС‚РѕРІ: {e}")
        print("  (Р­С‚Рѕ РЅРµ РІР»РёСЏРµС‚ РЅР° РѕР±С‰РёР№ СЂРµР·СѓР»СЊС‚Р°С‚ С‚РµСЃС‚РѕРІ)")

    # РС‚РѕРіРё
    print("\n" + "=" * 70)
    print("РРўРћР“Р РўР•РЎРўРР РћР’РђРќРРЇ CSPRNG")
    print("=" * 70)

    all_passed = True
    for test_name, passed in results.items():
        status = "вњ… РЈРЎРџР•РҐ" if passed else "вќЊ РћРЁРР‘РљРђ"
        print(f"{test_name:40} : {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n[+] Р’РЎР• РўР•РЎРўР« SPRINT 3 РџР РћР™Р”Р•РќР«!")
        print("    вЂў TEST-1: Key Generation Test вњ“")
        print("    вЂў TEST-2: Uniqueness Test вњ“")
        print("    вЂў TEST-4: Basic Distribution Test вњ“")
        print("    вЂў TEST-3: NIST С‚РµСЃС‚С‹ РїРѕРґРіРѕС‚РѕРІР»РµРЅС‹ вњ“")
        sys.exit(0)
    else:
        print("\n[-] РќР•РљРћРўРћР Р«Р• РўР•РЎРўР« РќР• РџР РћР™Р”Р•РќР«")
        sys.exit(1)


if __name__ == "__main__":
    main()

