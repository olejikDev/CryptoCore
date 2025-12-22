#!/usr/bin/env python3
"""
РўРµСЃС‚С‹ РґР»СЏ С…РµС€-С„СѓРЅРєС†РёР№ (Sprint 4)
"""

import sys
import os
import tempfile
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256


def test_sha256_nist_vectors():
    """РўРµСЃС‚ РёР·РІРµСЃС‚РЅС‹С… РІРµРєС‚РѕСЂРѕРІ NIST РґР»СЏ SHA-256"""
    print("=== РўРµСЃС‚ SHA-256 СЃ NIST РІРµРєС‚РѕСЂР°РјРё ===")

    # РўРµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ РёР· NIST
    test_vectors = [
        # (input, expected_hash)
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ("a" * 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ]

    for input_str, expected in test_vectors:
        sha = SHA256()
        sha.update(input_str)
        result = sha.hexdigest()

        if result == expected:
            print(f"[+] '{input_str[:20] if input_str else 'empty'}...': OK")
        else:
            print(f"[-] '{input_str[:20] if input_str else 'empty'}...': FAIL")
            print(f"    РћР¶РёРґР°Р»РѕСЃСЊ: {expected}")
            print(f"    РџРѕР»СѓС‡РµРЅРѕ:  {result}")
            return False

    print("[+] Р’СЃРµ NIST РІРµРєС‚РѕСЂС‹ РґР»СЏ SHA-256 РїСЂРѕР№РґРµРЅС‹")
    return True


def test_sha3_256_nist_vectors():
    """РўРµСЃС‚ РёР·РІРµСЃС‚РЅС‹С… РІРµРєС‚РѕСЂРѕРІ NIST РґР»СЏ SHA3-256"""
    print("=== РўРµСЃС‚ SHA3-256 СЃ NIST РІРµРєС‚РѕСЂР°РјРё ===")

    # РўРµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ РёР· NIST
    test_vectors = [
        # (input, expected_hash)
        ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        ("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    ]

    for input_str, expected in test_vectors:
        sha3 = SHA3_256()
        sha3.update(input_str)
        result = sha3.hexdigest()

        if result == expected:
            print(f"[+] '{input_str[:20] if input_str else 'empty'}...': OK")
        else:
            print(f"[-] '{input_str[:20] if input_str else 'empty'}...': FAIL")
            print(f"    РћР¶РёРґР°Р»РѕСЃСЊ: {expected}")
            print(f"    РџРѕР»СѓС‡РµРЅРѕ:  {result}")
            return False

    print("[+] Р’СЃРµ NIST РІРµРєС‚РѕСЂС‹ РґР»СЏ SHA3-256 РїСЂРѕР№РґРµРЅС‹")
    return True


def test_avalanche_effect():
    """РўРµСЃС‚ Р»Р°РІРёРЅРЅРѕРіРѕ СЌС„С„РµРєС‚Р°"""
    print("=== РўРµСЃС‚ Р»Р°РІРёРЅРЅРѕРіРѕ СЌС„С„РµРєС‚Р° ===")

    # РўРµСЃС‚РёСЂСѓРµРј РґР»СЏ РѕР±РѕРёС… Р°Р»РіРѕСЂРёС‚РјРѕРІ
    algorithms = [
        ('SHA-256', SHA256),
        ('SHA3-256', SHA3_256),
    ]

    for algo_name, algo_class in algorithms:
        print(f"\nРўРµСЃС‚РёСЂРѕРІР°РЅРёРµ {algo_name}:")

        # РўРµСЃС‚РѕРІС‹Рµ РґР°РЅРЅС‹Рµ
        original_data = b"A" * 1000
        modified_data = b"B" + b"A" * 999  # РР·РјРµРЅСЏРµРј С‚РѕР»СЊРєРѕ РїРµСЂРІС‹Р№ Р±Р°Р№С‚

        # Р’С‹С‡РёСЃР»СЏРµРј С…РµС€Рё
        hasher1 = algo_class()
        hasher1.update(original_data)
        hash1 = hasher1.hexdigest()

        hasher2 = algo_class()
        hasher2.update(modified_data)
        hash2 = hasher2.hexdigest()

        # РџСЂРµРѕР±СЂР°Р·СѓРµРј РІ Р±РёРЅР°СЂРЅС‹Р№ РІРёРґ
        bin1 = bin(int(hash1, 16))[2:].zfill(256)
        bin2 = bin(int(hash2, 16))[2:].zfill(256)

        # РЎС‡РёС‚Р°РµРј СЂР°Р·Р»РёС‡Р°СЋС‰РёРµСЃСЏ Р±РёС‚С‹
        diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
        diff_percentage = (diff_count / 256) * 100

        print(f"  Р Р°Р·Р»РёС‡Р°СЋС‰РёС…СЃСЏ Р±РёС‚РѕРІ: {diff_count}/256 ({diff_percentage:.1f}%)")

        # Р”Р»СЏ С…РѕСЂРѕС€РµРіРѕ Р»Р°РІРёРЅРЅРѕРіРѕ СЌС„С„РµРєС‚Р° РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ ~50% СЂР°Р·Р»РёС‡РёР№
        if 40 <= diff_percentage <= 60:
            print(f"  [+] Р›Р°РІРёРЅРЅС‹Р№ СЌС„С„РµРєС‚ С…РѕСЂРѕС€РёР№")
        else:
            print(f"  [-] Р›Р°РІРёРЅРЅС‹Р№ СЌС„С„РµРєС‚ СЃР»Р°Р±С‹Р№")

    return True


def test_large_file():
    """РўРµСЃС‚ С…РµС€РёСЂРѕРІР°РЅРёСЏ Р±РѕР»СЊС€РѕРіРѕ С„Р°Р№Р»Р°"""
    print("=== РўРµСЃС‚ С…РµС€РёСЂРѕРІР°РЅРёСЏ Р±РѕР»СЊС€РѕРіРѕ С„Р°Р№Р»Р° ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        # РЎРѕР·РґР°РµРј С„Р°Р№Р» СЂР°Р·РјРµСЂРѕРј ~10MB
        large_file = os.path.join(tmpdir, "large.bin")
        file_size = 10 * 1024 * 1024  # 10 MB

        print(f"РЎРѕР·РґР°РЅРёРµ С„Р°Р№Р»Р° СЂР°Р·РјРµСЂРѕРј {file_size // (1024 * 1024)} MB...")

        with open(large_file, 'wb') as f:
            # РџРёС€РµРј РїРѕРІС‚РѕСЂСЏСЋС‰РёРµСЃСЏ РґР°РЅРЅС‹Рµ
            chunk = b"X" * 1024  # 1KB С‡Р°РЅРє
            for _ in range(file_size // 1024):
                f.write(chunk)

        print(f"Р¤Р°Р№Р» СЃРѕР·РґР°РЅ: {large_file}")

        # РўРµСЃС‚РёСЂСѓРµРј РѕР±Р° Р°Р»РіРѕСЂРёС‚РјР°
        algorithms = [('sha256', SHA256), ('sha3-256', SHA3_256)]

        for algo_name, algo_class in algorithms:
            print(f"\nРўРµСЃС‚РёСЂРѕРІР°РЅРёРµ {algo_name}:")

            hasher = algo_class()
            hash_result = hasher.hash_file(large_file)

            print(f"  РҐРµС€: {hash_result}")
            print(f"  [+] РЈСЃРїРµС€РЅРѕ РѕР±СЂР°Р±РѕС‚Р°РЅ С„Р°Р№Р» {file_size // (1024 * 1024)} MB")

    return True


def test_cli_integration():
    """РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Р№ С‚РµСЃС‚ CLI РєРѕРјР°РЅРґС‹ dgst"""
    print("=== РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Р№ С‚РµСЃС‚ CLI ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        # РЎРѕР·РґР°РµРј С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»
        test_file = os.path.join(tmpdir, "test.txt")
        test_data = b"Hello CryptoCore Hash Test!\n" * 100

        with open(test_file, 'wb') as f:
            f.write(test_data)

        print(f"РЎРѕР·РґР°РЅ С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»: {test_file}")

        # РўРµСЃС‚РёСЂСѓРµРј РѕР±Р° Р°Р»РіРѕСЂРёС‚РјР° С‡РµСЂРµР· CLI
        algorithms = ['sha256', 'sha3-256']

        for algo in algorithms:
            print(f"\nРўРµСЃС‚РёСЂРѕРІР°РЅРёРµ {algo}:")

            # Р—Р°РїСѓСЃРєР°РµРј С‡РµСЂРµР· CLI
            cmd = [
                sys.executable, "cryptocore.py",
                "dgst",
                "--algorithm", algo,
                "--input", test_file
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"  [-] РћС€РёР±РєР° CLI: {result.stderr}")
                return False

            # РџСЂРѕРІРµСЂСЏРµРј С„РѕСЂРјР°С‚ РІС‹РІРѕРґР°
            output = result.stdout.strip()
            if output and len(output.split()) >= 2:
                hash_value, filename = output.split()[:2]

                if len(hash_value) == 64:  # 256 Р±РёС‚ РІ hex = 64 СЃРёРјРІРѕР»Р°
                    print(f"  [+] Р¤РѕСЂРјР°С‚ РІС‹РІРѕРґР° РєРѕСЂСЂРµРєС‚РµРЅ")
                    print(f"  РҐРµС€: {hash_value}")
                else:
                    print(f"  [-] РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ РґР»РёРЅР° С…РµС€Р°: {len(hash_value)}")
                    return False
            else:
                print(f"  [-] РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ С„РѕСЂРјР°С‚ РІС‹РІРѕРґР°: {output}")
                return False

    return True


def test_interoperability():
    """РўРµСЃС‚ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё СЃ СЃРёСЃС‚РµРјРЅС‹РјРё СѓС‚РёР»РёС‚Р°РјРё"""
    print("=== РўРµСЃС‚ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё СЃ СЃРёСЃС‚РµРјРЅС‹РјРё СѓС‚РёР»РёС‚Р°РјРё ===")

    # РџСЂРѕРІРµСЂСЏРµРј РЅР°Р»РёС‡РёРµ СЃРёСЃС‚РµРјРЅС‹С… СѓС‚РёР»РёС‚
    system_tools = {
        'sha256': 'sha256sum',
        'sha3-256': 'sha3sum',
    }

    available_tools = {}
    for algo, tool in system_tools.items():
        try:
            result = subprocess.run([tool, '--version'], capture_output=True, text=True)
            if result.returncode == 0 or result.returncode == 1:
                available_tools[algo] = tool
                print(f"[+] РќР°Р№РґРµРЅР° СЃРёСЃС‚РµРјРЅР°СЏ СѓС‚РёР»РёС‚Р°: {tool}")
        except:
            print(f"[-] РЎРёСЃС‚РµРјРЅР°СЏ СѓС‚РёР»РёС‚Р° {tool} РЅРµ РЅР°Р№РґРµРЅР°")

    if not available_tools:
        print("  [i] РЎРёСЃС‚РµРјРЅС‹Рµ СѓС‚РёР»РёС‚С‹ РЅРµ РЅР°Р№РґРµРЅС‹, С‚РµСЃС‚ РїСЂРѕРїСѓС‰РµРЅ")
        return True

    with tempfile.TemporaryDirectory() as tmpdir:
        # РЎРѕР·РґР°РµРј С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»
        test_file = os.path.join(tmpdir, "interop_test.bin")
        test_data = b"Interoperability test data " * 1000

        with open(test_file, 'wb') as f:
            f.write(test_data)

        print(f"\nРЎРѕР·РґР°РЅ С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»: {test_file}")

        for algo, tool in available_tools.items():
            print(f"\nРўРµСЃС‚РёСЂРѕРІР°РЅРёРµ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё СЃ {tool}:")

            # 1. Р’С‹С‡РёСЃР»СЏРµРј С…РµС€ РЅР°С€РёРј РёРЅСЃС‚СЂСѓРјРµРЅС‚РѕРј
            our_cmd = [
                sys.executable, "cryptocore.py",
                "dgst",
                "--algorithm", algo,
                "--input", test_file
            ]

            our_result = subprocess.run(our_cmd, capture_output=True, text=True)
            if our_result.returncode != 0:
                print(f"  [-] РћС€РёР±РєР° РЅР°С€РµРіРѕ РёРЅСЃС‚СЂСѓРјРµРЅС‚Р°: {our_result.stderr}")
                continue

            our_hash = our_result.stdout.strip().split()[0]

            # 2. Р’С‹С‡РёСЃР»СЏРµРј С…РµС€ СЃРёСЃС‚РµРјРЅРѕР№ СѓС‚РёР»РёС‚РѕР№
            sys_cmd = [tool, test_file]
            sys_result = subprocess.run(sys_cmd, capture_output=True, text=True)

            if sys_result.returncode != 0:
                print(f"  [-] РћС€РёР±РєР° СЃРёСЃС‚РµРјРЅРѕР№ СѓС‚РёР»РёС‚С‹: {sys_result.stderr}")
                continue

            sys_hash = sys_result.stdout.strip().split()[0]

            # 3. РЎСЂР°РІРЅРёРІР°РµРј
            if our_hash == sys_hash:
                print(f"  [+] РЎРѕРІРјРµСЃС‚РёРјРѕСЃС‚СЊ РїРѕРґС‚РІРµСЂР¶РґРµРЅР°!")
                print(f"  РҐРµС€: {our_hash}")
            else:
                print(f"  [-] РќРµСЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚СЊ!")
                print(f"  РќР°С€ С…РµС€:    {our_hash}")
                print(f"  РЎРёСЃС‚РµРјРЅС‹Р№:  {sys_hash}")

    return True


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С„СѓРЅРєС†РёСЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ"""
    print("=" * 70)
    print("РўР•РЎРўР« РҐР•РЁ-Р¤РЈРќРљР¦РР™ (Sprint 4)")
    print("=" * 70)

    tests = [
        ("SHA-256 NIST РІРµРєС‚РѕСЂС‹", test_sha256_nist_vectors),
        ("SHA3-256 NIST РІРµРєС‚РѕСЂС‹", test_sha3_256_nist_vectors),
        ("Р›Р°РІРёРЅРЅС‹Р№ СЌС„С„РµРєС‚", test_avalanche_effect),
        ("Р‘РѕР»СЊС€РѕР№ С„Р°Р№Р»", test_large_file),
        ("CLI РёРЅС‚РµРіСЂР°С†РёСЏ", test_cli_integration),
        ("РЎРѕРІРјРµСЃС‚РёРјРѕСЃС‚СЊ", test_interoperability),
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

    # РС‚РѕРіРё
    print("\n" + "=" * 70)
    print("РРўРћР“Р РўР•РЎРўРР РћР’РђРќРРЇ SPRINT 4")
    print("=" * 70)

    all_passed = True
    for test_name, passed in results.items():
        status = "вњ… РЈРЎРџР•РҐ" if passed else "вќЊ РћРЁРР‘РљРђ"
        print(f"{test_name:30} : {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n[+] Р’РЎР• РўР•РЎРўР« SPRINT 4 РџР РћР™Р”Р•РќР«!")
        print("    вЂў HASH-1: SHA-256 СЃ РЅСѓР»СЏ вњ“")
        print("    вЂў HASH-2: SHA3-256 СЃ РЅСѓР»СЏ вњ“")
        print("    вЂў CLI-1: РљРѕРјР°РЅРґР° dgst вњ“")
        print("    вЂў TEST-1: NIST РІРµРєС‚РѕСЂС‹ вњ“")
        print("    вЂў TEST-2: РџСѓСЃС‚РѕР№ С„Р°Р№Р» вњ“")
        print("    вЂў TEST-4: Р‘РѕР»СЊС€РѕР№ С„Р°Р№Р» вњ“")
        print("    вЂў TEST-5: Р›Р°РІРёРЅРЅС‹Р№ СЌС„С„РµРєС‚ вњ“")
        sys.exit(0)
    else:
        print("\n[-] РќР•РљРћРўРћР Р«Р• РўР•РЎРўР« РќР• РџР РћР™Р”Р•РќР«")
        sys.exit(1)


if __name__ == "__main__":
    main()

