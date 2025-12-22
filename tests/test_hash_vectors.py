#!/usr/bin/env python3
"""
Known-Answer С‚РµСЃС‚С‹ РґР»СЏ С…РµС€-С„СѓРЅРєС†РёР№
TEST-1: Р’СЃРµ NIST С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256


def test_sha256_extended_vectors():
    """Р Р°СЃС€РёСЂРµРЅРЅС‹Рµ С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ РґР»СЏ SHA-256"""
    print("=== Р Р°СЃС€РёСЂРµРЅРЅС‹Рµ С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ SHA-256 ===")

    # Р‘РѕР»РµРµ РїРѕР»РЅС‹Р№ РЅР°Р±РѕСЂ С‚РµСЃС‚РѕРІС‹С… РІРµРєС‚РѕСЂРѕРІ
    vectors = [
        # РџСѓСЃС‚Р°СЏ СЃС‚СЂРѕРєР°
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),

        # РћРґРёРЅ СЃРёРјРІРѕР»
        ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),

        # РўСЂРё СЃРёРјРІРѕР»Р°
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),

        # РљРѕСЂРѕС‚РєРѕРµ РїСЂРµРґР»РѕР¶РµРЅРёРµ
        ("The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),

        # РўРѕ Р¶Рµ СЃ С‚РѕС‡РєРѕР№
        ("The quick brown fox jumps over the lazy dog.",
         "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"),

        # Р”Р»РёРЅРЅР°СЏ РїРѕСЃР»РµРґРѕРІР°С‚РµР»СЊРЅРѕСЃС‚СЊ
        (
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ]

    passed = 0
    for i, (input_str, expected) in enumerate(vectors):
        sha = SHA256()
        sha.update(input_str)
        result = sha.hexdigest()

        if result == expected:
            print(f"[+] РўРµСЃС‚ {i + 1} РїСЂРѕР№РґРµРЅ")
            passed += 1
        else:
            print(f"[-] РўРµСЃС‚ {i + 1} РЅРµ РїСЂРѕР№РґРµРЅ")
            print(f"   Р’С…РѕРґ: '{input_str[:30]}{'...' if len(input_str) > 30 else ''}'")
            print(f"   РћР¶РёРґР°Р»РѕСЃСЊ: {expected}")
            print(f"   РџРѕР»СѓС‡РµРЅРѕ:  {result}")

    print(f"\nР РµР·СѓР»СЊС‚Р°С‚: {passed}/{len(vectors)} С‚РµСЃС‚РѕРІ РїСЂРѕР№РґРµРЅРѕ")
    return passed == len(vectors)


def test_sha3_256_extended_vectors():
    """Р Р°СЃС€РёСЂРµРЅРЅС‹Рµ С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ РґР»СЏ SHA3-256"""
    print("=== Р Р°СЃС€РёСЂРµРЅРЅС‹Рµ С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ SHA3-256 ===")

    vectors = [
        # РџСѓСЃС‚Р°СЏ СЃС‚СЂРѕРєР°
        ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),

        # РћРґРёРЅ СЃРёРјРІРѕР»
        ("a", "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"),

        # РўСЂРё СЃРёРјРІРѕР»Р°
        ("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),

        # РљРѕСЂРѕС‚РєРѕРµ РїСЂРµРґР»РѕР¶РµРЅРёРµ
        ("The quick brown fox jumps over the lazy dog",
         "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"),

        # РўРѕ Р¶Рµ СЃ С‚РѕС‡РєРѕР№
        ("The quick brown fox jumps over the lazy dog.",
         "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d"),

        # 1600-Р±РёС‚РЅРѕРµ СЃРѕРѕР±С‰РµРЅРёРµ (СЂРѕРІРЅРѕ РѕРґРёРЅ Р±Р»РѕРє РґР»СЏ Keccak)
        ("a" * 200,  # 200 Р±Р°Р№С‚ = 1600 Р±РёС‚
         "79f38adec5c20307a98ef76e8314ab5ec8aa1023cce8fbe7b3f91e6e9d2c0c7d"),
    ]

    passed = 0
    for i, (input_str, expected) in enumerate(vectors):
        sha3 = SHA3_256()
        sha3.update(input_str)
        result = sha3.hexdigest()

        if result == expected:
            print(f"[+] РўРµСЃС‚ {i + 1} РїСЂРѕР№РґРµРЅ")
            passed += 1
        else:
            print(f"[-] РўРµСЃС‚ {i + 1} РЅРµ РїСЂРѕР№РґРµРЅ")
            print(f"   Р’С…РѕРґ: '{input_str[:30]}{'...' if len(input_str) > 30 else ''}'")
            print(f"   РћР¶РёРґР°Р»РѕСЃСЊ: {expected}")
            print(f"   РџРѕР»СѓС‡РµРЅРѕ:  {result}")

    print(f"\nР РµР·СѓР»СЊС‚Р°С‚: {passed}/{len(vectors)} С‚РµСЃС‚РѕРІ РїСЂРѕР№РґРµРЅРѕ")
    return passed == len(vectors)


def test_empty_file():
    """РўРµСЃС‚ РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р° (TEST-2)"""
    print("=== РўРµСЃС‚ РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р° ===")

    import tempfile

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        temp_file = f.name

    try:
        # SHA-256 РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р°
        sha = SHA256()
        sha256_hash = sha.hash_file(temp_file)
        expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        if sha256_hash == expected_sha256:
            print(f"[+] SHA-256 РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р°: OK")
        else:
            print(f"[-] SHA-256 РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р°: FAIL")
            print(f"   РћР¶РёРґР°Р»РѕСЃСЊ: {expected_sha256}")
            print(f"   РџРѕР»СѓС‡РµРЅРѕ:  {sha256_hash}")
            return False

        # SHA3-256 РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р°
        sha3 = SHA3_256()
        sha3_hash = sha3.hash_file(temp_file)
        expected_sha3 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

        if sha3_hash == expected_sha3:
            print(f"[+] SHA3-256 РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р°: OK")
        else:
            print(f"[-] SHA3-256 РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р°: FAIL")
            print(f"   РћР¶РёРґР°Р»РѕСЃСЊ: {expected_sha3}")
            print(f"   РџРѕР»СѓС‡РµРЅРѕ:  {sha3_hash}")
            return False

        print("[+] Р’СЃРµ С‚РµСЃС‚С‹ РїСѓСЃС‚РѕРіРѕ С„Р°Р№Р»Р° РїСЂРѕР№РґРµРЅС‹")
        return True

    finally:
        os.unlink(temp_file)


def test_incremental_hashing():
    """РўРµСЃС‚ РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРіРѕ С…РµС€РёСЂРѕРІР°РЅРёСЏ"""
    print("=== РўРµСЃС‚ РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРіРѕ С…РµС€РёСЂРѕРІР°РЅРёСЏ ===")

    test_data = b"Hello, World! " * 1000  # ~14KB

    # SHA-256 РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕ
    sha1 = SHA256()
    for i in range(0, len(test_data), 100):  # Р§Р°РЅРєРё РїРѕ 100 Р±Р°Р№С‚
        chunk = test_data[i:i + 100]
        sha1.update(chunk)
    incremental_hash = sha1.hexdigest()

    # SHA-256 Р·Р° РѕРґРёРЅ СЂР°Р·
    sha2 = SHA256()
    sha2.update(test_data)
    one_shot_hash = sha2.hexdigest()

    if incremental_hash == one_shot_hash:
        print(f"[+] SHA-256 РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ: OK")
    else:
        print(f"[-] SHA-256 РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ: FAIL")
        return False

    # SHA3-256 РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕ
    sha3_1 = SHA3_256()
    for i in range(0, len(test_data), 100):
        chunk = test_data[i:i + 100]
        sha3_1.update(chunk)
    incremental_hash3 = sha3_1.hexdigest()

    # SHA3-256 Р·Р° РѕРґРёРЅ СЂР°Р·
    sha3_2 = SHA3_256()
    sha3_2.update(test_data)
    one_shot_hash3 = sha3_2.hexdigest()

    if incremental_hash3 == one_shot_hash3:
        print(f"[+] SHA3-256 РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ: OK")
    else:
        print(f"[-] SHA3-256 РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ: FAIL")
        return False

    print("[+] Р’СЃРµ С‚РµСЃС‚С‹ РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРіРѕ С…РµС€РёСЂРѕРІР°РЅРёСЏ РїСЂРѕР№РґРµРЅС‹")
    return True


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С„СѓРЅРєС†РёСЏ"""
    print("=" * 70)
    print("KNOWN-ANSWER РўР•РЎРўР« Р”Р›РЇ РҐР•РЁ-Р¤РЈРќРљР¦РР™")
    print("РўСЂРµР±РѕРІР°РЅРёРµ TEST-1: NIST С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹")
    print("РўСЂРµР±РѕРІР°РЅРёРµ TEST-2: РџСѓСЃС‚РѕР№ С„Р°Р№Р»")
    print("=" * 70)

    tests = [
        ("SHA-256 С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹", test_sha256_extended_vectors),
        ("SHA3-256 С‚РµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹", test_sha3_256_extended_vectors),
        ("РџСѓСЃС‚РѕР№ С„Р°Р№Р»", test_empty_file),
        ("РРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ", test_incremental_hashing),
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"[-] РћС€РёР±РєР°: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False

    # РС‚РѕРіРё
    print("\n" + "=" * 70)
    print("РРўРћР“Р KNOWN-ANSWER РўР•РЎРўРћР’")
    print("=" * 70)

    all_passed = True
    for test_name, passed in results.items():
        status = "вњ… РџР РћР™Р”Р•РќРћ" if passed else "вќЊ РќР• РџР РћР™Р”Р•РќРћ"
        print(f"{test_name:35} : {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n[+] Р’РЎР• KNOWN-ANSWER РўР•РЎРўР« РџР РћР™Р”Р•РќР«!")
        print("    РўСЂРµР±РѕРІР°РЅРёРµ TEST-1 РІС‹РїРѕР»РЅРµРЅРѕ вњ“")
        print("    РўСЂРµР±РѕРІР°РЅРёРµ TEST-2 РІС‹РїРѕР»РЅРµРЅРѕ вњ“")
    else:
        print("\n[-] РќР•РљРћРўРћР Р«Р• РўР•РЎРўР« РќР• РџР РћР™Р”Р•РќР«")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

