#!/usr/bin/env python3
"""
РЎРєСЂРёРїС‚ РґР»СЏ РїРѕРґРіРѕС‚РѕРІРєРё Рё Р·Р°РїСѓСЃРєР° NIST С‚РµСЃС‚РѕРІ
РўСЂРµР±РѕРІР°РЅРёРµ TEST-3: Р·Р°РїСѓСЃРє NIST Statistical Test Suite
"""

import os
import sys
import subprocess
import argparse

# Р”РѕР±Р°РІР»СЏРµРј РїСѓС‚СЊ Рє src РґР»СЏ РёРјРїРѕСЂС‚Р° РјРѕРґСѓР»РµР№
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from src.csprng import generate_random_bytes
except ImportError:
    print("РћС€РёР±РєР°: РќРµ СѓРґР°Р»РѕСЃСЊ РёРјРїРѕСЂС‚РёСЂРѕРІР°С‚СЊ РјРѕРґСѓР»СЊ csprng")
    print("РЈР±РµРґРёС‚РµСЃСЊ, С‡С‚Рѕ РІС‹ Р·Р°РїСѓСЃРєР°РµС‚Рµ СЃРєСЂРёРїС‚ РёР· РєРѕСЂРЅРµРІРѕР№ РґРёСЂРµРєС‚РѕСЂРёРё РїСЂРѕРµРєС‚Р°")
    sys.exit(1)


def generate_nist_test_file(size_mb, output_file):
    """
    Р“РµРЅРµСЂР°С†РёСЏ С„Р°Р№Р»Р° РґР»СЏ NIST С‚РµСЃС‚РѕРІ

    Args:
        size_mb: СЂР°Р·РјРµСЂ С„Р°Р№Р»Р° РІ РјРµРіР°Р±Р°Р№С‚Р°С…
        output_file: РїСѓС‚СЊ Рє РІС‹С…РѕРґРЅРѕРјСѓ С„Р°Р№Р»Сѓ
    """
    print(f"Р“РµРЅРµСЂР°С†РёСЏ С„Р°Р№Р»Р° СЂР°Р·РјРµСЂРѕРј {size_mb} MB РґР»СЏ NIST С‚РµСЃС‚РѕРІ...")

    total_size = size_mb * 1024 * 1024

    try:
        with open(output_file, 'wb') as f:
            bytes_written = 0
            chunk_size = 4096

            while bytes_written < total_size:
                # РћС‚РѕР±СЂР°Р¶РµРЅРёРµ РїСЂРѕРіСЂРµСЃСЃР°
                if bytes_written % (5 * 1024 * 1024) == 0 and bytes_written > 0:
                    progress = (bytes_written / total_size) * 100
                    print(f"  РџСЂРѕРіСЂРµСЃСЃ: {progress:.1f}% ({bytes_written / 1024 / 1024:.1f} MB / {size_mb} MB)")

                # Р’С‹С‡РёСЃР»СЏРµРј СЂР°Р·РјРµСЂ С‚РµРєСѓС‰РµРіРѕ С‡Р°РЅРєР°
                current_chunk_size = min(chunk_size, total_size - bytes_written)

                # Р“РµРЅРµСЂРёСЂСѓРµРј СЃР»СѓС‡Р°Р№РЅС‹Рµ РґР°РЅРЅС‹Рµ
                random_chunk = generate_random_bytes(current_chunk_size)

                # Р—Р°РїРёСЃС‹РІР°РµРј РІ С„Р°Р№Р»
                f.write(random_chunk)
                bytes_written += current_chunk_size

        print(f"[+] Р¤Р°Р№Р» СЃРѕР·РґР°РЅ: {output_file}")
        print(f"    Р Р°Р·РјРµСЂ: {bytes_written:,} Р±Р°Р№С‚РѕРІ ({bytes_written / 1024 / 1024:.2f} MB)")
        print(f"    SHA-256: ", end="")

        # Р’С‹С‡РёСЃР»СЏРµРј С…СЌС€ РґР»СЏ РїСЂРѕРІРµСЂРєРё
        import hashlib
        with open(output_file, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            print(file_hash.hexdigest())

        return True

    except Exception as e:
        print(f"[-] РћС€РёР±РєР° РїСЂРё СЃРѕР·РґР°РЅРёРё С„Р°Р№Р»Р°: {e}")
        return False


def check_nist_installed():
    """РџСЂРѕРІРµСЂРєР°, СѓСЃС‚Р°РЅРѕРІР»РµРЅ Р»Рё NIST STS"""
    nist_paths = [
        "sts-2.1.2/assess",
        "STS/assess",
        "assess"
    ]

    for path in nist_paths:
        if os.path.exists(path):
            print(f"[+] РќР°Р№РґРµРЅ NIST STS: {path}")
            return path

    print("[!] NIST STS РЅРµ РЅР°Р№РґРµРЅ РІ СЃС‚Р°РЅРґР°СЂС‚РЅС‹С… РїСѓС‚СЏС…")
    return None


def run_nist_tests(data_file, nist_path):
    """
    Р—Р°РїСѓСЃРє NIST С‚РµСЃС‚РѕРІ

    Args:
        data_file: РїСѓС‚СЊ Рє С‚РµСЃС‚РѕРІРѕРјСѓ С„Р°Р№Р»Сѓ
        nist_path: РїСѓС‚СЊ Рє РёСЃРїРѕР»РЅСЏРµРјРѕРјСѓ С„Р°Р№Р»Сѓ NIST STS
    """
    print(f"\nР—Р°РїСѓСЃРє NIST С‚РµСЃС‚РѕРІ РґР»СЏ С„Р°Р№Р»Р°: {data_file}")

    # РџРѕР»СѓС‡Р°РµРј СЂР°Р·РјРµСЂ С„Р°Р№Р»Р° РІ Р±РёС‚Р°С…
    file_size = os.path.getsize(data_file)
    bit_length = file_size * 8

    print(f"Р Р°Р·РјРµСЂ С„Р°Р№Р»Р°: {file_size:,} Р±Р°Р№С‚РѕРІ ({bit_length:,} Р±РёС‚)")

    # РљРѕРјР°РЅРґР° РґР»СЏ Р·Р°РїСѓСЃРєР° NIST STS
    cmd = [nist_path, str(bit_length)]

    print(f"\nРљРѕРјР°РЅРґР° РґР»СЏ Р·Р°РїСѓСЃРєР°: {' '.join(cmd)}")
    print("\nРџРѕСЃР»Рµ Р·Р°РїСѓСЃРєР° NIST STS:")
    print("1. Р’РІРµРґРёС‚Рµ РїСѓС‚СЊ Рє С‚РµСЃС‚РѕРІРѕРјСѓ С„Р°Р№Р»Сѓ")
    print("2. Р’С‹Р±РµСЂРёС‚Рµ '0' РґР»СЏ РІСЃРµС… С‚РµСЃС‚РѕРІ")
    print("3. РќР°СЃС‚СЂРѕР№С‚Рµ РїР°СЂР°РјРµС‚СЂС‹ РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ")
    print("4. Р”РѕР¶РґРёС‚РµСЃСЊ Р·Р°РІРµСЂС€РµРЅРёСЏ С‚РµСЃС‚РѕРІ")
    print("5. Р РµР·СѓР»СЊС‚Р°С‚С‹ Р±СѓРґСѓС‚ РІ РїР°РїРєРµ 'experiments/'")

    # Р—Р°РїСЂРѕСЃ РЅР° Р·Р°РїСѓСЃРє
    response = input("\nР—Р°РїСѓСЃС‚РёС‚СЊ NIST STS СЃРµР№С‡Р°СЃ? (y/n): ")
    if response.lower() == 'y':
        try:
            subprocess.run(cmd, cwd=os.path.dirname(nist_path) or '.')
        except Exception as e:
            print(f"РћС€РёР±РєР° РїСЂРё Р·Р°РїСѓСЃРєРµ NIST STS: {e}")
    else:
        print("\nР’С‹ РјРѕР¶РµС‚Рµ Р·Р°РїСѓСЃС‚РёС‚СЊ NIST STS РІСЂСѓС‡РЅСѓСЋ:")
        print(f"cd {os.path.dirname(nist_path) or '.'}")
        print(f"./assess {bit_length}")


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С„СѓРЅРєС†РёСЏ"""
    parser = argparse.ArgumentParser(
        description="РџРѕРґРіРѕС‚РѕРІРєР° РґР°РЅРЅС‹С… Рё Р·Р°РїСѓСЃРє NIST Statistical Test Suite"
    )

    parser.add_argument(
        "--size",
        type=int,
        default=10,
        help="Р Р°Р·РјРµСЂ С‚РµСЃС‚РѕРІРѕРіРѕ С„Р°Р№Р»Р° РІ РјРµРіР°Р±Р°Р№С‚Р°С… (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ: 10)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="nist_test_data.bin",
        help="РРјСЏ РІС‹С…РѕРґРЅРѕРіРѕ С„Р°Р№Р»Р° (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ: nist_test_data.bin)"
    )

    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="РўРѕР»СЊРєРѕ СЃРіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ С„Р°Р№Р», РЅРµ Р·Р°РїСѓСЃРєР°С‚СЊ NIST STS"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("РџРћР”Р“РћРўРћР’РљРђ Рљ NIST STATISTICAL TEST SUITE")
    print("РўСЂРµР±РѕРІР°РЅРёРµ TEST-3: РџСЂРѕРІРµСЂРєР° CSPRNG СЃ РїРѕРјРѕС‰СЊСЋ NIST STS")
    print("=" * 70)

    # 1. Р“РµРЅРµСЂР°С†РёСЏ С‚РµСЃС‚РѕРІРѕРіРѕ С„Р°Р№Р»Р°
    print("\n[1/3] Р“РµРЅРµСЂР°С†РёСЏ С‚РµСЃС‚РѕРІРѕРіРѕ С„Р°Р№Р»Р°...")
    if not generate_nist_test_file(args.size, args.output):
        sys.exit(1)

    # 2. РџСЂРѕРІРµСЂРєР° РЅР°Р»РёС‡РёСЏ NIST STS
    print("\n[2/3] РџРѕРёСЃРє NIST STS...")
    nist_path = check_nist_installed()

    if not nist_path:
        print("\n[!] NIST STS РЅРµ СѓСЃС‚Р°РЅРѕРІР»РµРЅ")
        print("\nРРЅСЃС‚СЂСѓРєС†РёРё РїРѕ СѓСЃС‚Р°РЅРѕРІРєРµ:")
        print("1. РЎРєР°С‡Р°Р№С‚Рµ NIST Statistical Test Suite:")
        print("   https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software")
        print("2. Р Р°СЃРїР°РєСѓР№С‚Рµ Р°СЂС…РёРІ:")
        print("   tar -xzf sts-2.1.2.tar.gz")
        print("3. РџРµСЂРµР№РґРёС‚Рµ РІ РґРёСЂРµРєС‚РѕСЂРёСЋ Рё СЃРєРѕРјРїРёР»РёСЂСѓР№С‚Рµ:")
        print("   cd sts-2.1.2")
        print("   make")
        print("4. РСЃРїРѕР»РЅСЏРµРјС‹Р№ С„Р°Р№Р» Р±СѓРґРµС‚ РІ sts-2.1.2/assess")

    # 3. Р—Р°РїСѓСЃРє NIST STS (РµСЃР»Рё РЅРµ СѓРєР°Р·Р°РЅ --generate-only)
    if not args.generate_only and nist_path:
        print("\n[3/3] Р—Р°РїСѓСЃРє NIST STS...")
        run_nist_tests(args.output, nist_path)
    elif args.generate_only:
        print("\n[3/3] Р“РµРЅРµСЂР°С†РёСЏ Р·Р°РІРµСЂС€РµРЅР°. NIST STS РЅРµ Р·Р°РїСѓС‰РµРЅ (--generate-only)")
    else:
        print("\n[3/3] NIST STS РЅРµ РЅР°Р№РґРµРЅ, Р·Р°РїСѓСЃРє РЅРµРІРѕР·РјРѕР¶РµРЅ")

    # РРЅС„РѕСЂРјР°С†РёСЏ РѕР± Р°РЅР°Р»РёР·Рµ СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ
    print("\n" + "=" * 70)
    print("РђРќРђР›РР— Р Р•Р—РЈР›Р¬РўРђРўРћР’ NIST STS")
    print("=" * 70)
    print("\nРљСЂРёС‚РµСЂРёРё СѓСЃРїРµС…Р° РґР»СЏ CSPRNG:")
    print("1. Р‘РѕР»СЊС€РёРЅСЃС‚РІРѕ С‚РµСЃС‚РѕРІ РґРѕР»Р¶РЅРѕ РёРјРµС‚СЊ p-value в‰Ґ 0.01")
    print("2. РџСЂРѕС†РµРЅС‚ СѓСЃРїРµС€РЅС‹С… С‚РµСЃС‚РѕРІ РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ в‰Ґ 95%")
    print("3. РќРµР±РѕР»СЊС€РѕРµ РєРѕР»РёС‡РµСЃС‚РІРѕ СЃР±РѕРµРІ СЃС‚Р°С‚РёСЃС‚РёС‡РµСЃРєРё РѕР¶РёРґР°РµРјРѕ")
    print("\nРўРµСЃС‚С‹, РєРѕС‚РѕСЂС‹Рµ РІС‹РїРѕР»РЅСЏРµС‚ NIST STS:")
    print("1. Frequency (Monobit) Test")
    print("2. Frequency Test within a Block")
    print("3. Runs Test")
    print("4. Test for the Longest Run of Ones in a Block")
    print("5. Binary Matrix Rank Test")
    print("6. Discrete Fourier Transform (Spectral) Test")
    print("7. Non-overlapping Template Matching Test")
    print("8. Overlapping Template Matching Test")
    print("9. Maurer's Universal Statistical Test")
    print("10. Linear Complexity Test")
    print("11. Serial Test")
    print("12. Approximate Entropy Test")
    print("13. Cumulative Sums (Cusum) Test")
    print("14. Random Excursions Test")
    print("15. Random Excursions Variant Test")
    print("\nР РµР·СѓР»СЊС‚Р°С‚С‹ Р±СѓРґСѓС‚ СЃРѕС…СЂР°РЅРµРЅС‹ РІ experiments/AlgorithmTesting/finalAnalysisReport.txt")


if __name__ == "__main__":
    main()

