#!/usr/bin/env python3
"""
CryptoCore - CLI РёРЅСЃС‚СЂСѓРјРµРЅС‚ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ/РґРµС€РёС„СЂРѕРІР°РЅРёСЏ Рё С…РµС€РёСЂРѕРІР°РЅРёСЏ С„Р°Р№Р»РѕРІ
Р“Р»Р°РІРЅС‹Р№ РёСЃРїРѕР»РЅСЏРµРјС‹Р№ С„Р°Р№Р»
Sprint 6: Р”РѕР±Р°РІР»РµРЅРёРµ GCM Рё Encrypt-then-MAC
"""

import sys
import os
from src.cli_parser import parse_args
from src.crypto_core import CryptoCipher
from src.hash.hash_core import HashCore
from src.modes.gcm import GCM, AuthenticationError
from src.modes.aead import EncryptThenMAC


def main():
    """РћСЃРЅРѕРІРЅР°СЏ С‚РѕС‡РєР° РІС…РѕРґР° РїСЂРѕРіСЂР°РјРјС‹"""
    try:
        # РџР°СЂСЃРёРј Р°СЂРіСѓРјРµРЅС‚С‹ РєРѕРјР°РЅРґРЅРѕР№ СЃС‚СЂРѕРєРё
        args = parse_args()

        if args.command == 'dgst':
            # Sprint 4: РћР±СЂР°Р±РѕС‚РєР° РєРѕРјР°РЅРґС‹ dgst
            _handle_dgst_command(args)
        else:
            # РћР±СЂР°Р±РѕС‚РєР° С€РёС„СЂРѕРІР°РЅРёСЏ/РґРµС€РёС„СЂРѕРІР°РЅРёСЏ
            _handle_crypto_command(args)

    except AuthenticationError as e:
        print(f"[-] РћС€РёР±РєР° Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] РћС€РёР±РєР°: {e}", file=sys.stderr)
        sys.exit(1)


def _handle_crypto_command(args):
    """РћР±СЂР°Р±РѕС‚РєР° РєРѕРјР°РЅРґС‹ С€РёС„СЂРѕРІР°РЅРёСЏ/РґРµС€РёС„СЂРѕРІР°РЅРёСЏ"""
    # Sprint 6: РџСЂРѕРІРµСЂСЏРµРј, РЅРµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ Р»Рё GCM РёР»Рё AEAD
    if args.mode == 'gcm':
        _handle_gcm_command(args)
        return

    if args.mode == 'aead':
        _handle_aead_command(args)
        return

    # РћСЂРёРіРёРЅР°Р»СЊРЅС‹Р№ РєРѕРґ РґР»СЏ РґСЂСѓРіРёС… СЂРµР¶РёРјРѕРІ
    # Sprint 3: РћРїСЂРµРґРµР»СЏРµРј, РЅСѓР¶РЅРѕ Р»Рё РіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ РєР»СЋС‡
    auto_generate_key = args.encrypt and not args.key

    # РЎРѕР·РґР°РµРј РѕР±СЉРµРєС‚ С€РёС„СЂР°
    cipher = CryptoCipher(
        algorithm=args.algorithm,
        mode=args.mode,
        key=args.key,
        iv=args.iv
    )

    # Sprint 3: Р’С‹РІРѕРґРёРј auto-generated РєР»СЋС‡
    if auto_generate_key:
        key_hex = cipher.get_auto_generated_key_hex()
        if key_hex:
            print(f"[+] РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅ СЃР»СѓС‡Р°Р№РЅС‹Р№ РєР»СЋС‡: {key_hex}")
            print(f"    РЎРѕС…СЂР°РЅРёС‚Рµ СЌС‚РѕС‚ РєР»СЋС‡ РґР»СЏ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ!")
            print(f"    РџСЂРёРјРµСЂ РєРѕРјР°РЅРґС‹ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ:")
            print(f"    python cryptocore.py -algorithm aes -mode {args.mode} -decrypt \\")
            print(f"      -key @{key_hex} -input {args.output} -output decrypted.txt")

    # Р’С‹РїРѕР»РЅСЏРµРј РѕРїРµСЂР°С†РёСЋ
    if args.encrypt:
        cipher.encrypt_file(args.input, args.output)
        print(f"[+] Р¤Р°Р№Р» СѓСЃРїРµС€РЅРѕ Р·Р°С€РёС„СЂРѕРІР°РЅ (СЂРµР¶РёРј: {args.mode.upper()})")
        print(f"  Р’С…РѕРґ:  {args.input}")
        print(f"  Р’С‹С…РѕРґ: {args.output}")

        if args.mode != 'ecb':
            print(f"  IV Р±С‹Р» СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё Рё Р·Р°РїРёСЃР°РЅ РІ РЅР°С‡Р°Р»Рѕ С„Р°Р№Р»Р°")
    else:  # decrypt
        cipher.decrypt_file(args.input, args.output)
        print(f"[+] Р¤Р°Р№Р» СѓСЃРїРµС€РЅРѕ СЂР°СЃС€РёС„СЂРѕРІР°РЅ (СЂРµР¶РёРј: {args.mode.upper()})")
        print(f"  Р’С…РѕРґ:  {args.input}")
        print(f"  Р’С‹С…РѕРґ: {args.output}")

        if args.mode != 'ecb':
            if args.iv:
                print(f"  РСЃРїРѕР»СЊР·РѕРІР°РЅ IV РёР· Р°СЂРіСѓРјРµРЅС‚Р° РєРѕРјР°РЅРґРЅРѕР№ СЃС‚СЂРѕРєРё")
            else:
                print(f"  IV РїСЂРѕС‡РёС‚Р°РЅ РёР· РЅР°С‡Р°Р»Р° РІС…РѕРґРЅРѕРіРѕ С„Р°Р№Р»Р°")


def _handle_gcm_command(args):
    """РћР±СЂР°Р±РѕС‚РєР° РєРѕРјР°РЅРґС‹ GCM С€РёС„СЂРѕРІР°РЅРёСЏ/РґРµС€РёС„СЂРѕРІР°РЅРёСЏ"""
    # Р§РёС‚Р°РµРј РІС…РѕРґРЅРѕР№ С„Р°Р№Р»
    with open(args.input, 'rb') as f:
        data = f.read()

    # РџРѕР»СѓС‡Р°РµРј РєР»СЋС‡
    if args.encrypt and not args.key:
        # Р“РµРЅРµСЂРёСЂСѓРµРј РєР»СЋС‡ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё
        from src.csprng import generate_random_bytes
        key = generate_random_bytes(16)
        key_hex = key.hex()
        print(f"[+] РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅ СЃР»СѓС‡Р°Р№РЅС‹Р№ РєР»СЋС‡ GCM: {key_hex}")
        print(f"    РЎРѕС…СЂР°РЅРёС‚Рµ СЌС‚РѕС‚ РєР»СЋС‡ РґР»СЏ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ!")
    else:
        if not args.key:
            raise ValueError("Р”Р»СЏ GCM СЂРµР¶РёРјР° С‚СЂРµР±СѓРµС‚СЃСЏ РєР»СЋС‡ (--key)")
        key = bytes.fromhex(args.key)

    # РџРѕР»СѓС‡Р°РµРј AAD (РµСЃР»Рё РµСЃС‚СЊ)
    aad = b""
    if hasattr(args, 'aad') and args.aad:
        aad = bytes.fromhex(args.aad)

    # Р’С‹РїРѕР»РЅСЏРµРј РѕРїРµСЂР°С†РёСЋ
    if args.encrypt:
        # РЁРёС„СЂРѕРІР°РЅРёРµ GCM
        gcm = GCM(key)
        ciphertext = gcm.encrypt(data, aad)

        with open(args.output, 'wb') as f:
            f.write(ciphertext)

        print(f"[+] GCM С€РёС„СЂРѕРІР°РЅРёРµ СѓСЃРїРµС€РЅРѕ Р·Р°РІРµСЂС€РµРЅРѕ")
        print(f"  Р’С…РѕРґ:     {args.input}")
        print(f"  Р’С‹С…РѕРґ:    {args.output}")
        print(f"  Nonce:    {gcm.nonce.hex()}")
        print(f"  РљР»СЋС‡:     {key.hex()}")
        if aad:
            print(f"  AAD:      {aad.hex()}")
        print(f"  Р Р°Р·РјРµСЂ:   {len(data)} Р±Р°Р№С‚ -> {len(ciphertext)} Р±Р°Р№С‚")

    else:
        # Р”РµС€РёС„СЂРѕРІР°РЅРёРµ GCM
        # Р”Р»СЏ GCM nonce С‡РёС‚Р°РµС‚СЃСЏ РёР· С„Р°Р№Р»Р°, РЅРѕ РјРѕР¶РµС‚ Р±С‹С‚СЊ РїРµСЂРµРґР°РЅ С‡РµСЂРµР· --iv
        if args.iv:
            nonce = bytes.fromhex(args.iv)
            gcm = GCM(key, nonce)
        else:
            # Nonce Р±СѓРґРµС‚ РїСЂРѕС‡РёС‚Р°РЅ РёР· С„Р°Р№Р»Р° Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё
            gcm = GCM(key)

        try:
            plaintext = gcm.decrypt(data, aad)

            with open(args.output, 'wb') as f:
                f.write(plaintext)

            print(f"[+] GCM РґРµС€РёС„СЂРѕРІР°РЅРёРµ СѓСЃРїРµС€РЅРѕ Р·Р°РІРµСЂС€РµРЅРѕ")
            print(f"  Р’С…РѕРґ:     {args.input}")
            print(f"  Р’С‹С…РѕРґ:    {args.output}")
            print(f"  Nonce:    {gcm.nonce.hex()}")
            print(f"  РљР»СЋС‡:     {key.hex()}")
            if aad:
                print(f"  AAD:      {aad.hex()}")
            print(f"  Р Р°Р·РјРµСЂ:   {len(data)} Р±Р°Р№С‚ -> {len(plaintext)} Р±Р°Р№С‚")
            print(f"  РђСѓС‚РµРЅС‚РёС„РёРєР°С†РёСЏ: РЈРЎРџР•РЁРќРћ")

        except AuthenticationError:
            # РЈРґР°Р»СЏРµРј С‡Р°СЃС‚РёС‡РЅРѕ СЃРѕР·РґР°РЅРЅС‹Р№ С„Р°Р№Р» РµСЃР»Рё РµСЃС‚СЊ
            if os.path.exists(args.output):
                os.remove(args.output)
            raise AuthenticationError(
                "РђСѓС‚РµРЅС‚РёС„РёРєР°С†РёСЏ GCM РЅРµ СѓРґР°Р»Р°СЃСЊ. Р¤Р°Р№Р» РјРѕР¶РµС‚ Р±С‹С‚СЊ РїРѕРІСЂРµР¶РґРµРЅ РёР»Рё РёСЃРїРѕР»СЊР·РѕРІР°РЅ РЅРµРІРµСЂРЅС‹Р№ РєР»СЋС‡/AAD.")


def _handle_aead_command(args):
    """РћР±СЂР°Р±РѕС‚РєР° РєРѕРјР°РЅРґС‹ Encrypt-then-MAC"""
    # Р§РёС‚Р°РµРј РІС…РѕРґРЅРѕР№ С„Р°Р№Р»
    with open(args.input, 'rb') as f:
        data = f.read()

    # РџРѕР»СѓС‡Р°РµРј РєР»СЋС‡
    if args.encrypt and not args.key:
        # Р“РµРЅРµСЂРёСЂСѓРµРј РєР»СЋС‡ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё
        from src.csprng import generate_random_bytes
        master_key = generate_random_bytes(32)  # Р‘РѕР»СЊС€РёР№ РєР»СЋС‡ РґР»СЏ РґРµСЂРёРІР°С†РёРё
        key_hex = master_key.hex()
        print(f"[+] РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅ РјР°СЃС‚РµСЂ-РєР»СЋС‡ AEAD: {key_hex}")
        print(f"    РЎРѕС…СЂР°РЅРёС‚Рµ СЌС‚РѕС‚ РєР»СЋС‡ РґР»СЏ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ!")
    else:
        if not args.key:
            raise ValueError("Р”Р»СЏ AEAD СЂРµР¶РёРјР° С‚СЂРµР±СѓРµС‚СЃСЏ РєР»СЋС‡ (--key)")
        master_key = bytes.fromhex(args.key)

    # РџРѕР»СѓС‡Р°РµРј AAD (РµСЃР»Рё РµСЃС‚СЊ)
    aad = b""
    if hasattr(args, 'aad') and args.aad:
        aad = bytes.fromhex(args.aad)

    # РЎРѕР·РґР°РµРј AEAD РѕР±СЉРµРєС‚
    aead = EncryptThenMAC.from_master_key(master_key)

    # Р’С‹РїРѕР»РЅСЏРµРј РѕРїРµСЂР°С†РёСЋ
    if args.encrypt:
        # РЁРёС„СЂРѕРІР°РЅРёРµ Encrypt-then-MAC
        ciphertext = aead.encrypt(data, aad)

        with open(args.output, 'wb') as f:
            f.write(ciphertext)

        print(f"[+] Encrypt-then-MAC С€РёС„СЂРѕРІР°РЅРёРµ СѓСЃРїРµС€РЅРѕ Р·Р°РІРµСЂС€РµРЅРѕ")
        print(f"  Р’С…РѕРґ:     {args.input}")
        print(f"  Р’С‹С…РѕРґ:    {args.output}")
        print(f"  РњР°СЃС‚РµСЂ-РєР»СЋС‡: {master_key.hex()}")
        if aad:
            print(f"  AAD:      {aad.hex()}")
        print(f"  Р Р°Р·РјРµСЂ:   {len(data)} Р±Р°Р№С‚ -> {len(ciphertext)} Р±Р°Р№С‚")
        print(f"  Р¤РѕСЂРјР°С‚:   IV(16) || ciphertext || tag(16)")

    else:
        # Р”РµС€РёС„СЂРѕРІР°РЅРёРµ Encrypt-then-MAC
        try:
            plaintext = aead.decrypt(data, aad)

            with open(args.output, 'wb') as f:
                f.write(plaintext)

            print(f"[+] Encrypt-then-MAC РґРµС€РёС„СЂРѕРІР°РЅРёРµ СѓСЃРїРµС€РЅРѕ Р·Р°РІРµСЂС€РµРЅРѕ")
            print(f"  Р’С…РѕРґ:     {args.input}")
            print(f"  Р’С‹С…РѕРґ:    {args.output}")
            print(f"  РњР°СЃС‚РµСЂ-РєР»СЋС‡: {master_key.hex()}")
            if aad:
                print(f"  AAD:      {aad.hex()}")
            print(f"  Р Р°Р·РјРµСЂ:   {len(data)} Р±Р°Р№С‚ -> {len(plaintext)} Р±Р°Р№С‚")
            print(f"  РђСѓС‚РµРЅС‚РёС„РёРєР°С†РёСЏ: РЈРЎРџР•РЁРќРћ")

        except AuthenticationError:
            # РЈРґР°Р»СЏРµРј С‡Р°СЃС‚РёС‡РЅРѕ СЃРѕР·РґР°РЅРЅС‹Р№ С„Р°Р№Р» РµСЃР»Рё РµСЃС‚СЊ
            if os.path.exists(args.output):
                os.remove(args.output)
            raise AuthenticationError(
                "РђСѓС‚РµРЅС‚РёС„РёРєР°С†РёСЏ Encrypt-then-MAC РЅРµ СѓРґР°Р»Р°СЃСЊ. Р¤Р°Р№Р» РјРѕР¶РµС‚ Р±С‹С‚СЊ РїРѕРІСЂРµР¶РґРµРЅ РёР»Рё РёСЃРїРѕР»СЊР·РѕРІР°РЅ РЅРµРІРµСЂРЅС‹Р№ РєР»СЋС‡/AAD.")


def _handle_dgst_command(args):
    """РћР±СЂР°Р±РѕС‚РєР° РєРѕРјР°РЅРґС‹ dgst РґР»СЏ С…РµС€РёСЂРѕРІР°РЅРёСЏ"""
    import sys

    # Р•СЃР»Рё РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ HMAC РёР»Рё CMAC
    if args.hmac or args.cmac:
        _handle_mac_command(args)
        return

    # РЎС‚Р°РЅРґР°СЂС‚РЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ (РєР°Рє Р±С‹Р»Рѕ)
    hasher = HashCore(algorithm=args.algorithm)
    file_hash = hasher.hash_file(args.input)
    output_line = f"{file_hash}  {args.input}"

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_line + '\n')
        print(f"[+] РҐРµС€ Р·Р°РїРёСЃР°РЅ РІ С„Р°Р№Р»: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output_line + '\n')


def _handle_mac_command(args):
    """РћР±СЂР°Р±РѕС‚РєР° РєРѕРјР°РЅРґС‹ MAC (HMAC РёР»Рё CMAC)"""
    import sys
    from src.mac.hmac import HMAC
    from src.mac.cmac import CMAC

    # Р§РёС‚Р°РµРј С„Р°Р№Р»
    with open(args.input, 'rb') as f:
        data = f.read()

    key_bytes = bytes.fromhex(args.key)

    # Р’С‹С‡РёСЃР»СЏРµРј MAC
    if args.hmac:
        # HMAC СЃ SHA-256
        hmac = HMAC(key_bytes, 'sha256')
        mac_value = hmac.compute(data)
        mac_type = "HMAC"
        algo_info = f"SHA-256"
    else:
        # AES-CMAC
        cmac = CMAC(key_bytes)
        mac_value = cmac.compute(data)
        mac_type = "CMAC"
        algo_info = f"AES-{len(key_bytes) * 8}"

    mac_hex = mac_value.hex()

    # Р•СЃР»Рё С‚СЂРµР±СѓРµС‚СЃСЏ РїСЂРѕРІРµСЂРєР°
    if args.verify:
        # Р§РёС‚Р°РµРј РѕР¶РёРґР°РµРјС‹Р№ MAC РёР· С„Р°Р№Р»Р°
        try:
            with open(args.verify, 'r') as f:
                expected_line = f.read().strip()

            # РџР°СЂСЃРёРј РѕР¶РёРґР°РµРјС‹Р№ MAC (РјРѕР¶РµС‚ СЃРѕРґРµСЂР¶Р°С‚СЊ РёРјСЏ С„Р°Р№Р»Р°)
            expected_parts = expected_line.split()
            expected_mac = expected_parts[0] if expected_parts else expected_line

            # РЎСЂР°РІРЅРёРІР°РµРј
            if mac_hex == expected_mac:
                print(f"[OK] {mac_type} verification successful", file=sys.stderr)
                print(f"[OK] Р¤Р°Р№Р» '{args.input}' Р°СѓС‚РµРЅС‚РёС‡РµРЅ", file=sys.stderr)
                sys.exit(0)
            else:
                print(f"[ERROR] {mac_type} verification failed", file=sys.stderr)
                print(f"  Р’С‹С‡РёСЃР»РµРЅРѕ: {mac_hex}", file=sys.stderr)
                print(f"  РћР¶РёРґР°Р»РѕСЃСЊ: {expected_mac}", file=sys.stderr)
                sys.exit(1)

        except FileNotFoundError:
            print(f"[ERROR] Р¤Р°Р№Р» СЃ РѕР¶РёРґР°РµРјС‹Рј {mac_type} РЅРµ РЅР°Р№РґРµРЅ: {args.verify}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] РћС€РёР±РєР° РїСЂРё РїСЂРѕРІРµСЂРєРµ {mac_type}: {e}", file=sys.stderr)
            sys.exit(1)

    # Р’С‹РІРѕРґ СЂРµР·СѓР»СЊС‚Р°С‚Р°
    output_line = f"{mac_hex} {args.input}"

    if args.output:
        # Р—Р°РїРёСЃС‹РІР°РµРј РІ С„Р°Р№Р»
        with open(args.output, 'w') as f:
            f.write(output_line + '\n')
        print(f"[+] {mac_type} Р·Р°РїРёСЃР°РЅ РІ С„Р°Р№Р»: {args.output}", file=sys.stderr)
    else:
        # Р’С‹РІРѕРґРёРј РІ stdout
        sys.stdout.write(output_line + '\n')

    # Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅР°СЏ РёРЅС„РѕСЂРјР°С†РёСЏ РІ stderr
    print(f"[+] {mac_type} СѓСЃРїРµС€РЅРѕ РІС‹С‡РёСЃР»РµРЅ ({algo_info})", file=sys.stderr)
    print(f"  Р¤Р°Р№Р»: {args.input}", file=sys.stderr)
    print(f"  РљР»СЋС‡: {args.key}", file=sys.stderr)
    print(f"  {mac_type}: {mac_hex}", file=sys.stderr)


if __name__ == "__main__":
    main()

