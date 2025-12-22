#!/usr/bin/env python3
"""
РћСЃРЅРѕРІРЅРѕР№ РєР»Р°СЃСЃ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ Рё РґРµС€РёС„СЂРѕРІР°РЅРёСЏ С„Р°Р№Р»РѕРІ
Sprint 6: Р”РѕР±Р°РІР»РµРЅР° РїРѕРґРґРµСЂР¶РєР° GCM Рё AEAD
"""

import sys
import os
from typing import Optional

# РРјРїРѕСЂС‚С‹ РёР· СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёС… РјРѕРґСѓР»РµР№
from src.modes.ecb import ECBMode
from src.modes.cbc import CBCMode
from src.modes.cfb import CFBMode
from src.modes.ofb import OFBMode
from src.modes.ctr import CTRMode
from src.modes.gcm import GCM, AuthenticationError
from src.aead import EncryptThenMAC, AuthenticationError
from src.file_io import read_file_safe, write_file_safe
from src.csprng import generate_random_bytes, generate_aes_key, generate_aes_key_hex


class CryptoCipher:
    """РћСЃРЅРѕРІРЅРѕР№ РєР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ С€РёС„СЂРѕРІР°РЅРёРµРј"""

    def __init__(self, algorithm, mode, key=None, iv=None, aad=None):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ С€РёС„СЂР°"""
        self.algorithm = algorithm.lower()
        self.mode = mode.lower()
        self.auto_generated_key = None
        self.aad = aad or b""

        # Sprint 3: РћР±СЂР°Р±РѕС‚РєР° РєР»СЋС‡Р° (РјРѕР¶РµС‚ Р±С‹С‚СЊ None РґР»СЏ auto-generation)
        self.key = self._process_key(key)

        # Р”Р»СЏ GCM РёСЃРїРѕР»СЊР·СѓРµРј nonce (12 Р±Р°Р№С‚), РґР»СЏ РґСЂСѓРіРёС… СЂРµР¶РёРјРѕРІ IV (16 Р±Р°Р№С‚)
        if self.mode == 'gcm':
            self.nonce = self._parse_nonce(iv) if iv else None
            self.iv = self.nonce  # Р”Р»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        else:
            self.iv = self._parse_iv(iv) if iv else None
            self.nonce = None

        # РЎРѕС…СЂР°РЅСЏРµРј РѕСЂРёРіРёРЅР°Р»СЊРЅС‹Р№ СЂРµР¶РёРј
        self.original_mode = mode.lower()

        self.cipher = self._init_cipher()

    def _process_key(self, key_str):
        """
        РћР±СЂР°Р±РѕС‚РєР° РєР»СЋС‡Р°:
        - Р•СЃР»Рё РїРµСЂРµРґР°РЅ РєР»СЋС‡, РїР°СЂСЃРёРј РµРіРѕ
        - Р•СЃР»Рё None, РіРµРЅРµСЂРёСЂСѓРµРј СЃР»СѓС‡Р°Р№РЅС‹Р№ РєР»СЋС‡
        """
        if key_str:
            # РСЃРїРѕР»СЊР·СѓРµРј РїРµСЂРµРґР°РЅРЅС‹Р№ РєР»СЋС‡
            return self._parse_key(key_str)
        else:
            # Sprint 3: Р“РµРЅРµСЂР°С†РёСЏ СЃР»СѓС‡Р°Р№РЅРѕРіРѕ РєР»СЋС‡Р°
            self.auto_generated_key = generate_random_bytes(16)
            print(f"[INFO] Generated random key: {self.auto_generated_key.hex()}")
            return self.auto_generated_key

    def _parse_key(self, key_str):
        """РџР°СЂСЃРёРЅРі РєР»СЋС‡Р° РёР· hex СЃС‚СЂРѕРєРё"""
        # РЈР±РёСЂР°РµРј РїСЂРµС„РёРєСЃ @ РµСЃР»Рё РµСЃС‚СЊ
        if key_str.startswith('@'):
            key_str = key_str[1:]

        try:
            key_bytes = bytes.fromhex(key_str)

            if len(key_bytes) not in [16, 24, 32]:
                print(f"WARNING: AES key should be 16, 24, or 32 bytes, got {len(key_bytes)}",
                      file=sys.stderr)

            return key_bytes

        except ValueError as e:
            raise ValueError(f"РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ С„РѕСЂРјР°С‚ РєР»СЋС‡Р° '{key_str}': {e}")

    def _parse_iv(self, iv_str):
        """РџР°СЂСЃРёРЅРі IV РёР· hex СЃС‚СЂРѕРєРё (16 Р±Р°Р№С‚ РґР»СЏ CBC, CFB, OFB, CTR)"""
        try:
            iv_bytes = bytes.fromhex(iv_str)
            if len(iv_bytes) != 16 and self.mode != 'gcm':
                print(f"WARNING: IV should be 16 bytes for {self.mode}, got {len(iv_bytes)}",
                      file=sys.stderr)
            return iv_bytes
        except ValueError as e:
            raise ValueError(f"РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ С„РѕСЂРјР°С‚ IV '{iv_str}': {e}")

    def _parse_nonce(self, nonce_str):
        """РџР°СЂСЃРёРЅРі nonce РёР· hex СЃС‚СЂРѕРєРё (12 Р±Р°Р№С‚ РґР»СЏ GCM)"""
        try:
            nonce_bytes = bytes.fromhex(nonce_str)
            if len(nonce_bytes) != 12:
                print(f"WARNING: GCM nonce is recommended to be 12 bytes, got {len(nonce_bytes)}",
                      file=sys.stderr)
            return nonce_bytes
        except ValueError as e:
            raise ValueError(f"РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ С„РѕСЂРјР°С‚ nonce '{nonce_str}': {e}")

    def _init_cipher(self):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РѕР±СЉРµРєС‚Р° С€РёС„СЂРѕРІР°РЅРёСЏ"""
        if self.algorithm != "aes":
            raise ValueError(f"РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјС‹Р№ Р°Р»РіРѕСЂРёС‚Рј: {self.algorithm}")

        mode_classes = {
            'ecb': ECBMode,
            'cbc': CBCMode,
            'cfb': CFBMode,
            'ofb': OFBMode,
            'ctr': CTRMode,
            'gcm': GCM,
            'aead': EncryptThenMAC
        }

        if self.mode not in mode_classes:
            raise ValueError(f"РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјС‹Р№ СЂРµР¶РёРј: {self.mode}")

        cipher_class = mode_classes[self.mode]

        # Р”Р»СЏ GCM РёСЃРїРѕР»СЊР·СѓРµРј nonce
        if self.mode == 'gcm':
            return cipher_class(self.key, self.nonce)

        # Р”Р»СЏ AEAD РёСЃРїРѕР»СЊР·СѓРµРј master key Рё AAD
        if self.mode == 'aead':
            # AEAD С‚СЂРµР±СѓРµС‚ РѕС‚РґРµР»СЊРЅС‹Рµ РєР»СЋС‡Рё РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ Рё MAC
            enc_key, mac_key = EncryptThenMAC.derive_keys(self.key)
            return cipher_class(enc_key, mac_key, cipher_mode='ctr')

        # Р”Р»СЏ ECB РЅРµ РЅСѓР¶РµРЅ IV
        if self.mode == 'ecb':
            return cipher_class(self.key)

        # Р”Р»СЏ РѕСЃС‚Р°Р»СЊРЅС‹С… СЂРµР¶РёРјРѕРІ РїРµСЂРµРґР°РµРј IV
        return cipher_class(self.key, self.iv)

    def get_auto_generated_key_hex(self):
        """
        РџРѕР»СѓС‡РёС‚СЊ auto-generated РєР»СЋС‡ РІ hex С„РѕСЂРјР°С‚Рµ

        Returns:
            str: hex СЃС‚СЂРѕРєР° РєР»СЋС‡Р° РёР»Рё None РµСЃР»Рё РєР»СЋС‡ РЅРµ Р±С‹Р» auto-generated
        """
        if self.auto_generated_key:
            return self.auto_generated_key.hex()
        return None

    def encrypt_file(self, input_file, output_file):
        """РЁРёС„СЂРѕРІР°РЅРёРµ С„Р°Р№Р»Р°"""
        try:
            # Р§РёС‚Р°РµРј РІС…РѕРґРЅРѕР№ С„Р°Р№Р»
            plaintext = read_file_safe(input_file)

            print(f"[INFO] Encrypting {len(plaintext)} bytes with {self.mode.upper()} mode")

            # Handle different modes
            if self.mode == 'gcm':
                # GCM encryption with AAD
                ciphertext = self.cipher.encrypt(plaintext, self.aad)
                print(f"[INFO] GCM nonce: {self.cipher.nonce.hex()}")
                print(f"[INFO] AAD length: {len(self.aad)} bytes")

            elif self.mode == 'aead':
                # Encrypt-then-MAC
                ciphertext = self.cipher.encrypt(plaintext, self.aad)

            else:
                # Traditional modes (ECB, CBC, CFB, OFB, CTR)
                ciphertext = self.cipher.encrypt(plaintext)

                # Р”Р»СЏ СЂРµР¶РёРјРѕРІ СЃ IV (РєСЂРѕРјРµ ECB) РІС‹РІРѕРґРёРј IV
                if self.mode in ['cbc', 'cfb', 'ofb', 'ctr'] and hasattr(self.cipher, 'iv'):
                    print(f"[INFO] IV: {self.cipher.iv.hex()}")

            # Р—Р°РїРёСЃС‹РІР°РµРј СЂРµР·СѓР»СЊС‚Р°С‚
            write_file_safe(output_file, ciphertext)

            print(f"[SUCCESS] Encryption completed. Output: {output_file}")

            # Return generated key if any
            return self.get_auto_generated_key_hex()

        except Exception as e:
            print(f"ERROR: Encryption failed: {e}", file=sys.stderr)
            sys.exit(1)

    def decrypt_file(self, input_file, output_file):
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ С„Р°Р№Р»Р°"""
        try:
            # Р§РёС‚Р°РµРј РІС…РѕРґРЅРѕР№ С„Р°Р№Р»
            ciphertext = read_file_safe(input_file)

            print(f"[INFO] Decrypting {len(ciphertext)} bytes with {self.mode.upper()} mode")

            # Handle different modes
            if self.mode == 'gcm':
                # GCM decryption with authentication
                try:
                    # Р”Р»СЏ GCM nonce Р»РёР±Рѕ РїСЂРµРґРѕСЃС‚Р°РІР»РµРЅ, Р»РёР±Рѕ С‡РёС‚Р°РµС‚СЃСЏ РёР· С„Р°Р№Р»Р°
                    if self.nonce:
                        # Nonce РїСЂРµРґРѕСЃС‚Р°РІР»РµРЅ СЏРІРЅРѕ
                        plaintext = self.cipher.decrypt(ciphertext, self.aad)
                    else:
                        # Nonce С‡РёС‚Р°РµС‚СЃСЏ РёР· С„Р°Р№Р»Р° (РїРµСЂРІС‹Рµ 12 Р±Р°Р№С‚)
                        if len(ciphertext) < 12:
                            raise ValueError("File too short for GCM nonce")

                        # РЎРѕР·РґР°РµРј РЅРѕРІС‹Р№ GCM РѕР±СЉРµРєС‚ СЃ nonce РёР· С„Р°Р№Р»Р°
                        file_nonce = ciphertext[:12]
                        actual_ciphertext = ciphertext[12:]

                        gcm = GCM(self.key, file_nonce)
                        plaintext = gcm.decrypt(actual_ciphertext, self.aad)

                    print(f"[SUCCESS] GCM authentication successful")

                except AuthenticationError as e:
                    print(f"ERROR: Authentication failed: {e}", file=sys.stderr)

                    # Clean up output file on auth failure
                    FileHandler.cleanup_on_failure(output_file)

                    sys.exit(1)

            elif self.mode == 'aead':
                # Decrypt-and-verify with AEAD
                try:
                    plaintext = self.cipher.decrypt(ciphertext, self.aad)
                    print(f"[SUCCESS] AEAD authentication successful")
                except Exception as e:
                    print(f"ERROR: Authentication failed: {e}", file=sys.stderr)
                    FileHandler.cleanup_on_failure(output_file)
                    sys.exit(1)

            else:
                # Traditional modes decryption
                plaintext = self._decrypt_data(ciphertext)

            # Р—Р°РїРёСЃС‹РІР°РµРј СЂРµР·СѓР»СЊС‚Р°С‚
            write_file_safe(output_file, plaintext)

            print(f"[SUCCESS] Decryption completed. Output: {output_file}")

        except Exception as e:
            print(f"ERROR: Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)

    def _decrypt_data(self, ciphertext):
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ РґР°РЅРЅС‹С… СЃ СѓС‡РµС‚РѕРј СЂРµР¶РёРјР°"""
        # Р”Р»СЏ ECB
        if self.mode == 'ecb':
            return self.cipher.decrypt(ciphertext, remove_padding=True)

        # Р”Р»СЏ СЂРµР¶РёРјРѕРІ СЃ IV
        if self.iv:
            # Р•СЃР»Рё IV Р±С‹Р» РїРµСЂРµРґР°РЅ РІ РєРѕРјР°РЅРґРЅРѕР№ СЃС‚СЂРѕРєРµ
            if self.mode == 'cbc':
                # Р”Р»СЏ CBC РїСЂРѕР±СѓРµРј СЃ padding, РµСЃР»Рё РЅРµ РїРѕР»СѓС‡Р°РµС‚СЃСЏ - Р±РµР· padding
                try:
                    return self.cipher.decrypt(ciphertext, remove_padding=True)
                except:
                    return self.cipher.decrypt(ciphertext, remove_padding=False)
            else:
                # CFB, OFB, CTR - РїРѕС‚РѕРєРѕРІС‹Рµ СЂРµР¶РёРјС‹ Р±РµР· padding
                return self.cipher.decrypt(ciphertext, remove_padding=False)
        else:
            # Р•СЃР»Рё IV РЅРµ Р±С‹Р» РїРµСЂРµРґР°РЅ, С‡РёС‚Р°РµРј РµРіРѕ РёР· РЅР°С‡Р°Р»Р° С„Р°Р№Р»Р°
            if len(ciphertext) < 16:
                raise ValueError(
                    f"Р¤Р°Р№Р» СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёР№ РґР»СЏ РїРѕР»СѓС‡РµРЅРёСЏ IV. РўСЂРµР±СѓРµС‚СЃСЏ РјРёРЅРёРјСѓРј 16 Р±Р°Р№С‚, РїРѕР»СѓС‡РµРЅРѕ: {len(ciphertext)} Р±Р°Р№С‚")

            # Р§РёС‚Р°РµРј IV РёР· С„Р°Р№Р»Р°
            file_iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]

            # РЎРѕР·РґР°РµРј РЅРѕРІС‹Р№ cipher СЃ IV РёР· С„Р°Р№Р»Р°
            mode_classes = {
                'cbc': CBCMode,
                'cfb': CFBMode,
                'ofb': OFBMode,
                'ctr': CTRMode
            }

            cipher_class = mode_classes[self.mode]
            cipher = cipher_class(self.key, file_iv)

            # Р”Р»СЏ CBC РїСЂРѕР±СѓРµРј СЃ padding, РµСЃР»Рё РЅРµ РїРѕР»СѓС‡Р°РµС‚СЃСЏ - Р±РµР· padding
            if self.mode == 'cbc':
                try:
                    return cipher.decrypt(actual_ciphertext, remove_padding=True)
                except:
                    return cipher.decrypt(actual_ciphertext, remove_padding=False)
            else:
                # CFB, OFB, CTR - РїРѕС‚РѕРєРѕРІС‹Рµ СЂРµР¶РёРјС‹ Р±РµР· padding
                return cipher.decrypt(actual_ciphertext, remove_padding=False)


# ===== РЈРўРР›РРўР« Р”Р›РЇ Р¤РђР™Р›РћР’РћР“Рћ Р’Р’РћР”Рђ/Р’Р«Р’РћР”Рђ =====
def read_binary(filepath: str) -> bytes:
    """Р§С‚РµРЅРёРµ С„Р°Р№Р»Р° РІ Р±РёРЅР°СЂРЅРѕРј СЂРµР¶РёРјРµ (РґР»СЏ РѕР±СЂР°С‚РЅРѕР№ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё)"""
    return read_file_safe(filepath)

def write_binary(filepath: str, data: bytes) -> None:
    """Р—Р°РїРёСЃСЊ С„Р°Р№Р»Р° РІ Р±РёРЅР°СЂРЅРѕРј СЂРµР¶РёРјРµ (РґР»СЏ РѕР±СЂР°С‚РЅРѕР№ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё)"""
    write_file_safe(filepath, data)


# ===== РўР•РЎРўРР РћР’РђРќРР• =====
def test_crypto_core():
    """РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ CryptoCipher"""
    print("Testing CryptoCipher...")

    # Test key generation
    test_key = generate_aes_key()
    print(f"1. Generated test key: {test_key.hex()}")

    # Test GCM mode
    try:
        gcm = GCM(test_key)
        test_data = b"Hello, GCM World!"
        test_aad = b"authenticated data"

        encrypted = gcm.encrypt(test_data, test_aad)
        decrypted = gcm.decrypt(encrypted, test_aad)

        assert decrypted == test_data
        print("2. вњ“ GCM encryption/decryption test passed")

    except Exception as e:
        print(f"2. вњ— GCM test failed: {e}")

    print("\n[+] CryptoCipher tests completed")


if __name__ == "__main__":
    test_crypto_core()

