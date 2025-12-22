#!/usr/bin/env python3
"""
РўРµСЃС‚С‹ РґР»СЏ AEAD (Authenticated Encryption with Associated Data) - Sprint 6
"""

import os
import unittest
import tempfile
from src.aead import EncryptThenMAC, AuthenticationError


class TestAEAD(unittest.TestCase):
    """РўРµСЃС‚С‹ РґР»СЏ Encrypt-then-MAC"""

    def setUp(self):
        """РќР°СЃС‚СЂРѕР№РєР° С‚РµСЃС‚РѕРІ"""
        self.master_key = os.urandom(32)
        self.test_data = b"Test data for Encrypt-then-MAC AEAD"
        self.test_aad = b"Associated authenticated data"

    def test_key_derivation(self):
        """РўРµСЃС‚ РіРµРЅРµСЂР°С†РёРё РєР»СЋС‡РµР№"""
        print("\n=== Test 1: Key derivation ===")

        enc_key, mac_key = EncryptThenMAC.derive_keys(self.master_key)

        # РџСЂРѕРІРµСЂСЏРµРј СЂР°Р·РјРµСЂС‹ РєР»СЋС‡РµР№
        self.assertEqual(len(enc_key), 16)  # AES-128 РєР»СЋС‡
        self.assertEqual(len(mac_key), 32)  # SHA-256 РєР»СЋС‡

        # РљР»СЋС‡Рё РґРѕР»Р¶РЅС‹ Р±С‹С‚СЊ СЂР°Р·РЅС‹РјРё
        self.assertNotEqual(enc_key, mac_key[:16])
        print("вњ“ Key derivation test passed")

    def test_encrypt_then_mac_basic(self):
        """РўРµСЃС‚ Р±Р°Р·РѕРІРѕРіРѕ Encrypt-then-MAC"""
        print("\n=== Test 2: Basic Encrypt-then-MAC ===")

        # Р“РµРЅРµСЂРёСЂСѓРµРј РєР»СЋС‡Рё
        enc_key, mac_key = EncryptThenMAC.derive_keys(self.master_key)

        # РЎРѕР·РґР°РµРј AEAD РѕР±СЉРµРєС‚
        aead = EncryptThenMAC(enc_key, mac_key, 'ctr')

        # РЁРёС„СЂСѓРµРј
        ciphertext = aead.encrypt(self.test_data, self.test_aad)

        # РџСЂРѕРІРµСЂСЏРµРј СЃС‚СЂСѓРєС‚СѓСЂСѓ (IV + ciphertext + tag)
        # IV (16) + ciphertext + tag (32 РґР»СЏ SHA-256)
        self.assertGreaterEqual(len(ciphertext), 16 + 32)

        # Р Р°СЃС€РёС„СЂРѕРІС‹РІР°РµРј
        plaintext = aead.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, self.test_data)
        print("вњ“ Basic Encrypt-then-MAC test passed")

    def test_authentication_failure_wrong_key(self):
        """РўРµСЃС‚ РЅРµСѓРґР°С‡Рё Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё РїСЂРё РЅРµРІРµСЂРЅРѕРј РєР»СЋС‡Рµ"""
        print("\n=== Test 3: Authentication failure with wrong key ===")

        enc_key1, mac_key1 = EncryptThenMAC.derive_keys(self.master_key)
        enc_key2, mac_key2 = EncryptThenMAC.derive_keys(os.urandom(32))

        aead1 = EncryptThenMAC(enc_key1, mac_key1, 'ctr')
        aead2 = EncryptThenMAC(enc_key2, mac_key2, 'ctr')

        ciphertext = aead1.encrypt(self.test_data, self.test_aad)

        # РџСЂРѕР±СѓРµРј СЂР°СЃС€РёС„СЂРѕРІР°С‚СЊ РґСЂСѓРіРёРј РєР»СЋС‡РѕРј
        with self.assertRaises(AuthenticationError):
            aead2.decrypt(ciphertext, self.test_aad)

        print("вњ“ Wrong key detection test passed")

    def test_authentication_failure_wrong_aad(self):
        """РўРµСЃС‚ РЅРµСѓРґР°С‡Рё Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё РїСЂРё РЅРµРІРµСЂРЅРѕРј AAD"""
        print("\n=== Test 4: Authentication failure with wrong AAD ===")

        enc_key, mac_key = EncryptThenMAC.derive_keys(self.master_key)
        aead = EncryptThenMAC(enc_key, mac_key, 'ctr')

        ciphertext = aead.encrypt(self.test_data, self.test_aad)

        # РџСЂРѕР±СѓРµРј СЂР°СЃС€РёС„СЂРѕРІР°С‚СЊ СЃ РЅРµРІРµСЂРЅС‹Рј AAD
        with self.assertRaises(AuthenticationError):
            aead.decrypt(ciphertext, b"wrong aad")

        print("вњ“ Wrong AAD detection test passed")

    # ... РѕСЃС‚Р°Р»СЊРЅС‹Рµ С‚РµСЃС‚С‹ РѕСЃС‚Р°СЋС‚СЃСЏ Р±РµР· РёР·РјРµРЅРµРЅРёР№ ...


if __name__ == "__main__":
    print("Running AEAD tests...")
    unittest.main(verbosity=2)

